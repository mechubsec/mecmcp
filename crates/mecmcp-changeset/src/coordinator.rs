//! Changeset coordinator for managing in-memory state and endpoint locking.

use crate::lifecycle::{ApplyHandle, change_set_transition_allowed};
use crate::{
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::{ChangesetState, PersistenceError, read_state_with_key, write_state},
    records::{ChangeSetRecord, OperationRecord},
    state_lock::StateFileLock,
    types::OperationLimits,
};
use mecmcp_audit::recorder::EvidenceRecorder;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

/// Whether a change set still occupies the one-pending-per-principal slot.
///
/// `Expired`, `Applied`, `Failed`, and `Cancelled` are terminal and block nothing.
fn is_pending(state: ChangeSetState) -> bool {
    matches!(
        state,
        ChangeSetState::Planned | ChangeSetState::Approved | ChangeSetState::Applying
    )
}

/// Whether the approval deadline may still retire this change set.
///
/// Narrower than [`is_pending`], and deliberately so. `Applying` means a device
/// transaction is in flight against this record — the deadline bounds how long
/// an approval may sit unused, not how long an apply may take. Retiring an
/// `Applying` record would rewrite the lifecycle out from under the running
/// apply, make it evictable at capacity, and admit a second change set for the
/// same principal and device. A crash would then leave the live operation paired
/// with an expired or absent change set, instead of the `Failed` state that
/// restart recovery assigns to anything caught mid-apply.
pub(crate) fn is_expirable(state: ChangeSetState) -> bool {
    matches!(state, ChangeSetState::Planned | ChangeSetState::Approved)
}

/// Error type for coordinator operations.
#[derive(Debug)]
pub struct CoordinatorError {
    field: &'static str,
    message: String,
}

impl CoordinatorError {
    /// Creates a new coordinator error for a specific field.
    pub fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the field name associated with this error.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for CoordinatorError {}

impl From<PersistenceError> for CoordinatorError {
    fn from(error: PersistenceError) -> Self {
        Self::new("state", error.to_string())
    }
}

/// HMAC key for the v6 (keyed) approval digest.
///
/// `ChangesetCoordinator` derives `Debug` for tracing and test-failure output,
/// and `Arc<[u8]>`'s own `Debug` prints the raw bytes — a coordinator holding a
/// bare `Arc<[u8]>` key would leak it through any `{:?}` of the coordinator, a
/// tracing field, or a panic message. This wraps the bytes so that path prints
/// `ApprovalDigestKey(<redacted>)` instead, and zeroizes them when the last
/// clone is dropped (MEC-457 review, finding 3).
#[derive(Clone)]
pub struct ApprovalDigestKey(Arc<zeroize::Zeroizing<Box<[u8]>>>);

impl ApprovalDigestKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Self(Arc::new(zeroize::Zeroizing::new(bytes.into())))
    }
}

impl std::fmt::Debug for ApprovalDigestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalDigestKey(<redacted>)")
    }
}

impl std::ops::Deref for ApprovalDigestKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Arc<[u8]>> for ApprovalDigestKey {
    fn from(bytes: Arc<[u8]>) -> Self {
        Self::new(bytes.as_ref())
    }
}

/// Minimum acceptable length, in bytes, for a loaded approval digest key.
///
/// HMAC-SHA256 accepts a key of any length, so this is not a cryptographic
/// requirement of the algorithm -- it exists so `--approval-digest-key`
/// pointed at an accidentally short or empty file fails to start rather than
/// producing a weak, guessable key silently.
pub const MIN_APPROVAL_DIGEST_KEY_BYTES: usize = 32;

/// Error loading an approval digest key from a file.
#[derive(Debug)]
pub enum ApprovalDigestKeyError {
    /// The file could not be read, or failed a permission/ownership check.
    Io {
        /// The path that failed to load.
        path: PathBuf,
        /// The underlying error.
        source: mecmcp_secret::SecretError,
    },
    /// The file's contents are shorter than [`MIN_APPROVAL_DIGEST_KEY_BYTES`].
    TooShort {
        /// The path that was too short.
        path: PathBuf,
        /// The actual length in bytes.
        len: usize,
    },
}

impl std::fmt::Display for ApprovalDigestKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "could not read approval digest key '{}': {source}",
                    path.display()
                )
            }
            Self::TooShort { path, len } => write!(
                f,
                "approval digest key '{}' is {len} bytes; at least {MIN_APPROVAL_DIGEST_KEY_BYTES} are required",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ApprovalDigestKeyError {}

impl From<ApprovalDigestKeyError> for CoordinatorError {
    fn from(error: ApprovalDigestKeyError) -> Self {
        Self::new("approval_digest_key", error.to_string())
    }
}

impl ApprovalDigestKey {
    /// Loads a key from a file, applying the same hardened-file checks
    /// [`crate::persistence::read_state`] uses: the file must be a regular
    /// file, owned by the effective uid, mode 0600 (no group/other access),
    /// and not a symlink. Rejects a key shorter than
    /// [`MIN_APPROVAL_DIGEST_KEY_BYTES`].
    ///
    /// This is the one place a deployment turns `--approval-digest-key
    /// <path>` into a key: callers should pass the result straight to
    /// [`ChangesetCoordinator::load_with_key`] rather than loading the file
    /// themselves, so the load path and the permission checks cannot drift
    /// from `read_state_with_key`'s (MEC-457 review, finding 2).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, fails a permission or
    /// ownership check, or is shorter than the minimum key length.
    pub fn load_from_file(path: &Path) -> Result<Self, ApprovalDigestKeyError> {
        let bytes =
            mecmcp_secret::read_hardened_file(path, mecmcp_secret::FileLimits { max_bytes: 4096 })
                .map_err(|source| ApprovalDigestKeyError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
        let bytes = bytes.expose();
        if bytes.len() < MIN_APPROVAL_DIGEST_KEY_BYTES {
            return Err(ApprovalDigestKeyError::TooShort {
                path: path.to_path_buf(),
                len: bytes.len(),
            });
        }
        Ok(Self::new(bytes))
    }
}

/// Changeset coordinator managing in-memory state, endpoint locks, and persistence.
///
/// This coordinator is vendor-agnostic and manages the lifecycle of operations and
/// change sets across device endpoints. It provides per-endpoint mutual exclusion
/// and atomic persistence of state updates.
#[derive(Debug)]
pub struct ChangesetCoordinator {
    state: Mutex<ChangesetState>,
    endpoint_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    state_path: Option<PathBuf>,
    limits: OperationLimits,
    approval_ttl: Duration,
    lab_mode: bool,
    /// Emits the four evidence records, when a server wants an evidence trail.
    ///
    /// Optional because evidence is a deployment choice: a server with no sink
    /// configured should not be forced to build chains nothing will read. When
    /// absent, every emission point is a no-op (mecmcp#292).
    evidence: Option<Arc<EvidenceRecorder>>,
    /// The single-writer lock on `<state_path>.owner`, held for as long as this
    /// coordinator has `state_path` loaded.
    ///
    /// `None` when `state_path` is `None` (in-memory only, nothing to own).
    /// Its only job is to be alive: nothing reads it after construction.
    /// Dropping it releases the lock, which is why it must live exactly as
    /// long as the coordinator does rather than as a local in `load`
    /// (MEC-540 review, finding 2).
    _owner_lock: Option<StateFileLock>,
    /// HMAC key for the v6 (keyed) approval digest, when a deployment has one
    /// configured.
    ///
    /// Optional for the same reason `evidence` is: a deployment that has not
    /// been given a key keeps signing approvals under the unkeyed v5 rule,
    /// rather than being forced to provision a key it may not yet have a
    /// distribution story for. `approve_change_set` reads this at approval
    /// time; `load_with_recovery_and_key` reads it at load time, because a
    /// v6-signed record already on disk cannot be verified without it (MEC-457).
    approval_digest_key: Option<ApprovalDigestKey>,
    /// Strict mode for verified-approver identity (MEC-994 W4).
    ///
    /// When set, `approve_change_set` refuses any approver that is not
    /// `ApproverIdentity::OidcVerified`, and `create_change_set` refuses to
    /// propose for an owner with no `oidc_subject` on their token. `false` by
    /// default so a deployment that has not configured step-up
    /// authentication keeps behaving exactly as it did before this field
    /// existed.
    require_verified_approver: bool,
}

impl ChangesetCoordinator {
    /// Emit evidence records for every change this coordinator handles.
    ///
    /// Consuming a recorder rather than borrowing one: the chain must have a
    /// single writer per `(tier, server_id)`, and sharing one coordinator's
    /// recorder with another would fork it — a fork verifies as two valid
    /// chains rather than as an error (ssdf#47).
    #[must_use]
    pub fn with_evidence(mut self, recorder: Arc<EvidenceRecorder>) -> Self {
        self.evidence = Some(recorder);
        self
    }

    /// The evidence recorder, if this coordinator has one.
    pub(crate) fn evidence(&self) -> Option<&EvidenceRecorder> {
        self.evidence.as_deref()
    }

    /// Sign approvals with a keyed (v6) digest instead of the unkeyed v5 one.
    ///
    /// Once set, every approval this coordinator records is bound to
    /// `approval_digest_key`: forging or editing one requires the key, not just
    /// the visible fields a v5 digest is computed from (MEC-457).
    ///
    /// This only affects *new* approvals recorded through this instance.
    /// Verifying a v6 digest already on disk at load time is
    /// [`load_with_recovery_and_key`](Self::load_with_recovery_and_key)'s job —
    /// setting this builder after [`load`](Self::load) has already read the
    /// file does not retroactively verify what load already accepted or
    /// rejected.
    #[must_use]
    pub fn with_approval_digest_key(mut self, key: impl Into<ApprovalDigestKey>) -> Self {
        self.approval_digest_key = Some(key.into());
        self
    }

    /// The approval digest key, if this coordinator has one.
    pub(crate) fn approval_digest_key(&self) -> Option<&[u8]> {
        self.approval_digest_key.as_deref()
    }

    /// Require a verified (IdP step-up) approver identity on every approval,
    /// and an owner `oidc_subject` on every proposal (MEC-994 W4).
    ///
    /// Only affects calls made through this instance from here on; it does
    /// not retroactively judge records already on disk.
    #[must_use]
    pub fn with_require_verified_approver(mut self, value: bool) -> Self {
        self.require_verified_approver = value;
        self
    }

    /// Whether strict verified-approver mode is enabled.
    pub(crate) fn require_verified_approver(&self) -> bool {
        self.require_verified_approver
    }
}

impl Default for ChangesetCoordinator {
    fn default() -> Self {
        Self {
            state: Mutex::new(ChangesetState::default()),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: None,
            limits: OperationLimits::default(),
            approval_ttl: Duration::from_secs(15 * 60),
            evidence: None,
            lab_mode: false,
            approval_digest_key: None,
            require_verified_approver: false,
            _owner_lock: None,
        }
    }
}

/// Whether a `Staged` operation can survive a server restart.
///
/// The answer is a property of the vendor's staged handle, not of the change-set
/// model, so the coordinator cannot decide it alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedRecovery {
    /// Mark `Staged` operations `Indeterminate` on load.
    ///
    /// Correct where the handle is a live device session — Junos holds an open
    /// NETCONF session and a locked candidate, both of which die with the process.
    Discard,
    /// Leave `Staged` operations staged on load.
    ///
    /// Correct where the device owns the candidate and the handle is reconstructible
    /// from the persisted record, as on PAN-OS.
    Retain,
}

impl ChangesetCoordinator {
    /// Loads the coordinator from disk, applying restart recovery if needed.
    ///
    /// On restart, any in-flight operations (`Staging`, `Validating`, `Committing`) are
    /// marked `Indeterminate` and any in-flight change sets (`Applying`) are marked `Failed`.
    /// The recovery is persisted back to disk only if state was modified.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute, the file cannot be read, or the
    /// state is invalid.
    pub fn load(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
    ) -> Result<Self, CoordinatorError> {
        Self::load_with_recovery(
            path,
            limits,
            approval_ttl,
            lab_mode,
            StagedRecovery::Discard,
        )
    }

    /// [`load`](Self::load), verifying any on-disk v6 approval digest against
    /// `approval_digest_key`.
    ///
    /// A deployment that configures a key must pass it here, not just to
    /// [`with_approval_digest_key`](Self::with_approval_digest_key) afterwards:
    /// the file is read and its approvals verified during this call, before
    /// that builder would ever run.
    ///
    /// # Errors
    ///
    /// As [`load`](Self::load).
    pub fn load_with_key(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
        approval_digest_key: Option<ApprovalDigestKey>,
    ) -> Result<Self, CoordinatorError> {
        Self::load_with_recovery_and_key(
            path,
            limits,
            approval_ttl,
            lab_mode,
            StagedRecovery::Discard,
            approval_digest_key,
        )
    }

    /// Loads the coordinator, choosing how `Staged` operations survive a restart.
    ///
    /// [`load`](Self::load) defaults to [`StagedRecovery::Discard`], which is right
    /// wherever the staged handle is a live device session: Junos holds an open
    /// NETCONF session and a locked candidate that die with the process, so the
    /// operation genuinely cannot continue.
    ///
    /// [`StagedRecovery::Retain`] suits a vendor whose device owns the candidate and
    /// whose staged handle is reconstructible from the record — PAN-OS keeps the
    /// candidate server-side and identifies it by operation id, so a restart does not
    /// invalidate it.
    ///
    /// This is a parameter rather than something a consumer patches afterwards
    /// because the fix has to land while the state is being loaded. Rewriting the
    /// state file after construction leaves the coordinator's memory and the file
    /// divergent — the API answering from one and the offline recovery tool reading
    /// the other — which strands the operation beyond use or resolution
    /// (rustpanosmcp#72).
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not absolute, the file cannot be read, or the
    /// state is invalid.
    pub fn load_with_recovery(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
        staged_recovery: StagedRecovery,
    ) -> Result<Self, CoordinatorError> {
        Self::load_with_recovery_and_key(
            path,
            limits,
            approval_ttl,
            lab_mode,
            staged_recovery,
            None,
        )
    }

    /// [`load_with_recovery`](Self::load_with_recovery), verifying any on-disk
    /// v6 approval digest against `approval_digest_key`. See
    /// [`load_with_key`](Self::load_with_key) for why the key is a parameter
    /// here rather than a builder call made afterwards.
    ///
    /// # Errors
    ///
    /// As [`load_with_recovery`](Self::load_with_recovery).
    pub fn load_with_recovery_and_key(
        path: Option<&Path>,
        limits: OperationLimits,
        approval_ttl: Duration,
        lab_mode: bool,
        staged_recovery: StagedRecovery,
        approval_digest_key: Option<ApprovalDigestKey>,
    ) -> Result<Self, CoordinatorError> {
        let Some(path) = path else {
            return Ok(Self {
                state: Mutex::new(ChangesetState::default()),
                endpoint_locks: Mutex::new(BTreeMap::new()),
                state_path: None,
                limits,
                approval_ttl,
                lab_mode,
                evidence: None,
                approval_digest_key,
                require_verified_approver: false,
                _owner_lock: None,
            });
        };

        if !path.is_absolute() {
            return Err(CoordinatorError::new(
                "path",
                "changeset state path must be absolute",
            ));
        }

        // Claim single-writer ownership of this state file before reading it,
        // and hold the claim for the coordinator's whole lifetime. Without
        // this, a second server pointed at the same file (or a live server
        // plus an offline `resolve_persisted_operation` repair) is a lost
        // update no lock scoped to one RMW cycle can catch: each side reads
        // its own consistent snapshot, and whichever writes last wins,
        // silently discarding the other's change. Fails fast rather than
        // blocking, because there is nothing productive to wait for -- the
        // other holder is not expected to exit on its own (MEC-540 review,
        // finding 2).
        let owner_lock = StateFileLock::try_acquire_owner(path)?.ok_or_else(|| {
            CoordinatorError::new(
                "state",
                "another process already holds this state file (an existing server, or an \
                 offline resolution in progress); stop it before starting a second one against \
                 the same path",
            )
        })?;

        // Hold the RMW lock across the read too, not just the recovery write
        // below. A reader that skips the lock can still see a consistent
        // snapshot -- `write_state`'s rename guarantees that -- but a
        // consistent snapshot is not the same as an up-to-date one: an
        // offline repair's write landing between this read and the recovery
        // write further down would be silently reverted when that write
        // lands, even though the owner lock above stops a second *server*
        // from doing the same (MEC-540 review, finding 1).
        let _state_lock = if path.exists() {
            Some(StateFileLock::acquire(path)?)
        } else {
            None
        };

        let mut state = if path.exists() {
            read_state_with_key(path, limits.max_state_bytes, approval_digest_key.as_deref())?
        } else {
            ChangesetState::default()
        };

        // Restart recovery: mark in-flight operations as indeterminate.
        // `Staged` is included because the opaque `T::Staged` handle only exists
        // in memory and cannot be reconstructed after a restart. Without the handle,
        // the operation cannot proceed through diff/validate/commit or be discarded.
        // The operator must manually reconcile the device state.
        let mut recovered = false;
        for record in state.operations.values_mut() {
            // A `Staged` operation the vendor can genuinely resume is left alone.
            // It must have no `job_id`: once a job exists the operation reached
            // validation or commit, and whether that job landed is exactly the
            // question `Indeterminate` exists to flag.
            if staged_recovery == StagedRecovery::Retain
                && record.state == LifecycleState::Staged
                && record.job_id.is_none()
            {
                continue;
            }

            if matches!(
                record.state,
                LifecycleState::Staging
                    | LifecycleState::Staged
                    | LifecycleState::Validating
                    | LifecycleState::Committing
            ) {
                record.state = LifecycleState::Indeterminate;
                record.details = Some(
                    "server restarted during a non-terminal operation; manual reconciliation required"
                        .to_owned(),
                );
                recovered = true;
            }
        }

        // Normalise first, then settle. Load is the boundary where a file
        // written by an older binary enters memory, so it is where the
        // `Some("")` invariant has to be established — otherwise the
        // coordinator hands back an empty handle that `write_state` has
        // already dropped from the file, and memory and disk disagree about
        // the same record. Non-`Applying` legacy records matter too: nothing
        // else rewrites them, so without this they keep the empty handle
        // indefinitely.
        //
        // With the invariant established, settling can ask the plain question.
        //
        // A record carrying a real `task_id` names a vendor operation that is
        // still running, or has finished and holds its own answer. Marking it
        // `Failed` would assert an outcome nobody observed — and the likelier
        // outcome is success, because the vendor accepted the operation before
        // this process died. It would also hide the record from the caller's
        // re-probe, which looks for `Applying` plus a handle, so the feature
        // that field exists for would never fire.
        //
        // Without a handle there is genuinely nothing to ask, and `Failed` is
        // the existing behaviour for those.
        for record in state.change_sets.values_mut() {
            if record.task_id.as_deref().is_some_and(str::is_empty) {
                record.task_id = None;
                recovered = true;
            }
            // ...unless the apply never had a handle to write. Then `Applying`
            // with none is not evidence that nothing started; it is the state
            // that says only the device knows, and settling it as `Failed`
            // would assert an outcome nobody observed on an operation that is
            // usually not idempotent. It also keeps the approval spent, which
            // is the point: a record left `Approved` could run again.
            if record.state == ChangeSetState::Applying
                && record.task_id.is_none()
                && !record.apply_without_handle
            {
                record.state = ChangeSetState::Failed;
                recovered = true;
            }
        }

        // Persist recovery only if we changed something. Covered by the same
        // `_state_lock` taken before the read above, so the read-modify-write
        // is one atomic cycle from another process's point of view -- for
        // example against an offline `resolve_persisted_operation` repair
        // racing server startup (MEC-540).
        if recovered {
            write_state(path, &state, limits.max_state_bytes)?;
        }

        Ok(Self {
            evidence: None,
            state: Mutex::new(state),
            endpoint_locks: Mutex::new(BTreeMap::new()),
            state_path: Some(path.to_path_buf()),
            limits,
            approval_ttl,
            lab_mode,
            approval_digest_key,
            require_verified_approver: false,
            _owner_lock: Some(owner_lock),
        })
    }

    /// Acquires a per-endpoint guard, serializing concurrent access to the same endpoint.
    ///
    /// Different endpoints may proceed concurrently. The guard is cancellable via the
    /// provided cancellation token.
    ///
    /// # Errors
    ///
    /// Returns an error if the cancellation token is triggered before the lock is acquired.
    pub async fn device_guard(
        &self,
        endpoint: &str,
        cancellation: &CancellationToken,
    ) -> Result<OwnedMutexGuard<()>, CoordinatorError> {
        let lock = {
            let mut locks = self.endpoint_locks.lock().await;
            locks
                .entry(endpoint.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        tokio::select! {
            () = cancellation.cancelled() => Err(CoordinatorError::new("device", "operation cancelled")),
            guard = lock.lock_owned() => Ok(guard),
        }
    }

    /// Retrieves an operation record by ID, validating ownership.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation does not exist or is not owned by the
    /// specified principal and device.
    pub async fn record(
        &self,
        operation_id: &str,
        owner: &str,
        device: &str,
    ) -> Result<OperationRecord, CoordinatorError> {
        validate_operation_id(operation_id)?;
        let state = self.state.lock().await;
        let record = state
            .operations
            .get(operation_id)
            .ok_or_else(|| CoordinatorError::new("operation_id", "unknown operation"))?;
        if record.owner != owner || record.device != device {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is not owned by this principal and device",
            ));
        }
        Ok(record.clone())
    }

    /// Snapshot of every persisted operation.
    ///
    /// Exists for vendor-specific recovery that has to run *after* [`load`](Self::load):
    /// the coordinator promotes non-terminal operations to `Indeterminate` on load
    /// because a staged candidate generally cannot survive a restart, but a vendor
    /// whose device holds the candidate independently can legitimately restore them.
    ///
    /// Such a pass must go through [`update`](Self::update) on these records rather
    /// than rewriting the state file directly. Editing the file behind a loaded
    /// coordinator leaves the two permanently divergent — the API answers from
    /// memory while the offline recovery tool reads the file — and the affected
    /// operation can then be neither used nor resolved (rustpanosmcp#72).
    pub async fn operations(&self) -> Vec<OperationRecord> {
        let state = self.state.lock().await;
        state.operations.values().cloned().collect()
    }

    /// Every change set currently held, for enumeration by a consumer's tool.
    ///
    /// Mirrors [`ChangesetCoordinator::operations`]. This exists because not being able
    /// to ask "what change sets exist for this device?" is what turned a stale
    /// record into a lockout: the status path requires an id, and an operator
    /// who never recorded it had no supported way to find out (#193). The
    /// reporter escaped only by reading the state file on the container, which
    /// is not an API.
    ///
    /// Returns records as stored. Filtering by device or owner, and deciding
    /// what a caller is allowed to see, is the consumer's scope policy — this
    /// crate has never made that decision and should not start here.
    pub async fn change_sets(&self) -> Vec<ChangeSetRecord> {
        let state = self.state.lock().await;
        state.change_sets.values().cloned().collect()
    }

    /// Inserts a new operation record.
    ///
    /// If the operation store is at capacity, terminal records are evicted first.
    /// If still at capacity, the insert fails. Only one active operation per endpoint
    /// is allowed.
    ///
    /// On persistence failure, the in-memory insert is rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation store is full after evicting terminal records
    /// - The device already has an active or unreconciled operation
    /// - Persistence fails
    pub async fn insert(&self, record: OperationRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;

        // Evict terminal records if at capacity
        if state.operations.len() >= self.limits.max_operations {
            state
                .operations
                .retain(|_, record| !record.state.terminal());
        }

        if state.operations.len() >= self.limits.max_operations {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation store is full",
            ));
        }

        // Enforce one active operation per device or endpoint. Two inventory names
        // can legitimately resolve to the same endpoint (management IP + DNS name),
        // and if both passed the device-only check, two operations could mutate
        // one candidate concurrently. Reject when EITHER the device name matches
        // OR the canonical endpoint matches.
        for existing in state.operations.values() {
            if existing.state.terminal() {
                continue;
            }
            // Check device match
            if existing.device == record.device {
                return Err(CoordinatorError::new(
                    "operation_id",
                    "the device already has an active or unreconciled operation",
                ));
            }
            // Check canonical endpoint match
            if existing.endpoint == record.endpoint {
                return Err(CoordinatorError::new(
                    "operation_id",
                    "the device already has an active or unreconciled operation",
                ));
            }
        }

        let id = record.id.clone();
        state.operations.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            state.operations.remove(&id);
            return Err(error);
        }

        Ok(())
    }

    /// Updates an existing operation record.
    ///
    /// On persistence failure, the in-memory update is rolled back to the previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn update(&self, record: OperationRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let previous = state.operations.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.operations.insert(id, previous);
                }
                None => {
                    state.operations.remove(&id);
                }
            }
            return Err(error);
        }

        Ok(())
    }

    /// Removes an operation record.
    ///
    /// Persistence failures are logged but do not error; the operation is removed from
    /// memory regardless.
    pub async fn remove(&self, operation_id: &str) {
        let mut state = self.state.lock().await;
        state.operations.remove(operation_id);
        if let Err(error) = self.persist_locked(&state) {
            // Log the error but do not fail the remove operation
            eprintln!("changeset state persistence failed during remove: {error}");
        }
    }

    /// Inserts a new change-set record.
    ///
    /// If the change-set store is at capacity, terminal records (`Applied`, `Expired`,
    /// `Failed`) are evicted first. If still at capacity, the insert fails. Only one
    /// pending change set per principal and device is allowed.
    ///
    /// On persistence failure, the in-memory insert is rolled back.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change-set store is full after evicting terminal records
    /// - The principal already has a pending change set on the device
    /// - Persistence fails
    pub async fn insert_change_set(&self, record: ChangeSetRecord) -> Result<(), CoordinatorError> {
        // The configured ceilings, enforced where the limits are in scope.
        // `validate_state` sees no limits, so it checks structure only — a file
        // that was legal when written must not become unloadable because a
        // ceiling was lowered afterwards. Nothing called either of these before,
        // so `max_targets_per_set` and `max_preview_bytes` had no effect at all.
        record
            .validate_target_set(self.limits.max_targets_per_set)
            .map_err(|error| CoordinatorError::new("targets", error.to_string()))?;
        record
            .validate_preview(self.limits.max_preview_bytes)
            .map_err(|error| CoordinatorError::new("preview", error.to_string()))?;

        // Every boundary the record crosses into the store normalises, so no
        // caller can seed `Some("")` here either.
        let record = normalise_apply_marker(normalise_task_handle(record));

        // A change set is created `Planned`. Every later state is reached by a
        // transition the policy governs, so accepting one here would be a door
        // straight into `Applying` with no claim.
        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "state",
                format!(
                    "a change set is created Planned, not {:?}; later states are reached \
                     through the lifecycle, and accepting one here would bypass the \
                     transition policy",
                    record.state
                ),
            ));
        }

        // A change set is created unapproved. This insert path doesn't go
        // through `check_change_set_write`, so a record already carrying an
        // approval (even a self-consistent one with `approver == owner`)
        // would otherwise be persisted unchecked. It could never advance,
        // since invariant 4 blocks the move to `Approved`, but a stored
        // record with a forged-but-consistent digest is exactly what
        // `validate_state_with_key` now rejects on reload — taking every
        // change set in the file down with it.
        if record.approval.is_some() || record.approver.is_some() {
            return Err(CoordinatorError::new(
                "approval",
                "a change set is created unapproved; approval is granted through \
                 approve_change_set, not at creation",
            ));
        }

        let mut state = self.state.lock().await;

        // Before anything expires or is evicted, and under the same lock that
        // performs the insert.
        //
        // Both halves matter. Before eviction, because at capacity an
        // `Applying` record could otherwise be settled to `Failed`, evicted as
        // terminal, and re-inserted under its own id to be claimed a second
        // time. Under one lock, because checking absence and then releasing
        // before inserting lets two concurrent inserts of the same id both find
        // nothing and the later one overwrite the earlier — which is the same
        // check-then-act race this whole change exists to remove, and the first
        // version of this guard reintroduced it by taking its own lock.
        if let Some(existing) = state.change_sets.get(&record.id) {
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "change set {} already exists in state {:?}; insert does not \
                     overwrite, and lifecycle changes go through the update path",
                    record.id, existing.state
                ),
            ));
        }

        // Retire anything past its approval deadline before doing anything else.
        //
        // A change set only became `Expired` lazily, when someone tried to apply
        // it. One that simply ran out of time kept its `Approved` state
        // indefinitely, went on blocking the guard below, and was never eligible
        // for the capacity eviction either — that only retains terminal states.
        // An operator who had lost the id was then locked out of change sets for
        // that device with no MCP-reachable remedy (#193).
        let now = crate::changeset::now_unix()?;
        // No log line here: this crate has no `tracing` dependency and adding
        // one for a single message is not worth it. The transition is durable
        // in the state file and visible through `change_sets()`.
        //
        // What each retirement replaced is kept so the sweep can be undone if
        // the persist below fails.
        let mut retired: Vec<(String, ChangeSetState)> = Vec::new();
        for (id, existing) in &mut state.change_sets {
            // Two deadlines can retire a record: its own approval TTL, and the
            // expiry of the waiver that approved it (#284). The second is
            // checked through the same predicate the apply gate uses.
            if is_expirable(existing.state)
                && (existing.expires_at_unix <= now || crate::apply::waiver_lapsed(existing, now))
            {
                retired.push((id.clone(), existing.state));
                existing.state = ChangeSetState::Expired;
            }
        }

        // Evict terminal change sets if at capacity
        let mut evicted: Vec<ChangeSetRecord> = Vec::new();
        if state.change_sets.len() >= self.limits.max_change_sets {
            state.change_sets.retain(|_, existing| {
                let terminal = matches!(
                    existing.state,
                    ChangeSetState::Applied
                        | ChangeSetState::Expired
                        | ChangeSetState::Failed
                        | ChangeSetState::Cancelled
                );
                if terminal {
                    evicted.push(existing.clone());
                }
                !terminal
            });
        }

        // Both of those changed the store regardless of whether this insert goes
        // on to succeed, so persist them now rather than on the success path
        // alone. Every rejection below returns early; leaving the sweep unwritten
        // would let memory report a record `Expired` while the file still says
        // `Approved`, and a restart would resurrect the blocker this sweep just
        // retired — #193 again, with the fix in place.
        let swept = !retired.is_empty() || !evicted.is_empty();
        if swept && let Err(error) = self.persist_locked(&state) {
            for (id, previous) in retired {
                if let Some(existing) = state.change_sets.get_mut(&id) {
                    existing.state = previous;
                }
            }
            for record in evicted {
                state.change_sets.insert(record.id.clone(), record);
            }
            return Err(error);
        }

        if state.change_sets.len() >= self.limits.max_change_sets {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set store is full",
            ));
        }

        // Enforce one pending change set per principal and device.
        //
        // Expiry is handled above rather than here, so anything still pending at
        // this point is genuinely live.
        if let Some(blocker) = state.change_sets.values().find(|existing| {
            existing.owner == record.owner
                && existing.device == record.device
                && is_pending(existing.state)
        }) {
            // Name the blocker. The bare refusal was a dead end: the status tool
            // requires an id, there was no way to list, and the message did not
            // say which record was in the way (#193).
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "this principal already has a pending change set on the device \
                     (id {}, state {:?}, expires at unix {})",
                    blocker.id, blocker.state, blocker.expires_at_unix
                ),
            ));
        }

        let id = record.id.clone();
        state.change_sets.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            state.change_sets.remove(&id);
            return Err(error);
        }

        Ok(())
    }

    /// Retrieves a change-set record by ID, validating the device.
    ///
    /// # Errors
    ///
    /// Returns an error if the change set does not exist or belongs to a different device.
    pub async fn change_set(
        &self,
        id: &str,
        device: &str,
    ) -> Result<ChangeSetRecord, CoordinatorError> {
        validate_operation_id(id)?;
        let state = self.state.lock().await;
        let record = state
            .change_sets
            .get(id)
            .ok_or_else(|| CoordinatorError::new("change_set_id", "unknown change set"))?;
        if record.device != device {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set belongs to another device",
            ));
        }
        Ok(record.clone())
    }

    /// Seed a record in any state. **Tests only.**
    ///
    /// `insert_change_set` creates `Planned` and nothing else, because any
    /// other state is a door into the lifecycle the transition policy governs.
    /// Tests still need records sitting in `Expired`, `Applying`, `Failed` and
    /// so on to exercise sweeps and refusals, and walking each one through the
    /// full lifecycle would obscure what they are actually asserting.
    ///
    /// Behind a feature to keep it out of an ordinary build — but a feature is
    /// **not** a security boundary, and this must not be read as one. Cargo
    /// features are additive: if any crate in a build enables
    /// `mecmcp-changeset/test-util`, this becomes available to every user of
    /// the package in that build. It is a signpost, not a lock. The boundary
    /// that does hold is `insert_change_set` accepting only `Planned`.
    ///
    /// Still refuses to overwrite an existing id — seeding is creation too.
    ///
    /// # Errors
    ///
    /// Returns an error if the id already exists or if persistence fails.
    #[cfg(feature = "test-util")]
    pub async fn seed_change_set_for_test(
        &self,
        record: ChangeSetRecord,
    ) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        if let Some(existing) = state.change_sets.get(&id) {
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "change set {id} already exists in state {:?}",
                    existing.state
                ),
            ));
        }
        state
            .change_sets
            .insert(id.clone(), normalise_task_handle(record));
        if let Err(error) = self.persist_locked(&state) {
            state.change_sets.remove(&id);
            return Err(error);
        }
        Ok(())
    }

    /// Atomically claim an approved change set for apply.
    ///
    /// Checking `Approved` with `change_set()` and then writing `Applying` with
    /// `update_change_set()` is two operations, and the lock is released
    /// between them. Two applies could therefore both read `Approved`, both
    /// pass the check, and both execute — one approval, two executions. The
    /// second write could also land on top of an `Applied` written by the
    /// first, erasing the outcome.
    ///
    /// For a destroy that is close to harmless, because a second destroy of an
    /// absent guest fails. For an operation that runs an arbitrary command it
    /// is not harmless at all, which is why this exists.
    ///
    /// The check and the transition happen under one lock here, so exactly one
    /// caller can move a record out of `Approved`. Everyone else is refused and
    /// told which state they lost to.
    ///
    /// Pass [`ApplyHandle::None`] when the operation produces no vendor task
    /// handle; see [`ChangeSetRecord::apply_without_handle`].
    ///
    /// # Errors
    ///
    /// Returns an error if the change set is unknown, belongs to another
    /// device, is not `Approved`, or if persistence fails. A claim whose
    /// persistence fails is deliberately **not** rolled back; see the comment
    /// at that branch for why keeping it is the fail-closed choice.
    pub async fn claim_change_set_for_apply(
        &self,
        id: &str,
        device: &str,
        handle: ApplyHandle,
    ) -> Result<ChangeSetRecord, CoordinatorError> {
        validate_operation_id(id)?;
        let mut state = self.state.lock().await;
        let record = state
            .change_sets
            .get(id)
            .ok_or_else(|| CoordinatorError::new("change_set_id", "unknown change set"))?;
        if record.device != device {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set belongs to another device",
            ));
        }
        if record.state != ChangeSetState::Approved {
            // Naming the state it is in matters: "already applying" and
            // "expired" send the caller to different places, and a caller that
            // lost a race needs to know it was a race.
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "change set is {:?}, not Approved; it cannot be claimed for apply",
                    record.state
                ),
            ));
        }

        let previous = record.clone();
        let mut claimed = previous.clone();
        claimed.state = ChangeSetState::Applying;
        claimed.apply_without_handle = matches!(handle, ApplyHandle::None);
        check_change_set_write(Some(&previous), &claimed, WriteVia::ApplyClaim)?;
        state.change_sets.insert(id.to_owned(), claimed.clone());

        if let Err(error) = self.persist_locked(&state) {
            // Deliberately no rollback here, unlike `update_change_set`.
            //
            // `write_state` renames the new file into place before it fsyncs
            // the directory, so a failure can mean either "nothing was written"
            // or "it was written and we cannot prove it is durable". Rolling
            // memory back to `Approved` on the second of those would leave disk
            // saying `Applying` and memory saying `Approved` — and this process
            // would then let a *second* apply claim it.
            //
            // Keeping the claim is the fail-closed choice: the caller gets an
            // error and does not execute, nobody else can claim, and a human
            // resolves a record that is at worst stuck. A replayed approval is
            // the outcome worth spending a stuck record to avoid.
            let _ = previous;
            return Err(error);
        }
        Ok(claimed)
    }

    /// Updates an existing record, refusing the write if the state moved.
    ///
    /// Every lifecycle method reads a record, decides from that snapshot, and
    /// writes it back — with the lock released in between. A claim landing in
    /// that gap used to be erased by a stale cancellation that had already
    /// decided the record was cancellable. Passing the state the caller
    /// actually saw makes the write conditional on nothing having moved since.
    ///
    /// # Errors
    ///
    /// Returns an error if the change set is unknown, if its state is no longer
    /// `observed`, if the transition is not permitted, or if persistence fails.
    pub async fn update_change_set_from(
        &self,
        observed: ChangeSetState,
        record: ChangeSetRecord,
    ) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        let current = state
            .change_sets
            .get(&id)
            .ok_or_else(|| CoordinatorError::new("change_set_id", "unknown change set"))?;
        if current.state != observed {
            return Err(CoordinatorError::new(
                "state",
                format!(
                    "change set moved to {:?} since it was read as {observed:?}; \
                     the update was decided against a state that no longer holds",
                    current.state
                ),
            ));
        }
        let record = normalise_apply_marker(normalise_task_handle(record));
        check_change_set_write(state.change_sets.get(&id), &record, WriteVia::Update)?;
        let previous = state.change_sets.insert(id.clone(), record);
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.change_sets.insert(id, previous);
                }
                None => {
                    state.change_sets.remove(&id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    /// Updates an existing change-set record.
    ///
    /// On persistence failure, the in-memory update is rolled back to the previous value.
    ///
    /// # Errors
    ///
    /// Returns an error if persistence fails.
    pub async fn update_change_set(&self, record: ChangeSetRecord) -> Result<(), CoordinatorError> {
        let mut state = self.state.lock().await;
        let id = record.id.clone();
        // Normalise before the record enters the map, not only on the way to
        // disk. `write_state` drops an empty handle from its own copy, so
        // normalising there alone would leave the coordinator returning
        // `Some("")` from `change_set()` while the file holds `None` — and a
        // restart would then observe a different record than the running
        // process reports. Memory and file must agree.
        let record = normalise_apply_marker(normalise_task_handle(record));

        check_change_set_write(state.change_sets.get(&id), &record, WriteVia::Update)?;

        let previous = state.change_sets.insert(id.clone(), record);

        // Roll back on persist failure
        if let Err(error) = self.persist_locked(&state) {
            match previous {
                Some(previous) => {
                    state.change_sets.insert(id, previous);
                }
                None => {
                    state.change_sets.remove(&id);
                }
            }
            return Err(error);
        }

        Ok(())
    }

    /// Returns the configured approval TTL.
    #[must_use]
    pub fn approval_ttl(&self) -> Duration {
        self.approval_ttl
    }

    /// Returns the configured operation limits.
    #[must_use]
    pub fn limits(&self) -> &OperationLimits {
        &self.limits
    }

    /// Returns whether lab mode is enabled.
    ///
    /// When lab mode is enabled, change sets can be applied without a second
    /// principal approval, and the approval is recorded as waived rather than
    /// fabricating an approver.
    #[must_use]
    pub fn lab_mode(&self) -> bool {
        self.lab_mode
    }

    /// Persists the state to disk atomically.
    ///
    /// This is a low-level method called by insert/update/remove. It assumes the caller
    /// holds the state lock.
    fn persist_locked(&self, state: &ChangesetState) -> Result<(), CoordinatorError> {
        if let Some(path) = &self.state_path {
            // Cross-process, not just in-process: without this, this write
            // can land in the middle of another process's read-modify-write
            // cycle (offline recovery, most commonly) — not corrupting the
            // file itself, since `write_state`'s rename is already atomic,
            // but racing which of the two writes' snapshots wins (MEC-540).
            let _state_lock = StateFileLock::acquire(path)?;
            write_state(path, state, self.limits.max_state_bytes)?;
        }
        Ok(())
    }
}

fn validate_operation_id(value: &str) -> Result<(), CoordinatorError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "operation_id",
            "value must contain exactly 64 hexadecimal characters",
        ))
    }
}

/// Drop an empty vendor task handle, so `Some("")` never enters the store.
///
/// An empty handle names no vendor operation: nothing can re-probe it, yet it
/// is still `Some`, so a recovery path asking `is_none()` reads it as "this
/// apply is recoverable" and holds the record `Applying` forever. Absent means
/// absent.
///
/// Applied at every boundary the record crosses — into the coordinator's map
/// here, and onto disk in `write_state` — because normalising only one of them
/// makes the API and the file disagree about the same change set.
/// Which door a write is coming through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteVia {
    /// Any ordinary update. `Approved -> Applying` is not available here.
    Update,
    /// `claim_change_set_for_apply`, the only holder of that transition.
    ApplyClaim,
}

/// The single point every change-set write passes through.
///
/// One place, because the previous attempt guarded two edges and left the rest
/// of the graph open — an intermediate state reached `Applying` just as well as
/// a direct write did.
fn check_change_set_write(
    current: Option<&ChangeSetRecord>,
    next: &ChangeSetRecord,
    via: WriteVia,
) -> Result<(), CoordinatorError> {
    let Some(current) = current else {
        // An update naming an unknown id used to insert it, which made this an
        // unguarded creation door: a record could arrive already `Applying`, or
        // arrive `Approved` and be claimed, skipping the capacity and
        // one-pending-per-principal checks on the way.
        return Err(CoordinatorError::new(
            "change_set_id",
            "unknown change set; update does not create, and a change set is created \
             Planned through insert_change_set",
        ));
    };

    // 0. A change set's owner, device and plan digest are fixed at creation.
    //
    // Invariant 4 below compares `approver` against `next.owner`, not the
    // owner the record was created with. Without this check a caller can
    // rewrite `owner` to a co-conspirator's name on one write, then approve
    // as the original owner on the next: the approver-versus-owner check
    // passes because both writes individually satisfy it, but the same
    // principal both created and approved the plan. `digest` binds
    // `(owner, device, fingerprint, actions)`, so freezing it here also
    // catches a rewritten owner or device that a stale digest still matches,
    // and stops the record from failing to reload later in
    // `validate_state_with_key`, which recomputes and compares the digest.
    if next.owner != current.owner || next.device != current.device || next.digest != current.digest
    {
        return Err(CoordinatorError::new(
            "change_set_id",
            "a change set's owner, device and plan digest are fixed at creation; \
             plan the operation again",
        ));
    }

    if current.state == ChangeSetState::Approved && next.state == ChangeSetState::Applying {
        if via == WriteVia::ApplyClaim {
            return Ok(());
        }
        return Err(CoordinatorError::new(
            "state",
            "Approved -> Applying must go through claim_change_set_for_apply; writing it \
             here reintroduces the race where two applies both read Approved and both execute",
        ));
    }

    // Three invariants, stated as invariants rather than as guards on the paths
    // that happened to be found. Each earlier version of this block was scoped
    // to one route and was bypassed by another.
    //
    // 1. A preview that is written must be self-consistent.
    //
    // Unconditional, not only for approved records. `approve_change_set` signs
    // the stored preview digest, so a `Planned` record whose artifact and digest
    // already disagree yields a valid approval over an inconsistent preview --
    // claimable in-process, and rejected by `read_state` only at the next
    // restart, taking the whole file with it. Refusing it at the write is the
    // only point where the two values are both present and comparable.
    if next.preview.is_some() {
        next.validate_preview(usize::MAX).map_err(|error| {
            CoordinatorError::new("preview", format!("the preview is invalid: {error}"))
        })?;
    }

    if let Some(current_approval) = current.approval.as_ref() {
        // 2. A granted two-person approval's digest and version are immutable.
        //
        // Without this, invariant 3 is bypassed in two steps: replace the v5
        // approval with a valid v4 one, at which point the record no longer
        // reports v5, then change the preview freely on the next write. The
        // downgraded record stays claimable and reloadable throughout. An
        // approval is evidence of an act that already happened; nothing later
        // has cause to rewrite it.
        //
        // Scoped to a genuine approval (`approver` present) rather than to any
        // approval record. A waiver carries no approver and never binds a
        // preview, so it cannot be the start of that downgrade -- and the
        // expiry TOCTOU that `post_guard_waiver_expiry_check_detects_toctou_rewrite`
        // exercises is a real attack whose detection lives in the apply path,
        // not here. Freezing waivers would remove that test's ability to stage
        // the scenario without removing the attack.
        // Whole-record equality, and removal counts. A previous version compared
        // only the digest and version, which an update setting `approval` to
        // `None` skipped entirely -- and because the top-level `approver` field
        // survives, `apply_change_set` then accepted the record through its
        // legacy-approval path while the preview, no longer bound by anything,
        // was free to be replaced on the next write. Nothing legitimate clears a
        // granted approval: `approval: None` is written once, at creation.
        if current_approval.approver.is_some() && next.approval.as_ref() != Some(current_approval) {
            return Err(CoordinatorError::new(
                "approval",
                "an approval cannot be rewritten or removed once granted; \
                 plan the operation again to produce a new one",
            ));
        }

        // 3. A v5 approval binds the preview digest, so the preview is frozen.
        //
        // The digest check in `read_state` only fires on a reload, so between an
        // in-process swap and the next restart the record still applies while
        // carrying an approval for text that is no longer there. Refusing the
        // write closes that window at its source. Invariant 1 above is what
        // makes this comparison mean anything -- the digest is a field of the
        // record being written, so on its own it proves nothing about the text.
        if current_approval.digest_version >= 5 {
            let current_preview = current
                .preview
                .as_ref()
                .map(|preview| preview.digest.as_str());
            let next_preview = next.preview.as_ref().map(|preview| preview.digest.as_str());
            if current_preview != next_preview {
                return Err(CoordinatorError::new(
                    "preview",
                    "the preview is bound by an approval and cannot be changed; \
                     plan the operation again to produce a new one",
                ));
            }
        }
    }

    // 4. A two-person approval's approver must not be the owner.
    //
    // `approve_change_set` checks this too, but this function is the one door
    // every write passes through -- including a caller that reaches this
    // function directly with a hand-built `ChangeSetRecord`, bypassing
    // `approve_change_set` entirely. Checked unconditionally against `next`,
    // not gated on `current`, because a `Planned` record with no prior
    // approval at all can carry a self-approval the moment it is written.
    if let Some(approver) = next
        .approval
        .as_ref()
        .and_then(|approval| approval.approver.as_ref())
        && *approver == next.owner
    {
        return Err(CoordinatorError::new(
            "approval",
            "the change-set owner cannot approve their own plan",
        ));
    }
    if let Some(approver) = next.approver.as_ref()
        && *approver == next.owner
    {
        return Err(CoordinatorError::new(
            "approver",
            "the change-set owner cannot approve their own plan",
        ));
    }

    if !change_set_transition_allowed(current.state, next.state) {
        return Err(CoordinatorError::new(
            "state",
            format!(
                "{:?} -> {:?} is not a permitted change-set transition",
                current.state, next.state
            ),
        ));
    }

    // The flag is what keeps an in-flight handleless apply out of reach.
    // Clearing it while still `Applying` would let the next write walk the
    // record back to `Approved` through an edge the table does allow.
    if current.state == ChangeSetState::Applying
        && next.state == ChangeSetState::Applying
        && current.apply_without_handle
        && !next.apply_without_handle
    {
        return Err(CoordinatorError::new(
            "state",
            "an in-flight apply with no vendor handle cannot have that marker cleared: \
             whether the operation ran is unknown, and clearing it would permit a \
             second execution",
        ));
    }

    Ok(())
}

/// Clear the handleless marker once the record is no longer in flight.
///
/// It answers one question — "is this `Applying` record's outcome unknown?" —
/// so on a settled record it is noise, and expensive noise: the field forces a
/// version-5 state file, which a binary predating it cannot read. A caller that
/// settles a record by writing `state` alone would otherwise leave it set
/// forever and pin the whole file to v5 for nothing.
fn normalise_apply_marker(mut record: ChangeSetRecord) -> ChangeSetRecord {
    if record.state != ChangeSetState::Applying {
        record.apply_without_handle = false;
    }
    record
}

fn normalise_task_handle(mut record: ChangeSetRecord) -> ChangeSetRecord {
    if record.task_id.as_deref().is_some_and(str::is_empty) {
        record.task_id = None;
    }
    record
}
