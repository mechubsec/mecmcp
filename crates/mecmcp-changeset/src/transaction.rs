//! Device transaction trait and associated types.
//!
//! The [`DeviceTransaction`] trait abstracts vendor-specific configuration
//! transactions behind a common lifecycle: fingerprint → stage → diff →
//! validate → commit. Both PAN-OS (XPath set/delete + detached commit workers)
//! and Junos (NETCONF candidate/commit with synchronous operations and
//! confirmed-commit auto-rollback) implement this trait without adapters.

use async_trait::async_trait;
use mecmcp_audit::Attribution;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Fingerprint-bound change transaction on a vendor device.
///
/// Implementations must guarantee:
///
/// - **Fingerprint stability:** Two consecutive [`fingerprint()`](Self::fingerprint)
///   calls with no intervening mutation return the same value. Background changes
///   by another session invalidate a staged operation's fingerprint binding; the
///   coordinator detects this during [`diff()`](Self::diff) or
///   [`validate()`](Self::validate) and fails the operation.
///
/// - **Stage atomicity:** [`stage()`](Self::stage) applies all actions or none.
///   A partial failure (e.g., second action fails) must revert the first action
///   before returning an error. The returned `Staged` handle represents a
///   consistent snapshot. This holds for every implementation, including one
///   reporting [`Atomicity::atomic_apply`] `= false` -- the coordinator's apply
///   path depends on it. See [`stage()`](Self::stage) for why that declaration
///   does not yet relax this.
///
/// - **Indeterminate honesty:** [`commit()`](Self::commit) returns
///   [`CommitOutcome::Indeterminate`] on timeout or cancellation rather than
///   guessing the remote state. The caller persists recovery instructions and
///   exposes manual reconciliation. An implementation must never silently resolve
///   an unknown outcome as success or failure.
///
/// - **Fingerprint scope:** What the fingerprint covers is vendor-specific.
///   PAN-OS fingerprints the operator-authorized candidate subtrees listed in
///   inventory policy. Junos fingerprints the entire candidate configuration
///   database. A vendor with no candidate database fingerprints the running
///   state of the resources it will touch. All are stable (same input → same
///   hash) and binding (any change to the in-scope content changes the hash).
///   An implementation documents its scope and guarantees the hash detects all
///   mutations within that scope.
#[async_trait]
pub trait DeviceTransaction: Send + Sync {
    /// Vendor-specific action type.
    ///
    /// PAN-OS: `{action: Set|Delete, xpath: String, element: Option<String>}`.
    /// Junos: `{payload: ConfigPayload, rollback_source: Option<u32>}`.
    ///
    /// The shared crate requires only `Serialize + DeserializeOwned + Send + Sync`.
    /// There is no common action trait; the two vendors have no shared interface
    /// beyond serde.
    type Action: Serialize + for<'de> Deserialize<'de> + Send + Sync;

    /// Opaque staged-transaction handle returned by [`stage()`](Self::stage)
    /// and passed to later lifecycle steps.
    ///
    /// PAN-OS: captures `config_lock_held`, `operation_id`, fingerprints.
    /// Junos: captures the NETCONF session, the diff, and lock state.
    ///
    /// The coordinator stores this opaque and passes it back to
    /// [`diff()`](Self::diff), [`validate()`](Self::validate), and
    /// [`commit()`](Self::commit).
    type Staged: Send + Sync;

    /// Diff output. Vendor-specific format (XML, text, JSON).
    type Diff: Serialize + Send + Sync;

    /// Validation result.
    ///
    /// Must report whether validation succeeded, any job identifier for async
    /// validation, and details (warnings, errors, etc.). The exact shape is
    /// vendor-specific.
    type Validation: Serialize + Send + Sync;

    /// Transaction-specific error.
    ///
    /// Must implement `std::error::Error + Send + Sync + 'static` for use in
    /// `Box<dyn Error>` and async contexts.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Compute a stable fingerprint over the configuration state this
    /// transaction will mutate.
    ///
    /// # Fingerprint contract
    ///
    /// The fingerprint is a `sha256:<64 lowercase hex>` string computed over
    /// the configuration this transaction will mutate -- the device's candidate
    /// database, or the in-scope subset of it.
    ///
    /// **A vendor with no candidate database hashes its running state instead** --
    /// the resources this transaction will touch, before it touches them.
    ///
    /// That is a weaker guarantee, and worth naming rather than glossing: it
    /// detects that the target moved, but it cannot detect that someone staged
    /// something else alongside this change, because nothing can be staged.
    /// What it binds is drift, not exclusivity. Such a vendor is the one
    /// declaring [`Atomicity::live_writes`] from
    /// [`atomicity()`](Self::atomicity), and that declaration -- not this
    /// fingerprint -- is what tells shared code the whole shape is weaker.
    ///
    /// The stability and binding requirements below still apply in full over
    /// whatever scope is chosen. A running-state hash is a different scope, not
    /// a licence to be unstable.
    ///
    /// It must be:
    ///
    /// - **Stable:** Two consecutive calls with no intervening mutation return
    ///   the same value.
    /// - **Binding:** Any mutation to the in-scope configuration changes the
    ///   fingerprint. This is the guarantee that lets the coordinator detect
    ///   unexpected changes.
    /// - **Scoped:** What the fingerprint covers is implementation-defined.
    ///   PAN-OS hashes the candidate subtrees listed in inventory policy (not
    ///   the entire running config). Junos would hash the entire candidate
    ///   database via `<get-configuration database="candidate"/>`. A live-write
    ///   vendor hashes the running state of the resources it will touch. All
    ///   are valid; the scope must be documented and stable.
    ///
    /// # Device changes underneath
    ///
    /// If another session mutates the candidate between fingerprint capture
    /// and stage/commit, the post-stage fingerprint will differ from the
    /// pre-stage fingerprint, and the coordinator will fail the operation
    /// with a fingerprint-mismatch error. This is the intended behavior:
    /// the operator's plan was bound to a specific pre-state, and that
    /// pre-state no longer exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable, the candidate cannot
    /// be read, or the implementation's configured scope (e.g., PAN-OS
    /// `allowed_xpath_root`) is invalid.
    async fn fingerprint(&self) -> Result<String, Self::Error>;

    /// Stage one or more actions atomically.
    ///
    /// All actions succeed or all fail. A partial failure (e.g., the second
    /// action fails after the first succeeds) must revert the first action
    /// before returning an error.
    ///
    /// **This is still required of every implementation, including one that
    /// reports [`atomicity()`](Self::atomicity) `atomic_apply: false`.** The
    /// coordinator's apply path depends on it: `apply_change_set` treats a
    /// `stage()` error as all-or-none, marks the change set `Failed`, and
    /// removes the operation record, on the stated grounds that "nothing is on
    /// the device". A vendor that left earlier writes applied would strand
    /// those changes with no operation record and no reconciliation detail.
    ///
    /// So `atomic_apply: false` is, for now, a statement *about* a vendor and
    /// not yet a licence to behave differently here. It exists so shared code
    /// can describe what an operator is consenting to. Driving a genuinely
    /// non-atomic vendor through `apply_change_set` needs the coordinator to
    /// retain a reconcilable record for a partial failure first; until that
    /// exists, such a vendor must confine its live writes to
    /// [`commit()`](Self::commit), where an indeterminate outcome is already
    /// modelled by [`CommitOutcome::Indeterminate`].
    ///
    /// Returns a vendor-specific `Staged` handle that the coordinator passes
    /// back opaque to [`diff()`](Self::diff), [`validate()`](Self::validate),
    /// and [`commit()`](Self::commit).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The device is unreachable or the configuration lock cannot be acquired.
    /// - Any action fails validation (e.g., PAN-OS XPath outside policy, Junos
    ///   payload parse failure).
    /// - A partial-stage revert fails. In this case the implementation should
    ///   mark the session tainted and close it rather than pool it.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error>;

    /// Compute a diff of the staged changes.
    ///
    /// PAN-OS: `<show><config><list><change-summary/></list></config></show>`.
    /// Junos: the diff was captured during [`stage()`](Self::stage) (via
    /// `<get-configuration compare="rollback" rollback="0"/>`); this method
    /// returns it.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable or the diff RPC fails.
    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error>;

    /// Validate the staged transaction.
    ///
    /// PAN-OS: `<validate><full/></validate>`, poll the job until complete.
    /// Junos: `<commit-check/>`, wait for the synchronous RPC to complete.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The device is unreachable or the validation RPC fails.
    /// - Validation completes but reports the configuration is invalid. The
    ///   error should carry the device's rejection message.
    ///
    /// Note: Junos `<commit-check/>` on a chassis cluster returns an
    /// unparseable multi-RE reply that rustnetconf cannot parse. An
    /// implementation must distinguish "the device rejected the config"
    /// (`Invalid`) from "the check could not reach a verdict" (`CheckFailed`).
    /// See `candidate_transaction.rs:classify_check_error` for the pattern.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error>;

    /// Whether a successful [`validate`](Self::validate) may itself change the
    /// fingerprinted candidate.
    ///
    /// Junos `<commit-check/>` assigns a `uid` to a new login user and writes it
    /// into the candidate, so the fingerprint observed after staging no longer
    /// matches by commit time (rustjunosmcp#626). When this returns `true` the
    /// coordinator re-reads the fingerprint after a successful validation and
    /// binds the operation to it; the caller must then pass
    /// [`ChangesetCoordinator::record`](crate::ChangesetCoordinator::record)`(..).current` as the commit's expected fingerprint.
    ///
    /// Return `true` only if the implementation also holds an exclusive
    /// configuration lock from stage through commit, so that no other writer
    /// can change the candidate during validation. Without that lock a refresh
    /// would absorb another session's concurrent edit, which the fingerprint
    /// guard exists to catch; that is why the default is `false`.
    fn validate_rewrites_candidate(&self) -> bool {
        false
    }

    /// Commit the validated transaction.
    ///
    /// Must wait for the operation to complete and return a known outcome, or
    /// return [`CommitOutcome::Indeterminate`] if the outcome is unknown
    /// (timeout, cancellation, lock-release failure after a successful commit).
    ///
    /// # Attribution
    ///
    /// The `attribution` parameter carries the principal, change reference,
    /// agent identity, and request ID for on-device commit logs and audit.
    /// Junos writes this into the commit comment:
    /// `commit comment "CHG0012345 by alice via claude-opus-5"`. PAN-OS writes
    /// it into `<commit><description>...</description></commit>`.
    ///
    /// The attribution is also serialized into the persisted operation record
    /// for audit, independent of what the device logs.
    ///
    /// # Confirmed commit (Junos)
    ///
    /// Junos `<commit confirmed="N"/>` commits the configuration and schedules
    /// an automatic rollback after N seconds unless the operator runs a
    /// confirming commit. This is a safety feature: if the operator loses
    /// connectivity after the commit, the device reverts itself.
    ///
    /// PAN-OS has no equivalent. The `options` parameter allows Junos to
    /// express this via `CommitOptions { confirm_timeout: Some(Duration) }`,
    /// and PAN-OS to pass `CommitOptions::default()`.
    ///
    /// **Critical:** A Junos confirmed commit does NOT apply the commit comment.
    /// The comment is silently dropped. An implementation must document this
    /// and either apply the comment in a second confirming commit, or omit the
    /// comment and log the attribution separately. The trait makes no
    /// requirement; it only documents the constraint so implementers and
    /// callers are aware.
    ///
    /// # Detached workers
    ///
    /// PAN-OS commits are asynchronous: the `<commit>` RPC returns a job ID,
    /// and the caller polls `<show><jobs><id>N</id></jobs></show>` until the
    /// job completes. If the caller cancels, the commit continues in the
    /// background. In this case the implementation returns
    /// [`CommitOutcome::Detached`] with the job ID, and the coordinator
    /// persists it so the operator can poll for completion.
    ///
    /// Junos commits are synchronous: the `<commit/>` RPC waits for the
    /// operation to complete. `Detached` is not used. If the commit RPC times
    /// out, the outcome is unknown, and the implementation must return
    /// [`CommitOutcome::Indeterminate`].
    ///
    /// # Lock release failure
    ///
    /// A successful commit must release the configuration lock (PAN-OS) or
    /// unlock the candidate database (Junos). If the unlock RPC fails after
    /// a successful commit, the commit succeeded but the lock state is unknown.
    /// This is also [`CommitOutcome::Indeterminate`]: the operator must check
    /// the device and run manual reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable or the commit RPC fails
    /// before reaching the device. A commit that reaches the device but fails
    /// validation or application returns
    /// [`CommitOutcome::Reconciled { succeeded: false }`], not an error.
    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error>;

    /// Rollback to a named or numbered checkpoint.
    ///
    /// Junos: [`RollbackRef::Archive(N)`](RollbackRef::Archive) loads rollback
    /// archive N via `<load-configuration rollback="N"/>` and commits it.
    /// `RollbackRef::CandidateRevert` loads rollback 0 (clears uncommitted
    /// candidate changes) without committing.
    ///
    /// PAN-OS: `RollbackRef::CandidateRevert` runs
    /// `<revert><config><partial><admin>...</admin></partial></config></revert>`,
    /// reverting candidate changes attributed to the configured admin.
    /// `RollbackRef::Archive(N)` is unsupported (no archive-based rollback).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The device is unreachable or the rollback RPC fails.
    /// - The requested archive does not exist (Junos).
    /// - The rollback target is unsupported by this implementation (e.g.,
    ///   `Archive(N)` on PAN-OS).
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error>;

    /// What this implementation can guarantee about applying a change set.
    ///
    /// **The default guarantees nothing, and that is deliberate.** An earlier
    /// draft defaulted to the candidate-configuration answer so that Junos and
    /// PAN-OS needed no edit. That is the wrong direction for a safety signal:
    /// it hands every implementation that has not thought about the question a
    /// claim of atomicity, dry-run validation and guaranteed rollback.
    ///
    /// It was also immediately untrue. `rustsdcmcp` has five implementations of
    /// this trait -- firewall, NAT, object, device-sync and license -- and SDC
    /// has no candidate store at all; `SdcFirewallTransaction::stage` only
    /// validates a prepared plan locally and its rollback says "no remote
    /// candidate exists". An optimistic default would have had all five report
    /// dry-run validation and reliable rollback they do not have, in the exact
    /// approval prompt this method exists to make honest.
    ///
    /// So: a vendor that genuinely has candidate configuration says so, with
    /// [`Atomicity::candidate_configuration`]. Everything else under-claims
    /// until someone checks, which is the direction that cannot mislead an
    /// approver.
    fn atomicity(&self) -> Atomicity {
        Atomicity::nothing_guaranteed()
    }

    /// Whether this implementation wants a device configuration lock held
    /// across a coordinator operation.
    ///
    /// The default is `false`: a vendor with no lock concept, or one whose
    /// deployment has not enabled locking, is unchanged. When this returns
    /// `true` the coordinator calls [`lock()`](Self::lock) before reading the
    /// fingerprint and [`unlock()`](Self::unlock) once the operation finishes.
    fn requires_config_lock(&self) -> bool {
        false
    }

    /// Acquire the device configuration lock.
    ///
    /// # Scope
    ///
    /// The lock is held for **one coordinator operation** — the
    /// fingerprint-read through staging window — and not across a change set's
    /// whole lifecycle. That limit is not a simplification: on Junos the lock
    /// is bound to the NETCONF session, so it cannot outlive it, and promising
    /// callers more than one operation's worth of protection would be a claim
    /// the implementation cannot keep.
    ///
    /// What it does close is the race this exists for. Without it, another
    /// session — a second MCP process, an operator at the CLI, Panorama — can
    /// move the candidate between the fingerprint check and staging, and the
    /// actions land on a state nobody approved. The coordinator's in-process
    /// mutex serialises only this server's own callers.
    ///
    /// The default is a no-op `Ok(())` so implementations that do not lock keep
    /// compiling. Pair it with [`requires_config_lock()`](Self::requires_config_lock):
    /// returning `false` from that method means this is never called.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable, or if the lock is already
    /// held by another administrator. A refused lock must fail the operation
    /// rather than proceed unlocked — proceeding is the exact condition the
    /// lock was requested to prevent.
    async fn lock(&self, _comment: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Release the device configuration lock, if this implementation holds one.
    ///
    /// Reverting a candidate is not the same as releasing the lock — on PAN-OS
    /// the commit lock survives a revert — so a coordinator that cleared its
    /// `config_lock_held` flag after a rollback would be recording something it
    /// never verified, and the device would stay locked against every later
    /// change while the state file said otherwise.
    ///
    /// The default returns [`UnlockOutcome::Unsupported`] so existing
    /// implementations keep compiling; a caller receiving it must leave the
    /// recorded lock state alone rather than assume the lock is gone.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable or refuses the unlock. The
    /// caller should treat that as an unresolved operation, not a clean discard.
    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        Ok(UnlockOutcome::Unsupported)
    }

    /// Issue a confirming commit after a confirmed commit (Junos only).
    ///
    /// When [`commit()`](Self::commit) with `CommitOptions { confirm_timeout: Some(N) }`
    /// returns [`CommitOutcome::AwaitingConfirmation`], the device has committed
    /// the configuration but will automatically roll it back after N seconds
    /// unless a confirming commit is issued.
    ///
    /// This method issues that confirming commit, which:
    ///
    /// 1. Prevents the auto-rollback (the change becomes permanent).
    /// 2. Applies a commit comment carrying the attribution and referencing the
    ///    confirmed commit, so the provenance lands on the device even though
    ///    the initial confirmed commit dropped the comment.
    ///
    /// The comment format is implementation-defined but must make the linkage
    /// explicit. Example (Junos):
    /// `"Confirming commit <operation_id>: CHG0012345 by alice via anthropic-public, claude-opus-5, none, dev@example.com"`
    ///
    /// # PAN-OS behavior
    ///
    /// PAN-OS has no confirmed commit feature. An implementation should return
    /// an error stating the operation is unsupported, exactly as
    /// [`rollback(RollbackRef::Archive(N))`](Self::rollback) does on PAN-OS.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The device is unreachable or the confirming commit RPC fails.
    /// - The operation is unsupported by this vendor (PAN-OS).
    /// - There is no confirmed commit awaiting confirmation (the operation ID
    ///   does not match a pending confirmed commit).
    async fn confirm_commit(
        &self,
        operation_id: &str,
        attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error>;
}

/// What a vendor's transaction implementation can actually guarantee.
///
/// [`DeviceTransaction`] was derived from two vendors that both have candidate
/// configuration -- Junos NETCONF and PAN-OS candidate/commit. Both can stage
/// an arbitrary set of changes off to the side, diff it against running,
/// validate it on-box, and apply it atomically. The trait's guarantees were
/// written as that answer, for every vendor.
///
/// A vendor whose API writes directly to live configuration has none of the
/// three. Every write is an immediate, independent request; there is no
/// candidate to hash, nothing to validate before applying, and no checkpoint to
/// return to. Such an implementation is not defective -- the promise was simply
/// never true for it.
///
/// This exists so shared code can *say so*. The value lands in the approval
/// prompt: an operator approving a change set against a live-write API is not
/// getting commit-confirmed semantics, and a renderer that assumes the
/// candidate-configuration answer tells them otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Atomicity {
    /// Applying the change set lands all of its mutations, or none.
    ///
    /// `false` means the vendor's API cannot offer that: the mutations reach
    /// the device one request at a time during [`DeviceTransaction::commit`],
    /// so a failure part-way leaves earlier ones applied.
    ///
    /// **This says nothing about [`DeviceTransaction::stage`],** which is
    /// all-or-none for every implementation regardless of this field -- the
    /// coordinator removes the operation record on a stage error and would
    /// strand anything left behind. A vendor that cannot stage without writing
    /// does not write in `stage()`; it defers to `commit()`, where
    /// [`CommitOutcome::Indeterminate`] already models an outcome the process
    /// cannot resolve.
    pub atomic_apply: bool,

    /// The device can validate the change before it is applied.
    ///
    /// `false` means [`DeviceTransaction::validate`] cannot consult the device
    /// and any check it performs is local.
    pub dry_run_validation: bool,

    /// A failed apply can be returned to the pre-change state reliably.
    ///
    /// `false` means [`DeviceTransaction::rollback`] is best-effort
    /// compensation: the revert is itself a live write that can fail.
    pub guaranteed_rollback: bool,
}

impl Atomicity {
    /// The candidate-configuration answer: all three guaranteed.
    ///
    /// Junos and PAN-OS. This is the default, so neither changes.
    #[must_use]
    pub const fn candidate_configuration() -> Self {
        Self {
            atomic_apply: true,
            dry_run_validation: true,
            guaranteed_rollback: true,
        }
    }

    /// None of the three guaranteed. The default.
    ///
    /// Both the honest answer for a live-write API and the safe answer for an
    /// implementation that has not declared one: an approval prompt keyed on
    /// this describes no guarantee it cannot demonstrate.
    #[must_use]
    pub const fn nothing_guaranteed() -> Self {
        Self {
            atomic_apply: false,
            dry_run_validation: false,
            guaranteed_rollback: false,
        }
    }

    /// The live-write answer, which is the same as guaranteeing nothing.
    ///
    /// Spelled separately because a vendor declaring it means something the
    /// default does not: someone looked, and the answer is no.
    #[must_use]
    pub const fn live_writes() -> Self {
        Self::nothing_guaranteed()
    }

    /// Whether every guarantee holds.
    ///
    /// The one question a renderer usually needs: if this is false, the prompt
    /// must not describe the change as all-or-nothing.
    #[must_use]
    pub const fn is_fully_guaranteed(&self) -> bool {
        self.atomic_apply && self.dry_run_validation && self.guaranteed_rollback
    }
}

impl Default for Atomicity {
    /// Guarantees nothing, matching [`DeviceTransaction::atomicity`]'s default.
    fn default() -> Self {
        Self::nothing_guaranteed()
    }
}

/// Rollback target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackRef {
    /// Load a numbered rollback archive and commit it (Junos only).
    ///
    /// Junos: `<load-configuration rollback="N"/>` followed by `<commit/>`.
    /// PAN-OS: unsupported (returns an error).
    Archive(u32),

    /// Revert uncommitted candidate changes without committing.
    ///
    /// Junos: `<load-configuration rollback="0"/>` (clears the candidate).
    /// PAN-OS: `<revert><config><partial><admin>...</admin></partial></config></revert>`.
    CandidateRevert,

    /// Vendor-specific rollback target (e.g., named checkpoint).
    ///
    /// The string is opaque to the shared crate and interpreted by the
    /// implementation. Use this for vendor-specific rollback mechanisms
    /// that do not fit `Archive` or `CandidateRevert`.
    ///
    /// This is also where best-effort compensation belongs. A vendor reporting
    /// [`Atomicity::guaranteed_rollback`] `= false` has no checkpoint to name,
    /// so it describes its own pre-image here -- there is deliberately no
    /// dedicated variant, because adding one would break every exhaustive match
    /// in the consuming servers to express something `Custom` already carries.
    Custom(String),
}

/// Options for commit behavior.
///
/// This type allows Junos to express confirmed-commit auto-rollback and
/// PAN-OS to reject unsupported options explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOptions {
    /// Junos confirmed commit: automatically rollback after this duration
    /// unless a confirming commit is issued.
    ///
    /// Junos: translates to `<commit confirmed="{seconds}"/>`.
    /// PAN-OS: **returns an error** if `Some(...)`. Silently ignoring a
    /// requested auto-rollback safety feature is worse than an error — the
    /// operator believes the device will revert itself and it will not.
    ///
    /// **Critical Junos behavior:** A confirmed commit does NOT apply the
    /// commit comment. The comment is silently dropped by Junos. The
    /// attribution is applied later via [`confirm_commit()`](DeviceTransaction::confirm_commit),
    /// which issues a second commit carrying the comment and referencing
    /// the confirmed commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm_timeout: Option<Duration>,
}

/// Commit outcome or detached/indeterminate acknowledgement.
///
/// This enum distinguishes three cases:
///
/// 1. **Reconciled:** The commit reached a known terminal state (success or
///    failure).
/// 2. **Detached:** The caller cancelled but the commit continues in the
///    background (PAN-OS async commits).
/// 3. **Indeterminate:** The outcome is unknown (timeout, lock-release failure
///    after success). Manual reconciliation required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum CommitOutcome {
    /// Commit reached a known terminal state.
    Reconciled {
        /// Whether the commit succeeded.
        succeeded: bool,
        /// Job identifier, if the commit was asynchronous (PAN-OS).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<String>,
        /// Human-readable details (warnings, errors, job status).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },

    /// Caller cancelled; commit continues in background (PAN-OS only).
    ///
    /// The coordinator persists the job ID and the operation remains in
    /// `Committing` state until the operator polls for completion.
    Detached {
        /// Job identifier for polling.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<String>,
    },

    /// Outcome is unknown; manual reconciliation required.
    ///
    /// This variant is returned when:
    ///
    /// - The commit RPC times out (Junos synchronous commit).
    /// - The commit succeeds but the unlock RPC fails (lock state unknown).
    /// - The commit job is cancelled mid-flight and the final state cannot
    ///   be determined (PAN-OS).
    ///
    /// The coordinator persists this state and exposes
    /// `resolve_persisted_operation(confirmation: "RESOLVED {id} AS COMMITTED|DISCARDED")`
    /// for manual reconciliation. The operator checks the device state
    /// (`show system commit`, `show configuration`, etc.) and resolves the
    /// persisted operation.
    Indeterminate {
        /// Human-readable reason (e.g., "commit RPC timed out after 600s",
        /// "unlock failed after successful commit").
        reason: String,
    },

    /// Confirmed commit awaiting confirmation (Junos only).
    ///
    /// The commit succeeded and is active, but the device will automatically
    /// rollback after the configured timeout unless a confirming commit is
    /// issued.
    ///
    /// This variant allows the coordinator to track that the commit is
    /// provisional and expose a `confirm_commit(operation_id)` tool to
    /// issue the confirming commit.
    ///
    /// PAN-OS does not use this variant (no confirmed commit feature).
    AwaitingConfirmation {
        /// Job identifier, if applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<String>,
        /// When the device will auto-rollback if not confirmed (unix timestamp).
        rollback_deadline_unix: u64,
        /// Human-readable details.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<String>,
    },
}

/// Result of asking a transaction to release the device configuration lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockOutcome {
    /// The lock was released. The coordinator may record it as no longer held.
    Released,
    /// This implementation offers no explicit unlock, so nothing can be said
    /// about the lock. The coordinator must NOT record the lock as released:
    /// on PAN-OS a candidate revert leaves the commit lock in place, and a
    /// state file claiming otherwise sends an operator looking in the wrong
    /// place when the next change is blocked.
    Unsupported,
}

/// Rollback outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackOutcome {
    /// Whether the rollback succeeded.
    pub succeeded: bool,
    /// Human-readable details (warnings, errors).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[cfg(test)]
mod atomicity_tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("unused in these tests")]
    struct NoError;

    /// Does not override `atomicity()`, so it takes the trait default.
    struct UndeclaredVendor;
    /// Declares the candidate-configuration answer, like Junos and PAN-OS.
    struct CandidateVendor;
    /// Declares the live-write answer, like SDC or UniFi.
    struct LiveWriteVendor;

    macro_rules! stub_transaction {
        ($name:ident $(, $atomicity:expr)?) => {
            #[async_trait]
            impl DeviceTransaction for $name {
                type Action = String;
                type Staged = ();
                type Diff = String;
                type Validation = String;
                type Error = NoError;

                $( fn atomicity(&self) -> Atomicity { $atomicity } )?

                async fn fingerprint(&self) -> Result<String, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn stage(&self, _: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn diff(&self, _: &Self::Staged) -> Result<Self::Diff, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn validate(
                    &self,
                    _: &Self::Staged,
                ) -> Result<Self::Validation, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn commit(
                    &self,
                    _: &Self::Staged,
                    _: &Attribution,
                    _: &CommitOptions,
                ) -> Result<CommitOutcome, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn rollback(&self, _: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
                async fn confirm_commit(
                    &self,
                    _: &str,
                    _: &Attribution,
                ) -> Result<CommitOutcome, Self::Error> {
                    unimplemented!("these tests only read atomicity()")
                }
            }
        };
    }

    stub_transaction!(UndeclaredVendor);
    stub_transaction!(CandidateVendor, Atomicity::candidate_configuration());
    stub_transaction!(LiveWriteVendor, Atomicity::live_writes());

    /// The default must guarantee nothing.
    ///
    /// An optimistic default would hand a claim of atomicity, dry-run
    /// validation and reliable rollback to every implementation that has not
    /// considered the question -- including rustsdcmcp's five, where SDC has no
    /// candidate store at all. This is the assertion that stops that.
    ///
    /// Exercised through a real `DeviceTransaction` that does **not** override
    /// `atomicity()`, so it reads the trait's own default body. Asserting
    /// `Atomicity::nothing_guaranteed()` directly would only prove that
    /// constructor and would pass with the default body changed to anything.
    #[test]
    fn an_implementation_that_does_not_override_guarantees_nothing() {
        let got = <UndeclaredVendor as DeviceTransaction>::atomicity(&UndeclaredVendor);
        assert!(!got.atomic_apply);
        assert!(!got.dry_run_validation);
        assert!(!got.guaranteed_rollback);
        assert!(
            !got.is_fully_guaranteed(),
            "an undeclared vendor must not be described to an approver as guaranteed"
        );
        assert_eq!(got, Atomicity::default());
    }

    /// A vendor that does have candidate configuration says so explicitly, and
    /// that is what shared code sees.
    #[test]
    fn a_candidate_vendor_declares_its_guarantees() {
        let got = <CandidateVendor as DeviceTransaction>::atomicity(&CandidateVendor);
        assert!(got.is_fully_guaranteed());
        assert_eq!(got, Atomicity::candidate_configuration());
    }

    /// A live-write vendor declaring `live_writes()` and an undeclared one land
    /// on the same value -- but the declaration means someone looked.
    #[test]
    fn a_live_write_vendor_matches_the_default() {
        let got = <LiveWriteVendor as DeviceTransaction>::atomicity(&LiveWriteVendor);
        assert!(!got.is_fully_guaranteed());
        assert_eq!(got, Atomicity::nothing_guaranteed());
    }

    /// A live-write vendor answers no to all three, and a renderer can tell.
    #[test]
    fn the_live_write_constructor_guarantees_nothing() {
        let got = Atomicity::live_writes();
        assert!(!got.atomic_apply);
        assert!(!got.dry_run_validation);
        assert!(!got.guaranteed_rollback);
        assert!(
            !got.is_fully_guaranteed(),
            "a prompt keyed on this would have described the change as all-or-nothing"
        );
    }

    /// Partial answers are representable: a vendor may validate but not apply
    /// atomically. The type must not collapse to a single boolean.
    #[test]
    fn the_three_guarantees_are_independent() {
        let partial = Atomicity {
            atomic_apply: false,
            dry_run_validation: true,
            guaranteed_rollback: false,
        };
        assert!(!partial.is_fully_guaranteed());
        assert!(partial.dry_run_validation);
    }

    /// It crosses the wire with the change-set record, so the field names are
    /// part of the on-disk shape.
    #[test]
    fn it_round_trips_through_serde_with_stable_field_names() {
        let json = serde_json::to_string(&Atomicity::live_writes()).expect("serialize");
        assert_eq!(
            json,
            r#"{"atomic_apply":false,"dry_run_validation":false,"guaranteed_rollback":false}"#
        );
        let back: Atomicity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, Atomicity::live_writes());
    }
}
