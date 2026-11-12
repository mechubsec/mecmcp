//! Single-operation lifecycle methods for device transactions.
//!
//! This module implements the stage → diff → validate → commit → discard
//! lifecycle for individual operations, wrapping the `DeviceTransaction`
//! trait behind fingerprint guards and coordinator persistence.

use crate::{
    coordinator::{ChangesetCoordinator, CoordinatorError},
    lifecycle::LifecycleState,
    records::{OperationRecord, require_operation_fingerprint, require_operation_policy},
    transaction::{CommitOptions, CommitOutcome, DeviceTransaction, RollbackRef},
};
use mecmcp_audit::Attribution;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

/// Canonicalizes an endpoint URL to a consistent form for use as a device guard key.
///
/// This function:
/// - Validates the URL starts with `https://`
/// - Lowercases the scheme and host
/// - Removes trailing slashes from the path
/// - Rejects malformed URLs
///
/// # Errors
///
/// Returns an error if the endpoint is not a valid HTTPS URL.
fn canonicalize_endpoint(endpoint: &str) -> Result<String, CoordinatorError> {
    if !endpoint.starts_with("https://") && !endpoint.starts_with("HTTPS://") {
        return Err(CoordinatorError::new(
            "endpoint",
            "endpoint must start with https://",
        ));
    }

    // Parse the URL to validate structure
    let url = url::Url::parse(endpoint)
        .map_err(|e| CoordinatorError::new("endpoint", format!("invalid endpoint URL: {e}")))?;

    if url.scheme() != "https" {
        return Err(CoordinatorError::new(
            "endpoint",
            "endpoint must use https scheme",
        ));
    }

    // Rebuild with normalized components
    let host = url
        .host_str()
        .ok_or_else(|| CoordinatorError::new("endpoint", "endpoint must contain a valid host"))?;

    let mut canonical = format!("https://{}", host.to_lowercase());

    if let Some(port) = url.port() {
        canonical.push_str(&format!(":{port}"));
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        canonical.push_str(path);
    }

    Ok(canonical)
}

/// Output from staging a single operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageOutput<S> {
    /// Operation identifier (64 hex characters).
    pub operation_id: String,
    /// Opaque staged-transaction handle.
    pub staged: S,
    /// Candidate fingerprint before staging.
    pub before_fingerprint: String,
    /// Candidate fingerprint after staging.
    pub after_fingerprint: String,
}

impl ChangesetCoordinator {
    /// Stage one fingerprint-guarded operation.
    ///
    /// This method:
    /// 1. Acquires the device guard (serializing concurrent access to the same endpoint)
    /// 2. Validates the expected fingerprint matches the device's current state
    /// 3. Calls `transaction.fingerprint()` to capture the before-state
    /// 4. Calls `transaction.stage(actions)` to stage the operation
    /// 5. Calls `transaction.fingerprint()` again to capture the after-state
    /// 6. Persists the operation record in `Staged` state
    ///
    /// The returned `StageOutput` includes the operation ID, the opaque `Staged` handle,
    /// and both fingerprints. The caller must pass the `Staged` handle to later lifecycle
    /// steps.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device guard cannot be acquired (cancelled or endpoint busy)
    /// - The expected fingerprint does not match the device's actual state
    /// - The transaction's `stage()` method fails
    /// - Persistence fails
    ///
    /// # Config authority
    ///
    /// `config_authority` records who owns the device's configuration. Pass the
    /// string representation of the authority discriminant (e.g., `"local"`,
    /// `"mist"`, `"panorama"`). When not `"local"`, changes may be overwritten.
    #[allow(clippy::too_many_arguments)]
    pub async fn stage_operation<T: DeviceTransaction>(
        &self,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        endpoint: &str,
        transaction: &T,
        actions: &[T::Action],
        primary_action_discriminator: &str,
        vendor_primary_target: Option<&str>,
        policy_signature: &str,
        config_authority: Option<String>,
        cancellation: &CancellationToken,
    ) -> Result<StageOutput<T::Staged>, CoordinatorError> {
        // P2-a: Validate non-empty actions
        if actions.is_empty() {
            return Err(CoordinatorError::new(
                "actions",
                "actions must not be empty",
            ));
        }

        // Canonicalize and validate the endpoint
        let canonical_endpoint = canonicalize_endpoint(endpoint)?;

        // Acquire device guard keyed on device name. Two valid addresses for one device
        // (e.g., management IP and DNS name) would otherwise take different locks.
        let _guard = self.device_guard(device, cancellation).await?;

        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Generate operation ID
        let operation_id = crate::changeset::new_operation_id()?;

        // P2-e: Validate expected fingerprint format before persisting. A malformed
        // fingerprint written into the record makes `read_state` reject the entire
        // state file, not just this record — so validation must happen before insert.
        crate::digest::validate_fingerprint(expected_fingerprint)
            .map_err(|e| CoordinatorError::new("expected_candidate_fingerprint", e.to_string()))?;

        // Create initial operation record in Staging state
        let mut record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.to_owned(),
            device: device.to_owned(),
            endpoint: canonical_endpoint.clone(),
            action: serde_json::Value::String(primary_action_discriminator.to_owned()),
            xpath: vendor_primary_target.map(|s| s.to_owned()),
            actions: actions
                .iter()
                .map(|a| {
                    serde_json::to_value(a)
                        .map_err(|e| CoordinatorError::new("actions", e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            change_set_id: None,
            current: expected_fingerprint.to_owned(),
            state: LifecycleState::Staging,
            job_id: None,
            details: None,
            config_lock_held: false,
            policy_signature: policy_signature.to_owned(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority,
        };

        // Insert the record early so restart recovery can see it
        self.insert(record.clone()).await?;

        // Whether the device was actually touched. A failure before staging
        // begins leaves nothing behind, and recording that as `Indeterminate`
        // would be its own kind of lie — it fills the recovery queue with
        // operations that need no recovery, which is how a real one gets missed.
        let mut device_touched = false;

        // Whether this call took a device-side lock, so the error paths know
        // whether there is one to release.
        let mut device_lock_acquired = false;

        // Stage the operation
        let stage_result: Result<_, CoordinatorError> = async {
            // Take the device lock before reading the fingerprint. The check and
            // the staging are only atomic against other sessions while a
            // device-side lock is held: the coordinator's own guard serialises
            // this process and nothing else, so without this an operator at the
            // CLI or a second MCP process can move the candidate in between, and
            // the actions land on a state nobody approved.
            if transaction.requires_config_lock() {
                // Persist the lock risk *before* acquiring, for the same reason
                // the pre-stage persist below exists: if the process dies between
                // taking the lock and recording it, a stored `false` tells the
                // operator no lock is held when one is. Claiming a lock that was
                // never taken costs a no-op unlock; the reverse strands the device.
                record.config_lock_held = true;
                self.update(record.clone()).await?;

                transaction
                    .lock(&format!("mecmcp operation {operation_id}"))
                    .await
                    .map_err(|e| CoordinatorError::new("config_lock", e.to_string()))?;
                device_lock_acquired = true;
            }

            // Capture before fingerprint
            let before_fp = transaction
                .fingerprint()
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            // Validate expected fingerprint matches
            if expected_fingerprint != before_fp {
                return Err(CoordinatorError::new(
                    "expected_candidate_fingerprint",
                    format!(
                        "candidate changed since the caller observed it \
                         (expected {expected_fingerprint}, found {before_fp}); checked before stage"
                    ),
                ));
            }

            // P2-f: Persist lock-risk before the staging RPC. `device_touched` lives
            // only on the stack, so if the process dies after `stage()` takes the
            // device lock or changes the candidate, the persisted record still says
            // `Staging` with `config_lock_held = false`. Restart recovery flips the
            // state to `Indeterminate` but keeps that false flag, telling the operator
            // no lock is held when one may be. Persist the lock-risk now.
            record.config_lock_held = true;
            self.update(record.clone()).await?;

            // Past this point the candidate may have been modified, whatever the
            // outcome, so the record must survive for recovery. Set this AFTER the
            // lock-risk persist succeeds: if the update fails before `transaction.stage()`
            // is ever called, the error path should not treat the operation as unresolved.
            // The failed update rolls back to the original `Staging` record, and without
            // this flag being set correctly, that can leave an operation blocking the
            // endpoint whose ID was never returned to any caller.
            device_touched = true;

            // Stage the transaction
            let staged = transaction
                .stage(actions)
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            // Capture after fingerprint
            let after_fp = transaction
                .fingerprint()
                .await
                .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

            Ok((before_fp, after_fp, staged))
        }
        .await;

        match stage_result {
            Ok((before_fp, after_fp, staged)) => {
                // Update record to Staged state
                record.current = after_fp.clone();
                record.state = LifecycleState::Staged;
                record.config_lock_held = true; // Assume lock held after successful stage

                // If persistence fails after stage() succeeded, the device has been modified
                // and possibly locked, but the final state update fails. Keep the operation
                // as Indeterminate rather than dropping it or leaving a stale Staging record.
                if let Err(persist_error) = self.update(record.clone()).await {
                    // Persist as Indeterminate with the known post-stage fingerprint and lock held.
                    // The `after_fp` is already known from stage() — persisting it instead of the
                    // pre-stage expected_fingerprint gives manual reconciliation the correct state.
                    record.state = LifecycleState::Indeterminate;
                    record.current = after_fp.clone(); // Keep the post-stage fingerprint
                    record.details = Some(format!(
                        "staging succeeded but final persistence failed: {persist_error}"
                    ));
                    record.config_lock_held = true;
                    let _ = self.update(record).await; // Best-effort
                    return Err(CoordinatorError::new(
                        "state",
                        format!(
                            "{persist_error} (operation {operation_id} requires manual reconciliation)"
                        ),
                    ));
                }

                Ok(StageOutput {
                    operation_id,
                    staged,
                    before_fingerprint: before_fp,
                    after_fingerprint: after_fp,
                })
            }
            Err(error) if device_touched => {
                // Staging began. The device may hold changes and a lock, and
                // nothing here established which, so the record is retained as
                // Indeterminate for `resolve_persisted_operation` to settle.
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!(
                    "staging failed after the candidate was touched: {error}"
                ));
                record.config_lock_held = true;
                let _ = self.update(record).await; // Persist best-effort
                Err(CoordinatorError::new(
                    "transaction",
                    format!("{error} (operation {operation_id} requires manual reconciliation)"),
                ))
            }
            Err(error) => {
                // Nothing reached the device — a fingerprint read that failed, or
                // a candidate that had already moved. There is no uncertainty to
                // record, so drop the reservation instead of leaving an operation
                // an operator would have to resolve by hand for no reason.
                //
                // A lock taken on the way in must come back off first, though.
                // Dropping the reservation while the device stays locked is the
                // worst of both: no record anyone can find, and a device that
                // refuses every later change.
                if device_lock_acquired
                    && !matches!(
                        transaction.unlock().await,
                        Ok(crate::transaction::UnlockOutcome::Released)
                    )
                {
                    // The unlock did not confirm a release, so the lock may still
                    // be held and the record is the only thing that can say so.
                    // Keep it rather than dropping it.
                    record.state = LifecycleState::Indeterminate;
                    record.details = Some(format!(
                        "staging failed and the device lock could not be confirmed released: {error}"
                    ));
                    record.config_lock_held = true;
                    let _ = self.update(record).await; // Best-effort
                    return Err(CoordinatorError::new(
                        "config_lock",
                        format!(
                            "{error} (operation {operation_id} may still hold the device lock)"
                        ),
                    ));
                }

                self.remove(&operation_id).await;
                Err(error)
            }
        }
    }

    /// Compute a diff of the staged operation.
    ///
    /// Validates the operation fingerprint still matches the device state, then
    /// calls `transaction.diff(staged)` to compute the diff.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation does not exist or is not owned by this principal and device
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `diff()` method fails
    #[allow(clippy::too_many_arguments)]
    pub async fn diff_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        staged: &T::Staged,
        cancellation: &CancellationToken,
    ) -> Result<T::Diff, CoordinatorError> {
        // Retrieve and validate the operation record
        let record = self.record(operation_id, owner, device).await?;

        // Acquire device guard to serialize with commit and validation
        let _guard = self.device_guard(&record.device, cancellation).await?;

        // `device_guard` can return the guard at the same moment the token fires:
        // `tokio::select!` may take the ready-lock branch. Re-check before issuing
        // any device RPC. A diff only reads, so this is not about damage — it is
        // that an inconsistent rule gets copied into the next method someone adds.
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Re-read the record after acquiring the guard
        let record = self.record(operation_id, owner, device).await?;

        // Reject states that are no longer safely staged. A diff waiting behind a
        // commit can read `Committing` or `Committed`, and since a successful commit
        // often leaves the candidate fingerprint unchanged, the fingerprint guard
        // passes and `transaction.diff` runs against stale state.
        if !matches!(
            record.state,
            LifecycleState::Staged | LifecycleState::Validated | LifecycleState::Failed
        ) {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is no longer in a state where diff is meaningful",
            ));
        }

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp).map_err(|e| {
            CoordinatorError::new(e.field(), format!("{}; checked before diff", e.message()))
        })?;

        // Compute the diff
        let diff = transaction
            .diff(staged)
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        Ok(diff)
    }

    /// Validate the staged operation.
    ///
    /// Validates the operation fingerprint matches, calls `transaction.validate(staged)`,
    /// and transitions `Staged` → `Validating` → `Validated` or `Failed`.
    ///
    /// If the transaction opts in via
    /// [`DeviceTransaction::validate_rewrites_candidate`], every validation attempt,
    /// passed or failed, re-reads the fingerprint (still under the device guard)
    /// and stores it in `record.current`. The caller must then pass [`ChangesetCoordinator::record`]`(..).current`
    /// as the commit's expected fingerprint, not the post-stage one.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is not in `Staged` state
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `validate()` method fails
    /// - Persistence fails
    #[allow(clippy::too_many_arguments)]
    pub async fn validate_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        staged: &T::Staged,
        cancellation: &CancellationToken,
    ) -> Result<T::Validation, CoordinatorError> {
        // Retrieve and validate the operation record
        let record = self.record(operation_id, owner, device).await?;

        if record.state != LifecycleState::Staged {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is not in staged state",
            ));
        }

        // Acquire device guard
        let _guard = self.device_guard(&record.device, cancellation).await?;

        // `device_guard` can return the guard at the same moment the token fires:
        // `tokio::select!` may take the ready-lock branch. Re-check before issuing
        // any device RPC — `<validate>` / `<commit-check>` is not destructive, but
        // it is still work sent to a device the caller has stopped waiting on.
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // P1-b-validate: Re-read state after acquiring guard. Two validations starting
        // from `Staged` both pass the pre-lock check; the second uses its stale record
        // after the first stored `Validated`, re-running validation, and a transient
        // failure there can overwrite the success with `Failed`. Re-read now.
        let mut record = self.record(operation_id, owner, device).await?;

        // Re-check state after acquiring guard
        if record.state != LifecycleState::Staged {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation is not in staged state",
            ));
        }

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp).map_err(|e| {
            CoordinatorError::new(
                e.field(),
                format!("{}; checked before validate", e.message()),
            )
        })?;

        // Transition to Validating
        record.state = LifecycleState::Validating;
        self.update(record.clone()).await?;

        // Perform validation
        let validation_result = transaction.validate(staged).await;

        // An opted-in validation may have written into the candidate whatever it
        // reports: a lost or unparseable reply still ran the check. The device
        // guard serialises this process, and a transaction that opts in holds the
        // device lock from stage through commit, so the fingerprint can only have
        // moved through validate itself. Re-bind the operation to it either way,
        // so commit after a pass and discard after a failure can still pass the
        // guard (rustjunosmcp#626).
        if transaction.validate_rewrites_candidate() {
            match transaction.fingerprint().await {
                Ok(refreshed_fp) => record.current = refreshed_fp,
                Err(error) => {
                    // Keeping the pre-validate fingerprint would leave a record no
                    // commit or discard could ever match again. Hand it to manual
                    // reconciliation, as staging does for a candidate it touched.
                    let outcome = match &validation_result {
                        Ok(_) => "validation passed".to_string(),
                        Err(validation_error) => format!("validation failed ({validation_error})"),
                    };
                    record.state = LifecycleState::Indeterminate;
                    record.details = Some(format!(
                        "{outcome} but the candidate fingerprint could not be re-read: {error}"
                    ));
                    record.config_lock_held = true;
                    self.update(record).await?;
                    return Err(CoordinatorError::new(
                        "transaction",
                        format!(
                            "{error} (operation {operation_id} requires manual reconciliation)"
                        ),
                    ));
                }
            }
        }

        match validation_result {
            Ok(validation) => {
                // Transition to Validated
                record.state = LifecycleState::Validated;
                record.details = None;
                self.update(record).await?;
                Ok(validation)
            }
            Err(error) => {
                // Transition to Failed
                record.state = LifecycleState::Failed;
                record.details = Some(error.to_string());
                self.update(record).await?;
                Err(CoordinatorError::new("transaction", error.to_string()))
            }
        }
    }

    /// Commit the validated operation.
    ///
    /// Spawns the commit and polls for completion. If the commit outcome cannot be
    /// determined (timeout, lock release failure), the operation is marked `Indeterminate`.
    ///
    /// `expected_fingerprint` is the post-validate `record.current` when the
    /// transaction opted into [`DeviceTransaction::validate_rewrites_candidate`].
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is not in `Validated` state
    /// - The operation's fingerprint no longer matches the device state
    /// - The operation's policy signature no longer matches the current policy
    /// - The transaction's `commit()` method fails
    /// - Persistence fails
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        current_policy_signature: &str,
        transaction: &T,
        staged: &T::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
        cancellation: &CancellationToken,
    ) -> Result<CommitOutcome, CoordinatorError> {
        // P1-e: Acquire guard before reading record to prevent concurrent commits
        let record = self.record(operation_id, owner, device).await?;
        let _guard = self.device_guard(&record.device, cancellation).await?;

        // Re-check cancellation after acquiring the guard. If cancellation fires while
        // waiting and the endpoint lock becomes free at the same moment, the guard can
        // take the ready-lock branch. Without this re-check, the commit RPC may be sent
        // despite being cancelled.
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Re-check state after acquiring guard
        let mut record = self.record(operation_id, owner, device).await?;

        if record.state != LifecycleState::Validated {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation must validate successfully before commit",
            ));
        }

        // P1-a: Validate policy signature to detect policy drift
        require_operation_policy(&record, current_policy_signature)
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp).map_err(|e| {
            CoordinatorError::new(e.field(), format!("{}; checked before commit", e.message()))
        })?;

        // Persist who asked for this commit before the device is told to do it.
        // Without it, a restart mid-commit leaves an operation nobody can be
        // attributed for. This goes in its own field rather than `details`,
        // which recovery.rs also writes — one field with two writers would
        // silently lose whichever wrote first.
        record.attribution = Some(crate::records::PersistedAttribution::from(attribution));

        // Everything above — the fingerprint read and the attribution write — is
        // awaited, so cancellation can have fired during any of it while nothing
        // has been sent to the device. Check here, before `Committing`, because
        // past this point a cancellation is recorded as `Indeterminate`.
        //
        // That distinction is the point: `Indeterminate` means "the commit may
        // have reached the device and someone must go and look". Recording it for
        // an operation that provably never left this process is safe but
        // pessimistic, and it puts an entry needing no recovery into the manual
        // recovery queue. Filling that queue with false entries is how a real one
        // gets overlooked.
        // The record is left exactly as it is: still `Staged`, with the candidate
        // sitting on the device. Dropping it here would strand that candidate with
        // no record pointing at it, which is worse than the false recovery entry
        // this check exists to avoid. The caller can retry the commit or discard.
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new(
                "device",
                "operation cancelled before the commit was sent; the operation is still staged",
            ));
        }

        // The device is about to be touched. This is written — and, with a
        // spool attached, persisted — *before* that happens, so a crash during
        // the commit still leaves evidence that the attempt was made. A record
        // written only on the way out cannot describe the case that matters
        // most (mecmcp#292).
        //
        // It also happens before the `Committing` transition below, so a spool
        // that refuses leaves the record exactly where it was — still
        // `Validated`, candidate on the device, retryable once the outbox is
        // writable again. Refusing after the transition would strand it in
        // `Committing` for a commit that never happened.
        if let Some(evidence) = self.evidence() {
            evidence
                .apply_intent(
                    &attribution.request_id.to_string(),
                    record.change_set_id.as_deref().unwrap_or(operation_id),
                    &record.device,
                    &attribution.principal.to_string(),
                )
                .map_err(|error| {
                    // Fail closed. Committing anyway would produce the one state
                    // the chain exists to rule out — a device changed with no
                    // record that anyone tried — and #292 is explicit that such
                    // a gap is worse than no audit at all because it is
                    // invisible.
                    CoordinatorError::new(
                        "device",
                        format!(
                            "commit refused: the apply-intent evidence record could not be \
                             persisted ({error}); the operation is still staged"
                        ),
                    )
                })?;
        }

        // Transition to Committing
        record.state = LifecycleState::Committing;
        self.update(record.clone()).await?;

        // P1-b: Perform the commit with cancellation support
        // If cancelled, return Indeterminate consistently (no detached worker survives)
        let commit_result = tokio::select! {
            result = transaction.commit(staged, attribution, options) => {
                result
            }
            () = cancellation.cancelled() => {
                // Cancellation drops the commit future; outcome is unknown
                record.state = LifecycleState::Indeterminate;
                record.details = Some("commit cancelled; outcome unknown".to_owned());
                self.update(record).await?;
                return Ok(CommitOutcome::Indeterminate {
                    reason: "commit cancelled; outcome unknown".to_owned(),
                });
            }
        };

        match commit_result {
            Ok(CommitOutcome::Reconciled {
                succeeded,
                job_id,
                details,
            }) => {
                // Known outcome
                record.state = if succeeded {
                    LifecycleState::Committed
                } else {
                    LifecycleState::Failed
                };
                record.job_id = job_id.clone();
                record.details = details.clone();
                // P2-g: `Reconciled { succeeded: false }` used to clear the lock flag,
                // but the trait only guarantees release on a *successful* commit.
                // Preserve the held state unless release is established.
                if succeeded {
                    record.config_lock_held = false;
                }
                let receipt_device = record.device.clone();
                let receipt_changeset = record
                    .change_set_id
                    .clone()
                    .unwrap_or_else(|| operation_id.to_owned());
                // The device answered. A failure is recorded as fully as a
                // success — a trail that only shows what worked cannot answer
                // the question anyone actually asks it.
                //
                // Written *before* the local state update, which can fail on a
                // full disk or a permission change. Doing it after meant the `?`
                // below returned first and the chain ended at apply intent for a
                // commit that had reached the device: evidence of an attempt
                // with no outcome, at precisely the moment device state and
                // local state have diverged and someone has to go and look.
                // The receipt describes what the device did, which local
                // persistence cannot retract.
                if let Some(evidence) = self.evidence() {
                    // Unlike the intent, this cannot fail closed: the device has
                    // already acted, and refusing afterwards would not un-act
                    // it. The caller still gets its outcome; a trail that could
                    // not be written is reported here rather than swallowed,
                    // because an evidence gap that nobody hears about is the
                    // condition this whole chain exists to make impossible.
                    if let Err(error) = evidence.result_receipt(
                        &attribution.request_id.to_string(),
                        &receipt_changeset,
                        &receipt_device,
                        // The principal that *applied*, which need not be the
                        // one that proposed -- two-person control exists to
                        // make those different people.
                        &attribution.principal.to_string(),
                        succeeded,
                        // Only a failure's details are an error. A successful
                        // commit's details are warnings or a job note, and
                        // filing those as errors hands every warning-bearing
                        // success back to anyone filtering the trail for
                        // failures.
                        if succeeded {
                            ""
                        } else {
                            details.as_deref().unwrap_or("")
                        },
                    ) {
                        tracing::error!(
                            %error,
                            operation_id,
                            "the device answered but its result receipt could not be \
                             persisted; the evidence chain ends at apply intent"
                        );
                    }
                }

                self.update(record).await?;

                Ok(CommitOutcome::Reconciled {
                    succeeded,
                    job_id,
                    details,
                })
            }
            Ok(CommitOutcome::Detached { job_id }) => {
                // Commit continues in background
                record.job_id = job_id.clone();
                // Keep state as Committing
                self.update(record).await?;
                Ok(CommitOutcome::Detached { job_id })
            }
            Ok(CommitOutcome::Indeterminate { reason }) => {
                // Unknown outcome - this is the critical case
                record.state = LifecycleState::Indeterminate;
                record.details = Some(reason.clone());
                // Keep config_lock_held as-is since we don't know if it was released
                self.update(record).await?;
                Ok(CommitOutcome::Indeterminate { reason })
            }
            Ok(CommitOutcome::AwaitingConfirmation {
                job_id,
                rollback_deadline_unix,
                details,
            }) => {
                // P2-h: Persist confirmed-commit deadlines. On `AwaitingConfirmation`
                // the `rollback_deadline_unix` went only into the response, not the
                // record. If the client loses the response or the server restarts,
                // nothing knows when the provisional commit rolls back or whether
                // confirmation is still valid. Store it as structured state.
                record.job_id = job_id.clone();
                record.details = details.clone();
                record.rollback_deadline_unix = Some(rollback_deadline_unix);
                // Clear the lock flag: the transaction contract guarantees a successful
                // confirmed commit releases the candidate lock (the commit succeeded
                // provisionally and no longer holds the lock). Leaving `config_lock_held`
                // set would record a lock as held when it is not.
                record.config_lock_held = false;
                // Keep in Committing state until confirmed
                self.update(record).await?;
                Ok(CommitOutcome::AwaitingConfirmation {
                    job_id,
                    rollback_deadline_unix,
                    details,
                })
            }
            Err(error) => {
                // Commit failed before reaching the device or during execution
                record.state = LifecycleState::Failed;
                record.details = Some(error.to_string());
                self.update(record).await?;
                Err(CoordinatorError::new("transaction", error.to_string()))
            }
        }
    }

    /// Discard the operation without committing.
    ///
    /// Calls `transaction.rollback(RollbackRef::CandidateRevert)`, releases the
    /// configuration lock if held, and transitions to `Discarded`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation is in a state that cannot be discarded
    /// - The operation's fingerprint no longer matches the device state
    /// - The transaction's `rollback()` method fails
    /// - Lock release fails after a successful discard (operation marked `Indeterminate`)
    /// - Persistence fails
    pub async fn discard_operation<T: DeviceTransaction>(
        &self,
        operation_id: &str,
        device: &str,
        owner: &str,
        expected_fingerprint: &str,
        transaction: &T,
        cancellation: &CancellationToken,
    ) -> Result<String, CoordinatorError> {
        // Retrieve and validate the operation record
        let record = self.record(operation_id, owner, device).await?;

        // Cannot discard operations in certain states
        if matches!(
            record.state,
            LifecycleState::Validating
                | LifecycleState::Committing
                | LifecycleState::Committed
                | LifecycleState::Discarded
                | LifecycleState::Indeterminate
        ) {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation cannot be discarded in its current state",
            ));
        }

        // Acquire device guard
        let _guard = self.device_guard(&record.device, cancellation).await?;

        // Re-check cancellation after acquiring the guard. If cancellation fires while
        // waiting and the endpoint lock becomes free at the same moment, the guard can
        // take the ready-lock branch. Without this re-check, the method proceeds to a
        // destructive rollback despite being cancelled.
        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // P1-a-discard: Re-read state after acquiring the guard. Discard reads a
        // `Validated` record, then waits behind `commit_operation`. The commit
        // persists `Committed`; discard proceeds with its stale record, and because
        // a commit usually leaves the candidate fingerprint unchanged the fingerprint
        // guard passes — so the stale update overwrites `Committed` with `Discarded`.
        // A committed change would be recorded as discarded. Re-read and re-check now.
        let mut record = self.record(operation_id, owner, device).await?;

        // Re-check state after acquiring guard
        if matches!(
            record.state,
            LifecycleState::Validating
                | LifecycleState::Committing
                | LifecycleState::Committed
                | LifecycleState::Discarded
                | LifecycleState::Indeterminate
        ) {
            return Err(CoordinatorError::new(
                "operation_id",
                "operation cannot be discarded in its current state",
            ));
        }

        // Validate fingerprint
        let actual_fp = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("transaction", e.to_string()))?;

        require_operation_fingerprint(&record, expected_fingerprint, &actual_fp).map_err(|e| {
            CoordinatorError::new(
                e.field(),
                format!("{}; checked before discard", e.message()),
            )
        })?;

        // Persist an in-flight state before issuing the rollback RPC. If the process
        // exits after the rollback request reaches the device but before the await
        // returns, the persisted record would still be `Staged`, `Validated`, or
        // `Failed`. Restart recovery ignores those states — and if the revert actually
        // succeeded, the changed candidate fingerprint blocks any retry of discard, so
        // the operation and a possibly-held lock have no route to recovery. Persist an
        // in-progress record BEFORE the rollback call, then settle it afterwards.
        record.state = LifecycleState::Indeterminate;
        record.details = Some("rollback in progress".to_owned());
        self.update(record.clone()).await?;

        // Rollback the candidate
        let rollback_result = transaction.rollback(RollbackRef::CandidateRevert).await;

        match rollback_result {
            Ok(outcome) if outcome.succeeded => {
                // Rollback succeeded; proceed to unlock
            }
            Ok(outcome) => {
                // Rollback failed cleanly; the device rejected it
                record.state = LifecycleState::Failed;
                record.details = outcome.details.clone();
                self.update(record).await?;
                return Err(CoordinatorError::new(
                    "transaction",
                    outcome
                        .details
                        .unwrap_or_else(|| "rollback failed".to_owned()),
                ));
            }
            Err(e) => {
                // Rollback error is ambiguous: the device may have performed the revert
                // but the response was lost or timed out. The candidate fingerprint has
                // changed by now, so every retry fails the fingerprint guard, and neither
                // restart nor manual recovery handles `Staged`/`Failed` states — only
                // `Indeterminate`. Record the uncertainty.
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!("rollback outcome unknown: {e}"));
                self.update(record).await?;
                return Err(CoordinatorError::new("transaction", e.to_string()));
            }
        }

        // P1-c-persist: Persist rollback completion as non-terminal until unlock is
        // established. If the process exits after rollback succeeds but before
        // `unlock()` completes, a terminal `Discarded` state with `config_lock_held
        // = true` would leave a held lock with no recovery path: terminal records
        // are ignored by restart recovery, are evictable, and do not block another
        // operation. Persist an in-progress state first.
        record.state = LifecycleState::Indeterminate;
        record.details = Some("candidate reverted; verifying lock release".to_owned());
        self.update(record.clone()).await?;

        // P1-c: Attempt to unlock via rollback; if that doesn't release the lock,
        // the implementation must provide explicit unlock support
        match transaction.unlock().await {
            Ok(crate::transaction::UnlockOutcome::Released) => {
                record.config_lock_held = false;
                record.state = LifecycleState::Discarded;
                record.details = Some("candidate reverted".to_owned());
            }
            Ok(crate::transaction::UnlockOutcome::Unsupported) => {
                // P1-d: An unreleased lock must not end terminal. When `unlock()`
                // returns the default `Unsupported` and the rollback did not release
                // the lock, the method keeps `config_lock_held = true` but would
                // return success with state `Discarded`. `Discarded` is terminal and
                // evictable, another discard is refused, and offline recovery only
                // accepts `Indeterminate` — so the held lock has no route to
                // resolution. Keep the state as `Indeterminate`.
                record.state = LifecycleState::Indeterminate;
                record.details = Some(
                    "candidate reverted; the transaction offers no explicit unlock, \
                     so the configuration lock state is unchanged"
                        .to_owned(),
                );
                // Persist the unresolved state before returning error
                self.update(record).await?;
                return Err(CoordinatorError::new(
                    "transaction",
                    "candidate reverted but the configuration lock state could not be verified; manual reconciliation required",
                ));
            }
            Err(error) => {
                // The revert landed but the unlock did not. That is not a clean
                // discard, and recording it as one would hide a held lock.
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!("candidate reverted but unlock failed: {error}"));
                record.config_lock_held = true;
                self.update(record).await?;
                return Err(CoordinatorError::new(
                    "transaction",
                    format!(
                        "candidate reverted but the configuration lock could not be released: {error}"
                    ),
                ));
            }
        }

        // Capture the after-discard fingerprint (best-effort)
        let after_fp = transaction.fingerprint().await.map_err(|e| {
            // Fingerprint read failed but rollback succeeded; persist what we know
            record.details = Some(format!("candidate reverted; fingerprint read failed: {e}"));
            e
        });

        match after_fp {
            Ok(fp) => {
                record.current = fp.clone();
                // Leave `details` alone: the unlock step may have recorded that
                // the configuration lock state is unchanged, and clearing it here
                // would drop the one note explaining why `config_lock_held` is
                // still set on a record that otherwise reads as a clean discard.
                self.update(record).await?;
                Ok(fp)
            }
            Err(e) => {
                // Persist Indeterminate state if fingerprint cannot be read
                record.state = LifecycleState::Indeterminate;
                self.update(record).await?;
                Err(CoordinatorError::new("transaction", e.to_string()))
            }
        }
    }
}
