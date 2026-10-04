//! Change-set apply operation.

use crate::lifecycle::ApplyHandle;
use crate::{
    changeset::{new_operation_id, now_unix},
    coordinator::{ChangesetCoordinator, CoordinatorError},
    digest::validate_digest,
    lifecycle::{ChangeSetState, LifecycleState},
    records::OperationRecord,
    transaction::DeviceTransaction,
};
use mecmcp_audit::Attribution;
use mecmcp_redact::Untrusted;
use serde::Serialize;
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
    // Parse the URL to validate structure
    let url = url::Url::parse(endpoint)
        .map_err(|e| CoordinatorError::new("endpoint", format!("invalid endpoint URL: {e}")))?;

    // Any scheme is accepted. This value identifies a device and is used as a
    // guard key; it is not dialled. PAN-OS supplies an HTTPS management URL,
    // Junos a NETCONF-over-SSH address, and requiring `https` forced the latter
    // to persist a false endpoint to pass validation (#69). What matters is
    // that it parses, has a host, and canonicalizes stably so two spellings of
    // one device cannot take separate locks.

    // Rebuild with normalized components
    let host = url
        .host_str()
        .ok_or_else(|| CoordinatorError::new("endpoint", "endpoint must contain a valid host"))?;

    let mut canonical = format!("{}://{}", url.scheme(), host.to_lowercase());

    if let Some(port) = url.port() {
        canonical.push_str(&format!(":{port}"));
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        canonical.push_str(path);
    }

    Ok(canonical)
}

/// Whether `change_set` was approved by a waiver that has lapsed as of `now`.
///
/// Shared by the apply gates and by the retirement sweeps in `coordinator` and
/// `changeset` so the two cannot disagree. They did disagree before #284: apply
/// refused a lapsed record while every read path went on reporting it
/// `Approved`, and a sweep written separately could reintroduce that in the
/// narrower form of an off-by-one on the boundary second.
///
/// A waiver with no `expires_at_unix` never lapses — that absence is the only
/// thing lab mode can mean.
pub(crate) fn waiver_lapsed(change_set: &crate::records::ChangeSetRecord, now: u64) -> bool {
    change_set
        .approval
        .as_ref()
        .and_then(|approval| approval.waived.as_ref())
        .and_then(|waiver| waiver.expires_at_unix)
        .is_some_and(|expires_at| now >= expires_at)
}

/// Returns an error when `change_set` was approved by a waiver whose
/// `expires_at_unix` has passed as of `now`.
///
/// Takes `now` rather than reading the clock so each call site can pass the
/// instant it already observed: the pre-guard and post-guard checks are
/// deliberately separated in time to detect TOCTOU attacks.
///
/// The `gate` parameter distinguishes the pre-guard check (before the device lock)
/// from the post-guard check (after acquiring it, on a freshly re-read change set)
/// so the error message identifies which gate fired. This helps operators diagnose
/// whether the waiver had already lapsed when they started, or lapsed while waiting
/// for the device lock.
///
/// # Errors
///
/// Returns a `CoordinatorError` if the waiver has expired.
fn waiver_expiry_error(
    change_set: &crate::records::ChangeSetRecord,
    now: u64,
    gate: &str,
) -> Option<CoordinatorError> {
    if waiver_lapsed(change_set, now) {
        Some(CoordinatorError::new(
            "change_set_id",
            format!(
                "waiver expired: this change set was approved by a time-boxed waiver that has \
                 lapsed ({gate}), so it requires a fresh approval or a new waiver"
            ),
        ))
    } else {
        None
    }
}

/// Output from applying a change set.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutput<S> {
    /// Operation identifier assigned during apply.
    pub operation_id: String,
    /// Candidate fingerprint before the change set was applied.
    pub before_fingerprint: String,
    /// Candidate fingerprint after the change set was applied.
    pub after_fingerprint: String,
    /// Vendor-specific staged handle returned by the transaction.
    #[serde(skip)]
    pub staged: S,
    /// The change-set state actually persisted, which is not always `Applied`.
    ///
    /// The device staging can succeed and the final record write still fail. The
    /// staged handle has to be returned regardless — dropping it would strand the
    /// operation with no way to commit or discard — so the caller is handed the
    /// handle plus the truth about what reached disk. Anything other than
    /// `Applied` here means the device changed and the record did not, and the
    /// operation needs resolving before the change set is treated as done.
    pub recorded_state: ChangeSetState,
}

impl ChangesetCoordinator {
    /// Applies an independently approved change set.
    ///
    /// This is the apply step: the caller provides an approved change-set ID and the
    /// coordinator validates the approval is fresh, acquires the device guard, stages
    /// all actions through the device transaction, and records the operation.
    ///
    /// On partial failure (e.g., the third action fails), the coordinator auto-reverts
    /// any staged changes and marks the change set as `Failed`. The change set must NOT
    /// be left looking `Applied` after a partial failure.
    ///
    /// # Cross-process atomicity limitation
    ///
    /// The in-process device guard serializes concurrent `apply_change_set` calls within
    /// this process, but it cannot exclude external sessions (other processes, SSH, GUI).
    /// Between the fingerprint check and the `stage()` call, an external session could
    /// mutate the candidate, causing actions to be staged onto a state that was never
    /// approved.
    ///
    /// To narrow the window, this method re-reads the fingerprint immediately before
    /// staging and compares it to the expected value. This is not true atomicity —
    /// that requires a device-side lock held across the check-then-stage sequence —
    /// but it detects drift that happens in the (now much smaller) window. A future
    /// task will add a device-lock primitive to close the window entirely.
    ///
    /// # Lab mode
    ///
    /// A change set approved by waiver (lab mode enabled, `ApprovalRecord.waived` is
    /// `Some`) is legitimately applicable. The approval check accepts both genuine
    /// two-person approvals and waived approvals.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected digest or fingerprint format is invalid
    /// - The endpoint format is invalid (must start with `https://`)
    /// - The change set does not exist or belongs to another device
    /// - The change set is not owned by the specified owner
    /// - The change set is not in `Approved` state
    /// - The approval has expired
    /// - The supplied digest or fingerprint does not match the stored values exactly
    /// - The device guard cannot be acquired (cancellation)
    /// - Any action fails to stage (the change set is marked `Failed`)
    /// - Persistence fails
    ///
    /// # Attribution
    ///
    /// `attribution` is accepted but not yet consumed. Applying a change set only
    /// *stages* it; nothing is written to the device's running configuration here,
    /// and it is [`commit_operation`](Self::commit_operation) that puts attribution
    /// into the commit log. The parameter is on this signature so the call site
    /// carries it from the start rather than acquiring it later — but be aware that
    /// today an apply records no attribution of its own.
    ///
    /// # Config authority
    ///
    /// `config_authority` records who owns the device's configuration. Pass the
    /// string representation of the authority discriminant from the device's
    /// `ConfigAuthority<A>` field (e.g., `"local"`, `"mist"`, `"panorama"`).
    /// When the authority is not `"local"`, changes may be overwritten by the
    /// owning management plane. This value is stored in the operation record
    /// and should be included in audit events to distinguish durable changes
    /// from transient ones.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_change_set<T: DeviceTransaction>(
        &self,
        change_set_id: String,
        device: String,
        endpoint: String,
        owner: String,
        expected_digest: String,
        expected_fingerprint: String,
        transaction: &T,
        primary_action_discriminator: &str,
        vendor_primary_target: Option<&str>,
        config_authority: Option<String>,
        _attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<ApplyOutput<T::Staged>, CoordinatorError> {
        // Validate inputs
        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;
        crate::digest::validate_fingerprint(&expected_fingerprint)
            .map_err(|e| CoordinatorError::new("expected_fingerprint", e.to_string()))?;

        // Canonicalize and validate the endpoint before using it as a device guard key
        let endpoint = canonicalize_endpoint(&endpoint)?;

        // Retrieve and validate the change set before acquiring the device guard
        let mut change_set = self.change_set(&change_set_id, &device).await?;

        if change_set.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the principal that created the change set may apply it",
            ));
        }

        if change_set.state != ChangeSetState::Approved {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set requires approval before apply",
            ));
        }

        // An approval obtained by a waiver is only an approval while the waiver
        // is valid. Checked here rather than at waive time because expiry is a
        // property of the moment of use, not of the moment of grant.
        let now_for_waiver = now_unix()?;
        if let Some(error) = waiver_expiry_error(&change_set, now_for_waiver, "before device guard")
        {
            return Err(error);
        }

        // Validate approval is present and either genuine or waived.
        // Legacy compatibility: records created before the approval-digest feature have
        // `approver: Some(...)` but `approval: None`. Accept both forms.
        if let Some(approval) = &change_set.approval {
            // New tamper-evident approval: must have either an approver or a waiver
            if approval.approver.is_none() && approval.waived.is_none() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approval record must contain either an approver or a waiver",
                ));
            }
            // Defense in depth: `check_change_set_write` refuses to persist a
            // self-approved record, but this is the function that actually
            // executes against the device, so it does not trust that every
            // record in the store necessarily passed through that gate (a
            // state file older than that check, for instance).
            if let Some(approver) = approval.approver.as_ref()
                && *approver == change_set.owner
            {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "change set was approved by its own owner; refusing to apply",
                ));
            }
            // A waiver digest is unkeyed (compute_waiver_digest_v3 needs no
            // key), so it verifies on its own hash regardless of whether this
            // deployment currently runs in lab mode. Someone with write access
            // to the state file could write a well-formed waiver record for a
            // change set that was never actually waived under lab mode, and
            // loading it would treat it as a valid approval. `waive_approval`
            // already refuses to create a waiver outside lab mode; re-check it
            // here too, since lab mode can be toggled off (or the record can be
            // moved to a deployment where it never was on) between waiving and
            // applying (MEC-457 review, finding 1, "also check").
            if approval.waived.is_some() && !self.lab_mode() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "change set was approved by a lab-mode waiver, but lab mode is not enabled on this deployment",
                ));
            }
            // Strict verified-approver mode exists so a second verified
            // human, not a waiver or a token-asserted approver, signs off.
            // `mechanism` is HMAC-covered by the approval digest (v7), so it
            // cannot be forged post hoc without the digest key. This also
            // closes a transition gap: a token-asserted approval recorded
            // before strict mode was turned on would otherwise still apply
            // once it is (MEC-994 Percy review F10).
            if self.require_verified_approver()
                && (approval.waived.is_some() || approval.mechanism.as_deref() != Some("oidc"))
            {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approval is refused under strict verified-approver mode: the change set \
                     was not approved by a verified human approver",
                ));
            }
        } else {
            // Legacy approval: must have an approver in the top-level field
            if change_set.approver.is_none() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approved change set missing approval record",
                ));
            }
            if let Some(approver) = change_set.approver.as_ref()
                && *approver == change_set.owner
            {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "change set was approved by its own owner; refusing to apply",
                ));
            }
            // Legacy records predate the approval-digest feature entirely,
            // so there is no `mechanism` to check; under strict mode none of
            // them can be a verified human approval (MEC-994 Percy review
            // F10).
            if self.require_verified_approver() {
                return Err(CoordinatorError::new(
                    "change_set_id",
                    "approval is refused under strict verified-approver mode: the change set \
                     was not approved by a verified human approver",
                ));
            }
        }

        let now = now_unix()?;
        if now >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.update_change_set(change_set).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "approved change set expired",
            ));
        }

        if change_set.digest != expected_digest
            || change_set.expected_candidate_fingerprint != expected_fingerprint
        {
            return Err(CoordinatorError::new(
                "expected_digest",
                "apply input does not match the exact approved plan",
            ));
        }

        // Acquire device guard to serialize concurrent operations.
        // Use the change-set's device field (trusted inventory identity) as the guard key,
        // not the caller-supplied endpoint. Two different endpoints for the same device
        // (e.g., DNS name vs IP, or two DNS names) must serialize through the same guard.
        let _guard = self.device_guard(&device, cancellation).await?;

        if cancellation.is_cancelled() {
            return Err(CoordinatorError::new("device", "operation cancelled"));
        }

        // Re-check the change set after acquiring the guard
        change_set = self.change_set(&change_set_id, &device).await?;

        let now_after_guard = now_unix()?;

        if change_set.owner != owner
            || change_set.state != ChangeSetState::Approved
            || change_set.digest != expected_digest
            || change_set.expected_candidate_fingerprint != expected_fingerprint
        {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is no longer the exact unexpired approved plan",
            ));
        }

        // An approval obtained by a waiver is only an approval while the waiver
        // is valid. Checked here rather than at waive time because expiry is a
        // property of the moment of use, not of the moment of grant.
        if let Some(error) =
            waiver_expiry_error(&change_set, now_after_guard, "after acquiring device guard")
        {
            return Err(error);
        }

        // Check expiration after acquiring the guard. If the TTL elapses while waiting
        // for a busy guard, transition the change set to Expired rather than proceeding.
        if now_after_guard >= change_set.expires_at_unix {
            change_set.state = ChangeSetState::Expired;
            self.update_change_set(change_set).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set expired while waiting for device guard",
            ));
        }

        // Remembered so a failed final write can report what is really on disk
        // rather than claiming a state that was never persisted.
        // (Not currently used, but left for clarity about the intent.)
        let _change_set_state_before_apply = change_set.state;

        // Capture the before fingerprint
        let before_fingerprint = transaction
            .fingerprint()
            .await
            .map_err(|e| CoordinatorError::new("device", format!("fingerprint failed: {e}")))?;

        // Validate the device state matches the expected fingerprint
        if before_fingerprint != expected_fingerprint {
            return Err(CoordinatorError::new(
                "expected_fingerprint",
                format!(
                    "device fingerprint changed: expected {}, found {}",
                    expected_fingerprint, before_fingerprint
                ),
            ));
        }

        // Reject legacy plans with empty policy signature before staging.
        // A pre-upgrade change set has `policy_signature = ""` (the field is now
        // `#[serde(default)]`), so apply would create a staged operation that the
        // existing `require_operation_policy` guard will then reject against any
        // non-empty current signature. Such a plan is allowed to mutate the device
        // but can never proceed through the guarded lifecycle. Reject it before
        // staging with a clear error, rather than letting it touch the device and
        // strand.
        if change_set.policy_signature.is_empty() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set created before policy signatures were tracked; cannot apply",
            ));
        }

        // Deserialize actions before marking the change set as Applying
        let actions: Vec<T::Action> = change_set
            .actions
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                serde_json::from_value(value.clone()).map_err(|e| {
                    CoordinatorError::new(
                        "actions",
                        format!("failed to deserialize action {}: {}", idx, e),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Generate operation ID
        let operation_id = new_operation_id()?;

        // Create operation record in staging state BEFORE calling the device
        let operation_record = OperationRecord {
            id: operation_id.clone(),
            owner: owner.clone(),
            device: device.clone(),
            endpoint: endpoint.clone(),
            // The deployed v1 record stores the vendor's discriminator string here
            // ("set"/"delete") with the full object in `actions`, and the vendor's
            // primary target in `xpath`. Both are vendor-shaped, so this crate takes
            // them rather than guessing them from `actions[0]` — writing the whole
            // object here produced a v1 file the deployed PAN-OS reader could not
            // parse. Matches `stage_operation`.
            action: serde_json::Value::String(primary_action_discriminator.to_owned()),
            xpath: vendor_primary_target.map(|s| s.to_owned()),
            actions: change_set.actions.clone(),
            change_set_id: Some(change_set_id.clone()),
            current: before_fingerprint.clone(),
            state: LifecycleState::Staging,
            job_id: None,
            details: Some(format!(
                "staging change set {} with {} actions",
                change_set_id,
                actions.len()
            )),
            config_lock_held: false,
            policy_signature: change_set.policy_signature.clone(),
            attribution: None,
            rollback_deadline_unix: None,
            config_authority,
        };

        self.insert(operation_record).await?;

        // Claim the change set, rather than writing `Applying` onto the copy
        // read earlier. That read and this write used to be two operations with
        // the lock released between them, so two applies could both see
        // `Approved` and both proceed. The claim does the check and the
        // transition under one lock, so exactly one gets through and the rest
        // are refused here instead of at the device.
        //
        // On failure the operation reservation is removed, or the endpoint
        // stays blocked by an apply that never started.
        let mut change_set = match self
            .claim_change_set_for_apply(&change_set.id, &change_set.device, ApplyHandle::Expected)
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                self.remove(&operation_id).await;
                return Err(error);
            }
        };
        change_set.operation_id = Some(operation_id.clone());
        if let Err(error) = self.update_change_set(change_set.clone()).await {
            self.remove(&operation_id).await;
            return Err(error);
        }

        // Persist the risk that stage() may acquire a device lock. If the process exits
        // after stage() acquires a lock but before it returns, the record on disk must
        // reflect that a lock may be held so restart recovery can flag it for manual
        // inspection. Set config_lock_held to true BEFORE the pre-stage fingerprint check
        // and the stage() call, so a crash during stage() leaves the risk persisted.
        // This must be the LAST persistence write before stage() to minimize the window
        // where an external session could mutate the candidate between the fingerprint
        // check and the stage() call.
        let mut pre_stage_record = self.record(&operation_id, &owner, &device).await?;
        pre_stage_record.config_lock_held = true;
        if let Err(persist_error) = self.update(pre_stage_record).await {
            // Persistence failed before we called stage(), so no lock has been acquired.
            // Remove the operation reservation and fail the apply.
            self.remove(&operation_id).await;
            change_set.state = ChangeSetState::Failed;
            let _ = self.update_change_set(change_set).await;
            return Err(persist_error);
        }

        // Take the device lock, if this implementation has one. The lock-risk is
        // already persisted above, so a crash between here and the record write
        // still leaves the risk visible to restart recovery.
        let device_lock_acquired = if transaction.requires_config_lock() {
            if let Err(lock_error) = transaction
                .lock(&format!("mecmcp change set {change_set_id}"))
                .await
            {
                // Nothing has been staged and no lock is held, so this is a clean
                // failure — but the record says a lock may be held, so clear that
                // before dropping the reservation.
                self.remove(&operation_id).await;
                change_set.state = ChangeSetState::Failed;
                let _ = self.update_change_set(change_set).await;
                return Err(CoordinatorError::new(
                    "config_lock",
                    format!("could not acquire the device configuration lock: {lock_error}"),
                ));
            }
            true
        } else {
            false
        };

        // The in-process guard cannot exclude external sessions (other processes, SSH,
        // GUI). Between the fingerprint read below and the stage() call, another session
        // could mutate the candidate.
        //
        // When the implementation takes a device lock (above), that window is genuinely
        // closed. When it does not — `requires_config_lock()` is false — re-reading the
        // fingerprint immediately before staging is the best available mitigation: it is
        // not atomicity, but it detects drift in the much smaller remaining window. The
        // pre-stage fingerprint read and the stage() call must be adjacent with NO
        // persistence operations in between, so an external mutation cannot slip through
        // during a write.
        let pre_stage_fingerprint = match transaction.fingerprint().await {
            Ok(fp) => fp,
            Err(e) => {
                // Fingerprint read failed before staging — the operation was inserted as Staging
                // and the change set marked Applying, but stage() was never called and the device
                // was never touched. Remove the operation and restore or terminally fail the
                // change set before returning.
                if device_lock_acquired {
                    let _ = transaction.unlock().await; // Best-effort; nothing was staged.
                }
                self.remove(&operation_id).await;
                change_set.state = ChangeSetState::Failed;
                let _ = self.update_change_set(change_set.clone()).await;
                return Err(CoordinatorError::new(
                    "device",
                    format!("pre-stage fingerprint failed: {e}"),
                ));
            }
        };

        if pre_stage_fingerprint != expected_fingerprint {
            // Drift detected before staging — clean up the reservation and fail the change set.
            // With a device lock held this should be unreachable for external mutation; it
            // still fires when the candidate moved before the lock was taken.
            if device_lock_acquired {
                let _ = transaction.unlock().await; // Best-effort; nothing was staged.
            }
            self.remove(&operation_id).await;
            change_set.state = ChangeSetState::Failed;
            let _ = self.update_change_set(change_set.clone()).await;
            return Err(CoordinatorError::new(
                "expected_fingerprint",
                format!(
                    "device fingerprint changed between check and stage: expected {}, found {}",
                    expected_fingerprint, pre_stage_fingerprint
                ),
            ));
        }

        // Stage all actions through the transaction
        let staged = match transaction.stage(&actions).await {
            Ok(staged) => staged,
            Err(error) => {
                // The DeviceTransaction::stage contract guarantees that on partial
                // failure (e.g., action 2 fails after action 1 succeeds), the
                // implementation reverts action 1 before returning an error.
                // A failed partial-stage revert obliges the implementation to mark
                // the session tainted and close it. Therefore, the coordinator does
                // NOT revert here — doing so would be redundant and dangerous
                // (a candidate revert clears ALL uncommitted changes, including
                // pre-existing operator work).

                // Mark change set as Failed. The stage contract is all-or-none, so nothing
                // is on the device and the operation reservation must be removed regardless
                // of whether this bookkeeping succeeds.
                change_set.state = ChangeSetState::Failed;
                let changeset_update_result = self.update_change_set(change_set).await;

                // Remove the staging operation record unconditionally. If the change-set
                // update failed, we still remove the operation so the endpoint is unblocked.
                self.remove(&operation_id).await;

                // Return the first error we encountered
                changeset_update_result?;

                // `error` is the vendor transaction's own words (a NETCONF
                // reply, a PAN-OS API error body), not something this process
                // composed — wrap it as untrusted so it stays visibly marked
                // once a tool result carries `CoordinatorError`'s message to
                // the model (mecmcp-server's `tool_error` renders whatever
                // `Display` gives it verbatim).
                let tagged_error =
                    Untrusted::new(error.to_string()).render_tagged("device.stage_error");
                return Err(CoordinatorError::new(
                    "device",
                    format!("staging failed: {tagged_error}"),
                ));
            }
        };

        // Capture the after fingerprint
        let after_fingerprint = match transaction.fingerprint().await {
            Ok(fp) => fp,
            Err(error) => {
                // Fingerprint read failed after a successful stage. DO NOT revert:
                // 1. The approved fingerprint may legitimately include pre-existing
                //    uncommitted work.
                // 2. Both Junos rollback-0 and PAN-OS partial admin revert clear more
                //    than just this change set — they would destroy unrelated operator work.
                //
                // Mark the operation as Indeterminate FIRST, before updating the change set,
                // so if the change-set update fails we still have the operation state recorded.
                // Same as the stage error above: `error` is the device's own
                // words, tagged once and reused for both the persisted
                // operation record and the returned `CoordinatorError`.
                let tagged_error =
                    Untrusted::new(error.to_string()).render_tagged("device.fingerprint_error");

                let mut record = self.record(&operation_id, &owner, &device).await?;
                record.state = LifecycleState::Indeterminate;
                record.details = Some(format!(
                    "fingerprint read failed after staging: {tagged_error}; staged changes remain on device"
                ));
                self.update(record).await?;

                // Then mark the change set as Failed. Treat this as secondary: if it errors,
                // the operation state is already recorded correctly.
                change_set.state = ChangeSetState::Failed;
                let _ = self.update_change_set(change_set).await;

                return Err(CoordinatorError::new(
                    "device",
                    format!(
                        "fingerprint read failed after staging: {tagged_error}; operation is indeterminate"
                    ),
                ));
            }
        };

        // Update operation record to Staged state with the after fingerprint
        let mut operation_record = self.record(&operation_id, &owner, &device).await?;
        operation_record.current = after_fingerprint.clone();
        operation_record.state = LifecycleState::Staged;
        operation_record.details = Some(format!(
            "applied change set {} with {} actions",
            change_set_id,
            actions.len()
        ));
        // A successful stage may hold a configuration lock (PAN-OS) or candidate lock (Junos).
        // The trait does not expose whether a lock is held, so we conservatively record that
        // a lock may be held. Later discard/commit operations must attempt to release it.
        operation_record.config_lock_held = true;

        // Persist the operation update. If that write fails, the handle must still
        // reach the caller — returning `Err` would drop the only `T::Staged`, and
        // the operation would remain in Staging (or be marked Indeterminate on
        // restart), possibly holding a device lock, with no handle able to commit
        // or discard it. The same rationale that applies to the change-set write
        // below applies here: return the handle regardless of persistence outcome.
        if let Err(_persist_error) = self.update(operation_record.clone()).await {
            // The Staged record write failed. The earlier config_lock_held write
            // succeeded, so the on-disk state is Staging with config_lock_held=true.
            // Try to mark it Indeterminate so restart recovery flags it, but if
            // that also fails, restart recovery will convert Staging to Indeterminate.
            operation_record.state = LifecycleState::Indeterminate;
            operation_record.details = Some(
                "staging succeeded but Staged record persistence failed; handle returned"
                    .to_owned(),
            );
            let _ = self.update(operation_record).await;
            // Fall through and return the handle. The operation state on disk is
            // either Staging (with config_lock_held=true) or Indeterminate, and
            // restart recovery will convert either to Indeterminate if needed.
        }

        // Mark the change set Applied. If that write fails the handle must still
        // reach the caller — the rationale is the same as above. Report what is
        // actually on disk and let the caller decide.
        change_set.state = ChangeSetState::Applied;
        let change_set_state_on_disk = match self.update_change_set(change_set.clone()).await {
            Ok(()) => ChangeSetState::Applied,
            Err(_) => {
                // The final Applied write failed. The earlier update already persisted
                // `Applying`, and `update_change_set` rolls its attempt back to that.
                // Report what is really on disk (Applying), not the pre-apply value.
                ChangeSetState::Applying
            }
        };

        // The recorded_state field reports the change-set state as persisted, not
        // the operation state. If the operation write failed but the change-set
        // write succeeded, the caller sees Applied and must check the operation
        // state separately if needed. Both failed-write branches return the handle,
        // so the caller can commit or discard regardless of persistence outcome.

        Ok(ApplyOutput {
            operation_id,
            before_fingerprint,
            after_fingerprint,
            staged,
            recorded_state: change_set_state_on_disk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lifecycle::ChangeSetState,
        records::{ApprovalRecord, ChangeSetRecord, WaiverKind, WaiverRecord},
    };

    /// Waiver expiry boundary: a waiver whose `expires_at_unix` equals `now` is expired.
    /// The check is `now >= expires_at`, consistent with change-set expiry everywhere.
    /// This test calls the helper directly with fixed values so the boundary case is
    /// deterministic, unlike the end-to-end test which reads the real clock.
    #[test]
    fn waiver_expiry_boundary_is_exact() {
        let expires_at = 1_700_000_000_u64;

        let waiver = WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "boundary test".to_owned(),
            expires_at_unix: Some(expires_at),
            ticket: None,
        };

        let change_set = ChangeSetRecord {
            id: "test".to_owned(),
            device: "test".to_owned(),
            owner: "test".to_owned(),
            digest: "a".repeat(64),
            expected_candidate_fingerprint: "b".repeat(64),
            actions: vec![],
            state: ChangeSetState::Approved,
            expires_at_unix: expires_at + 86400,
            operation_id: None,
            approver: None,
            approval: Some(ApprovalRecord {
                approver: None,
                approved_at_unix: expires_at - 3600,
                digest: "c".repeat(64),
                digest_version: 4,
                waived: Some(waiver),
                mechanism: None,
                issuer: None,
                subject: None,
            }),
            policy_signature: "test".to_owned(),
            targets: vec![],
            preview: None,
            task_id: None,
            apply_without_handle: false,
            owner_subject: None,
        };

        // One second before expiry: still valid
        assert!(
            waiver_expiry_error(&change_set, expires_at - 1, "test").is_none(),
            "waiver must be valid one second before expiry"
        );

        // Exactly at expiry: expired
        let err = waiver_expiry_error(&change_set, expires_at, "test")
            .expect("waiver must be expired at the exact instant");
        let message = format!("{err:?}");
        assert!(
            message.contains("waiver expired"),
            "error message must name expiry: {message}"
        );

        // One second after expiry: expired
        let err = waiver_expiry_error(&change_set, expires_at + 1, "test")
            .expect("waiver must be expired one second after expiry");
        let message = format!("{err:?}");
        assert!(
            message.contains("waiver expired"),
            "error message must name expiry: {message}"
        );
    }
}
