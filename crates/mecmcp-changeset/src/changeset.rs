//! Change-set lifecycle operations: create, approve, status.

use crate::{
    approver::ApproverIdentity,
    coordinator::{ChangesetCoordinator, CoordinatorError},
    digest::{
        change_set_digest, compute_approval_digest_v5, compute_approval_digest_v7,
        compute_waiver_digest_v3, validate_digest, validate_principal_for_digest,
    },
    lifecycle::ChangeSetState,
    records::{ApprovalRecord, ChangeSetRecord, OwnerSubject, WaiverKind, WaiverRecord},
};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Output from change-set lifecycle operations.
#[derive(Debug, Clone, Serialize)]
pub struct ChangeSetOutput {
    /// Change-set identifier.
    pub change_set_id: String,
    /// Owner principal.
    pub owner: String,
    /// Device name.
    pub device: String,
    /// SHA-256 digest binding the plan.
    pub digest: String,
    /// Current lifecycle state.
    pub state: ChangeSetState,
    /// Approver principal (distinct from owner), if approved.
    pub approver: Option<String>,
    /// Unix timestamp when approval expires.
    pub expires_at_unix: u64,
    /// Number of actions in the change set.
    pub action_count: usize,
    /// Why approval was waived, when it was.
    ///
    /// `None` on an ordinary change set. `Some("lab-mode")` when a single-operator
    /// server approved it without a second principal.
    ///
    /// `approver` alone cannot carry this: it is `None` both for a change set
    /// still awaiting approval and for one that was waived, and those are very
    /// different facts. A reader — operator or SIEM — needs to tell "nobody has
    /// approved this yet" from "this was deliberately approved without review".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_waiver: Option<String>,
    /// The staged actions, when requested for review.
    ///
    /// Absent by default. Populated only when the caller explicitly requests the
    /// actions via `change_set_status_with_actions`. This allows approvers to see
    /// what they are approving, and SIEM to audit terminal change sets.
    ///
    /// Exposure is gated server-side (e.g., `--web-enabled-approver` in
    /// rust-junosmcp) — not all deployments want staged config content readable
    /// through the status tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<serde_json::Value>>,
}

impl From<ChangeSetRecord> for ChangeSetOutput {
    fn from(record: ChangeSetRecord) -> Self {
        Self {
            change_set_id: record.id,
            owner: record.owner,
            device: record.device,
            digest: record.digest,
            state: record.state,
            approver: record.approver,
            expires_at_unix: record.expires_at_unix,
            action_count: record.actions.len(),
            approval_waiver: record
                .approval
                .as_ref()
                .and_then(|approval| approval.waived.as_ref())
                .map(|waiver| waiver.reason.clone()),
            actions: None,
        }
    }
}

/// Returns the current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns an error if the system clock is set before the Unix epoch.
pub(crate) fn now_unix() -> Result<u64, CoordinatorError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| CoordinatorError::new("time", "system clock is before the Unix epoch"))
}

/// Generates a new 64-character hex operation/change-set identifier.
///
/// # Errors
///
/// Returns an error if the system's random number generator is unavailable.
pub(crate) fn new_operation_id() -> Result<String, CoordinatorError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        CoordinatorError::new("operation_id", format!("RNG unavailable: {error}"))
    })?;
    Ok(hex::encode(bytes))
}

impl ChangesetCoordinator {
    /// Creates and persists a new change set without mutating the device.
    ///
    /// This is the plan step: the caller provides ordered actions and an expected
    /// candidate fingerprint. The coordinator computes a digest binding
    /// `(owner, device, expected_fingerprint, actions)`, assigns an expiry based on
    /// the configured approval TTL, and persists the plan as `Planned`.
    ///
    /// The digest is the approval target: an independent principal must approve the
    /// exact digest to advance the change set to `Approved`.
    ///
    /// `owner_subject` is the owner token's bound IdP identity (W2's
    /// `oidc_subject`), when it has one. Recorded on the change set at
    /// propose time so a later approval can refuse "the owner approving
    /// through a second token" without needing to re-look-up the owner's
    /// token at approval time, when the proposing request's `CallerCtx` is
    /// long gone.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected fingerprint format is invalid
    /// - Actions are empty or exceed operational limits
    /// - The principal already has a pending change set on the device
    /// - The change-set store is full after evicting terminal records
    /// - Strict mode (`require_verified_approver`) is enabled and
    ///   `owner_subject` is absent
    /// - Persistence fails
    pub async fn create_change_set<A: Serialize>(
        &self,
        device: String,
        actions: Vec<A>,
        owner: String,
        expected_fingerprint: String,
        policy_signature: String,
        owner_subject: Option<OwnerSubject>,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        if self.require_verified_approver() && owner_subject.is_none() {
            return Err(CoordinatorError::new(
                "owner_subject",
                "strict verified-approver mode requires the owner's token to carry an \
                 oidc_subject binding before a change set can be proposed",
            ));
        }

        crate::digest::validate_fingerprint(&expected_fingerprint)
            .map_err(|e| CoordinatorError::new("expected_candidate_fingerprint", e.to_string()))?;

        crate::records::validate_change_set_actions(&actions, self.limits())
            .map_err(|e| CoordinatorError::new(e.field(), e.message().to_owned()))?;

        let now = now_unix()?;
        let id = new_operation_id()?;

        // Serialize actions as serde_json::Value for storage
        let actions_value: Vec<serde_json::Value> = actions
            .into_iter()
            .map(|action| {
                serde_json::to_value(&action).map_err(|e| {
                    CoordinatorError::new("actions", format!("failed to serialize action: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let digest = change_set_digest(&owner, &device, &expected_fingerprint, &actions_value)
            .map_err(|e| CoordinatorError::new("digest", e.to_string()))?;

        let record = ChangeSetRecord {
            id: id.clone(),
            owner,
            device,
            expected_candidate_fingerprint: expected_fingerprint,
            actions: actions_value,
            digest: digest.clone(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: now.saturating_add(self.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature,
            // Single-target, so both stay absent and the record still writes as
            // version 1 — which is what LXC 608 is running.
            targets: Vec::new(),
            preview: None,
            // No apply has begun, so there is no vendor task to re-probe.
            task_id: None,
            apply_without_handle: false,
            owner_subject,
        };

        self.insert_change_set(record.clone()).await?;

        // A change was proposed. `request_id` is the change-set id: this call
        // has no MCP request id to hand, and the two later records key on
        // `changeset_id` anyway, which is what carries context across the
        // lifecycle (mecmcp#292).
        if let Some(evidence) = self.evidence() {
            evidence.proposal(&id, &id, &record.device, &record.owner, &record.digest);
        }

        Ok(record.into())
    }

    /// Approves an unexpired change set with an independent human principal.
    ///
    /// This is the approval gate: the approver must be distinct from the owner,
    /// must be human — the house rule is that a human approves, so an agent or
    /// unattributed caller cannot stand in as the second principal — the
    /// change set must be in `Planned` state, the approval window must not
    /// have expired, and the provided digest must match the stored digest
    /// exactly.
    ///
    /// `approver` carries not just the principal name but how its identity
    /// was asserted (`ApproverIdentity`, MEC-994 W4). In strict mode
    /// (`require_verified_approver`), only `ApproverIdentity::OidcVerified`
    /// is accepted, and an approver whose verified subject equals the
    /// change set's recorded `owner_subject` is refused — the same human
    /// cannot satisfy both sides of the two-person rule by holding a second
    /// token bound to the same IdP identity.
    ///
    /// On success, the change set transitions to `Approved`, the approver is recorded,
    /// and an approval digest is computed over `(change_set_id, plan_digest, owner,
    /// approver, approved_at)` and stored for tamper detection on load.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected digest format is invalid
    /// - The change set does not exist or belongs to another device
    /// - The approver is the same principal as the owner (self-approval denied)
    /// - The approver's verified OIDC subject equals the owner's recorded subject
    /// - The approver identity is not human
    /// - Strict mode is enabled and the approver is not `OidcVerified`
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The provided digest does not match the stored digest
    /// - Persistence fails
    pub async fn approve_change_set(
        &self,
        change_set_id: String,
        device: String,
        approver: &ApproverIdentity,
        expected_digest: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner == approver.principal() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "the change-set owner cannot approve their own plan",
            ));
        }

        // Checked after self-approval so a proposer who is also non-human still
        // gets the more specific "cannot approve their own plan" message. Checked
        // before anything else stateful: this is a fact about the caller, not the
        // record, and must not depend on what state the record happens to be in.
        if !approver.is_human() {
            return Err(CoordinatorError::new(
                "approver_actor_type",
                "the change-set approver must be a human principal",
            ));
        }

        if self.require_verified_approver() {
            if !matches!(approver, ApproverIdentity::OidcVerified { .. }) {
                return Err(CoordinatorError::new(
                    "approver",
                    "strict verified-approver mode requires an IdP-verified approver assertion",
                ));
            }
            // Strict mode exists to make the verified-approver fields
            // (mechanism/issuer/subject/owner_subject) tamper-evident via the
            // keyed v7 digest. Without a key, `approve_change_set` below
            // falls back to the unkeyed v5 digest, which silently drops
            // every one of those fields — the acceptance criterion "editing
            // mechanism/issuer/subject fails the HMAC check" would then not
            // apply even though strict mode is on (MEC-994 Percy review F3).
            if self.approval_digest_key().is_none() {
                return Err(CoordinatorError::new(
                    "approval_digest_key",
                    "strict verified-approver mode requires a keyed approval digest \
                     (--approval-digest-key-file); without one, the verified-approver \
                     fields recorded in this approval would not be tamper-evident",
                ));
            }
            // A `Planned` record's `owner_subject` is not itself covered by
            // any digest until this approval signs it in, so a missing value
            // here could mean the owner's token genuinely had no binding at
            // propose time, or that the field was stripped from the state
            // file after the fact (MEC-994 Percy review F4). Strict mode
            // cannot tell those apart, so it refuses rather than silently
            // skipping the self-approval check below.
            if record.owner_subject.is_none() {
                return Err(CoordinatorError::new(
                    "owner_subject",
                    "strict verified-approver mode requires the change set to carry an \
                     owner_subject; this one has none, which either means it was proposed \
                     before strict mode was in effect or that owner_subject was stripped \
                     from the state file after proposal",
                ));
            }
        }

        // The house rule is two *people*, not two tokens. A verified subject
        // equal to the owner's recorded subject means the same human proposed
        // and approved, however many different token names they used to do
        // it.
        if let (Some((approver_issuer, approver_subject)), Some(owner_subject)) =
            (approver.oidc_subject(), record.owner_subject.as_ref())
            && approver_issuer == owner_subject.issuer
            && approver_subject == owner_subject.subject
        {
            return Err(CoordinatorError::new(
                "approver",
                "the verified approver is the same IdP identity as the change-set owner",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            let observed = record.state;
            record.state = ChangeSetState::Expired;
            self.update_change_set_from(observed, record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        // The v4 encoding is unambiguous by construction, so this check is no
        // longer what keeps pairings apart. It stays as an input rule: a `|` in
        // a principal is a sign of a malformed token name, and letting one in
        // here would also make the record unverifiable if it ever had to be read
        // back by a binary predating #283.
        validate_principal_for_digest("owner", &record.owner)
            .map_err(|msg| CoordinatorError::new("owner", msg))?;
        validate_principal_for_digest("approver", approver.principal())
            .map_err(|msg| CoordinatorError::new("approver", msg))?;

        // v5: the v4 tuple plus the digest of the preview this approver read.
        //
        // The plan digest covers the actions; the preview is rendered from them
        // and stored beside them, and until now nothing tied the two together —
        // so consent was evidenced against the actions while what was read was
        // the text (rustproxmoxmcp#56). Signing both means a rendering that
        // disagreed with its action cannot carry a valid approval.
        //
        // Taken from the record as it stands at this moment, which is the point:
        // the approver signs the text that is there when they approve, not
        // whatever was attached at plan time.
        // Signing a digest that does not match its own text would produce a
        // valid approval over an inconsistent preview: claimable here, and
        // rejected by `read_state` only at the next restart, taking the whole
        // state file with it. `check_change_set_write` refuses such a record on
        // the way in, and this is the second door -- a record already in the
        // store from before that check existed must not be signed either.
        record.validate_preview(usize::MAX).map_err(|error| {
            CoordinatorError::new("preview", format!("the preview is invalid: {error}"))
        })?;
        let preview_digest = record
            .preview
            .as_ref()
            .map(|preview| preview.digest.clone());

        // v7: keyed with an HMAC only this deployment holds (MEC-457), and
        // additionally binds the approver's identity mechanism, any verified
        // OIDC issuer/subject, and the owner's recorded subject (MEC-994 W4)
        // — a v6 digest authenticated the fields but not how `approver` was
        // asserted. Falls back to the unkeyed v5 digest when no key is
        // configured, so a deployment that has not been given one keeps
        // working exactly as before -- signing is optional, not the absence
        // of an approval.
        let approver_principal = approver.principal().to_owned();
        let approver_oidc = approver.oidc_subject();
        let owner_subject_pair = record
            .owner_subject
            .as_ref()
            .map(|s| (s.issuer.as_str(), s.subject.as_str()));
        let (approval_digest, digest_version, mechanism, issuer, subject) =
            if let Some(key) = self.approval_digest_key() {
                (
                    compute_approval_digest_v7(
                        key,
                        &change_set_id,
                        &record.digest,
                        preview_digest.as_deref(),
                        &record.owner,
                        &approver_principal,
                        now,
                        approver.mechanism(),
                        approver_oidc,
                        owner_subject_pair,
                    ),
                    7,
                    Some(approver.mechanism().to_owned()),
                    approver_oidc.map(|(issuer, _)| issuer.to_owned()),
                    approver_oidc.map(|(_, subject)| subject.to_owned()),
                )
            } else {
                (
                    compute_approval_digest_v5(
                        &change_set_id,
                        &record.digest,
                        preview_digest.as_deref(),
                        &record.owner,
                        &approver_principal,
                        now,
                    ),
                    5,
                    None,
                    None,
                    None,
                )
            };

        let observed = record.state;
        record.state = ChangeSetState::Approved;
        record.approver = Some(approver_principal.clone());
        record.approval = Some(ApprovalRecord {
            approver: Some(approver_principal.clone()),
            approved_at_unix: now,
            digest: approval_digest,
            digest_version,
            waived: None,
            mechanism,
            issuer,
            subject,
        });

        self.update_change_set_from(observed, record.clone())
            .await?;

        // A human decided. Recorded after the state write, so the trail cannot
        // claim an approval the coordinator failed to persist.
        if let Some(evidence) = self.evidence() {
            evidence.approval(
                &change_set_id,
                &change_set_id,
                &approver_principal,
                "approved",
            );
        }

        Ok(record.into())
    }

    /// Waives approval for a change set in lab mode, allowing single-operator application.
    ///
    /// This is the lab-mode path: when lab mode is enabled, a change set can transition
    /// directly from `Planned` to `Approved` without a second principal. The approval is
    /// recorded as **waived**, never as obtained — no approver is written, and the waiver
    /// reason documents that this was a lab-mode operation.
    ///
    /// The waiver digest covers `(change_set_id, plan_digest, owner, waived_at, "lab-mode-waived")`,
    /// making it tamper-evident but distinct from genuine two-person approvals.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Lab mode is not enabled
    /// - The expected digest format is invalid
    /// - The change set does not exist or belongs to another device
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The provided digest does not match the stored digest
    /// - Persistence fails
    pub async fn waive_approval(
        &self,
        change_set_id: String,
        device: String,
        owner: String,
        expected_digest: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        if !self.lab_mode() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "approval waiver requires lab mode to be enabled",
            ));
        }

        // Lab mode lets the owner approve their own change set outright —
        // the opposite of what strict verified-approver mode exists to
        // enforce. The two are mutually exclusive by construction
        // (`VerifiedApproverArgs::validate` refuses to start a server with
        // both), but that is a courtesy pre-check on one CLI shape, not a
        // guarantee about every coordinator built directly against this
        // crate's API. Refuse here too, so a lab-mode owner cannot waive
        // their own approval purely because this check was skipped
        // elsewhere (MEC-994 Percy review F2).
        if self.require_verified_approver() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "approval waiver is refused under strict verified-approver mode: lab mode \
                 lets the owner approve their own change set, which strict mode exists to \
                 prevent",
            ));
        }

        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner can waive approval in lab mode",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            let observed = record.state;
            record.state = ChangeSetState::Expired;
            self.update_change_set_from(observed, record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        let waiver = WaiverRecord {
            kind: WaiverKind::LabMode,
            reason: "lab-mode".to_owned(),
            expires_at_unix: None,
            ticket: None,
        };
        let waived_as = (
            waiver.kind,
            waiver.reason.clone(),
            waiver.expires_at_unix,
            waiver.ticket.clone(),
        );
        let waiver_digest =
            compute_waiver_digest_v3(&change_set_id, &record.digest, &record.owner, now, &waiver);

        let observed = record.state;
        record.state = ChangeSetState::Approved;
        record.approver = None;
        record.approval = Some(ApprovalRecord {
            approver: None,
            approved_at_unix: now,
            digest: waiver_digest,
            // A waived record's digest is a waiver digest, not an approval one,
            // so this field is never read for it. Set rather than defaulted so
            // it does not read as an approval version that was chosen.
            digest_version: 4,
            waived: Some(waiver),
            mechanism: None,
            issuer: None,
            subject: None,
        });

        self.update_change_set_from(observed, record.clone())
            .await?;

        // Every prod server in this fleet runs lab mode, so this — not
        // `approve_change_set` — is the path a real change takes. Emitting
        // nothing here would leave the trail jumping proposal to apply intent,
        // which reads exactly like a bypassed approval gate.
        if let Some(evidence) = self.evidence() {
            evidence.approval_waived(
                &change_set_id,
                &change_set_id,
                waived_as.0.as_str(),
                &waived_as.1,
                waived_as.2,
                waived_as.3.as_deref(),
            );
        }

        Ok(record.into())
    }

    /// Grants an operator-level approval waiver for the specified change set.
    ///
    /// Unlike `waive_approval`, this method does **not** require lab mode and
    /// records a documented exception granted under an active control. The
    /// waiver binds a kind, optional expiry, and optional ticket reference into
    /// its digest to prevent post-hoc relabelling or time-box extension.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The waiver `kind` is `WaiverKind::LabMode` (use `waive_approval` for that)
    /// - The `expires_at_unix` is already in the past (configuration error, not a valid waiver)
    /// - The change set does not exist or belongs to another device
    /// - Only the change-set owner can grant the waiver
    /// - The change set is not in `Planned` state
    /// - The approval window has expired
    /// - The expected digest does not match the stored digest
    #[allow(clippy::too_many_arguments)]
    pub async fn waive_approval_operator(
        &self,
        change_set_id: String,
        device: String,
        owner: String,
        expected_digest: String,
        kind: WaiverKind,
        reason: String,
        expires_at_unix: Option<u64>,
        ticket: Option<String>,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        if kind == WaiverKind::LabMode {
            return Err(CoordinatorError::new(
                "kind",
                "use waive_approval for a lab-mode waiver; this path records an \
                 operator-granted exception under a control that is still on",
            ));
        }

        // An operator waiver is granted in-band by a second principal calling
        // a tool, with no verified-identity check of its own. Strict mode
        // exists so a second human, not a second token, approves. Without
        // this check, the owner can grant themselves an operator waiver and
        // reach `Approved` with no verified approver at all (MEC-994 Percy
        // review F10).
        if self.require_verified_approver() {
            return Err(CoordinatorError::new(
                "change_set_id",
                "approval waiver is refused under strict verified-approver mode",
            ));
        }

        validate_digest(&expected_digest, "expected_digest")
            .map_err(|e| CoordinatorError::new("expected_digest", e.to_string()))?;

        let mut record = self.change_set(&change_set_id, &device).await?;

        if record.owner != owner {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner can waive approval",
            ));
        }

        if record.state != ChangeSetState::Planned {
            return Err(CoordinatorError::new(
                "change_set_id",
                "change set is not awaiting approval",
            ));
        }

        let now = now_unix()?;
        if now >= record.expires_at_unix {
            let observed = record.state;
            record.state = ChangeSetState::Expired;
            self.update_change_set_from(observed, record).await?;
            return Err(CoordinatorError::new(
                "change_set_id",
                "change-set approval window expired",
            ));
        }

        if record.digest != expected_digest {
            return Err(CoordinatorError::new(
                "expected_digest",
                "digest does not match the exact stored change set",
            ));
        }

        if let Some(expires) = expires_at_unix
            && expires <= now
        {
            return Err(CoordinatorError::new(
                "expires_at_unix",
                "waiver expiry is already in the past; a waiver that is dead on \
                 arrival is a configuration error, not a waiver",
            ));
        }

        let waiver = WaiverRecord {
            kind,
            reason,
            expires_at_unix,
            ticket,
        };
        let waived_as = (
            waiver.kind,
            waiver.reason.clone(),
            waiver.expires_at_unix,
            waiver.ticket.clone(),
        );
        let waiver_digest =
            compute_waiver_digest_v3(&change_set_id, &record.digest, &record.owner, now, &waiver);

        let observed = record.state;
        record.state = ChangeSetState::Approved;
        record.approver = None;
        record.approval = Some(ApprovalRecord {
            approver: None,
            approved_at_unix: now,
            digest: waiver_digest,
            // A waived record's digest is a waiver digest, not an approval one,
            // so this field is never read for it. Set rather than defaulted so
            // it does not read as an approval version that was chosen.
            digest_version: 4,
            waived: Some(waiver),
            mechanism: None,
            issuer: None,
            subject: None,
        });

        self.update_change_set_from(observed, record.clone())
            .await?;

        // Same reasoning as the lab-mode path, and more pointed: an operator
        // waiver is a bounded, ticketed exception, and the trail is where that
        // boundedness is visible. The ticket rides in metadata so an auditor can
        // follow the exception back to what authorised it.
        if let Some(evidence) = self.evidence() {
            evidence.approval_waived(
                &change_set_id,
                &change_set_id,
                waived_as.0.as_str(),
                &waived_as.1,
                waived_as.2,
                waived_as.3.as_deref(),
            );
        }

        Ok(record.into())
    }

    /// Retire `record` in place if either of its deadlines has passed.
    ///
    /// Two deadlines apply. A `Planned` record is retired by its own approval
    /// TTL, which is the long-standing rule and is left exactly as it was. A
    /// record approved by a time-boxed waiver is retired once that waiver has
    /// lapsed (#284) — before, `apply` refused such a record while every read
    /// path went on reporting it `Approved`, so the state the operator was shown
    /// contradicted the one the state machine enforced.
    ///
    /// The waiver check is deliberately not folded into the first condition.
    /// Widening the approval-TTL rule from `Planned` to every expirable state
    /// would retire `Approved` records on read for a reason unrelated to this
    /// defect, which is a larger behaviour change than the one being fixed.
    async fn retire_if_deadline_passed(
        &self,
        record: &mut ChangeSetRecord,
    ) -> Result<(), CoordinatorError> {
        let now = now_unix()?;

        let approval_ttl_passed =
            record.state == ChangeSetState::Planned && now >= record.expires_at_unix;
        let waiver_lapsed = crate::coordinator::is_expirable(record.state)
            && crate::apply::waiver_lapsed(record, now);

        if approval_ttl_passed || waiver_lapsed {
            let observed = record.state;
            record.state = ChangeSetState::Expired;
            self.update_change_set_from(observed, record.clone())
                .await?;
        }

        Ok(())
    }

    /// Retrieves the status of a change set, auto-expiring if needed.
    ///
    /// If the change set is in `Planned` state and the current time is past
    /// `expires_at_unix`, it is transitioned to `Expired` and persisted before
    /// returning.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - Persistence fails (when auto-expiring)
    pub async fn change_set_status(
        &self,
        change_set_id: String,
        device: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        self.retire_if_deadline_passed(&mut record).await?;

        Ok(record.into())
    }

    /// Retrieves the status of a change set WITH the stored actions, auto-expiring if needed.
    ///
    /// This is the review-enabled variant of `change_set_status`. It returns the same
    /// metadata as the base method but also populates the `actions` field with the
    /// exact stored actions. This allows approvers to see what they are approving and
    /// SIEM to audit terminal change sets.
    ///
    /// Authorization semantics are identical to `change_set_status` — no additional
    /// principal checks. Exposure is gated server-side (e.g., via `--web-enabled-approver`
    /// in rust-junosmcp).
    ///
    /// If the change set is in `Planned` state and the current time is past
    /// `expires_at_unix`, it is transitioned to `Expired` and persisted before
    /// returning.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - Persistence fails (when auto-expiring)
    pub async fn change_set_status_with_actions(
        &self,
        change_set_id: String,
        device: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        self.retire_if_deadline_passed(&mut record).await?;

        let mut output: ChangeSetOutput = record.clone().into();
        output.actions = Some(record.actions);
        Ok(output)
    }

    /// Cancels a change set, freeing the per-principal pending slot.
    ///
    /// A change set may be cancelled by its owner or by an approver-class principal.
    /// Valid from states `Planned` or `Approved` (not yet applied). Transitions the
    /// record to a terminal `Cancelled` state and frees the per-principal pending slot,
    /// allowing a new change set to be created immediately. Records are never deleted —
    /// the audit trail is preserved.
    ///
    /// Idempotent: cancelling an already-`Cancelled` set returns its current state
    /// without error.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The change set does not exist or belongs to another device
    /// - The principal is neither the owner nor an approver
    /// - The change set is in `Applied` or `Applying` state (cannot cancel an in-flight or completed apply)
    /// - Persistence fails
    pub async fn cancel_change_set(
        &self,
        change_set_id: String,
        device: String,
        principal: String,
    ) -> Result<ChangeSetOutput, CoordinatorError> {
        let mut record = self.change_set(&change_set_id, &device).await?;

        // Idempotent: return current state if already cancelled
        if record.state == ChangeSetState::Cancelled {
            return Ok(record.into());
        }

        // Check authorization: principal must be owner or approver
        let is_owner = record.owner == principal;
        let is_approver = record.approver.as_ref() == Some(&principal);

        if !is_owner && !is_approver {
            return Err(CoordinatorError::new(
                "change_set_id",
                "only the change-set owner or approver may cancel it",
            ));
        }

        // Reject if state is Applying or Applied
        if matches!(
            record.state,
            ChangeSetState::Applying | ChangeSetState::Applied
        ) {
            return Err(CoordinatorError::new(
                "change_set_id",
                format!(
                    "cannot cancel a change set in state {:?}",
                    record.state.as_str()
                ),
            ));
        }

        // Transition to Cancelled (valid from Planned, Approved, Expired, or Failed)
        let observed = record.state;
        record.state = ChangeSetState::Cancelled;
        self.update_change_set_from(observed, record.clone())
            .await?;

        Ok(record.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::compute_approval_digest_v4 as compute_approval_digest;

    #[test]
    fn test_approval_digest_is_deterministic() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_approval_digest_changes_with_approver() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 =
            compute_approval_digest("abc123", "sha256:plan", "alice", "charlie", 1700000000);
        assert_ne!(digest1, digest2);
    }

    #[test]
    fn test_approval_digest_changes_with_owner() {
        let digest1 = compute_approval_digest("abc123", "sha256:plan", "alice", "bob", 1700000000);
        let digest2 = compute_approval_digest("abc123", "sha256:plan", "eve", "bob", 1700000000);
        assert_ne!(digest1, digest2);
    }
}
