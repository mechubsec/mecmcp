//! Operation and change-set record types.

use crate::{
    digest::{digest_hex, validate_fingerprint},
    lifecycle::{ChangeSetState, LifecycleState},
    types::OperationLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Persisted operation record.
///
/// This type is vendor-agnostic and uses `serde_json::Value` for the `action` and `actions`
/// fields to allow any device transaction implementation to store its own action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    /// Operation identifier (64 hex characters).
    pub id: String,
    /// Principal who owns this operation.
    pub owner: String,
    /// Device name from inventory.
    pub device: String,
    /// Device endpoint (must start with `https://`).
    pub endpoint: String,
    /// Primary action type (vendor-specific, serialized as JSON).
    pub action: serde_json::Value,
    /// Primary action target path (vendor-specific, optional).
    ///
    /// PAN-OS operations carry an XPath identifying the config tree node being mutated.
    /// Junos operations have no analogous concept and omit the field entirely — `None`
    /// is skipped on serialization rather than written as `null`.
    ///
    /// The name is vendor-specific and deliberately so: it is the key already present in
    /// the deployed state file, and D6 adopts that schema unchanged. Renaming the Rust
    /// field while keeping the on-disk key was considered and rejected as a second name
    /// for the same thing. Treat this as PAN-OS-only; nothing in this crate reads it.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpath: Option<String>,
    /// All actions in this operation (vendor-specific, serialized as JSON).
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    /// Associated change-set identifier, if this operation was created by applying a change set.
    #[serde(default)]
    pub change_set_id: Option<String>,
    /// Candidate fingerprint when this operation was staged.
    pub current: String,
    /// Lifecycle state of the operation.
    pub state: LifecycleState,
    /// Job identifier from the device, if any.
    pub job_id: Option<String>,
    /// Human-readable details about the operation outcome.
    pub details: Option<String>,
    /// Whether the configuration lock is held by this operation.
    pub config_lock_held: bool,
    /// Policy signature at the time of staging.
    pub policy_signature: String,
    /// Who requested the commit, captured before the device was contacted.
    ///
    /// Absent on operations that have not reached commit, and on records written
    /// before this field existed — deployed state files must keep loading, so it
    /// is optional and omitted rather than written as `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<PersistedAttribution>,
    /// Confirmed-commit auto-rollback deadline (Junos only), as unix timestamp.
    ///
    /// When `AwaitingConfirmation`, the device will automatically rollback the
    /// commit at this time unless a confirming commit is issued. Absent on
    /// operations that do not use confirmed commit, and on records written
    /// before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_deadline_unix: Option<u64>,
    /// Configuration authority owning this device.
    ///
    /// Records who owns the device's configuration: `"local"` (this server),
    /// a management plane (`"mist"`, `"panorama"`, `"strata-cloud-manager"`,
    /// etc.), or `"unknown"` when unset. Vendor-neutral string representation
    /// of the authority discriminant from `mecmcp_inventory::ConfigAuthority`.
    ///
    /// When the authority is not `"local"`, changes made through this server
    /// may be overwritten by the owning plane at its next push. Audit events
    /// record this field to distinguish durable changes from transient ones.
    ///
    /// Optional for backward compatibility — records written before this field
    /// existed have no config authority and must still load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_authority: Option<String>,
}

/// An IdP identity bound to a principal's token (MEC-994 W2/W4).
///
/// Durable projection of `mecmcp_auth::OidcSubject`: just enough to detect
/// "the approver is the owner wearing a second token" (issuer+subject equal)
/// without ever carrying anything that could identify a human by name or
/// email.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerSubject {
    /// The IdP issuer that signed the owner token's bound assertion.
    pub issuer: String,
    /// The IdP's `sub` claim for the owner.
    pub subject: String,
}

/// The attribution fields worth keeping in the state file.
///
/// [`mecmcp_audit::Attribution`] is a live request object holding types that are
/// not serializable and values that mean nothing after a restart. This is the
/// durable projection of it: enough to answer "who asked for this, on whose
/// behalf, and under what change reference" when an operator finds an
/// unresolved operation tomorrow morning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedAttribution {
    /// Principal variant and value. Stores the discriminator so the audit record
    /// can distinguish an authenticated token from an unauthenticated request,
    /// even when both render to the same string (e.g., a token named "stdio").
    pub principal: PersistedPrincipal,
    /// Whether the actor was a human, an agent, or undeclared.
    pub actor_type: String,
    /// The human the actor was acting for, when the credential declared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// External change-control reference, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ref: Option<String>,
    /// Correlation id linking this record to the audit event for the request.
    pub request_id: String,
    /// Agent identity, when `actor_type == "agent"`. Durable projection of
    /// `mecmcp_audit::AgentIdentity` for audit trail: model, provider, tier,
    /// skills used. Optional for backward compatibility — records written before
    /// this field existed have no agent identity, and must still load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<PersistedAgentIdentity>,
}

/// Durable projection of [`mecmcp_audit::Principal`].
///
/// Preserves the discriminator so an audit record can distinguish
/// `Principal::Token("stdio")` from `Principal::Unauthenticated` (both render
/// to "stdio", but only one is an authenticated credential).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum PersistedPrincipal {
    /// Authenticated bearer token, identified by name.
    Token(String),
    /// Unauthenticated request (stdio or local socket with no auth).
    Unauthenticated,
}

/// Durable projection of `mecmcp_audit::AgentIdentity`.
///
/// Captures the provenance of an agent-driven commit: which model, provider,
/// tier, and skills generated the change. This is the contract requirement
/// from transaction.rs: "The attribution is also serialized into the persisted
/// operation record for audit, independent of what the device logs."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedAgentIdentity {
    /// Model identifier (e.g. `"claude-sonnet-4-5"`).
    pub model_id: String,
    /// Provider name (e.g., "anthropic", "ollama").
    pub provider: String,
    /// Provider tier: public hosted vs. private/self-hosted.
    pub provider_tier: String,
    /// Skills invoked during this action, space-separated or "none".
    pub skills_used: String,
}

impl From<&mecmcp_audit::Attribution> for PersistedAttribution {
    fn from(attribution: &mecmcp_audit::Attribution) -> Self {
        Self {
            principal: match &attribution.principal {
                mecmcp_audit::Principal::Token(name) => PersistedPrincipal::Token(name.clone()),
                mecmcp_audit::Principal::Unauthenticated => PersistedPrincipal::Unauthenticated,
            },
            // Rendered via Debug so a new actor-type variant lands here as its
            // own name rather than being silently folded into an existing one.
            actor_type: format!("{:?}", attribution.actor_type).to_lowercase(),
            on_behalf_of: attribution.on_behalf_of.clone(),
            change_ref: attribution.change_ref.clone(),
            request_id: attribution.request_id.to_string(),
            agent: attribution
                .agent
                .as_ref()
                .map(|agent| PersistedAgentIdentity {
                    model_id: agent.model_id.clone(),
                    provider: agent.provider.clone(),
                    provider_tier: agent.provider_tier.to_string(),
                    skills_used: if agent.skills_used.is_empty() {
                        "none".to_string()
                    } else {
                        agent.skills_used.join(" ")
                    },
                }),
        }
    }
}

/// Persisted change-set record.
///
/// This type is vendor-agnostic and uses `serde_json::Value` for the `actions` field
/// to allow any device transaction implementation to store its own action types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetRecord {
    /// Change-set identifier (64 hex characters).
    pub id: String,
    /// Principal who created this change set.
    pub owner: String,
    /// Device name from inventory.
    pub device: String,
    /// Expected candidate fingerprint at apply time.
    pub expected_candidate_fingerprint: String,
    /// Ordered actions (vendor-specific, serialized as JSON).
    pub actions: Vec<serde_json::Value>,
    /// SHA-256 digest binding `(owner, device, fingerprint, actions)`.
    pub digest: String,
    /// Lifecycle state of the change set.
    pub state: ChangeSetState,
    /// Principal who approved this change set (distinct from owner).
    ///
    /// Legacy field for backward compatibility. New records store approval data
    /// in the `approval` field. This field is populated from `approval.approver`
    /// when present, or directly when loading legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// Tamper-evident approval record.
    ///
    /// Stores the approver, timestamp, and digest over `(change_set_id, plan_digest,
    /// owner, approver, approved_at)`. Missing on legacy records created before the
    /// approval-digest feature; present on all new approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalRecord>,
    /// Unix timestamp when the approval expires.
    pub expires_at_unix: u64,
    /// Operation identifier created when this change set was applied.
    pub operation_id: Option<String>,
    /// Policy signature at the time of change-set creation.
    ///
    /// Absent on records written before this field existed. The deployed LXC 608
    /// state file carries `policy_signature` on operations but NOT on change
    /// sets, so this must default rather than be required — a required field
    /// here stops the coordinator loading its own state file after an upgrade.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_signature: String,
    /// Additional targets when this change set spans more than one device.
    ///
    /// Sorted and unique, and **absent** on a single-target change set — which
    /// is every change set both shipping servers create today. `device` remains
    /// the field they read; use [`ChangeSetRecord::targets`] to ask once and get
    /// the right answer either way.
    ///
    /// Absent rather than `[device]` for a reason: this type is
    /// `deny_unknown_fields`, so a binary predating this field rejects the whole
    /// state file if it appears. LXC 608's live file is version 1 and carries
    /// none of it. See the version gate in `persistence.rs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Preview artifact produced before applying, with its canonical digest.
    ///
    /// Absent when the product does not produce one, for the same
    /// forward-compatibility reason as `targets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewRecord>,
    /// Vendor task handle for an apply that is still running.
    ///
    /// Written **before** the apply begins polling, so a crash between
    /// starting the vendor operation and observing its result leaves a handle
    /// to re-probe. Without it, a crashed apply is detectable — the record is
    /// stuck in `Applying` — but not *recoverable*, because nothing records
    /// which vendor operation to ask about. The change set then has to be
    /// resolved by a human reading the device.
    ///
    /// A Proxmox UPID, a Junos commit token, or whatever the product's task
    /// identifier is; this crate stores it opaquely and never parses it.
    ///
    /// Cleared when the apply reaches a definitive outcome, so a present
    /// `task_id` on a non-`Applying` record means the process died between
    /// finishing and recording that fact.
    ///
    /// Absent by default for the same forward-compatibility reason as
    /// `targets` and `preview`: this type is `deny_unknown_fields`, so a
    /// binary predating this field rejects the whole state file if it appears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Set when the apply holding this record produces no vendor task handle.
    ///
    /// Most applies end in one — a Proxmox UPID, a Junos commit token — and an
    /// `Applying` record without one means the process died before it could be
    /// written. That is recorded as `Failed` at load, because the operation was
    /// never started as far as anything can tell.
    ///
    /// Some applies never have a handle to write. `guest_exec` runs a command
    /// through a guest agent and gets back a PID inside the guest; Proxmox's
    /// task system never sees it. For those, `Applying` with no handle means
    /// the opposite thing — the operation may well have run, and only the
    /// device knows. Calling that `Failed` would assert an outcome nobody
    /// observed, on an operation that is usually not idempotent.
    ///
    /// This flag is what tells the two apart. Set it and the record stays
    /// `Applying` across a restart: detectable, not recoverable, and a human
    /// has to go and look. That is the honest state, and it is also what keeps
    /// the approval from being spent twice.
    ///
    /// `false` is never serialised, so a state file written by a binary that
    /// sets it stays readable by one that predates it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub apply_without_handle: bool,
    /// The owner's IdP identity, recorded at propose time (MEC-994 W4).
    ///
    /// Copied from the owner token's `oidc_subject` (W2) when present. This is
    /// what lets a later approval refuse "the owner approving their own change
    /// through a second token": if the approver's verified subject equals this
    /// one, it is the same human regardless of which token name signed which
    /// side. Absent when the owner's token has no `oidc_subject` configured,
    /// which strict mode (`require_verified_approver`) refuses to propose for.
    ///
    /// Absent by default for the same forward-compatibility reason as
    /// `targets`, `preview` and `task_id`: this type is `deny_unknown_fields`,
    /// so a binary predating this field rejects the whole state file if it
    /// appears.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_subject: Option<OwnerSubject>,
}

/// A preview of what a change set will do, bound to a digest.
///
/// The digest is what makes the preview evidence rather than decoration: an
/// artifact edited in the state file no longer matches, and the mismatch is
/// detectable without re-running the preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviewRecord {
    /// The vendor's own preview output, opaque here.
    pub artifact: String,
    /// `sha256:<64 lowercase hex>` over `artifact`.
    pub digest: String,
    /// Identifier of the job that produced the preview, when the API returns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
}

impl ChangeSetRecord {
    /// Every device this change set applies to.
    ///
    /// Returns the multi-target set when present and `[device]` otherwise, so a
    /// caller never has to know which shape it is reading. Junos and PAN-OS see
    /// exactly one element today.
    #[must_use]
    pub fn targets(&self) -> Vec<String> {
        if self.targets.is_empty() {
            vec![self.device.clone()]
        } else {
            self.targets.clone()
        }
    }

    /// Check this record's target set, including that it names `device`.
    ///
    /// An empty set is the single-target shape and is always valid — `targets()`
    /// reports `[device]` for it.
    ///
    /// Separate from [`validate_targets`] because the primary-device rule needs
    /// the record, not just the list. Without it a set of `["fw-02"]` on a
    /// record whose `device` is `fw-01` passes every structural check while
    /// `targets()` reports `fw-02` and approval and apply still find the record
    /// under `fw-01`.
    ///
    /// # Errors
    /// Returns [`TargetError`] describing the first problem found.
    pub fn validate_target_set(&self, maximum: usize) -> Result<(), TargetError> {
        if self.targets.is_empty() {
            return Ok(());
        }
        validate_targets(&self.targets, maximum)?;
        if !self.targets.contains(&self.device) {
            return Err(TargetError::MissingPrimary(self.device.clone()));
        }
        Ok(())
    }

    /// Check the stored preview: digest well-formed, matching, and within
    /// `max_preview_bytes`.
    ///
    /// The digest is the only thing that makes a preview evidence rather than
    /// decoration. Nothing verified it, so an artifact edited in the state file
    /// reloaded cleanly and was served as valid evidence.
    ///
    /// # Errors
    /// Returns a message naming what failed.
    pub fn validate_preview(&self, max_preview_bytes: usize) -> Result<(), PreviewError> {
        let Some(preview) = &self.preview else {
            return Ok(());
        };
        if preview.artifact.len() > max_preview_bytes {
            return Err(PreviewError::TooLarge {
                bytes: preview.artifact.len(),
                maximum: max_preview_bytes,
            });
        }
        crate::digest::validate_digest(&preview.digest, "preview_digest")
            .map_err(|error| PreviewError::Malformed(error.to_string()))?;
        let expected = crate::digest::preview_digest(&preview.artifact);
        if expected != preview.digest {
            return Err(PreviewError::Mismatch);
        }
        Ok(())
    }
}

/// A stored preview that cannot be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewError {
    /// The digest was not `sha256:<64 lowercase hex>`.
    Malformed(String),
    /// The digest did not match the artifact.
    Mismatch,
    /// The artifact exceeded the configured maximum.
    TooLarge {
        /// How large the artifact is.
        bytes: usize,
        /// How large it may be.
        maximum: usize,
    },
}

impl std::fmt::Display for PreviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "preview: {detail}"),
            Self::Mismatch => write!(
                f,
                "preview: digest does not match the artifact; the preview has been tampered with"
            ),
            Self::TooLarge { bytes, maximum } => {
                write!(f, "preview: {bytes} bytes exceeds the maximum of {maximum}")
            }
        }
    }
}

impl std::error::Error for PreviewError {}

/// A target set that cannot be used.
///
/// Hand-written rather than derived: this crate does not depend on `thiserror`,
/// and matching `DigestError`'s shape keeps one error style across the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The set was empty.
    Empty,
    /// A target name was empty.
    EmptyName,
    /// The set held a duplicate.
    ///
    /// A duplicate changes the digest without changing the meaning, which makes
    /// the digest a function of how the caller built the list rather than of
    /// what the change set does.
    Duplicate(String),
    /// The set was not sorted. Same reason as a duplicate: order must not be
    /// able to alter the digest.
    Unsorted(String),
    /// The set did not contain the record's own `device`.
    ///
    /// Approval and apply look a record up by `device`, so a target set that
    /// omits it makes the record name different devices depending on which API
    /// is asked.
    MissingPrimary(String),
    /// The set exceeded the configured maximum.
    TooMany {
        /// How many were supplied.
        count: usize,
        /// How many are allowed.
        maximum: usize,
    },
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "targets: a change set must name at least one target"),
            Self::EmptyName => write!(f, "targets: a target name must not be empty"),
            Self::Duplicate(name) => write!(f, "targets: '{name}' appears more than once"),
            Self::Unsorted(name) => write!(f, "targets: must be sorted; '{name}' is out of order"),
            Self::MissingPrimary(device) => write!(
                f,
                "targets: must contain the change set's own device '{device}'"
            ),
            Self::TooMany { count, maximum } => {
                write!(f, "targets: {count} exceeds the maximum of {maximum}")
            }
        }
    }
}

impl std::error::Error for TargetError {}

/// Check a target set: non-empty, sorted, unique, and within `maximum`.
///
/// # Errors
/// Returns [`TargetError`] describing the first problem found.
pub fn validate_targets(targets: &[String], maximum: usize) -> Result<(), TargetError> {
    if targets.is_empty() {
        return Err(TargetError::Empty);
    }
    if targets.len() > maximum {
        return Err(TargetError::TooMany {
            count: targets.len(),
            maximum,
        });
    }
    for (index, name) in targets.iter().enumerate() {
        if name.is_empty() {
            return Err(TargetError::EmptyName);
        }
        if index > 0 {
            let previous = &targets[index - 1];
            if name == previous {
                return Err(TargetError::Duplicate(name.clone()));
            }
            if name < previous {
                return Err(TargetError::Unsorted(name.clone()));
            }
        }
    }
    Ok(())
}

/// Approval record stored on a change set after successful approval or waiver.
///
/// This record makes the approval tamper-evident: the digest binds the approver
/// to the plan digest, owner, and timestamp. Editing any of these fields in the
/// state file invalidates the digest and causes validation to fail on load.
///
/// For waived approvals in lab mode, the `approver` field is absent and `waived`
/// is present, making the record programmatically distinguishable from genuine
/// two-person approvals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    /// Principal who approved this change set (must be distinct from owner).
    ///
    /// Present only for genuine two-person approvals; absent when waived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    /// Unix timestamp when the approval was granted or waived.
    pub approved_at_unix: u64,
    /// Tamper-evident digest.
    ///
    /// For genuine approvals: `(change_set_id, plan_digest, owner, approver, approved_at)`.
    /// For waived approvals: [`crate::digest::compute_waiver_digest_v3`] over
    /// `(change_set_id, plan_digest, owner, waived_at, waiver)`, which binds the
    /// waiver's kind, expiry and ticket. Records written before schema v3 used
    /// [`crate::digest::compute_waiver_digest`] instead, and are still verified
    /// with it when the file declares version 1 or 2.
    pub digest: String,
    /// Which rule [`digest`](Self::digest) was computed under.
    ///
    /// Per-record rather than per-file, and deliberately so. The waiver and
    /// approval migrations before this one re-signed old records under the new
    /// rule on load, which was safe because the old digest already covered every
    /// field the new one bound — promoting it authenticated nothing new.
    ///
    /// v5 breaks that property: it binds the preview digest, which v4 did not
    /// cover. Re-signing a v4 approval as v5 would assert that its approver
    /// consented to the preview, when at the time they approved nothing tied the
    /// two together. So v4 records stay v4, are verified under v4 forever, and
    /// are never promoted — which needs the version to travel with the record
    /// rather than with the file.
    ///
    /// Defaults to 4: a file at schema version 4 or above has already had any
    /// legacy approval migrated to v4 by `read_state`, so an absent field means
    /// v4. Records below that are handled by the file-version branch instead.
    #[serde(default = "approval_digest_v4", skip_serializing_if = "is_v4")]
    pub digest_version: u8,
    /// Waiver record, present when approval was waived — whether by lab mode or
    /// by an operator-granted exception. See [`WaiverKind`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waived: Option<WaiverRecord>,
    /// How the approver's identity was asserted: `"token"` or `"oidc"`
    /// (MEC-994 W4). Signed into the v7 digest; absent on every record
    /// written under v4/v5/v6, which predate the distinction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
    /// The IdP issuer that signed the approver's verified assertion, when
    /// `mechanism` is `"oidc"`. Signed into the v7 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The IdP's `sub` claim for the approver, when `mechanism` is `"oidc"`.
    /// Signed into the v7 digest. Never an email or display name — see
    /// `mecmcp-oidc`'s claim extraction, which never reads one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// The default [`ApprovalRecord::digest_version`] — see that field.
const fn approval_digest_v4() -> u8 {
    4
}

/// Keeps a v4 record byte-identical on disk to what it was before this field
/// existed, so a deployment with no v5 approvals writes exactly what it wrote
/// before and keeps selecting its old schema version.
fn is_v4(version: &u8) -> bool {
    *version == 4
}

/// How an approval came to be waived.
///
/// Bound into the waiver digest, so a record cannot be relabelled after the
/// fact. Before mecmcp#275 every waiver was implicitly lab-mode, which reported
/// a bounded exception and a disabled control as the same event.
///
/// `#[non_exhaustive]`: the set of ways an exception can be granted is exactly
/// the kind of list that grows, and this type exists because the previous
/// version of it was implicitly a set of one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WaiverKind {
    /// `--lab-mode`: the control is switched off for this process.
    ///
    /// The default for a record that does not say, which is what every v1 and
    /// v2 waiver looks like.
    #[default]
    LabMode,
    /// Granted out of band, in a file the service process cannot write.
    OperatorFile,
    /// Granted in band, by a second principal calling a tool.
    OperatorTool,
}

impl WaiverKind {
    /// The wire name, identical to the serde representation.
    ///
    /// Evidence metadata and the persisted record must name a waiver the same
    /// way; two spellings of one kind is how a search for every operator-file
    /// exception quietly misses half of them.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LabMode => "lab_mode",
            Self::OperatorFile => "operator_file",
            Self::OperatorTool => "operator_tool",
        }
    }
}

/// Why an approval was waived, and under what authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverRecord {
    /// How the waiver was granted. Digest-bound.
    ///
    /// Defaults to [`WaiverKind::LabMode`] so a v1/v2 body carrying only
    /// `reason` still decodes.
    #[serde(default)]
    pub kind: WaiverKind,
    /// Reason for waiving approval.
    pub reason: String,
    /// When this waiver stops being valid. Digest-bound.
    ///
    /// `None` means it does not expire, which is the only thing lab mode can
    /// mean. Bound into the digest because an expiry that can be edited
    /// afterwards is not a time box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// External change-control reference. Digest-bound.
    ///
    /// Bound because its only purpose is pointing an auditor at the record that
    /// authorised this, and a rewritable pointer misleads that reader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

/// Error type for record validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    field: &'static str,
    message: String,
}

impl RecordError {
    fn new(field: &'static str, message: String) -> Self {
        Self { field, message }
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

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for RecordError {}

/// Validates that an operation's policy signature matches the current policy.
///
/// The policy signature is a stable identifier computed from the policy configuration
/// at the time the operation was staged. If the policy changes before the operation
/// commits, this guard detects the drift and rejects the operation.
///
/// # Errors
///
/// Returns an error if the operation's stored policy signature does not match
/// the current policy signature.
pub fn require_operation_policy<P: AsRef<str>>(
    record: &OperationRecord,
    current_policy_signature: P,
) -> Result<(), RecordError> {
    if record.policy_signature == current_policy_signature.as_ref() {
        Ok(())
    } else {
        Err(RecordError::new(
            "operation_id",
            "policy changed after this operation staged; discard or recover manually".to_string(),
        ))
    }
}

/// Validates that an operation's fingerprint matches the current candidate state.
///
/// This is the fingerprint guard: the caller observed a specific candidate fingerprint
/// and expects it unchanged. The operation staged against a specific fingerprint.
/// Both must match the device's actual current state.
///
/// # Errors
///
/// Returns an error if:
/// - The expected fingerprint format is invalid
/// - The actual fingerprint does not match the expected fingerprint
/// - The operation's stored fingerprint does not match the actual fingerprint
pub fn require_operation_fingerprint(
    record: &OperationRecord,
    expected_candidate_fingerprint: &str,
    actual_candidate_fingerprint: &str,
) -> Result<(), RecordError> {
    validate_fingerprint(expected_candidate_fingerprint)
        .map_err(|e| RecordError::new("expected_candidate_fingerprint", e.to_string()))?;

    if expected_candidate_fingerprint != actual_candidate_fingerprint {
        return Err(RecordError::new(
            "expected_candidate_fingerprint",
            "candidate changed since the caller observed it".to_string(),
        ));
    }

    if record.current != actual_candidate_fingerprint {
        return Err(RecordError::new(
            "operation_id",
            "candidate changed after this operation staged".to_string(),
        ));
    }

    Ok(())
}

/// Computes a stable policy signature from a policy identifier.
///
/// The policy signature binds an operation to the exact policy configuration
/// active when it staged. Implementations pass any stable policy identifier
/// (e.g., a policy name, a serialized config hash) and this function produces
/// a SHA-256 digest suitable for later comparison.
///
/// For vendor-specific policies with multiple fields, the implementation should
/// serialize all relevant fields into a single string before passing to this function.
#[must_use]
pub fn mutation_policy_signature<P: AsRef<str>>(policy_identifier: P) -> String {
    let mut digest = Sha256::new();
    digest.update(policy_identifier.as_ref().as_bytes());
    format!("sha256:{}", digest_hex(&digest.finalize()))
}

/// Validates a change-set's actions against operational limits.
///
/// This is vendor-agnostic validation: the crate validates only structural
/// constraints (non-empty, count limit, serialized size limit). Vendor-specific
/// validation (XPath roots, config format, admin scope) remains the implementation's
/// responsibility.
///
/// # Errors
///
/// Returns an error if:
/// - The actions list is empty
/// - The actions count exceeds `limits.max_actions_per_set`
/// - The serialized actions exceed `limits.max_change_set_bytes`
pub fn validate_change_set_actions<A: Serialize>(
    actions: &[A],
    limits: &OperationLimits,
) -> Result<(), RecordError> {
    if actions.is_empty() {
        return Err(RecordError::new(
            "actions",
            "change set must contain at least 1 action".to_string(),
        ));
    }

    if actions.len() > limits.max_actions_per_set {
        return Err(RecordError::new(
            "actions",
            format!(
                "change set exceeds maximum of {} actions",
                limits.max_actions_per_set
            ),
        ));
    }

    let encoded = serde_json::to_vec(actions).map_err(|error| {
        RecordError::new("actions", format!("could not encode change set: {error}"))
    })?;

    if encoded.len() as u64 > limits.max_change_set_bytes {
        return Err(RecordError::new(
            "actions",
            format!(
                "serialized change set exceeds {} bytes",
                limits.max_change_set_bytes
            ),
        ));
    }

    Ok(())
}

/// Re-export digest functions for use in tests and validation.
pub use crate::digest::{change_set_digest, change_set_digest_with_targets, preview_digest};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiver_kind_serializes_to_stable_snake_case_names() {
        // These strings are on disk in every persisted waiver. Renaming a variant
        // must not silently change them, so they are asserted explicitly rather
        // than derived.
        for (kind, expected) in [
            (WaiverKind::LabMode, "\"lab_mode\""),
            (WaiverKind::OperatorFile, "\"operator_file\""),
            (WaiverKind::OperatorTool, "\"operator_tool\""),
        ] {
            let encoded = serde_json::to_string(&kind).expect("encode kind");
            assert_eq!(encoded, expected, "on-disk name for {kind:?} changed");
            let decoded: WaiverKind = serde_json::from_str(&encoded).expect("decode kind");
            assert_eq!(decoded, kind);
        }
    }

    #[test]
    fn a_legacy_waiver_body_decodes_as_lab_mode() {
        // v1 and v2 files carry `{"reason": "..."}` and nothing else. They must
        // load, and they must mean lab mode — that is all a waiver could be before
        // this change.
        let record: WaiverRecord =
            serde_json::from_str(r#"{"reason":"lab-mode"}"#).expect("legacy waiver body");
        assert_eq!(record.kind, WaiverKind::LabMode);
        assert_eq!(record.reason, "lab-mode");
        assert_eq!(record.expires_at_unix, None);
        assert_eq!(record.ticket, None);
    }
}
