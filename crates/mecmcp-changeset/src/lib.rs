//! Fingerprint-bound change-set lifecycle for multi-vendor device automation.
//!
//! This crate provides two-person change control with digest-bound approval, indeterminate
//! recovery, and atomic persistence. It generalizes the PAN-OS mutation lifecycle behind
//! a vendor-agnostic trait so both PAN-OS and Junos can use the same workflow.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod apply;
pub mod approver;
pub mod changeset;
pub mod commit_metadata;
pub mod coordinator;
pub mod digest;
pub mod lifecycle;
pub mod operation;
pub mod persistence;
pub mod records;
pub mod recovery;
mod state_lock;
pub mod transaction;
pub mod types;

pub use apply::ApplyOutput;
pub use approver::ApproverIdentity;
pub use changeset::ChangeSetOutput;
pub use commit_metadata::{
    AttachOutcome, CommitMetaError, CommitMetadataSink, apply_commit_metadata,
};
pub use coordinator::{
    ApprovalDigestKey, ApprovalDigestKeyError, ChangesetCoordinator, CoordinatorError,
    MIN_APPROVAL_DIGEST_KEY_BYTES, StagedRecovery,
};
pub use lifecycle::{ApplyHandle, ChangeSetState, LifecycleState, change_set_transition_allowed};
pub use operation::StageOutput;
#[cfg(feature = "test-util")]
pub use persistence::write_state_for_test;
pub use persistence::{
    ChangesetState, PersistenceError, read_state, read_state_with_key, validate_state,
    validate_state_with_key,
};
pub use records::{
    ApprovalRecord, ChangeSetRecord, OperationRecord, OwnerSubject, PreviewError, PreviewRecord,
    RecordError, TargetError, WaiverKind, WaiverRecord, change_set_digest,
    change_set_digest_with_targets, mutation_policy_signature, preview_digest,
    require_operation_fingerprint, require_operation_policy, validate_change_set_actions,
    validate_targets,
};
pub use recovery::{RecoveryDisposition, ResolvedOperationOutput, resolve_persisted_operation};
pub use transaction::{
    Atomicity, CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
    UnlockOutcome,
};
pub use types::{Fingerprint, FingerprintError, OperationId, OperationIdError, OperationLimits};
