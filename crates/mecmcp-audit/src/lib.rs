//! Caller-attributed audit events for vendor-neutral MCP servers.
//!
//! This crate is deliberately free of vendor concepts. It knows about
//! principals, attribution, and audit outcomes; it does not know what
//! a device is or what configuration it holds.

mod attribution;
pub mod canonical;
pub mod checkpoint;
pub mod device_log;
pub mod direct_commit;
pub mod evidence;
mod init;
pub mod otel;
pub mod recorder;
mod redact;
mod schema;
mod scope;
pub mod service;
pub mod signing;
pub mod sinks;
pub mod testutil;

pub use attribution::{
    ActorType, AgentIdentity, Attribution, Principal, Tier, TokenVerifiedFields,
};
pub use checkpoint::{
    Checkpoint, CheckpointError, checkpoint_digest, key_id, sign_checkpoint, verify_checkpoint,
};
pub use direct_commit::{DIRECT_COMMIT_DENIED_REASON, DirectCommitPolicy, DirectCommitRefused};
pub use evidence::{
    ApplyIntentRecord, ApprovalRecord, ChainSegment, ClosedSegment, EvidenceError, EvidenceRecord,
    GENESIS_PREV_HASH, ProposalRecord, ResultReceipt, SegmentArchive, append, close,
};
pub use init::{AuditConfig, AuditFileSink, AuditFormat, FileHandle, init_tracing, shutdown_otel};
#[cfg(feature = "otel")]
pub use otel::OtelGuard;
pub use otel::{OtelConfig, OtelError};
pub use redact::{
    AuditRedaction, FieldTransform, REDACTABLE_FIELDS, RedactError, active, install, render,
};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::{
    AuditScope, DEFAULT_DURATION_METRIC, duration_metric_name, install_duration_metric_name,
};
pub use service::{EvidenceConfig, EvidencePipelineConfig, EvidenceService, ForwardOnlyConfig};
pub use sinks::{
    DeliveryLedger, DeliveryReport, DeliveryStatus, ForwardSink, ForwardSinkConfig,
    ForwardSinkError, ProducedHead, SsdfSink, SsdfSinkConfig, SsdfSinkError,
};
