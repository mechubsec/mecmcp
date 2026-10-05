//! Commit metadata hook for attaching provenance to vendor-native commit mechanisms.
//!
//! This module provides a trait and composition logic that every mecmcp-based server
//! inherits: device transactions implement [`CommitMetadataSink`], and the library
//! composes operator comments + provenance lines and handles attachment failures
//! gracefully (fail-open for the commit, fail-closed for the audit record).

use mecmcp_audit::Attribution;
use std::fmt;

/// Error attaching commit metadata to the vendor-native commit mechanism.
#[derive(Debug)]
pub enum CommitMetaError {
    /// The sink rejected the metadata line.
    SinkFailed(String),
}

impl fmt::Display for CommitMetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommitMetaError::SinkFailed(msg) => write!(f, "sink failed: {}", msg),
        }
    }
}

impl std::error::Error for CommitMetaError {}

/// Implemented by each server's device transport to attach commit metadata.
///
/// This trait lets Junos, PAN-OS, and future vendors attach provenance to their
/// native commit mechanisms (Junos commit comments, PAN-OS commit descriptions)
/// without the library knowing vendor-specific RPC details.
pub trait CommitMetadataSink {
    /// Attach the composed metadata line to the vendor-native commit mechanism.
    ///
    /// The line passed here is the full composed string (operator comment +
    /// provenance), ready to be written to the device. Implementations must NOT
    /// modify the line — composition is the library's job, not the sink's.
    ///
    /// # Errors
    ///
    /// Returns an error if the device is unreachable or the attachment RPC fails.
    /// The library handles these failures gracefully: the commit proceeds, and
    /// the miss is recorded in the audit event.
    fn attach(&mut self, line: &str) -> Result<(), CommitMetaError>;
}

/// Outcome of attempting to attach commit metadata.
///
/// Recorded in the audit event so SIEM queries can detect attribution misses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachOutcome {
    /// Metadata was successfully attached to the commit.
    Attached,
    /// Attachment failed; the commit proceeded without metadata.
    ///
    /// The reason is recorded in the audit event. Typical causes: device
    /// unreachable during the attach RPC, vendor API rejection, timeout.
    Missed {
        /// Human-readable reason for the failure.
        reason: String,
    },
}

/// Compose operator comment + provenance line and attach to the commit.
///
/// This is the library-owned hook that every mecmcp-based server flows through.
/// It composes the metadata line (never replacing the operator's text), calls
/// the sink, and on ANY failure lets the commit proceed while recording the
/// miss in the audit event (fail-open for the change, fail-closed for the record).
///
/// # Composition rules
///
/// - If `operator_comment` is `Some(text)` and non-empty, the composed line is
///   `{text} | {provenance}` (operator text, pipe delimiter, provenance).
/// - If `operator_comment` is `None` or empty, the composed line is just the
///   provenance string (no delimiter, no empty prefix).
/// - The provenance string is `AgentIdentity::provenance_string(on_behalf_of)`,
///   which includes the request ID for Task 10's cross-reference join.
///
/// # Fail-open semantics
///
/// A sink failure does NOT propagate as an error. The commit must proceed even
/// if provenance cannot be attached — an attribution miss is better than
/// blocking a legitimate change. The outcome is returned so the caller can
/// record it in the audit event.
///
/// # Parameters
///
/// - `sink`: Vendor-specific implementation that writes the line to the device.
/// - `operator_comment`: Optional human-provided comment to preserve and prefix.
/// - `attribution`: The structured attribution containing provenance data.
///
/// # Returns
///
/// [`AttachOutcome::Attached`] on success, or [`AttachOutcome::Missed`] with
/// the failure reason on any error. Never propagates an error — the outcome is
/// always returned for audit recording.
pub fn apply_commit_metadata(
    sink: &mut dyn CommitMetadataSink,
    operator_comment: Option<&str>,
    attribution: &Attribution,
) -> AttachOutcome {
    // Compose the provenance string. If the attribution has no agent, there's
    // no provenance to attach — return Attached (nothing to do is success).
    let provenance = match &attribution.agent {
        Some(agent) => {
            let prov_str = agent.provenance_string(attribution.on_behalf_of.as_deref());
            // Include the request ID so Task 10's verify can join on it
            format!("{} request.id={}", prov_str, attribution.request_id)
        }
        None => {
            // No agent identity means no provenance to attach. This is not an
            // error — human-only attributions have no provenance string.
            return AttachOutcome::Attached;
        }
    };

    // Compose the final line: operator comment (if present) + provenance
    let line = match operator_comment {
        Some(comment) if !comment.trim().is_empty() => {
            format!("{} | {}", comment.trim(), provenance)
        }
        _ => provenance,
    };

    // Attempt to attach. On failure, record the reason but do NOT propagate
    // the error — the commit must proceed.
    match sink.attach(&line) {
        Ok(()) => AttachOutcome::Attached,
        Err(error) => AttachOutcome::Missed {
            reason: error.to_string(),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_audit::{ActorType, AgentIdentity, Principal, Tier, TokenVerifiedFields};
    use uuid::Uuid;

    /// Mock sink that records the line it received.
    struct MockSink {
        recorded: Option<String>,
        fail: bool,
    }

    impl MockSink {
        fn new() -> Self {
            Self {
                recorded: None,
                fail: false,
            }
        }

        fn fail_next(&mut self) {
            self.fail = true;
        }
    }

    impl CommitMetadataSink for MockSink {
        fn attach(&mut self, line: &str) -> Result<(), CommitMetaError> {
            if self.fail {
                return Err(CommitMetaError::SinkFailed("mock failure".into()));
            }
            self.recorded = Some(line.to_string());
            Ok(())
        }
    }

    fn test_attribution() -> Attribution {
        Attribution {
            principal: Principal::Token("test-token".into()),
            actor_type: ActorType::Agent,
            agent: Some(AgentIdentity {
                model_id: "claude-opus-5".into(),
                session_id: "sess-123".into(),
                client_name: None,
                provider: "anthropic".into(),
                provider_tier: Tier::Public,
                skills_used: vec![],
            }),
            on_behalf_of: Some("dev@example.com".into()),
            change_ref: None,
            request_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            token_verified_fields: TokenVerifiedFields::none(),
            verified_approver: None,
            approver: None,
            change_set_id: None,
        }
    }

    #[test]
    fn composition_appends_operator_comment() {
        let mut sink = MockSink::new();
        let attr = test_attribution();

        let outcome = apply_commit_metadata(&mut sink, Some("Fix BGP peering"), &attr);

        assert_eq!(outcome, AttachOutcome::Attached);
        let recorded = sink.recorded.expect("sink should have received a line");
        assert!(
            recorded.starts_with("Fix BGP peering |"),
            "operator comment must be preserved as prefix"
        );
        assert!(
            recorded.contains("anthropic-public, claude-opus-5"),
            "provenance must be appended"
        );
    }

    #[test]
    fn composition_never_replaces_operator_comment() {
        let mut sink = MockSink::new();
        let attr = test_attribution();

        apply_commit_metadata(&mut sink, Some("Operator text here"), &attr);

        let recorded = sink.recorded.unwrap();
        assert!(
            recorded.contains("Operator text here"),
            "operator comment must be retained verbatim"
        );
        assert!(
            recorded.contains(" | "),
            "delimiter must separate operator text from provenance"
        );
    }

    #[test]
    fn provenance_line_contains_request_id() {
        let mut sink = MockSink::new();
        let attr = test_attribution();

        apply_commit_metadata(&mut sink, None, &attr);

        let recorded = sink.recorded.unwrap();
        assert!(
            recorded.contains("request.id=550e8400-e29b-41d4-a716-446655440000"),
            "request ID must be included for Task 10 join: {}",
            recorded
        );
    }

    #[test]
    fn sink_failure_yields_missed_outcome() {
        let mut sink = MockSink::new();
        sink.fail_next();
        let attr = test_attribution();

        let outcome = apply_commit_metadata(&mut sink, Some("comment"), &attr);

        match outcome {
            AttachOutcome::Missed { reason } => {
                assert!(
                    reason.contains("mock failure"),
                    "reason must carry the sink error"
                );
            }
            AttachOutcome::Attached => {
                panic!("expected Missed, got Attached");
            }
        }
    }

    #[test]
    fn sink_failure_does_not_propagate_error() {
        let mut sink = MockSink::new();
        sink.fail_next();
        let attr = test_attribution();

        // This must not panic — sink failure returns an outcome, not an error
        let _outcome = apply_commit_metadata(&mut sink, Some("comment"), &attr);
    }

    #[test]
    fn empty_operator_comment_omits_delimiter() {
        let mut sink = MockSink::new();
        let attr = test_attribution();

        apply_commit_metadata(&mut sink, Some("   "), &attr);

        let recorded = sink.recorded.unwrap();
        assert!(
            !recorded.contains(" | "),
            "empty comment must not produce a delimiter"
        );
        assert!(
            recorded.starts_with("anthropic-public"),
            "provenance must be the entire line when comment is empty"
        );
    }

    #[test]
    fn none_operator_comment_yields_provenance_only() {
        let mut sink = MockSink::new();
        let attr = test_attribution();

        apply_commit_metadata(&mut sink, None, &attr);

        let recorded = sink.recorded.unwrap();
        assert!(
            !recorded.contains(" | "),
            "None comment must not produce a delimiter"
        );
        assert!(
            recorded.starts_with("anthropic-public"),
            "provenance must be the entire line when comment is None"
        );
    }

    #[test]
    fn no_agent_returns_attached_without_calling_sink() {
        let mut sink = MockSink::new();
        let mut attr = test_attribution();
        attr.agent = None; // Human-only attribution

        let outcome = apply_commit_metadata(&mut sink, Some("comment"), &attr);

        assert_eq!(outcome, AttachOutcome::Attached);
        assert!(
            sink.recorded.is_none(),
            "sink must not be called when there's no agent"
        );
    }

    #[test]
    fn provenance_with_skills() {
        let mut sink = MockSink::new();
        let mut attr = test_attribution();
        if let Some(ref mut agent) = attr.agent {
            agent.skills_used = vec!["srx-nat".into(), "srx-policy".into()];
        }

        apply_commit_metadata(&mut sink, None, &attr);

        let recorded = sink.recorded.unwrap();
        assert!(
            recorded.contains("srx-nat srx-policy"),
            "skills must appear in provenance: {}",
            recorded
        );
    }
}
