//! `audit_scope` must produce a comparable record on both transports.
//!
//! An `AuditScope` keeps its fields private and emits exactly one
//! `target="audit"` event when it drops, so the emitted event *is* the
//! observable — asserting on struct fields would need mecmcp-audit to widen its
//! API for a test, which is the wrong trade.
//!
//! Its own test binary: the capture installs a global tracing subscriber, which
//! can only be set once per process.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::testutil::CapturingWriter;
use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
use mecmcp_server::audit_scope;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[test]
fn both_transports_emit_the_same_tool_and_action() {
    let writer = CapturingWriter::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false),
        )
        .init();

    {
        let caller = CallerCtx::<NoGrant> {
            token_name: "reader".to_owned(),
            devices: ScopeSet::Allowlist(vec!["fw-01".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let mut authenticated = audit_scope(
            Some(&caller),
            "get_config",
            "read",
            vec!["fw-01".to_owned()],
        );
        authenticated.succeed();
    }
    {
        let mut stdio =
            audit_scope::<NoGrant>(None, "get_config", "read", vec!["fw-01".to_owned()]);
        stdio.succeed();
    }

    let captured = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    let audit_lines: Vec<&str> = captured
        .lines()
        .filter(|line| line.contains("tool=get_config"))
        .collect();
    assert_eq!(
        audit_lines.len(),
        2,
        "both paths must emit exactly one audit event each:\n{captured}"
    );

    // The shape agrees, which is the point of routing both through one helper.
    for line in &audit_lines {
        assert!(line.contains("action=read"), "got {line}");
        assert!(line.contains("devices=fw-01"), "got {line}");
    }

    // What differs is the attribution: one names the token, the other says stdio.
    assert!(
        audit_lines.iter().any(|line| line.contains("reader")),
        "the authenticated event must name the token:\n{captured}"
    );
    assert!(
        audit_lines.iter().any(|line| line.contains("stdio")),
        "the stdio event must say so:\n{captured}"
    );
}
