//! Client name propagation to handler-side audit events (mecmcp#253).
//!
//! Transport-level audit events already captured client_name (mecmcp#53).
//! Handler-side events must also see it, via CallerCtx, without each handler
//! re-implementing the session lookup.

use mecmcp_audit::testutil::run_with_capture;
use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

/// Emit correlated transport and handler audit events with client name.
fn emit_correlated_events(client_name: Option<&'static str>) {
    let caller = CallerCtx::<NoGrant> {
        token_name: "test-token".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Agent,
        oidc_subject: None,
        verified_approver: None,
        client_name,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    };

    // Transport event (emitted by bearer_preflight_middleware)
    let mut transport_scope =
        mecmcp_audit::AuditScope::from_caller(&caller, "get_router_list", "transport", Vec::new());
    transport_scope.meta("layer", "preflight");
    transport_scope.succeed();

    // Handler event (emitted by handler via Attribution::from_caller)
    let mut handler_scope =
        mecmcp_audit::AuditScope::from_caller(&caller, "get_router_list", "read", Vec::new());
    handler_scope.succeed();
}

/// Both transport and handler events must carry the same client_name when present.
///
/// Regression test for mecmcp#253: handlers build their own Attribution from
/// CallerCtx, which now carries the client name captured from the session. Both
/// events should agree.
#[test]
fn transport_and_handler_events_carry_same_client_name() {
    let captured = run_with_capture(|| {
        emit_correlated_events(Some("pin-bump-proof"));
    });

    // Both events should contain the client name.
    let transport_count = captured.matches("client_name=pin-bump-proof").count();
    let action_transport = captured.matches("action=transport").count();
    let action_read = captured.matches("action=read").count();

    assert_eq!(
        transport_count, 2,
        "both transport and handler events must carry client_name, got:\n{captured}"
    );
    assert_eq!(
        action_transport, 1,
        "should have exactly one transport event, got:\n{captured}"
    );
    assert_eq!(
        action_read, 1,
        "should have exactly one handler event, got:\n{captured}"
    );
}

/// Both events must have empty client_name when the session provided none.
///
/// Ensures the field defaults to empty rather than carrying stale state.
#[test]
fn both_events_empty_when_no_client_name() {
    let captured = run_with_capture(|| {
        emit_correlated_events(None);
    });

    // When no client_name is present, agent identity should not be created (no provider either).
    // The audit format shows client_name= (empty) when there's no agent identity.
    assert!(
        captured.contains("client_name= "),
        "client_name must be empty when not provided, got:\n{captured}"
    );
    assert!(
        captured.contains("action=transport"),
        "transport event must be present:\n{captured}"
    );
    assert!(
        captured.contains("action=read"),
        "handler event must be present:\n{captured}"
    );
}

/// Sequential requests must not leak client_name between them.
///
/// Ensures that a request with clientInfo followed by one without does not
/// carry the first request's name into the second's events.
#[test]
fn no_client_name_leakage_between_requests() {
    let captured = run_with_capture(|| {
        // First request: has client name
        emit_correlated_events(Some("first-client"));

        // Second request: no client name
        emit_correlated_events(None);
    });

    // The first pair of events should have the client name
    let first_client_count = captured.matches("client_name=first-client").count();
    assert_eq!(
        first_client_count, 2,
        "first request's events must carry its client_name:\n{captured}"
    );

    // The second pair should have empty client_name (no agent identity).
    // Count how many times we see "client_name= " (with space, indicating empty).
    let empty_client_name_count = captured.matches("client_name= ").count();
    assert_eq!(
        empty_client_name_count, 2,
        "second request must have empty client_name, got:\n{captured}"
    );

    // Verify we have 4 total events (2 transport + 2 handler)
    let transport_count = captured.matches("action=transport").count();
    let read_count = captured.matches("action=read").count();
    assert_eq!(transport_count, 2, "expected 2 transport events");
    assert_eq!(read_count, 2, "expected 2 handler events");
}

/// Round-trip test: CallerCtx -> Attribution -> audit event carries client_name.
///
/// Verifies the complete path from CallerCtx.client_name through
/// Attribution::from_caller to the emitted audit event.
#[test]
fn client_name_round_trips_from_caller_ctx_to_audit_event() {
    let caller = CallerCtx::<NoGrant> {
        token_name: "test".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: Some("anthropic".to_owned()),
        provider_tier: Some(mecmcp_auth::Tier::Public),
        on_behalf_of: None,
        actor_type: ActorType::Agent,
        oidc_subject: None,
        verified_approver: None,
        client_name: Some("claude-code"),
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    };

    let captured = run_with_capture(|| {
        let mut scope =
            mecmcp_audit::AuditScope::from_caller(&caller, "get_config", "read", Vec::new());
        scope.succeed();
    });

    assert!(
        captured.contains("client_name=claude-code"),
        "client_name from CallerCtx must appear in audit event:\n{captured}"
    );
}
