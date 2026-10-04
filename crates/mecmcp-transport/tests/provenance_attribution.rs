//! Unit tests for `Attribution::from_caller` provenance population.
//!
//! These tests hand-construct `CallerCtx` with provenance fields already set,
//! so they verify only that `Attribution::from_caller` copies those fields into
//! `AgentIdentity`. They do NOT exercise:
//! - Parsing `_meta.mecmcp/provenance` from initialize params
//! - Storing provenance in SessionTracker
//! - The hand-off in `auth.rs` that extracts provenance from the session
//!
//! For the complete chain, see `bearer_boundary::provenance_from_meta_reaches_audit_attribution`,
//! which drives the real parse → session store → hand-off → attribution path.

use mecmcp_audit::testutil::run_with_capture;
use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

#[test]
fn provenance_fields_flow_from_meta_to_audit_attribution() {
    // Simulate what the bearer preflight does: extract provenance from
    // the session and set it on CallerCtx.
    let caller = CallerCtx::<NoGrant> {
        token_name: "test-token".to_owned(),
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
        model_id: Some("claude-opus-5"),
        session_id: Some("01JXYZ123456789".to_owned()),
        request_id: uuid::Uuid::new_v4(),
    };

    let captured = run_with_capture(|| {
        let mut scope =
            mecmcp_audit::AuditScope::from_caller(&caller, "get_config", "read", Vec::new());
        scope.succeed();
    });

    // Both model_id and session_id must appear in the audit event.
    assert!(
        captured.contains("model_id=claude-opus-5"),
        "model_id missing from audit event:\n{captured}"
    );
    assert!(
        captured.contains("session_id=01JXYZ123456789"),
        "session_id missing from audit event:\n{captured}"
    );
    assert!(
        captured.contains("client_name=claude-code"),
        "client_name missing from audit event:\n{captured}"
    );
}

#[test]
fn missing_provenance_fields_work() {
    // A client that doesn't send `_meta` must still work. The provenance
    // fields on CallerCtx remain None.
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
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    };

    let captured = run_with_capture(|| {
        let mut scope =
            mecmcp_audit::AuditScope::from_caller(&caller, "get_config", "read", Vec::new());
        scope.succeed();
    });

    // The event should not error. Fields will be empty strings when None.
    assert!(captured.contains("action=read"));
    // Empty strings render as `model_id=` and `session_id=` (no value after =)
    assert!(
        captured.contains("model_id=,") || captured.contains("model_id= "),
        "model_id should be empty in audit event:\n{captured}"
    );
    assert!(
        captured.contains("session_id=,")
            || captured.contains("session_id= ")
            || captured.contains("session_id=\n"),
        "session_id should be empty in audit event:\n{captured}"
    );
}

#[test]
fn provenance_populated_in_both_attribution_arms() {
    // Regression test: both the provider-verified arm and the fallback arm
    // of Attribution::from_caller must populate model_id and session_id.
    // Forgetting to populate them in the _ => arm would leave fields empty
    // for tokens without a provider.

    // Case 1: Token WITH provider (verified arm)
    let caller_verified = CallerCtx::<NoGrant> {
        token_name: "verified".to_owned(),
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
        model_id: Some("claude-opus-5"),
        session_id: Some("01JVERIFIED".to_owned()),
        request_id: uuid::Uuid::new_v4(),
    };

    let captured_verified = run_with_capture(|| {
        let mut scope = mecmcp_audit::AuditScope::from_caller(
            &caller_verified,
            "get_config",
            "read",
            Vec::new(),
        );
        scope.succeed();
    });

    assert!(
        captured_verified.contains("model_id=claude-opus-5"),
        "provider arm must populate model_id:\n{captured_verified}"
    );
    assert!(
        captured_verified.contains("session_id=01JVERIFIED"),
        "provider arm must populate session_id:\n{captured_verified}"
    );

    // Case 2: Token WITHOUT provider (fallback arm)
    let caller_fallback = CallerCtx::<NoGrant> {
        token_name: "fallback".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Agent,
        oidc_subject: None,
        verified_approver: None,
        client_name: Some("claude-code"),
        model_id: Some("claude-opus-5"),
        session_id: Some("01JFALLBACK".to_owned()),
        request_id: uuid::Uuid::new_v4(),
    };

    let captured_fallback = run_with_capture(|| {
        let mut scope = mecmcp_audit::AuditScope::from_caller(
            &caller_fallback,
            "get_config",
            "read",
            Vec::new(),
        );
        scope.succeed();
    });

    assert!(
        captured_fallback.contains("model_id=claude-opus-5"),
        "fallback arm must populate model_id:\n{captured_fallback}"
    );
    assert!(
        captured_fallback.contains("session_id=01JFALLBACK"),
        "fallback arm must populate session_id:\n{captured_fallback}"
    );
}
