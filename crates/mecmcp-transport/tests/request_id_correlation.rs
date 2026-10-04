//! Transport and handler audit events for one request share a `request_id` (mecmcp#269).
//!
//! Since mecmcp#32 an authenticated `tools/call` produces two audit events: the
//! transport preflight event and the handler's enriched event. They are meant to
//! be joinable by a SIEM consumer — the comment in
//! `mecmcp-transport/src/auth.rs` says so. Before mecmcp#269 they were not:
//! `Attribution::from_caller` minted a fresh `Uuid` on every call, so each event
//! carried its own correlation ID and the join was impossible.
//!
//! These tests assert the two IDs are **equal**, not merely that both events
//! exist. Asserting existence is what let the defect survive.

use axum::{
    Extension, Router,
    body::Body,
    http::{Request, header},
    routing::post,
};
use mecmcp_audit::testutil::run_with_capture;
use mecmcp_auth::{ActorType, BearerSyntax, CallerCtx, Grant, GrantError, NoGrant, ScopeSet};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting, LimitsConfig,
    apply_bearer_boundary,
};
use std::sync::Arc;
use tower::ServiceExt as _;

/// Collect every `request_id=<value>` emitted, in order.
fn captured_request_ids(captured: &str) -> Vec<String> {
    captured
        .match_indices("request_id=")
        .map(|(idx, marker)| {
            captured[idx + marker.len()..]
                .split(|c: char| c.is_whitespace() || c == ',')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

fn caller(client_name: Option<&'static str>) -> CallerCtx<NoGrant> {
    CallerCtx::<NoGrant> {
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
    }
}

/// Emit the transport event and the handler event for one request, the way the
/// bearer preflight middleware and a handler each do.
fn emit_correlated_events(caller: &CallerCtx<NoGrant>) {
    let mut transport_scope =
        mecmcp_audit::AuditScope::from_caller(caller, "get_router_list", "transport", Vec::new());
    transport_scope.meta("layer", "preflight");
    transport_scope.succeed();
    drop(transport_scope);

    let mut handler_scope =
        mecmcp_audit::AuditScope::from_caller(caller, "get_router_list", "read", Vec::new());
    handler_scope.succeed();
}

/// The two events for one request must be joinable.
///
/// Regression test for mecmcp#269.
#[test]
fn transport_and_handler_events_share_one_request_id() {
    let captured = run_with_capture(|| {
        emit_correlated_events(&caller(Some("correlation-proof")));
    });

    let ids = captured_request_ids(&captured);

    assert_eq!(
        ids.len(),
        2,
        "expected one transport and one handler event, got:\n{captured}"
    );
    assert_eq!(
        ids[0], ids[1],
        "transport and handler events for one request must share a request_id, \
         otherwise a SIEM cannot join the preflight attribution to the handler \
         outcome; got:\n{captured}"
    );
}

/// Two separate requests must not collide.
///
/// The fix must make one ID per request, not one ID per process — a constant
/// would satisfy the test above and destroy the correlation it exists for.
#[test]
fn separate_requests_get_distinct_request_ids() {
    let captured = run_with_capture(|| {
        emit_correlated_events(&caller(None));
        emit_correlated_events(&caller(None));
    });

    let ids = captured_request_ids(&captured);

    assert_eq!(ids.len(), 4, "expected four events, got:\n{captured}");
    assert_eq!(ids[0], ids[1], "first request's two events must agree");
    assert_eq!(ids[2], ids[3], "second request's two events must agree");
    assert_ne!(
        ids[0], ids[2],
        "two different requests must not share a request_id, or the correlation \
         ID identifies nothing; got:\n{captured}"
    );
}

// ---------------------------------------------------------------------------
// Boundary-level test.
//
// The tests above build one `CallerCtx` by hand and prove `from_caller` reads
// it. That is necessary but not sufficient, and it is precisely the shape that
// let mecmcp#53's inert `client_name` ship: a unit test proves the mechanism
// works *when wired*, and observes nothing about the wiring.
//
// The wiring question here is whether the caller context the handler receives
// is the same one the transport audited. The preflight middleware clones the
// context out of extensions, audits from the clone, then re-inserts it — so a
// future refactor that rebuilt the context instead of re-inserting it would
// restore the defect with every test above still green.
//
// This test drives a real `apply_bearer_boundary` stack and reads the context
// the handler is actually handed.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TestGrant;

impl Grant for TestGrant {
    type Action = ();
    fn allows_action(&self, _action: Self::Action) -> bool {
        true
    }
    fn allows_subject(&self, _subject: &str) -> bool {
        true
    }
    fn validate(&self) -> Result<(), GrantError> {
        Ok(())
    }
}

/// Mint a caller the way production does: a fresh `request_id` per authentication.
fn authenticated_caller() -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "operator".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: Some(TestGrant),
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
    }
}

/// A router whose terminal handler emits the handler-side audit event from the
/// `CallerCtx` the boundary handed it — the same way a real handler does.
fn app() -> Router {
    let router = Router::new().route(
        "/",
        post(
            |Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                let mut scope =
                    mecmcp_audit::AuditScope::from_caller(&caller, "read", "read", Vec::new());
                scope.succeed();
                "ok"
            },
        ),
    );

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(authenticated_caller)
    });

    apply_bearer_boundary(
        router,
        BearerBoundary::new(authenticator, BearerResponseProfile::compact("test")),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 4096,
                ..Default::default()
            }),
        },
    )
}

/// The context the handler receives must carry the ID the transport audited.
///
/// Regression guard for mecmcp#269 at the layer that actually assembles the
/// request, not at a hand-built `CallerCtx`.
#[test]
fn boundary_hands_the_handler_the_audited_request_id() {
    let captured = run_with_capture(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");

        runtime.block_on(async {
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(
                    r#"{"method":"tools/call","params":{"name":"read","arguments":{}}}"#,
                ))
                .expect("request");

            let response = app().oneshot(request).await.expect("response");
            assert_eq!(response.status(), 200, "request should have been allowed");
        });
    });

    let ids = captured_request_ids(&captured);

    assert_eq!(
        ids.len(),
        2,
        "expected the transport preflight event and the handler event, got:\n{captured}"
    );
    assert_eq!(
        ids[0], ids[1],
        "the CallerCtx handed to the handler must carry the same request_id the \
         transport audited, or the two events for one request cannot be joined; \
         got:\n{captured}"
    );
}
