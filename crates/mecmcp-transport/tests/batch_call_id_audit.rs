//! A batch splits where the per-call id may go (mecmcp#304).
//!
//! The transport's audit event describes one specific element — the same one
//! `audited_tool` names — so it keeps that element's `client_call_id`. The
//! request extension is per HTTP request and cannot say which element a
//! handler is dispatching, so it withholds the id for a batch. Both facts are
//! asserted here, together, because the fix for either one alone breaks the
//! other: gating both loses real provenance, gating neither misattributes it.
//!
//! Its own binary for the reason given in `client_extras_extension.rs` — audit
//! capture in this crate's test suite is sensitive to what else runs beside it
//! (mecmcp#305).

use axum::{
    Extension, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{ActorType, BearerSyntax, CallerCtx, Grant, GrantError, ScopeSet};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting, ClientExtras,
    LimitsConfig, apply_bearer_boundary,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt as _;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

fn caller() -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "operator".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: Some(TestGrant),
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
    }
}

fn app() -> Router {
    let router = Router::new().route(
        "/",
        post(|extras: Option<Extension<ClientExtras>>| async move {
            let extras = extras.map(|Extension(extras)| extras).unwrap_or_default();
            json!({ "client_call_id": extras.client_call_id }).to_string()
        }),
    );
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    apply_bearer_boundary(
        router,
        BearerBoundary::new(authenticator, BearerResponseProfile::compact("test")),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 8192,
                ..Default::default()
            }),
        },
    )
}

const BATCH: &str = r#"[
    {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_config",
     "_meta":{"claudecode/toolUseId":"toolu_FIRST"}}},
    {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_config",
     "_meta":{"claudecode/toolUseId":"toolu_SECOND"}}}
]"#;

#[test]
fn a_batch_keeps_the_id_in_the_audit_event_and_withholds_it_from_the_extension() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let mut handler_body = Value::Null;
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(BATCH))
                .expect("request");
            let response = app().oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("body");
            handler_body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        });
    });

    assert!(
        captured.contains("client_call_id=toolu_FIRST"),
        "the transport event describes the first audited element and must keep \
         its id: {captured}"
    );
    assert!(
        !captured.contains("toolu_SECOND"),
        "only the audited element's id belongs on that event: {captured}"
    );
    assert!(
        handler_body["client_call_id"].is_null(),
        "the per-request extension cannot say which element a handler is on, so \
         it must withhold the id: {handler_body}"
    );
}
