//! A handler must be able to reach the client-asserted facts that do not fit on
//! `CallerCtx` (mecmcp#304).
//!
//! `client_version` and `client_call_id` are resolved by the bearer boundary and
//! were spent on the transport's own audit line alone, so a consuming server's
//! tool-level audit record showed them empty however much the client asserted.
//! They now travel in request extensions, which is additive: `CallerCtx` is
//! built field-by-field by every consumer, so growing it would break all of them.
//!
//! # Why its own binary
//!
//! These drive the same middleware as `bearer_boundary`, and running them in
//! that binary made `an_unknown_session_leaves_the_client_name_empty` capture no
//! audit output at all — deterministically, and with this file's production code
//! reverted, so the interference is between the *tests*, through process-global
//! state, not through the change under test. `auth.rs` already documents that
//! hazard on `intern_tool_into` ("a cap test that fills the global one leaks
//! into every other test in the module"), and the same file records an
//! equivalent `client_info` defect that "failed roughly one run in six". A
//! separate integration test is a separate process, which removes the coupling
//! by construction rather than by scheduling luck. Filed as mecmcp#305.

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

/// Echoes back whatever extras reached the handler, so the assertion is on what
/// a real consumer would see rather than on middleware internals.
fn app() -> Router {
    let router = Router::new().route(
        "/",
        post(|extras: Option<Extension<ClientExtras>>| async move {
            let extras = extras.map(|Extension(extras)| extras).unwrap_or_default();
            json!({
                "client_version": extras.client_version,
                "client_call_id": extras.client_call_id,
            })
            .to_string()
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
                max_request_body_bytes: 4096,
                ..Default::default()
            }),
        },
    )
}

fn post_body(body: &'static str) -> (StatusCode, Value) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::from(body))
            .expect("request");
        let response = app().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, parsed)
    })
}

const CALL_WITH_EXTRAS: &str = r#"{
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {
        "name": "get_config",
        "_meta": {
            "io.modelcontextprotocol/clientInfo": {"name": "claude-code", "version": "2.4.1"},
            "claudecode/toolUseId": "toolu_01ABCDEF"
        }
    }
}"#;

#[test]
fn a_handler_can_read_the_client_version_and_call_id() {
    let (status, body) = post_body(CALL_WITH_EXTRAS);

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["client_version"], "2.4.1", "{body}");
    assert_eq!(body["client_call_id"], "toolu_01ABCDEF", "{body}");
}

/// A client that asserts nothing must still reach the handler, with the fields
/// absent rather than invented.
#[test]
fn a_request_without_client_facts_carries_empty_extras() {
    const BARE: &str =
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_config"}}"#;
    let (status, body) = post_body(BARE);

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["client_version"].is_null(), "{body}");
    assert!(body["client_call_id"].is_null(), "{body}");
}

/// A batch is dispatched element by element, and the extension is per HTTP
/// request. Handing it the first element's call id would attribute every
/// element's record to that one call, so it is withheld — the client version,
/// which describes the client rather than the call, still stands.
#[test]
fn a_batch_withholds_the_call_id_but_keeps_the_client_version() {
    const BATCH: &str = r#"[
        {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_config",
         "_meta":{"io.modelcontextprotocol/clientInfo":{"name":"claude-code","version":"2.4.1"},
                  "claudecode/toolUseId":"toolu_FIRST"}}},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_config",
         "_meta":{"claudecode/toolUseId":"toolu_SECOND"}}}
    ]"#;
    let (status, body) = post_body(BATCH);

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["client_version"], "2.4.1", "{body}");
    assert!(
        body["client_call_id"].is_null(),
        "a batch must not attribute one element's call id to all of them: {body}"
    );
}
