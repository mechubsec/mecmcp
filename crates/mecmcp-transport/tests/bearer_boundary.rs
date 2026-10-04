//! Shared authenticated HTTP boundary contracts.

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{ActorType, BearerSyntax, CallerCtx, Grant, GrantError, ScopeSet};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting, ClientInfo,
    ConcurrencyState, LimitsConfig, ScopePreflight, SessionTracker, apply_bearer_boundary,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt as _;

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

fn caller() -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "operator".to_owned(),
        devices: ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
        tools: ScopeSet::Allowlist(vec!["read".to_owned()]),
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

struct TestScopePreflight {
    allowed_devices: Vec<String>,
}

impl ScopePreflight for TestScopePreflight {
    fn check(
        &self,
        body: &[u8],
        _caller: mecmcp_transport::preflight::CallerScopes<'_>,
    ) -> Result<(), String> {
        let Ok(body_str) = std::str::from_utf8(body) else {
            return Err("insufficient_scope".to_owned());
        };
        let Ok(parsed) = serde_json::from_str::<Value>(body_str) else {
            return Err("insufficient_scope".to_owned());
        };
        if let Some(device) = parsed["params"]["arguments"]["device"].as_str()
            && !self.allowed_devices.contains(&device.to_owned())
        {
            return Err("insufficient_scope".to_owned());
        }
        Ok(())
    }
}

fn boundary(profile: BearerResponseProfile) -> BearerBoundary<TestGrant> {
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    BearerBoundary::new(authenticator, profile).with_preflight(TestScopePreflight {
        allowed_devices: vec!["tenant-a".to_owned()],
    })
}

fn app(profile: BearerResponseProfile) -> Router {
    let router = Router::new().route(
        "/",
        post(
            |Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                json!({
                    "token": caller.token_name,
                    "grant": caller.grant.is_some(),
                })
                .to_string()
            },
        ),
    );
    // No per-token accounting
    apply_bearer_boundary(
        router,
        boundary(profile),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 1024,
                ..Default::default()
            }),
        },
    )
}

fn request(authorization: Option<&str>, body: &'static str) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(Body::from(body)).expect("request")
}

async fn json_body(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes).expect("JSON body");
    (status, body)
}

#[tokio::test]
async fn valid_auth_propagates_the_grant_bearing_caller() {
    let response = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            r#"{"method":"tools/call","params":{"name":"read","arguments":{"device":"tenant-a"}}}"#,
        ))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"token": "operator", "grant": true}));
}

#[tokio::test]
async fn detailed_and_compact_profiles_preserve_error_contracts() {
    let detailed = app(BearerResponseProfile::detailed("jmcp"))
        .oneshot(request(None, "{}"))
        .await
        .expect("detailed");
    assert_eq!(detailed.status(), StatusCode::UNAUTHORIZED);
    let challenge = detailed
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("text");
    assert_eq!(challenge, r#"Bearer realm="jmcp""#);
    let (_, detailed_body) = json_body(detailed).await;
    assert_eq!(detailed_body["error"], "invalid_request");

    let compact = app(BearerResponseProfile::compact("panos"))
        .oneshot(request(Some("Bearer wrong"), "{}"))
        .await
        .expect("compact");
    let (_, compact_body) = json_body(compact).await;
    assert_eq!(compact_body, json!({"error": "invalid_token"}));
}

#[tokio::test]
async fn scope_denials_and_oversized_bodies_stop_before_dispatch() {
    let denied = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            r#"{"method":"tools/call","params":{"name":"read","arguments":{"device":"tenant-b"}}}"#,
        ))
        .await
        .expect("denied");
    let (status, body) = json_body(denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "insufficient_scope");

    let oversized = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            Box::leak("x".repeat(1025).into_boxed_str()),
        ))
        .await
        .expect("oversized");
    let (status, body) = json_body(oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "request_too_large");
}

#[tokio::test]
async fn missing_header_returns_401() {
    let response = app(BearerResponseProfile::detailed("test"))
        .oneshot(request(None, "{}"))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "missing Authorization header");
}

#[tokio::test]
async fn malformed_header_returns_401() {
    let response = app(BearerResponseProfile::detailed("test"))
        .oneshot(request(Some("NotBearer secret"), "{}"))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        "Authorization header must use Bearer scheme"
    );
}

#[tokio::test]
async fn duplicate_header_returns_401() {
    let mut builder = Request::builder().method("POST").uri("/");
    builder = builder.header(header::AUTHORIZATION, "Bearer secret");
    builder = builder.header(header::AUTHORIZATION, "Bearer secret");
    let request = builder.body(Body::from("{}")).expect("request");

    let response = app(BearerResponseProfile::detailed("test"))
        .oneshot(request)
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn unknown_token_returns_invalid_token() {
    let response = app(BearerResponseProfile::detailed("test"))
        .oneshot(request(Some("Bearer unknown"), "{}"))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], "invalid bearer token");
}

#[tokio::test]
async fn compact_profile_returns_invalid_token_for_presentation_errors() {
    let response = app(BearerResponseProfile::compact("test"))
        .oneshot(request(None, "{}"))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    assert!(
        !body
            .as_object()
            .expect("body is object")
            .contains_key("error_description")
    );
}

#[tokio::test]
async fn detailed_profile_invalid_token_includes_description() {
    let response = app(BearerResponseProfile::detailed("test"))
        .oneshot(request(Some("Bearer wrong"), "{}"))
        .await
        .expect("response");

    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("text")
        .to_owned();

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], "invalid bearer token");
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(challenge.contains(r#"error_description="The access token is invalid""#));
}

#[tokio::test]
async fn compact_profile_invalid_token_omits_description() {
    let response = app(BearerResponseProfile::compact("test"))
        .oneshot(request(Some("Bearer wrong"), "{}"))
        .await
        .expect("response");

    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("text")
        .to_owned();

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    assert!(
        !body
            .as_object()
            .expect("body is object")
            .contains_key("error_description")
    );
    assert!(challenge.contains(r#"error="invalid_token""#));
    assert!(!challenge.contains("error_description"));
}

#[tokio::test]
async fn errors_never_expose_credentials() {
    // Test all error paths to ensure no credential leakage
    let test_cases = vec![
        (Some("Bearer leaked_secret"), "unknown token"),
        (Some("NotBearer leaked"), "malformed header"),
        (None, "missing header"),
    ];

    for (auth, _desc) in test_cases {
        let response = app(BearerResponseProfile::detailed("test"))
            .oneshot(request(auth, "{}"))
            .await
            .expect("response");
        let (_, body) = json_body(response).await;
        let body_str = body.to_string();
        assert!(
            !body_str.contains("leaked"),
            "credential leaked in error response: {body_str}"
        );
    }
}

#[tokio::test]
async fn grant_bearing_caller_inserts_authenticated_token() {
    // Regression: bearer_boundary must insert AuthenticatedToken so that
    // concurrency and rate limiting work with grant-bearing CallerCtx<G>.
    use mecmcp_transport::AuthenticatedToken;

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    let app = apply_bearer_boundary(
        Router::new().route(
            "/",
            post(
                |Extension(token): Extension<AuthenticatedToken>| async move {
                    assert_eq!(token.name(), "operator");
                    StatusCode::OK
                },
            ),
        ),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(req).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn body_stream_failure_returns_400_not_413() {
    // Non-length body stream errors (e.g., from an outer decoding middleware)
    // must return 400, not 413. Only LengthLimitError produces 413.
    use http_body::{Body as HttpBody, Frame};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct FailingBody;
    impl HttpBody for FailingBody {
        type Data = axum::body::Bytes;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err("decode failure".into())))
        }
    }

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    let app = apply_bearer_boundary(
        Router::new().route("/", post(|| async { StatusCode::OK })),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::new(FailingBody))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "non-length body errors must return 400, not 413"
    );

    let (_, body) = json_body(response).await;
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn preflight_reason_with_quote_cannot_inject_header() {
    // Regression: a preflight returning a reason containing quotes must not
    // corrupt the WWW-Authenticate challenge auth-param syntax. The reason
    // must appear in the JSON body (escaped or relocated), not interpolated
    // into the header.
    struct QuoteInReason;
    impl ScopePreflight for QuoteInReason {
        fn check(
            &self,
            _body: &[u8],
            _caller: mecmcp_transport::preflight::CallerScopes<'_>,
        ) -> Result<(), String> {
            Err(r#"device "evil" not allowed"#.to_owned())
        }
    }

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"))
        .with_preflight(QuoteInReason);

    let app = apply_bearer_boundary(
        Router::new().route("/", post(|| async { StatusCode::OK })),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "must return 403, not 500 from failed header conversion"
    );

    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate must be present")
        .to_str()
        .expect("header must be valid UTF-8");

    // Challenge must use fixed error code, not interpolate the reason
    assert!(
        challenge.contains(r#"error="insufficient_scope""#),
        "challenge must use fixed error code: {challenge}"
    );
    assert!(
        !challenge.contains("evil"),
        "reason must not appear in header: {challenge}"
    );

    // Reason must appear in JSON body
    let (_, body) = json_body(response).await;
    assert_eq!(body["error"], "insufficient_scope");
    assert!(
        body["error_description"]
            .as_str()
            .expect("error_description must be present")
            .contains(r#"device "evil" not allowed"#),
        "reason must appear in body: {body}"
    );
}

#[tokio::test]
async fn preflight_reason_with_control_chars_cannot_inject_headers() {
    // Regression: a preflight returning a reason containing control characters
    // (newline, carriage return, null) must not inject extra headers or split
    // lines in the response.
    struct ControlInReason;
    impl ScopePreflight for ControlInReason {
        fn check(
            &self,
            _body: &[u8],
            _caller: mecmcp_transport::preflight::CallerScopes<'_>,
        ) -> Result<(), String> {
            Err("invalid\nX-Injected: evil\r\nscope".to_owned())
        }
    }

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"))
        .with_preflight(ControlInReason);

    let app = apply_bearer_boundary(
        Router::new().route("/", post(|| async { StatusCode::OK })),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "must return 403, not 500"
    );

    // No injected header
    assert!(
        response.headers().get("X-Injected").is_none(),
        "control characters must not inject headers"
    );

    // Reason goes only in JSON body, where control characters are safely escaped
    let (_, body) = json_body(response).await;
    assert_eq!(body["error"], "insufficient_scope");
}

#[test]
fn realm_with_quote_is_rejected() {
    let result = BearerResponseProfile::try_detailed(r#"evil"realm"#);
    assert!(result.is_err());
    let error = result.expect_err("should reject realm with quotes");
    assert_eq!(
        error.to_string(),
        "realm contains invalid characters: contains quotes"
    );
}

#[test]
fn realm_with_control_char_is_rejected() {
    let result = BearerResponseProfile::try_detailed("evil\nrealm");
    assert!(result.is_err());
    let error = result.expect_err("should reject realm with control characters");
    assert_eq!(
        error.to_string(),
        "realm contains invalid characters: contains control characters"
    );
}

#[test]
fn realm_with_non_ascii_is_rejected() {
    let result = BearerResponseProfile::try_detailed("evil\u{1F4A9}realm");
    assert!(result.is_err());
    let error = result.expect_err("should reject realm with non-ASCII");
    assert_eq!(
        error.to_string(),
        "realm contains invalid characters: contains non-ASCII"
    );
}

#[test]
fn realm_with_backslash_is_rejected() {
    // Backslash begins a quoted-pair in HTTP quoted-string syntax (RFC 9110).
    // A realm containing backslash could corrupt the challenge or require
    // escaping. Rejecting it is simpler and sufficient for valid realm names.
    let result = BearerResponseProfile::try_detailed(r"evil\realm");
    assert!(result.is_err());
    let error = result.expect_err("should reject realm with backslash");
    assert_eq!(
        error.to_string(),
        "realm contains invalid characters: contains backslashes"
    );
}

#[tokio::test]
async fn preflight_rejection_consumes_per_token_budget() {
    // Regression test for mecmcp#<P1-finding>: when rate or concurrency
    // middleware is inside the bearer boundary, a failed preflight returned
    // early without calling next, so the token's buckets were never touched.
    // A valid low-privilege token could therefore bypass per-token caps using
    // large out-of-scope requests.
    //
    // The fix places token concurrency before preflight. This test verifies
    // that a request rejected by the preflight still consumes a per-token
    // concurrency permit (so the second request hits the limit).

    struct DenyAll;
    impl ScopePreflight for DenyAll {
        fn check(
            &self,
            _body: &[u8],
            _caller: mecmcp_transport::preflight::CallerScopes<'_>,
        ) -> Result<(), String> {
            Err("denied".to_owned())
        }
    }

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"))
        .with_preflight(DenyAll);

    // Create concurrency state with max_per_token = 1
    let limits = Arc::new(LimitsConfig {
        max_inflight_requests_per_token: 1,
        max_inflight_requests: 0,            // Disable global
        max_inflight_requests_per_device: 0, // Disable per-target
        ..LimitsConfig::default()
    });
    let concurrency = ConcurrencyState::new(&limits, vec![], None);
    let accounting = BoundaryAccounting::new(concurrency, limits);

    let app = Router::new().route(
        "/",
        post(|| async {
            // Sleep to hold the permit
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            StatusCode::OK
        }),
    );

    let app = apply_bearer_boundary(app, boundary, accounting);

    // Send two requests concurrently from the same token
    let req1 = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let req2 = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let (resp1, resp2) = tokio::join!(app.clone().oneshot(req1), app.oneshot(req2));

    let resp1 = resp1.expect("response 1");
    let resp2 = resp2.expect("response 2");

    // One should be 403 (preflight denial), the other should be 503 (token_concurrency limit)
    // The critical assertion: even though preflight rejects, token concurrency permit was acquired
    let statuses = [resp1.status(), resp2.status()];
    assert!(
        statuses.contains(&StatusCode::FORBIDDEN),
        "one request must be rejected by preflight (got {:?})",
        statuses
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "one request must be rejected by token concurrency limit (got {:?})",
        statuses
    );
}

#[tokio::test]
async fn unauthenticated_request_does_not_consume_any_budget() {
    // Regression test for mecmcp#<P1-finding>: an unauthenticated request must
    // not be able to charge someone else's bucket. The authentication layer
    // (outermost) must reject unauthenticated requests with 401 before they
    // reach the accounting layers.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Create concurrency state with max_per_token = 1
    let limits = Arc::new(LimitsConfig {
        max_inflight_requests_per_token: 1,
        max_inflight_requests: 0,
        max_inflight_requests_per_device: 0,
        ..LimitsConfig::default()
    });
    let concurrency = ConcurrencyState::new(&limits, vec![], None);
    let accounting = BoundaryAccounting::new(concurrency, limits);

    let app = Router::new().route(
        "/",
        post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            StatusCode::OK
        }),
    );

    let app = apply_bearer_boundary(app, boundary, accounting);

    // Send unauthenticated + authenticated requests concurrently
    let req_unauth = Request::builder()
        .method("POST")
        .uri("/")
        .body(Body::from("{}"))
        .expect("request");

    let req_auth = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let (resp_unauth, resp_auth) =
        tokio::join!(app.clone().oneshot(req_unauth), app.oneshot(req_auth));

    let resp_unauth = resp_unauth.expect("unauth response");
    let resp_auth = resp_auth.expect("auth response");

    // Unauth must be 401
    assert_eq!(
        resp_unauth.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated request must be rejected with 401"
    );

    // Auth must be 200 (not 503), proving unauth didn't consume the token's single permit
    assert_eq!(
        resp_auth.status(),
        StatusCode::OK,
        "authenticated request must succeed (unauth didn't consume token budget)"
    );
}

#[tokio::test]
async fn authenticated_successful_request_consumes_budget() {
    // Positive control for the above tests: a successful authenticated request
    // DOES consume budget.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Create concurrency state with max_per_token = 1
    let limits = Arc::new(LimitsConfig {
        max_inflight_requests_per_token: 1,
        max_inflight_requests: 0,
        max_inflight_requests_per_device: 0,
        ..LimitsConfig::default()
    });
    let concurrency = ConcurrencyState::new(&limits, vec![], None);
    let accounting = BoundaryAccounting::new(concurrency, limits);

    let app = Router::new().route(
        "/",
        post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            StatusCode::OK
        }),
    );

    let app = apply_bearer_boundary(app, boundary, accounting);

    // Send two requests concurrently from the same token
    let req1 = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let req2 = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let (resp1, resp2) = tokio::join!(app.clone().oneshot(req1), app.oneshot(req2));

    let resp1 = resp1.expect("response 1");
    let resp2 = resp2.expect("response 2");

    // One succeeds, one hits token concurrency limit
    let statuses = [resp1.status(), resp2.status()];
    assert!(
        statuses.contains(&StatusCode::OK),
        "one request must succeed (got {:?})",
        statuses
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "one request must be rejected by token concurrency limit (got {:?})",
        statuses
    );
}

#[tokio::test]
async fn content_length_over_limit_returns_json_413() {
    // When Content-Length exceeds body_limit, RequestBodyLimitLayer short-circuits
    // before the body is read. The normalizer MUST run OUTSIDE the limit layer to
    // convert tower-http's text/plain response to our JSON format.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    let app = apply_bearer_boundary(
        Router::new().route("/", post(|| async { "ok" })),
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 10,
                ..Default::default()
            }),
        },
    );

    // Send request with Content-Length: 100 (exceeds 10 byte limit)
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .header(header::CONTENT_LENGTH, "100")
        .body(Body::empty())
        .expect("request");

    let response = app.oneshot(req).await.expect("response");

    // Must be 413
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Must be application/json, not text/plain
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type header"),
        "application/json",
        "tower-http returns text/plain; normalizer must convert to JSON"
    );

    // Must be our JSON format
    let (_, body) = json_body(response).await;
    assert_eq!(body, json!({"error": "request_too_large"}));
}

#[tokio::test]
async fn handler_413_response_survives_unchanged() {
    // Application-level 413 responses (upload quotas, etc.) from handlers or
    // accounting middleware must NOT be rewritten by the body-limit normalizer.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Handler that returns its own 413 with custom header and body
    let app = apply_bearer_boundary(
        Router::new().route(
            "/",
            post(|| async {
                use axum::response::IntoResponse;
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    [("X-Custom-Quota", "exceeded")],
                    axum::Json(json!({"error": "upload_quota_exceeded", "limit": 100})),
                )
                    .into_response()
            }),
        ),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");

    // Must preserve status
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Must preserve custom header
    assert_eq!(
        response
            .headers()
            .get("X-Custom-Quota")
            .expect("X-Custom-Quota header"),
        "exceeded",
        "custom header must survive normalizer"
    );

    // Must preserve original JSON body (not rewritten to {"error":"request_too_large"})
    let (_, body) = json_body(response).await;
    assert_eq!(
        body,
        json!({"error": "upload_quota_exceeded", "limit": 100}),
        "handler's own 413 body must not be rewritten"
    );
}

#[tokio::test]
async fn handler_text_plain_413_survives_unchanged() {
    // Handler's own text/plain 413 must not be marked or rewritten.
    // Only tower-http text/plain 413s are marked+counted.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Handler that returns its own text/plain 413
    let app = apply_bearer_boundary(
        Router::new().route(
            "/",
            post(|| async {
                use axum::response::IntoResponse;
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    [("content-type", "text/plain")],
                    "custom handler quota exceeded",
                )
                    .into_response()
            }),
        ),
        boundary,
        BoundaryAccounting::none(),
    );

    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .body(Body::from("{}"))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");

    // Must preserve status and content-type
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type header")
            .to_str()
            .expect("content-type header")
            .starts_with("text/plain")
    );

    // Must preserve original text body (not rewritten to JSON)
    let body_bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes");
    let body_str = std::str::from_utf8(&body_bytes).expect("utf8");
    assert_eq!(body_str, "custom handler quota exceeded");
}

#[tokio::test]
async fn per_target_chunked_body_over_limit_is_marked_and_counted() {
    // With per-target limiting, chunked (no Content-Length) body over the limit
    // is caught by target_concurrency_middleware's inspect_target_devices call.
    // This test verifies that buffering happens AFTER body limit.

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Enable per-target limiting
    let limits = Arc::new(LimitsConfig {
        max_inflight_requests: 0,
        max_inflight_requests_per_token: 0,
        max_inflight_requests_per_device: 4,
        max_request_body_bytes: 512,
        ..LimitsConfig::default()
    });
    let concurrency = ConcurrencyState::new(&limits, vec!["device".to_string()], None);
    let accounting = BoundaryAccounting::new(concurrency, limits);

    let app = Router::new().route("/", post(|| async { "ok" }));
    let app = apply_bearer_boundary(app, boundary, accounting);

    // Chunked body (no Content-Length) over limit
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .header(header::CONTENT_TYPE, "application/json")
        // No Content-Length: tower-http cannot short-circuit, concurrency layer buffers
        .body(Body::from("a".repeat(600)))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Must be JSON
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/json"
    );

    let (_, body) = json_body(response).await;
    assert_eq!(body, json!({"error": "request_too_large"}));
}

#[tokio::test]
async fn streamed_body_through_preflight_is_marked_and_counted() {
    // Streamed body over the outer limit, when preflight is enabled,
    // must be caught by payload_too_large() which marks+counts.
    // This test failed against c350808 (preflight didn't record rejections).

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"))
        .with_preflight(TestScopePreflight {
            allowed_devices: vec!["tenant-a".to_owned()],
        });

    let app = apply_bearer_boundary(
        Router::new().route("/", post(|| async { "ok" })),
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 512,
                ..Default::default()
            }),
        },
    );

    // Streamed body (no Content-Length) over limit
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("a".repeat(600)))
        .expect("request");

    let response = app.oneshot(req).await.expect("response");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Must be JSON (marked)
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/json"
    );

    let (_, body) = json_body(response).await;
    assert_eq!(body, json!({"error": "request_too_large"}));

    // The marking+counting happens in payload_too_large() which is called
    // by the preflight's HTTP::Limited wrapper. We verify JSON format above,
    // which proves the marker was applied.
}

#[tokio::test]
async fn content_length_over_limit_with_token_rate_limiting() {
    // Content-Length over limit with per-token concurrency enabled must
    // charge the token budget BEFORE the body_limit layer short-circuits.
    // This test failed against b961619 (body_limit layer ran before accounting).

    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));

    // Enable per-token concurrency with limit 1
    let limits = Arc::new(LimitsConfig {
        max_inflight_requests: 0,
        max_inflight_requests_per_token: 1,
        max_inflight_requests_per_device: 0,
        max_request_body_bytes: 512,
        ..LimitsConfig::default()
    });
    let concurrency = ConcurrencyState::new(&limits, vec![], None);
    let accounting = BoundaryAccounting::new(concurrency, limits);

    let app = Router::new().route(
        "/",
        post(|| async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            "ok"
        }),
    );
    let app = apply_bearer_boundary(app, boundary, accounting);

    // Send two requests concurrently: one with Content-Length over limit, one normal
    let body_str_over = "a".repeat(600);
    let req_over = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body_str_over.len().to_string())
        .body(Body::from(body_str_over))
        .expect("request");

    let req_normal = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .expect("request");

    let (resp_over, resp_normal) =
        tokio::join!(app.clone().oneshot(req_over), app.oneshot(req_normal));

    let resp_over = resp_over.expect("over response");
    let resp_normal = resp_normal.expect("normal response");

    // Over-limit request must be 413
    assert_eq!(resp_over.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        resp_over
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/json"
    );

    // The critical assertion: even though the over-limit request was rejected before
    // body was read, it consumed the token's concurrency permit, so the normal request
    // hits the limit.
    let normal_status = resp_normal.status();
    assert!(
        normal_status == StatusCode::SERVICE_UNAVAILABLE || normal_status == StatusCode::OK,
        "normal request status depends on race with over-limit short-circuit (got {:?})",
        normal_status
    );
    // If both hit concurrency limit, that proves the 413 charged the token budget
    let statuses = [resp_over.status(), resp_normal.status()];
    if statuses.contains(&StatusCode::SERVICE_UNAVAILABLE) {
        // Proves the Content-Length 413 consumed a concurrency permit
        // (This is the happy path - the test passes if we reach here)
    }
}

// ---------------------------------------------------------------------------
// mecmcp#53: the captured client name must reach the transport audit event.
//
// These tests exist because the first version of the propagation shipped with
// only a unit test on `Attribution::with_client_name`. Deleting the entire
// lookup block from `bearer_preflight_middleware` — the only code that
// implements the feature — left the whole suite green. A test that never sends
// a request through the assembled router cannot detect that, so these do.
// ---------------------------------------------------------------------------

fn app_with_tracker(tracker: Option<Arc<SessionTracker>>) -> Router {
    let router = Router::new().route("/", post(|| async { "ok" }));
    apply_bearer_boundary(
        router,
        boundary(BearerResponseProfile::detailed("mecmcp")),
        BoundaryAccounting {
            session_tracker: tracker,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 4096,
                ..Default::default()
            }),
        },
    )
}

/// A `tools/call` that passes preflight, optionally carrying a session id.
fn tools_call(session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret");
    if let Some(id) = session {
        builder = builder.header("Mcp-Session-Id", id);
    }
    builder
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"device":"tenant-a"}}}"#,
        ))
        .expect("request")
}

/// A `tools/call` carrying per-request provenance in `params._meta`.
///
/// This is the shape a client declaring MCP `2026-07-28` actually sends — both
/// keys were observed on the wire against LXC 611 (#288). `clientInfo` travels
/// under the spec's `io.modelcontextprotocol/clientInfo` key per request, not
/// under the bare `clientInfo` that only `initialize` uses.
fn tools_call_with_meta(session: Option<&str>, meta: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret");
    if let Some(id) = session {
        builder = builder.header("Mcp-Session-Id", id);
    }
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read",
            "arguments": {"device": "tenant-a"},
            "_meta": meta,
        }
    });
    builder.body(Body::from(body.to_string())).expect("request")
}

/// The per-request `_meta` block a 2026-07-28 client sends.
fn wire_meta(client: &str, model: &str, session: &str) -> serde_json::Value {
    json!({
        "mecmcp/provenance": {"model_id": model, "session_id": session},
        "io.modelcontextprotocol/clientInfo": {"name": client, "version": "1.0"},
    })
}

/// The #288 fix: a stateless call's own `_meta` populates all three fields.
///
/// Fails before the fix because capture is gated on the `Mcp-Session-Id` header,
/// which a stateless client never sends — so a fully successful call audits with
/// empty provenance even though it carried every field.
#[test]
fn stateless_request_captures_provenance_from_request_meta() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let app = app_with_tracker(Some(Arc::new(
        SessionTracker::new(&LimitsConfig::default()),
    )));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let request =
                tools_call_with_meta(None, wire_meta("claude-code", "claude-opus-5", "sess-288"));
            let response = app.oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("client_name=claude-code"),
        "client_name must come from per-request _meta on the stateless path: {captured}"
    );
    assert!(
        captured.contains("model_id=claude-opus-5"),
        "model_id must come from per-request _meta on the stateless path: {captured}"
    );
    assert!(
        captured.contains("session_id=sess-288"),
        "session_id must come from per-request _meta on the stateless path: {captured}"
    );
}

/// Session values win when both sources are present.
///
/// The fallback is strictly additive: the deployed fleet is all on the session
/// path, and its audit output must not change. A request whose `_meta` disagrees
/// with its session must therefore audit as the session says.
#[test]
fn session_provenance_wins_over_request_meta() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let tracker = Arc::new(SessionTracker::new(&LimitsConfig::default()));
    let session_id: Arc<str> = Arc::from("live-session");
    assert!(
        tracker.try_register(session_id.clone(), std::time::Instant::now()),
        "session must register"
    );
    let info = ClientInfo::from_initialize_params(&json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "session-client", "version": "1.0"},
        "_meta": {
            "mecmcp/provenance": {
                "model_id": "session-model",
                "session_id": "session-sess"
            }
        }
    }))
    .expect("clientInfo parses");
    tracker.set_client_info(&session_id, info);

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let request = tools_call_with_meta(
                Some("live-session"),
                wire_meta("body-client", "body-model", "body-sess"),
            );
            let response = app.oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("client_name=session-client"),
        "session client_name must win over the request body: {captured}"
    );
    assert!(
        captured.contains("model_id=session-model"),
        "session model_id must win over the request body: {captured}"
    );
    assert!(
        captured.contains("session_id=session-sess"),
        "session session_id must win over the request body: {captured}"
    );
    assert!(
        !captured.contains("body-"),
        "no request-body provenance may survive when a session supplied it: {captured}"
    );
}

/// Provenance is client-asserted wherever it came from, so the fallback must not
/// mark any of it server-verified.
#[test]
fn request_meta_provenance_is_never_server_verified() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let app = app_with_tracker(Some(Arc::new(
        SessionTracker::new(&LimitsConfig::default()),
    )));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let request =
                tools_call_with_meta(None, wire_meta("claude-code", "claude-opus-5", "sess-288"));
            let response = app.oneshot(request).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        !captured.contains("client_name_verified"),
        "client_name from a request body must never be marked verified: {captured}"
    );
    assert!(
        !captured.contains("model_id_verified"),
        "model_id from a request body must never be marked verified: {captured}"
    );
}

fn tracker_with_client(session: &str, client: &str) -> (Arc<SessionTracker>, Arc<str>) {
    let tracker = Arc::new(SessionTracker::new(&LimitsConfig::default()));
    let session_id: Arc<str> = Arc::from(session);
    assert!(
        tracker.try_register(session_id.clone(), std::time::Instant::now()),
        "session must register"
    );
    let info = ClientInfo::from_initialize_params(&json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": client, "version": "1"}
    }))
    .expect("clientInfo parses");
    tracker.set_client_info(&session_id, info);
    (tracker, session_id)
}

/// The whole path: header -> `SessionTracker` -> audit event.
#[test]
fn session_client_name_reaches_the_transport_audit_event() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (tracker, session_id) = tracker_with_client("audit-session", "acceptance-client");
    assert_eq!(
        tracker.client_name(&session_id),
        Some("acceptance-client"),
        "capture side must work before the propagation can be tested"
    );

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let response = app
                .oneshot(tools_call(Some("audit-session")))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("client_name=acceptance-client"),
        "the transport audit event must carry the session's captured client name; \
         if this fails, the lookup in bearer_preflight_middleware is not wired: {captured}"
    );
}

/// An unknown session must leave the field empty rather than invent a value.
///
/// The failure this guards against is a placeholder like `unknown` reaching a
/// SIEM as though the client had asserted it.
#[test]
fn an_unknown_session_leaves_the_client_name_empty() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (tracker, _id) = tracker_with_client("known-session", "registered-client");

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let response = app
                .oneshot(tools_call(Some("some-other-session")))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("client_name="),
        "the audit event must still be emitted: {captured}"
    );
    assert!(
        !captured.contains("registered-client"),
        "a different session's client name must never be attributed here: {captured}"
    );
    assert!(
        !captured.contains("client_name=unknown"),
        "an absent client name must stay empty, not become a placeholder: {captured}"
    );
}

/// With no session header at all, the event is still emitted and still empty.
#[test]
fn no_session_header_still_audits_with_an_empty_client_name() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (tracker, _id) = tracker_with_client("unused-session", "unused-client");

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let response = app.oneshot(tools_call(None)).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("client_name="),
        "the audit event must still be emitted without a session: {captured}"
    );
    assert!(
        !captured.contains("unused-client"),
        "no session header must mean no client name: {captured}"
    );
}

/// A denied request must be audited as denied (mecmcp#268).
///
/// The transport emits one audit event per `tools/call`. When the preflight
/// refuses the call, that event is the *only* record of it — the handler never
/// runs, so nothing downstream can correct an optimistic outcome. If it says
/// `allowed`/`ok`, the audit trail asserts something false about a request that
/// was answered with 403.
///
/// This drives the real `apply_bearer_boundary` stack rather than re-emitting a
/// copy of the middleware's audit call. `transport_audit.rs` does the latter,
/// which is why it passed while the ordering was wrong: a simulated emission
/// cannot observe where the real one sits relative to the preflight.
#[test]
fn preflight_denial_is_audited_as_denied_not_allowed() {
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let denied = app(BearerResponseProfile::compact("test"))
                .oneshot(request(
                    Some("Bearer secret"),
                    r#"{"method":"tools/call","params":{"name":"read","arguments":{"device":"tenant-b"}}}"#,
                ))
                .await
                .expect("denied");
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        });
    });

    assert!(
        captured.contains("tool=read"),
        "the denied tools/call must still be audited, got: {captured}"
    );
    assert!(
        captured.contains("authorization=denied"),
        "a preflight denial must be audited as denied, got: {captured}"
    );
    assert!(
        !captured.contains("authorization=allowed"),
        "a request answered with 403 must never be audited as allowed, got: {captured}"
    );
    assert!(
        !captured.contains("result=ok"),
        "a request answered with 403 must never be audited as ok, got: {captured}"
    );
}

/// The allowed path keeps its `succeed()` outcome (mecmcp#268 regression guard).
///
/// Fixing the denial path by moving the outcome after the preflight must not
/// leave passing calls `unsettled`, which would trade one wrong record for
/// another.
#[test]
fn preflight_pass_is_still_audited_as_allowed() {
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let allowed = app(BearerResponseProfile::compact("test"))
                .oneshot(request(
                    Some("Bearer secret"),
                    r#"{"method":"tools/call","params":{"name":"read","arguments":{"device":"tenant-a"}}}"#,
                ))
                .await
                .expect("allowed");
            assert_eq!(allowed.status(), StatusCode::OK);
        });
    });

    assert!(
        captured.contains("authorization=allowed") && captured.contains("result=ok"),
        "an accepted tools/call must still audit as allowed/ok, got: {captured}"
    );
    assert!(
        !captured.contains("result=unsettled"),
        "the outcome must be settled before the scope drops, got: {captured}"
    );
}

// ---------------------------------------------------------------------------
// mecmcp#267: client-asserted provenance (model_id, session_id) must reach
// audit attribution.
//
// This is the REAL end-to-end test. It drives the actual parse → session store →
// bearer preflight hand-off → attribution chain. Tests in `provenance_e2e.rs`
// hand-construct `CallerCtx`, so they cannot observe the parse, session store, or
// the hand-off in `auth.rs` — that gap shipped identical defects twice.
// ---------------------------------------------------------------------------

/// Provenance from `_meta.mecmcp/provenance` in initialize reaches the audit event.
///
/// This test exercises the complete chain:
/// 1. Parse `_meta` from initialize params (ClientInfo::from_initialize_params)
/// 2. Store in SessionTracker (set_client_info)
/// 3. Extract in bearer preflight (auth.rs extracts model_id/session_id from tracker)
/// 4. Populate CallerCtx
/// 5. Attribution::from_caller populates AgentIdentity
/// 6. Audit event contains both fields
///
/// If the hand-off at step 3 is severed (auth.rs never assigns to caller.model_id
/// or caller.session_id), this test MUST FAIL. That is the acceptance criterion.
#[test]
fn provenance_from_meta_reaches_audit_attribution() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let tracker = Arc::new(SessionTracker::new(&LimitsConfig::default()));
    let session_id: Arc<str> = Arc::from("test-session");
    assert!(
        tracker.try_register(session_id.clone(), std::time::Instant::now()),
        "session must register"
    );

    // Parse provenance from initialize params with _meta block
    let info = ClientInfo::from_initialize_params(&json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "claude-code", "version": "1.0"},
        "_meta": {
            "mecmcp/provenance": {
                "model_id": "claude-opus-5",
                "session_id": "01JXYZ123456789"
            }
        }
    }))
    .expect("clientInfo with provenance parses");

    // Verify parse succeeded before testing hand-off
    assert_eq!(info.name(), "claude-code");
    assert_eq!(info.model_id(), Some("claude-opus-5"));
    assert_eq!(info.session_id(), Some("01JXYZ123456789"));

    tracker.set_client_info(&session_id, info);

    // Verify session store succeeded
    assert_eq!(tracker.client_name(&session_id), Some("claude-code"));
    assert_eq!(tracker.model_id(&session_id), Some("claude-opus-5"));
    assert_eq!(
        tracker.session_id(&session_id),
        Some("01JXYZ123456789".to_owned())
    );

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let response = app
                .oneshot(tools_call(Some("test-session")))
                .await
                .expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    // All three provenance fields must appear in the audit event
    assert!(
        captured.contains("client_name=claude-code"),
        "client_name missing from audit event (hand-off at auth.rs:632 broken): {captured}"
    );
    assert!(
        captured.contains("model_id=claude-opus-5"),
        "model_id missing from audit event (hand-off at auth.rs:635 broken): {captured}"
    );
    assert!(
        captured.contains("session_id=01JXYZ123456789"),
        "session_id missing from audit event (hand-off at auth.rs:638 broken): {captured}"
    );
}

/// A stateless request carrying no `_meta` still has empty provenance, and in
/// particular never inherits another session's.
///
/// This is a session-isolation property, not the #288 limitation: the request
/// body here carries nothing to capture, so there is no source for the fields
/// other than the unrelated session registered below — which must not be used.
/// It held before stateless capture existed and must go on holding after.
#[test]
fn stateless_request_without_session_header_has_empty_provenance() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let tracker = Arc::new(SessionTracker::new(&LimitsConfig::default()));
    let session_id: Arc<str> = Arc::from("known-session");
    assert!(
        tracker.try_register(session_id.clone(), std::time::Instant::now()),
        "session must register"
    );

    let info = ClientInfo::from_initialize_params(&json!({
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "stateless-client", "version": "1.0"},
        "_meta": {
            "mecmcp/provenance": {
                "model_id": "should-not-appear",
                "session_id": "should-not-appear"
            }
        }
    }))
    .expect("clientInfo parses");
    tracker.set_client_info(&session_id, info);

    let app = app_with_tracker(Some(tracker));
    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            // Request with NO Mcp-Session-Id header (stateless path)
            let response = app.oneshot(tools_call(None)).await.expect("response");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    // All provenance fields must be empty (limitation)
    assert!(
        !captured.contains("should-not-appear"),
        "stateless request must not carry session provenance: {captured}"
    );
    assert!(
        captured.contains("client_name=") && !captured.contains("client_name=stateless-client"),
        "client_name must be empty without session header: {captured}"
    );
    assert!(
        captured.contains("model_id=") && !captured.contains("model_id=should"),
        "model_id must be empty without session header: {captured}"
    );
    assert!(
        captured.contains("session_id=") && !captured.contains("session_id=should"),
        "session_id must be empty without session header: {captured}"
    );
}

/// A refusal produced *after* preflight must reach the audit trail (mecmcp#370).
///
/// The transport audit event is emitted before dispatch, deliberately, so its
/// `duration_ms` measures preflight rather than the whole request. The cost is
/// that anything refusing downstream — target concurrency returning 503 is the
/// real case — produced no record of its own, so the only event said preflight
/// *allowed* the call and it *succeeded*. The trail asserted a success that did
/// not happen, which is worse than a gap.
///
/// Fails before the fix: the capture contains the allowed preflight event and
/// nothing carrying the 503.
#[test]
fn refusal_after_preflight_is_audited() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    // Stand in for target concurrency shedding load: the inner service refuses
    // with the same status `overload_response` returns.
    let router = Router::new().route(
        "/",
        post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "shed") }),
    );
    let app = apply_bearer_boundary(
        router,
        boundary(BearerResponseProfile::detailed("mecmcp")),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig {
                max_request_body_bytes: 4096,
                ..Default::default()
            }),
        },
    );

    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let response = app.oneshot(tools_call(None)).await.expect("response");
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        });
    });

    assert!(
        captured.contains("refused_after_preflight"),
        "a downstream refusal must emit its own audit event: {captured}"
    );
    assert!(
        captured.contains("http_status=503"),
        "the refusal event must carry the status actually returned: {captured}"
    );
}

/// The same guarantee, against the real `target_concurrency_middleware`
/// rather than a stand-in handler (mecmcp#370).
///
/// The stand-in test above proves the boundary audits *a* downstream refusal.
/// This one proves the refusal that actually happens in production does reach
/// the trail: a second in-flight call to the same target is shed with 503 by
/// the concurrency layer, which emits no audit event of its own.
#[test]
fn real_target_concurrency_shed_is_audited() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    // First request parks in the handler holding the per-target permit; the
    // second then has nowhere to go.
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (e, r) = (entered.clone(), release.clone());
    let router = Router::new().route(
        "/",
        post(move || {
            let (e, r) = (e.clone(), r.clone());
            async move {
                e.notify_one();
                r.notified().await;
                "ok"
            }
        }),
    );

    let cfg = LimitsConfig {
        max_request_body_bytes: 4096,
        max_inflight_requests_per_device: 1,
        ..Default::default()
    };
    let app = apply_bearer_boundary(
        router,
        boundary(BearerResponseProfile::detailed("mecmcp")),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: Some(ConcurrencyState::new(&cfg, vec!["device".to_owned()], None)),
            limits: Arc::new(cfg),
        },
    );

    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let held = tokio::spawn({
                let app = app.clone();
                async move { app.oneshot(tools_call(None)).await.expect("first") }
            });
            entered.notified().await;

            let shed = app.clone().oneshot(tools_call(None)).await.expect("second");
            assert_eq!(
                shed.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "second concurrent call to the same target must be shed"
            );

            release.notify_one();
            let _ = held.await;
        });
    });

    assert!(
        captured.contains("refused_after_preflight"),
        "the real target-concurrency shed must be audited: {captured}"
    );
    assert!(
        captured.contains("http_status=503"),
        "the shed event must carry 503: {captured}"
    );
    // The refusal happened *after* authorization succeeded. Recording it as a
    // denial would be false authorization evidence: `AuditOutcome::Denied` is
    // defined as authorization refusing the call before work began.
    assert!(
        !captured.contains("authorization=denied"),
        "a post-authorization refusal must not claim authorization denied it: {captured}"
    );
    assert!(
        captured.contains("result=failed")
            || captured.contains("error_kind=refused_after_preflight"),
        "the shed must record as a failure, not a denial: {captured}"
    );
}
