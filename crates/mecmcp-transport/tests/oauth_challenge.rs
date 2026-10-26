//! The `resource_metadata` parameter on 401 challenges (RFC 9728 s5.1, mecmcp#498).

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{BearerSyntax, NoGrant};
use mecmcp_transport::{
    BearerAuthError, BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    BoundaryAccounting, LimitsConfig, apply_bearer_boundary,
};
use std::sync::Arc;
use tower::ServiceExt as _;

const METADATA_URL: &str = "https://mcp.example/.well-known/oauth-protected-resource/mcp";

fn app(profile: BearerResponseProfile) -> Router {
    let authenticator = BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
    apply_bearer_boundary(
        Router::new().route("/", post(|| async { "ok" })),
        BearerBoundary::new(authenticator, profile),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    )
}

async fn challenge(app: Router, authorization: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let response = app
        .oneshot(builder.body(Body::from("{}")).expect("request"))
        .await
        .expect("response");
    let value = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("401 carries a challenge")
        .to_str()
        .expect("ASCII challenge")
        .to_owned();
    (response.status(), value)
}

#[tokio::test]
async fn every_401_names_the_metadata_document_when_configured() {
    let profile = BearerResponseProfile::detailed("test")
        .with_resource_metadata(METADATA_URL)
        .expect("valid URL");
    let (status, missing) = challenge(app(profile.clone()), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing,
        format!(r#"Bearer realm="test", resource_metadata="{METADATA_URL}""#)
    );

    let (_, bad_token) = challenge(app(profile), Some("Bearer nope")).await;
    assert_eq!(
        bad_token,
        format!(
            r#"Bearer realm="test", resource_metadata="{METADATA_URL}", error="invalid_token", error_description="The access token is invalid""#
        )
    );
}

#[tokio::test]
async fn the_compact_profile_carries_it_too() {
    let profile = BearerResponseProfile::compact("test")
        .with_resource_metadata(METADATA_URL)
        .expect("valid URL");
    let (_, value) = challenge(app(profile), None).await;
    assert_eq!(
        value,
        format!(
            r#"Bearer realm="test", resource_metadata="{METADATA_URL}", error="invalid_token""#
        )
    );
}

#[tokio::test]
async fn url_legal_delimiters_stay_inside_the_quoted_string() {
    // `,;'*` are legal in a URL path but would split an unquoted auth-param.
    let url = "https://h.example/.well-known/oauth-protected-resource/a,b;c'd*e";
    let profile = BearerResponseProfile::detailed("test")
        .with_resource_metadata(url)
        .expect("URL-legal delimiters are accepted");
    let (_, value) = challenge(app(profile), None).await;
    assert_eq!(
        value,
        format!(r#"Bearer realm="test", resource_metadata="{url}""#)
    );
}

#[tokio::test]
async fn without_it_the_challenge_is_byte_identical_to_before() {
    let (_, missing) = challenge(app(BearerResponseProfile::detailed("test")), None).await;
    assert_eq!(missing, r#"Bearer realm="test""#);
    let (_, bad) = challenge(
        app(BearerResponseProfile::detailed("test")),
        Some("Bearer x"),
    )
    .await;
    assert_eq!(
        bad,
        r#"Bearer realm="test", error="invalid_token", error_description="The access token is invalid""#
    );
    let (_, compact) = challenge(
        app(BearerResponseProfile::compact("test")),
        Some("Bearer x"),
    )
    .await;
    assert_eq!(compact, r#"Bearer realm="test", error="invalid_token""#);
}

#[test]
fn well_formed_urls_are_accepted() {
    for url in [
        "https://h.example/.well-known/oauth-protected-resource/mcp",
        "http://127.0.0.1:8080/.well-known/oauth-protected-resource",
        "http://[::1]:8080/.well-known/oauth-protected-resource",
        "https://a-b.example:8443/p%2Fq?x=1",
        &format!("https://{}.example/", "a".repeat(63)),
    ] {
        assert!(
            BearerResponseProfile::detailed("test")
                .with_resource_metadata(url)
                .is_ok(),
            "{url:?} must be accepted"
        );
    }
}

#[test]
fn a_url_that_could_break_out_of_the_quoted_string_is_refused() {
    for hostile in [
        "https://h/\", error=\"insufficient_scope",
        "https://h/a\\b",
        "https://h/a\r\nSet-Cookie: x=1",
        "https://h/\u{e9}",
        "javascript:alert(1)",
        "/relative",
        // Not absolute URLs with a usable host, though they start with the scheme.
        "https://",
        "https://bad host/metadata",
        "https://[broken]/",
        "https://h:bogus/metadata",
        concat!("https://user", ":pw@h.example/metadata"),
        "https://a{b}.example/metadata",
        // http::Uri accepts these; a strict URL parser does not.
        "https://h.example/{x}",
        "https://h.example/#frag with spaces",
        "https://h.example/meta#frag",
        "https://h.example/a%zz",
        "https://h.example/a|b",
        // Host labels: empty, over 63 bytes, leading or trailing hyphen.
        "https://a..example/metadata",
        "https://h.example./metadata",
        "https://-a.example/metadata",
        "https://a-.example/metadata",
        &format!("https://{}.example/metadata", "a".repeat(64)),
    ] {
        let result = BearerResponseProfile::detailed("test").with_resource_metadata(hostile);
        assert!(
            matches!(result, Err(BearerAuthError::InvalidResourceMetadata(_))),
            "{hostile:?} must be refused"
        );
    }
}
