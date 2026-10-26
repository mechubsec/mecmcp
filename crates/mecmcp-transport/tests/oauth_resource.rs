//! Signed-JWT integration tests for OAuth resource-server mode (mecmcp#498).
//!
//! Ephemeral RSA keys, in-memory `KeySource`; no socket to an IdP is ever opened.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_auth::{ActorType, Grant, GrantError, ScopeSet};
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource};
use mecmcp_transport::{OAuthRejection, OAuthResource, OAuthResourceConfig, OAuthScopeMap};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const ISSUER: &str = "https://idp.lab.example/realms/lab";
const JUNOS: &str = "https://junos.lab.example/mcp";
const PANOS: &str = "https://panos.lab.example/mcp";
const KID: &str = "oauth-test-key";

const SCOPE_MAP: &str = r#"{
    "version": 1,
    "actor_type": "agent",
    "scopes": {
        "junos:read": {"tools": ["get_junos_config"], "devices": ["srx-1"]},
        "panos:read": {"tools": ["get_panos_config"], "devices": ["fw-1"]}
    },
    "roles": {"netops": {"tools": ["get_device_list"], "devices": ["srx-1"]}}
}"#;

#[derive(Debug, Clone)]
struct TestGrant;
impl Grant for TestGrant {
    type Action = ();
    fn allows_action(&self, _action: ()) -> bool {
        true
    }
    fn allows_subject(&self, _subject: &str) -> bool {
        true
    }
    fn validate(&self) -> Result<(), GrantError> {
        Ok(())
    }
}

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestKey {
    let key_pair = KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation");
    let pkcs8_der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = key_pair.as_der().expect("PKCS8");
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.as_ref().to_vec()));
    let encoding_key = EncodingKey::from_rsa_pem(pem_text.as_bytes()).expect("PEM");
    let mut jwk =
        Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256).expect("JWK");
    jwk.common.key_id = Some(kid.to_owned());
    TestKey { encoding_key, jwk }
}

fn sign(key: &TestKey, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("sign")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits")
}

/// A well-formed RFC 9068 access token for `audience` carrying `scope`.
fn claims(audience: Value, scope: &str) -> Value {
    json!({
        "iss": ISSUER, "sub": "alice", "aud": audience,
        "exp": now() + 3600, "iat": now() - 10, "jti": "jti-1",
        "client_id": "odysseus", "scope": scope,
    })
}

/// Serves the key set from memory and counts JWKS fetches.
struct FixtureSource {
    jwks: JwkSet,
    fetches: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl KeySource for FixtureSource {
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        Ok(DiscoveryDocument {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/jwks"),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: Vec::new(),
            id_token_signing_alg_values_supported: Vec::new(),
        })
    }
    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(self.jwks.clone())
    }
}

fn config_for(resource: &str) -> OAuthResourceConfig {
    OAuthResourceConfig::new(
        ISSUER,
        resource,
        OAuthScopeMap::from_json(SCOPE_MAP.as_bytes()).expect("map"),
    )
    .expect("config")
}

fn resource_from(
    config: OAuthResourceConfig,
    key: &TestKey,
) -> (OAuthResource<TestGrant>, Arc<AtomicUsize>) {
    let fetches = Arc::new(AtomicUsize::new(0));
    let source = FixtureSource {
        jwks: JwkSet {
            keys: vec![key.jwk.clone()],
        },
        fetches: Arc::clone(&fetches),
    };
    (OAuthResource::new(config, Arc::new(source)), fetches)
}

fn resource_for(resource: &str, key: &TestKey) -> (OAuthResource<TestGrant>, Arc<AtomicUsize>) {
    resource_from(config_for(resource), key)
}

#[tokio::test]
async fn a_mapped_token_becomes_the_caller_the_map_describes() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "openid junos:read"));

    let caller = junos.authenticate(&token).await.expect("authenticates");

    assert_eq!(caller.token_name, "oauth:alice");
    assert_eq!(
        caller.tools,
        ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
    );
    assert_eq!(
        caller.devices,
        ScopeSet::Allowlist(vec!["srx-1".to_owned()])
    );
    assert_eq!(caller.actor_type, ActorType::Agent);
    assert!(caller.grant.is_none());
    let identity = caller.oauth.expect("OAuth identity recorded");
    assert_eq!(identity.issuer, ISSUER);
    assert_eq!(identity.subject, "alice");
    assert_eq!(identity.client_id.as_deref(), Some("odysseus"));
}

/// Requirement 4: a token minted for junos is refused by a panos-configured verifier.
/// The control assertion (junos accepts it) is what keeps this from passing vacuously.
#[tokio::test]
async fn a_junos_audience_token_is_refused_by_a_panos_resource() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let (panos, _) = resource_for(PANOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "junos:read panos:read"));

    assert!(
        junos.authenticate(&token).await.is_ok(),
        "control: the intended server accepts it"
    );
    assert_eq!(
        panos.authenticate(&token).await.expect_err("refused"),
        OAuthRejection::Invalid("wrong_audience"),
        "the same token, scopes included, must not work on another server"
    );
}

#[tokio::test]
async fn audience_must_equal_the_resource_not_resemble_it() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    for near_miss in [
        "https://panos.lab.example/mcp/extra",
        "https://panos.lab.example/mc",
        "https://panos.lab.example/mcp/",
        "xhttps://panos.lab.example/mcp",
        "https://panos.lab.example/mcp ",
        "https://PANOS.lab.example/mcp",
        "https://panos.lab.example",
        "panos.lab.example/mcp",
    ] {
        let token = sign(&key, &claims(json!(near_miss), "panos:read"));
        assert_eq!(
            panos.authenticate(&token).await.expect_err("refused"),
            OAuthRejection::Invalid("wrong_audience"),
            "aud {near_miss:?}"
        );
    }
    let token = sign(&key, &claims(json!([JUNOS, "account"]), "panos:read"));
    assert_eq!(
        panos.authenticate(&token).await.expect_err("refused"),
        OAuthRejection::Invalid("wrong_audience"),
        "an audience list that does not contain this server"
    );
}

/// Pinned behaviour, not an endorsement: a token whose `aud` lists this server among others
/// was issued for this server too. See docs/OAUTH.md ("Multi-audience tokens").
#[tokio::test]
async fn an_audience_list_containing_this_resource_is_accepted() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let token = sign(&key, &claims(json!(["account", PANOS]), "panos:read"));
    assert!(panos.authenticate(&token).await.is_ok());
}

#[tokio::test]
async fn an_unmapped_or_absent_scope_is_a_verified_token_that_grants_nothing() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    for scope in ["junos:admin", "openid profile", ""] {
        let token = sign(&key, &claims(json!(JUNOS), scope));
        match junos.authenticate(&token).await.expect_err("refused") {
            OAuthRejection::Unmapped(identity) => assert_eq!(identity.subject, "alice"),
            other => panic!("scope {scope:?}: expected Unmapped, got {other:?}"),
        }
    }
    let mut no_scope_claim = claims(json!(JUNOS), "");
    no_scope_claim
        .as_object_mut()
        .expect("object")
        .remove("scope");
    let token = sign(&key, &no_scope_claim);
    assert!(matches!(
        junos.authenticate(&token).await.expect_err("refused"),
        OAuthRejection::Unmapped(_)
    ));
}

#[tokio::test]
async fn smuggled_scopes_do_not_escalate() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);

    // Tab / newline are not delimiters (RFC 6749 uses SP only): one invalid token, dropped.
    for injected in [
        "junos:read\tpanos:read",
        "junos:read\npanos:read",
        "junos:read,panos:read",
    ] {
        let token = sign(&key, &claims(json!(JUNOS), injected));
        assert!(
            matches!(
                junos.authenticate(&token).await.expect_err("refused"),
                OAuthRejection::Unmapped(_)
            ),
            "{injected:?}"
        );
    }

    // A space *inside* an `scp` array element is not split into two scopes.
    let mut array_claims = claims(json!(JUNOS), "");
    let object = array_claims.as_object_mut().expect("object");
    object.remove("scope");
    object.insert("scp".to_owned(), json!(["junos:read panos:read"]));
    let token = sign(&key, &array_claims);
    assert!(matches!(
        junos.authenticate(&token).await.expect_err("refused"),
        OAuthRejection::Unmapped(_)
    ));

    // The legitimate scope still works beside a hostile one, and gains nothing from it
    // (`panos:read` alone is mapped on this server, so it must not leak in via the tab).
    let token = sign(
        &key,
        &claims(json!(JUNOS), "junos:read junos:admin\tpanos:read"),
    );
    let caller = junos.authenticate(&token).await.expect("junos:read maps");
    assert_eq!(
        caller.tools,
        ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
    );
}

#[tokio::test]
async fn a_configured_role_claim_maps_too() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let mut with_role = claims(json!(JUNOS), "junos:read");
    with_role["roles"] = json!(["netops"]);
    let caller = junos
        .authenticate(&sign(&key, &with_role))
        .await
        .expect("maps");
    assert_eq!(
        caller.tools,
        ScopeSet::Allowlist(vec![
            "get_junos_config".to_owned(),
            "get_device_list".to_owned()
        ])
    );

    // `with_role_claim` moves the claim: `roles` is then ignored, `groups` is read.
    let (grouped, _) = resource_from(config_for(JUNOS).with_role_claim("groups"), &key);
    let mut role_only = claims(json!(JUNOS), "");
    role_only["roles"] = json!(["netops"]);
    assert!(matches!(
        grouped
            .authenticate(&sign(&key, &role_only))
            .await
            .expect_err("roles ignored"),
        OAuthRejection::Unmapped(_)
    ));
    role_only["groups"] = json!(["netops"]);
    let caller = grouped
        .authenticate(&sign(&key, &role_only))
        .await
        .expect("groups maps");
    assert_eq!(
        caller.tools,
        ScopeSet::Allowlist(vec!["get_device_list".to_owned()])
    );
}

#[tokio::test]
async fn at_jwt_typ_is_required_only_when_configured() {
    let key = generate_test_key(KID);
    let (lenient, _) = resource_for(JUNOS, &key);
    let (strict, _) = resource_from(config_for(JUNOS).with_require_at_jwt_typ(true), &key);
    let plain = sign(&key, &claims(json!(JUNOS), "junos:read"));
    assert!(
        lenient.authenticate(&plain).await.is_ok(),
        "default: typ JWT accepted"
    );
    assert_eq!(
        strict
            .authenticate(&plain)
            .await
            .expect_err("typ JWT refused"),
        OAuthRejection::Invalid("wrong_token_type")
    );
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("at+jwt".to_owned());
    let typed = jsonwebtoken::encode(
        &header,
        &claims(json!(JUNOS), "junos:read"),
        &key.encoding_key,
    )
    .expect("sign");
    assert!(strict.authenticate(&typed).await.is_ok());
}

#[tokio::test]
async fn a_symmetric_algorithm_confusion_attempt_is_refused() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(KID.to_owned());
    let forged = jsonwebtoken::encode(
        &header,
        &claims(json!(JUNOS), "junos:read"),
        &EncodingKey::from_secret(b"anything-an-attacker-can-compute"),
    )
    .expect("sign");
    assert_eq!(
        junos.authenticate(&forged).await.expect_err("refused"),
        OAuthRejection::Invalid("unsupported_algorithm")
    );
}

#[tokio::test]
async fn other_verification_failures_keep_distinct_reason_codes() {
    let key = generate_test_key(KID);
    let other_key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);

    let mut expired = claims(json!(JUNOS), "junos:read");
    expired["exp"] = json!(now() - 3600);
    let mut wrong_issuer = claims(json!(JUNOS), "junos:read");
    wrong_issuer["iss"] = json!("https://evil.example");
    let mut no_client = claims(json!(JUNOS), "junos:read");
    no_client
        .as_object_mut()
        .expect("object")
        .remove("client_id");

    let cases = [
        (sign(&key, &expired), "expired"),
        (sign(&key, &wrong_issuer), "wrong_issuer"),
        (
            sign(&other_key, &claims(json!(JUNOS), "junos:read")),
            "invalid_signature",
        ),
        (sign(&key, &no_client), "missing_claim"),
    ];
    for (token, reason) in cases {
        assert_eq!(
            junos.authenticate(&token).await.expect_err("refused"),
            OAuthRejection::Invalid(reason)
        );
    }
}

#[tokio::test]
async fn a_subject_that_could_forge_an_identity_key_is_refused() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    for subject in [
        "",
        "alice bob",
        "alice\nbob",
        &"a".repeat(129),
        "alice\u{202e}nimda",
        "\u{e5}lice",
        "alice\u{200b}",
    ] {
        let mut hostile = claims(json!(JUNOS), "junos:read");
        hostile["sub"] = json!(subject);
        assert_eq!(
            junos
                .authenticate(&sign(&key, &hostile))
                .await
                .expect_err("refused"),
            OAuthRejection::Invalid("invalid_subject"),
            "{subject:?}"
        );
    }
}

/// `client_id` reaches audit text and `CallerCtx` verbatim; bidi/format characters are
/// refused here rather than trusted to every later renderer's escaping.
#[tokio::test]
async fn a_client_id_with_invisible_characters_is_refused() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    for client in [
        "odysseus\u{202e}",
        "\u{200b}odysseus",
        "ody sseus",
        "\u{f6}dysseus",
    ] {
        let mut hostile = claims(json!(JUNOS), "junos:read");
        hostile["client_id"] = json!(client);
        assert_eq!(
            junos
                .authenticate(&sign(&key, &hostile))
                .await
                .expect_err("refused"),
            OAuthRejection::Invalid("invalid_client_id"),
            "{client:?}"
        );
    }
}

#[tokio::test]
async fn the_caller_context_does_not_contain_the_token() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "junos:read"));
    let caller = junos.authenticate(&token).await.expect("authenticates");
    let rendered = format!("{caller:?}");
    for segment in token.split('.') {
        assert!(
            !rendered.contains(segment),
            "a token segment leaked into CallerCtx: {segment}"
        );
    }
}

/// An IdP that cannot be reached.
struct DownSource;

#[async_trait::async_trait]
impl KeySource for DownSource {
    async fn fetch_discovery(&self, _issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        Err(FetchError::HttpStatus {
            what: "discovery",
            status: 503,
        })
    }
    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        Err(FetchError::HttpStatus {
            what: "jwks",
            status: 503,
        })
    }
}

/// An unreachable IdP is "cannot judge", never "invalid token" (503, not 401).
#[tokio::test]
async fn unreachable_keys_are_unavailable_not_invalid() {
    let key = generate_test_key(KID);
    let junos: OAuthResource<TestGrant> =
        OAuthResource::new(config_for(JUNOS), Arc::new(DownSource));
    let token = sign(&key, &claims(json!(JUNOS), "junos:read"));
    assert_eq!(
        junos.authenticate(&token).await.expect_err("refused"),
        OAuthRejection::Unavailable("keys_unavailable")
    );
}

// ---- Over HTTP: the real bearer boundary and router assembly (Task 9) ----

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{BearerSyntax, CallerCtx};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting,
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, TransportIdentity, apply_bearer_boundary,
    build_streamable_http_router, test_harness::serve_on_loopback,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

const STATIC_TOKEN: &str = "static-secret";

fn static_caller() -> CallerCtx<TestGrant> {
    let mut caller = CallerCtx::oauth(
        mecmcp_auth::OAuthIdentity {
            issuer: "static".into(),
            subject: "ci".into(),
            client_id: None,
        },
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        ActorType::Human,
    );
    // A static-token caller as the token store would build it: its own name, no OAuth identity.
    caller.token_name = "ci-static".to_owned();
    caller.oauth = None;
    caller
}

/// `/` behind the real bearer boundary: one static token, optionally the OAuth resource.
fn app_with_static(resource: Option<OAuthResource<TestGrant>>, static_token: &str) -> Router {
    let static_token = static_token.to_owned();
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
        (candidate == static_token).then(static_caller)
    });
    let mut boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
    if let Some(resource) = resource {
        boundary = boundary.with_oauth_resource(Arc::new(resource));
    }
    let router = Router::new().route(
        "/",
        post(
            |Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                json!({
                    "token_name": caller.token_name,
                    "tools": caller.tools.summary(),
                    "client_id": caller.oauth.as_ref().and_then(|identity| identity.client_id.clone()),
                })
                .to_string()
            },
        ),
    );
    apply_bearer_boundary(
        router,
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    )
}

fn app(resource: Option<OAuthResource<TestGrant>>) -> Router {
    app_with_static(resource, STATIC_TOKEN)
}

async fn call(
    app: &Router,
    bearer: Option<&str>,
) -> (StatusCode, Option<String>, Option<String>, Value) {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from("{}")).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let header_text = |name| {
        response
            .headers()
            .get(name)
            .map(|value: &header::HeaderValue| value.to_str().expect("ASCII").to_owned())
    };
    let challenge = header_text(header::WWW_AUTHENTICATE);
    let retry_after = header_text(header::RETRY_AFTER);
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("body");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, challenge, retry_after, body)
}

const METADATA_PARAM: &str =
    r#"resource_metadata="https://panos.lab.example/.well-known/oauth-protected-resource/mcp""#;

/// "Static first" is only observable if trying OAuth first would *do* something: the static
/// token here is JWT-shaped (signed by a key the IdP does not publish), so an OAuth attempt
/// would fetch the JWKS. The second request is the control that proves the counter counts.
#[tokio::test]
async fn static_tokens_are_tried_first_and_never_touch_the_idp() {
    let key = generate_test_key(KID);
    let stranger = generate_test_key(KID);
    let jwt_shaped_static = sign(&stranger, &claims(json!(PANOS), "panos:read"));
    let (panos, fetches) = resource_for(PANOS, &key);
    let app = app_with_static(Some(panos), &jwt_shaped_static);

    let (status, _, _, body) = call(&app, Some(jwt_shaped_static.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_name"], "ci-static");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        0,
        "a static hit must not touch the IdP"
    );

    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, _, _, _) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::OK, "control: OAuth itself works");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "control: an OAuth request fetches"
    );
}

#[tokio::test]
async fn a_valid_access_token_authenticates_over_http() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(panos));
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, _, _, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_name"], "oauth:alice");
    assert_eq!(body["tools"], "get_panos_config");
    assert_eq!(body["client_id"], "odysseus");
}

/// Every verification failure, including a token for another server and the identity
/// checks layered on top of signature verification, is a 401 that points at discovery.
#[tokio::test]
async fn invalid_tokens_get_401_with_discovery() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(panos));
    let mut bad_client = claims(json!(PANOS), "panos:read");
    bad_client["client_id"] = json!("ody sseus");
    for token in [
        sign(&key, &claims(json!(JUNOS), "junos:read panos:read")),
        sign(&key, &bad_client),
    ] {
        let (status, challenge, _, body) = call(&app, Some(token.as_str())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_token");
        let challenge = challenge.expect("challenge");
        assert!(challenge.contains(METADATA_PARAM), "{challenge}");
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "{challenge}"
        );
    }
}

/// A verified token that maps to nothing is 403 `insufficient_scope`, not 401, and the
/// refusal is a denied audit event attributed to the OAuth identity.
#[test]
fn a_valid_token_with_no_mapped_authority_is_403_and_audited() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(panos));
    let token = sign(&key, &claims(json!(PANOS), "openid"));

    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        runtime.block_on(async {
            let (status, challenge, _, body) = call(&app, Some(token.as_str())).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(body["error"], "insufficient_scope");
            assert_eq!(
                challenge.as_deref(),
                Some(r#"Bearer realm="test", error="insufficient_scope""#)
            );
        });
    });

    for expected in [
        "authorization=denied",
        "reason=unmapped_scope",
        "oauth_subject=alice",
        "oauth_client_id=odysseus",
    ] {
        assert!(captured.contains(expected), "{expected}: {captured}");
    }
}

/// An unreachable IdP is 503 for JWTs and never authorizes; static tokens are unaffected.
#[tokio::test]
async fn an_unreachable_idp_is_503_and_static_tokens_still_work() {
    let key = generate_test_key(KID);
    let down: OAuthResource<TestGrant> =
        OAuthResource::new(config_for(PANOS), Arc::new(DownSource));
    let app = app(Some(down));

    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, _, retry_after, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(retry_after.as_deref(), Some("5"));

    let (status, _, _, body) = call(&app, Some(STATIC_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_name"], "ci-static");
}

#[tokio::test]
async fn unauthenticated_requests_are_pointed_at_the_metadata_document() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(panos));
    for bearer in [None, Some("not-a-jwt")] {
        let (status, challenge, _, _) = call(&app, bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(challenge.expect("challenge").contains(METADATA_PARAM));
    }
}

#[tokio::test]
async fn without_the_resource_installed_a_jwt_is_just_an_unknown_token() {
    let key = generate_test_key(KID);
    let app = app(None);
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, challenge, _, _) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!challenge.expect("challenge").contains("resource_metadata"));
}

#[derive(Clone)]
struct StubServer;
impl ServerHandler for StubServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("stub", "0.1"))
    }
}

/// Raw HTTP/1.1 so the Host header is exactly what the test says it is.
fn raw_get(address: std::net::SocketAddr, path: &str, host: &str) -> (u16, String) {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(address).expect("connect");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line");
    (status, response)
}

/// Metadata is outside the bearer boundary but inside Host/Origin validation; `/mcp` is not
/// opened up by it.
#[tokio::test]
async fn the_assembled_router_serves_metadata_unauthenticated_and_guards_mcp() {
    let key = generate_test_key(KID);
    let (resource, _) = resource_for("http://127.0.0.1/mcp", &key);
    let authenticator = BearerAuthenticator::<TestGrant>::new(BearerSyntax::Strict, |_| None);
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("stub"))
        .with_oauth_resource(Arc::new(resource));
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::authenticated(
        TransportIdentity::new("stubmcp", "stub", "stub", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        boundary,
    );
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(StubServer), config)
        .expect("router builds");
    let served = serve_on_loopback(plan).await;
    let address = served.address;

    let (metadata, foreign_host, mcp) = tokio::task::spawn_blocking(move || {
        let path = "/.well-known/oauth-protected-resource/mcp";
        let metadata = raw_get(address, path, &address.to_string());
        let foreign_host = raw_get(address, path, "evil.example");
        let mcp = raw_get(address, "/mcp", &address.to_string());
        (metadata, foreign_host, mcp)
    })
    .await
    .expect("blocking task");

    assert_eq!(
        metadata.0, 200,
        "metadata must be reachable without credentials: {}",
        metadata.1
    );
    let document: Value =
        serde_json::from_str(metadata.1.split("\r\n\r\n").nth(1).expect("body")).expect("JSON");
    assert_eq!(document["resource"], "http://127.0.0.1/mcp");
    assert_eq!(document["authorization_servers"], json!([ISSUER]));
    assert_ne!(
        foreign_host.0, 200,
        "metadata must stay behind Host validation: {}",
        foreign_host.1
    );
    assert_eq!(mcp.0, 401, "{}", mcp.1);
    assert!(
        mcp.1.contains(
            r#"resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp""#
        ),
        "{}",
        mcp.1
    );

    shutdown.cancel();
    served.serving.await.expect("join").expect("clean shutdown");
}
