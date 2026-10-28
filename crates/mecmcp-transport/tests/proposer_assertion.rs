//! Full-stack contract for the `Mecmcp-Proposer-Assertion` step-up header (mecmcp#400).
//!
//! Signs real ephemeral JWTs and drives them through `apply_bearer_boundary`, as
//! `approver_assertion.rs` does for the approver header.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_auth::{
    ActorType, ApproverPolicy, BearerSyntax, CallerCtx, Grant, GrantError, OidcSubject, ScopeSet,
};
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource, OidcConfig, TokenVerifier};
use mecmcp_transport::{
    APPROVER_ASSERTION_HEADER, ApproverAssertionVerifier, BearerAuthenticator, BearerBoundary,
    BearerResponseProfile, BoundaryAccounting, LimitsConfig, PROPOSER_ASSERTION_HEADER,
    apply_bearer_boundary,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt as _;

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "mecmcp-server";
const KID: &str = "approver-test-key";
const APPROVER_ROLE: &str = "approver";

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

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestKey {
    let key_pair = KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation");
    let pkcs8_der: aws_lc_rs::encoding::Pkcs8V1Der<'static> =
        key_pair.as_der().expect("PKCS8 encoding");
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.as_ref().to_vec()));
    let encoding_key =
        EncodingKey::from_rsa_pem(pem_text.as_bytes()).expect("valid PEM for jsonwebtoken");
    let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256)
        .expect("JWK derivation");
    jwk.common.key_id = Some(kid.to_owned());
    TestKey { encoding_key, jwk }
}

fn sign_token(key: &TestKey, claims: &Value, kid: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("token signing")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs(),
    )
    .expect("timestamp fits in i64")
}

fn valid_claims(subject: &str, jti: &str) -> Value {
    json!({
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now() + 3600,
        "iat": now() - 10,
        "groups": [APPROVER_ROLE],
        "jti": jti,
    })
}

struct FixtureSource {
    jwks: JwkSet,
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
        Ok(self.jwks.clone())
    }
}

fn caller(oidc_subject: Option<OidcSubject>) -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "approver-token".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: Some(TestGrant),
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
        oidc_subject,
        verified_approver: None,
        verified_proposer: None,
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
        oauth: None,
        token_created_at: None,
        token_expires_at: None,
    }
}

fn bound_subject() -> OidcSubject {
    OidcSubject {
        issuer: ISSUER.to_owned(),
        subject: "alice".to_owned(),
    }
}

fn policy() -> ApproverPolicy {
    ApproverPolicy {
        approver_role: APPROVER_ROLE.to_owned(),
        max_age: Duration::from_secs(300),
        require_auth_time: false,
    }
}

/// An app whose bearer token has the given actor type and, optionally, a subject binding — an
/// `agent` token must never bind an approver assertion, regardless of
/// whether it happens to carry an `oidc_subject` (MEC-994 Percy review F5:
/// "no transport-level test for an assertion on an agent token").
fn app_with_actor(
    key: &TestKey,
    oidc_subject: Option<OidcSubject>,
    with_verifier: bool,
    actor_type: ActorType,
) -> Router {
    app_with_store(key, oidc_subject, with_verifier, actor_type, None)
}

/// Like [`app_with_actor`], optionally with a durable replay store at `store`.
fn app_with_store(
    key: &TestKey,
    oidc_subject: Option<OidcSubject>,
    with_verifier: bool,
    actor_type: ActorType,
    store: Option<&std::path::Path>,
) -> Router {
    let mut bound_caller = caller(oidc_subject);
    bound_caller.actor_type = actor_type;
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
        (candidate == "secret").then(|| bound_caller.clone())
    });
    let mut boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));
    if with_verifier {
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        let token_verifier = TokenVerifier::new(config, Arc::new(FixtureSource { jwks }));
        let mut verifier =
            ApproverAssertionVerifier::new(Arc::new(token_verifier), ISSUER, policy());
        if let Some(path) = store {
            verifier = verifier.with_replay_store(path).expect("replay store");
        }
        boundary = boundary.with_approver_assertion(Arc::new(verifier));
    }

    let router =
        Router::new().route(
            "/",
            post(
                |headers: axum::http::HeaderMap,
                 Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                    json!({
                        "saw_assertion_header": headers.contains_key(APPROVER_ASSERTION_HEADER)
                            || headers.contains_key(PROPOSER_ASSERTION_HEADER),
                        "verified_approver_subject": caller.verified_approver.map(|a| a.subject),
                        "verified_proposer_subject": caller.verified_proposer.map(|p| p.subject),
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

fn request(header_name: Option<&str>, assertion: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret");
    if let Some(name) = header_name {
        builder = builder.header(name, assertion);
    }
    builder.body(Body::from("{}")).expect("request")
}

/// An assertion for `subject` carrying no roles at all: a proposer needs none.
fn proposer_claims(subject: &str, jti: &str) -> Value {
    let mut claims = valid_claims(subject, jti);
    claims["groups"] = json!([]);
    claims
}

async fn send(app: &Router, name: Option<&str>, token: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(request(name, token))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn an_agent_token_with_no_approver_role_binds_a_proposer_assertion() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &proposer_claims("alice", "p-ok"), KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Agent);
    let (status, body) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified_proposer_subject"], "alice");
    // A proposal assertion is never approval evidence.
    assert_eq!(body["verified_approver_subject"], Value::Null);
}

#[tokio::test]
async fn no_header_leaves_the_caller_unverified_with_or_without_a_verifier() {
    let key = generate_test_key(KID);
    for with_verifier in [false, true] {
        let app = app_with_actor(&key, Some(bound_subject()), with_verifier, ActorType::Agent);
        let (status, body) = send(&app, None, "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verified_proposer_subject"], Value::Null);
    }
}

#[tokio::test]
async fn the_header_with_no_verifier_configured_is_400_not_silently_ignored() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &proposer_claims("alice", "p-unconfigured"), KID);
    let app = app_with_actor(&key, Some(bound_subject()), false, ActorType::Agent);
    let (status, body) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "approver_assertion_not_configured");
}

#[tokio::test]
async fn a_subject_other_than_the_tokens_binding_is_refused() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &proposer_claims("mallory", "p-wrong-sub"), KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Agent);
    let (status, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_token_with_no_subject_binding_cannot_present_one() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &proposer_claims("alice", "p-unbound"), KID);
    let app = app_with_actor(&key, None, true, ActorType::Agent);
    let (status, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_forged_or_wrong_audience_assertion_is_refused() {
    let key = generate_test_key(KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Agent);
    let mut stale = proposer_claims("alice", "p-stale");
    stale["iat"] = json!(now() - 3600);
    let mut wrong_aud = proposer_claims("alice", "p-aud");
    wrong_aud["aud"] = json!("someone-else");
    let forged = sign_token(
        &generate_test_key(KID),
        &proposer_claims("alice", "p-forged"),
        KID,
    );
    for token in [
        sign_token(&key, &stale, KID),
        sign_token(&key, &wrong_aud, KID),
        forged,
    ] {
        let (status, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn a_proposer_assertion_is_single_use() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &proposer_claims("alice", "p-once"), KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Agent);
    let (first, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    let (second, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!((first, second), (StatusCode::OK, StatusCode::UNAUTHORIZED));
}

/// The replay set is shared across roles: an assertion spent as a proposal cannot then be
/// presented as an approval, and the reverse.
#[tokio::test]
async fn one_assertion_cannot_be_spent_as_both_a_proposal_and_an_approval() {
    let key = generate_test_key(KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Human);

    let token = sign_token(&key, &valid_claims("alice", "x-1"), KID);
    let (as_proposal, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    let (as_approval, _) = send(&app, Some(APPROVER_ASSERTION_HEADER), &token).await;
    assert_eq!(
        (as_proposal, as_approval),
        (StatusCode::OK, StatusCode::UNAUTHORIZED)
    );

    let token = sign_token(&key, &valid_claims("alice", "x-2"), KID);
    let (as_approval, _) = send(&app, Some(APPROVER_ASSERTION_HEADER), &token).await;
    let (as_proposal, _) = send(&app, Some(PROPOSER_ASSERTION_HEADER), &token).await;
    assert_eq!(
        (as_approval, as_proposal),
        (StatusCode::OK, StatusCode::UNAUTHORIZED)
    );
}

/// The approver header keeps its stricter rules: an agent token still cannot approve.
#[tokio::test]
async fn the_approver_header_still_refuses_an_agent_token() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "x-agent"), KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Agent);
    let (status, _) = send(&app, Some(APPROVER_ASSERTION_HEADER), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A verified assertion is a bearer-equivalent JWT: it must not reach the handler, where rmcp
/// would copy it into tool extensions. Both headers are removed once spent.
#[tokio::test]
async fn a_verified_assertion_header_is_stripped_before_the_handler() {
    let key = generate_test_key(KID);
    let app = app_with_actor(&key, Some(bound_subject()), true, ActorType::Human);
    for (name, jti) in [
        (PROPOSER_ASSERTION_HEADER, "strip-p"),
        (APPROVER_ASSERTION_HEADER, "strip-a"),
    ] {
        let token = sign_token(&key, &valid_claims("alice", jti), KID);
        let (status, body) = send(&app, Some(name), &token).await;
        assert_eq!(status, StatusCode::OK, "{name}");
        assert_eq!(
            body["saw_assertion_header"], false,
            "{name} reached the handler"
        );
    }
}
