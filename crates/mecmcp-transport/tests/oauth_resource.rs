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
