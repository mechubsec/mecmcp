//! Verifying a presented JWT against a configured issuer's cached JWKS.

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::Algorithm;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use serde::Deserialize;

use crate::cache::{CacheConfig, KeyCache};
use crate::claims::{VerifiedClaims, extract_roles};
use crate::error::VerificationFailure;
use crate::fetch::KeySource;

/// Static configuration for one issuer's resource-server verification.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// The issuer URL. Compared against both the discovery document's own
    /// `issuer` and every token's `iss` claim.
    pub issuer: String,
    /// The audience this server expects tokens to be issued for.
    pub audience: String,
    /// Which claim carries the caller's group/role. Server-side configuration,
    /// never client-supplied — a token cannot tell this verifier which of its
    /// own claims to trust as the role.
    pub role_claim: String,
    /// Clock-skew tolerance applied to `exp` and `nbf`.
    pub leeway: Duration,
    /// JWKS cache tuning. See [`CacheConfig`] for what each field bounds.
    pub cache: CacheConfig,
}

impl OidcConfig {
    /// Build a config with the documented cache defaults.
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        role_claim: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            role_claim: role_claim.into(),
            leeway: Duration::from_secs(60),
            cache: CacheConfig::default(),
        }
    }
}

/// The raw claim shape read off the wire, before minimization.
///
/// `sub` and `exp` are named explicitly because [`VerifiedClaims`] needs them
/// typed; everything else — including `iss`, `aud`, `nbf`, and the configured
/// role claim — lands in `extra` and is read out of it, since which of those
/// are relevant is either server configuration (the role claim) or already
/// checked by `jsonwebtoken` against the raw claims independently of this
/// struct.
#[derive(Debug, Deserialize)]
struct RawClaims {
    sub: String,
    exp: i64,
    iat: Option<i64>,
    auth_time: Option<i64>,
    jti: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

/// Verifies presented JWTs against one configured issuer.
pub struct TokenVerifier {
    config: OidcConfig,
    cache: KeyCache,
}

impl TokenVerifier {
    /// Build a verifier for `config`, fetching discovery/JWKS through `source`.
    #[must_use]
    pub fn new(config: OidcConfig, source: Arc<dyn KeySource>) -> Self {
        let cache = KeyCache::new(source, config.issuer.clone(), config.cache.clone());
        Self { config, cache }
    }

    /// Verify `token` and, on success, return its minimal typed claim set.
    ///
    /// # Errors
    /// Returns the specific [`VerificationFailure`] variant describing why
    /// the token was rejected — never a single undifferentiated failure. See
    /// the crate-level acceptance criteria this maps to: forged signature,
    /// expired, wrong audience, and wrong issuer are each distinguishable by
    /// variant.
    pub async fn verify(&self, token: &str) -> Result<VerifiedClaims, VerificationFailure> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|error| VerificationFailure::Malformed(error.to_string()))?;

        // The keys lookup happens before signature verification: an IdP that
        // is unreachable must fail closed with a distinct reason, not be
        // reported as an ordinary signature failure once no key can be found.
        let keys = self.cache.keys().await?;

        let kid = header.kid.clone();
        let jwk = kid
            .as_deref()
            .and_then(|kid| keys.find(kid))
            .ok_or_else(|| VerificationFailure::UnknownKeyId(kid.clone()))?;

        let alg = matching_algorithm(jwk, header.alg)?;

        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
            .map_err(|_| VerificationFailure::UnsupportedAlgorithm)?;

        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = self.config.leeway.as_secs();
        validation.validate_nbf = true;
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let token_data = jsonwebtoken::decode::<RawClaims>(token, &decoding_key, &validation)
            .map_err(|error| map_decode_error(error.into_kind()))?;

        let roles = extract_roles(&token_data.claims.extra, &self.config.role_claim);

        let issued_at = token_data
            .claims
            .iat
            .ok_or(VerificationFailure::MissingIssuedAt)?;

        Ok(VerifiedClaims {
            subject: token_data.claims.sub,
            roles,
            expires_at: token_data.claims.exp,
            issued_at,
            auth_time: token_data.claims.auth_time,
            jwt_id: token_data.claims.jti,
        })
    }
}

/// Asymmetric signature algorithms this verifier accepts. A resource server
/// only ever holds a public key, never a shared secret, so no symmetric
/// (`HS*`) algorithm belongs here — see [`matching_algorithm`].
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Resolve which algorithm to validate with, and reject a mismatch between
/// what the JWK declares and what the token's header claims.
///
/// A JWK published by the IdP without a declared `alg` defers to the header,
/// which is ordinary for many providers. But when the JWK *does* declare one,
/// the header must agree — otherwise a caller holding a valid RS256 key could
/// try to get it accepted as, say, HS256 by relabeling the header, which is
/// the classic "alg confusion" JWT attack. Rejecting the mismatch outright
/// (rather than silently preferring one source) keeps that unrepresentable.
///
/// A JWKS is public by definition, so an `oct` (symmetric) key published
/// there is either a misconfiguration or a hostile IdP — either way, treating
/// its bytes as an HMAC secret would let anyone who can read the JWKS forge a
/// token. Both the key's own algorithm family and the header's algorithm must
/// come from [`ALLOWED_ALGORITHMS`], which excludes every `HS*` variant.
fn matching_algorithm(jwk: &Jwk, header_alg: Algorithm) -> Result<Algorithm, VerificationFailure> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(VerificationFailure::UnsupportedAlgorithm);
    }
    if !ALLOWED_ALGORITHMS.contains(&header_alg) {
        return Err(VerificationFailure::UnsupportedAlgorithm);
    }

    match jwk.common.key_algorithm {
        Some(declared) => {
            let declared_alg = Algorithm::try_from(declared)
                .map_err(|_| VerificationFailure::UnsupportedAlgorithm)?;
            if declared_alg == header_alg {
                Ok(declared_alg)
            } else {
                Err(VerificationFailure::UnsupportedAlgorithm)
            }
        }
        None => Ok(header_alg),
    }
}

/// Map `jsonwebtoken`'s error kinds to this crate's distinct failure reasons.
fn map_decode_error(kind: ErrorKind) -> VerificationFailure {
    match kind {
        ErrorKind::ExpiredSignature => VerificationFailure::Expired,
        ErrorKind::ImmatureSignature => VerificationFailure::NotYetValid,
        ErrorKind::InvalidIssuer => VerificationFailure::WrongIssuer,
        ErrorKind::InvalidAudience => VerificationFailure::WrongAudience,
        ErrorKind::InvalidSignature => VerificationFailure::InvalidSignature,
        ErrorKind::InvalidAlgorithm => VerificationFailure::UnsupportedAlgorithm,
        ErrorKind::MissingRequiredClaim(claim) => VerificationFailure::MissingClaim(claim),
        other => VerificationFailure::Malformed(format!("{other:?}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::discovery::DiscoveryDocument;
    use crate::error::FetchError;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use jsonwebtoken::EncodingKey;
    use jsonwebtoken::jwk::JwkSet;

    const ISSUER: &str = "https://idp.example.com";
    const AUDIENCE: &str = "mecmcp-server";
    const KID: &str = "test-key-1";

    /// An ephemeral RSA keypair and its matching JWK, generated fresh per
    /// test — never a committed fixture, so there is no secret-shaped
    /// literal for gitleaks to flag and nothing to rotate.
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

        // Derived straight from the private key via jsonwebtoken's own
        // crypto provider, rather than by touching RSA bignums in this test
        // module at all.
        let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256)
            .expect("JWK derivation");
        jwk.common.key_id = Some(kid.to_owned());

        TestKey { encoding_key, jwk }
    }

    fn sign_token(key: &TestKey, claims: &serde_json::Value, kid: &str) -> String {
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

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "alice@example.com",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "iat": now() - 60,
            "nbf": now() - 60,
            "groups": ["ops", "pci-approvers"],
        })
    }

    /// A [`KeySource`] backed entirely by in-memory fixtures. No socket is
    /// ever opened, which is what makes this test module runnable offline.
    struct FixtureSource {
        jwks: JwkSet,
    }

    #[async_trait::async_trait]
    impl KeySource for FixtureSource {
        async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
            Ok(DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: format!("{issuer}/jwks"),
            })
        }

        async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
            Ok(self.jwks.clone())
        }
    }

    fn verifier_for(jwks: JwkSet) -> TokenVerifier {
        let config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        TokenVerifier::new(config, Arc::new(FixtureSource { jwks }))
    }

    #[tokio::test]
    async fn accepts_a_validly_signed_token_and_extracts_minimal_claims() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims_json = valid_claims();
        claims_json["auth_time"] = serde_json::json!(now() - 120);
        claims_json["jti"] = serde_json::json!("assertion-1");
        let token = sign_token(&key, &claims_json, KID);
        let claims = verifier.verify(&token).await.expect("token must verify");

        assert_eq!(claims.subject, "alice@example.com");
        assert_eq!(
            claims.roles,
            vec!["ops".to_string(), "pci-approvers".to_string()]
        );
        assert_eq!(claims.issued_at, claims_json["iat"].as_i64().unwrap());
        assert_eq!(
            claims.auth_time,
            Some(claims_json["auth_time"].as_i64().unwrap())
        );
        assert_eq!(claims.jwt_id, Some("assertion-1".to_string()));
    }

    /// W1: `iat` is required by this crate even though `jsonwebtoken` itself
    /// does not treat it as a spec-required claim — without it, a caller
    /// enforcing step-up freshness (RFC 9470 `max_age`) has nothing to
    /// compare `now` against, and would otherwise pass the check vacuously.
    #[tokio::test]
    async fn rejects_a_token_missing_iat_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove("iat");
        let token = sign_token(&key, &claims, KID);

        let result = verifier.verify(&token).await;
        assert_eq!(result.unwrap_err(), VerificationFailure::MissingIssuedAt);
    }

    #[tokio::test]
    async fn rejects_a_forged_signature_distinctly() {
        let key = generate_test_key(KID);
        let attacker_key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk],
        };
        let verifier = verifier_for(jwks);

        // Signed with a *different* key that happens to share the published kid —
        // this is what a forged signature against a known kid looks like.
        let token = sign_token(&attacker_key, &valid_claims(), KID);
        let result = verifier.verify(&token).await;

        assert_eq!(result.unwrap_err(), VerificationFailure::InvalidSignature);
    }

    #[tokio::test]
    async fn rejects_an_expired_token_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now() - 3600);
        let token = sign_token(&key, &claims, KID);

        let result = verifier.verify(&token).await;
        assert_eq!(result.unwrap_err(), VerificationFailure::Expired);
    }

    #[tokio::test]
    async fn rejects_a_wrong_audience_token_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("some-other-service");
        let token = sign_token(&key, &claims, KID);

        let result = verifier.verify(&token).await;
        assert_eq!(result.unwrap_err(), VerificationFailure::WrongAudience);
    }

    #[tokio::test]
    async fn rejects_a_wrong_issuer_token_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims = valid_claims();
        claims["iss"] = serde_json::json!("https://not-the-configured-idp.example.com");
        let token = sign_token(&key, &claims, KID);

        let result = verifier.verify(&token).await;
        assert_eq!(result.unwrap_err(), VerificationFailure::WrongIssuer);
    }

    #[tokio::test]
    async fn rejects_a_not_yet_valid_token_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let mut claims = valid_claims();
        claims["nbf"] = serde_json::json!(now() + 3600);
        let token = sign_token(&key, &claims, KID);

        let result = verifier.verify(&token).await;
        assert_eq!(result.unwrap_err(), VerificationFailure::NotYetValid);
    }

    #[tokio::test]
    async fn rejects_unknown_key_id_distinctly() {
        let key = generate_test_key(KID);
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let verifier = verifier_for(jwks);

        let token = sign_token(&key, &valid_claims(), "some-other-kid");
        let result = verifier.verify(&token).await;

        assert_eq!(
            result.unwrap_err(),
            VerificationFailure::UnknownKeyId(Some("some-other-kid".to_string()))
        );
    }

    /// F1 regression: a symmetric (`oct`) JWK combined with a header-chosen
    /// `alg` must never be accepted, or anyone who can read the (public by
    /// definition) JWKS can forge tokens for any subject and role by signing
    /// HS256 with the published key bytes. Fails against the pre-fix code.
    #[tokio::test]
    async fn rejects_a_symmetric_oct_jwk_used_to_forge_hs256() {
        let secret = b"jwks-are-public-do-not-trust-these-bytes-as-a-hmac-secret";
        let encoding_key = EncodingKey::from_secret(secret);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::HS256)
            .expect("oct JWK derivation");
        jwk.common.key_id = Some(KID.to_owned());

        let jwks = JwkSet { keys: vec![jwk] };
        let verifier = verifier_for(jwks);

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_owned());
        let mut claims = valid_claims();
        claims["sub"] = serde_json::json!("attacker");
        claims["groups"] = serde_json::json!(["pci-approvers"]);
        let forged =
            jsonwebtoken::encode(&header, &claims, &encoding_key).expect("forge HS256 token");

        let result = verifier.verify(&forged).await;
        assert_eq!(
            result.unwrap_err(),
            VerificationFailure::UnsupportedAlgorithm
        );
    }

    #[tokio::test]
    async fn rejects_malformed_tokens_distinctly() {
        let verifier = verifier_for(JwkSet { keys: vec![] });
        let result = verifier.verify("not-a-jwt").await;
        assert!(matches!(result, Err(VerificationFailure::Malformed(_))));
    }

    /// JWKS rotation: the old `kid` is retired and a new one takes its place
    /// in what the IdP serves next. A cache primed with the old key set must
    /// pick up the new key once its refresh interval elapses — no server
    /// restart, matching the acceptance criterion by name.
    #[tokio::test(start_paused = true)]
    async fn jwks_rotation_is_picked_up_without_a_restart() {
        struct RotatingSource {
            keys: std::sync::Mutex<JwkSet>,
        }

        #[async_trait::async_trait]
        impl KeySource for RotatingSource {
            async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
                Ok(DiscoveryDocument {
                    issuer: issuer.to_owned(),
                    jwks_uri: format!("{issuer}/jwks"),
                })
            }

            async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
                Ok(self.keys.lock().expect("lock").clone())
            }
        }

        let old_key = generate_test_key("old-kid");
        let new_key = generate_test_key("new-kid");

        let source = Arc::new(RotatingSource {
            keys: std::sync::Mutex::new(JwkSet {
                keys: vec![old_key.jwk.clone()],
            }),
        });

        let mut config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        config.cache.refresh_interval = Duration::from_secs(60);
        let verifier = TokenVerifier::new(config, source.clone());

        let old_token = sign_token(&old_key, &valid_claims(), "old-kid");
        verifier
            .verify(&old_token)
            .await
            .expect("old key must verify before rotation");

        // The IdP retires the old key and publishes the new one.
        *source.keys.lock().expect("lock") = JwkSet {
            keys: vec![new_key.jwk.clone()],
        };

        let new_token = sign_token(&new_key, &valid_claims(), "new-kid");

        // Immediately after rotation, still within refresh_interval: the cache
        // has not refetched yet, so the new key is not visible.
        let too_soon = verifier.verify(&new_token).await;
        assert!(
            matches!(too_soon, Err(VerificationFailure::UnknownKeyId(_))),
            "new key should not be visible before the cache refreshes"
        );

        tokio::time::advance(Duration::from_secs(61)).await;

        let claims = verifier
            .verify(&new_token)
            .await
            .expect("new key must verify once the cache refreshes, with no restart");
        assert_eq!(claims.subject, "alice@example.com");

        let old_after_rotation = verifier.verify(&old_token).await;
        assert!(
            matches!(
                old_after_rotation,
                Err(VerificationFailure::UnknownKeyId(_))
            ),
            "the retired key must no longer verify once the cache has refreshed past it"
        );
    }

    #[tokio::test]
    async fn idp_unreachable_fails_closed_distinctly() {
        struct AlwaysDownSource;

        #[async_trait::async_trait]
        impl KeySource for AlwaysDownSource {
            async fn fetch_discovery(
                &self,
                _issuer: &str,
            ) -> Result<DiscoveryDocument, FetchError> {
                Err(FetchError::HttpStatus {
                    what: "OIDC discovery document",
                    status: 503,
                })
            }

            async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
                unreachable!("discovery fails first")
            }
        }

        let config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        let verifier = TokenVerifier::new(config, Arc::new(AlwaysDownSource));

        let key = generate_test_key(KID);
        let token = sign_token(&key, &valid_claims(), KID);

        let result = verifier.verify(&token).await;
        assert!(matches!(
            result,
            Err(VerificationFailure::KeysUnavailable { .. })
        ));
    }
}
