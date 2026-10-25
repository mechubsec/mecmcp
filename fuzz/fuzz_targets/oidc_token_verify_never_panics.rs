#![no_main]
//! `TokenVerifier::verify` is the one function in this crate that consumes a
//! fully caller-controlled bearer token -- base64url framing, JSON header
//! and claims, and a signature, none of it trustworthy until this call
//! returns. A panic here (rather than a `VerificationFailure`) is reachable
//! by any client that can reach the server's request handler, authenticated
//! or not. The JWKS is fixed to one real key so the target exercises
//! `decode_header`, `matching_algorithm`, and `jsonwebtoken::decode` against
//! realistic (if malformed) tokens rather than always failing at "unknown
//! key id".

use std::sync::{Arc, OnceLock};

use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use libfuzzer_sys::fuzz_target;
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource, OidcConfig, TokenVerifier};

const ISSUER: &str = "https://idp.fuzz.example.com";
const AUDIENCE: &str = "mecmcp-server";
const KID: &str = "fuzz-key-1";

/// A [`KeySource`] backed by one fixed, freshly generated key. No socket is
/// ever opened, matching the crate's own offline-first test suite.
struct FixedSource {
    jwks: JwkSet,
}

#[async_trait::async_trait]
impl KeySource for FixedSource {
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

fn verifier() -> &'static TokenVerifier {
    static VERIFIER: OnceLock<TokenVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let key_pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("RSA key generation");
        let pkcs8_der: aws_lc_rs::encoding::Pkcs8V1Der<'static> =
            aws_lc_rs::encoding::AsDer::as_der(&key_pair).expect("PKCS8 encoding");
        let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.as_ref().to_vec()));

        let encoding_key =
            EncodingKey::from_rsa_pem(pem_text.as_bytes()).expect("valid PEM for jsonwebtoken");
        let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256)
            .expect("JWK derivation");
        jwk.common.key_id = Some(KID.to_owned());

        let config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        let source = Arc::new(FixedSource {
            jwks: JwkSet { keys: vec![jwk] },
        });
        TokenVerifier::new(config, source)
    })
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime")
    })
}

fuzz_target!(|data: &str| {
    let _ = runtime().block_on(verifier().verify(data));
});
