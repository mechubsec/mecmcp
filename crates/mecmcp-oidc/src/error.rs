//! Error types for discovery/JWKS fetching and token verification.
//!
//! Two separate enums on purpose: [`FetchError`] describes why the network
//! leg to the customer's IdP failed, and [`VerificationFailure`] describes
//! why a *presented token* was rejected. Collapsing them into one "auth
//! failed" catch-all is exactly what the acceptance criteria for this crate
//! forbid — an auditor reading a rejection needs to know whether the caller
//! forged a signature or the IdP was simply unreachable, and those are very
//! different incidents.

use thiserror::Error;

/// Why fetching the discovery document or JWKS failed.
#[derive(Debug, Error)]
pub enum FetchError {
    /// The HTTP transport itself failed (DNS, TLS, connect, timeout, ...).
    #[error("transport error fetching {what}: {source}")]
    Transport {
        /// What was being fetched, for the log line.
        what: &'static str,
        /// The underlying transport error.
        #[source]
        source: mecmcp_http::HttpError,
    },
    /// The IdP responded, but not with a success status.
    #[error("{what} returned HTTP status {status}")]
    HttpStatus {
        /// What was being fetched.
        what: &'static str,
        /// The HTTP status code returned.
        status: u16,
    },
    /// The response body was not valid JSON, or not shaped like the document expected.
    #[error("{what} response could not be parsed: {detail}")]
    InvalidResponse {
        /// What was being fetched.
        what: &'static str,
        /// Parse failure detail.
        detail: String,
    },
    /// The discovery document's `issuer` does not match the configured
    /// issuer. Per OIDC Discovery §4.3 this is a hard mismatch, not a detail
    /// to log and continue past — an IdP claiming to be someone else is the
    /// same class of problem as an unreachable IdP, so this fails closed
    /// through the same [`crate::error::VerificationFailure::KeysUnavailable`] path.
    #[error(
        "OIDC discovery document issuer {discovered:?} does not match configured issuer {configured:?}"
    )]
    IssuerMismatch {
        /// The issuer this verifier was configured with.
        configured: String,
        /// The issuer the discovery document actually declared.
        discovered: String,
    },
}

/// Why a presented JWT was rejected.
///
/// Every variant is a distinct, loggable reason. Do not add a catch-all
/// variant here — a call site that cannot determine which of these applies
/// has a bug, not a reason to hide the detail.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationFailure {
    /// The token is not a well-formed JWT (bad base64, bad JSON, wrong number of segments).
    #[error("token is not a well-formed JWT: {0}")]
    Malformed(String),
    /// The token's header does not carry a Key ID, or names one absent from
    /// the cached JWKS.
    #[error("token key id {0:?} is not present in the cached JWKS")]
    UnknownKeyId(Option<String>),
    /// The token's `alg` disagrees with what the matching JWK declares, or
    /// names an algorithm this verifier does not support.
    #[error(
        "token algorithm is unsupported or disagrees with the matching key's declared algorithm"
    )]
    UnsupportedAlgorithm,
    /// Signature verification failed against every cached key considered.
    #[error("token signature is invalid")]
    InvalidSignature,
    /// The token's `exp` claim is in the past.
    #[error("token has expired")]
    Expired,
    /// The token's `nbf` claim is in the future.
    #[error("token is not yet valid (nbf)")]
    NotYetValid,
    /// The token's `aud` claim does not contain the configured audience.
    #[error("token audience does not match the configured audience")]
    WrongAudience,
    /// The token's `iss` claim does not equal the configured issuer.
    #[error("token issuer does not match the configured issuer")]
    WrongIssuer,
    /// A claim required for verification (`exp`, `iss`, `aud`, or `sub`) was absent.
    #[error("token is missing required claim '{0}'")]
    MissingClaim(String),
    /// No usable signing keys were available: the IdP has never been
    /// reachable, or the last known-good keys are older than the configured
    /// maximum age. This is the fail-closed path for an unreachable IdP.
    #[error(
        "no usable signing keys are available for issuer '{issuer}' (IdP unreachable and cache is empty or too stale)"
    )]
    KeysUnavailable {
        /// The issuer whose keys could not be obtained.
        issuer: String,
    },
    /// The token's `nonce` claim was expected but is missing.
    ///
    /// For browser-login relying parties, `nonce` binds the token to the
    /// authorization request and MUST be verified per OIDC Core §3.1.3.2.
    /// Resource servers that never initiate authorization leave
    /// `expected_nonce` as `None` and never hit this variant.
    #[error("token is missing the required 'nonce' claim")]
    NonceMissing,
    /// The token's `nonce` claim does not match the expected value.
    ///
    /// Constant-time comparison per OIDC Core §3.1.3.2 — a timing leak in
    /// nonce comparison is a session fixation oracle.
    #[error("token nonce does not match the expected value")]
    NonceMismatch,
    /// The token's `azp` (authorized party) claim validation failed.
    ///
    /// Per OIDC Core §3.1.3.7, when the ID Token contains multiple audiences,
    /// the `azp` claim MUST be present and match the client ID. When `azp` is
    /// present in a single-audience token, it must also match.
    #[error("token authorized party claim validation failed")]
    AuthorizedPartyMismatch,
}
