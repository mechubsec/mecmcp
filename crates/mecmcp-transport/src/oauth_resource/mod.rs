//! OAuth 2.1 resource-server mode (mecmcp#498). See `docs/OAUTH.md`.

mod metadata;
mod scope_map;

pub use metadata::{metadata_document, metadata_router};
pub use scope_map::{MappedAuthority, OAuthScopeMap, ScopeMapError};

use mecmcp_auth::{CallerCtx, Grant, OAuthIdentity};
use mecmcp_oidc::{
    KeySource, OidcConfig, ResourceUri, ResourceUriError, TokenProfile, TokenVerifier,
    VerificationFailure,
};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Why an [`OAuthResourceConfig`] was refused.
#[derive(Debug, thiserror::Error)]
pub enum OAuthConfigError {
    /// The issuer is not an `https` URL of printable ASCII with a host and no userinfo,
    /// query or fragment. Any userinfo in the rejected value is redacted.
    #[error(
        "OAuth issuer must be an https URL with a host, of printable ASCII without spaces: {0:?}"
    )]
    Issuer(String),
    /// The canonical resource URI is invalid.
    #[error(transparent)]
    Resource(#[from] ResourceUriError),
}

/// `issuer` for an error message, with anything before an `@` hidden: a refused issuer
/// may carry `user:password@` and the message reaches logs.
fn redact_userinfo(issuer: &str) -> String {
    match issuer.rsplit_once('@') {
        Some((_, after)) => format!("https://<redacted>@{after}"),
        None => issuer.to_owned(),
    }
}

/// Static configuration of one server's OAuth resource-server mode.
#[derive(Debug, Clone)]
pub struct OAuthResourceConfig {
    issuer: String,
    resource: ResourceUri,
    audience: Option<String>,
    scope_map: OAuthScopeMap,
    role_claim: String,
    require_at_jwt_typ: bool,
    verify_timeout: Duration,
    max_concurrent_verifications: usize,
}

impl OAuthResourceConfig {
    /// Validate and assemble a configuration. `issuer` is compared byte-for-byte with each
    /// token's `iss`, so it is *not* normalised: write it exactly as the IdP issues it.
    ///
    /// # Errors
    /// Returns [`OAuthConfigError`] for an unusable issuer or resource URI.
    pub fn new(
        issuer: &str,
        resource: &str,
        scope_map: OAuthScopeMap,
    ) -> Result<Self, OAuthConfigError> {
        // Refused at startup rather than surfacing later as every token's `iss` mismatching,
        // or as a discovery URL with the well-known suffix inside a query or fragment.
        let usable = issuer.bytes().all(|byte| byte.is_ascii_graphic())
            && issuer.starts_with("https://")
            && !issuer.contains(['?', '#'])
            && crate::auth::is_absolute_http_url(issuer);
        if !usable {
            return Err(OAuthConfigError::Issuer(redact_userinfo(issuer)));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            resource: ResourceUri::parse(resource)?,
            audience: None,
            scope_map,
            role_claim: "roles".to_owned(),
            require_at_jwt_typ: false,
            verify_timeout: Duration::from_secs(3),
            max_concurrent_verifications: 32,
        })
    }

    /// Override the expected `aud` (for IdPs that can only emit a client id). Must be
    /// unique per server, or tokens are not bound to one server.
    #[must_use]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_owned());
        self
    }

    /// The token claim carrying role/group names (default `roles`).
    #[must_use]
    pub fn with_role_claim(mut self, claim: &str) -> Self {
        self.role_claim = claim.to_owned();
        self
    }

    /// Require the RFC 9068 `typ: at+jwt` header (default off: many IdPs omit it).
    #[must_use]
    pub fn with_require_at_jwt_typ(mut self, required: bool) -> Self {
        self.require_at_jwt_typ = required;
        self
    }

    /// How long one verification (including any JWKS fetch it waits on) may take before
    /// the request is refused as unavailable (default 3 s).
    #[must_use]
    pub fn with_verify_timeout(mut self, timeout: Duration) -> Self {
        self.verify_timeout = timeout;
        self
    }

    /// How many verifications may be in flight at once; beyond that a request is refused
    /// as unavailable rather than queued (default 32, clamped to 1..=`Semaphore::MAX_PERMITS`).
    #[must_use]
    pub fn with_max_concurrent_verifications(mut self, permits: usize) -> Self {
        // Tokio's Semaphore::new panics above MAX_PERMITS; "unlimited" must not crash startup.
        self.max_concurrent_verifications = permits.clamp(1, Semaphore::MAX_PERMITS);
        self
    }

    /// The per-verification time limit.
    #[must_use]
    pub fn verify_timeout(&self) -> Duration {
        self.verify_timeout
    }

    /// The concurrent-verification limit.
    #[must_use]
    pub fn max_concurrent_verifications(&self) -> usize {
        self.max_concurrent_verifications
    }

    /// The issuer, exactly as configured.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The canonical resource URI.
    #[must_use]
    pub fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// The audience tokens must carry: the override, else the canonical resource string.
    #[must_use]
    pub fn audience(&self) -> &str {
        self.audience
            .as_deref()
            .unwrap_or_else(|| self.resource.as_str())
    }

    /// The claim -> scope table.
    #[must_use]
    pub fn scope_map(&self) -> &OAuthScopeMap {
        &self.scope_map
    }

    /// The token claim carrying role/group names.
    #[must_use]
    pub fn role_claim(&self) -> &str {
        &self.role_claim
    }

    /// Whether the `typ: at+jwt` header is required.
    #[must_use]
    pub fn require_at_jwt_typ(&self) -> bool {
        self.require_at_jwt_typ
    }
}

/// Why OAuth authentication did not produce a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthRejection {
    /// The token failed verification. The code is stable and safe to log
    /// (`VerificationFailure::reason_code`, `invalid_subject` or `invalid_client_id`).
    Invalid(&'static str),
    /// The token verified but maps to no tools: the caller is known and granted nothing.
    Unmapped(OAuthIdentity),
    /// Verification could not be completed (IdP keys unavailable, timed out, or the
    /// verifier is saturated). The token is not judged invalid.
    Unavailable(&'static str),
}

/// OAuth 2.1 resource-server authentication for one server.
pub struct OAuthResource<G: Grant> {
    config: OAuthResourceConfig,
    verifier: TokenVerifier,
    permits: Semaphore,
    _grant: PhantomData<fn() -> G>,
}

impl<G: Grant> OAuthResource<G> {
    /// Build the verifier from `config`; JWKS and discovery are fetched through `source`
    /// (pass `Arc::new(HttpKeySource::new(client))` in production, a fixture in tests).
    #[must_use]
    pub fn new(config: OAuthResourceConfig, source: Arc<dyn KeySource>) -> Self {
        let mut oidc = OidcConfig::new(config.issuer(), config.audience(), config.role_claim());
        oidc.token_profile = TokenProfile::AccessToken {
            require_at_jwt_typ: config.require_at_jwt_typ(),
        };
        Self {
            verifier: TokenVerifier::new(oidc, source),
            permits: Semaphore::new(config.max_concurrent_verifications()),
            config,
            _grant: PhantomData,
        }
    }

    /// The configuration this resource was built from.
    #[must_use]
    pub fn config(&self) -> &OAuthResourceConfig {
        &self.config
    }

    /// The RFC 9728 router for this resource (merge outside the bearer boundary).
    pub fn metadata_router(&self) -> axum::Router {
        metadata_router(&self.config)
    }

    /// Verify `token` and map it to a caller.
    ///
    /// The token is read, never stored: the returned context carries only the verified
    /// issuer, subject and client id.
    ///
    /// # Errors
    /// See [`OAuthRejection`].
    pub async fn authenticate(&self, token: &str) -> Result<CallerCtx<G>, OAuthRejection> {
        // A slow IdP holds the key cache while it fetches: refuse rather than queue, and
        // stop waiting after the timeout, so unauthenticated callers cannot pile up on it.
        let Ok(_permit) = self.permits.try_acquire() else {
            return Err(OAuthRejection::Unavailable("busy"));
        };
        let verified =
            tokio::time::timeout(self.config.verify_timeout(), self.verifier.verify(token))
                .await
                .map_err(|_elapsed| OAuthRejection::Unavailable("timeout"))?;
        let claims = match verified {
            Ok(claims) => claims,
            Err(VerificationFailure::KeysUnavailable { .. }) => {
                return Err(OAuthRejection::Unavailable("keys_unavailable"));
            }
            Err(failure) => return Err(OAuthRejection::Invalid(failure.reason_code())),
        };
        // `sub` becomes the rate-limit key and the change-set identity, and `client_id`
        // reaches audit text: neither may carry spaces, controls or bidi/format characters.
        if !valid_identity_part(&claims.subject) {
            return Err(OAuthRejection::Invalid("invalid_subject"));
        }
        if !claims.client_id.as_deref().is_some_and(valid_identity_part) {
            return Err(OAuthRejection::Invalid("invalid_client_id"));
        }
        let identity = OAuthIdentity {
            issuer: self.config.issuer().to_owned(),
            subject: claims.subject,
            client_id: claims.client_id,
        };
        let Some(authority) = self.config.scope_map().map(&claims.scopes, &claims.roles) else {
            return Err(OAuthRejection::Unmapped(identity));
        };
        Ok(CallerCtx::oauth(
            identity,
            authority.devices,
            authority.tools,
            authority.actor_type,
        ))
    }
}

/// Cheap shape test run before any async work: exactly three non-empty base64url segments.
///
/// Length is bounded upstream: an `Authorization` header over 4096 bytes is refused before
/// this runs, so access tokens larger than about 4 KiB are not supported.
pub(crate) fn looks_like_jwt(candidate: &str) -> bool {
    let mut segments = 0;
    for segment in candidate.split('.') {
        segments += 1;
        let clean = !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !clean {
            return false;
        }
    }
    segments == 3
}

/// 1-128 bytes of printable ASCII without spaces.
fn valid_identity_part(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn map() -> OAuthScopeMap {
        OAuthScopeMap::from_json(br#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#)
            .unwrap()
    }

    #[test]
    fn audience_defaults_to_the_canonical_resource() {
        let config = OAuthResourceConfig::new(
            "https://idp.example/realms/lab",
            "https://junos.example/mcp",
            map(),
        )
        .unwrap();
        assert_eq!(config.audience(), "https://junos.example/mcp");
        assert_eq!(
            config.clone().with_audience("junos-client").audience(),
            "junos-client"
        );
    }

    #[test]
    fn an_insecure_or_hostile_issuer_is_refused() {
        for bad in [
            "http://idp.example",
            "idp.example",
            "https://idp.example/a b",
            "https://idp\n.example",
        ] {
            assert!(
                OAuthResourceConfig::new(bad, "https://junos.example/mcp", map()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn an_issuer_without_a_host_is_refused() {
        for bad in [
            "https://",
            "https:///realms/lab",
            "https://:443/realms/lab",
            "https://?x",
            "https://user@/realms/lab",
            "https://[broken",
            "https://idp.example:bogus/path",
            "https://idp.example/realms/lab?x=1",
            "https://idp.example/realms/lab#frag",
            "https://user@idp.example/realms/lab",
        ] {
            assert!(
                OAuthResourceConfig::new(bad, "https://junos.example/mcp", map()).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            OAuthResourceConfig::new(
                "https://idp.example:8443/realms/lab",
                "https://junos.example/mcp",
                map()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_refused_issuer_does_not_echo_its_credentials() {
        let error = OAuthResourceConfig::new(
            "https://alice:s3cr3t@idp.example/realms/lab",
            "https://junos.example/mcp",
            map(),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("s3cr3t"), "{error}");
        assert!(!error.contains("alice"), "{error}");
    }

    #[test]
    fn looks_like_jwt_accepts_only_three_base64url_segments() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(looks_like_jwt("a-_.B9.c"));
        for bad in [
            "", "a", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b.", "a.b.c=", "a.b.c d", "a.b.é",
            "a.b+.c", "a/.b.c", "a.b.c~",
        ] {
            assert!(!looks_like_jwt(bad), "{bad:?}");
        }
    }

    #[test]
    fn verification_limits_default_and_floor() {
        let config =
            OAuthResourceConfig::new("https://idp.example", "https://junos.example/mcp", map())
                .unwrap();
        assert_eq!(config.verify_timeout(), Duration::from_secs(3));
        assert_eq!(config.max_concurrent_verifications(), 32);
        assert_eq!(
            config
                .clone()
                .with_max_concurrent_verifications(0)
                .max_concurrent_verifications(),
            1
        );
        assert_eq!(
            config
                .with_max_concurrent_verifications(usize::MAX)
                .max_concurrent_verifications(),
            Semaphore::MAX_PERMITS
        );
    }

    #[test]
    fn a_bad_resource_is_refused() {
        assert!(
            OAuthResourceConfig::new("https://idp.example", "http://junos.example/mcp", map())
                .is_err()
        );
    }
}
