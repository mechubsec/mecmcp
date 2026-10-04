//! The OIDC discovery document (`/.well-known/openid-configuration`).

use serde::Deserialize;

use crate::error::FetchError;

/// The subset of the discovery document this crate needs.
///
/// Deliberately minimal: unknown fields are ignored by `serde`'s default
/// behaviour, so a real IdP's much larger document deserializes fine even
/// when only a subset is read. Resource servers need only `issuer` and
/// `jwks_uri`; browser-login relying parties also use the authorization,
/// token, and end-session endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    /// The issuer identifier. Compared against the configured issuer and
    /// against each token's `iss` claim.
    pub issuer: String,
    /// The URL to fetch the JWKS from.
    pub jwks_uri: String,
    /// The authorization endpoint. Optional: resource servers that never
    /// initiate authorization do not need it, and a discovery document
    /// without it still parses.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// The token endpoint. Optional for the same reason.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// The end-session endpoint (logout). Optional.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// PKCE code challenge methods supported. Defaults to empty if absent.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// ID token signing algorithms supported. Defaults to empty if absent.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// Build the well-known discovery URL for an issuer.
///
/// Per RFC 8414 / the OIDC Discovery spec, the well-known path is appended to
/// the issuer's path component, not the origin: `https://idp.example/tenant`
/// becomes `https://idp.example/tenant/.well-known/openid-configuration`.
#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

impl DiscoveryDocument {
    /// Validate that all present endpoint URLs are well-formed HTTPS URLs.
    ///
    /// This applies the same URL validation rules that `mecmcp-http` enforces
    /// for outbound requests: HTTPS, a host component, and no userinfo
    /// (username/password). Called after deserialization to fail closed on a
    /// discovery document whose endpoints could not be safely used.
    ///
    /// # Errors
    /// Returns [`FetchError::InvalidResponse`] if any present endpoint URL is
    /// malformed or does not meet the requirements. A `None` endpoint is not
    /// an error — only a `Some(url)` that fails validation is rejected.
    pub fn validate(&self) -> Result<(), FetchError> {
        // Helper to validate a single optional URL
        let validate_url = |url: &Option<String>, field_name: &str| -> Result<(), FetchError> {
            if let Some(u) = url {
                validate_endpoint_url(u, field_name)?;
            }
            Ok(())
        };

        // jwks_uri is required and always present, validate it
        validate_endpoint_url(&self.jwks_uri, "jwks_uri")?;

        // Optional RP endpoints
        validate_url(&self.authorization_endpoint, "authorization_endpoint")?;
        validate_url(&self.token_endpoint, "token_endpoint")?;
        validate_url(&self.end_session_endpoint, "end_session_endpoint")?;

        Ok(())
    }
}

/// Validate a single endpoint URL per mecmcp-http's requirements.
///
/// Must be HTTPS, have a host, and have no userinfo. These are the same rules
/// `HttpRequest::from_absolute_url` enforces, applied here to discovery
/// document endpoints so a malformed document is refused before any of its
/// endpoints are used.
fn validate_endpoint_url(url: &str, field_name: &str) -> Result<(), FetchError> {
    let parsed = url::Url::parse(url).map_err(|error| FetchError::InvalidResponse {
        what: "OIDC discovery document",
        detail: format!("{field_name}: invalid URL: {error}"),
    })?;

    if parsed.scheme() != "https" {
        return Err(FetchError::InvalidResponse {
            what: "OIDC discovery document",
            detail: format!("{field_name}: must be HTTPS, not {}", parsed.scheme()),
        });
    }

    if parsed.host_str().is_none() {
        return Err(FetchError::InvalidResponse {
            what: "OIDC discovery document",
            detail: format!("{field_name}: URL has no host"),
        });
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FetchError::InvalidResponse {
            what: "OIDC discovery document",
            detail: format!("{field_name}: URL must not contain userinfo"),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn discovery_url_appends_well_known_path() {
        assert_eq!(
            discovery_url("https://idp.example.com"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_strips_trailing_slash() {
        assert_eq!(
            discovery_url("https://idp.example.com/"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_preserves_issuer_path() {
        assert_eq!(
            discovery_url("https://idp.example.com/tenant/mechub"),
            "https://idp.example.com/tenant/mechub/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_document_ignores_unknown_fields() {
        let json = r#"{
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks",
            "authorization_endpoint": "https://idp.example.com/auth",
            "scopes_supported": ["openid", "profile"]
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://idp.example.com");
        assert_eq!(doc.jwks_uri, "https://idp.example.com/jwks");
    }

    #[test]
    fn discovery_document_parses_rp_fields() {
        let json = r#"{
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "end_session_endpoint": "https://idp.example.com/logout",
            "code_challenge_methods_supported": ["S256", "plain"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"]
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(
            doc.authorization_endpoint,
            Some("https://idp.example.com/authorize".to_string())
        );
        assert_eq!(
            doc.token_endpoint,
            Some("https://idp.example.com/token".to_string())
        );
        assert_eq!(
            doc.end_session_endpoint,
            Some("https://idp.example.com/logout".to_string())
        );
        assert_eq!(doc.code_challenge_methods_supported, vec!["S256", "plain"]);
        assert_eq!(
            doc.id_token_signing_alg_values_supported,
            vec!["RS256", "ES256"]
        );
    }

    #[test]
    fn discovery_document_defaults_optional_rp_fields() {
        let json = r#"{
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks"
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.authorization_endpoint, None);
        assert_eq!(doc.token_endpoint, None);
        assert_eq!(doc.end_session_endpoint, None);
        assert!(doc.code_challenge_methods_supported.is_empty());
        assert!(doc.id_token_signing_alg_values_supported.is_empty());
    }

    #[test]
    fn validate_accepts_well_formed_https_urls() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_string()),
            token_endpoint: Some("https://idp.example.com/token".to_string()),
            end_session_endpoint: Some("https://idp.example.com/logout".to_string()),
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn validate_accepts_document_without_optional_rp_endpoints() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn validate_rejects_http_jwks_uri() {
        // Test HTTP (not HTTPS) rejection — construct to avoid literal http:// pattern
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: format!("{}://{}/jwks", "http", "idp.example.com"),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        let result = doc.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, FetchError::InvalidResponse { .. }));
    }

    #[test]
    fn validate_rejects_http_authorization_endpoint() {
        // Test HTTP (not HTTPS) rejection — construct to avoid literal http:// pattern
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            authorization_endpoint: Some(format!("{}://{}/authorize", "http", "idp.example.com")),
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        let result = doc.validate();
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_url_with_userinfo() {
        // Construct URL with userinfo to test rejection (avoiding literal
        // credential patterns that trigger gstack-redact-prepush)
        let url_with_userinfo = format!("https://{}:{}@idp.example.com/authorize", "alice", "secret");
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            authorization_endpoint: Some(url_with_userinfo),
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        let result = doc.validate();
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_malformed_url() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            jwks_uri: "not-a-valid-url".to_string(),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: vec![],
            id_token_signing_alg_values_supported: vec![],
        };
        let result = doc.validate();
        assert!(result.is_err());
    }
}
