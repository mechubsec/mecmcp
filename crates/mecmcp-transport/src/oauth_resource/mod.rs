//! OAuth 2.1 resource-server mode (mecmcp#498). See `docs/OAUTH.md`.

mod scope_map;

pub use scope_map::{MappedAuthority, OAuthScopeMap, ScopeMapError};

use mecmcp_oidc::{ResourceUri, ResourceUriError};

/// Why an [`OAuthResourceConfig`] was refused.
#[derive(Debug, thiserror::Error)]
pub enum OAuthConfigError {
    /// The issuer is not an `https` URL of printable ASCII with a host.
    #[error(
        "OAuth issuer must be an https URL with a host, of printable ASCII without spaces: {0:?}"
    )]
    Issuer(String),
    /// The canonical resource URI is invalid.
    #[error(transparent)]
    Resource(#[from] ResourceUriError),
}

/// Static configuration of one server's OAuth resource-server mode.
#[derive(Debug, Clone)]
pub struct OAuthResourceConfig {
    issuer: String,
    resource: ResourceUri,
    audience: Option<String>,
    scope_map: OAuthScopeMap,
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
        let printable = issuer.bytes().all(|byte| byte.is_ascii_graphic());
        let Some(after_scheme) = issuer.strip_prefix("https://") else {
            return Err(OAuthConfigError::Issuer(issuer.to_owned()));
        };
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        // Refused at startup rather than surfacing later as every token's `iss` mismatching.
        let has_host =
            !authority.is_empty() && !authority.starts_with(':') && !authority.contains('@');
        if !printable || !has_host {
            return Err(OAuthConfigError::Issuer(issuer.to_owned()));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            resource: ResourceUri::parse(resource)?,
            audience: None,
            scope_map,
        })
    }

    /// Override the expected `aud` (for IdPs that can only emit a client id). Must be
    /// unique per server, or tokens are not bound to one server.
    #[must_use]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_owned());
        self
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
    fn a_bad_resource_is_refused() {
        assert!(
            OAuthResourceConfig::new("https://idp.example", "http://junos.example/mcp", map())
                .is_err()
        );
    }
}
