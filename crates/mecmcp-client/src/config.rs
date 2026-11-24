//! Client configuration.

use std::time::Duration;

use url::Url;

use crate::{BearerToken, ClientError};

/// Upper bound for `max_response_bytes`: rmcp caps plain-JSON bodies at a fixed
/// 16 MiB, so a larger setting would promise a limit we cannot enforce.
const MAX_RESPONSE_BYTES_CEILING: usize = 16 * 1024 * 1024;

/// Which MCP protocol generation to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMode {
    /// Try the stateless 2026 protocol, fall back to the legacy session lifecycle.
    Auto,
    /// Stateless 2026 protocol only.
    Stateless2026,
    /// Legacy initialize/session lifecycle only.
    Legacy,
}

/// Connection settings for one MCP server.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server endpoint: `https` only, no userinfo, no fragment.
    pub url: Url,
    /// Bearer token sent with every request.
    pub token: BearerToken,
    /// Extra CA certificates (PEM). Non-empty replaces the system root store.
    pub ca_pem: Vec<String>,
    /// TCP+TLS connect timeout (default 10s).
    pub connect_timeout: Duration,
    /// Per-call timeout (default 30s).
    pub request_timeout: Duration,
    /// Response size cap in bytes (default 8 MiB). Must be in `1..=16 MiB`:
    /// rmcp caps plain-JSON bodies at a fixed 16 MiB, so more would be a lie.
    pub max_response_bytes: usize,
    /// Maximum `tools/list` pages followed (default 32).
    pub max_tool_pages: usize,
    /// Protocol generation (default [`ProtocolMode::Auto`]).
    pub protocol: ProtocolMode,
    /// `clientInfo.name` sent to the server.
    pub client_name: String,
    /// `clientInfo.version` sent to the server.
    pub client_version: String,
}

impl ClientConfig {
    /// Build a config with defaults.
    ///
    /// # Errors
    /// [`ClientError::Config`] if `url` is unparsable, not `https`, or carries
    /// userinfo or a fragment.
    pub fn new(url: &str, token: BearerToken) -> Result<Self, ClientError> {
        let url = Url::parse(url).map_err(|_| ClientError::Config { field: "url" })?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ClientError::Config { field: "url" });
        }
        Ok(Self {
            url,
            token,
            ca_pem: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
            max_tool_pages: 32,
            protocol: ProtocolMode::Auto,
            client_name: "mecmcp-client".to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
        })
    }

    /// Reject zero timeouts/pages and an out-of-range response cap. Call after
    /// editing public fields, before connecting.
    ///
    /// # Errors
    /// [`ClientError::Config`] naming the first bad field.
    pub fn validate(&self) -> Result<(), ClientError> {
        let bad = |field| Err(ClientError::Config { field });
        if self.connect_timeout.is_zero() {
            return bad("connect_timeout");
        }
        if self.request_timeout.is_zero() {
            return bad("request_timeout");
        }
        if !(1..=MAX_RESPONSE_BYTES_CEILING).contains(&self.max_response_bytes) {
            return bad("max_response_bytes");
        }
        if self.max_tool_pages == 0 {
            return bad("max_tool_pages");
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests
mod tests {
    use super::*;
    use mecmcp_secret::OutboundSecret;

    fn token() -> BearerToken {
        BearerToken::from_secret(OutboundSecret::new_unchecked("fake-test-token".into()))
    }

    fn config() -> ClientConfig {
        ClientConfig::new("https://mcp.example/mcp", token()).unwrap()
    }

    #[test]
    fn rejects_http_scheme() {
        assert!(ClientConfig::new("http://mcp.example/mcp", token()).is_err());
    }

    #[test]
    fn rejects_userinfo_in_url() {
        assert!(ClientConfig::new("https://user:pw@mcp.example/mcp", token()).is_err());
        assert!(ClientConfig::new("https://user@mcp.example/mcp", token()).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        let mut cfg = config();
        cfg.request_timeout = Duration::ZERO;
        assert!(matches!(
            cfg.validate(),
            Err(ClientError::Config {
                field: "request_timeout"
            })
        ));
    }

    #[test]
    fn response_cap_bounds() {
        let mut cfg = config();
        assert!(cfg.validate().is_ok());
        cfg.max_response_bytes = 0;
        assert!(cfg.validate().is_err());
        cfg.max_response_bytes = MAX_RESPONSE_BYTES_CEILING;
        assert!(cfg.validate().is_ok());
        cfg.max_response_bytes += 1;
        assert!(cfg.validate().is_err());
    }
}
