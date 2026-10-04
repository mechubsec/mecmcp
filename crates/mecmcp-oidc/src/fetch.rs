//! The seam between key caching and the network.
//!
//! [`KeySource`] is the only way this crate touches a customer's IdP. That
//! makes the offline-first guarantee mechanical rather than a promise: the
//! test suite supplies a [`KeySource`] backed by in-memory fixtures and never
//! links against a socket, while [`HttpKeySource`] is the one production
//! implementation, built on `mecmcp-http`'s hardened client rather than a raw
//! `reqwest` call.

use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use mecmcp_http::{HttpClient, HttpRequest, Method};

use crate::discovery::{DiscoveryDocument, discovery_url};
use crate::error::FetchError;

/// Fetches the two documents a resource server needs from an IdP: the
/// discovery document and the JWKS it points to.
///
/// `async_trait` rather than native `async fn` in a trait, because this trait
/// is used as `Arc<dyn KeySource>` — a cache shared across concurrent
/// verification calls needs a trait object, and native RPITIT is not object
/// safe.
#[async_trait]
pub trait KeySource: Send + Sync {
    /// Fetch and parse the discovery document for `issuer`.
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError>;

    /// Fetch and parse the JWKS at `jwks_uri`.
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, FetchError>;
}

/// Production [`KeySource`], built on `mecmcp-http`'s hardened outbound client.
///
/// Inherits that client's guarantees for free: HTTPS-only, no redirects, no
/// proxy, bounded response size, and a whole-request deadline. An OIDC
/// discovery/JWKS endpoint is exactly the kind of outbound API call that
/// crate was built for.
pub struct HttpKeySource {
    client: HttpClient,
}

impl HttpKeySource {
    /// Wrap an already-constructed [`HttpClient`].
    ///
    /// Construction (and therefore the crypto-provider requirement) is the
    /// caller's concern — this crate has no opinion about which provider a
    /// consuming binary installs.
    #[must_use]
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    async fn get_json_bytes(&self, url: &str, what: &'static str) -> Result<Vec<u8>, FetchError> {
        let request = HttpRequest::from_absolute_url(Method::Get, url)
            .map_err(|source| FetchError::Transport { what, source })?
            .header("Accept", "application/json")
            .map_err(|source| FetchError::Transport { what, source })?;

        let response = self
            .client
            .send(request)
            .await
            .map_err(|source| FetchError::Transport { what, source })?;

        if response.status() != 200 {
            return Err(FetchError::HttpStatus {
                what,
                status: response.status(),
            });
        }

        Ok(response.body().to_vec())
    }
}

#[async_trait]
impl KeySource for HttpKeySource {
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        let url = discovery_url(issuer);
        let body = self.get_json_bytes(&url, "OIDC discovery document").await?;
        let doc: DiscoveryDocument =
            serde_json::from_slice(&body).map_err(|error| FetchError::InvalidResponse {
                what: "OIDC discovery document",
                detail: error.to_string(),
            })?;
        // Validate endpoint URLs before accepting the document
        doc.validate()?;
        Ok(doc)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwkSet, FetchError> {
        let body = self.get_json_bytes(jwks_uri, "JWKS").await?;
        serde_json::from_slice(&body).map_err(|error| FetchError::InvalidResponse {
            what: "JWKS",
            detail: error.to_string(),
        })
    }
}
