//! Bridges this workspace's `reqwest` client (rustls, no bundled TLS
//! provider, HTTP/1.1 only -- the same posture as `mecmcp-http`, see D4 in
//! `mecmcp-http/Cargo.toml`) to `oauth2`'s [`oauth2::AsyncHttpClient`].
//!
//! `oauth2` ships its own `reqwest` feature for this, but enabling it pulls
//! a second `reqwest` major version (0.12, vs this workspace's 0.13) and
//! `reqwest/rustls-tls`, which links `ring` as the crypto provider alongside
//! this workspace's `aws-lc-rs` -- precisely the two-provider conflict
//! `mecmcp-http`'s own Cargo.toml comment warns broke TLS before. A thin
//! bridge avoids both: one `reqwest`, one provider, and `oauth2` only ever
//! sees the [`oauth2::HttpRequest`]/[`oauth2::HttpResponse`] types it already
//! defines as its extension point.

use std::error::Error as StdError;
use std::fmt;

use oauth2::{HttpRequest, HttpResponse};

/// Error performing a bridged OAuth2 HTTP request.
#[derive(Debug)]
pub struct BridgeError(pub reqwest::Error);

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for BridgeError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}

/// Perform one `oauth2` HTTP request over a caller-supplied `reqwest::Client`.
///
/// `oauth2::AsyncHttpClient` is blanket-implemented for any
/// `Fn(HttpRequest) -> F` where `F: Future<Output = Result<HttpResponse, E>>`,
/// so callers pass a closure capturing `client.clone()` and calling this
/// function -- see `oidc.rs`. Kept as a free function rather than a type
/// implementing the trait directly: implementing `Fn` for a user type needs
/// an unstable nightly feature, and the device-code poll loop calls this
/// many times, which the blanket impl's own doc comment says a closure must
/// support (`Fn`, not `FnOnce`).
pub async fn send(
    client: &reqwest::Client,
    request: HttpRequest,
) -> Result<HttpResponse, BridgeError> {
    let method = request.method().clone();
    let uri = request.uri().to_string();
    let mut builder = client.request(method, uri);
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder = builder.body(request.body().clone());

    let response = builder.send().await.map_err(BridgeError)?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(BridgeError)?.to_vec();

    let mut out = http::Response::builder().status(status);
    for (name, value) in &headers {
        out = out.header(name, value);
    }
    // `headers`/`status` above came straight from `reqwest::Response`, which
    // only ever yields a valid `http::StatusCode`/`HeaderMap` in the first
    // place -- nothing user-controlled is re-parsed here, so a builder error
    // would mean `reqwest` itself returned something it shouldn't have.
    #[allow(clippy::expect_used)]
    Ok(out
        .body(body)
        .expect("status and headers were already validated by reqwest::Response"))
}
