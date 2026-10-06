//! A one-shot loopback HTTP listener catching the authorization-code
//! redirect, per RFC 8252 ("OAuth 2.0 for Native Apps") §7.3.
//!
//! Binds `127.0.0.1:0` (an OS-assigned ephemeral port, never a fixed one --
//! RFC 8252 recommends this so two logins in flight on the same host never
//! collide), accepts exactly one connection, extracts `code`/`state`/`iss`
//! from the request line's query string, and replies with a static HTML
//! page telling the human to go back to their terminal. The listener is
//! dropped (and the port freed) the moment that one request is read; it
//! never accepts a second connection, so a probe after the real redirect
//! lands on a closed port, not a second chance to replay someone else's
//! callback.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::error::ApproveError;

const CALLBACK_PATH: &str = "/callback";
const RESPONSE_BODY: &str = "mecmcp-approve received the authorization response. You can close this tab and return to your terminal.";

/// A bound loopback listener, ready to accept the one redirect it expects.
pub struct LoopbackListener {
    listener: TcpListener,
    port: u16,
}

/// The `code`/`state` pair (and optional RFC 9207 `iss`) pulled from the
/// redirect's query string.
#[derive(Debug, Clone)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
    pub issuer: Option<String>,
}

impl LoopbackListener {
    /// Bind an ephemeral loopback port, or `requested_port` when the caller
    /// asked for a specific one (some IdPs pre-register a fixed redirect
    /// URI and refuse anything else).
    pub async fn bind(requested_port: u16) -> Result<Self, ApproveError> {
        let listener = TcpListener::bind(("127.0.0.1", requested_port))
            .await
            .map_err(ApproveError::LoopbackBind)?;
        let port = listener
            .local_addr()
            .map_err(ApproveError::LoopbackBind)?
            .port();
        Ok(Self { listener, port })
    }

    /// The redirect URI the authorization request should advertise.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    /// Accept the single expected redirect, bounded by `timeout`.
    ///
    /// Reads only the request line (never the body, never further headers)
    /// -- everything this flow needs is in the query string, and a browser's
    /// GET has no body worth reading. Replies with a fixed 200 regardless of
    /// what was in the query string; callers decide separately whether
    /// `code`/`state` were valid.
    pub async fn accept_once(self, timeout: Duration) -> Result<CallbackParams, ApproveError> {
        let (mut stream, _) = tokio::time::timeout(timeout, self.listener.accept())
            .await
            .map_err(|_elapsed| ApproveError::LoopbackTimeout)?
            .map_err(ApproveError::LoopbackRead)?;

        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .map_err(ApproveError::LoopbackRead)?;

        let params =
            parse_request_line(&request_line).ok_or(ApproveError::LoopbackMalformedCallback)?;

        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            RESPONSE_BODY.len(),
            RESPONSE_BODY
        );
        // Best-effort: the human already has what they need from the
        // browser tab regardless of whether this write lands, and the CLI
        // process already has `params`.
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;

        Ok(params)
    }
}

/// Parse `GET /callback?code=...&state=...&iss=... HTTP/1.1` into its query
/// parameters. Returns `None` if the request line is not a well-formed GET
/// with both `code` and `state` present -- both are required by this flow,
/// so a redirect missing either is malformed, not a different valid case.
fn parse_request_line(line: &str) -> Option<CallbackParams> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path_and_query = parts.next()?;
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }

    // Query parsing needs a base to resolve against; the authority is
    // never used (only the query string is read), so any placeholder works.
    let url = url::Url::parse(&format!("http://127.0.0.1{path_and_query}")).ok()?;

    let mut code = None;
    let mut state = None;
    let mut issuer = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "iss" => issuer = Some(value.into_owned()),
            _ => {}
        }
    }

    Some(CallbackParams {
        code: code?,
        state: state?,
        issuer,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_code_and_state() {
        let params =
            parse_request_line("GET /callback?code=abc123&state=xyz HTTP/1.1\r\n").unwrap();
        assert_eq!(params.code, "abc123");
        assert_eq!(params.state, "xyz");
        assert_eq!(params.issuer, None);
    }

    #[test]
    fn parses_optional_issuer() {
        let params = parse_request_line(
            "GET /callback?code=abc&state=xyz&iss=https%3A%2F%2Fidp.example HTTP/1.1\r\n",
        )
        .unwrap();
        assert_eq!(params.issuer, Some("https://idp.example".to_owned()));
    }

    #[test]
    fn rejects_missing_code() {
        assert!(parse_request_line("GET /callback?state=xyz HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_missing_state() {
        assert!(parse_request_line("GET /callback?code=abc HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_non_get() {
        assert!(parse_request_line("POST /callback?code=abc&state=xyz HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_malformed_line() {
        assert!(parse_request_line("not a request line").is_none());
    }

    #[tokio::test]
    async fn bind_picks_an_ephemeral_port_by_default() {
        let listener = LoopbackListener::bind(0).await.unwrap();
        assert_ne!(listener.port, 0);
        assert!(listener.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(listener.redirect_uri().ends_with("/callback"));
    }

    #[tokio::test]
    async fn accept_once_reads_the_redirect() {
        let listener = LoopbackListener::bind(0).await.unwrap();
        let port = listener.port;

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            stream
                .write_all(b"GET /callback?code=the-code&state=the-state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        });

        let params = listener.accept_once(Duration::from_secs(5)).await.unwrap();
        client.await.unwrap();

        assert_eq!(params.code, "the-code");
        assert_eq!(params.state, "the-state");
    }

    #[tokio::test]
    async fn accept_once_times_out_with_no_connection() {
        let listener = LoopbackListener::bind(0).await.unwrap();
        let result = listener.accept_once(Duration::from_millis(50)).await;
        assert!(matches!(result, Err(ApproveError::LoopbackTimeout)));
    }
}
