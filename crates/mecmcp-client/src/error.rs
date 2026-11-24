//! The client's error type.

use crate::UntrustedText;

/// Everything a client call can fail with. No variant holds a token, an
/// assertion, or a URL-bearing transport error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A configuration value was rejected.
    #[error("invalid client configuration: {field}")]
    Config {
        /// The offending field.
        field: &'static str,
    },
    /// The bearer token could not be loaded (message names the path, never the value).
    #[error("bearer token: {0}")]
    Token(String),
    /// TLS setup or handshake failed.
    #[error("TLS: {0}")]
    Tls(String),
    /// The connection could not be established.
    #[error("connection failed")]
    Connect,
    /// An operation exceeded its deadline.
    #[error("timed out during {operation}")]
    Timeout {
        /// The operation that timed out.
        operation: String,
    },
    /// The server answered with a non-success HTTP status.
    #[error("HTTP status {status}")]
    Http {
        /// The status code.
        status: u16,
    },
    /// The server violated the MCP protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The server returned a JSON-RPC error.
    #[error("JSON-RPC error {code}: {message}")]
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
        /// The server-supplied message, escaped for terminals when displayed.
        message: UntrustedText,
    },
    /// A tool call reported `isError`.
    #[error("tool error: {content}")]
    Tool {
        /// The tool's error content, escaped for terminals when displayed.
        content: UntrustedText,
    },
    /// A response exceeded the configured size limit.
    #[error("response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// A response body could not be decoded.
    #[error("response could not be decoded")]
    Decode,
    /// The session is closed.
    #[error("client closed")]
    Closed,
}
