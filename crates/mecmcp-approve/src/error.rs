//! Error types for the `mecmcp-approve` CLI.

use thiserror::Error;

/// Everything that can go wrong running `mecmcp-approve`.
///
/// Every variant maps to a distinct, non-zero exit path. None of these ever
/// cause an approval to be sent anyway -- on any of these, the process exits
/// without calling the approve tool, per the fail-closed lens.
#[derive(Debug, Error)]
pub enum ApproveError {
    /// The OIDC discovery document could not be fetched from the issuer.
    #[error("failed to fetch OIDC discovery document from {issuer}: {source}")]
    Discovery {
        /// The issuer URL discovery was attempted against.
        issuer: String,
        /// The underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },

    /// The OIDC discovery document was fetched but is missing a required
    /// field, or the field is not a valid URL.
    #[error("OIDC discovery document from {issuer} is missing or has an invalid {field}")]
    DiscoveryField {
        /// The issuer URL discovery was fetched from.
        issuer: String,
        /// The name of the missing or invalid field.
        field: &'static str,
    },

    /// `--device-code` was passed but the issuer's discovery document has
    /// no `device_authorization_endpoint`.
    #[error(
        "device authorization is not supported by this issuer (no device_authorization_endpoint in discovery)"
    )]
    DeviceAuthUnsupported,

    /// The `oauth2` client could not be constructed from the discovery
    /// document or CLI arguments.
    #[error("failed to build the OIDC client: {0}")]
    OidcConfig(String),

    /// The loopback redirect listener could not bind its port.
    #[error("failed to start the loopback redirect listener: {0}")]
    LoopbackBind(#[source] std::io::Error),

    /// No redirect arrived on the loopback listener before the login
    /// timeout elapsed.
    #[error("timed out waiting for the OIDC redirect on the loopback listener")]
    LoopbackTimeout,

    /// The loopback listener accepted a connection but could not read the
    /// request line from it.
    #[error("failed to read the OIDC redirect request: {0}")]
    LoopbackRead(#[source] std::io::Error),

    /// The loopback redirect's request line was not a well-formed GET with
    /// both `code` and `state` present.
    #[error("the OIDC redirect did not include a valid callback (missing code or state)")]
    LoopbackMalformedCallback,

    /// The loopback redirect's `state` did not match the value this
    /// process generated for the authorization request.
    #[error("the OIDC redirect's state did not match the request we sent (possible CSRF)")]
    CsrfMismatch,

    /// The discovery document's `issuer` did not match the issuer URL this
    /// CLI was configured with (OIDC Discovery §4.3), or the loopback
    /// redirect's RFC 9207 `iss` parameter did not match the configured
    /// issuer. Either is a sign of an authorization-server mix-up attack.
    #[error("issuer mismatch: configured issuer is {configured}, but {origin} reported {reported}")]
    IssuerMismatch {
        /// The issuer URL this CLI was configured with (`--oidc-issuer`).
        configured: String,
        /// The issuer the discovery document or redirect actually reported.
        reported: String,
        /// Where the mismatched value came from.
        origin: &'static str,
    },

    /// The authorization server rejected the authorization-code exchange.
    #[error("the authorization server rejected the code exchange: {0}")]
    CodeExchange(String),

    /// The authorization server rejected the device-code exchange or poll.
    #[error("the authorization server rejected the device code exchange: {0}")]
    DeviceCodeExchange(String),

    /// The token response had no `id_token`, so there is nothing to send
    /// as the `Mecmcp-Approver-Assertion` header.
    #[error(
        "the token response did not include an id_token, so there is nothing to use as the Mecmcp-Approver-Assertion"
    )]
    MissingIdToken,

    /// Neither a static bearer token nor an OIDC login produced one.
    #[error("no bearer token available: pass --bearer-token-env or --bearer-token-file")]
    MissingBearerToken,

    /// The static bearer token could not be loaded from the environment
    /// variable or file the operator named.
    #[error("failed to load the bearer token: {0}")]
    BearerToken(#[source] mecmcp_secret::SecretError),

    /// `--expect-digest` was given and the preview tool's server-reported
    /// digest did not match it.
    #[error(
        "server-reported digest ({actual}) does not match --expect-digest ({expected}); refusing to approve"
    )]
    DigestMismatch {
        /// The digest the operator required via `--expect-digest`.
        expected: String,
        /// The digest the preview tool actually reported.
        actual: String,
    },

    /// The human declined (or failed to correctly type) the confirmation
    /// prompt.
    #[error("approval was not confirmed")]
    NotConfirmed,

    /// Reading the confirmation prompt's answer from stdin failed.
    #[error("failed to read confirmation from stdin: {0}")]
    ConfirmationRead(#[source] std::io::Error),

    /// A `--arg`/`--preview-arg` value was not in `KEY=VALUE` form.
    #[error("the --arg value {0:?} is not in KEY=VALUE form")]
    InvalidArg(String),

    /// Sending the `tools/call` HTTP request failed.
    #[error("failed to send the {tool} tools/call request: {source}")]
    ToolCallSend {
        /// The tool name the call was for.
        tool: String,
        /// The underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },

    /// Reading the `tools/call` response body failed.
    #[error("failed to read the {tool} tools/call response body: {source}")]
    ToolCallBody {
        /// The tool name the call was for.
        tool: String,
        /// The underlying HTTP error.
        #[source]
        source: reqwest::Error,
    },

    /// The `tools/call` response body was not valid JSON-RPC.
    #[error("the {tool} tools/call response was not a valid JSON-RPC response: {source}")]
    ToolCallDecode {
        /// The tool name the call was for.
        tool: String,
        /// The underlying JSON decode error.
        #[source]
        source: serde_json::Error,
    },

    /// The server returned a JSON-RPC error for the `tools/call` request.
    #[error("the server refused {tool}: {code} {message}")]
    ToolCallRpcError {
        /// The tool name the call was for.
        tool: String,
        /// The JSON-RPC error code.
        code: i64,
        /// The JSON-RPC error message.
        message: String,
    },

    /// The `tools/call` response had neither a `result` nor an `error`.
    #[error("the {tool} tools/call response had neither a result nor an error")]
    ToolCallMissingResult {
        /// The tool name the call was for.
        tool: String,
    },

    /// The tool itself reported an error via `CallToolResult::is_error`.
    #[error("{tool} reported a tool-level error: {content}")]
    ToolCallToolError {
        /// The tool name the call was for.
        tool: String,
        /// The tool result's rendered text content.
        content: String,
    },
}
