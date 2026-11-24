//! `McpClient`: connect, call tools, close.

use std::error::Error as StdError;

use mecmcp_secret::OutboundSecret;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ClientCapabilities, ContentBlock, Implementation,
    MetaObject, ProtocolVersion, RequestMetaObject,
};
use rmcp::service::{ClientInitializeError, ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransportConfig, StreamableHttpError,
};
use rmcp::{ClientHandler, RoleClient, ServiceError};
use serde_json::{Map, Value};

use crate::http::{AssertionClient, CALL_SLOT_KEY, build_reqwest_client};
use crate::{ClientConfig, ClientError, ProtocolMode, UntrustedText};

/// The result of a tool call.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// The tool's `structuredContent`, if any.
    pub structured: Option<Value>,
    /// Text content blocks. Non-text blocks appear as fixed markers such as
    /// `[image content omitted]`, so a preview never looks more complete than it is.
    pub text: Vec<UntrustedText>,
    /// Whether the server flagged the result `isError`.
    pub is_error: bool,
}

impl ToolOutput {
    /// Turn an `isError` result into [`ClientError::Tool`].
    ///
    /// # Errors
    /// [`ClientError::Tool`] when `is_error` is set.
    pub fn into_result(self) -> Result<Self, ClientError> {
        if !self.is_error {
            return Ok(self);
        }
        let joined = self
            .text
            .iter()
            .map(UntrustedText::raw)
            .collect::<Vec<_>>()
            .join("\n");
        Err(ClientError::Tool {
            content: UntrustedText::new(joined),
        })
    }
}

#[derive(Clone)]
struct Identity(rmcp::model::ClientConfig);

impl ClientHandler for Identity {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        self.0.clone()
    }
}

/// A connected MCP client.
///
/// Size limits: `max_response_bytes` bounds each SSE event (rmcp's
/// `max_sse_event_size`). A plain `application/json` body is bounded by rmcp's
/// own fixed 16 MiB, which is why `ClientConfig::validate` rejects a larger
/// setting. Both are enforced while the body streams in, and the per-call
/// `request_timeout` bounds a stream that never ends.
pub struct McpClient {
    service: RunningService<RoleClient, Identity>,
    http: AssertionClient,
    config: ClientConfig,
}

impl McpClient {
    /// Connect and negotiate the protocol.
    ///
    /// `Auto` speaks stateless 2026-07-28 and falls back to `initialize` plus a
    /// session; `Stateless2026` never falls back; `Legacy` always initializes.
    ///
    /// # Errors
    /// [`ClientError::Config`] if `config.validate()` fails, [`ClientError::Tls`]
    /// if no rustls provider is installed or `ca_pem` is bad, otherwise the
    /// mapped transport error.
    pub async fn connect(config: ClientConfig) -> Result<Self, ClientError> {
        config.validate()?;
        let http = AssertionClient::new(build_reqwest_client(&config)?);
        let mut transport_config =
            StreamableHttpClientTransportConfig::with_uri(config.url.as_str().to_owned());
        transport_config.auth_header = Some(config.token.expose().to_owned());
        transport_config.max_sse_event_size = config.max_response_bytes;
        let transport = StreamableHttpClientTransport::with_client(http.clone(), transport_config);

        let modern = vec![ProtocolVersion::V_2026_07_28];
        let (version, lifecycle) = match config.protocol {
            ProtocolMode::Auto => (
                ProtocolVersion::V_2026_07_28,
                ClientLifecycleMode::Auto {
                    preferred_versions: modern,
                    legacy_version: Some(ProtocolVersion::V_2025_11_25),
                },
            ),
            ProtocolMode::Stateless2026 => (
                ProtocolVersion::V_2026_07_28,
                ClientLifecycleMode::Discover {
                    preferred_versions: modern,
                },
            ),
            ProtocolMode::Legacy => (
                ProtocolVersion::V_2025_11_25,
                ClientLifecycleMode::Initialize,
            ),
        };
        let identity = Identity(
            rmcp::model::ClientConfig::new(
                ClientCapabilities::default(),
                Implementation::new(config.client_name.clone(), config.client_version.clone()),
            )
            .with_protocol_version(version),
        );
        // Auto waits on a server that ignores `server/discover`; bound the whole handshake.
        let handshake = identity.serve_with_lifecycle(transport, lifecycle);
        let service = match tokio::time::timeout(config.request_timeout, handshake).await {
            Err(_) => {
                return Err(ClientError::Timeout {
                    operation: "connect".to_owned(),
                });
            }
            Ok(Err(error)) => return Err(map_initialize(&error)),
            Ok(Ok(service)) => service,
        };
        Ok(Self {
            service,
            http,
            config,
        })
    }

    /// Call a tool. An `isError` result is `Ok` with `is_error` set; see
    /// [`ToolOutput::into_result`].
    ///
    /// # Errors
    /// [`ClientError::Timeout`] after `request_timeout`, [`ClientError::Rpc`]
    /// for a JSON-RPC error, [`ClientError::Http`], [`ClientError::ResponseTooLarge`]
    /// and the other transport failures.
    pub async fn call_tool(
        &self,
        name: &str,
        args: Map<String, Value>,
    ) -> Result<ToolOutput, ClientError> {
        self.call(name, args, None).await
    }

    /// [`call_tool`](Self::call_tool) with `Mecmcp-Approver-Assertion: <assertion>`
    /// on this one request. The header is never sent for any other call, nor for
    /// `initialize`, `server/discover` or `tools/list`.
    ///
    /// # Errors
    /// As [`call_tool`](Self::call_tool), plus [`ClientError::Config`] when the
    /// assertion is not a valid header value.
    pub async fn call_tool_with_assertion(
        &self,
        name: &str,
        args: Map<String, Value>,
        assertion: &OutboundSecret,
    ) -> Result<ToolOutput, ClientError> {
        self.call(name, args, Some(assertion)).await
    }

    /// Close the session (sends `DELETE` for a legacy session).
    pub async fn close(self) {
        let _ = self.service.cancel().await;
    }

    async fn call(
        &self,
        name: &str,
        args: Map<String, Value>,
        assertion: Option<&OutboundSecret>,
    ) -> Result<ToolOutput, ClientError> {
        let operation = format!("tools/call {name}");
        let slot = self.http.register(assertion)?;
        let mut meta = MetaObject::new();
        meta.0.insert(
            CALL_SLOT_KEY.to_owned(),
            Value::String(slot.id().to_owned()),
        );
        let mut params = CallToolRequestParams::new(name.to_owned());
        params.arguments = Some(args);
        params.meta = Some(RequestMetaObject(meta));
        let pending = self.service.call_tool_once(params);
        let outcome = match tokio::time::timeout(self.config.request_timeout, pending).await {
            Err(_) => return Err(ClientError::Timeout { operation }),
            Ok(outcome) => outcome,
        };
        match outcome {
            Ok(CallToolResponse::Complete(result)) => Ok(tool_output(result)),
            Ok(_) => Err(ClientError::Protocol(
                "unsupported tools/call result type".to_owned(),
            )),
            Err(error) => Err(map_service(
                &error,
                &operation,
                self.config.max_response_bytes,
                slot.saw_oversize(),
            )),
        }
    }
}

fn tool_output(result: rmcp::model::CallToolResult) -> ToolOutput {
    let text = result
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::Text(text) => UntrustedText::new(text.text.clone()),
            ContentBlock::Image(_) => UntrustedText::new("[image content omitted]"),
            ContentBlock::Audio(_) => UntrustedText::new("[audio content omitted]"),
            ContentBlock::Resource(_) => UntrustedText::new("[embedded resource omitted]"),
            ContentBlock::ResourceLink(_) => UntrustedText::new("[resource link omitted]"),
            _ => UntrustedText::new("[unrecognized content block omitted]"),
        })
        .collect();
    ToolOutput {
        structured: result.structured_content,
        text,
        is_error: result.is_error == Some(true),
    }
}

fn rpc_error(error: &rmcp::model::ErrorData) -> ClientError {
    ClientError::Rpc {
        code: i64::from(error.code.0),
        message: UntrustedText::new(error.message.to_string()),
    }
}

fn map_service(
    error: &ServiceError,
    operation: &str,
    limit: usize,
    oversize_seen: bool,
) -> ClientError {
    match error {
        ServiceError::McpError(data) => rpc_error(data),
        ServiceError::Timeout { .. } => ClientError::Timeout {
            operation: operation.to_owned(),
        },
        ServiceError::TransportSend(dynamic) => map_transport(dynamic.error.as_ref(), limit),
        // rmcp reports an oversize SSE event as a bare closed transport; the
        // wrapper saw the size error go by, so say what it was.
        ServiceError::TransportClosed if oversize_seen => ClientError::ResponseTooLarge { limit },
        ServiceError::TransportClosed | ServiceError::Cancelled { .. } => ClientError::Closed,
        _ => ClientError::Protocol("unexpected response from server".to_owned()),
    }
}

fn map_initialize(error: &ClientInitializeError) -> ClientError {
    match error {
        ClientInitializeError::TransportError { error, .. } => {
            map_transport(error.error.as_ref(), usize::MAX)
        }
        ClientInitializeError::JsonRpcError(data) => rpc_error(data),
        ClientInitializeError::LegacyFallbackFailed { fallback, .. } => map_initialize(fallback),
        ClientInitializeError::ConnectionClosed(_) | ClientInitializeError::Cancelled => {
            ClientError::Closed
        }
        ClientInitializeError::NoCompatibleProtocolVersion { .. } => {
            ClientError::Protocol("no compatible protocol version".to_owned())
        }
        _ => ClientError::Protocol("MCP handshake failed".to_owned()),
    }
}

fn map_transport(error: &(dyn StdError + 'static), limit: usize) -> ClientError {
    let Some(error) = error.downcast_ref::<StreamableHttpError<reqwest::Error>>() else {
        return ClientError::Protocol("transport failure".to_owned());
    };
    match error {
        StreamableHttpError::Client(inner) if inner.is_timeout() => ClientError::Timeout {
            operation: "http request".to_owned(),
        },
        StreamableHttpError::Client(inner) if inner.is_connect() => ClientError::Connect,
        StreamableHttpError::Client(_) => ClientError::Protocol("HTTP client failure".to_owned()),
        StreamableHttpError::HttpStatus(status) => ClientError::Http {
            status: status.status,
        },
        StreamableHttpError::AuthRequired(_) => ClientError::Http { status: 401 },
        StreamableHttpError::InsufficientScope(_) => ClientError::Http { status: 403 },
        StreamableHttpError::SessionExpired => ClientError::Http { status: 404 },
        StreamableHttpError::ResponseBodyTooLarge { max_size } => ClientError::ResponseTooLarge {
            limit: limit.min(*max_size),
        },
        // rmcp formats non-success statuses as "HTTP <code> <reason>: <body>".
        // Only the code is taken: the body is server-controlled text.
        StreamableHttpError::UnexpectedServerResponse(message) => message
            .strip_prefix("HTTP ")
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse().ok())
            .map_or_else(
                || ClientError::Protocol("unexpected server response".to_owned()),
                |status| ClientError::Http { status },
            ),
        StreamableHttpError::UnexpectedEndOfStream
        | StreamableHttpError::TransportChannelClosed => ClientError::Closed,
        StreamableHttpError::Deserialize(_) | StreamableHttpError::UnexpectedContentType(_) => {
            ClientError::Decode
        }
        _ => ClientError::Protocol("transport failure".to_owned()),
    }
}
