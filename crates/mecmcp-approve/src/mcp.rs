//! A minimal MCP streamable-HTTP `tools/call`, typed against `rmcp::model`
//! but sent as a single, non-streaming POST.
//!
//! This workspace's crates ship no client transport of their own
//! (`mecmcp-server` depends on `rmcp::model` only, by design -- see its
//! Cargo.toml). Pulling in `rmcp`'s full `transport-streamable-http-client`
//! feature (SSE parsing, a worker task, session resumption) would be a lot
//! of machinery for a CLI that makes exactly one call and exits; a direct
//! POST with the two headers this flow cares about is the whole transport
//! contract this binary actually needs. `rmcp::model`'s `CallToolResult`
//! still does the response parsing, so the shape matches a real server's
//! reply exactly rather than a hand-rolled guess at the schema.

use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::ApproveError;

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: &'a CallToolRequestParams,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<CallToolResult>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

/// One `tools/call`, with an optional step-up assertion header.
///
/// `assertion` is `None` for a plain preview/read call (the preview tool
/// does not need step-up) and `Some` only for the call that actually
/// approves -- see `main.rs`. This mirrors the server's own header
/// contract: the header is additive and only consulted at approval time.
pub async fn call_tool(
    http: &reqwest::Client,
    server_url: &str,
    bearer_token: &str,
    assertion: Option<&str>,
    tool: &str,
    arguments: Map<String, Value>,
) -> Result<CallToolResult, ApproveError> {
    let params = CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments);
    let body = JsonRpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: &params,
    };

    let mut request = http
        .post(server_url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .bearer_auth(bearer_token);
    if let Some(assertion) = assertion {
        request = request.header(mecmcp_transport::APPROVER_ASSERTION_HEADER, assertion);
    }

    let response =
        request
            .json(&body)
            .send()
            .await
            .map_err(|source| ApproveError::ToolCallSend {
                tool: tool.to_owned(),
                source,
            })?;

    let bytes = response
        .bytes()
        .await
        .map_err(|source| ApproveError::ToolCallBody {
            tool: tool.to_owned(),
            source,
        })?;

    let parsed: JsonRpcResponse =
        serde_json::from_slice(&bytes).map_err(|source| ApproveError::ToolCallDecode {
            tool: tool.to_owned(),
            source,
        })?;

    if let Some(error) = parsed.error {
        return Err(ApproveError::ToolCallRpcError {
            tool: tool.to_owned(),
            code: error.code,
            message: error.message,
        });
    }

    let result = parsed
        .result
        .ok_or_else(|| ApproveError::ToolCallMissingResult {
            tool: tool.to_owned(),
        })?;

    if result.is_error == Some(true) {
        return Err(ApproveError::ToolCallToolError {
            tool: tool.to_owned(),
            content: render_text(&result),
        });
    }

    Ok(result)
}

/// Render a [`CallToolResult`]'s text content blocks for human display.
/// Non-text blocks are summarized by kind rather than dropped silently, so
/// the preview never looks more complete than it is.
pub fn render_text(result: &CallToolResult) -> String {
    use rmcp::model::ContentBlock;

    result
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::Text(text) => text.text.clone(),
            ContentBlock::Image(_) => "[image content omitted]".to_owned(),
            ContentBlock::Audio(_) => "[audio content omitted]".to_owned(),
            ContentBlock::Resource(_) => "[embedded resource omitted]".to_owned(),
            ContentBlock::ResourceLink(_) => "[resource link omitted]".to_owned(),
            _ => "[unrecognized content block omitted]".to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pull a top-level string field named `digest` out of a result's
/// `structured_content`, when present. Used to read a server-reported
/// change-set digest out of a preview tool's reply.
#[must_use]
pub fn structured_digest(result: &CallToolResult) -> Option<String> {
    result
        .structured_content
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("digest"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
