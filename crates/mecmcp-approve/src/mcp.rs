//! Tool-call helpers on top of `mecmcp-client`: rendering a [`ToolOutput`]
//! for the approver and mapping [`ClientError`] onto [`ApproveError`] so the
//! messages the approver sees do not change.

use mecmcp_client::{ClientError, ToolOutput, UntrustedText};
use serde_json::Value;

use crate::error::ApproveError;

/// Map a failed `tools/call` onto the approver-facing error. The server's
/// RPC message and tool content stay escaped: `UntrustedText`'s `Display`
/// is the same escaping `terminal_safe` applies.
pub(crate) fn map_client_error(tool: &str, error: ClientError) -> ApproveError {
    let tool = tool.to_owned();
    match error {
        ClientError::Rpc { code, message } => ApproveError::ToolCallRpcError {
            tool,
            code,
            message: message.to_string(),
        },
        ClientError::Tool { content } => ApproveError::ToolCallToolError {
            tool,
            content: content.to_string(),
        },
        ClientError::Decode | ClientError::Protocol(_) => ApproveError::ToolCallDecode {
            tool,
            source: error,
        },
        _ => ApproveError::ToolCallSend {
            tool,
            source: error,
        },
    }
}

/// Render a [`ToolOutput`]'s text blocks for human display (not yet
/// escaped; print through `terminal_safe`). Non-text blocks arrive as fixed
/// markers, so the preview never looks more complete than it is.
pub fn render_text(output: &ToolOutput) -> String {
    output
        .text
        .iter()
        .map(UntrustedText::raw)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pull a top-level string field named `digest` out of a result's
/// structured content, when present. Used to read a server-reported
/// change-set digest out of a preview tool's reply.
#[must_use]
pub fn structured_digest(output: &ToolOutput) -> Option<String> {
    output
        .structured
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|obj| obj.get("digest"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}
