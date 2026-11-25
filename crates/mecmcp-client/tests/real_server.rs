//! Round trips against a real `mecmcp-transport` server over TLS.
#![allow(clippy::unwrap_used)] // tests

mod support;

use std::sync::Arc;

use mecmcp_auth::NoGrant;
use mecmcp_client::{McpClient, ProtocolMode};
use mecmcp_transport::test_harness::{ServedPlan, serve_on_loopback_tls};
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, NoAuthAcknowledgement, TransportIdentity,
    build_streamable_http_router,
};
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::Map;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct EchoServer;

impl ServerHandler for EchoServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test-server", "0.1"))
    }
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = serde_json::json!({"type":"object"});
        let tool = Tool::new(
            "echo",
            "echo",
            Arc::new(schema.as_object().unwrap().clone()),
        );
        let mut result = ListToolsResult::with_all_items(vec![tool]);
        if context
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28)
        {
            result = result.with_ttl_ms(0).with_cache_scope(CacheScope::Private);
        }
        Ok(result)
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let text = format!("{} @ {:?}", request.name, context.protocol_version());
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into())
    }
}

async fn serve() -> (String, String, CancellationToken) {
    let (cert_pem, tls) = support::tls_material();
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );
    let plan =
        build_streamable_http_router(|| Ok::<_, std::io::Error>(EchoServer), config).unwrap();
    let ServedPlan { address, .. } = serve_on_loopback_tls(plan, tls).await;
    (
        format!("https://localhost:{}/mcp", address.port()),
        cert_pem,
        shutdown,
    )
}

async fn echo_text(mode: ProtocolMode) -> String {
    let (url, cert_pem, shutdown) = serve().await;
    let mut config = support::config_for(&url, &cert_pem);
    config.protocol = mode;
    let client = McpClient::connect(config).await.unwrap();
    let output = client.call_tool("echo", Map::new()).await.unwrap();
    client.close().await;
    shutdown.cancel();
    output.text[0].raw().to_owned()
}

#[tokio::test]
async fn real_server_speaks_stateless_2026_by_default() {
    assert!(echo_text(ProtocolMode::Auto).await.contains("2026-07-28"));
    assert!(
        echo_text(ProtocolMode::Stateless2026)
            .await
            .contains("2026-07-28")
    );
}

#[tokio::test]
async fn real_server_legacy_mode_negotiates_an_older_session() {
    let text = echo_text(ProtocolMode::Legacy).await;
    assert!(text.contains("2025-11-25"), "got {text}");
}
