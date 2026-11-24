//! Transport behaviour against a raw TLS stub (header capture, hostile servers)
//! and against a real `mecmcp-transport` server (round trips).
#![allow(clippy::unwrap_used)] // tests

mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use mecmcp_client::{ClientError, McpClient, ProtocolMode};
use mecmcp_secret::OutboundSecret;
use serde_json::{Map, Value, json};
use support::{
    Reply, Seen, TOKEN, config_for, echo_result, modern_handler, non_rpc, result_for, spawn,
};

fn args(pairs: Value) -> Map<String, Value> {
    pairs.as_object().cloned().unwrap_or_default()
}

fn assertion(value: &str) -> OutboundSecret {
    OutboundSecret::new_unchecked(value.to_owned())
}

#[tokio::test]
async fn stateless_call_sends_required_headers_and_meta() {
    let stub = spawn(modern_handler(false)).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    client
        .call_tool("echo", args(json!({"a": 1})))
        .await
        .unwrap();
    let calls = stub.calls();
    let call = calls.first().expect("a tools/call reached the server");
    assert_eq!(call.header("mcp-protocol-version"), Some("2026-07-28"));
    assert_eq!(call.header("mcp-method"), Some("tools/call"));
    assert_eq!(call.header("mcp-name"), Some("echo"));
    assert_eq!(
        call.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert!(call.header("mcp-session-id").is_none());
    let meta = &call.body["params"]["_meta"];
    for key in [
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/clientCapabilities",
    ] {
        assert!(meta.get(key).is_some(), "missing _meta key {key}");
    }
    assert!(
        stub.requests()
            .iter()
            .all(|r| r.header("mcp-session-id").is_none())
    );
}

#[tokio::test]
async fn legacy_server_gets_initialize_and_session_id() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if let Some(reply) = non_rpc(request) {
            return reply;
        }
        match request.rpc_method() {
            "server/discover" => Reply::Json(
                json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32601,"message":"Method not found"}}),
            ),
            "initialize" => Reply::JsonWith(
                "mcp-session-id: sess-legacy-1".to_owned(),
                result_for(
                    request,
                    json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"stub","version":"0"}}),
                ),
            ),
            _ => Reply::Json(result_for(request, echo_result("hi"))),
        }
    });
    let stub = spawn(handler).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    client.call_tool("echo", Map::new()).await.unwrap();
    client.call_tool("echo", Map::new()).await.unwrap();
    client.close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let requests = stub.requests();
    assert!(requests.iter().any(|r| r.rpc_method() == "initialize"));
    let calls = stub.calls();
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|c| c.header("mcp-session-id") == Some("sess-legacy-1"))
    );
    assert!(
        requests.iter().any(|r| r.method == "DELETE"),
        "close() must DELETE the session"
    );
}

#[tokio::test]
async fn sse_response_is_parsed() {
    let stub = spawn(modern_handler(true)).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let output = client.call_tool("echo", Map::new()).await.unwrap();
    assert_eq!(output.text[0].raw(), "hi");
    assert_eq!(output.structured, Some(json!({"echo":"hi"})));
    assert!(!output.is_error);
}

#[tokio::test]
async fn plain_json_response_is_parsed() {
    let stub = spawn(modern_handler(false)).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let output = client.call_tool("echo", Map::new()).await.unwrap();
    assert_eq!(output.text[0].raw(), "hi");
}

#[tokio::test]
async fn non_text_content_becomes_fixed_markers_and_error_flag_is_kept() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if let Some(reply) = non_rpc(request) {
            return reply;
        }
        match request.rpc_method() {
            "tools/call" => Reply::Json(result_for(
                request,
                json!({
                "content":[{"type":"image","data":"AAAA","mimeType":"image/png"},{"type":"text","text":"bad"}],
                "isError":true}),
            )),
            _ => modern_handler(false)(request),
        }
    });
    let stub = spawn(handler).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let output = client.call_tool("echo", Map::new()).await.unwrap();
    assert!(output.is_error);
    let shown: Vec<&str> = output.text.iter().map(|t| t.raw()).collect();
    assert_eq!(shown, ["[image content omitted]", "bad"]);
    assert!(matches!(
        output.into_result(),
        Err(ClientError::Tool { .. })
    ));
}

#[tokio::test]
async fn response_over_cap_is_rejected_while_streaming() {
    const TOTAL_CHUNKS: usize = 1024; // 64 MiB offered, cap is 1 MiB
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() == "tools/call" {
            return Reply::Flood {
                chunks: TOTAL_CHUNKS,
            };
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_response_bytes = 1024 * 1024;
    let client = McpClient::connect(config).await.unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::ResponseTooLarge { limit: 1_048_576 }),
        "got {error:?}"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    // 1 MiB cap: the server must have been cut off close to it, not at rmcp's default.
    let written = stub.flooded.load(Ordering::Relaxed);
    assert!(
        written < 4 * 1024 * 1024,
        "server wrote {written} bytes: the cap did not close the connection"
    );
    // the client survives for a later call (the stub floods again, so the same error)
    let again = client.call_tool("echo", Map::new()).await;
    assert!(
        matches!(again, Err(ClientError::ResponseTooLarge { .. })),
        "{again:?}"
    );
}

#[tokio::test]
async fn slow_server_times_out_per_call() {
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let handler: support::Handler = Arc::new(move |request: &Seen| {
        if request.rpc_method() == "tools/call" && first.swap(false, Ordering::SeqCst) {
            return Reply::Delayed(
                Duration::from_secs(2),
                Box::new(Reply::Json(result_for(request, echo_result("late")))),
            );
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.request_timeout = Duration::from_millis(200);
    let client = McpClient::connect(config).await.unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(&error, ClientError::Timeout { operation } if operation == "tools/call echo"),
        "got {error:?}"
    );
    assert_eq!(
        client.call_tool("echo", Map::new()).await.unwrap().text[0].raw(),
        "hi"
    );
}

#[tokio::test]
async fn zeroed_timeout_is_rejected_at_connect() {
    let stub = spawn(modern_handler(false)).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.request_timeout = Duration::ZERO;
    let result = McpClient::connect(config).await;
    assert!(matches!(
        result,
        Err(ClientError::Config {
            field: "request_timeout"
        })
    ));
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn http_401_maps_to_http_error_without_token_in_message() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() == "tools/call" {
            return Reply::Status(
                401,
                vec![("www-authenticate", "Bearer realm=\"x\"".to_owned())],
            );
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Http { status: 401 }),
        "got {error:?}"
    );
    assert!(!format!("{error} {error:?}").contains(TOKEN));
}

#[tokio::test]
async fn host_mismatch_421_is_reported_as_http_421() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() == "tools/call" {
            return Reply::Status(421, vec![]);
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Http { status: 421 }),
        "got {error:?}"
    );
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let (cert_pem, server_config) = support::tls_material();
    let other = support::spawn_with(
        modern_handler(false),
        cert_pem.clone(),
        server_config.clone(),
    )
    .await;
    let location = other.url();
    let handler: support::Handler = Arc::new(move |request: &Seen| {
        if request.rpc_method() == "tools/call" {
            return Reply::Status(302, vec![("location", location.clone())]);
        }
        modern_handler(false)(request)
    });
    let stub = support::spawn_with(handler, cert_pem.clone(), server_config).await;
    let client = McpClient::connect(config_for(&stub.url(), &cert_pem))
        .await
        .unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Http { status: 302 }),
        "got {error:?}"
    );
    assert!(
        other.requests().is_empty(),
        "the redirect target received a request"
    );
}

#[tokio::test]
async fn assertion_header_only_on_the_assertion_call() {
    let stub = spawn(modern_handler(false)).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    client
        .call_tool_with_assertion("approve", Map::new(), &assertion("fake-assertion-jwt"))
        .await
        .unwrap(); // gitleaks:allow
    client.call_tool("echo", Map::new()).await.unwrap();
    let requests = stub.requests();
    let with_header: Vec<&str> = requests
        .iter()
        .filter(|r| r.header("mecmcp-approver-assertion").is_some())
        .map(Seen::rpc_method)
        .collect();
    assert_eq!(
        with_header,
        ["tools/call"],
        "only the assertion call carries the header"
    );
    let calls = stub.calls();
    assert_eq!(
        calls[0].header("mecmcp-approver-assertion"),
        Some("fake-assertion-jwt")
    ); // gitleaks:allow
    assert!(calls[1].header("mecmcp-approver-assertion").is_none());
    let wire = serde_json::to_string(&calls[0].body).unwrap();
    assert!(
        !wire.contains("assertion-slot"),
        "slot marker leaked onto the wire: {wire}"
    );
}

#[tokio::test]
async fn concurrent_plain_call_never_gets_the_assertion() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        // Hold the assertion call open so plain calls overlap it.
        if request.rpc_method() == "tools/call"
            && request.body["params"]["arguments"]["who"] == "assert"
        {
            return Reply::Delayed(
                Duration::from_millis(300),
                Box::new(Reply::Json(result_for(request, echo_result("a")))),
            );
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let client = Arc::new(
        McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
            .await
            .unwrap(),
    );
    let secret = assertion("fake-assertion-jwt"); // gitleaks:allow
    let asserted = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .call_tool_with_assertion("echo", args(json!({"who":"assert"})), &secret)
                .await
                .unwrap();
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut plain = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        plain.push(tokio::spawn(async move {
            client
                .call_tool("echo", args(json!({"who":"plain"})))
                .await
                .unwrap()
        }));
    }
    for handle in plain {
        handle.await.unwrap();
    }
    asserted.await.unwrap();
    let calls = stub.calls();
    assert_eq!(calls.len(), 9);
    for call in calls {
        let carries = call.header("mecmcp-approver-assertion").is_some();
        let is_assert = call.body["params"]["arguments"]["who"] == "assert";
        assert_eq!(
            carries, is_assert,
            "assertion misattributed: {:?}",
            call.body
        );
    }
}

#[tokio::test]
async fn rpc_error_message_is_escaped() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() == "tools/call" {
            return Reply::Json(
                json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32000,"message":"\u{1b}[2Kboom"}}),
            );
        }
        modern_handler(false)(request)
    });
    let stub = spawn(handler).await;
    let client = McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
        .await
        .unwrap();
    let error = client.call_tool("echo", Map::new()).await.unwrap_err();
    assert!(
        matches!(error, ClientError::Rpc { code: -32000, .. }),
        "got {error:?}"
    );
    let shown = format!("{error} {error:?}");
    assert!(
        !shown.contains('\u{1b}'),
        "raw ESC reached a Display/Debug string"
    );
    assert!(shown.contains("boom"));
}

#[tokio::test]
async fn concurrent_calls_use_distinct_jsonrpc_ids() {
    let stub = spawn(modern_handler(false)).await;
    let client = Arc::new(
        McpClient::connect(config_for(&stub.url(), &stub.cert_pem))
            .await
            .unwrap(),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            client.call_tool("echo", Map::new()).await.unwrap()
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    let mut ids: Vec<String> = stub
        .calls()
        .iter()
        .map(|c| c.body["id"].to_string())
        .collect();
    assert_eq!(ids.len(), 8);
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8, "JSON-RPC ids collided");
}

#[tokio::test]
async fn stateless_mode_never_falls_back_to_initialize() {
    let handler: support::Handler = Arc::new(|request: &Seen| {
        if let Some(reply) = non_rpc(request) {
            return reply;
        }
        match request.rpc_method() {
            "server/discover" => Reply::Json(
                json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32601,"message":"Method not found"}}),
            ),
            "initialize" => Reply::JsonWith(
                "mcp-session-id: sess-legacy-1".to_owned(),
                result_for(
                    request,
                    json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"stub","version":"0"}}),
                ),
            ),
            _ => Reply::Json(result_for(request, echo_result("hi"))),
        }
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.protocol = ProtocolMode::Stateless2026;
    assert!(
        McpClient::connect(config).await.is_err(),
        "a legacy-only server must be refused"
    );
    assert!(
        stub.requests()
            .iter()
            .all(|r| r.rpc_method() != "initialize"),
        "Stateless2026 fell back to initialize"
    );
}

#[tokio::test]
async fn concurrent_oversize_and_rpc_error_keep_their_own_errors() {
    let handler: support::Handler = Arc::new(|request: &Seen| match request.body["params"]["name"]
        .as_str()
    {
        Some("big") => Reply::Flood { chunks: 1024 },
        Some("boom") => Reply::Delayed(
            Duration::from_millis(100),
            Box::new(Reply::Json(
                json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-32000,"message":"boom"}}),
            )),
        ),
        _ => modern_handler(false)(request),
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_response_bytes = 1024 * 1024;
    let client = McpClient::connect(config).await.unwrap();
    let (big, boom) = tokio::join!(
        client.call_tool("big", Map::new()),
        client.call_tool("boom", Map::new())
    );
    assert!(
        matches!(big, Err(ClientError::ResponseTooLarge { .. })),
        "{big:?}"
    );
    assert!(
        matches!(boom, Err(ClientError::Rpc { code: -32000, .. })),
        "{boom:?}"
    );
}
