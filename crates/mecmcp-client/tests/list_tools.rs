//! `list_tools` pagination bounds and typed `call_tool_as`, against a raw TLS stub.
#![allow(clippy::unwrap_used)] // tests

mod support;

use std::sync::Arc;
use std::time::Duration;

use mecmcp_client::{ClientError, McpClient};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use support::{Handler, Reply, Seen, config_for, modern_handler, result_for, spawn};

fn tool(name: &str) -> Value {
    json!({"name": name, "inputSchema": {"type": "object"}})
}

async fn client_for(handler: Handler, pages: usize) -> (support::Stub, McpClient) {
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_tool_pages = pages;
    let client = McpClient::connect(config).await.unwrap();
    (stub, client)
}

fn page_reply(request_id: &Value, result: Value) -> Reply {
    Reply::Json(json!({"jsonrpc":"2.0","id":request_id,"result":result}))
}

/// A stub that numbers its pages: cursor `pN` -> page N, last page `last`.
fn numbered(last: usize) -> Handler {
    Arc::new(move |request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        let index = request.body["params"]["cursor"]
            .as_str()
            .and_then(|c| c.strip_prefix('p'))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);
        let mut result = json!({"tools": [tool(&format!("t{index}"))]});
        if index < last {
            result["nextCursor"] = json!(format!("p{}", index + 1));
        }
        Reply::Json(result_for(request, result))
    })
}

#[tokio::test]
async fn follows_cursors_to_the_end() {
    let (stub, client) = client_for(numbered(2), 32).await;
    let tools = client.list_tools().await.unwrap();
    let names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names, ["t0", "t1", "t2"]);
    let lists: Vec<_> = stub
        .requests()
        .into_iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .collect();
    assert_eq!(lists.len(), 3);
    // the private slot marker must not leave the process
    assert!(
        lists
            .iter()
            .all(|r| !r.body.to_string().contains("call-slot"))
    );
}

#[tokio::test]
async fn stops_at_max_tool_pages_with_protocol_error() {
    // fresh cursor every page: only the page bound can stop this server
    let (stub, client) = client_for(numbered(usize::MAX), 5).await;
    let outcome = tokio::time::timeout(Duration::from_secs(5), client.list_tools())
        .await
        .expect("page bound must stop the loop");
    match outcome {
        Err(ClientError::Protocol(message)) => {
            assert_eq!(message, "tools/list cursor loop exceeded 5 pages");
        }
        other => panic!("got {other:?}"),
    }
    let pages = stub
        .requests()
        .iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .count();
    assert_eq!(pages, 5);
}

#[tokio::test]
async fn repeated_cursor_is_rejected_immediately() {
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        page_reply(
            &request.body["id"],
            json!({"tools": [tool("t")], "nextCursor": "same"}),
        )
    });
    let (stub, client) = client_for(handler, 32).await;
    let outcome = tokio::time::timeout(Duration::from_secs(5), client.list_tools())
        .await
        .expect("a repeated cursor must stop the loop");
    assert!(
        matches!(&outcome, Err(ClientError::Protocol(m)) if m.contains("repeated a cursor")),
        "got {outcome:?}"
    );
    let pages = stub
        .requests()
        .iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .count();
    assert_eq!(
        pages, 2,
        "first page, then the page that repeated the cursor"
    );
}

#[tokio::test]
async fn tolerates_ttl_and_cache_scope_and_never_caches() {
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        page_reply(
            &request.body["id"],
            json!({"tools": [tool("a")], "ttlMs": 60000, "cacheScope": "public"}),
        )
    });
    let (stub, client) = client_for(handler, 32).await;
    assert_eq!(client.list_tools().await.unwrap().len(), 1);
    assert_eq!(client.list_tools().await.unwrap().len(), 1);
    let lists = stub
        .requests()
        .iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .count();
    assert_eq!(lists, 2, "ttlMs must not turn into a client-side cache");
}

#[tokio::test]
async fn legacy_reply_without_them() {
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        page_reply(
            &request.body["id"],
            json!({"tools": [tool("a"), tool("b")]}),
        )
    });
    let (_stub, client) = client_for(handler, 32).await;
    assert_eq!(client.list_tools().await.unwrap().len(), 2);
}

#[tokio::test]
async fn list_tools_total_bytes_capped() {
    // page 1 fits, page 2 is one 2 MiB SSE event against a 1 MiB cap
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        match request.body["params"]["cursor"].as_str() {
            None => page_reply(
                &request.body["id"],
                json!({"tools": [tool("a")], "nextCursor": "p1"}),
            ),
            Some(_) => Reply::Sse(result_for(
                request,
                json!({"tools": [{"name": "big", "description": "x".repeat(2 * 1024 * 1024),
                    "inputSchema": {"type": "object"}}]}),
            )),
        }
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_response_bytes = 1024 * 1024;
    let client = McpClient::connect(config).await.unwrap();
    let outcome = client.list_tools().await;
    assert!(
        matches!(
            outcome,
            Err(ClientError::ResponseTooLarge { limit: 1_048_576 })
        ),
        "got {outcome:?}"
    );
}

#[derive(Deserialize, Debug, PartialEq)]
struct Echo {
    echo: String,
}

fn call_handler(result: Value) -> Handler {
    Arc::new(move |request: &Seen| {
        if request.rpc_method() != "tools/call" {
            return modern_handler(false)(request);
        }
        Reply::Json(result_for(request, result.clone()))
    })
}

#[tokio::test]
async fn call_tool_as_decodes_structured_content() {
    let (_stub, client) = client_for(modern_handler(false), 32).await;
    let echo: Echo = client.call_tool_as("echo", Map::new()).await.unwrap();
    assert_eq!(echo, Echo { echo: "hi".into() });
}

#[tokio::test]
async fn call_tool_as_tool_error_is_err_tool_with_escaped_content() {
    let result = json!({"content":[{"type":"text","text":"bad \u{1b}[31mred"}],
        "structuredContent":{"echo":"ignored"},"isError":true});
    let (_stub, client) = client_for(call_handler(result), 32).await;
    let error = client
        .call_tool_as::<Echo>("echo", Map::new())
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Tool { .. }), "got {error:?}");
    let shown = error.to_string();
    assert!(
        !shown.contains('\u{1b}'),
        "raw escape reached Display: {shown:?}"
    );
    assert!(shown.contains("bad"));
}

#[tokio::test]
async fn call_tool_as_missing_structured_is_decode_error() {
    let result = json!({"content":[{"type":"text","text":"hi"}],"isError":false});
    let (_stub, client) = client_for(call_handler(result), 32).await;
    let error = client
        .call_tool_as::<Echo>("echo", Map::new())
        .await
        .unwrap_err();
    assert!(matches!(error, ClientError::Decode), "got {error:?}");
}

#[tokio::test]
async fn cumulative_tool_bytes_over_the_cap_is_response_too_large() {
    // each page is ~400 KB of JSON (under the 1 MiB cap); three exceed it
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        let index = request.body["params"]["cursor"]
            .as_str()
            .and_then(|c| c.strip_prefix('p'))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);
        let mut big = tool(&format!("t{index}"));
        big["description"] = json!("x".repeat(400_000));
        Reply::Json(result_for(
            request,
            json!({"tools": [big], "nextCursor": format!("p{}", index + 1)}),
        ))
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_response_bytes = 1024 * 1024;
    let client = McpClient::connect(config).await.unwrap();
    let outcome = client.list_tools().await;
    assert!(
        matches!(
            outcome,
            Err(ClientError::ResponseTooLarge { limit: 1_048_576 })
        ),
        "{outcome:?}"
    );
    let pages = stub
        .requests()
        .iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .count();
    assert_eq!(pages, 3, "must stop at the page that crosses the cap");
}

#[tokio::test]
async fn large_cursors_count_toward_the_budget() {
    // empty pages, each with a distinct ~400 KB cursor: only the cursors add up
    let handler: Handler = Arc::new(|request: &Seen| {
        if request.rpc_method() != "tools/list" {
            return modern_handler(false)(request);
        }
        let index = request.body["params"]["cursor"]
            .as_str()
            .map_or(0, |c| c.len() % 7 + c.matches('p').count());
        let cursor = format!("p{index}{}", "c".repeat(400_000));
        Reply::Json(result_for(
            request,
            json!({"tools": [], "nextCursor": cursor}),
        ))
    });
    let stub = spawn(handler).await;
    let mut config = config_for(&stub.url(), &stub.cert_pem);
    config.max_response_bytes = 1024 * 1024;
    let client = McpClient::connect(config).await.unwrap();
    let outcome = client.list_tools().await;
    assert!(
        matches!(
            outcome,
            Err(ClientError::ResponseTooLarge { limit: 1_048_576 })
        ),
        "{outcome:?}"
    );
    let pages = stub
        .requests()
        .iter()
        .filter(|r| r.rpc_method() == "tools/list")
        .count();
    assert_eq!(pages, 3);
}
