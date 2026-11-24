//! The approve flow on top of `mecmcp-client`: one client, the assertion only
//! on the approve call, and the pre-migration `ApproveError` strings.
#![allow(clippy::unwrap_used)] // tests

// The client crate's raw TLS stub, shared rather than copied.
#[path = "../../mecmcp-client/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use clap::Parser;
use mecmcp_approve::cli::Args;
use mecmcp_approve::error::ApproveError;
use serde_json::{Value, json};
use support::{Handler, Reply, Seen, config_for, echo_result, modern_handler, non_rpc, result_for};

const ID_TOKEN: &str = "fake-id-token-for-tests"; // gitleaks:allow

fn args(url: &str, with_preview: bool) -> Args {
    let mut argv = vec![
        "mecmcp-approve",
        "--server-url",
        url,
        "--approve-tool",
        "approve",
        "--oidc-issuer",
        "https://idp.example",
        "--oidc-client-id",
        "client",
        "--yes",
    ];
    if with_preview {
        argv.extend(["--preview-tool", "preview"]);
    }
    Args::try_parse_from(argv).unwrap()
}

/// A stateless server whose `tools/call` answers with `reply`.
fn calls_reply(reply: fn(&Seen) -> Value) -> Handler {
    let modern = modern_handler(false);
    Arc::new(move |request: &Seen| {
        if non_rpc(request).is_none() && request.rpc_method() == "tools/call" {
            return Reply::Json(reply(request));
        }
        modern(request)
    })
}

async fn approve_error(reply: fn(&Seen) -> Value) -> String {
    let stub = support::spawn(calls_reply(reply)).await;
    let config = config_for(&stub.url(), &stub.cert_pem);
    let err = mecmcp_approve::review_and_approve(&args(&stub.url(), false), config, ID_TOKEN)
        .await
        .unwrap_err();
    err.to_string()
}

#[tokio::test]
async fn approve_flow_uses_one_client_and_assertion_only_on_approve() {
    let stub = support::spawn(modern_handler(false)).await;
    let config = config_for(&stub.url(), &stub.cert_pem);
    mecmcp_approve::review_and_approve(&args(&stub.url(), true), config, ID_TOKEN)
        .await
        .unwrap();

    let requests = stub.requests();
    let discovers = requests
        .iter()
        .filter(|r| r.rpc_method() == "server/discover")
        .count();
    assert_eq!(discovers, 1, "one McpClient per run");

    let calls = stub.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].body["params"]["name"], "preview");
    assert_eq!(calls[1].body["params"]["name"], "approve");
    assert!(calls[0].header("mecmcp-approver-assertion").is_none());
    assert_eq!(calls[1].header("mecmcp-approver-assertion"), Some(ID_TOKEN));
}

#[test]
fn approver_assertion_header_matches_transport_const() {
    assert_eq!(
        mecmcp_client::APPROVER_ASSERTION_HEADER,
        mecmcp_transport::APPROVER_ASSERTION_HEADER
    );
}

#[tokio::test]
async fn terminal_escape_regression() {
    let rendered = approve_error(|request| {
        json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-1,"message":"\u{1b}[2Kclobbered"}})
    })
    .await;
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains("clobbered"));
}

#[tokio::test]
async fn rpc_error_display_unchanged() {
    let rendered = approve_error(|request| {
        json!({"jsonrpc":"2.0","id":request.body["id"],"error":{"code":-1,"message":"\u{1b}[2Kclobbered"}})
    })
    .await;
    assert_eq!(
        rendered,
        r"the server refused approve: -1 \u{1b}[2Kclobbered"
    );
}

#[tokio::test]
async fn tool_error_display_unchanged() {
    let rendered = approve_error(|request| {
        let mut result = echo_result("boom \u{1b}[2K");
        result["isError"] = json!(true);
        result_for(request, result)
    })
    .await;
    assert_eq!(
        rendered,
        r"approve reported a tool-level error: boom \u{1b}[2K"
    );
}

#[test]
fn http_server_url_is_refused_naming_the_field() {
    let token = mecmcp_client::BearerToken::from_secret(
        mecmcp_secret::OutboundSecret::new_unchecked("t".to_owned()),
    );
    let err = mecmcp_approve::client_config("http://127.0.0.1:1/mcp", token).unwrap_err();
    assert!(matches!(err, ApproveError::McpClient(_)));
    assert_eq!(
        err.to_string(),
        "MCP client: invalid client configuration: url"
    );
}
