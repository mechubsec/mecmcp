//! `mecmcp-approve`: an approver CLI that does a fresh OIDC login (PKCE by
//! default, device code opt-in) and then a reviewed MCP `tools/call`
//! carrying both the caller's bearer token and the login's `id_token` as
//! the `Mecmcp-Approver-Assertion` header.
//!
//! See `crates/mecmcp-transport/src/approver_assertion.rs` for what the
//! server verifies, and `oidc.rs` for why the assertion is simply the OIDC
//! login's own ID token rather than something this crate signs itself.

pub mod cli;
pub mod error;
mod http_bridge;
mod loopback;
mod mcp;
mod oidc;
pub mod preview;

use error::ApproveError;

/// Run one approval end to end: OIDC login, preview, confirm, approve.
///
/// # Errors
/// Returns the first [`ApproveError`] encountered. No approve call is made
/// on any error path -- every failure here, including a `NotConfirmed`
/// from the human declining, happens strictly before the approve request is
/// built.
pub async fn run(args: &cli::Args) -> Result<(), ApproveError> {
    // Installed once, process-wide, before any `reqwest::Client` is built --
    // the same requirement `mecmcp-http::HttpClient::new` documents (D4).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|source| ApproveError::Discovery {
            issuer: args.oidc_issuer.clone(),
            source,
        })?;

    let login_config = oidc::LoginConfig {
        issuer: args.oidc_issuer.clone(),
        client_id: args.oidc_client_id.clone(),
        client_secret: args.oidc_client_secret.clone(),
        scopes: args.oidc_scopes_with_openid(),
        redirect_port: args.redirect_port,
        login_timeout: args.login_timeout(),
    };

    let login = if args.device_code {
        oidc::login_device_code(&http, &login_config).await?
    } else {
        oidc::login_pkce(&http, &login_config).await?
    };

    let bearer_token = match cli::resolve_static_bearer_token(args)? {
        Some(token) => token,
        None => login.access_token.clone(),
    };

    if let Some(preview_tool) = &args.preview_tool {
        let preview_args = cli::args_to_json(&args.preview_args);
        let preview_result = mcp::call_tool(
            &http,
            &args.server_url,
            &bearer_token,
            None,
            preview_tool,
            preview_args,
        )
        .await?;

        println!("--- {preview_tool} ---");
        println!("{}", mcp::render_text(&preview_result));

        if let Some(server_digest) = mcp::structured_digest(&preview_result) {
            println!("server-reported digest: {server_digest}");
            if let Some(expected) = &args.expect_digest
                && expected != &server_digest
            {
                return Err(ApproveError::DigestMismatch {
                    expected: expected.clone(),
                    actual: server_digest,
                });
            }
        }
        println!();
    }

    let approve_args = cli::args_to_json(&args.args);
    let request_digest = preview::request_digest(&args.approve_tool, &approve_args);
    preview::print_preview(&args.approve_tool, &approve_args, &request_digest);
    preview::confirm(args.yes)?;

    let result = mcp::call_tool(
        &http,
        &args.server_url,
        &bearer_token,
        Some(&login.id_token),
        &args.approve_tool,
        approve_args,
    )
    .await?;

    println!("{}", mcp::render_text(&result));
    Ok(())
}
