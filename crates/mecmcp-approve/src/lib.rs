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
mod scheme;
mod terminal;

use error::ApproveError;

/// Run one approval end to end: OIDC login, preview, confirm, approve.
///
/// # Errors
/// Returns the first [`ApproveError`] encountered. No approve call is made
/// on any error path -- every failure here, including a `NotConfirmed`
/// from the human declining, happens strictly before the approve request is
/// built.
pub async fn run(args: &cli::Args) -> Result<(), ApproveError> {
    // Every URL this process dereferences directly carries credentials in
    // flight (the bearer token, the approver assertion, the OIDC client
    // secret, the authorization code) -- check both before doing anything
    // else. Endpoints read back out of discovery get the same check inside
    // `oidc::discover`.
    scheme::require_secure("--server-url", &args.server_url, args.allow_insecure_http)?;
    scheme::require_secure("--oidc-issuer", &args.oidc_issuer, args.allow_insecure_http)?;

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
        client_secret: cli::resolve_client_secret(args)?,
        scopes: args.oidc_scopes_with_openid(),
        redirect_port: args.redirect_port,
        login_timeout: args.login_timeout(),
        max_age_secs: args.max_age_secs,
        allow_cached_login: args.allow_cached_login,
        allow_insecure_http: args.allow_insecure_http,
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

    // The server-reported digest, once read from a preview reply, binding
    // the preview the human saw to the approve call about to be made below
    // (see `preview::check_expected_digest_arg` right before that call).
    let mut server_digest: Option<String> = None;

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
        println!(
            "{}",
            terminal::terminal_safe(&mcp::render_text(&preview_result))
        );

        server_digest = mcp::structured_digest(&preview_result);
        if let Some(digest) = &server_digest {
            println!("server-reported digest: {digest}");
        }
        println!();
    }
    preview::check_expect_digest(args.expect_digest.as_deref(), server_digest.as_deref())?;

    let approve_args = cli::args_to_json(&args.args);
    preview::check_expected_digest_arg(&approve_args, server_digest.as_deref())?;

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

    println!("{}", terminal::terminal_safe(&mcp::render_text(&result)));
    Ok(())
}
