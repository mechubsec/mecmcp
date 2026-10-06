//! Command-line arguments for `mecmcp-approve`.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use serde_json::{Map, Value};

use crate::error::ApproveError;

/// Approve an mecmcp change set as a verified human, over a fresh OIDC
/// login -- see mecmcp#400 (MEC-996).
#[derive(Parser, Debug)]
#[command(name = "mecmcp-approve", version)]
pub struct Args {
    /// The MCP server's streamable-HTTP endpoint, e.g.
    /// `https://junos01.example:8443/mcp`.
    #[arg(long)]
    pub server_url: String,

    /// The approve tool's name (vendor-specific -- this workspace defines
    /// no shared tools/call registry, only the shared header and claims
    /// contract the approve tool's handler relies on).
    #[arg(long)]
    pub approve_tool: String,

    /// A tool to call first, unauthenticated by the approver assertion, so
    /// its reply can be shown as the change-set preview. Its
    /// `structured_content.digest`, when present, is compared against
    /// `--expect-digest`.
    #[arg(long)]
    pub preview_tool: Option<String>,

    /// Arguments for `--preview-tool`, as repeated `KEY=VALUE` pairs.
    #[arg(long = "preview-arg", value_parser = parse_kv)]
    pub preview_args: Vec<(String, String)>,

    /// Arguments for `--approve-tool`, as repeated `KEY=VALUE` pairs.
    #[arg(long = "arg", value_parser = parse_kv)]
    pub args: Vec<(String, String)>,

    /// Refuse to approve unless the preview tool's reported digest equals
    /// this value exactly.
    #[arg(long)]
    pub expect_digest: Option<String>,

    /// Environment variable holding the static bearer token. Mutually
    /// exclusive with `--bearer-token-file`; if neither is given, the
    /// OIDC login's own access token is used as the bearer token instead.
    #[arg(long)]
    pub bearer_token_env: Option<String>,

    /// File holding the static bearer token (hardened permissions
    /// required, see `mecmcp-secret`). Mutually exclusive with
    /// `--bearer-token-env`.
    #[arg(long)]
    pub bearer_token_file: Option<PathBuf>,

    /// The IdP's issuer URL (its discovery document is fetched from
    /// `<issuer>/.well-known/openid-configuration`).
    #[arg(long)]
    pub oidc_issuer: String,

    /// The OIDC client ID registered with the IdP for this CLI.
    #[arg(long)]
    pub oidc_client_id: String,

    /// The OIDC client secret, if the IdP requires one for a native/CLI
    /// client (most public clients do not).
    #[arg(long)]
    pub oidc_client_secret: Option<String>,

    /// OIDC scopes to request, in addition to `openid` (always requested).
    #[arg(long = "oidc-scope")]
    pub oidc_scopes: Vec<String>,

    /// Use the RFC 8628 device authorization grant instead of the default
    /// authorization-code + PKCE loopback flow. Opt-in only: never choose
    /// this automatically.
    #[arg(long)]
    pub device_code: bool,

    /// Loopback redirect port for the PKCE flow. `0` (the default) lets
    /// the OS assign one; set this only when the IdP requires a
    /// pre-registered fixed redirect URI.
    #[arg(long, default_value_t = 0)]
    pub redirect_port: u16,

    /// How long to wait for the human to complete the login before giving
    /// up, in seconds.
    #[arg(long, default_value_t = 300)]
    pub login_timeout_secs: u64,

    /// Skip the interactive confirmation prompt. The preview and digest are
    /// still printed first regardless.
    #[arg(long)]
    pub yes: bool,
}

impl Args {
    /// `--login-timeout-secs` as a [`Duration`].
    #[must_use]
    pub fn login_timeout(&self) -> Duration {
        Duration::from_secs(self.login_timeout_secs)
    }

    /// The scopes to request: `openid` plus every `--oidc-scope`.
    #[must_use]
    pub fn oidc_scopes_with_openid(&self) -> Vec<String> {
        let mut scopes = vec!["openid".to_owned()];
        scopes.extend(self.oidc_scopes.iter().cloned());
        scopes
    }
}

fn parse_kv(raw: &str) -> Result<(String, String), String> {
    raw.split_once('=')
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .ok_or_else(|| format!("expected KEY=VALUE, got {raw:?}"))
}

/// Turn `--arg`/`--preview-arg` pairs into a JSON object. Later duplicate
/// keys overwrite earlier ones (clap preserves the order given on the
/// command line), matching how most CLI flag parsers treat repeated keys.
#[must_use]
pub fn args_to_json(pairs: &[(String, String)]) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.clone(), Value::String(value.clone()));
    }
    map
}

/// Resolve the bearer token from exactly one of `--bearer-token-env` /
/// `--bearer-token-file`, or fall back to the OIDC access token.
pub fn resolve_static_bearer_token(args: &Args) -> Result<Option<String>, ApproveError> {
    match (&args.bearer_token_env, &args.bearer_token_file) {
        (Some(_), Some(_)) => Err(ApproveError::OidcConfig(
            "--bearer-token-env and --bearer-token-file are mutually exclusive".to_owned(),
        )),
        (Some(var), None) => {
            let secret = mecmcp_secret::load_from_env(var, mecmcp_secret::SecretLimits::default())
                .map_err(ApproveError::BearerToken)?;
            Ok(Some(secret.expose().to_owned()))
        }
        (None, Some(path)) => {
            let secret =
                mecmcp_secret::load_from_file(path, mecmcp_secret::SecretLimits::default())
                    .map_err(ApproveError::BearerToken)?;
            Ok(Some(secret.expose().to_owned()))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_kv() {
        assert_eq!(
            parse_kv("change_set_id=cs-1").unwrap(),
            ("change_set_id".to_owned(), "cs-1".to_owned())
        );
    }

    #[test]
    fn kv_value_may_contain_equals() {
        assert_eq!(
            parse_kv("note=a=b").unwrap(),
            ("note".to_owned(), "a=b".to_owned())
        );
    }

    #[test]
    fn rejects_kv_without_equals() {
        assert!(parse_kv("no-equals-here").is_err());
    }

    #[test]
    fn args_to_json_builds_object() {
        let pairs = vec![
            ("change_set_id".to_owned(), "cs-1".to_owned()),
            ("device".to_owned(), "srx01".to_owned()),
        ];
        let json = args_to_json(&pairs);
        assert_eq!(
            json.get("change_set_id").and_then(Value::as_str),
            Some("cs-1")
        );
        assert_eq!(json.get("device").and_then(Value::as_str), Some("srx01"));
    }

    #[test]
    fn oidc_scopes_always_include_openid() {
        let args = Args {
            server_url: String::new(),
            approve_tool: String::new(),
            preview_tool: None,
            preview_args: vec![],
            args: vec![],
            expect_digest: None,
            bearer_token_env: None,
            bearer_token_file: None,
            oidc_issuer: String::new(),
            oidc_client_id: String::new(),
            oidc_client_secret: None,
            oidc_scopes: vec!["offline_access".to_owned()],
            device_code: false,
            redirect_port: 0,
            login_timeout_secs: 300,
            yes: false,
        };
        assert_eq!(
            args.oidc_scopes_with_openid(),
            vec!["openid".to_owned(), "offline_access".to_owned()]
        );
    }
}
