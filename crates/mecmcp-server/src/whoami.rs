//! The built-in `whoami` tool (mecmcp#580): a token holder reads its own expiry, so an
//! unattended client learns of an expiring token before the 401.

use crate::{OutputRedaction, ResultFormat, ResultLimits, tool_error, tool_result};
use mecmcp_auth::{CallerCtx, Grant};

/// Tool description for a server's `#[tool(name = "whoami", description = WHOAMI_DESCRIPTION)]`.
pub const WHOAMI_DESCRIPTION: &str = "Returns the calling token's own name, auth type \
(`static` or `oauth`), actor type, and for a static token its `created_at` and `expires_at` \
(RFC 3339; `null` means it never expires). Touches no device; available to every token \
regardless of tool scope; never returns scopes, digests, or other tokens.";

/// Report the calling token's own metadata.
///
/// A server wires it with a `#[tool(name = "whoami", description =
/// mecmcp_server::WHOAMI_DESCRIPTION)]` method returning
/// `mecmcp_server::whoami(caller.as_ref())`, and adds `"whoami"` to its tool registry list.
///
/// A `None` caller (stdio) has no bearer token and gets a tool error. An OAuth caller gets
/// no `created_at`/`expires_at` keys at all.
#[must_use]
pub fn whoami<G: Grant>(caller: Option<&CallerCtx<G>>) -> rmcp::model::CallToolResult {
    let Some(caller) = caller else {
        return tool_error("whoami reports the calling bearer token; a stdio call has none");
    };
    let value = if caller.oauth.is_some() {
        // The access token's own `exp` is the expiry and the client already holds it; a
        // `null` here would read as "never expires".
        serde_json::json!({
            "name": caller.token_name,
            "auth": "oauth",
            "actor_type": caller.actor_type,
        })
    } else {
        serde_json::json!({
            "name": caller.token_name,
            "auth": "static",
            "actor_type": caller.actor_type,
            "created_at": caller.token_created_at,
            "expires_at": caller.token_expires_at,
        })
    };
    tool_result(
        Ok::<_, std::convert::Infallible>(value),
        ResultFormat::PrettyJson,
        ResultLimits {
            max_text_bytes: 4096,
            max_json_bytes: 4096,
        },
        OutputRedaction::Apply,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use mecmcp_auth::{ActorType, NoGrant, OidcSubject, ScopeSet};

    fn instant(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn caller(devices: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "reader".to_owned(),
            devices,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            verified_proposer: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
            oauth: None,
            token_created_at: Some(instant(1_783_850_400)),
            token_expires_at: Some(instant(1_783_936_800)),
        }
    }

    fn text_of(result: &rmcp::model::CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.clone()))
            .collect()
    }

    fn json_of(result: &rmcp::model::CallToolResult) -> serde_json::Value {
        serde_json::from_str(&text_of(result)).unwrap()
    }

    #[test]
    fn stdio_has_no_token_to_report() {
        let result = whoami::<NoGrant>(None);
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn a_static_token_reports_its_instants() {
        let ctx = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        let result = whoami(Some(&ctx));
        let json = json_of(&result);
        assert_eq!(json["auth"], "static");
        assert_eq!(json["name"], "reader");
        assert_eq!(
            json["expires_at"],
            instant(1_783_936_800).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
        assert_eq!(
            json["created_at"],
            instant(1_783_850_400).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        );
    }

    #[test]
    fn a_never_expiring_token_reports_null_expiry() {
        let mut ctx = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        ctx.token_expires_at = None;
        let json = json_of(&whoami(Some(&ctx)));
        assert!(json.as_object().unwrap().contains_key("expires_at"));
        assert!(json["expires_at"].is_null());
    }

    #[test]
    fn an_oauth_caller_reports_no_instants() {
        let mut ctx = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        ctx.oauth = Some(mecmcp_auth::OAuthIdentity {
            issuer: "https://idp.example.com".to_owned(),
            subject: "alice".to_owned(),
            client_id: None,
        });
        ctx.token_created_at = None;
        ctx.token_expires_at = None;
        let json = json_of(&whoami(Some(&ctx)));
        assert_eq!(json["auth"], "oauth");
        assert!(!json.as_object().unwrap().contains_key("created_at"));
        assert!(!json.as_object().unwrap().contains_key("expires_at"));
    }

    #[test]
    fn scopes_and_identity_details_never_leak() {
        let names = |name: &str| ScopeSet::Allowlist(vec![name.to_owned()]);
        let mut ctx = caller(names("secret-device"), names("secret-tool"));
        ctx.on_behalf_of = Some("secret-principal".to_owned());
        ctx.oidc_subject = Some(OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: "secret-subject".to_owned(),
        });
        let text = text_of(&whoami(Some(&ctx)));
        for secret in [
            "secret-device",
            "secret-tool",
            "secret-principal",
            "secret-subject",
        ] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }
}
