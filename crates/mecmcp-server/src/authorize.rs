//! Whether this caller may make this call.
//!
//! Four checks over a [`CallerCtx`], plus the two ways a handler gets at one:
//! [`caller_from_extensions`] to recover it from an HTTP request, and
//! [`audit_scope`] to describe the call for the audit log whether or not there
//! is a caller at all.
//!
//! ## The `None` caller is the stdio path, and it is authorized
//!
//! Every function here returns success for `caller: None`. That is not an
//! oversight and not a fallback: stdio has no bearer token because it has no
//! network, and the process on the other end already runs as whoever started it.
//! Scope enforcement is the HTTP boundary's job, and on that boundary a caller
//! is always present — [`mecmcp_transport`]'s bearer middleware rejects a
//! request before a handler sees it.
//!
//! The consequence to keep in mind: **calling these with `None` on an
//! authenticated path authorizes everything.** A handler must pass the caller it
//! recovered, not `None` on a lookup miss.
//!
//! [`mecmcp_transport`]: https://docs.rs/mecmcp-transport

use mecmcp_audit::AuditScope;
use mecmcp_auth::{CallerCtx, Grant};

/// A handler-level scope denial safe to return to an MCP caller.
///
/// Carries the token *name*, never the secret or its digest — a denial is a
/// message a caller reads, and the name is what makes it actionable for an
/// operator reading the same text in an audit log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    /// The caller's tool scope does not permit the requested tool.
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
    },
    /// The caller's target scope does not permit the requested target.
    #[error("token '{token}' is not authorized for the requested target (tool '{tool}')")]
    TargetNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
        /// Caller-supplied target, retained for structured handling.
        ///
        /// Deliberately absent from the `Display` text: the target is caller
        /// input, and echoing caller input into a message that reaches logs is
        /// how a log line gets forged. A handler that wants it has it here.
        target: String,
    },
}

/// Construct an audit scope for an authenticated caller or the stdio path.
///
/// The point of the helper is that the two cases produce the same shape, so an
/// audit record is comparable whether the call arrived over HTTP or stdio.
#[must_use]
pub fn audit_scope<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &'static str,
    action: &'static str,
    targets: Vec<String>,
) -> AuditScope {
    match caller {
        Some(caller) => AuditScope::from_caller(caller, tool, action, targets),
        None => AuditScope::stdio(tool, action, targets),
    }
}

/// Require the caller's tool scope to permit `tool`.
///
/// `write_tools` is the server's own registry of mutating tools, and it is a
/// parameter because only the server knows it. It is load-bearing: a wildcard
/// tool scope permits everything **except** the names in this list, so passing
/// an empty slice silently turns every wildcard token into a writer.
///
/// # Errors
/// [`AuthorizationError::ToolNotInScope`] if the scope does not permit `tool`.
pub fn authorize_tool<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.tools.allows_tool(tool, write_tools) {
        return Ok(());
    }
    Err(AuthorizationError::ToolNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
    })
}

/// Require the caller's target scope to permit `target`, without inventory
/// lookup.
///
/// No lookup on purpose. This answers "is this name inside the caller's scope",
/// which is a question about the token; whether the name exists is a question
/// about the inventory and belongs to whatever resolves it. Merging the two
/// would make an out-of-scope target and an unknown one indistinguishable to
/// the caller, which tells an unauthorized caller which names are real.
///
/// # Errors
/// [`AuthorizationError::TargetNotInScope`] if the scope does not permit
/// `target`.
pub fn authorize_target<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: &str,
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.devices.allows(target) {
        return Ok(());
    }
    Err(AuthorizationError::TargetNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
        target: target.to_owned(),
    })
}

/// Check tool scope, then an optional target scope.
///
/// Tool first, and the order matters for what a caller learns. A token with no
/// right to `apply_change_set` is told exactly that, rather than being told
/// which targets it may not touch — the narrower failure is the one that leaks
/// less.
///
/// # Errors
/// The first failing check's [`AuthorizationError`].
pub fn authorize_call<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: Option<&str>,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    authorize_tool(caller, tool, write_tools)?;
    if let Some(target) = target {
        authorize_target(caller, tool, target)?;
    }
    Ok(())
}

/// Recover the authenticated caller from nested HTTP request parts.
///
/// Two levels deep because that is where it is: the MCP layer carries the
/// `http::request::Parts` in its own extensions, and the bearer middleware put
/// the caller in *those*. Reading only the outer map finds nothing and — given
/// the `None`-authorizes rule above — would authorize every call.
#[must_use]
pub fn caller_from_extensions<G: Grant>(
    extensions: &rmcp::model::Extensions,
) -> Option<&CallerCtx<G>> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<CallerCtx<G>>())
}

/// Filter tools down to the exact set the caller may invoke.
///
/// A tool the caller cannot call should not appear in `tools/list`. Listing it
/// invites a call that will be refused, and tells an unauthorized caller what
/// the server can do.
#[must_use]
pub fn filter_tools_for_scope<G: Grant>(
    tools: Vec<rmcp::model::Tool>,
    caller: Option<&CallerCtx<G>>,
    write_tools: &[&str],
) -> Vec<rmcp::model::Tool> {
    let Some(caller) = caller else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| caller.tools.allows_tool(tool.name.as_ref(), write_tools))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_auth::{ActorType, NoGrant, ScopeSet};

    /// A server's mutating tools. `authorize_tool` cannot know these, which is
    /// exactly why they are a parameter.
    const WRITE_TOOLS: &[&str] = &["apply_change_set", "commit_candidate"];

    fn caller(devices: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "reader".to_owned(),
            devices,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    fn allow(names: &[&str]) -> ScopeSet {
        ScopeSet::Allowlist(names.iter().map(|name| (*name).to_owned()).collect())
    }

    /// The property the whole write-tool registry exists for: a wildcard tool
    /// scope is *not* "everything". It withholds the server's mutating tools,
    /// so a broadly scoped reader cannot apply a change set.
    #[test]
    fn a_wildcard_tool_scope_still_excludes_the_write_tools() {
        let caller = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);

        assert!(authorize_call(Some(&caller), "get_config", Some("fw-01"), WRITE_TOOLS).is_ok());
        assert!(matches!(
            authorize_call(
                Some(&caller),
                "apply_change_set",
                Some("fw-01"),
                WRITE_TOOLS
            ),
            Err(AuthorizationError::ToolNotInScope { .. })
        ));
    }

    /// Passing an empty registry turns every wildcard token into a writer. The
    /// parameter is load-bearing, and this is the test that says so.
    #[test]
    fn an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool() {
        let caller = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        assert!(
            authorize_tool(Some(&caller), "apply_change_set", &[]).is_ok(),
            "documents the hazard: an empty registry is not a safe default"
        );
    }

    /// An explicit allowlist can name a write tool — that is how a writer is
    /// granted one, and the reason a `Wildcard -> Allowlist` change on a tool
    /// scope is an escalation rather than a narrowing.
    #[test]
    fn an_allowlist_may_name_a_write_tool() {
        let caller = caller(ScopeSet::Wildcard, allow(&["apply_change_set"]));
        assert!(authorize_tool(Some(&caller), "apply_change_set", WRITE_TOOLS).is_ok());
        assert!(matches!(
            authorize_tool(Some(&caller), "get_config", WRITE_TOOLS),
            Err(AuthorizationError::ToolNotInScope { .. })
        ));
    }

    #[test]
    fn a_target_outside_the_device_scope_is_refused() {
        let caller = caller(allow(&["fw-01"]), ScopeSet::Wildcard);
        assert!(authorize_call(Some(&caller), "get_config", Some("fw-01"), WRITE_TOOLS).is_ok());

        let error =
            authorize_call(Some(&caller), "get_config", Some("fw-02"), WRITE_TOOLS).unwrap_err();
        assert!(matches!(error, AuthorizationError::TargetNotInScope { .. }));
    }

    /// Tool first. A token with no right to the tool is told that, rather than
    /// being told which targets it may not touch — the narrower failure leaks
    /// less about the inventory.
    #[test]
    fn the_tool_check_runs_before_the_target_check() {
        let caller = caller(allow(&["fw-01"]), allow(&["get_config"]));
        let error = authorize_call(
            Some(&caller),
            "apply_change_set",
            Some("fw-99"),
            WRITE_TOOLS,
        )
        .unwrap_err();
        assert!(
            matches!(error, AuthorizationError::ToolNotInScope { .. }),
            "both checks fail; the tool one must be the one reported: {error:?}"
        );
    }

    /// The target is caller input, so it stays out of the `Display` text that
    /// reaches logs and is available structurally instead.
    #[test]
    fn a_denial_names_the_token_but_never_echoes_the_target() {
        let caller = caller(allow(&["fw-01"]), ScopeSet::Wildcard);
        let error =
            authorize_target(Some(&caller), "get_config", "fw-02\nforged log line").unwrap_err();

        let rendered = error.to_string();
        assert!(rendered.contains("reader"), "got {rendered}");
        assert!(
            !rendered.contains("forged log line"),
            "caller input must not reach the message: {rendered}"
        );
        let AuthorizationError::TargetNotInScope { target, .. } = &error else {
            panic!("wrong variant: {error:?}");
        };
        assert_eq!(target, "fw-02\nforged log line");
    }

    /// The nesting is the whole function, and getting it wrong is the worst
    /// failure in this module: `caller_from_extensions` returning `None` on an
    /// authenticated path means every check below authorizes the call.
    ///
    /// The caller lives two levels deep — the MCP layer carries
    /// `http::request::Parts`, and the bearer middleware put the caller in
    /// *those* extensions, not the outer ones.
    #[test]
    fn the_caller_is_recovered_from_the_nested_request_parts() {
        let expected = caller(allow(&["fw-01"]), ScopeSet::Wildcard);

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.extensions.insert(expected.clone());
        let mut extensions = rmcp::model::Extensions::new();
        extensions.insert(parts);

        let found = caller_from_extensions::<NoGrant>(&extensions)
            .expect("the caller must be found through the nested parts");
        assert_eq!(found.token_name, "reader");
        assert_eq!(found.devices, expected.devices);
    }

    /// A caller placed in the outer map is *not* found. That is not a quirk to
    /// paper over: the bearer middleware puts it in the request parts, so
    /// accepting the outer position would mean accepting one nobody
    /// authenticated.
    #[test]
    fn a_caller_in_the_outer_map_alone_is_not_recovered() {
        let mut extensions = rmcp::model::Extensions::new();
        extensions.insert(caller(allow(&["fw-01"]), ScopeSet::Wildcard));

        assert!(
            caller_from_extensions::<NoGrant>(&extensions).is_none(),
            "only the middleware's position counts"
        );
    }

    #[test]
    fn an_unauthenticated_request_yields_no_caller() {
        let (parts, ()) = http::Request::new(()).into_parts();
        let mut extensions = rmcp::model::Extensions::new();
        extensions.insert(parts);

        assert!(caller_from_extensions::<NoGrant>(&extensions).is_none());
    }

    /// The stdio path. Documented as authorized, so it is tested as authorized
    /// — and the hazard that goes with it is stated in the module docs.
    #[test]
    fn a_none_caller_is_authorized_for_everything() {
        assert!(
            authorize_call::<NoGrant>(None, "apply_change_set", Some("fw-99"), WRITE_TOOLS).is_ok()
        );
        assert!(authorize_tool::<NoGrant>(None, "apply_change_set", WRITE_TOOLS).is_ok());
        assert!(authorize_target::<NoGrant>(None, "get_config", "fw-99").is_ok());
    }

    #[test]
    fn tool_listing_hides_what_the_caller_cannot_call() {
        fn tool(name: &'static str) -> rmcp::model::Tool {
            rmcp::model::Tool::new(name, "", std::sync::Arc::new(serde_json::Map::new()))
        }
        let tools = vec![tool("get_config"), tool("apply_change_set")];

        let reader = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
        let visible = filter_tools_for_scope(tools.clone(), Some(&reader), WRITE_TOOLS);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name.as_ref(), "get_config");

        // stdio sees everything, consistent with the `None` rule above.
        let all = filter_tools_for_scope::<NoGrant>(tools, None, WRITE_TOOLS);
        assert_eq!(all.len(), 2);
    }
}
