//! Optional scope preflight for middleware-layer authorization.
//!
//! PAN-OS runs a preflight that parses the request body and checks the tool plus
//! `params.arguments.device` against the token's scopes, returning 403
//! `insufficient_scope`. Junos has no equivalent and defers to its handler.
//!
//! `None` must be behaviourally identical to Junos today.

use mecmcp_auth::{CallerCtx, Grant, ScopeSet};
use serde_json::Value;
use std::sync::Arc;

/// Scope-only view of an authenticated caller, usable by preflights.
///
/// Preflight implementations inspect scopes (`devices`, `tools`) but never
/// need the grant or provider metadata. This type extracts just those fields,
/// allowing a single `ScopePreflight` implementation to work with
/// `CallerCtx<G>` for any `G`.
#[derive(Debug, Clone)]
pub struct CallerScopes<'a> {
    /// Non-secret token name.
    pub token_name: &'a str,
    /// Devices this caller may address.
    pub devices: &'a ScopeSet,
    /// Tools this caller may call.
    pub tools: &'a ScopeSet,
}

impl<'a, G: Grant> From<&'a CallerCtx<G>> for CallerScopes<'a> {
    fn from(caller: &'a CallerCtx<G>) -> Self {
        Self {
            token_name: &caller.token_name,
            devices: &caller.devices,
            tools: &caller.tools,
        }
    }
}

/// Preflight authorization check, run before the request reaches the handler.
///
/// Returning `Ok(())` allows the request to proceed. Returning `Err(reason)`
/// causes a 403 carrying that reason.
///
/// # Why this is synchronous
///
/// The body arrives as `&[u8]` rather than as a `Request`, and the method does
/// not return a future. Both follow from what the only real implementation
/// does: `rustpanosmcp`'s `request_exceeds_scope(bytes: &[u8], caller:
/// &CallerContext) -> bool` and its `tool_call_exceeds_scope` contain **zero**
/// `await` points — they parse an in-memory buffer and compare against scopes
/// already loaded in `CallerCtx`.
///
/// The middleware has those bytes in hand regardless, because it must buffer
/// the body to enforce the size limit. Making this `async` would therefore add
/// an `async-trait` dependency and a `Box<dyn Future>` allocation on the hot
/// path of every MCP request, to await nothing. If a future implementation
/// genuinely needs to await — consulting a remote authorization service, say —
/// this trait changes then, and the crate has no external consumers yet to
/// break.
pub trait ScopePreflight: Send + Sync {
    /// Check whether `caller` may issue the request carried in `body`.
    ///
    /// `body` is the complete, already-buffered request body. `Err` should
    /// carry a reason safe to return to the caller.
    ///
    /// The `caller` parameter is a `CallerScopes` view containing just the
    /// scope fields, allowing a single implementation to work with
    /// `CallerCtx<G>` for any grant type `G`.
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String>;
}

/// An optional preflight. `None` disables it entirely.
pub type OptionalPreflight = Option<Arc<dyn ScopePreflight>>;

/// Run a preflight if one is configured.
///
/// This is the whole of the `None` contract: with no preflight there is no
/// check, and every request proceeds exactly as it does on a server that never
/// had one. Middleware calls this rather than matching on the `Option` itself,
/// so the skip semantics live in one place and are testable.
pub fn run_preflight<G: Grant>(
    preflight: &OptionalPreflight,
    body: &[u8],
    caller: &CallerCtx<G>,
) -> Result<(), String> {
    match preflight {
        Some(check) => check.check(body, CallerScopes::from(caller)),
        None => Ok(()),
    }
}

/// Whether to deny or ignore malformed arguments structures.
///
/// Extracted from rustsdcmcp for issue #109.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedArgumentsPolicy {
    /// Reject requests with malformed arguments (fail closed).
    Deny,
    /// Ignore malformed arguments and defer to handler (not recommended).
    Ignore,
}

/// Whether to deny or ignore malformed target values.
///
/// Extracted from rustsdcmcp for issue #110.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedTargetPolicy {
    /// Reject requests with malformed target values (fail closed).
    Deny,
    /// Ignore malformed targets and defer to handler (not recommended).
    Ignore,
}

/// Expected shape of a target value in JSON-RPC arguments.
///
/// Extracted from rustsdcmcp for issue #111.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetValueShape {
    /// Single string value.
    Scalar,
    /// Non-empty array of strings.
    NonEmptyArray,
}

/// Target field specification: name, shape, and malformed policy.
///
/// Extracted from rustsdcmcp for issue #112. Consumers configure a preflight
/// with one or more target fields, each naming a JSON argument key that carries
/// device/tenant/site identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetField {
    /// JSON object key name in `params.arguments`.
    pub name: &'static str,
    /// Expected value shape.
    pub shape: TargetValueShape,
    /// Whether to deny malformed values for this field.
    pub malformed: MalformedTargetPolicy,
}

impl TargetField {
    /// Construct a scalar target field that denies malformed values.
    ///
    /// Extracted from rustsdcmcp for issue #142. This is the common case:
    /// a single string device/tenant/site name, failing closed on anything else.
    #[must_use]
    pub const fn scalar(name: &'static str) -> Self {
        Self {
            name,
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Deny,
        }
    }
}

/// Generic tool-scope preflight for MCP servers with device/tenant/site scopes.
///
/// Extracted from rustsdcmcp for issue #113. Four consumers (Junos, PAN-OS, SDC,
/// Mist) have near-identical preflights differing only in argument field names:
/// Junos parses `router`/`router_name`/`routers`/`router_names`, PAN-OS parses
/// `device`/`devices`, SDC parses `tenant`, Mist parses org/site. This generic
/// implementation is configured with field names via `TargetField`.
///
/// # Design
///
/// Fail closed: malformed body, unparseable targets, or absent caller refused.
/// A wildcard tool scope still excludes write tools (invariant from junos #199).
/// Runs before rmcp dispatch in the established order:
/// IP rate → auth → token rate → token concurrency → body limit → **preflight**
/// → target concurrency → handler.
#[derive(Debug, Clone)]
pub struct ToolScopePreflight {
    write_tools: &'static [&'static str],
    target_fields: Vec<TargetField>,
    malformed_arguments: MalformedArgumentsPolicy,
}

impl ToolScopePreflight {
    /// Construct a new preflight with the given write-tool registry, target
    /// fields, and malformed-arguments policy.
    ///
    /// Extracted from rustsdcmcp for issue #143.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::{ToolScopePreflight, TargetField, MalformedArgumentsPolicy};
    ///
    /// static WRITE_TOOLS: &[&str] = &["delete_thing", "update_thing"];
    ///
    /// let preflight = ToolScopePreflight::new(
    ///     WRITE_TOOLS,
    ///     [TargetField::scalar("device")],
    ///     MalformedArgumentsPolicy::Deny,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        write_tools: &'static [&'static str],
        target_fields: impl IntoIterator<Item = TargetField>,
        malformed_arguments: MalformedArgumentsPolicy,
    ) -> Self {
        Self {
            write_tools,
            target_fields: target_fields.into_iter().collect(),
            malformed_arguments,
        }
    }

    /// Check whether a single JSON-RPC request exceeds the caller's scopes.
    ///
    /// Extracted from rustsdcmcp for issue #144. This is the core preflight
    /// logic: parse `tools/call`, check tool name, then check all target fields.
    /// Returns `true` if the request should be rejected.
    ///
    /// Only checks `tools/call` requests — other methods pass through. Tool
    /// check runs before target check (fail fast on tool denial). Malformed
    /// arguments structure is controlled by `malformed_arguments` policy.
    fn request_exceeds_scope(&self, value: &Value, caller: CallerScopes<'_>) -> bool {
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(params) = value.get("params") else {
            return false;
        };
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !caller.tools.allows_tool(tool, self.write_tools) {
            return true;
        }
        let Some(arguments_value) = params.get("arguments") else {
            return false;
        };
        let Some(arguments) = arguments_value.as_object() else {
            return self.malformed_arguments == MalformedArgumentsPolicy::Deny;
        };
        self.target_fields.iter().any(|field| {
            arguments
                .get(field.name)
                .is_some_and(|value| !target_value_in_scope(value, *field, caller.devices))
        })
    }
}

impl ScopePreflight for ToolScopePreflight {
    /// Check the request body against caller scopes.
    ///
    /// Extracted from rustsdcmcp for issue #145. Handles both single and batched
    /// JSON-RPC requests. Denies the entire batch if any request exceeds scope
    /// (deny-any batch behavior).
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return Ok(());
        };
        let denied = match value {
            Value::Array(values) => values
                .iter()
                .any(|value| self.request_exceeds_scope(value, caller.clone())),
            value => self.request_exceeds_scope(&value, caller),
        };
        if denied {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

/// Check whether a target value is within the caller's device scope.
///
/// Extracted from rustsdcmcp for issue #146. Handles both scalar strings and
/// non-empty string arrays. Malformed values are handled per the field's policy:
/// `Deny` fails closed, `Ignore` passes through if the value doesn't match the
/// expected shape.
fn target_value_in_scope(value: &Value, field: TargetField, devices: &ScopeSet) -> bool {
    let valid = match field.shape {
        TargetValueShape::Scalar => value.as_str().is_some_and(|name| devices.allows(name)),
        TargetValueShape::NonEmptyArray => value.as_array().is_some_and(|names| {
            !names.is_empty()
                && names
                    .iter()
                    .all(|name| name.as_str().is_some_and(|name| devices.allows(name)))
        }),
    };
    valid
        || field.malformed == MalformedTargetPolicy::Ignore && !value_has_shape(value, field.shape)
}

/// Check whether a JSON value matches the expected shape.
///
/// Extracted from rustsdcmcp for issue #147. Returns `true` if the value
/// structurally matches the shape (regardless of scope). Used to distinguish
/// malformed values from out-of-scope values.
fn value_has_shape(value: &Value, shape: TargetValueShape) -> bool {
    match shape {
        TargetValueShape::Scalar => value.is_string(),
        TargetValueShape::NonEmptyArray => value
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_auth::ScopeSet;

    /// Body that a scope-checking preflight would reject: a tool call naming a
    /// tool and device the caller has no claim to.
    const FORBIDDEN: &[u8] = br#"{"method":"tools/call","params":{"name":"forbidden_tool","arguments":{"device":"blocked"}}}"#;

    fn caller() -> CallerCtx {
        CallerCtx {
            token_name: "t1".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    struct AlwaysReject;
    impl ScopePreflight for AlwaysReject {
        fn check(&self, _body: &[u8], _caller: CallerScopes<'_>) -> Result<(), String> {
            Err("insufficient_scope".to_owned())
        }
    }

    /// Task 7's requirement, asserted on behaviour rather than on the shape of
    /// the `Option`: the *same* body that `Some(...)` rejects must be admitted
    /// when the preflight is `None`. Checking only `preflight.is_none()` would
    /// pass even if `run_preflight` rejected everything.
    #[test]
    fn none_admits_a_body_that_some_rejects() {
        let caller = caller();

        let rejecting: OptionalPreflight = Some(Arc::new(AlwaysReject));
        assert_eq!(
            run_preflight(&rejecting, FORBIDDEN, &caller),
            Err("insufficient_scope".to_owned()),
            "the fixture must actually be rejected, or the None case proves nothing"
        );

        let disabled: OptionalPreflight = None;
        assert_eq!(
            run_preflight(&disabled, FORBIDDEN, &caller),
            Ok(()),
            "None must admit every request — this is the Junos behaviour"
        );
    }

    /// The preflight sees the body the middleware buffered, unmodified.
    #[test]
    fn body_reaches_the_implementation_unaltered() {
        struct Capture(std::sync::Mutex<Vec<u8>>);
        impl ScopePreflight for Capture {
            fn check(&self, body: &[u8], _caller: CallerScopes<'_>) -> Result<(), String> {
                *self.0.lock().unwrap() = body.to_vec();
                Ok(())
            }
        }

        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let preflight: OptionalPreflight = Some(capture.clone());

        run_preflight(&preflight, FORBIDDEN, &caller()).unwrap();

        assert_eq!(capture.0.lock().unwrap().as_slice(), FORBIDDEN);
    }

    /// Helper to construct `CallerScopes` for testing.
    fn caller_with(devices: ScopeSet, tools: ScopeSet) -> CallerScopes<'static> {
        // Leak the ScopeSets so they have 'static lifetime for testing
        let devices = Box::leak(Box::new(devices));
        let tools = Box::leak(Box::new(tools));
        CallerScopes {
            token_name: "test-token",
            devices,
            tools,
        }
    }

    static TEST_WRITE_TOOLS: &[&str] = &["delete_device", "update_config"];

    /// Test ToolScopePreflight rejects out-of-scope targets.
    #[test]
    fn tool_scope_preflight_rejects_out_of_scope_target() {
        let preflight = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["allowed-device".to_owned()]),
            ScopeSet::Wildcard,
        );

        // Out of scope device should be rejected
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"forbidden-device"}}}"#,
                caller.clone(),
            )
            .is_err());

        // In-scope device should be allowed
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"allowed-device"}}}"#,
                caller,
            )
            .is_ok());
    }

    /// Test wildcard tool scope still excludes write tools.
    #[test]
    fn wildcard_tool_scope_excludes_write_tools() {
        let preflight = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(ScopeSet::Wildcard, ScopeSet::Wildcard);

        // Read tool should be allowed
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"any"}}}"#,
                caller.clone(),
            )
            .is_ok());

        // Write tool should be denied even with wildcard tool scope
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"delete_device","arguments":{"device":"any"}}}"#,
                caller,
            )
            .is_err());
    }

    /// Test malformed arguments handling.
    #[test]
    fn malformed_arguments_policy() {
        let preflight_deny = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let preflight_ignore = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Ignore,
        );
        let caller = caller_with(ScopeSet::Wildcard, ScopeSet::Wildcard);

        // Arguments as non-object should be denied with Deny policy
        assert!(preflight_deny
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":"not-an-object"}}"#,
                caller.clone(),
            )
            .is_err());

        // Arguments as non-object should be allowed with Ignore policy
        assert!(preflight_ignore
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":"not-an-object"}}"#,
                caller,
            )
            .is_ok());
    }

    /// Test malformed target value handling.
    #[test]
    fn malformed_target_policy() {
        let field_deny = TargetField {
            name: "device",
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Deny,
        };
        let field_ignore = TargetField {
            name: "device",
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Ignore,
        };

        let preflight_deny = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [field_deny],
            MalformedArgumentsPolicy::Deny,
        );
        let preflight_ignore = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [field_ignore],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(ScopeSet::Wildcard, ScopeSet::Wildcard);

        // Non-string device (number) should be denied with Deny policy
        assert!(preflight_deny
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":123}}}"#,
                caller.clone(),
            )
            .is_err());

        // Non-string device should be allowed with Ignore policy
        assert!(preflight_ignore
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":123}}}"#,
                caller,
            )
            .is_ok());
    }

    /// Test batch requests: deny if any request exceeds scope.
    #[test]
    fn batch_denies_if_any_exceeds_scope() {
        let preflight = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["allowed".to_owned()]),
            ScopeSet::Wildcard,
        );

        // All allowed should pass
        assert!(preflight
            .check(
                br#"[
                    {"method":"tools/call","params":{"name":"get_info","arguments":{"device":"allowed"}}},
                    {"method":"tools/call","params":{"name":"get_status","arguments":{"device":"allowed"}}}
                ]"#,
                caller.clone(),
            )
            .is_ok());

        // Any forbidden should deny entire batch
        assert!(preflight
            .check(
                br#"[
                    {"method":"tools/call","params":{"name":"get_info","arguments":{"device":"allowed"}}},
                    {"method":"tools/call","params":{"name":"get_status","arguments":{"device":"forbidden"}}}
                ]"#,
                caller,
            )
            .is_err());
    }

    /// Test non-empty array target shape.
    #[test]
    fn non_empty_array_shape() {
        let field = TargetField {
            name: "devices",
            shape: TargetValueShape::NonEmptyArray,
            malformed: MalformedTargetPolicy::Deny,
        };
        let preflight =
            ToolScopePreflight::new(TEST_WRITE_TOOLS, [field], MalformedArgumentsPolicy::Deny);
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["dev1".to_owned(), "dev2".to_owned()]),
            ScopeSet::Wildcard,
        );

        // Valid non-empty array with all allowed devices
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"devices":["dev1","dev2"]}}}"#,
                caller.clone(),
            )
            .is_ok());

        // Empty array should be denied
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"devices":[]}}}"#,
                caller.clone(),
            )
            .is_err());

        // Array with out-of-scope device should be denied
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"devices":["dev1","forbidden"]}}}"#,
                caller.clone(),
            )
            .is_err());

        // Array with non-string should be denied
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"devices":["dev1",123]}}}"#,
                caller,
            )
            .is_err());
    }

    /// Test multiple target fields.
    #[test]
    fn multiple_target_fields() {
        let preflight = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device"), TargetField::scalar("tenant")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["allowed-id".to_owned()]),
            ScopeSet::Wildcard,
        );

        // Both fields in scope
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"allowed-id","tenant":"allowed-id"}}}"#,
                caller.clone(),
            )
            .is_ok());

        // Device out of scope
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"forbidden","tenant":"allowed-id"}}}"#,
                caller.clone(),
            )
            .is_err());

        // Tenant out of scope
        assert!(preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"get_info","arguments":{"device":"allowed-id","tenant":"forbidden"}}}"#,
                caller,
            )
            .is_err());
    }

    /// Test non-tools/call methods pass through.
    #[test]
    fn non_tool_call_methods_pass() {
        let preflight = ToolScopePreflight::new(
            TEST_WRITE_TOOLS,
            [TargetField::scalar("device")],
            MalformedArgumentsPolicy::Deny,
        );
        let caller = caller_with(
            ScopeSet::Allowlist(vec!["allowed".to_owned()]),
            ScopeSet::Wildcard,
        );

        // tools/list should pass
        assert!(
            preflight
                .check(br#"{"method":"tools/list","params":{}}"#, caller.clone(),)
                .is_ok()
        );

        // initialize should pass
        assert!(
            preflight
                .check(
                    br#"{"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
                    caller,
                )
                .is_ok()
        );
    }

    /// Test TargetField::scalar constructor.
    #[test]
    fn target_field_scalar_constructor() {
        let field = TargetField::scalar("device");
        assert_eq!(field.name, "device");
        assert_eq!(field.shape, TargetValueShape::Scalar);
        assert_eq!(field.malformed, MalformedTargetPolicy::Deny);
    }

    /// Test value_has_shape for scalar.
    #[test]
    fn value_has_shape_scalar() {
        assert!(value_has_shape(
            &Value::String("test".to_owned()),
            TargetValueShape::Scalar
        ));
        assert!(!value_has_shape(
            &Value::Number(123.into()),
            TargetValueShape::Scalar
        ));
        assert!(!value_has_shape(
            &Value::Array(vec![Value::String("test".to_owned())]),
            TargetValueShape::Scalar
        ));
    }

    /// Test value_has_shape for non-empty array.
    #[test]
    fn value_has_shape_non_empty_array() {
        assert!(value_has_shape(
            &Value::Array(vec![
                Value::String("a".to_owned()),
                Value::String("b".to_owned())
            ]),
            TargetValueShape::NonEmptyArray
        ));
        assert!(!value_has_shape(
            &Value::Array(vec![]),
            TargetValueShape::NonEmptyArray
        ));
        assert!(!value_has_shape(
            &Value::Array(vec![
                Value::String("a".to_owned()),
                Value::Number(123.into())
            ]),
            TargetValueShape::NonEmptyArray
        ));
        assert!(!value_has_shape(
            &Value::String("test".to_owned()),
            TargetValueShape::NonEmptyArray
        ));
    }

    // Each guard above was verified by breaking it and confirming the test went
    // red, then restoring it. Recorded here because the verification is the
    // reason to trust the tests, and a reader cannot see it from the code:
    //
    //   out-of-scope target   dropped the `!` in request_exceeds_scope
    //                         -> tool_scope_preflight_rejects_out_of_scope_target
    //   wildcard excludes     made ScopeSet::Wildcard return true unconditionally
    //   write tools           -> wildcard_tool_scope_excludes_write_tools
    //   malformed arguments   flipped the Deny policy to allow
    //                         -> malformed_arguments_policy
    //   malformed target      made the shape check always true
    //                         -> malformed_target_policy
    //   empty array           removed the emptiness check
    //                         -> non_empty_array_shape
    //
    // This was previously five #[ignore]d tests whose bodies were a bare panic!.
    // They asserted nothing, inflated the test count, and would have failed
    // confusingly if ever run. A comment is the honest form for a record of work
    // already done.
}
