//! RAII audit guard: emits exactly one `target="audit"` event on Drop.

use crate::attribution::{ActorType, Attribution, Principal};
use crate::redact::escape_control_chars;
use crate::schema::{AuditOutcome, AuditValue, bounded_error};
use std::fmt::Display;
use std::time::Instant;

/// One audited tool call. Construct at the top of a handler, set an outcome,
/// and let it drop — the drop emits the audit event.
pub struct AuditScope {
    attribution: Attribution,
    tool: &'static str,
    devices: Vec<String>,
    action: &'static str,
    started: Instant,
    outcome: AuditOutcome,
    metadata: Vec<(&'static str, AuditValue)>,
    /// Client-asserted version string, if the client sent one.
    client_version: Option<String>,
    /// Client-asserted per-call identifier, if the client sent one.
    client_call_id: Option<String>,
}

impl AuditScope {
    /// Record client-asserted call context alongside the rest of the event.
    ///
    /// Both values come from the request's `_meta` and are **client-asserted**,
    /// exactly like `client_name` — never usable for authorization. The call id
    /// is the useful half: `request_id` correlates this server's transport and
    /// handler events with each other, and nothing beyond them, whereas this
    /// ties the record to the exact tool call in the client's own transcript.
    pub fn set_client_extras(&mut self, version: Option<String>, call_id: Option<String>) {
        self.client_version = version;
        self.client_call_id = call_id;
    }

    /// Build for a call with an explicit `Attribution`.
    ///
    /// This is the primary constructor when the caller has built an
    /// `Attribution` that may include agent identity or other enrichment.
    pub fn new(
        attribution: Attribution,
        tool: &'static str,
        action: &'static str,
        devices: Vec<String>,
    ) -> Self {
        Self {
            attribution,
            tool,
            devices,
            action,
            started: Instant::now(),
            outcome: AuditOutcome::Unsettled,
            metadata: Vec::new(),
            client_version: None,
            client_call_id: None,
        }
    }

    /// Build for a call from an authenticated context, defaulting to human attribution.
    ///
    /// Convenience wrapper over `new(Attribution::from_caller(ctx), ...)`.
    pub fn from_caller<G>(
        ctx: &mecmcp_auth::CallerCtx<G>,
        tool: &'static str,
        action: &'static str,
        devices: Vec<String>,
    ) -> Self
    where
        G: mecmcp_auth::Grant,
    {
        Self::new(Attribution::from_caller(ctx), tool, action, devices)
    }

    /// Build for the stdio / no-auth path.
    ///
    /// Convenience wrapper over `new(Attribution::stdio(), ...)`.
    pub fn stdio(tool: &'static str, action: &'static str, devices: Vec<String>) -> Self {
        Self::new(Attribution::stdio(), tool, action, devices)
    }

    /// Attach a safe metadata field (never secrets).
    pub fn meta(&mut self, key: &'static str, val: impl Into<AuditValue>) {
        self.metadata.push((key, val.into()));
    }

    /// Mark success.
    pub fn succeed(&mut self) {
        self.outcome = AuditOutcome::Succeeded;
    }

    /// Mark failure with a generic kind (`"error"`).
    pub fn fail(&mut self, error: impl Display) {
        self.outcome = AuditOutcome::Failed {
            kind: "error",
            msg: bounded_error(error),
        };
    }

    /// Mark failure with a specific stable kind (e.g. `"timeout"`, `"lease_busy"`).
    pub fn fail_kind(&mut self, kind: &'static str, error: impl Display) {
        self.outcome = AuditOutcome::Failed {
            kind,
            msg: bounded_error(error),
        };
    }

    /// Mark an authorization denial with a reason.
    pub fn deny(&mut self, reason: &'static str) {
        self.outcome = AuditOutcome::Denied { reason };
    }

    /// Attach a client name to this audit scope.
    ///
    /// The name is always client-asserted and will never be marked as
    /// server-verified. This method is intended for transport-level audit
    /// emission where the client name was captured from the MCP `initialize`
    /// handshake and looked up via the session tracker.
    pub fn attach_client_name(&mut self, name: &'static str) {
        self.attribution.with_client_name(name);
    }
}

/// The default name for the tool-duration histogram.
pub const DEFAULT_DURATION_METRIC: &str = "mecmcp_tool_duration_seconds";

static DURATION_METRIC: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Set the tool-duration histogram's metric name.
///
/// A metric name is part of the consuming server's public interface — dashboards
/// and alerts are written against it — so this crate must not impose one. A
/// server adopting this crate should install its existing name here rather than
/// silently renaming a metric its operators already query.
///
/// Idempotent, matching [`crate::redact::install`]: a second call is a no-op.
/// Install before the first [`AuditScope`] is dropped; afterwards the name is
/// fixed for the process, so the emitted name can never diverge from whatever
/// bucket configuration was registered for it.
pub fn install_duration_metric_name(name: &'static str) {
    let _ = DURATION_METRIC.set(name);
}

/// The metric name in effect, defaulting to [`DEFAULT_DURATION_METRIC`].
#[must_use]
pub fn duration_metric_name() -> &'static str {
    DURATION_METRIC
        .get()
        .copied()
        .unwrap_or(DEFAULT_DURATION_METRIC)
}

impl Drop for AuditScope {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        let duration_ms = elapsed.as_millis() as u64;
        let device_count = self.devices.len() as u64;
        let (devices, metadata) =
            crate::redact::render(crate::redact::active(), &self.devices, &self.metadata);

        // `caller` is emitted directly and is NEVER redactable; only `devices` and
        // `metadata` pass through redact::render above.
        let authorization = match &self.outcome {
            AuditOutcome::Denied { .. } => "denied",
            _ if matches!(self.attribution.principal, Principal::Unauthenticated) => "no_auth",
            _ => "allowed",
        };
        let (result, error_kind, error, reason) = match &self.outcome {
            AuditOutcome::Succeeded => ("ok", "", String::new(), ""),
            AuditOutcome::Failed { kind, msg } => ("error", *kind, escape_control_chars(msg), ""),
            AuditOutcome::Denied { reason } => ("denied", "", String::new(), *reason),
            AuditOutcome::Unsettled => ("unsettled", "", String::new(), ""),
        };

        let actor_type = match self.attribution.actor_type {
            ActorType::Human => "human",
            ActorType::Agent => "agent",
            ActorType::Unknown => "unknown",
        };

        // Read the recorded source rather than guessing from the values. A
        // client-asserted provider is indistinguishable from a token-verified
        // one by inspection, so inferring here would label a caller's claim as
        // server-verified (mecmcp#52).
        let token_verified_fields = self.attribution.token_verified_fields;

        // Emit flat attribution fields.
        let model_id = self
            .attribution
            .agent
            .as_ref()
            .map(|a| escape_control_chars(&a.model_id))
            .unwrap_or_default();
        let session_id = self
            .attribution
            .agent
            .as_ref()
            .map(|a| escape_control_chars(&a.session_id))
            .unwrap_or_default();
        let client_name = self
            .attribution
            .agent
            .as_ref()
            .and_then(|a| a.client_name.as_deref())
            .map(escape_control_chars)
            .unwrap_or_default();
        // The provider and its tier are the fields this whole mechanism exists to
        // make trustworthy. Carrying them on the Attribution but never emitting
        // them would leave every SIEM consumer with the trust marker and nothing
        // for it to describe.
        let provider = self
            .attribution
            .agent
            .as_ref()
            .map(|a| escape_control_chars(&a.provider))
            .unwrap_or_default();
        let provider_tier = self
            .attribution
            .agent
            .as_ref()
            .map(|a| a.provider_tier.to_string())
            .unwrap_or_default();
        let on_behalf_of = self
            .attribution
            .on_behalf_of
            .as_deref()
            .map(escape_control_chars)
            .unwrap_or_default();
        let change_ref = self
            .attribution
            .change_ref
            .as_deref()
            .map(escape_control_chars)
            .unwrap_or_default();

        metrics::histogram!(
            duration_metric_name(),
            "tool" => self.tool,
            "result" => result
        )
        .record(elapsed.as_secs_f64());

        tracing::info!(
            target: "audit",
            request_id = %self.attribution.request_id,
            caller = %self.attribution.principal,
            actor_type = %actor_type,
            token_verified_fields = %token_verified_fields,
            provider = %provider,
            provider_tier = %provider_tier,
            model_id = %model_id,
            session_id = %session_id,
            client_name = %client_name,
            client_version = %self.client_version.as_deref().map(escape_control_chars).unwrap_or_default(),
            client_call_id = %self.client_call_id.as_deref().map(escape_control_chars).unwrap_or_default(),
            on_behalf_of = %on_behalf_of,
            change_ref = %change_ref,
            tool = %self.tool,
            devices = %devices,
            device_count = device_count,
            action = %self.action,
            authorization = %authorization,
            result = %result,
            duration_ms = duration_ms,
            error_kind = %error_kind,
            error = %error,
            reason = %reason,
            metadata = %metadata,
            "audit"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::attribution::{AgentIdentity, Attribution};
    use crate::testutil::run_with_capture;
    use mecmcp_auth::{CallerCtx, NoGrant, ScopeSet};

    fn ctx(name: &str) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: name.into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Unknown,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn success_emits_ok_with_duration_and_meta() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(
                &ctx("ci"),
                "load_and_commit_config",
                "commit",
                vec!["r1".into()],
            );
            a.meta("config_bytes", 1234u64);
            a.succeed();
        });
        assert!(out.contains("audit"));
        assert!(out.contains("tool=load_and_commit_config"));
        assert!(out.contains("caller=ci"));
        assert!(out.contains("authorization=allowed"));
        assert!(out.contains("result=ok"));
        assert!(out.contains("config_bytes=1234"));
        assert!(out.contains("duration_ms="));
    }

    #[test]
    fn unsettled_when_dropped_without_outcome() {
        let out = run_with_capture(|| {
            let _a =
                AuditScope::from_caller(&ctx("ci"), "upgrade_junos", "upgrade", vec!["r1".into()]);
        });
        assert!(out.contains("result=unsettled"));
    }

    #[test]
    fn deny_emits_denied_authorization() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(&ctx("ci"), "add_device", "add-device", vec![]);
            a.deny("tool_scope");
        });
        assert!(out.contains("authorization=denied"));
        assert!(out.contains("result=denied"));
        assert!(out.contains("reason=tool_scope"));
    }

    #[test]
    fn stdio_caller_is_no_auth() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::stdio("get_device_list", "read", vec![]);
            a.succeed();
        });
        assert!(out.contains("caller=stdio"));
        assert!(out.contains("authorization=no_auth"));
    }

    #[test]
    fn tool_duration_metrics_cover_all_results_without_sensitive_labels() {
        use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

        let recorder = PrometheusBuilder::new()
            .add_global_label("server", "test")
            .set_buckets_for_metric(
                Matcher::Full("mecmcp_tool_duration_seconds".to_owned()),
                &[0.01, 1.0, 1800.0],
            )
            .unwrap()
            .build_recorder();
        let handle = recorder.handle();
        let caller = ctx("secret-token-name");

        metrics::with_local_recorder(&recorder, || {
            let mut ok = AuditScope::from_caller(
                &caller,
                "get_device_list",
                "read",
                vec!["secret-device".into()],
            );
            ok.succeed();

            let mut error = AuditScope::from_caller(
                &caller,
                "get_device_list",
                "read",
                vec!["secret-device".into()],
            );
            error.fail("secret-error-text");

            let mut denied = AuditScope::from_caller(
                &caller,
                "get_device_list",
                "read",
                vec!["secret-device".into()],
            );
            denied.deny("tool_scope");

            let _unsettled = AuditScope::from_caller(
                &caller,
                "get_device_list",
                "read",
                vec!["secret-device".into()],
            );
        });

        handle.run_upkeep();
        let text = handle.render();
        for result in ["ok", "error", "denied", "unsettled"] {
            assert!(
                text.lines().any(|line| {
                    line.starts_with("mecmcp_tool_duration_seconds_bucket{")
                        && line.contains("server=\"test\"")
                        && line.contains("tool=\"get_device_list\"")
                        && line.contains(&format!("result=\"{result}\""))
                }),
                "missing {result} in:\n{text}"
            );
        }
        for forbidden in [
            "secret-token-name",
            "secret-device",
            "secret-error-text",
            "caller=",
            "device=",
            "error=",
        ] {
            assert!(!text.contains(forbidden), "leaked {forbidden} in:\n{text}");
        }
    }

    #[test]
    fn drop_applies_installed_redaction() {
        use crate::redact::{self, AuditRedaction};
        // Install a drop policy for `host`. OnceLock is process-global, so this is
        // the only scope test that installs redaction; other tests rely on None.
        redact::install(AuditRedaction::parse("host=drop", None).unwrap());
        let out = run_with_capture(|| {
            let mut a = AuditScope::stdio("add_device", "add-device", vec!["r1".into()]);
            a.meta("host", "10.0.0.5");
            a.meta("name", "r1");
            a.succeed();
        });
        assert!(
            !out.contains("10.0.0.5"),
            "dropped host value must be absent: {out}"
        );
        assert!(
            out.contains("name=r1"),
            "non-dropped field must survive: {out}"
        );
    }

    #[test]
    fn agent_attribution_emits_all_fields() {
        let out = run_with_capture(|| {
            let mut attr = Attribution::stdio();
            attr.actor_type = ActorType::Agent;
            attr.agent = Some(AgentIdentity {
                model_id: "claude-sonnet-4-5".into(),
                session_id: "sess-abc".into(),
                client_name: Some("mcp-client/1.0".into()),
                provider: "anthropic".into(),
                provider_tier: crate::Tier::Public,
                skills_used: vec![],
            });
            attr.on_behalf_of = Some("alice".into());
            attr.change_ref = Some("CHG0012345".into());
            let mut a = AuditScope::new(attr, "commit_config", "commit", vec!["r1".into()]);
            a.succeed();
        });
        assert!(out.contains("actor_type=agent"));
        assert!(out.contains("model_id=claude-sonnet-4-5"));
        assert!(out.contains("session_id=sess-abc"));
        assert!(out.contains("client_name=mcp-client/1.0"));
        assert!(out.contains("on_behalf_of=alice"));
        assert!(out.contains("change_ref=CHG0012345"));
    }

    /// Client version and per-call id reach the audit line.
    ///
    /// Both are client-asserted, like `client_name`. The call id is what ties a
    /// server-side record to the exact tool call in the client's own transcript;
    /// `request_id` only correlates this server's two events with each other.
    #[test]
    fn client_extras_reach_the_audit_line() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(&ctx("writer"), "commit_config", "commit", vec![]);
            a.set_client_extras(
                Some("2.1.234".into()),
                Some("toolu_011on2R3XWgvKmG2WRChDa5P".into()),
            );
            a.succeed();
        });
        assert!(
            out.contains("client_version=2.1.234"),
            "client version must be emitted: {out}"
        );
        assert!(
            out.contains("client_call_id=toolu_011on2R3XWgvKmG2WRChDa5P"),
            "per-call id must be emitted: {out}"
        );
    }

    /// A client that sends neither must not gain empty-looking claims that read
    /// as though something was asserted.
    #[test]
    fn client_extras_are_empty_when_the_client_sends_none() {
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(&ctx("writer"), "commit_config", "commit", vec![]);
            a.succeed();
        });
        assert!(
            out.contains("client_version="),
            "the field is always present: {out}"
        );
        assert!(
            !out.contains("client_version=2."),
            "nothing may be invented: {out}"
        );
    }

    #[test]
    fn unknown_attribution_leaves_agent_fields_empty() {
        let out = run_with_capture(|| {
            let mut a =
                AuditScope::from_caller(&ctx("legacy-token"), "commit_config", "commit", vec![]);
            a.succeed();
        });
        assert!(out.contains("actor_type=unknown"));
        assert!(out.contains("token_verified_fields=none"));
        // Agent fields should be present but empty when no provenance exists.
        assert!(out.contains("model_id="));
        assert!(out.contains("session_id="));
    }

    #[test]
    fn a_token_named_stdio_is_still_recorded_as_authenticated() {
        // The authorization field must derive from the Principal variant, not from
        // the token's name. Nothing stops an operator minting a token called
        // "stdio", and that must not let it masquerade as the no-auth path.
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(&ctx("stdio"), "commit_config", "commit", vec![]);
            a.succeed();
        });
        assert!(
            out.contains("authorization=allowed"),
            "a token named 'stdio' must be recorded as authenticated, not no_auth: {out}"
        );
        assert!(
            !out.contains("authorization=no_auth"),
            "authorization must not be no_auth for an authenticated token: {out}"
        );
    }

    #[test]
    fn token_verified_provenance_marks_source_as_token() {
        let ctx: CallerCtx<NoGrant> = CallerCtx {
            token_name: "claude-code-ops".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: Some("anthropic".into()),
            provider_tier: Some(mecmcp_auth::Tier::Public),
            on_behalf_of: Some("dev@example.com".into()),
            actor_type: mecmcp_auth::ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let out = run_with_capture(|| {
            let mut a = AuditScope::from_caller(&ctx, "commit_config", "commit", vec!["r1".into()]);
            a.succeed();
        });
        assert!(
            out.contains("token_verified_fields=actor_type,on_behalf_of,provider"),
            "the audit event must name which fields the token bound: {out}"
        );
        assert!(
            out.contains("actor_type=agent"),
            "actor_type must flow from token entry: {out}"
        );
        assert!(
            out.contains("on_behalf_of=dev@example.com"),
            "on_behalf_of must flow from token entry: {out}"
        );
    }

    /// A newline embedded in any caller-asserted free-text field must not let
    /// that field start what looks like a second, independently-parseable
    /// audit line.
    #[test]
    fn newline_in_free_text_fields_does_not_split_the_audit_line() {
        let out = run_with_capture(|| {
            let mut attr = Attribution::stdio();
            attr.actor_type = ActorType::Agent;
            attr.agent = Some(AgentIdentity {
                model_id: "claude\nsonnet".into(),
                session_id: "sess\nabc".into(),
                client_name: Some("mcp-client\n/1.0".into()),
                provider: "anthro\npic".into(),
                provider_tier: crate::Tier::Public,
                skills_used: vec![],
            });
            attr.on_behalf_of = Some("alice\nbob".into());
            attr.change_ref = Some("CHG\n0012345".into());
            let mut a = AuditScope::new(attr, "commit_config", "commit", vec!["r1".into()]);
            a.set_client_extras(Some("1\nX".into()), Some("call\nid".into()));
            a.fail("device said:\nunexpected prompt");
        });
        assert_eq!(
            out.lines().count(),
            1,
            "a caller-asserted newline must not produce a second audit line: {out:?}"
        );
        assert!(!out.contains("model_id=claude\nsonnet"));
        assert!(out.contains("model_id=claude%0Asonnet"));
        assert!(out.contains("session_id=sess%0Aabc"));
        assert!(out.contains("client_name=mcp-client%0A/1.0"));
        assert!(out.contains("provider=anthro%0Apic"));
        assert!(out.contains("on_behalf_of=alice%0Abob"));
        assert!(out.contains("change_ref=CHG%0A0012345"));
        assert!(out.contains("client_version=1%0AX"));
        assert!(out.contains("client_call_id=call%0Aid"));
        assert!(out.contains("error=device said:%0Aunexpected prompt"));
    }

    /// Well-formed values with legitimate spaces render unchanged: the escape
    /// targets control characters, not the space delimiter the text format
    /// already uses loosely for these free-text fields.
    #[test]
    fn well_formed_free_text_values_render_unchanged() {
        let out = run_with_capture(|| {
            let mut attr = Attribution::stdio();
            attr.actor_type = ActorType::Agent;
            attr.agent = Some(AgentIdentity {
                model_id: "claude-sonnet-4-5".into(),
                session_id: "sess-abc".into(),
                client_name: Some("my client app".into()),
                provider: "anthropic".into(),
                provider_tier: crate::Tier::Public,
                skills_used: vec![],
            });
            attr.on_behalf_of = Some("alice smith".into());
            attr.change_ref = Some("CHG0012345".into());
            let mut a = AuditScope::new(attr, "commit_config", "commit", vec!["r1".into()]);
            a.fail("device returned a timeout after 30 seconds");
        });
        assert!(out.contains("client_name=my client app"));
        assert!(out.contains("on_behalf_of=alice smith"));
        assert!(out.contains("error=device returned a timeout after 30 seconds"));
    }
}
