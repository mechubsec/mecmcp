//! Gate for tools that mutate a device without going through change-set review.
//!
//! House rule: deterministic code decides, a human approves. A tool that stages,
//! validates, and commits a device change in one call — with no independent
//! second-principal approval — breaks that rule outright. This gate is the single
//! place a server refuses such a tool unless an operator has explicitly accepted
//! the risk with `--allow-direct-commit`.

use crate::scope::AuditScope;

/// A direct-commit tool was refused because the server was not started with
/// `--allow-direct-commit`.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error(
    "direct-commit tools are disabled on this server; pass --allow-direct-commit to enable \
     them, or route this operation through a change set for independent approval"
)]
pub struct DirectCommitRefused;

/// The stable audit `reason` recorded when [`DirectCommitPolicy::check`] refuses a call.
pub const DIRECT_COMMIT_DENIED_REASON: &str = "direct_commit_disabled";

/// Whether this server permits tools that commit to a device with no
/// second-principal change-set approval.
///
/// Construct once at startup from the `--allow-direct-commit` CLI flag and hold
/// it for the process lifetime. The policy is a process-level setting, not a
/// property of the caller: it is checked identically for a stdio session
/// (which carries no caller context at all) and an authenticated HTTP one, so
/// enabling it is a deliberate, visible operator decision rather than
/// something a caller can influence per request.
#[derive(Debug, Clone, Copy)]
pub struct DirectCommitPolicy {
    allowed: bool,
}

impl DirectCommitPolicy {
    /// Builds the policy from the operator's `--allow-direct-commit` flag.
    #[must_use]
    pub fn new(allowed: bool) -> Self {
        Self { allowed }
    }

    /// Whether direct-commit tools are permitted on this server.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// Logs a loud, structured warning if direct-commit is enabled.
    ///
    /// Call once, at process startup, after CLI parsing and before serving any
    /// request. A no-op when the flag is off, so a default deployment's
    /// startup log carries no mention of a risk it did not take.
    ///
    /// Deliberately NOT on `target: "audit"`: that stream carries one record
    /// per tool call with a fixed schema (`AuditScope`'s `Drop` impl), and a
    /// startup banner has none of those fields. Emitting it there would
    /// pollute the audit stream with something no consumer can parse as an
    /// action record — the per-call `direct_commit_allowed=true` tag on
    /// `AuditScope` is what belongs there instead.
    pub fn log_startup(&self, binary_name: &'static str) {
        if self.allowed {
            tracing::warn!(
                binary = binary_name,
                "SECURITY: --allow-direct-commit is enabled on this server. Direct-write tools \
                 will commit device changes with no independent second-principal approval. \
                 Every use is audited. An operator made this choice; disable the flag unless \
                 that risk is accepted for this deployment."
            );
        }
    }

    /// Enforces the gate for one direct-commit tool call, recording the
    /// outcome on `scope`.
    ///
    /// On refusal, marks `scope` denied with [`DIRECT_COMMIT_DENIED_REASON`]
    /// and returns [`DirectCommitRefused`] — the caller must not perform the
    /// device mutation. On success, tags `scope` so the audit trail shows the
    /// call ran under the flag, and returns `Ok(())`. Either way `scope`'s
    /// `Drop` emits exactly one audit event, so a use of this gate is always
    /// audited — refusals included.
    pub fn check(&self, scope: &mut AuditScope) -> Result<(), DirectCommitRefused> {
        if self.allowed {
            scope.meta("direct_commit_allowed", true);
            Ok(())
        } else {
            scope.deny(DIRECT_COMMIT_DENIED_REASON);
            Err(DirectCommitRefused)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testutil::run_with_capture;

    #[test]
    fn refuses_and_denies_when_not_allowed() {
        let policy = DirectCommitPolicy::new(false);
        let out = run_with_capture(|| {
            let mut scope = AuditScope::stdio("load_and_commit_config", "commit", vec![]);
            let result = policy.check(&mut scope);
            assert!(result.is_err());
        });
        assert!(out.contains("authorization=denied"));
        assert!(out.contains("result=denied"));
        assert!(out.contains("reason=direct_commit_disabled"));
    }

    #[test]
    fn allows_and_tags_metadata_when_allowed() {
        let policy = DirectCommitPolicy::new(true);
        let out = run_with_capture(|| {
            let mut scope = AuditScope::stdio("load_and_commit_config", "commit", vec![]);
            let result = policy.check(&mut scope);
            assert!(result.is_ok());
            scope.succeed();
        });
        assert!(out.contains("direct_commit_allowed=true"));
        assert!(out.contains("result=ok"));
    }

    /// The gate does not read the caller context at all, so a stdio call (no
    /// context) and an authenticated one are refused on identical terms.
    #[test]
    fn refusal_is_identical_over_stdio_and_an_authenticated_caller() {
        let policy = DirectCommitPolicy::new(false);
        let ctx = mecmcp_auth::CallerCtx::<mecmcp_auth::NoGrant> {
            token_name: "writer".into(),
            devices: mecmcp_auth::ScopeSet::Wildcard,
            tools: mecmcp_auth::ScopeSet::Wildcard,
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
        };

        let stdio_out = run_with_capture(|| {
            let mut scope = AuditScope::stdio("upgrade_junos", "upgrade", vec![]);
            let _ = policy.check(&mut scope);
        });
        let http_out = run_with_capture(|| {
            let mut scope = AuditScope::from_caller(&ctx, "upgrade_junos", "upgrade", vec![]);
            let _ = policy.check(&mut scope);
        });

        for out in [&stdio_out, &http_out] {
            assert!(out.contains("authorization=denied"));
            assert!(out.contains("reason=direct_commit_disabled"));
        }
    }
}
