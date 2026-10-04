//! Binding a verified OIDC assertion to an approver's token (mecmcp#400 Phase
//! 2 / MEC-994, W3).
//!
//! This module is deliberately transport-free: it has no HTTP types and does
//! no I/O (no clock reads, no network, no shared replay state), and no
//! dependency on a JWT/JWKS verification crate — the caller supplies `now`
//! and has already verified the assertion's signature, issuer, and audience
//! elsewhere (`mecmcp-oidc`, in this workspace), handing in only the already-
//! minimal [`ApproverClaims`]. What is left to check here is entirely a
//! function of three already-in-hand values — the token's entry, the
//! presented claims, and policy — which is what makes it testable without a
//! server, a clock, or a mock IdP.
//!
//! Single-use replay protection (the `jti` not having been seen before) is
//! deliberately NOT checked here. It requires shared, mutable state (a
//! bounded in-memory set), which cannot be a pure function's input without
//! becoming the one argument every test has to fake. The transport layer
//! checks it as a separate step, immediately around a call to
//! [`bind_approver`], once binding has otherwise succeeded.

use crate::Grant;
use crate::entry::{ActorType, OidcSubject};
use crate::store::CallerCtx;
use std::time::Duration;

/// The subset of a verified assertion's claims [`bind_approver`] needs.
///
/// Deliberately a local type rather than taking `mecmcp-oidc`'s
/// `VerifiedClaims` directly: this crate has no business linking a JWT/JWKS
/// verification stack (and the HTTP client it pulls in) just to name one
/// claims type. A caller that already holds a `VerifiedClaims` (today, only
/// `mecmcp-transport`, which already depends on `mecmcp-oidc`) converts it
/// into this type at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverClaims {
    /// The IdP's `sub` claim for the approver.
    pub subject: String,
    /// The caller's group/role claim values.
    pub roles: Vec<String>,
    /// The assertion's `iat` claim.
    pub issued_at: i64,
    /// The assertion's `auth_time` claim, if present.
    pub auth_time: Option<i64>,
}

/// Server-side policy for step-up approver verification.
///
/// Every field here is server configuration, set once at startup
/// (mecmcp-runtime's `VerifiedApproverArgs`, W5) — never client-supplied.
#[derive(Debug, Clone)]
pub struct ApproverPolicy {
    /// The role or group claim value a verified assertion must carry to be
    /// accepted as an approver. Compared against `mecmcp_oidc::VerifiedClaims::roles`.
    pub approver_role: String,
    /// Maximum age of the assertion's `iat` claim, per RFC 9470's `max_age`
    /// step-up pattern. An assertion older than this is stale, however valid
    /// its signature.
    pub max_age: Duration,
    /// When set, an assertion with no `auth_time` claim, or one older than
    /// `max_age`, is rejected. Off by default because not every IdP or grant
    /// type emits `auth_time`; operators who need proof of a fresh
    /// interactive login (rather than merely a fresh token) turn this on.
    pub require_auth_time: bool,
}

/// An approver identity bound to one request, after a successful
/// [`bind_approver`].
///
/// Deliberately minimal: issuer and subject only. No email, no display name,
/// no raw claims — the spec requires the JWT itself never be retained past
/// verification, and widening this type would be the easiest way to violate
/// that by accident.
///
/// `#[non_exhaustive]`, and no public constructor outside this crate: the
/// only way to produce one is [`bind_approver`] succeeding. No tool argument
/// or model output can construct this type directly — approver identity is
/// decided only by this module's own verification path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedApprover {
    /// The IdP issuer that signed the verified assertion.
    pub issuer: String,
    /// The IdP's `sub` claim for the approver.
    pub subject: String,
}

impl VerifiedApprover {
    /// Test-only constructor, for crates that need a `VerifiedApprover`
    /// fixture without going through [`bind_approver`]. Gated behind the
    /// `test-util` feature so it can never ship enabled in a release build.
    #[cfg(any(test, feature = "test-util"))]
    #[doc(hidden)]
    pub fn for_test(issuer: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.into(),
        }
    }
}

/// Why a presented approver assertion was refused binding to a caller's
/// token.
///
/// Every variant is a distinct, audited reason (see the MEC-994 acceptance
/// criteria: "each of these is refused with a distinct audited reason"). No
/// catch-all: a call site unable to name which of these applies has found a
/// gap in this enum, not a reason to collapse the detail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingFailure {
    /// The token presenting the assertion is not a `human` token. Only a
    /// human token can approve; binding an assertion to an `agent` token
    /// would let the proposer's own agent credential double as its approver.
    #[error("an approver assertion can only bind to a human token, not an agent token")]
    NotHumanToken,
    /// The token has no `oidc_subject` binding at all, so there is nothing
    /// to check the assertion's subject against.
    #[error("the token has no oidc_subject binding configured")]
    NoSubjectBinding,
    /// The assertion's `(issuer, subject)` does not match the token's bound
    /// `oidc_subject`.
    #[error("the assertion's issuer or subject does not match the token's bound oidc_subject")]
    SubjectMismatch,
    /// The assertion's roles do not include the configured approver role.
    #[error("the assertion does not carry the configured approver role")]
    MissingApproverRole,
    /// `now - iat` exceeds `policy.max_age`.
    #[error("the assertion is older than the configured maximum age")]
    Stale,
    /// `iat` is after `now` (beyond a small clock-skew allowance). This
    /// needs no attacker: an un-synced IdP clock, or one deliberately set
    /// ahead, would otherwise pass the staleness check trivially, since
    /// `now.saturating_sub(iat)` is zero or clamped for any `iat > now`.
    #[error("the assertion's issued_at claim is in the future")]
    IssuedInFuture,
    /// `policy.require_auth_time` is set, but the assertion has no
    /// `auth_time` claim.
    #[error("the assertion has no auth_time claim, and one is required")]
    MissingAuthTime,
    /// `policy.require_auth_time` is set and the assertion has an
    /// `auth_time`, but `now - auth_time` exceeds `policy.max_age`.
    #[error("the assertion's auth_time is older than the configured maximum age")]
    StaleAuthTime,
}

impl BindingFailure {
    /// A stable, lowercase machine-readable code for this reason, for
    /// structured audit logging. See
    /// `mecmcp_oidc::VerificationFailure::reason_code` for the sibling
    /// used upstream of this one.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NotHumanToken => "not_human_token",
            Self::NoSubjectBinding => "no_subject_binding",
            Self::SubjectMismatch => "subject_mismatch",
            Self::MissingApproverRole => "missing_approver_role",
            Self::Stale => "stale",
            Self::IssuedInFuture => "issued_in_future",
            Self::MissingAuthTime => "missing_auth_time",
            Self::StaleAuthTime => "stale_auth_time",
        }
    }
}

/// Bind a verified assertion's claims to a caller's token.
///
/// `issuer` is the issuer the assertion was verified against — `ApproverClaims`
/// carries no `iss` field of its own, because the caller's verifier is
/// configured with exactly one issuer and already checked the token's `iss`
/// against it during verification. Passing it here, rather than
/// re-deriving it, keeps this function honest about which issuer actually
/// vouched for `claims`.
///
/// `claims` must already have passed the caller's own signature, issuer,
/// audience, and expiry checks — this function does not re-verify any of
/// that. `now` is injected rather than read from the system clock so this
/// stays a pure function of its arguments; callers pass
/// `chrono::Utc::now().timestamp()`.
///
/// Does not check `jti` replay. See the module docs for why, and
/// `mecmcp-transport`'s replay guard for where that check lives.
///
/// # Errors
/// Returns the specific [`BindingFailure`] naming why binding was refused.
pub fn bind_approver<G: Grant>(
    caller: &CallerCtx<G>,
    issuer: &str,
    claims: &ApproverClaims,
    policy: &ApproverPolicy,
    now: i64,
) -> Result<VerifiedApprover, BindingFailure> {
    if caller.actor_type != ActorType::Human {
        return Err(BindingFailure::NotHumanToken);
    }

    let bound: &OidcSubject = caller
        .oidc_subject
        .as_ref()
        .ok_or(BindingFailure::NoSubjectBinding)?;

    if bound.issuer != issuer || bound.subject != claims.subject {
        return Err(BindingFailure::SubjectMismatch);
    }

    if !claims
        .roles
        .iter()
        .any(|role| role == &policy.approver_role)
    {
        return Err(BindingFailure::MissingApproverRole);
    }

    // Allowance for IdP/server clock skew. Not configurable: this guards
    // against misconfiguration, not an attacker who controls `iat` (`claims`
    // is already signature-verified), so there is no policy knob to tune.
    const FUTURE_SKEW_SECS: i64 = 60;
    if claims.issued_at > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(BindingFailure::IssuedInFuture);
    }

    let max_age_secs = i64::try_from(policy.max_age.as_secs()).unwrap_or(i64::MAX);
    if now.saturating_sub(claims.issued_at) > max_age_secs {
        return Err(BindingFailure::Stale);
    }

    if policy.require_auth_time {
        let auth_time = claims.auth_time.ok_or(BindingFailure::MissingAuthTime)?;
        if now.saturating_sub(auth_time) > max_age_secs {
            return Err(BindingFailure::StaleAuthTime);
        }
    }

    Ok(VerifiedApprover {
        issuer: bound.issuer.clone(),
        subject: bound.subject.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::NoGrant;
    use crate::scope::ScopeSet;

    const TEST_ISSUER: &str = "https://idp.example.com";

    fn claims(subject: &str, roles: &[&str], issued_at: i64) -> ApproverClaims {
        ApproverClaims {
            subject: subject.to_owned(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            issued_at,
            auth_time: None,
        }
    }

    fn human_caller(oidc_subject: Option<OidcSubject>) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "approver-token".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            oidc_subject,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    fn policy() -> ApproverPolicy {
        ApproverPolicy {
            approver_role: "approver".to_owned(),
            max_age: Duration::from_secs(300),
            require_auth_time: false,
        }
    }

    fn bound() -> OidcSubject {
        OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: "alice".to_owned(),
        }
    }

    #[test]
    fn a_matching_human_token_binds() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1000);
        let approver = bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1010).unwrap();
        assert_eq!(approver.issuer, TEST_ISSUER);
        assert_eq!(approver.subject, "alice");
    }

    #[test]
    fn an_agent_token_is_refused() {
        let mut caller = human_caller(Some(bound()));
        caller.actor_type = ActorType::Agent;
        let claims = claims("alice", &["approver"], 1000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1010),
            Err(BindingFailure::NotHumanToken)
        );
    }

    #[test]
    fn a_token_with_no_oidc_subject_is_refused() {
        let caller = human_caller(None);
        let claims = claims("alice", &["approver"], 1000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1010),
            Err(BindingFailure::NoSubjectBinding)
        );
    }

    #[test]
    fn a_different_subject_is_refused() {
        let caller = human_caller(Some(bound()));
        let claims = claims("mallory", &["approver"], 1000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1010),
            Err(BindingFailure::SubjectMismatch)
        );
    }

    #[test]
    fn a_different_issuer_is_refused() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1000);
        assert_eq!(
            bind_approver(
                &caller,
                "https://other-idp.example.com",
                &claims,
                &policy(),
                1010
            ),
            Err(BindingFailure::SubjectMismatch)
        );
    }

    #[test]
    fn missing_the_approver_role_is_refused() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["employee"], 1000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1010),
            Err(BindingFailure::MissingApproverRole)
        );
    }

    #[test]
    fn an_assertion_older_than_max_age_is_stale() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1000 + 301),
            Err(BindingFailure::Stale)
        );
    }

    #[test]
    fn an_assertion_at_exactly_max_age_is_accepted() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1000);
        assert!(bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1000 + 300).is_ok());
    }

    #[test]
    fn an_assertion_issued_in_the_future_is_refused() {
        let caller = human_caller(Some(bound()));
        // A misconfigured or ahead-of-skew IdP clock, not an attacker:
        // without this check, `now.saturating_sub(iat)` would be 0 here and
        // pass staleness trivially.
        let claims = claims("alice", &["approver"], 10_000);
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1000),
            Err(BindingFailure::IssuedInFuture)
        );
    }

    #[test]
    fn an_assertion_within_the_clock_skew_allowance_is_accepted() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1060);
        assert!(bind_approver(&caller, TEST_ISSUER, &claims, &policy(), 1000).is_ok());
    }

    #[test]
    fn require_auth_time_rejects_an_assertion_with_none() {
        let caller = human_caller(Some(bound()));
        let claims = claims("alice", &["approver"], 1000);
        let mut policy = policy();
        policy.require_auth_time = true;
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy, 1010),
            Err(BindingFailure::MissingAuthTime)
        );
    }

    #[test]
    fn require_auth_time_rejects_a_stale_auth_time() {
        let caller = human_caller(Some(bound()));
        let mut claims = claims("alice", &["approver"], 1000);
        claims.auth_time = Some(600);
        let mut policy = policy();
        policy.require_auth_time = true;
        assert_eq!(
            bind_approver(&caller, TEST_ISSUER, &claims, &policy, 1010),
            Err(BindingFailure::StaleAuthTime)
        );
    }

    #[test]
    fn require_auth_time_accepts_a_fresh_auth_time() {
        let caller = human_caller(Some(bound()));
        let mut claims = claims("alice", &["approver"], 1000);
        claims.auth_time = Some(1005);
        let mut policy = policy();
        policy.require_auth_time = true;
        assert!(bind_approver(&caller, TEST_ISSUER, &claims, &policy, 1010).is_ok());
    }
}
