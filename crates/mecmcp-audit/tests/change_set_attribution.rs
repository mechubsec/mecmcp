//! `Attribution` carries the approver and the change set it belongs to
//! (rustjunosmcp#307).
//!
//! A change set applied under two-person control reached the device naming only
//! the applier. Reading the firewall's commit log alone, that is indistinguishable
//! from a single-operator change: nothing on the device says a second principal
//! authorised it, or which change set it came from.
//!
//! The commit log is the durable artifact, and often the only one an outside
//! reviewer is given — an audit log can be re-derived or forwarded, a commit
//! comment cannot be corrected retroactively. The two fields live here rather
//! than in one server because every server in the family consumes this crate and
//! has the same gap.
//!
//! Neither field is ever server-derived here. `from_caller` sees a token, and a
//! token cannot vouch for who approved a change set; only the change-set store
//! knows that, so only a call site holding the record may set them.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::{ActorType, Attribution, Principal, TokenVerifiedFields};

fn attribution() -> Attribution {
    Attribution {
        principal: Principal::Token("claude-test".to_owned()),
        actor_type: ActorType::Agent,
        agent: None,
        on_behalf_of: None,
        change_ref: None,
        request_id: uuid::Uuid::nil(),
        token_verified_fields: TokenVerifiedFields::default(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

/// The two-person evidence is carried, and carried separately.
///
/// `approver` must not be conflated with `change_ref`: that field is an external
/// change-control reference such as a ticket id, is supplied by the caller, and
/// is absent on most applies. An auditor asking "who else signed this off" and an
/// auditor asking "which ticket authorised this" are asking different questions.
#[test]
fn attribution_carries_the_approver_and_change_set() {
    let mut attribution = attribution();
    attribution.approver = Some("codex-approver".to_owned());
    attribution.change_set_id = Some("86324b20a3ecbfde".to_owned());

    assert_eq!(attribution.approver.as_deref(), Some("codex-approver"));
    assert_eq!(
        attribution.change_set_id.as_deref(),
        Some("86324b20a3ecbfde")
    );
    assert_eq!(
        attribution.change_ref, None,
        "the approver must not be written into the external change reference"
    );
}

/// `with_change_set` is the seam a call site holding the record uses.
#[test]
fn with_change_set_sets_both_fields() {
    let mut attribution = attribution();
    attribution.with_change_set("86324b20a3ecbfde", Some("codex-approver"));

    assert_eq!(
        attribution.change_set_id.as_deref(),
        Some("86324b20a3ecbfde")
    );
    assert_eq!(attribution.approver.as_deref(), Some("codex-approver"));
}

/// A waived or single-operator apply has a change set but no approver.
///
/// The absence must survive as an absence. Inventing a value here would put a
/// name on a device's commit log that never approved anything.
#[test]
fn with_change_set_leaves_an_absent_approver_absent() {
    let mut attribution = attribution();
    attribution.with_change_set("86324b20a3ecbfde", None);

    assert_eq!(
        attribution.change_set_id.as_deref(),
        Some("86324b20a3ecbfde")
    );
    assert_eq!(
        attribution.approver, None,
        "a waived apply has no approver, and none may be invented"
    );
}

/// A token cannot vouch for an approver, so building from one must not claim it.
#[test]
fn from_caller_never_invents_an_approver_or_change_set() {
    use mecmcp_auth::{CallerCtx, NoGrant, ScopeSet};

    let ctx: CallerCtx<NoGrant> = CallerCtx {
        token_name: "claude-test".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: mecmcp_auth::ActorType::Agent,
        oidc_subject: None,
        verified_approver: None,
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::nil(),
    };

    let attribution = Attribution::from_caller(&ctx);

    assert_eq!(
        attribution.approver, None,
        "only the change-set store knows the approver; a token cannot vouch for one"
    );
    assert_eq!(
        attribution.change_set_id, None,
        "a caller context does not identify a change set"
    );
}
