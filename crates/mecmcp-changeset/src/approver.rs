//! The identity of the principal approving a change set (MEC-994 W4).
//!
//! Replaces the old `approver_actor_type: ActorType` parameter to
//! `approve_change_set`: an actor type alone says "this token is declared
//! human", which is a label the token's own owner chose at `token add` time.
//! It says nothing about who is actually holding it. [`ApproverIdentity`]
//! carries that distinction through the rest of the crate so the approval
//! digest and the strict-mode gate can tell the two apart.

/// Identity of the principal approving a change set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverIdentity {
    /// The approver is known only by their bearer token's declared actor
    /// type — the identity assertion that predates MEC-994, and the only
    /// one available when no IdP is configured.
    TokenAsserted {
        /// Principal identifier (token name).
        principal: String,
        /// The token's declared actor type. Must be `Human` for the
        /// approval to succeed; carried here rather than checked by the
        /// caller so every call site is judged by the same rule.
        actor_type: mecmcp_audit::ActorType,
    },
    /// The approver additionally presented a fresh IdP-issued JWT, verified
    /// and bound to their token by `mecmcp_auth::bind_approver` (W3). A
    /// bound assertion only ever comes from a `human` token, so this variant
    /// never needs a separate actor-type check.
    ///
    /// Carries a crate-private payload type precisely so outside callers
    /// cannot name it: Rust gives struct-variant fields the same visibility
    /// as the enum itself, so a `pub` enum cannot restrict `{ principal,
    /// issuer, subject }` fields directly. Wrapping them in
    /// `OidcVerifiedFields`, which has no `pub` on its declaration, closes
    /// that gap — a caller outside this crate cannot write
    /// `ApproverIdentity::OidcVerified(..)` with a literal because it cannot
    /// name the payload type. The only way to produce this variant is
    /// [`ApproverIdentity::from_attribution`], which reads
    /// `Attribution::verified_approver` — a field only `bind_approver`
    /// (mecmcp-transport's bearer preflight) ever populates. A caller cannot
    /// build this from a tool argument, which would be exactly the "model
    /// output decides an approval" path the house rule forbids.
    #[allow(private_interfaces)]
    OidcVerified(OidcVerifiedFields),
}

/// Payload of [`ApproverIdentity::OidcVerified`].
///
/// Deliberately `pub(crate)`, not `pub`: the `private_interfaces` lint
/// expects a tuple-variant payload to be as visible as the enum itself, but
/// that is exactly what this type must NOT be — a caller outside this crate
/// must not be able to name it or construct the variant. See the variant's
/// doc comment for why that matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OidcVerifiedFields {
    /// Principal identifier (token name).
    principal: String,
    /// The IdP issuer that signed the verified assertion.
    issuer: String,
    /// The IdP's `sub` claim for the approver.
    subject: String,
}

impl ApproverIdentity {
    /// Derive the approver identity a caller actually presented, from the
    /// `Attribution` built off their authenticated `CallerCtx`.
    ///
    /// Returns `OidcVerified` iff `attribution.verified_approver` is
    /// `Some` — i.e. iff the bearer preflight's `bind_approver` check
    /// passed for this request (MEC-994 W3). Otherwise falls back to the
    /// pre-MEC-994 `TokenAsserted` identity. This is the only public
    /// constructor for `OidcVerified`; see its doc comment for why.
    #[must_use]
    pub fn from_attribution(attribution: &mecmcp_audit::Attribution) -> Self {
        let principal = attribution.principal.to_string();
        match &attribution.verified_approver {
            Some(approver) => Self::OidcVerified(OidcVerifiedFields {
                principal,
                issuer: approver.issuer.clone(),
                subject: approver.subject.clone(),
            }),
            None => Self::TokenAsserted {
                principal,
                actor_type: attribution.actor_type,
            },
        }
    }

    /// The principal identifier, regardless of how it was asserted.
    #[must_use]
    pub fn principal(&self) -> &str {
        match self {
            Self::TokenAsserted { principal, .. } => principal,
            Self::OidcVerified(fields) => &fields.principal,
        }
    }

    /// Whether this identity satisfies the house rule that a human approves.
    pub(crate) fn is_human(&self) -> bool {
        match self {
            Self::TokenAsserted { actor_type, .. } => *actor_type == mecmcp_audit::ActorType::Human,
            Self::OidcVerified(_) => true,
        }
    }

    /// The mechanism name signed into the v7 approval digest.
    pub(crate) fn mechanism(&self) -> &'static str {
        match self {
            Self::TokenAsserted { .. } => "token",
            Self::OidcVerified(_) => "oidc",
        }
    }

    /// The verified `(issuer, subject)` pair, when this identity carries one.
    pub(crate) fn oidc_subject(&self) -> Option<(&str, &str)> {
        match self {
            Self::OidcVerified(fields) => Some((fields.issuer.as_str(), fields.subject.as_str())),
            Self::TokenAsserted { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_asserted_human_is_human() {
        let identity = ApproverIdentity::TokenAsserted {
            principal: "alice".to_owned(),
            actor_type: mecmcp_audit::ActorType::Human,
        };
        assert!(identity.is_human());
        assert_eq!(identity.mechanism(), "token");
        assert_eq!(identity.oidc_subject(), None);
    }

    #[test]
    fn token_asserted_agent_is_not_human() {
        let identity = ApproverIdentity::TokenAsserted {
            principal: "agent-1".to_owned(),
            actor_type: mecmcp_audit::ActorType::Agent,
        };
        assert!(!identity.is_human());
    }

    #[test]
    fn oidc_verified_is_human_and_carries_subject() {
        let identity = ApproverIdentity::OidcVerified(OidcVerifiedFields {
            principal: "bob".to_owned(),
            issuer: "https://idp.example".to_owned(),
            subject: "bob-sub".to_owned(),
        });
        assert!(identity.is_human());
        assert_eq!(identity.mechanism(), "oidc");
        assert_eq!(
            identity.oidc_subject(),
            Some(("https://idp.example", "bob-sub"))
        );
        assert_eq!(identity.principal(), "bob");
    }

    fn test_attribution(
        principal: &str,
        actor_type: mecmcp_audit::ActorType,
        verified_approver: Option<mecmcp_auth::VerifiedApprover>,
    ) -> mecmcp_audit::Attribution {
        mecmcp_audit::Attribution {
            principal: mecmcp_audit::Principal::Token(principal.to_owned()),
            actor_type,
            agent: None,
            on_behalf_of: None,
            change_ref: None,
            request_id: uuid::Uuid::nil(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::default(),
            verified_approver,
            approver: None,
            change_set_id: None,
        }
    }

    #[test]
    fn from_attribution_without_verified_approver_is_token_asserted() {
        let attribution = test_attribution("alice", mecmcp_audit::ActorType::Human, None);
        let identity = ApproverIdentity::from_attribution(&attribution);
        assert_eq!(
            identity,
            ApproverIdentity::TokenAsserted {
                principal: "alice".to_owned(),
                actor_type: mecmcp_audit::ActorType::Human,
            }
        );
    }

    #[test]
    fn from_attribution_with_verified_approver_is_oidc_verified() {
        let attribution = test_attribution(
            "bob",
            mecmcp_audit::ActorType::Human,
            Some(mecmcp_auth::VerifiedApprover::for_test(
                "https://idp.example",
                "bob-sub",
            )),
        );
        let identity = ApproverIdentity::from_attribution(&attribution);
        assert_eq!(
            identity,
            ApproverIdentity::OidcVerified(OidcVerifiedFields {
                principal: "bob".to_owned(),
                issuer: "https://idp.example".to_owned(),
                subject: "bob-sub".to_owned(),
            })
        );
    }
}
