//! Attribution: the principal, actor type, and optional agent identity behind an action.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Who is acting. The authenticated and unauthenticated cases are distinct
/// variants rather than sentinel strings, so no token name can forge the
/// unauthenticated case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// An authenticated bearer token, identified by its non-secret name.
    Token(String),
    /// The stdio / `--allow-no-auth` path, where no credential was presented.
    Unauthenticated,
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Token(name) => write!(f, "{name}"),
            Principal::Unauthenticated => write!(f, "stdio"),
        }
    }
}

/// The type of actor performing an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    /// A human operator directly invoking a tool.
    Human,
    /// An autonomous agent (LLM-driven or otherwise) acting under delegation.
    Agent,
    /// Actor type is unknown (untagged legacy credential or no data available).
    Unknown,
}

/// LLM provider tier: public hosted vs. private/self-hosted deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Publicly hosted LLM service (e.g., Anthropic's public API).
    #[default]
    Public,
    /// Private or self-hosted LLM deployment.
    Private,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Public => write!(f, "public"),
            Tier::Private => write!(f, "private"),
        }
    }
}

/// Identity of an agent actor: the model, session, MCP client, provider, and skills used.
///
/// This provenance information flows into commit comments and audit events,
/// making committed changes traceable to the model and skills that generated
/// them (SSDF provenance tracking, mecmcp#26).
///
/// # Trust boundary
///
/// When present in an `Attribution`, the `provider` and `provider_tier` fields
/// may be server-verified (sourced from the token entry) or client-asserted
/// (relayed from the MCP caller). The other fields — `model_id`, `session_id`,
/// `client_name`, `skills_used` — are ALWAYS client-asserted and can never be
/// server-verified. The `Attribution::token_verified_fields` marker indicates
/// whether the token-bound subset (`provider`, `provider_tier`) was read from
/// the server's own token entry; it does NOT imply that the client-asserted
/// fields are verified. An audit consumer must not treat `model_id` or
/// `skills_used` as trustworthy solely because `token_verified_fields` is true.
///
/// # Skill naming constraint
///
/// Skill names MUST NOT contain spaces — they are joined with a single space
/// in the provenance string to maintain exactly 4 comma-separated fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Model identifier (e.g. `"claude-sonnet-4-5"`). ALWAYS client-asserted.
    pub model_id: String,
    /// Agent session or run identifier. ALWAYS client-asserted.
    pub session_id: String,
    /// MCP client name or user-agent, if known. ALWAYS client-asserted.
    pub client_name: Option<String>,
    /// Provider name (e.g., "anthropic", "ollama"). May be server-verified or
    /// client-asserted; see `Attribution::token_verified_fields`.
    ///
    /// Defaults to `"unknown"` if absent (existing audit events without this field).
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Provider tier: public hosted vs. private/self-hosted. May be server-verified
    /// or client-asserted; see `Attribution::token_verified_fields`.
    ///
    /// Defaults to `Public` if absent (existing audit events without this field).
    #[serde(default)]
    pub provider_tier: Tier,
    /// Skills invoked during this action. ALWAYS client-asserted.
    ///
    /// Defaults to an empty list (existing audit events without this field).
    #[serde(default)]
    pub skills_used: Vec<String>,
}

fn default_provider() -> String {
    "unknown".to_string()
}

impl AgentIdentity {
    /// Render the canonical provenance string for commit comments and audit.
    ///
    /// Format: `{provider}-{tier}, {model_id}, {skills}, {user}`
    ///
    /// Example: `"anthropic-public, claude-opus-5, none, dev@example.com"`
    ///
    /// The provider name comes from the `provider` field (explicit data, not inferred).
    /// Skills render as space-separated names, or "none" if the list is empty.
    /// The user is the human on whose behalf the agent acts (`on_behalf_of`).
    ///
    /// If `on_behalf_of` is `None`, the rendered string is still valid; the last
    /// component is omitted (e.g., `"anthropic-public, claude-opus-5, none"`).
    pub fn provenance_string(&self, on_behalf_of: Option<&str>) -> String {
        let provider_tier = format!("{}-{}", self.provider, self.provider_tier).to_lowercase();
        let skills = if self.skills_used.is_empty() {
            "none".to_string()
        } else {
            self.skills_used.join(" ")
        };
        match on_behalf_of {
            Some(user) => format!("{}, {}, {}, {}", provider_tier, self.model_id, skills, user),
            None => format!("{}, {}, {}", provider_tier, self.model_id, skills),
        }
    }
}

/// Structured attribution: who is acting, under whose authority, and for what change.
///
/// This type is constructed from a [`mecmcp_auth::CallerCtx`] at the top of
/// a handler and carried through the audit and change-control paths. It is
/// never serialized with secrets: a `Principal::Token` carries only the token
/// name (not the secret itself), and the rest are metadata.
#[derive(Debug, Clone)]
pub struct Attribution {
    /// The authenticated principal, or the unauthenticated stdio path.
    pub principal: Principal,
    /// Whether the actor is a human or an agent.
    pub actor_type: ActorType,
    /// Agent identity, when `actor_type == Agent`.
    pub agent: Option<AgentIdentity>,
    /// The human on whose behalf an agent is acting, if applicable.
    pub on_behalf_of: Option<String>,
    /// An external change-control reference (e.g. a ticket ID).
    pub change_ref: Option<String>,
    /// Per-request correlation ID.
    pub request_id: Uuid,
    /// Whether the token-bound provenance fields were server-verified.
    ///
    /// This marker applies ONLY to the subset of fields that can be bound to
    /// a server-side token entry: `actor_type`, `on_behalf_of`, and when
    /// `agent` is present, its `provider` and `provider_tier`. It does NOT
    /// cover `AgentIdentity`'s `model_id`, `session_id`, `client_name`, or
    /// `skills_used` — those are ALWAYS client-asserted and can never be
    /// server-verified.
    ///
    /// This must be recorded, not inferred. The token-bound fields can be
    /// populated either by the server from the token entry or by a call site
    /// relaying what the client claimed, and the resulting `Attribution` looks
    /// identical either way. An auditor reading the event needs to know which
    /// it was — that is the whole point of mecmcp#52 — so the fact is carried
    /// explicitly from the one place that knows it.
    pub token_verified_fields: TokenVerifiedFields,
    /// The verified approver identity bound to this request, when a
    /// `Mecmcp-Approver-Assertion` header passed `bind_approver` (MEC-994
    /// W3). `None` for every call that carried no assertion — which, before
    /// W4 lands, is every call: nothing populates this on `CallerCtx` yet.
    pub verified_approver: Option<mecmcp_auth::VerifiedApprover>,
    /// The second principal who approved, when applied under two-person control.
    ///
    /// Distinct from `change_ref`, which is an external change-control reference
    /// such as a ticket id. "Who else signed this off" and "which ticket
    /// authorised this" are different questions, and collapsing them would make
    /// the two-person evidence unreadable wherever a ticket was also supplied.
    ///
    /// Never populated by [`from_caller`](Self::from_caller): a token cannot
    /// vouch for who approved a change set. Only a call site holding the
    /// change-set record can set this, via
    /// [`with_change_set`](Self::with_change_set).
    ///
    /// `None` on a single-operator or waived apply, and that absence must
    /// survive — inventing a value here would put a name on a device's commit
    /// log that approved nothing (rustjunosmcp#307).
    pub approver: Option<String>,
    /// The change set this action belongs to.
    ///
    /// Carried so the durable record on the device can name it. `request_id`
    /// already correlates a commit to its audit event, but only for someone
    /// holding both artifacts and knowing to join them; the change-set id is
    /// what the server's own store is keyed by.
    ///
    /// Never populated by [`from_caller`](Self::from_caller) — a caller context
    /// does not identify a change set.
    pub change_set_id: Option<String>,
}

/// Which provenance fields the server read from the token entry.
///
/// Recorded per field rather than as one verdict over the group. An attribution
/// routinely mixes sources: a token may bind `on_behalf_of` while a handler
/// supplies a client-asserted `provider`, and a single "verified" flag would
/// then vouch for the provider too. Naming the fields individually is the only
/// form an audit consumer can act on.
///
/// Never covers `AgentIdentity`'s `model_id`, `session_id`, `client_name` or
/// `skills_used`. Those are client-asserted by nature and can never be verified
/// here, whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenVerifiedFields {
    /// `actor_type` came from the token entry.
    pub actor_type: bool,
    /// `on_behalf_of` came from the token entry.
    pub on_behalf_of: bool,
    /// `provider` and `provider_tier` came from the token entry. They are
    /// validated as a pair, so one flag covers both.
    pub provider: bool,
}

impl TokenVerifiedFields {
    /// Nothing was read from the token entry.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

impl fmt::Display for TokenVerifiedFields {
    /// Renders the verified field names, or `none`. The audit event carries this
    /// verbatim so a SIEM query can name the fields it is willing to trust.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names = Vec::new();
        if self.actor_type {
            names.push("actor_type");
        }
        if self.on_behalf_of {
            names.push("on_behalf_of");
        }
        if self.provider {
            names.push("provider");
        }
        if names.is_empty() {
            return write!(f, "none");
        }
        write!(f, "{}", names.join(","))
    }
}

impl Attribution {
    /// Build an attribution from an authenticated context.
    ///
    /// Propagates server-verified provenance fields from the token entry:
    /// `actor_type`, `on_behalf_of`, and when the token declares a provider,
    /// an `AgentIdentity` populated with the verified `provider` and
    /// `provider_tier`. The client-asserted `client_name` is populated from
    /// `CallerCtx` when available (captured from the MCP session). Other
    /// client-asserted fields (`model_id`, `session_id`, `skills_used`) are
    /// left at their empty defaults — they are not knowable at this point
    /// and must not be invented.
    ///
    /// The `request_id` is taken from `CallerCtx`, so every attribution built
    /// from one caller context shares it. That is what makes the transport
    /// preflight event and the handler's enriched event joinable (mecmcp#269).
    pub fn from_caller<G>(ctx: &mecmcp_auth::CallerCtx<G>) -> Self
    where
        G: mecmcp_auth::Grant,
    {
        // Convert mecmcp_auth::ActorType to mecmcp_audit::ActorType.
        let actor_type = match ctx.actor_type {
            mecmcp_auth::ActorType::Human => ActorType::Human,
            mecmcp_auth::ActorType::Agent => ActorType::Agent,
            mecmcp_auth::ActorType::Unknown => ActorType::Unknown,
        };

        // When the token declares a provider, populate an AgentIdentity with
        // server-verified fields. Client-asserted provenance (client_name, model_id,
        // session_id) is populated from CallerCtx if available (captured from the
        // MCP session during bearer preflight).
        let agent = match (&ctx.provider, ctx.provider_tier) {
            (Some(provider), Some(tier)) => Some(AgentIdentity {
                model_id: ctx.model_id.map(String::from).unwrap_or_default(),
                session_id: ctx.session_id.clone().unwrap_or_default(),
                client_name: ctx.client_name.map(String::from),
                provider: provider.clone(),
                provider_tier: match tier {
                    mecmcp_auth::Tier::Public => Tier::Public,
                    mecmcp_auth::Tier::Private => Tier::Private,
                },
                skills_used: Vec::new(),
            }),
            _ => {
                // Create an AgentIdentity if any client-asserted field is present.
                if ctx.client_name.is_some() || ctx.model_id.is_some() || ctx.session_id.is_some() {
                    Some(AgentIdentity {
                        model_id: ctx.model_id.map(String::from).unwrap_or_default(),
                        session_id: ctx.session_id.clone().unwrap_or_default(),
                        client_name: ctx.client_name.map(String::from),
                        provider: default_provider(),
                        provider_tier: Tier::default(),
                        skills_used: Vec::new(),
                    })
                } else {
                    None
                }
            }
        };

        // The token entry is the server's own record, so anything it declared is
        // verified by construction. Mark as verified only if at least one
        // token-bound field was explicitly set (not defaulted). A token with
        // provider requires provider_tier (enforced by validation), and both
        // on_behalf_of and actor_type are Option/enum with no "implicit true".
        // This prevents a freshly minted token with no provenance arguments from
        // producing a `Verified` marker on the strength of defaults alone (defect #2).
        // Recorded per field, not as one verdict over the group. A token can bind
        // `on_behalf_of` and nothing else, and a handler may then enrich the same
        // attribution with a client-asserted provider; a single "verified" flag
        // would sit next to that provider in the audit event and vouch for it.
        let token_verified_fields = TokenVerifiedFields {
            actor_type: ctx.actor_type != mecmcp_auth::ActorType::Unknown,
            on_behalf_of: ctx.on_behalf_of.is_some(),
            provider: ctx.provider.is_some(),
        };

        Self {
            principal: Principal::Token(ctx.token_name.clone()),
            actor_type,
            agent,
            on_behalf_of: ctx.on_behalf_of.clone(),
            change_ref: None,
            // Read from the caller context rather than minted here, so the
            // transport preflight event and the handler's enriched event for
            // one request carry the same ID and can be joined (mecmcp#269).
            // Minting per call is what made that correlation impossible.
            request_id: ctx.request_id,
            token_verified_fields,
            verified_approver: ctx.verified_approver.clone(),
            // A token cannot vouch for who approved a change set, nor identify
            // one. Only a call site holding the record may set these.
            approver: None,
            change_set_id: None,
        }
    }

    /// Build an attribution for the stdio / no-auth path.
    ///
    /// The principal is `Principal::Unauthenticated` and the actor type is
    /// `Unknown`: no credential was presented, so there is nothing to read it
    /// from. The stdio path is at least as often a desktop MCP client as a
    /// human at a terminal, so assuming either would put a guess into the
    /// audit trail.
    pub fn stdio() -> Self {
        Self {
            principal: Principal::Unauthenticated,
            actor_type: ActorType::Unknown,
            agent: None,
            on_behalf_of: None,
            change_ref: None,
            request_id: Uuid::new_v4(),
            token_verified_fields: TokenVerifiedFields::none(),
            verified_approver: None,
            // Never derived from a caller: only a change-set record knows these.
            approver: None,
            change_set_id: None,
        }
    }

    /// Attach a client name to this attribution.
    ///
    /// If this attribution has an `AgentIdentity`, the name is set on it. If
    /// there is no `AgentIdentity` yet, one is created with `provider` and
    /// `provider_tier` set to their defaults ("unknown" and `Tier::Public`)
    /// and other client-asserted fields left empty — this matches the defaults
    /// used throughout the audit system and ensures consistency.
    ///
    /// The client name is ALWAYS client-asserted and can never be server-verified,
    /// regardless of what `token_verified_fields` says. Callers must NOT add
    /// `client_name` to the verified fields marker.
    pub fn with_client_name(&mut self, name: &'static str) {
        if let Some(ref mut agent) = self.agent {
            agent.client_name = Some(name.to_string());
        } else {
            // No AgentIdentity exists yet. Create one with the client name and
            // defaults that match existing audit conventions: provider="unknown",
            // provider_tier=Public, all other client-asserted fields empty.
            self.agent = Some(AgentIdentity {
                model_id: String::new(),
                session_id: String::new(),
                client_name: Some(name.to_string()),
                provider: default_provider(),
                provider_tier: Tier::default(),
                skills_used: Vec::new(),
            });
        }
    }

    /// Record the change set being applied, and the approver if there was one.
    ///
    /// The seam for a call site that holds the change-set record — the only
    /// place that knows either value. `approver` is `None` for a waived or
    /// single-operator apply, and is stored as `None`: an absent approver is a
    /// fact about the change, not a gap to fill.
    pub fn with_change_set(&mut self, change_set_id: &str, approver: Option<&str>) {
        self.change_set_id = Some(change_set_id.to_owned());
        self.approver = approver.map(str::to_owned);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
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
    fn from_caller_with_untagged_token_yields_unknown() {
        let c = ctx("legacy-token");
        let a = Attribution::from_caller(&c);
        assert_eq!(a.principal, Principal::Token("legacy-token".into()));
        assert_eq!(a.actor_type, ActorType::Unknown);
        assert!(a.agent.is_none());
        assert!(a.on_behalf_of.is_none());
        assert!(a.change_ref.is_none());
    }

    #[test]
    fn stdio_attribution_is_usable() {
        let a = Attribution::stdio();
        assert_eq!(a.principal, Principal::Unauthenticated);
        // No credential was presented, so the actor is genuinely unknown. The
        // stdio path is at least as often an agent (a desktop MCP client) as a
        // human at a terminal, and recording either would be a guess.
        assert_eq!(a.actor_type, ActorType::Unknown);
        assert_eq!(a.token_verified_fields, TokenVerifiedFields::none());
        assert!(a.agent.is_none());
    }

    #[test]
    fn principal_display_renders_wire_format() {
        assert_eq!(Principal::Token("ci".into()).to_string(), "ci");
        assert_eq!(Principal::Unauthenticated.to_string(), "stdio");
    }

    /// One caller context means one request, so its attributions must agree.
    ///
    /// This replaces `correlation_ids_are_unique`, which asserted the opposite —
    /// that two attributions built from the *same* `CallerCtx` carry different
    /// IDs. That is precisely the defect in mecmcp#269: it is what made the
    /// transport event and the handler event for a single request impossible to
    /// join. The old test encoded the bug as the intended contract, which is why
    /// nothing here ever flagged it.
    #[test]
    fn one_caller_context_yields_one_correlation_id() {
        let c = ctx("ci");
        let a1 = Attribution::from_caller(&c);
        let a2 = Attribution::from_caller(&c);
        assert_eq!(
            a1.request_id, a2.request_id,
            "every attribution built from one caller context describes one \
             request and must share its correlation ID"
        );
        assert_eq!(
            a1.request_id, c.request_id,
            "the ID must come from the caller context, not be minted here"
        );
    }

    /// Distinct requests must still be distinguishable.
    ///
    /// Guards the other direction: sharing the ID within a request must not
    /// collapse into sharing it across requests.
    #[test]
    fn separate_caller_contexts_yield_distinct_correlation_ids() {
        let first = Attribution::from_caller(&ctx("ci"));
        let second = Attribution::from_caller(&ctx("ci"));
        assert_ne!(
            first.request_id, second.request_id,
            "two authentications are two requests and must not share an ID"
        );
    }

    #[test]
    fn agent_attribution_round_trips_identity() {
        let c = ctx("agent-token");
        let mut a = Attribution::from_caller(&c);
        a.actor_type = ActorType::Agent;
        a.agent = Some(AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-12345".into(),
            client_name: Some("mcp-client/1.0".into()),
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        });
        a.on_behalf_of = Some("alice".into());
        a.change_ref = Some("CHG0012345".into());

        assert_eq!(a.actor_type, ActorType::Agent);
        let agent = a.agent.as_ref().unwrap();
        assert_eq!(agent.model_id, "claude-sonnet-4-5");
        assert_eq!(agent.session_id, "sess-12345");
        assert_eq!(agent.client_name.as_deref(), Some("mcp-client/1.0"));
        assert_eq!(agent.provider, "anthropic");
        assert_eq!(agent.provider_tier, Tier::Public);
        assert_eq!(a.on_behalf_of.as_deref(), Some("alice"));
        assert_eq!(a.change_ref.as_deref(), Some("CHG0012345"));
    }

    #[test]
    fn provenance_string_renders_canonical_format() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("dev@example.com")),
            "anthropic-public, claude-opus-5, none, dev@example.com"
        );
    }

    #[test]
    fn provenance_string_with_skills() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec!["srx-nat".into(), "srx-policy".into(), "srx-mnha".into()],
        };
        assert_eq!(
            agent.provenance_string(Some("dev@example.com")),
            "anthropic-public, claude-opus-5, srx-nat srx-policy srx-mnha, dev@example.com"
        );
    }

    #[test]
    fn provenance_string_private_tier() {
        let agent = AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Private,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("bob")),
            "anthropic-private, claude-sonnet-4-5, none, bob"
        );
    }

    #[test]
    fn provenance_string_without_user() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(None),
            "anthropic-public, claude-opus-5, none"
        );
    }

    #[test]
    fn provenance_string_ollama_private() {
        let agent = AgentIdentity {
            model_id: "llama-3.3-70b".into(),
            session_id: "sess-local".into(),
            client_name: None,
            provider: "ollama".into(),
            provider_tier: Tier::Private,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("user")),
            "ollama-private, llama-3.3-70b, none, user"
        );
    }

    #[test]
    fn provenance_field_count_is_stable() {
        // Field count must be exactly 4 for zero, one, and three skills
        let zero = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "s".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        let one = AgentIdentity {
            skills_used: vec!["srx-nat".into()],
            ..zero.clone()
        };
        let three = AgentIdentity {
            skills_used: vec!["srx-nat".into(), "srx-policy".into(), "srx-mnha".into()],
            ..zero.clone()
        };

        for (agent, label) in [(zero, "zero"), (one, "one"), (three, "three")] {
            let s = agent.provenance_string(Some("user"));
            let field_count = s.split(", ").count();
            assert_eq!(
                field_count, 4,
                "{} skills must produce 4 fields, got {}: {}",
                label, field_count, s
            );
        }
    }

    #[test]
    fn backward_compat_deserializes_old_json_without_new_fields() {
        // Existing audit JSON without provider, provider_tier, or skills_used
        let json = r#"{
            "model_id": "claude-sonnet-4-5",
            "session_id": "sess-old",
            "client_name": "old-client"
        }"#;
        let agent: AgentIdentity = serde_json::from_str(json).unwrap();
        assert_eq!(agent.model_id, "claude-sonnet-4-5");
        assert_eq!(agent.provider, "unknown"); // default
        assert_eq!(agent.provider_tier, Tier::Public); // default
        assert!(agent.skills_used.is_empty()); // default
    }

    #[test]
    #[should_panic(expected = "missing field")]
    fn removing_default_breaks_backward_compat() {
        // This test proves that removing #[serde(default)] would break old JSON.
        // It must panic if we remove the defaults.
        let json = r#"{
            "model_id": "claude-sonnet-4-5",
            "session_id": "sess-old"
        }"#;
        // If provider, provider_tier, or skills_used lacked #[serde(default)],
        // this would fail. We use #[should_panic] to document the expectation, but
        // in reality the test above (backward_compat_deserializes_old_json_without_new_fields)
        // passing proves the defaults work.
        //
        // To actually test the negative case, we'd need to conditionally compile
        // without the defaults, which is beyond the scope here. This test documents
        // the intent: removing defaults MUST break old JSON parsing.
        #[allow(dead_code)]
        #[derive(Deserialize)]
        struct AgentWithoutDefaults {
            model_id: String,
            session_id: String,
            client_name: Option<String>,
            provider: String,         // no default
            provider_tier: Tier,      // no default
            skills_used: Vec<String>, // no default
        }
        let _: AgentWithoutDefaults = serde_json::from_str(json).unwrap();
    }

    #[test]
    fn from_caller_propagates_token_verified_provenance() {
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
        let a = Attribution::from_caller(&ctx);

        assert_eq!(a.principal, Principal::Token("claude-code-ops".into()));
        assert_eq!(a.actor_type, ActorType::Agent);
        assert_eq!(
            a.on_behalf_of.as_deref(),
            Some("dev@example.com"),
            "on_behalf_of must flow from token entry"
        );

        let agent = a
            .agent
            .as_ref()
            .expect("agent identity must be populated when token declares provider");
        assert_eq!(
            agent.provider, "anthropic",
            "provider must come from token entry"
        );
        assert_eq!(
            agent.provider_tier,
            Tier::Public,
            "provider_tier must come from token entry"
        );
        assert_eq!(
            agent.model_id, "",
            "model_id is client-asserted, must not be invented"
        );
        assert_eq!(
            agent.session_id, "",
            "session_id is client-asserted, must not be invented"
        );
        assert!(
            agent.client_name.is_none(),
            "client_name is client-asserted, must not be invented"
        );
        assert!(
            agent.skills_used.is_empty(),
            "skills_used is client-asserted, must not be invented"
        );
    }

    #[test]
    fn from_caller_human_token_does_not_populate_agent() {
        let ctx: CallerCtx<NoGrant> = CallerCtx {
            token_name: "human-operator".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: Some("alice@example.com".into()),
            actor_type: mecmcp_auth::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let a = Attribution::from_caller(&ctx);

        assert_eq!(a.actor_type, ActorType::Human);
        assert!(a.agent.is_none(), "human tokens must not populate agent");
        assert_eq!(
            a.on_behalf_of.as_deref(),
            Some("alice@example.com"),
            "on_behalf_of can be set for human tokens too"
        );
    }

    #[test]
    fn token_with_no_provenance_does_not_produce_verified_marker() {
        // Defect 2: a token minted with no provenance arguments must NOT emit
        // a verified marker. The add path defaults actor_type to
        // Unknown, and from_caller must not treat that default as server-verified.
        let c: CallerCtx<NoGrant> = CallerCtx {
            token_name: "automation".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Unknown, // defaulted, not explicit
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let a = Attribution::from_caller(&c);
        assert_eq!(a.actor_type, ActorType::Unknown);
        assert_eq!(
            a.token_verified_fields,
            TokenVerifiedFields::none(),
            "a token with all defaults must NOT produce Verified"
        );
        assert!(a.agent.is_none());
        assert!(a.on_behalf_of.is_none());
    }

    #[test]
    fn token_with_explicit_actor_type_is_verified() {
        // When actor_type is explicitly set (not defaulted), it's server-verified.
        let c: CallerCtx<NoGrant> = CallerCtx {
            token_name: "agent-token".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Agent, // explicit
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let a = Attribution::from_caller(&c);
        assert_eq!(a.actor_type, ActorType::Agent);
        assert_eq!(
            a.token_verified_fields,
            TokenVerifiedFields {
                actor_type: true,
                on_behalf_of: false,
                provider: false,
            },
            "only actor_type was bound by the token"
        );
    }

    #[test]
    fn token_with_provider_is_verified() {
        // When provider and provider_tier are set, they're server-verified.
        let c: CallerCtx<NoGrant> = CallerCtx {
            token_name: "agent-token".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: Some("anthropic".into()),
            provider_tier: Some(mecmcp_auth::Tier::Public),
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let a = Attribution::from_caller(&c);
        assert_eq!(
            a.token_verified_fields,
            TokenVerifiedFields {
                actor_type: true,
                on_behalf_of: false,
                provider: true,
            },
            "provider was bound, and actor_type is derived from it server-side"
        );
        let agent = a.agent.as_ref().expect("agent identity present");
        assert_eq!(agent.provider, "anthropic");
        assert_eq!(agent.provider_tier, Tier::Public);
    }

    #[test]
    fn token_with_on_behalf_of_is_verified() {
        // When on_behalf_of is set, it's server-verified.
        let c: CallerCtx<NoGrant> = CallerCtx {
            token_name: "delegated".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: Some("alice@example.com".into()),
            actor_type: mecmcp_auth::ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let a = Attribution::from_caller(&c);
        assert_eq!(
            a.token_verified_fields,
            TokenVerifiedFields {
                actor_type: true,
                on_behalf_of: true,
                provider: false,
            },
            "this token bound both actor_type and on_behalf_of, but no provider"
        );
        assert_eq!(a.on_behalf_of.as_deref(), Some("alice@example.com"));
    }
}
