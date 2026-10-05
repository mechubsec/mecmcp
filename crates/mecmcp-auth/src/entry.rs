//! One token as persisted on disk, in a shape both existing servers can load.

use crate::grant::{Grant, GrantError, NoGrant};
use crate::scope::{ScopeError, ScopeSet};
use crate::token::TokenDigest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum length of an operator-facing token name.
pub const MAX_TOKEN_NAME: usize = 128;

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

/// The type of actor performing an action.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorType {
    /// A human operator directly invoking a tool.
    Human,
    /// An autonomous agent (LLM-driven or otherwise) acting under delegation.
    Agent,
    /// Actor type is unknown (untagged legacy token).
    ///
    /// This is the default for tokens that predated this field. Recording
    /// `Unknown` in audit trails is truthful: the token entry declared neither
    /// `Human` nor `Agent`, so the server cannot know. Defaulting to `Human`
    /// would fabricate a fact, violating the principle from issue #54 that
    /// audit provenance must never invent an actor to satisfy a schema.
    #[default]
    Unknown,
}

/// Default actor type for tokens that don't declare one.
///
/// Returns `Unknown` rather than `Human` or `Agent` because:
/// - The token entry provides no data, so the server cannot know which it is
/// - Recording `Human` for an untagged agent token would fabricate a fact
/// - Issue #54 mandates that audit provenance never invents an actor
fn default_actor_type() -> ActorType {
    ActorType::Unknown
}

/// An IdP subject a token is bound to, for verified-approver identity
/// (mecmcp#400 Phase 2 / MEC-994).
///
/// On a `human` token, this means only this IdP subject may use the token to
/// approve a change set. On an `agent` token, it records the human this agent
/// proposes for, so a proposal's `owner_subject` can later be compared
/// against an approver's verified subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcSubject {
    /// The IdP's issuer URL, matched against a verified JWT's `iss`.
    pub issuer: String,
    /// The IdP's `sub` claim identifying the human at that issuer.
    pub subject: String,
}

/// Rejection reason for a malformed token entry.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// A scope failed validation.
    #[error("token '{name}': {source}")]
    Scope {
        /// The offending token's name.
        name: String,
        /// The underlying scope error.
        #[source]
        source: ScopeError,
    },
    /// A grant failed validation.
    #[error("token '{name}': {source}")]
    Grant {
        /// The offending token's name.
        name: String,
        /// The underlying grant error.
        #[source]
        source: GrantError,
    },
    /// The entry failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// One digest-only token entry.
///
/// Field names are canonical (`digest`, `devices`). Aliases accept the
/// spellings rustjunosmcp wrote before extraction (`hash` for digest,
/// `routers` for devices) so deployed `tokens.json` files load unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry<G: Grant = NoGrant> {
    /// Operator-facing, non-secret token name. Used for audit attribution.
    pub name: String,

    /// Versioned token digest. Never plaintext.
    #[serde(alias = "hash")]
    pub digest: TokenDigest,

    /// Devices — or, for a management-plane server, targets — this token may
    /// address.
    ///
    /// `targets` is an additive alias, not a second field: a tenant-scoped
    /// server writes `targets` and reads it back through
    /// [`targets()`](Self::targets), while the canonical serialized spelling
    /// stays `devices` so every deployed `tokens.json` keeps round-tripping
    /// unchanged (#91).
    #[serde(alias = "routers", alias = "targets", default = "wildcard")]
    pub devices: ScopeSet,

    /// MCP tools this token may call.
    #[serde(default = "wildcard")]
    pub tools: ScopeSet,

    /// Creation or last-rotation time.
    ///
    /// Accepts RFC 3339 under `created_at` (the `rustjunosmcp` spelling) or a
    /// Unix timestamp under `created_at_unix` (the `rustpanosmcp` spelling).
    #[serde(alias = "created_at_unix", with = "timestamp")]
    pub created_at: DateTime<Utc>,

    /// Optional absolute expiry. An expired token never authenticates.
    #[serde(
        default,
        alias = "expires_at_unix",
        with = "optional_timestamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<DateTime<Utc>>,

    /// Optional vendor-specific write authority.
    #[serde(
        alias = "mutation",
        default = "no_grant",
        skip_serializing_if = "Option::is_none"
    )]
    pub grant: Option<G>,

    /// Provider name (e.g., "anthropic", "ollama").
    ///
    /// Server-verified provenance field. When present, the server populates
    /// `AgentIdentity.provider` from this value rather than accepting it
    /// from the client. Absent for human-operator tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Provider tier: public hosted vs. private/self-hosted.
    ///
    /// Server-verified provenance field. Absent for human-operator tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_tier: Option<crate::Tier>,

    /// The human on whose behalf this credential acts.
    ///
    /// Server-verified provenance field. Populated for agent tokens acting
    /// under delegation (e.g., "dev@example.com"). May also be set for
    /// human-operator tokens to record the identity the token represents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,

    /// Whether this credential belongs to a human operator or an agent.
    ///
    /// Server-verified provenance field. Defaults to `Unknown` when absent,
    /// preserving the truthfulness of audit trails: an untagged token provides
    /// no data, so the server cannot assert `Human` or `Agent` without
    /// fabricating a fact (issue #54).
    #[serde(
        default = "default_actor_type",
        skip_serializing_if = "is_default_actor_type"
    )]
    pub actor_type: ActorType,

    /// The IdP subject this token is bound to, for verified-approver identity
    /// (MEC-994). Absent by default, so every existing `tokens.json` loads
    /// byte-for-byte unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_subject: Option<OidcSubject>,
}

/// Predicate for `skip_serializing_if` on `actor_type`.
fn is_default_actor_type(t: &ActorType) -> bool {
    matches!(t, ActorType::Unknown)
}

fn wildcard() -> ScopeSet {
    ScopeSet::Wildcard
}

/// The default grant: none.
///
/// Spelled as an explicit function rather than `#[serde(default)]` so serde's
/// derive does not add a `G: Default` bound. `Option<T>` needs no bound on `T`
/// to default to `None`, and requiring `Default` on a write-authority type
/// would force every consumer to define a "default write grant".
fn no_grant<G>() -> Option<G> {
    None
}

impl<G: Grant> TokenEntry<G> {
    /// The scope of targets this token may address.
    ///
    /// The same scope as [`devices`](Self::devices), under a target-neutral
    /// name. Management-plane consumers authorize tenants or sites rather than
    /// devices and should not have to spell those values `devices` to do it
    /// (#91). This is vocabulary only: one field, one set of rules.
    #[must_use]
    pub fn targets(&self) -> &ScopeSet {
        &self.devices
    }

    /// Whether this token is expired at the given instant.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }

    /// The actor type this credential should be read as.
    ///
    /// A token carrying provider metadata but no explicit actor type is an
    /// agent: nothing else has an LLM provider. Deriving it here rather than
    /// demanding the operator restate it keeps the documented token shape from
    /// issue #52 loadable, while `validate` still refuses the one combination
    /// that contradicts itself.
    ///
    /// Note the ambiguity this cannot resolve: `actor_type` deserializes to
    /// `Unknown` whether the key was omitted or written explicitly as
    /// `"unknown"`, so a hand-edited file declaring both a provider and an
    /// explicit `unknown` is read as an agent. The CLI refuses that combination
    /// at the point where the two are distinguishable.
    #[must_use]
    pub fn effective_actor_type(&self) -> ActorType {
        if self.provider.is_some() && self.actor_type == ActorType::Unknown {
            return ActorType::Agent;
        }
        self.actor_type
    }

    /// Validate name, scopes, grant, and provenance.
    ///
    /// # Errors
    /// Returns [`EntryError`] describing the first failing check.
    pub fn validate(&self) -> Result<(), EntryError> {
        if self.name.is_empty() || self.name.len() > MAX_TOKEN_NAME {
            return Err(EntryError::Invalid(format!(
                "token name must be 1-{MAX_TOKEN_NAME} characters"
            )));
        }
        if self.name.contains('\0') || self.name.contains(char::is_whitespace) {
            return Err(EntryError::Invalid(format!(
                "token name '{}' contains whitespace or a null byte",
                self.name
            )));
        }
        self.devices
            .validate("devices")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        self.tools
            .validate("tools")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        if let Some(grant) = &self.grant {
            grant.validate().map_err(|source| EntryError::Grant {
                name: self.name.clone(),
                source,
            })?;
        }
        // Provider and provider_tier must both be present or both be absent.
        match (&self.provider, &self.provider_tier) {
            (Some(_), None) => {
                return Err(EntryError::Invalid(format!(
                    "token '{}': provider is set but provider_tier is missing",
                    self.name
                )));
            }
            (None, Some(_)) => {
                return Err(EntryError::Invalid(format!(
                    "token '{}': provider_tier is set but provider is missing",
                    self.name
                )));
            }
            _ => {}
        }
        // An LLM provider only means something for an agent. Allowing a token to
        // declare `provider: anthropic` while claiming to be a human operator
        // produces a record that contradicts itself, and `Attribution::from_caller`
        // would build an agent identity for an actor typed as human. Reject the
        // combination rather than silently picking one side of it.
        // Only an explicit contradiction is rejected. An untagged token carrying
        // provider metadata is the shape issue #52 documents, and a hand-written
        // tokens.json in that form must load — rejecting it would fail the whole
        // store over a field the operator never had to state. `effective_actor_type`
        // reads such a token as an agent, since nothing but an agent has an LLM
        // provider.
        // Blank provenance is worse than absent: `Some("")` reads as declared, so
        // `from_caller` marks the field token-verified and the audit event then
        // carries a verified-but-empty provider or delegated user.
        for (field, value) in [
            ("provider", self.provider.as_deref()),
            ("on_behalf_of", self.on_behalf_of.as_deref()),
        ] {
            if value.is_some_and(|v| v.trim().is_empty()) {
                return Err(EntryError::Invalid(format!(
                    "token '{}': {field} is present but empty",
                    self.name
                )));
            }
        }
        if self.provider.is_some() && self.actor_type == ActorType::Human {
            return Err(EntryError::Invalid(format!(
                "token '{}': provider metadata contradicts actor_type \"human\"",
                self.name
            )));
        }
        if let Some(oidc_subject) = &self.oidc_subject {
            // Empty is rejected because it reads as declared (like the
            // provider/on_behalf_of blank check above). The approval digest
            // (see `compute_approval_digest_v7`) binds `(issuer, subject)` as
            // a serialized tuple, not a delimited string, so neither field
            // needs a character restriction to keep the two apart. A
            // restriction here would refuse subject shapes several IdPs
            // issue by default.
            for (field, value) in [
                ("oidc_subject.issuer", oidc_subject.issuer.as_str()),
                ("oidc_subject.subject", oidc_subject.subject.as_str()),
            ] {
                if value.trim().is_empty() {
                    return Err(EntryError::Invalid(format!(
                        "token '{}': {field} must not be empty",
                        self.name
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Accept a timestamp as either RFC 3339 (`rustjunosmcp`) or Unix seconds
/// (`rustpanosmcp`); always write RFC 3339.
mod timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Either on-disk spelling of an instant.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Rfc3339(DateTime<Utc>),
        Unix(i64),
    }

    impl Raw {
        fn into_datetime<E: serde::de::Error>(self) -> Result<DateTime<Utc>, E> {
            match self {
                Self::Rfc3339(value) => Ok(value),
                Self::Unix(seconds) => DateTime::from_timestamp(seconds, 0)
                    .ok_or_else(|| E::custom(format!("timestamp {seconds} is out of range"))),
            }
        }
    }

    pub(super) fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        Raw::deserialize(deserializer)?.into_datetime()
    }

    /// The `Option` form, for fields that may be absent entirely.
    pub(super) mod optional {
        use super::Raw;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            value: &Option<DateTime<Utc>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_str(&value.to_rfc3339()),
                None => serializer.serialize_none(),
            }
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            match Option::<Raw>::deserialize(deserializer)? {
                Some(raw) => raw.into_datetime().map(Some),
                None => Ok(None),
            }
        }
    }
}

use timestamp::optional as optional_timestamp;

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly the shape rustjunosmcp 0.9.1 writes today.
    const JUNOS_SHAPE: &str = r#"{
        "name": "lab",
        "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "routers": ["edge-fw", "core-fw"],
        "tools": ["*"],
        "created_at": "2026-07-12T10:00:00Z"
    }"#;

    /// Exactly the shape rustpanosmcp 0.2.2 writes today.
    const PANOS_SHAPE: &str = r#"{
        "name": "lab",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "devices": ["panosvm"],
        "tools": ["get_panos_config"],
        "created_at_unix": 1783850400
    }"#;

    #[test]
    fn loads_the_junos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse junos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["edge-fw".to_owned(), "core-fw".to_owned()])
        );
        assert_eq!(entry.tools, ScopeSet::Wildcard);
        assert!(entry.digest.verify("test"));
        assert!(entry.expires_at.is_none());
    }

    #[test]
    fn loads_the_panos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("parse panos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["panosvm".to_owned()])
        );
        assert!(entry.digest.verify("test"));
    }

    #[test]
    fn both_shapes_produce_an_identical_entry() {
        let junos: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("junos");
        let panos: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("panos");
        assert_eq!(junos.created_at, panos.created_at);
        assert_eq!(junos.digest, panos.digest);
    }

    #[test]
    fn a_token_without_expiry_never_expires() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let far_future = DateTime::from_timestamp(4_102_444_800, 0).expect("timestamp");
        assert!(!entry.is_expired_at(far_future));
    }

    #[test]
    fn a_token_past_its_expiry_is_expired() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "expires_at_unix": 1783936800
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let before = DateTime::from_timestamp(1_783_886_400, 0).expect("timestamp");
        let after = DateTime::from_timestamp(1_784_023_200, 0).expect("timestamp");
        assert!(!entry.is_expired_at(before));
        assert!(entry.is_expired_at(after));
    }

    #[test]
    fn an_entry_with_an_invalid_scope_fails_validation() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["a", "a"],
            "tools": ["*"],
            "created_at_unix": 1783850400
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    #[test]
    fn an_entry_with_an_out_of_range_name_fails_validation() {
        let raw = format!(
            r#"{{
                "name": "{}",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["*"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            }}"#,
            "x".repeat(200)
        );
        let entry: TokenEntry = serde_json::from_str(&raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    /// The shape a management-plane server writes: its scope entries are
    /// tenants and sites, not devices (#91).
    const TARGET_SHAPE: &str = r#"{
        "name": "lab",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "targets": ["tenant-a", "tenant-b"],
        "tools": ["*"],
        "created_at_unix": 1783850400
    }"#;

    #[test]
    fn loads_the_target_neutral_shape() {
        let entry: TokenEntry = serde_json::from_str(TARGET_SHAPE).expect("parse target shape");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["tenant-a".to_owned(), "tenant-b".to_owned()]),
            "`targets` must land in the same scope field the other spellings do"
        );
    }

    #[test]
    fn all_three_spellings_produce_the_same_scope() {
        let with_routers: TokenEntry = serde_json::from_str(&JUNOS_SHAPE.replace(
            r#""routers": ["edge-fw", "core-fw"]"#,
            r#""routers": ["a"]"#,
        ))
        .expect("routers");
        let with_devices: TokenEntry =
            serde_json::from_str(&PANOS_SHAPE.replace(r#""panosvm""#, r#""a""#)).expect("devices");
        let with_targets: TokenEntry =
            serde_json::from_str(&TARGET_SHAPE.replace(r#""tenant-a", "tenant-b""#, r#""a""#))
                .expect("targets");

        let expected = ScopeSet::Allowlist(vec!["a".to_owned()]);
        assert_eq!(with_routers.devices, expected);
        assert_eq!(with_devices.devices, expected);
        assert_eq!(with_targets.devices, expected);
    }

    #[test]
    fn the_neutral_accessor_reads_the_same_scope_as_the_field() {
        let entry: TokenEntry = serde_json::from_str(TARGET_SHAPE).expect("parse");
        assert_eq!(entry.targets(), &entry.devices);
    }

    #[test]
    fn a_target_spelled_file_still_serializes_as_devices() {
        let entry: TokenEntry = serde_json::from_str(TARGET_SHAPE).expect("parse");
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"devices\""), "canonical spelling: {json}");
        assert!(
            !json.contains("\"targets\""),
            "alias must not round-trip: {json}"
        );
    }

    #[test]
    fn serializing_writes_the_canonical_field_names() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"digest\""));
        assert!(json.contains("\"devices\""));
        assert!(!json.contains("\"hash\""));
        assert!(!json.contains("\"routers\""));
    }

    #[test]
    fn existing_tokens_without_provenance_fields_load_with_defaults() {
        // HARD CONSTRAINT: tokens.json is deployed on LXC 600, 601, 608, 609.
        // This test proves existing files load unchanged with safe defaults.
        // Written FIRST, must fail before defaults are added, then pass.
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse existing token");
        assert_eq!(entry.name, "lab");
        // All new fields default to None or Human
        assert!(entry.provider.is_none(), "provider defaults to None");
        assert!(
            entry.provider_tier.is_none(),
            "provider_tier defaults to None"
        );
        assert!(
            entry.on_behalf_of.is_none(),
            "on_behalf_of defaults to None"
        );
        assert_eq!(
            entry.actor_type,
            ActorType::Unknown,
            "actor_type defaults to Unknown (untagged legacy token provides no data)"
        );
        assert!(
            entry.oidc_subject.is_none(),
            "oidc_subject defaults to None (MEC-994)"
        );
    }

    #[test]
    fn oidc_subject_round_trips_and_is_absent_when_unset() {
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        assert!(
            !serde_json::to_string(&entry)
                .expect("serialize")
                .contains("oidc")
        );

        entry.oidc_subject = Some(OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: "alice".to_owned(),
        });
        let json = serde_json::to_string(&entry).expect("serialize");
        let round_tripped: TokenEntry = serde_json::from_str(&json).expect("parse");
        assert_eq!(round_tripped.oidc_subject, entry.oidc_subject);
    }

    #[test]
    fn an_empty_oidc_subject_field_is_rejected() {
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        entry.oidc_subject = Some(OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: String::new(),
        });
        let err = entry.validate().expect_err("empty subject must be refused");
        assert!(matches!(err, EntryError::Invalid(_)), "{err}");
    }

    #[test]
    fn an_empty_oidc_issuer_field_is_rejected() {
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        entry.oidc_subject = Some(OidcSubject {
            issuer: String::new(),
            subject: "alice".to_owned(),
        });
        let err = entry.validate().expect_err("empty issuer must be refused");
        assert!(matches!(err, EntryError::Invalid(_)), "{err}");
    }

    #[test]
    fn a_pipe_in_the_oidc_subject_is_accepted() {
        // The approval digest serializes `(issuer, subject)` as a tuple (see
        // `compute_approval_digest_v7`), not a delimited string, so a
        // character some IdPs use in their default subject shape needs no
        // special handling here.
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        entry.oidc_subject = Some(OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: "auth0|abc123".to_owned(),
        });
        entry
            .validate()
            .expect("a '|' in the subject must be accepted");
    }

    #[test]
    fn a_pipe_in_the_oidc_issuer_is_accepted() {
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        entry.oidc_subject = Some(OidcSubject {
            issuer: "https://idp|example.com".to_owned(),
            subject: "alice".to_owned(),
        });
        entry
            .validate()
            .expect("a '|' in the issuer must be accepted");
    }

    #[test]
    fn a_valid_oidc_subject_passes_validation() {
        let mut entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        entry.oidc_subject = Some(OidcSubject {
            issuer: "https://idp.example.com".to_owned(),
            subject: "alice".to_owned(),
        });
        entry
            .validate()
            .expect("a well-formed oidc_subject is valid");
    }

    #[test]
    fn a_grant_type_without_default_can_be_deserialized() {
        // Guards the public contract: a consumer's write-authority type must not
        // be forced to answer "what is the default write authority?".
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct NoDefaultGrant {
            subjects: Vec<String>,
        }
        impl Grant for NoDefaultGrant {
            type Action = ();
            fn allows_action(&self, _action: ()) -> bool {
                true
            }
            fn allows_subject(&self, subject: &str) -> bool {
                self.subjects.iter().any(|s| s == subject)
            }
            fn validate(&self) -> Result<(), GrantError> {
                Ok(())
            }
        }

        let raw = r#"{
            "name": "writer",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "grant": { "subjects": ["/a/b"] }
        }"#;
        let entry: TokenEntry<NoDefaultGrant> = serde_json::from_str(raw).expect("parse");
        let grant = entry.grant.as_ref().expect("grant present");
        assert!(grant.allows_subject("/a/b"));
        assert!(!grant.allows_subject("/a/c"));
    }

    #[test]
    fn provider_without_tier_fails_validation() {
        // Defect 4: a token declaring provider without provider_tier is invalid.
        let raw = r#"{
            "name": "incomplete",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "provider": "anthropic"
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let result = entry.validate();
        assert!(
            result.is_err(),
            "provider without provider_tier must fail validation"
        );
        let err = result.expect_err("validation should fail").to_string();
        assert!(
            err.contains("provider_tier is missing"),
            "error message should mention missing provider_tier: {err}"
        );
    }

    #[test]
    fn provider_tier_without_provider_fails_validation() {
        // Defect 4: a token declaring provider_tier without provider is invalid.
        let raw = r#"{
            "name": "incomplete",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "provider_tier": "public"
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let result = entry.validate();
        assert!(
            result.is_err(),
            "provider_tier without provider must fail validation"
        );
        let err = result.expect_err("validation should fail").to_string();
        assert!(
            err.contains("provider is missing"),
            "error message should mention missing provider: {err}"
        );
    }

    #[test]
    fn complete_provider_pair_validates() {
        // Both provider and provider_tier present, on an agent token: valid.
        let raw = r#"{
            "name": "complete",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "provider": "anthropic",
            "provider_tier": "public",
            "actor_type": "agent"
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        assert!(
            entry.validate().is_ok(),
            "complete provider pair on an agent token should validate"
        );
    }

    #[test]
    fn provider_on_a_human_token_fails_validation() {
        // An LLM provider on a token typed as a human operator is a record that
        // contradicts itself, and would make from_caller build an agent identity
        // for a human actor. Only this explicit contradiction is rejected.
        let raw = r#"{
            "name": "contradictory",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "provider": "anthropic",
            "provider_tier": "public",
            "actor_type": "human"
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let err = entry
            .validate()
            .expect_err("provider on a human token must be rejected")
            .to_string();
        assert!(err.contains("contradicts"), "unexpected error {err}");
    }

    #[test]
    fn blank_provenance_values_fail_validation() {
        // `Some("")` reads as declared, so it would be marked token-verified and
        // emitted as a verified-but-empty field. Absent and blank are different
        // things and only one of them is legitimate.
        for (field, extra) in [
            ("provider", r#""provider": "  ", "provider_tier": "public""#),
            ("on_behalf_of", r#""on_behalf_of": """#),
        ] {
            let raw = format!(
                r#"{{
                    "name": "blank",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["*"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400,
                    {extra}
                }}"#
            );
            let entry: TokenEntry = serde_json::from_str(&raw).expect("parse");
            let err = entry
                .validate()
                .expect_err("blank provenance must be rejected")
                .to_string();
            assert!(err.contains(field), "expected {field} in error, got {err}");
            assert!(err.contains("empty"), "unexpected error {err}");
        }
    }

    #[test]
    fn provider_without_an_actor_type_loads_and_reads_as_agent() {
        // This is the token shape issue #52 documents: provider and tier, no
        // actor_type. A hand-written tokens.json in that form must load — the
        // operator never had to state the actor type, and failing the whole
        // store over it would be a footgun. Nothing but an agent has a provider,
        // so it reads as one.
        let raw = r#"{
            "name": "claude-code-ops",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "provider": "anthropic",
            "provider_tier": "public",
            "on_behalf_of": "dev@example.com"
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        entry
            .validate()
            .expect("the documented token shape must load");
        assert_eq!(
            entry.actor_type,
            ActorType::Unknown,
            "stored value is untouched"
        );
        assert_eq!(
            entry.effective_actor_type(),
            ActorType::Agent,
            "a provider-bearing token reads as an agent"
        );
    }
}
