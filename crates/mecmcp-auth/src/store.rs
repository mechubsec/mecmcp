//! In-memory token store and per-request caller context.

use crate::entry::{EntryError, TokenEntry};
use crate::grant::{Grant, NoGrant};
use crate::scope::ScopeSet;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Maximum entries, keeping the linear authenticate scan bounded.
pub const MAX_TOKENS: usize = 1024;

/// Rejection reason for a malformed token store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Two entries share a name.
    #[error("duplicate token name: {0}")]
    Duplicate(String),
    /// The store exceeds [`MAX_TOKENS`].
    #[error("token store contains {0} entries, maximum is {MAX_TOKENS}")]
    TooMany(usize),
    /// An entry failed validation.
    #[error(transparent)]
    Entry(#[from] EntryError),
}

/// Immutable token store, swapped atomically on reload.
#[derive(Debug, Clone)]
pub struct TokenStore<G: Grant = NoGrant> {
    entries: Vec<TokenEntry<G>>,
}

impl<G: Grant> TokenStore<G> {
    /// Validate bounds, uniqueness, and every entry.
    ///
    /// # Errors
    /// Returns [`StoreError`] describing the first failing check.
    pub fn try_new(entries: Vec<TokenEntry<G>>) -> Result<Self, StoreError> {
        // Deliberately NOT rejected here: an entry whose device and tool scopes
        // are both empty. Such a token authenticates but authorizes nothing,
        // which reads like a configuration mistake — but rejecting it would fail
        // the whole call, and this call validates the entire file. One useless
        // entry would then stop every other token in `tokens.json` from loading
        // and take authentication offline server-wide. An entry that authorizes
        // nothing is already fail-closed and harmless; a fleet-wide outage is
        // not. Surface it in `token list` output instead, never here.
        if entries.len() > MAX_TOKENS {
            return Err(StoreError::TooMany(entries.len()));
        }
        let mut seen = BTreeSet::new();
        for entry in &entries {
            entry.validate()?;
            if !seen.insert(entry.name.as_str()) {
                return Err(StoreError::Duplicate(entry.name.clone()));
            }
        }
        Ok(Self { entries })
    }

    /// Authenticate a candidate secret against the current wall clock.
    #[must_use]
    pub fn authenticate(&self, candidate: &str) -> Option<&TokenEntry<G>> {
        self.authenticate_at(candidate, Utc::now())
    }

    /// Authenticate a candidate secret at an explicit instant.
    ///
    /// Every entry is compared even after a match, so lookup time does not
    /// depend on an entry's position in the store.
    #[must_use]
    pub fn authenticate_at(&self, candidate: &str, now: DateTime<Utc>) -> Option<&TokenEntry<G>> {
        let mut found = None;
        for entry in &self.entries {
            if entry.digest.verify(candidate) && !entry.is_expired_at(now) {
                found = Some(entry);
            }
        }
        found
    }

    /// All entries, for `token list` and load-time linting.
    #[must_use]
    pub fn entries(&self) -> &[TokenEntry<G>] {
        &self.entries
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<G: Grant> Default for TokenStore<G> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// Authenticated identity copied into per-request state.
#[derive(Debug, Clone)]
pub struct CallerCtx<G: Grant = NoGrant> {
    /// Non-secret token name, used for audit attribution and rate limiting.
    pub token_name: String,
    /// Devices this caller may address.
    pub devices: ScopeSet,
    /// Tools this caller may call.
    pub tools: ScopeSet,
    /// Vendor-specific write authority, if any.
    pub grant: Option<G>,
    /// Server-verified provider name, when the token declares one.
    pub provider: Option<String>,
    /// Server-verified provider tier, when the token declares one.
    pub provider_tier: Option<crate::Tier>,
    /// Server-verified human identity, when the token declares one.
    pub on_behalf_of: Option<String>,
    /// Server-verified actor type from the token entry.
    pub actor_type: crate::ActorType,
    /// The IdP subject this token is bound to, when the token entry declares
    /// one (MEC-994). Copied straight from [`TokenEntry::oidc_subject`].
    pub oidc_subject: Option<crate::entry::OidcSubject>,
    /// The verified approver identity bound to this request, when a
    /// `Mecmcp-Approver-Assertion` header passed [`crate::approver::bind_approver`]
    /// (MEC-994 W3). `None` for every request that carried no assertion, or
    /// carried one that was not yet checked at the point `CallerCtx` was
    /// built. Set by the bearer preflight middleware, never by a token entry.
    pub verified_approver: Option<crate::approver::VerifiedApprover>,
    /// Client-asserted MCP client name from `initialize` request.
    ///
    /// Captured from the MCP session identified by `Mcp-Session-Id` header.
    /// This field is ALWAYS client-asserted and can never be server-verified,
    /// regardless of what token-bound provenance fields say. Populated by the
    /// bearer preflight middleware when a session exists and provided clientInfo.
    ///
    /// `None` for the very first request (initialize itself, before the session
    /// has a captured name) or when the client did not provide `clientInfo`.
    pub client_name: Option<&'static str>,
    /// Client-asserted model ID from `_meta.mecmcp/provenance` in `initialize`.
    ///
    /// Interned, low-cardinality (a handful of model names). ALWAYS client-asserted.
    /// Populated by bearer preflight when the session provided provenance.
    pub model_id: Option<&'static str>,
    /// Client-asserted session ID from `_meta.mecmcp/provenance` in `initialize`.
    ///
    /// High-cardinality (one per session), not interned. ALWAYS client-asserted.
    /// Populated by bearer preflight when the session provided provenance.
    pub session_id: Option<String>,
    /// Correlation ID shared by every audit event for this one request.
    ///
    /// One authenticated `tools/call` emits two audit events — the transport
    /// preflight event and the handler's enriched event (mecmcp#32). Both read
    /// this field via `Attribution::from_caller`, so a SIEM consumer can join
    /// the preflight attribution (who called, from which client) to the handler
    /// outcome (what it did, to which targets).
    ///
    /// **This is per-request state, not per-caller state.** It is minted in
    /// `From<&TokenEntry>`, which the bearer middleware runs once per request.
    /// A consumer that builds one `CallerCtx` and reuses it across requests
    /// would make the ID identify nothing — build a fresh context per request,
    /// as the middleware does (mecmcp#269).
    pub request_id: Uuid,
}

impl<G: Grant> From<&TokenEntry<G>> for CallerCtx<G> {
    fn from(entry: &TokenEntry<G>) -> Self {
        Self {
            token_name: entry.name.clone(),
            devices: entry.devices.clone(),
            tools: entry.tools.clone(),
            grant: entry.grant.clone(),
            provider: entry.provider.clone(),
            provider_tier: entry.provider_tier,
            on_behalf_of: entry.on_behalf_of.clone(),
            actor_type: entry.effective_actor_type(),
            oidc_subject: entry.oidc_subject.clone(),
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            // Minted here rather than at the audit layer: authentication runs
            // once per request, so this is the point at which "one request"
            // is a fact rather than an assumption (mecmcp#269).
            request_id: Uuid::new_v4(),
        }
    }
}

impl<G: Grant> CallerCtx<G> {
    /// The scope of targets this caller may address.
    ///
    /// The same scope as [`devices`](Self::devices), under the target-neutral
    /// name a management-plane server needs (#91).
    #[must_use]
    pub fn targets(&self) -> &ScopeSet {
        &self.devices
    }
}

/// Filter inventory device names down to what this caller may see.
///
/// Filtering starts from the inventory names, never from the scope entries, so
/// a stale token naming a retired device can neither disclose nor synthesize
/// it. An absent caller context is the stdio / explicit-no-auth case and
/// preserves the full list.
#[must_use]
pub fn filter_device_names<G: Grant>(
    ctx: Option<&CallerCtx<G>>,
    names: Vec<String>,
) -> Vec<String> {
    match ctx {
        Some(ctx) => names
            .into_iter()
            .filter(|name| ctx.devices.allows(name))
            .collect(),
        None => names,
    }
}

/// Filter inventory target names down to what this caller may see.
///
/// [`filter_device_names`] under the target-neutral name, for servers whose
/// inventory is tenants or sites rather than devices (#91). It delegates rather
/// than reimplements: a second copy of this rule is a second thing to get
/// wrong.
#[must_use]
pub fn filter_target_names<G: Grant>(
    ctx: Option<&CallerCtx<G>>,
    names: Vec<String>,
) -> Vec<String> {
    filter_device_names(ctx, names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenSecret;

    fn entry_named(name: &str) -> (String, TokenEntry) {
        let (secret, digest) = TokenSecret::mint().expect("mint");
        let plaintext = secret.expose_secret().to_owned();
        let entry = TokenEntry {
            name: name.to_owned(),
            digest,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: DateTime::from_timestamp(1_783_850_400, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
        };
        (plaintext, entry)
    }

    #[test]
    fn authenticates_a_known_secret() {
        let (secret, entry) = entry_named("lab");
        let store = TokenStore::try_new(vec![entry]).expect("store");
        assert_eq!(
            store.authenticate(&secret).map(|e| e.name.as_str()),
            Some("lab")
        );
    }

    #[test]
    fn rejects_an_unknown_secret() {
        let (_secret, entry) = entry_named("lab");
        let store = TokenStore::try_new(vec![entry]).expect("store");
        assert!(store.authenticate("not-a-real-token").is_none());
    }

    #[test]
    fn rejects_an_expired_secret() {
        let (secret, mut entry) = entry_named("lab");
        entry.expires_at = Some(DateTime::from_timestamp(1_783_936_800, 0).expect("timestamp"));
        let store = TokenStore::try_new(vec![entry]).expect("store");
        let after = DateTime::from_timestamp(1_784_100_000, 0).expect("timestamp");
        let before = DateTime::from_timestamp(1_783_900_000, 0).expect("timestamp");
        assert!(store.authenticate_at(&secret, before).is_some());
        assert!(store.authenticate_at(&secret, after).is_none());
    }

    #[test]
    fn duplicate_names_are_rejected_at_construction() {
        let (_a, first) = entry_named("lab");
        let (_b, second) = entry_named("lab");
        assert!(matches!(
            TokenStore::try_new(vec![first, second]),
            Err(StoreError::Duplicate(_))
        ));
    }

    #[test]
    fn an_invalid_entry_is_rejected_at_construction() {
        let (_secret, mut entry) = entry_named("lab");
        entry.devices = ScopeSet::Allowlist(vec!["a".to_owned(), "a".to_owned()]);
        assert!(matches!(
            TokenStore::try_new(vec![entry]),
            Err(StoreError::Entry(_))
        ));
    }

    #[test]
    fn more_than_max_tokens_is_rejected() {
        let entries = (0..=MAX_TOKENS)
            .map(|i| entry_named(&format!("t{i}")).1)
            .collect();
        assert!(matches!(
            TokenStore::try_new(entries),
            Err(StoreError::TooMany(_))
        ));
    }

    #[test]
    fn caller_ctx_filters_device_names_to_its_scope() {
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let visible =
            filter_device_names(Some(&ctx), vec!["edge-fw".to_owned(), "core-fw".to_owned()]);
        assert_eq!(visible, vec!["edge-fw".to_owned()]);
    }

    #[test]
    fn the_neutral_filter_and_accessor_authorize_identically() {
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let names = vec!["tenant-a".to_owned(), "tenant-b".to_owned()];

        assert_eq!(ctx.targets(), &ctx.devices, "one scope, two names");
        assert_eq!(
            filter_target_names(Some(&ctx), names.clone()),
            filter_device_names(Some(&ctx), names),
            "the neutral filter must not be a second set of rules"
        );
    }

    #[test]
    fn absent_caller_ctx_sees_everything() {
        let names = vec!["edge-fw".to_owned(), "core-fw".to_owned()];
        let visible = filter_device_names(None::<&CallerCtx>, names.clone());
        assert_eq!(visible, names);
    }

    #[test]
    fn filtering_starts_from_inventory_not_scope() {
        // A stale token naming a device that no longer exists must not
        // synthesize it into the visible list.
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Allowlist(vec!["retired-fw".to_owned()]),
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let visible = filter_device_names(Some(&ctx), vec!["edge-fw".to_owned()]);
        assert!(visible.is_empty());
    }

    #[test]
    fn wildcard_scope_sees_the_whole_inventory() {
        // The most common shape for a real token, and the one case the other
        // filter tests do not reach.
        let ctx: CallerCtx = CallerCtx {
            token_name: "lab".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let names = vec!["edge-fw".to_owned(), "core-fw".to_owned()];
        let visible = filter_device_names(Some(&ctx), names.clone());
        assert_eq!(visible, names, "a wildcard device scope must not filter");
    }
}
