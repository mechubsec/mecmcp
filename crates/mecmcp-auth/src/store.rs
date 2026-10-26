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

    /// How many live (unexpired at `now`) tokens are `human` with no `oidc_subject` binding.
    ///
    /// These cannot present a verified approver identity, so they are what an operator
    /// must bind before enabling `--require-verified-approver` (#400). A count only: never
    /// names, so it is safe to log.
    #[must_use]
    pub fn unbound_human_count_at(&self, now: DateTime<Utc>) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                !entry.is_expired_at(now)
                    && entry.effective_actor_type() == crate::ActorType::Human
                    && entry.oidc_subject.is_none()
            })
            .count()
    }

    /// [`Self::unbound_human_count_at`] at the current wall clock.
    #[must_use]
    pub fn unbound_human_count(&self) -> usize {
        self.unbound_human_count_at(Utc::now())
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
    /// Set when this caller was authenticated by an OAuth access token rather than a
    /// static token. Holds the issuer, subject and client id only; **never the token**.
    pub oauth: Option<crate::oauth::OAuthIdentity>,
}

impl<G: Grant> From<&TokenEntry<G>> for CallerCtx<G> {
    /// Equivalent to [`CallerCtx::from_entry_with_attributes`] with no attribute source, so
    /// an entry carrying `device_selectors` addresses no devices through this path.
    fn from(entry: &TokenEntry<G>) -> Self {
        Self::from_entry_with_attributes(entry, None)
    }
}

impl<G: Grant> CallerCtx<G> {
    /// Build the context for a static token, resolving its `device_selectors` against
    /// `attributes` (mecmcp#400). The opt-in counterpart of OAuth's `with_device_attributes`:
    /// a server that labels its devices passes its live inventory here on each
    /// authentication.
    ///
    /// The attribute snapshot is read **once**, so every selector is judged against one
    /// inventory generation. Fails closed: with selectors but no source, an unlabelled
    /// device, or a result over [`MAX_SCOPE_NAMES`](crate::MAX_SCOPE_NAMES) (never
    /// truncated), the token addresses no devices. A token without selectors is unchanged.
    #[must_use]
    pub fn from_entry_with_attributes(
        entry: &TokenEntry<G>,
        attributes: Option<&dyn crate::DeviceAttributeSource>,
    ) -> Self {
        Self {
            token_name: entry.name.clone(),
            devices: effective_devices(entry, attributes),
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
            oauth: None,
        }
    }

    /// Build the context for a caller authenticated by an OAuth access token.
    ///
    /// The scopes come from the server's own scope map, never from the token. No vendor
    /// grant is attached (`grant: None`): a grant is vendor-specific and a token's claims
    /// cannot mint one, so OAuth callers cannot use grant-gated mutations in this version.
    #[must_use]
    pub fn oauth(
        identity: crate::oauth::OAuthIdentity,
        devices: ScopeSet,
        tools: ScopeSet,
        actor_type: crate::ActorType,
    ) -> Self {
        Self {
            token_name: identity.token_name(),
            devices,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: Uuid::new_v4(),
            oauth: Some(identity),
        }
    }

    /// The scope of targets this caller may address.
    ///
    /// The same scope as [`devices`](Self::devices), under the target-neutral
    /// name a management-plane server needs (#91).
    #[must_use]
    pub fn targets(&self) -> &ScopeSet {
        &self.devices
    }
}

fn effective_devices<G: Grant>(
    entry: &TokenEntry<G>,
    attributes: Option<&dyn crate::DeviceAttributeSource>,
) -> ScopeSet {
    let Some(expressions) = &entry.device_selectors else {
        return entry.devices.clone();
    };
    let Ok(selectors) = crate::SelectorSet::compile(expressions) else {
        return ScopeSet::Allowlist(Vec::new());
    };
    let snapshot = attributes
        .map(crate::DeviceAttributeSource::device_attributes)
        .unwrap_or_default();
    let narrowed = selectors.narrow(&entry.devices, &snapshot);
    if narrowed.validate("devices").is_err() {
        return ScopeSet::Allowlist(Vec::new());
    }
    narrowed
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::oauth::OAuthIdentity;
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
            device_selectors: None,
        };
        (plaintext, entry)
    }

    #[test]
    fn unbound_human_count_skips_bound_agent_and_expired_tokens() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).expect("timestamp");
        let (_, unbound) = entry_named("unbound");
        let (_, mut bound) = entry_named("bound");
        bound.oidc_subject = Some(crate::OidcSubject {
            issuer: "https://idp.example".to_owned(),
            subject: "alice".to_owned(),
        });
        let (_, mut agent) = entry_named("agent");
        agent.actor_type = crate::ActorType::Agent;
        let (_, mut unknown) = entry_named("unknown");
        unknown.actor_type = crate::ActorType::Unknown;
        let (_, mut expired) = entry_named("expired");
        expired.expires_at = Some(now - chrono::Duration::seconds(1));
        let store =
            TokenStore::try_new(vec![unbound, bound, agent, unknown, expired]).expect("store");
        assert_eq!(store.unbound_human_count_at(now), 1);
    }

    #[test]
    fn oauth_constructor_carries_identity_and_no_write_authority() {
        let identity = OAuthIdentity {
            issuer: "https://idp.example".to_owned(),
            subject: "alice".to_owned(),
            client_id: Some("odysseus".to_owned()),
        };
        let ctx: CallerCtx = CallerCtx::oauth(
            identity.clone(),
            ScopeSet::Allowlist(vec!["srx-1".to_owned()]),
            ScopeSet::Allowlist(vec!["get_device_list".to_owned()]),
            crate::ActorType::Agent,
        );
        assert_eq!(ctx.oauth, Some(identity));
        assert_eq!(ctx.token_name, "oauth:alice");
        assert!(
            ctx.grant.is_none(),
            "OAuth callers never hold a vendor grant"
        );
        assert!(ctx.verified_approver.is_none());
        assert!(ctx.oidc_subject.is_none());
        assert_eq!(ctx.actor_type, crate::ActorType::Agent);
    }

    #[test]
    fn a_token_entry_context_has_no_oauth_identity() {
        let (_, entry) = entry_named("ci");
        assert!(CallerCtx::from(&entry).oauth.is_none());
    }

    /// Exhaustive destructuring: a future `token`/`bearer`/`jwt` field makes this
    /// stop compiling, which is the point. The caller context must never hold the credential.
    #[test]
    fn caller_ctx_has_no_credential_field() {
        let ctx: CallerCtx = CallerCtx::oauth(
            OAuthIdentity {
                issuer: "i".into(),
                subject: "s".into(),
                client_id: None,
            },
            ScopeSet::Allowlist(vec![]),
            ScopeSet::Allowlist(vec![]),
            crate::ActorType::Unknown,
        );
        let CallerCtx {
            token_name: _,
            devices: _,
            tools: _,
            grant: _,
            provider: _,
            provider_tier: _,
            on_behalf_of: _,
            actor_type: _,
            oidc_subject: _,
            verified_approver: _,
            client_name: _,
            model_id: _,
            session_id: _,
            request_id: _,
            oauth: _,
        } = ctx;
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
            oauth: None,
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
            oauth: None,
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
            oauth: None,
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
            oauth: None,
        };
        let names = vec!["edge-fw".to_owned(), "core-fw".to_owned()];
        let visible = filter_device_names(Some(&ctx), names.clone());
        assert_eq!(visible, names, "a wildcard device scope must not filter");
    }

    // ---- device selectors on static tokens (mecmcp#400) ----

    use crate::selector::{DeviceAttributeSource, DeviceAttrs};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fixed inventory that counts how often it is read.
    struct Fleet(Vec<(String, DeviceAttrs)>, AtomicUsize);

    impl Fleet {
        fn new(devices: &[(&str, &str)]) -> Self {
            let rows = devices
                .iter()
                .map(|(name, site)| {
                    let json = format!(r#"{{"site":"{site}"}}"#);
                    ((*name).to_owned(), serde_json::from_str(&json).unwrap())
                })
                .collect();
            Self(rows, AtomicUsize::new(0))
        }
    }

    impl DeviceAttributeSource for Fleet {
        fn device_attributes(&self) -> Vec<(String, DeviceAttrs)> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.clone()
        }
    }

    fn selector_entry(devices: ScopeSet, selectors: &[&str]) -> TokenEntry {
        let (_, mut entry) = entry_named("scoped");
        entry.devices = devices;
        entry.device_selectors = Some(selectors.iter().map(|text| (*text).to_owned()).collect());
        entry
    }

    #[test]
    fn selectors_narrow_the_devices_the_token_names() {
        let fleet = Fleet::new(&[("lab-1", "lab-a"), ("prod-1", "prod-a"), ("lab-2", "lab-b")]);
        let wild = selector_entry(ScopeSet::Wildcard, &["site=lab-*"]);
        let ctx = CallerCtx::from_entry_with_attributes(&wild, Some(&fleet));
        assert!(ctx.devices.allows("lab-1") && ctx.devices.allows("lab-2"));
        assert!(!ctx.devices.allows("prod-1"));

        // Selectors never add a device `devices` does not name.
        let named = selector_entry(
            ScopeSet::Allowlist(vec!["lab-1".to_owned()]),
            &["site=lab-*"],
        );
        let ctx = CallerCtx::from_entry_with_attributes(&named, Some(&fleet));
        assert!(ctx.devices.allows("lab-1") && !ctx.devices.allows("lab-2"));
    }

    #[test]
    fn selectors_fail_closed_without_a_source_or_a_label() {
        let entry = selector_entry(ScopeSet::Wildcard, &["site=*"]);
        assert!(
            CallerCtx::from_entry_with_attributes(&entry, None)
                .devices
                .is_empty()
        );
        // The plain `From` path is the no-source path: a consumer that has not adopted
        // attributes must not read a selector entry as unrestricted.
        assert!(CallerCtx::from(&entry).devices.is_empty());
        // An unlabelled device never matches, even `site=*`.
        let unlabelled = Fleet(
            vec![("bare".to_owned(), DeviceAttrs::default())],
            AtomicUsize::new(0),
        );
        let ctx = CallerCtx::from_entry_with_attributes(&entry, Some(&unlabelled));
        assert!(!ctx.devices.allows("bare"));
    }

    #[test]
    fn an_entry_without_selectors_is_unchanged_and_never_reads_the_source() {
        let fleet = Fleet::new(&[("lab-1", "lab-a")]);
        let (_, entry) = entry_named("plain");
        let ctx = CallerCtx::from_entry_with_attributes(&entry, Some(&fleet));
        assert_eq!(ctx.devices, ScopeSet::Wildcard);
        assert_eq!(fleet.1.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn one_authentication_reads_the_attributes_once() {
        let fleet = Fleet::new(&[("lab-1", "lab-a")]);
        let entry = selector_entry(ScopeSet::Wildcard, &["site=lab-*", "vendor=*"]);
        let _ = CallerCtx::from_entry_with_attributes(&entry, Some(&fleet));
        assert_eq!(fleet.1.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lookalike_and_case_variants_never_match_a_selector() {
        // The isolation guarantee is the shared grammar's; this pins that the static path
        // goes through it. Non-alphabet values cannot even be labelled, so they fail the
        // inventory load before they can match.
        let fleet = Fleet::new(&[
            ("a", "EMEA-1"),
            ("b", "emea1"),
            ("c", "xemea-1"),
            ("d", "emea-1"),
        ]);
        let entry = selector_entry(ScopeSet::Wildcard, &["site=emea-*"]);
        let ctx = CallerCtx::from_entry_with_attributes(&entry, Some(&fleet));
        assert_eq!(ctx.devices, ScopeSet::Allowlist(vec!["d".to_owned()]));
        for lookalike in ["emea\u{2010}1", "emea-1\u{200b}", "\u{ff45}mea-1"] {
            let json = format!(r#"{{"site":"{lookalike}"}}"#);
            assert!(
                serde_json::from_str::<DeviceAttrs>(&json).is_err(),
                "{lookalike}"
            );
        }
    }

    #[test]
    fn a_result_over_the_scope_cap_grants_nothing_rather_than_truncating() {
        let names: Vec<String> = (0..=crate::MAX_SCOPE_NAMES)
            .map(|n| format!("d{n}"))
            .collect();
        let rows: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "lab-a")).collect();
        let fleet = Fleet::new(&rows);
        let entry = selector_entry(ScopeSet::Wildcard, &["site=lab-*"]);
        let ctx = CallerCtx::from_entry_with_attributes(&entry, Some(&fleet));
        assert!(ctx.devices.is_empty());
    }

    #[test]
    fn selectors_parse_from_json_and_null_is_refused() {
        let digest = serde_json::to_string(&entry_named("x").1.digest).unwrap();
        let base = |extra: &str| {
            format!(
                r#"{{"name":"t","digest":{digest},"created_at":"2026-01-01T00:00:00Z"{extra}}}"#
            )
        };
        let ok: TokenEntry =
            serde_json::from_str(&base(r#","device_selectors":["site=lab-*"]"#)).unwrap();
        assert_eq!(ok.device_selectors, Some(vec!["site=lab-*".to_owned()]));
        let absent: TokenEntry = serde_json::from_str(&base("")).unwrap();
        assert_eq!(absent.device_selectors, None);
        assert!(serde_json::from_str::<TokenEntry>(&base(r#","device_selectors":null"#)).is_err());
        // Round-trips, and an absent field is not written.
        assert!(
            !serde_json::to_string(&absent)
                .unwrap()
                .contains("device_selectors")
        );
        assert!(
            serde_json::to_string(&ok)
                .unwrap()
                .contains("device_selectors")
        );
    }

    #[test]
    fn a_selector_that_does_not_compile_is_refused_at_construction() {
        for bad in [&[][..], &["region=emea"], &["site="], &["site=a?"]] {
            let (_, mut entry) = entry_named("bad");
            entry.device_selectors = Some(bad.iter().map(|text| (*text).to_owned()).collect());
            assert!(TokenStore::try_new(vec![entry]).is_err(), "{bad:?}");
        }
    }
}
