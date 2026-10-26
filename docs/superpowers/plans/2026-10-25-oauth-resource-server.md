# OAuth 2.1 Resource-Server Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every rust\*mcp server can, behind one off-by-default cargo feature and one
flattened CLI group, accept a JWT access token from an external authorization server
as the `/mcp` bearer credential, advertise itself via RFC 9728 metadata, and map the
token's claims onto the existing `CallerCtx` scope model, failing closed, with static
tokens still working beside it (mecmcp#498).

**Architecture:** `mecmcp-oidc` gains the access-token profile (RFC 9068 claims: scope,
client id, `typ`) and a canonical resource-URI type. `mecmcp-auth` / `mecmcp-audit` gain an
`OAuthIdentity` on `CallerCtx` and a `Principal::OAuth`. `mecmcp-transport` gains an
`oauth-resource` feature holding the scope-map, the async verifier, the RFC 9728
metadata router and a second authentication step in `bearer_auth_middleware` that runs
only after the static `TokenStore` lookup misses. `mecmcp-runtime` gains the
flattenable `OAuthResourceArgs`. Docs and the threat model move OAuth-as-bearer into scope.

**Tech Stack:** Rust 2024 workspace (MSRV 1.89), axum 0.8, `jsonwebtoken` 11 (aws_lc_rs),
`url` 2 (already used by `mecmcp-oidc`), clap 4 derive, tower `oneshot` tests. No new
crates (see Global Constraints).

**Spec:** GitHub issue mechubsec/mecmcp#498 (requirements and security requirements);
`docs/superpowers/specs/2026-09-28-oidc-human-identity-design.md` (Phase 1 resource-server
core, which this reuses rather than forks); `docs/THREAT-MODEL.md` lines 43-50 (trust
boundary 5) and 112-118 ("Out of scope", which this plan edits). Related: #400, #397.

## Global Constraints

- **No new dependencies, no `Cargo.lock` changes.** `url` is already a dependency of
  `mecmcp-oidc` and every `mecmcp-transport` need for it goes through
  `mecmcp_oidc::ResourceUri` (Task 2). `mecmcp-transport` already lists `mecmcp-oidc` as an
  optional dependency (Cargo.toml:~34) and `tokio` with `time`+`sync`. After every
  task `git diff --stat Cargo.lock fuzz/Cargo.lock` must be empty; if it is not, stop and
  find out why before committing (see memory: separate lockfiles must move with the bump).
- **Feature name is `oauth-resource`**, in `mecmcp-transport` only, **off by default**,
  `oauth-resource = ["dep:mecmcp-oidc"]` (same shape as `verified-approver`). With it off,
  the middleware behaves byte-for-byte as today.
- **Static bearer tokens always keep working and are always tried first.** An OAuth
  failure never affects static-token traffic; a static hit never touches the network.
- **Fail closed, never wildcard by default.** An unmapped scope grants nothing; a verified
  token that maps to no tools is refused; the scope map has no default entry and a
  mapping that omits `tools` or `devices` is a load error.
- **Audience is exact string equality** with the configured canonical resource URI
  (or the explicit `--oauth-audience`). No normalisation, prefix or substring matching
  anywhere on the path.
- **The raw bearer is never stored.** `CallerCtx` and `Principal` hold only
  `issuer`, `sub`, `client_id`. The `Authorization` header is stripped from OAuth-authenticated
  requests before they reach inner layers (Task 10).
- **Offline tests only.** Fixtures sign ephemeral RSA JWTs and serve a `KeySource` trait
  object from memory (pattern: `crates/mecmcp-transport/tests/approver_assertion.rs:33-125`).
  No test opens a socket to an IdP.
- **Each commit under ~400 lines** (the Codex review gate times out near 700). Test code
  counts. If a task overruns while implementing, split it at the nearest step boundary
  and say so in the commit message.
- **House lints:** `missing_docs = "warn"` (every `pub` item needs a doc comment),
  `unwrap_used = "warn"` (tests carry `#[allow(clippy::unwrap_used)]` like the existing
  modules), `unsafe_code = "forbid"`. Early returns over nesting; descriptive names.
- **Repo CI commands (`.github/workflows/ci.yml:42-123`) run in full before the last commit
  of every task** (the "Verify" block below). In addition, this plan adds
  `oauth-resource` to the isolated feature step and to the MSRV job (both in Task 6).
- **Commit messages end with:**
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
- Work on branch `feat/498-oauth-resource` in a worktree; never push from this plan's
  execution without the user. Do not touch `~/Projects/mecmcp` directly.

### Verify block (run at the end of every task, from the worktree root)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked --features mecmcp-audit/test-util,mecmcp-changeset/test-util,mecmcp-transport/test-util
cargo test --locked -p mecmcp-transport --features test-util,verified-approver
cargo test --locked -p mecmcp-transport --features test-util,oauth-resource   # from Task 6 on
cargo doc --workspace --no-deps --locked
cargo check --locked --manifest-path fuzz/Cargo.toml --bins
git diff --stat Cargo.lock fuzz/Cargo.lock    # must print nothing
```

The MSRV job (`rm Cargo.lock; cargo check --workspace --all-targets` on 1.89) cannot be run
locally without a 1.89 toolchain. If `rustup toolchain list` has one, copy the tree, delete its
`Cargo.lock`, and run `cargo +1.89.0 check --workspace --all-targets` and, from Task 6,
`cargo +1.89.0 check -p mecmcp-transport --all-targets --features oauth-resource,test-util`.
Otherwise rely on CI, and keep new code to APIs already used elsewhere in the workspace.

## Current-state findings (verified against the tree at 0ee0947)

| Fact | Where |
|---|---|
| `OidcConfig` holds one issuer + one audience + `role_claim` + leeway + cache + `include_display_name`; constructed only via `OidcConfig::new` (no struct literals outside `verify.rs`) | `crates/mecmcp-oidc/src/verify.rs:42-80` |
| `verify_with`: header decode, `cache.keys()` (the only network touch), kid lookup, `matching_algorithm` (HS\* and `oct` keys refused; header alg must equal JWK alg), `jsonwebtoken` validates `iss`/`aud` (exact membership)/`exp`/`nbf`, required spec claims `exp iss aud sub`, then `iat` required (`MissingIssuedAt`) | `verify.rs:155-220` |
| `VerifiedClaims` has no scope and no client id; `jwt_id` is optional | `crates/mecmcp-oidc/src/claims.rs:16-47` |
| JWKS cache is time-driven: one fetch per `refresh_interval` (300 s) and at most one attempt per `retry_backoff` (30 s) regardless of how many tokens arrive; an unknown `kid` does **not** trigger a refetch. The cache holds a `tokio::Mutex` across the fetch, so concurrent verifications queue behind a slow IdP | `crates/mecmcp-oidc/src/cache.rs:37-135` |
| `decode_header` runs before `cache.keys()`, so a malformed token never reaches the network | `verify.rs:~160` |
| Discovery requires `https` for the issuer | `crates/mecmcp-oidc/src/discovery.rs:98` |
| `BearerAuthenticator` holds a **sync** `Fn(&str) -> Option<CallerCtx<G>>`; `bearer_auth_middleware` is already `async` and already awaits the verified-approver verifier after authentication | `crates/mecmcp-transport/src/auth.rs:41,88-104,566-638` |
| `/mcp` only is wrapped by `apply_bearer_boundary`; `/healthz` `/readyz` `/metrics` are merged afterwards; Host/Origin validation and the IP rate limit wrap the whole router (so a metadata route merged next to health is covered by both, and is outside the bearer boundary) | `crates/mecmcp-transport/src/server.rs:484-545` |
| 401 builders emit `Bearer realm="..."` (+ `error=`); `forbidden()` emits `insufficient_scope` and keeps the reason out of the header; `validate_realm` rejects `"`, `\`, control chars, non-ASCII | `auth.rs:1149-1214, 1360-1376` |
| Verified-approver precedent: optional `mecmcp-oidc` dep behind a feature, concrete `Arc<Verifier>` stored on `BearerBoundary` and `AuthState`, `#[cfg]` fields, a separate CI step | `Cargo.toml:~34,84`, `auth.rs:246-291,516`, `ci.yml:59-66` |
| `CallerCtx` has 14 public fields and is built by struct literal in ~60 places (34 files); `Principal` is `Token(String) | Unauthenticated`, rendered with `Display` and used as the identity key by `mecmcp-changeset` (`attribution.principal.to_string()`); `PersistedPrincipal` mirrors it | `crates/mecmcp-auth/src/store.rs:110-170`, `crates/mecmcp-audit/src/attribution.rs:11-24`, `crates/mecmcp-changeset/src/records.rs:137-150`, `operation.rs:623,713`, `approver.rs:74` |
| The audit event emits `caller = %principal` directly and **never redacts or escapes it**; other free-text fields go through `escape_control_chars` | `crates/mecmcp-audit/src/scope.rs:225-262` |
| Static token names forbid whitespace and `\0` and are capped at 128 bytes, but may otherwise be anything (including `oauth:x`) | `crates/mecmcp-auth/src/entry.rs:260-270` |
| `Grant` is vendor-specific and `StoredGrant`-serialised per server; the shared layer cannot mint one. OAuth callers therefore get `grant: None` (no write authority through grant-gated mutations) | `crates/mecmcp-auth/src/grant.rs` |
| `VerifiedApproverArgs` (`--oidc-*`) is the flattenable-args precedent; it owns the `--oidc-issuer` name so the new flags use the `--oauth-` prefix | `crates/mecmcp-runtime/src/cli.rs:347-450` |

## Design decisions (and why)

1. **Async verification as a concrete `Arc<OAuthResource<G>>` on the boundary, not an async
   `Authenticate` callback.** Changing `Authenticate<G>` to return a future would break
   every consumer's `BearerAuthenticator::new(syntax, |candidate| ...)` call (the doc
   examples and ~40 test sites) for something only OAuth needs. The verified-approver
   feature already established the pattern: an optional, feature-gated verifier object held
   beside the authenticator, awaited inside the already-async middleware. We copy it.
2. **Static first, then JWT, and only for JWT-shaped candidates.** The static lookup is
   constant-time over the store and offline. Only when it misses *and* the candidate is
   shaped like a compact JWT (two dots, three non-empty base64url segments, <= 8 KiB) do we
   enter the async path. A random guess therefore never costs a lock or a fetch.
3. **Audience = canonical resource URI, exact match; `--oauth-audience` may override.**
   RFC 8707 says the token's audience is the resource indicator. Some IdPs (Authentik)
   can only emit a client id as `aud`; the override exists for them and is documented as
   "must be unique per server, otherwise tokens are not server-bound". The startup log
   warns when it differs from the resource.
4. **`http://` resource URIs are accepted only for loopback hosts** (`localhost`,
   `127.0.0.1`, `[::1]`), matching how the rest of the crate treats loopback (listener
   refusals, `serve_on_loopback`) and what MCP clients accept for local development.
   The issuer must be `https` always (the discovery code already enforces it).
5. **Verified-but-unmapped -> 403 `insufficient_scope`; failed verification -> 401
   `invalid_token`; IdP unavailable / verifier saturated -> 503 `temporarily_unavailable`.**
   RFC 6750 s3.1: 401 means the credential is not good; 403 `insufficient_scope` means the
   credential is good but carries too little authority. A re-authorising client can act on
   403, and 401 would make it loop re-authenticating for the same empty grant. 503 keeps an
   IdP outage from looking like a credential problem (a client that gets 401 discards a
   good token) and never affects static-token traffic.
6. **Scope map file is JSON** (`serde_json` is already a transport dependency; `toml` is not
   in `mecmcp-transport`'s tree). Version-tagged, `deny_unknown_fields`, every entry must
   state both `tools` and `devices` explicitly (use `[]` for none). Matching is exact and
   case-sensitive; results are the union across matched scope and role entries.
7. **`access-token` profile is a config switch on `OidcConfig`, not a change to the ID-token
   path.** RFC 9068 requires `iss exp aud sub client_id iat jti`; the existing path already
   requires `iat` and `sub`. The new profile additionally requires `jti` and a client id
   (`client_id`, else `azp`), and can require the `at+jwt` `typ` header. `typ` enforcement
   is a flag defaulting to off because Keycloak's default access tokens carry `typ: JWT`.
8. **`CallerCtx` gets one new field, `oauth: Option<OAuthIdentity>`** (decided over reusing
   `oidc_subject`, which is a *token-entry binding* consumed by `bind_approver`, and which
   has no client id). The ~60 struct literals are fixed mechanically in their own task so
   the diff is reviewable as "add `oauth: None,`".
9. **Principal display is `oauth:<sub>`** (escaped), and `TokenEntry::validate` reserves the
   `oauth:` name prefix, so a static token can never share an identity key with an OAuth
   caller in `mecmcp-changeset`'s owner/approver comparison.
10. **RFC 9728 metadata is served at both the path-inserted URL and the root URL.**
    For resource `https://h/mcp` clients try `/.well-known/oauth-protected-resource/mcp`
    first (RFC 9728 s3.1) and fall back to the root; the issue names only the root. The
    `resource_metadata` challenge parameter points at the path-inserted form when the
    resource has a path.

## File Structure

| Path | Responsibility | Task |
|---|---|---|
| `crates/mecmcp-oidc/src/claims.rs` | `scopes`, `client_id` on `VerifiedClaims`; `extract_scopes`, `extract_client_id`, `is_scope_token` | 1 |
| `crates/mecmcp-oidc/src/verify.rs` | `TokenProfile`, `OidcConfig::token_profile`, `typ` / `jti` / client-id enforcement | 1 |
| `crates/mecmcp-oidc/src/error.rs` | `VerificationFailure::WrongTokenType` + reason code | 1 |
| `crates/mecmcp-oidc/src/resource.rs` (new) | `ResourceUri`: canonical, header-safe, route-safe resource URI + RFC 9728 URLs | 2 |
| `crates/mecmcp-auth/src/oauth.rs` (new) | `OAuthIdentity`, `OAUTH_TOKEN_NAME_PREFIX` | 3 |
| `crates/mecmcp-auth/src/store.rs`, `entry.rs` | `CallerCtx.oauth`, `CallerCtx::oauth(..)`, reserved name prefix; ~60 mechanical literal fix-ups across the workspace | 3 |
| `crates/mecmcp-audit/src/attribution.rs`, `scope.rs` | `Principal::OAuth`, audit fields | 4 |
| `crates/mecmcp-changeset/src/records.rs` | `PersistedPrincipal::OAuth` | 4 |
| `crates/mecmcp-transport/src/auth.rs` | `resource_metadata` in challenges (5); OAuth step in the middleware (9); shape prefilter and header strip (10) | 5, 9, 10 |
| `crates/mecmcp-transport/tests/oauth_challenge.rs` (new, ungated) | challenge-header tests | 5 |
| `crates/mecmcp-transport/Cargo.toml`, `src/lib.rs`, `.github/workflows/ci.yml` | `oauth-resource` feature, exports, CI steps | 6 |
| `crates/mecmcp-transport/src/oauth_resource/scope_map.rs` (new, gated) | `OAuthScopeMap`, file format, fail-closed mapping | 6 |
| `crates/mecmcp-transport/src/oauth_resource/mod.rs` (new, gated) | `OAuthResourceConfig` (6), `OAuthResource`/`OAuthRejection` (8), bounds (10) | 6, 8, 10 |
| `crates/mecmcp-transport/src/oauth_resource/metadata.rs` (new, gated) | RFC 9728 document + router | 7 |
| `crates/mecmcp-transport/src/server.rs` | merge metadata router outside the bearer boundary | 9 |
| `crates/mecmcp-transport/tests/oauth_resource.rs` (new, gated) | signed-JWT integration tests; grows in 8, 9, 10 | 6 (empty), 8, 9, 10 |
| `crates/mecmcp-runtime/src/cli.rs` | `OAuthResourceArgs` | 11 |
| `docs/OAUTH.md` (new), `docs/THREAT-MODEL.md`, `docs/ONBOARDING.md`, `CHANGELOG.md` | operator guide, trust boundary, release note | 12 |

Task order keeps the workspace green after each commit: 1-2 (oidc, additive), 3-4 (auth/audit
field + mechanical fix-up), 5 (ungated challenge), 6-10 (feature-gated transport), 11 (runtime),
12 (docs).

---

### Task 1: `mecmcp-oidc` access-token profile, scopes and client id

Satisfies requirement 6 (and the verification half of 4).

**Files:**
- Modify: `crates/mecmcp-oidc/src/claims.rs` (add fields at :16-47; add helpers after `extract_roles` :50)
- Modify: `crates/mecmcp-oidc/src/verify.rs` (`OidcConfig` :42-80, `verify_with` :155-220, tests module :361+)
- Modify: `crates/mecmcp-oidc/src/error.rs` (new variant after `MissingIssuedAt`; arm in `reason_code` :150-158)
- Modify: `crates/mecmcp-oidc/src/lib.rs` (exports)

**Interfaces:**
- Consumes: existing `OidcConfig::new(issuer, audience, role_claim)`, `TokenVerifier::verify`.
- Produces:
  - `pub enum TokenProfile { IdToken (default), AccessToken { require_at_jwt_typ: bool } }`
  - `OidcConfig { pub token_profile: TokenProfile, .. }` (set by `new` to `IdToken`)
  - `VerifiedClaims { pub scopes: Vec<String>, pub client_id: Option<String>, .. }`
  - `pub fn is_scope_token(candidate: &str) -> bool` (exported from the crate root)
  - `VerificationFailure::WrongTokenType` with `reason_code() == "wrong_token_type"`

RFC 9068 requires `iss exp aud sub client_id iat jti` on an access token. `verify_with`
already requires `iss exp aud sub` (jsonwebtoken) and `iat` (`MissingIssuedAt`), so the
ID-token defaults are *right* for access tokens on those. What is missing is `jti` and a
client id, plus the `typ` header. Those become profile-specific requirements; the
`IdToken` profile is untouched (proved by Step 1 test 5).

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module of `crates/mecmcp-oidc/src/verify.rs` (it already has
`generate_test_key`, `sign_token`, `now`, `FixtureSource`, `ISSUER`, `AUDIENCE`, `KID`):

```rust
    fn access_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "alice",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "iat": now() - 60,
            "jti": "at-1",
            "client_id": "odysseus",
            "scope": "junos:read junos:write",
            "roles": ["netops"],
        })
    }

    fn access_verifier(key: &TestKey, require_typ: bool) -> TokenVerifier {
        let mut config = OidcConfig::new(ISSUER, AUDIENCE, "roles");
        config.token_profile = TokenProfile::AccessToken {
            require_at_jwt_typ: require_typ,
        };
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        TokenVerifier::new(config, Arc::new(FixtureSource { jwks }))
    }

    fn sign_with_typ(key: &TestKey, claims: &serde_json::Value, typ: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        header.typ = Some(typ.to_owned());
        jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("token signing")
    }

    #[tokio::test]
    async fn access_token_scopes_and_client_id_are_extracted() {
        let key = generate_test_key(KID);
        let token = sign_token(&key, &access_claims(), KID);
        let claims = access_verifier(&key, false)
            .verify(&token)
            .await
            .expect("access token must verify");
        assert_eq!(claims.scopes, vec!["junos:read", "junos:write"]);
        assert_eq!(claims.client_id.as_deref(), Some("odysseus"));
        assert_eq!(claims.roles, vec!["netops"]);
    }

    #[tokio::test]
    async fn azp_is_the_client_id_when_client_id_is_absent() {
        let key = generate_test_key(KID);
        let mut claims = access_claims();
        claims.as_object_mut().expect("object").remove("client_id");
        claims["azp"] = serde_json::json!("keycloak-client");
        let token = sign_token(&key, &claims, KID);
        let verified = access_verifier(&key, false).verify(&token).await.expect("verifies");
        assert_eq!(verified.client_id.as_deref(), Some("keycloak-client"));
    }

    #[tokio::test]
    async fn scp_array_is_accepted_and_an_element_containing_a_space_is_dropped() {
        let key = generate_test_key(KID);
        let mut claims = access_claims();
        claims.as_object_mut().expect("object").remove("scope");
        // "junos:read junos:admin" as ONE array element must not be split into two
        // scopes, and must not survive as one either: it is not a scope-token.
        claims["scp"] = serde_json::json!(["junos:read", "junos:read junos:admin", 7, "junos:write"]);
        let token = sign_token(&key, &claims, KID);
        let verified = access_verifier(&key, false).verify(&token).await.expect("verifies");
        assert_eq!(verified.scopes, vec!["junos:read", "junos:write"]);
    }

    #[tokio::test]
    async fn a_non_string_non_array_scope_claim_yields_no_scopes() {
        let key = generate_test_key(KID);
        let mut claims = access_claims();
        claims["scope"] = serde_json::json!(5);
        let token = sign_token(&key, &claims, KID);
        let verified = access_verifier(&key, false).verify(&token).await.expect("verifies");
        assert!(verified.scopes.is_empty());
    }

    /// The ID-token profile is unchanged: no `jti` and no client id still verify.
    #[tokio::test]
    async fn id_token_profile_still_accepts_a_token_without_jti_or_client_id() {
        let key = generate_test_key(KID);
        let jwks = JwkSet { keys: vec![key.jwk.clone()] };
        let verifier = verifier_for(jwks);
        let token = sign_token(&key, &valid_claims(), KID);
        let verified = verifier.verify(&token).await.expect("ID-token path unchanged");
        assert!(verified.client_id.is_none());
        assert!(verified.jwt_id.is_none());
    }

    #[tokio::test]
    async fn access_profile_requires_a_client_id() {
        let key = generate_test_key(KID);
        let mut claims = access_claims();
        claims.as_object_mut().expect("object").remove("client_id");
        let token = sign_token(&key, &claims, KID);
        let error = access_verifier(&key, false).verify(&token).await.unwrap_err();
        assert_eq!(error, VerificationFailure::MissingClaim("client_id".to_owned()));
    }

    #[tokio::test]
    async fn access_profile_requires_a_jti() {
        let key = generate_test_key(KID);
        let mut claims = access_claims();
        claims.as_object_mut().expect("object").remove("jti");
        let token = sign_token(&key, &claims, KID);
        let error = access_verifier(&key, false).verify(&token).await.unwrap_err();
        assert_eq!(error, VerificationFailure::MissingClaim("jti".to_owned()));
    }

    #[tokio::test]
    async fn at_jwt_typ_is_enforced_only_when_configured() {
        let key = generate_test_key(KID);
        let strict = access_verifier(&key, true);
        let lax = access_verifier(&key, false);

        let plain_jwt = sign_with_typ(&key, &access_claims(), "JWT");
        assert_eq!(strict.verify(&plain_jwt).await.unwrap_err(), VerificationFailure::WrongTokenType);
        assert!(lax.verify(&plain_jwt).await.is_ok());

        for accepted in ["at+jwt", "AT+JWT", "application/at+jwt"] {
            let token = sign_with_typ(&key, &access_claims(), accepted);
            assert!(strict.verify(&token).await.is_ok(), "typ {accepted:?} must be accepted");
        }
    }

    #[test]
    fn is_scope_token_follows_rfc_6749_section_3_3() {
        use crate::claims::is_scope_token;
        assert!(is_scope_token("junos:read"));
        assert!(is_scope_token("https://example.com/scope"));
        assert!(!is_scope_token(""));
        assert!(!is_scope_token("two words"));
        assert!(!is_scope_token("quo\"te"));
        assert!(!is_scope_token("back\\slash"));
        assert!(!is_scope_token("tab\there"));
        assert!(!is_scope_token("caf\u{e9}"));
        assert!(!is_scope_token(&"a".repeat(129)));
    }

    #[tokio::test]
    async fn scopes_are_deduplicated_and_capped() {
        let key = generate_test_key(KID);
        let many: Vec<String> = (0..100).map(|index| format!("s{index}")).collect();
        let mut claims = access_claims();
        claims["scope"] = serde_json::json!(format!("a a {}", many.join(" ")));
        let token = sign_token(&key, &claims, KID);
        let verified = access_verifier(&key, false).verify(&token).await.expect("verifies");
        assert_eq!(verified.scopes.len(), 64);
        assert_eq!(verified.scopes.iter().filter(|scope| scope.as_str() == "a").count(), 1);
    }
```

The `TestKey` / `sign_token` helpers are private to the `tests` module; the new tests live
in the same module so they can use them.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-oidc 2>&1 | tail -20`
Expected: compile error, `TokenProfile` / `WrongTokenType` / `scopes` not found.

- [ ] **Step 3: Implement**

`crates/mecmcp-oidc/src/claims.rs`, add to `VerifiedClaims` (after `display_name`):

```rust
    /// OAuth scopes from the `scope` claim (RFC 9068 s2.2.3: a space-delimited
    /// string) or, when `scope` is absent, the `scp` claim (a string or an array).
    ///
    /// Each entry is a valid RFC 6749 s3.3 scope-token; anything else (an empty
    /// string, an array element containing a space, a control character) is dropped
    /// rather than split or repaired, so a crafted claim can only ever *reduce*
    /// what a caller maps to. Deduplicated, at most 64 entries of at most 128 bytes.
    /// A claim of any other JSON type yields an empty list.
    pub scopes: Vec<String>,
    /// The OAuth client the token was issued to: `client_id` (RFC 9068), else
    /// `azp`. `None` when neither is a clean string (<= 128 bytes, no control
    /// characters). Required (non-`None`) under [`crate::TokenProfile::AccessToken`].
    pub client_id: Option<String>,
```

and after `extract_roles`:

```rust
/// Maximum scopes retained from one token.
const MAX_SCOPES: usize = 64;
/// Maximum bytes in one scope-token or client id.
const MAX_TOKEN_LEN: usize = 128;

/// Whether `candidate` is a legal OAuth scope-token (RFC 6749 s3.3):
/// `1*( %x21 / %x23-5B / %x5D-7E )`, so no space, no `"`, no `\`, no control
/// character, no non-ASCII. Also bounded to 128 bytes.
#[must_use]
pub fn is_scope_token(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= MAX_TOKEN_LEN
        && candidate
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Pull the token's scopes out of its extra claims (see [`VerifiedClaims::scopes`]).
pub(crate) fn extract_scopes(
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let raw: Vec<&str> = match extra.get("scope").or_else(|| extra.get("scp")) {
        Some(serde_json::Value::String(joined)) => joined.split(' ').collect(),
        Some(serde_json::Value::Array(items)) => {
            items.iter().filter_map(serde_json::Value::as_str).collect()
        }
        _ => Vec::new(),
    };
    let mut scopes: Vec<String> = Vec::new();
    for candidate in raw {
        if !is_scope_token(candidate) || scopes.iter().any(|seen| seen == candidate) {
            continue;
        }
        if scopes.len() == MAX_SCOPES {
            break;
        }
        scopes.push(candidate.to_owned());
    }
    scopes
}

/// `client_id` (RFC 9068), else `azp`; `None` unless a clean, bounded string.
pub(crate) fn extract_client_id(
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let raw = extra.get("client_id").or_else(|| extra.get("azp"))?.as_str()?;
    let clean = !raw.is_empty()
        && raw.len() <= MAX_TOKEN_LEN
        && !raw.chars().any(char::is_control);
    clean.then(|| raw.to_owned())
}
```

`crates/mecmcp-oidc/src/error.rs`: add

```rust
    /// The token's `typ` header is not `at+jwt` / `application/at+jwt` and the
    /// verifier is configured to require it (RFC 9068 s2.1). Stops an ID token or
    /// another JWT type from being replayed as an access token.
    #[error("token typ header is not an access-token type")]
    WrongTokenType,
```

and in `reason_code`: `Self::WrongTokenType => "wrong_token_type",`.

`crates/mecmcp-oidc/src/verify.rs`:

```rust
/// Which JWT profile a [`TokenVerifier`] enforces beyond the common checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenProfile {
    /// OIDC ID-token / assertion style: the pre-existing behaviour.
    #[default]
    IdToken,
    /// RFC 9068 JWT access token. Additionally requires `jti` and a client id
    /// (`client_id`, else `azp`).
    AccessToken {
        /// Also require the `typ` header to be `at+jwt` or `application/at+jwt`.
        /// Off by default because some IdPs (Keycloak by default) sign access
        /// tokens with `typ: JWT`; recommended wherever the IdP supports it.
        require_at_jwt_typ: bool,
    },
}
```

Add to `OidcConfig`: `pub token_profile: TokenProfile,` (doc: "Defaults to [`TokenProfile::IdToken`]") and `token_profile: TokenProfile::default(),` in `new`.

In `verify_with`, immediately after `decode_header`:

```rust
        if matches!(
            self.config.token_profile,
            TokenProfile::AccessToken { require_at_jwt_typ: true }
        ) && !is_at_jwt_typ(header.typ.as_deref())
        {
            return Err(VerificationFailure::WrongTokenType);
        }
```

(before `self.cache.keys()`, so a wrong-typed token never costs a fetch), and after
`let roles = ...`:

```rust
        let scopes = extract_scopes(&token_data.claims.extra);
        let client_id = extract_client_id(&token_data.claims.extra);
        if matches!(self.config.token_profile, TokenProfile::AccessToken { .. }) {
            if token_data.claims.jti.is_none() {
                return Err(VerificationFailure::MissingClaim("jti".to_owned()));
            }
            if client_id.is_none() {
                return Err(VerificationFailure::MissingClaim("client_id".to_owned()));
            }
        }
```

adding `scopes, client_id,` to the returned `VerifiedClaims`, plus:

```rust
/// RFC 9068 s2.1: `at+jwt`, or the full media type, compared case-insensitively.
fn is_at_jwt_typ(typ: Option<&str>) -> bool {
    typ.is_some_and(|value| {
        value.eq_ignore_ascii_case("at+jwt") || value.eq_ignore_ascii_case("application/at+jwt")
    })
}
```

Update the `use crate::claims::{...}` line to include `extract_client_id, extract_scopes`.
`lib.rs`: `pub use claims::{VerifiedClaims, is_scope_token};` and
`pub use verify::{OidcConfig, TokenProfile, TokenVerifier, VerifyOptions};`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-oidc && cargo check --locked --manifest-path fuzz/Cargo.toml --bins`
Expected: all pass (existing ID-token tests included).

- [ ] **Step 5: Sabotage (prove the tests bite)**

One at a time; run `cargo test --locked -p mecmcp-oidc` after each, then `git checkout` the file:
1. In `extract_scopes`, drop the `!is_scope_token(candidate) ||` half of the filter ->
   `scp_array_is_accepted_and_an_element_containing_a_space_is_dropped` must fail.
2. Delete the `require_at_jwt_typ` check in `verify_with` -> `at_jwt_typ_is_enforced_only_when_configured` must fail.
3. Delete the `jti` / client-id requirement -> `access_profile_requires_a_client_id` and `access_profile_requires_a_jti` must fail.
4. Make that requirement unconditional (drop the `matches!(.., AccessToken { .. })` guard) ->
   `id_token_profile_still_accepts_a_token_without_jti_or_client_id` must fail.

**Security review points:** alg confusion untouched (`matching_algorithm` still runs; no
change to the allow-list); `scope` is attacker-influenced only through the IdP, but a
crafted array element cannot widen grants (dropped, never split); the `typ` check runs
before any key fetch; `client_id` is length-bounded and control-free because it lands in
audit records (Task 4).

- [ ] **Step 6: Verify block, then commit**

```bash
git add crates/mecmcp-oidc
git commit -m "feat(oidc): RFC 9068 access-token profile, scopes and client id (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~330 lines (about 190 of them tests).

---

### Task 2: `ResourceUri` canonical resource identifier

Satisfies the "configured canonical resource URI" half of requirements 1, 2 and 4, and the
https-validation decision in 9.

**Files:**
- Create: `crates/mecmcp-oidc/src/resource.rs`
- Modify: `crates/mecmcp-oidc/src/lib.rs` (`pub mod resource;` + re-export)

**Interfaces:**
- Consumes: `url::Url` (already a `mecmcp-oidc` dependency).
- Produces:
  - `ResourceUri::parse(&str) -> Result<ResourceUri, ResourceUriError>`
  - `ResourceUri::as_str(&self) -> &str` (the exact string used as the JWT audience and as `resource`)
  - `ResourceUri::metadata_path(&self) -> String` (RFC 9728 s3.1 path-inserted route, e.g. `/.well-known/oauth-protected-resource/mcp`)
  - `ResourceUri::metadata_url(&self) -> String` (absolute form of the above)
  - `pub const ROOT_METADATA_PATH: &str = "/.well-known/oauth-protected-resource"`
  - `ResourceUriError` (`thiserror`, `PartialEq`)

The string is used three ways: as the `aud` we compare byte-for-byte, as a JSON value in the
metadata document, and as part of a `WWW-Authenticate` header and an axum route. The type
makes every one of those safe by construction: ASCII, canonical (equal to its own `Url`
serialisation, so what we compare is what a client computes), no userinfo/query/fragment,
and a path limited to `[A-Za-z0-9._~/-]` (no `{`, `*` or `%` that axum would interpret).

- [ ] **Step 1: Write the failing tests**

`crates/mecmcp-oidc/src/resource.rs` (tests at the bottom; implementation in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_resources_and_derives_rfc_9728_urls() {
        let resource = ResourceUri::parse("https://junos.lab.example/mcp").expect("valid");
        assert_eq!(resource.as_str(), "https://junos.lab.example/mcp");
        assert_eq!(
            resource.metadata_path(),
            "/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            resource.metadata_url(),
            "https://junos.lab.example/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn a_bare_origin_uses_the_root_metadata_path() {
        let resource = ResourceUri::parse("https://junos.lab.example/").expect("valid");
        assert_eq!(resource.metadata_path(), ROOT_METADATA_PATH);
    }

    #[test]
    fn a_non_default_port_is_part_of_the_origin() {
        let resource = ResourceUri::parse("https://h.example:8443/mcp").expect("valid");
        assert_eq!(
            resource.metadata_url(),
            "https://h.example:8443/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn loopback_may_use_plain_http_and_nothing_else_may() {
        assert!(ResourceUri::parse("http://127.0.0.1:8080/mcp").is_ok());
        assert!(ResourceUri::parse("http://localhost:8080/mcp").is_ok());
        assert!(ResourceUri::parse("http://[::1]:8080/mcp").is_ok());
        for bad in [
            "http://junos.lab.example/mcp",
            "http://10.0.0.5/mcp",
            "http://localhost.evil.example/mcp",
            "ftp://junos.lab.example/mcp",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::InsecureScheme,
                "{bad}"
            );
        }
    }

    #[test]
    fn forbidden_components_are_refused() {
        for bad in [
            concat!("https://user", ":pw@h.example/mcp"),
            "https://user@h.example/mcp",
            "https://h.example/mcp?x=1",
            "https://h.example/mcp?",
            "https://h.example/mcp#frag",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::ForbiddenComponent,
                "{bad}"
            );
        }
    }

    #[test]
    fn unsafe_characters_are_refused_before_parsing() {
        for bad in [
            "https://h.example/m cp",
            "https://h.example/mcp\r\nX-Evil: 1",
            "https://h.example/\"mcp",
            "https://h.example/m\\cp",
            "https://b\u{fc}cher.example/mcp",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::UnsafeCharacters,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn route_metacharacters_in_the_path_are_refused() {
        for bad in [
            "https://h.example/{id}",
            "https://h.example/a/*",
            "https://h.example/a%2Fb",
            "https://h.example/a:b",
        ] {
            assert_eq!(
                ResourceUri::parse(bad).unwrap_err(),
                ResourceUriError::PathCharacters,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_non_canonical_spelling_is_refused_with_the_canonical_form() {
        assert_eq!(
            ResourceUri::parse("https://H.Example/mcp").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/mcp".to_owned())
        );
        assert_eq!(
            ResourceUri::parse("https://h.example").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/".to_owned())
        );
        assert_eq!(
            ResourceUri::parse("https://h.example:443/mcp").unwrap_err(),
            ResourceUriError::NotCanonical("https://h.example/mcp".to_owned())
        );
    }

    #[test]
    fn a_relative_reference_is_not_absolute() {
        assert!(matches!(
            ResourceUri::parse("/mcp").unwrap_err(),
            ResourceUriError::NotAbsolute(_)
        ));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-oidc resource 2>&1 | tail`
Expected: FAIL (unresolved import / module not found). Add `pub mod resource;` to `lib.rs` first so the failure is "cannot find `ResourceUri`".

- [ ] **Step 3: Implement**

```rust
//! The canonical identifier a resource server presents as its OAuth resource
//! (RFC 8707 s2) and protected-resource metadata `resource` (RFC 9728 s2).

use url::{Host, Url};

/// The RFC 9728 well-known path for a resource with no path component.
pub const ROOT_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Why a string is not an acceptable resource URI.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResourceUriError {
    /// Contains a non-ASCII-graphic byte, a quote, or a backslash.
    #[error("resource URI must be printable ASCII without quotes or backslashes")]
    UnsafeCharacters,
    /// Not parseable as an absolute URI.
    #[error("resource URI is not an absolute URI: {0}")]
    NotAbsolute(String),
    /// Not `https`, and not `http` to a loopback host.
    #[error("resource URI must use https (http is allowed only for a loopback host)")]
    InsecureScheme,
    /// Carries userinfo, a query, or a fragment (RFC 8707 s2).
    #[error("resource URI must not carry userinfo, a query, or a fragment")]
    ForbiddenComponent,
    /// Path contains something other than letters, digits and `. _ ~ - /`.
    #[error("resource URI path may contain only letters, digits and . _ ~ - /")]
    PathCharacters,
    /// Differs from its own normalised form; the field is the form to use.
    #[error("resource URI is not canonical; use {0:?}")]
    NotCanonical(String),
}

/// A validated, canonical resource URI. See the module docs for why each rule exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceUri {
    canonical: String,
    origin: String,
    path: String,
}

impl ResourceUri {
    /// Parse and validate `input`.
    ///
    /// # Errors
    /// Returns the first [`ResourceUriError`] that applies.
    pub fn parse(input: &str) -> Result<Self, ResourceUriError> {
        if !input.bytes().all(|byte| byte.is_ascii_graphic()) || input.contains(['"', '\\']) {
            return Err(ResourceUriError::UnsafeCharacters);
        }
        let url = Url::parse(input).map_err(|error| ResourceUriError::NotAbsolute(error.to_string()))?;
        if url.host().is_none() {
            return Err(ResourceUriError::NotAbsolute("no host".to_owned()));
        }
        let loopback = match url.host() {
            Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        if !scheme_ok {
            return Err(ResourceUriError::InsecureScheme);
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ResourceUriError::ForbiddenComponent);
        }
        let path_ok = url.path().bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-' | b'/')
        });
        if !path_ok {
            return Err(ResourceUriError::PathCharacters);
        }
        if url.as_str() != input {
            return Err(ResourceUriError::NotCanonical(url.as_str().to_owned()));
        }
        Ok(Self {
            canonical: input.to_owned(),
            origin: url.origin().ascii_serialization(),
            path: url.path().to_owned(),
        })
    }

    /// The exact string used as the audience and as the metadata `resource`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The RFC 9728 s3.1 route: the well-known prefix with the resource path inserted.
    #[must_use]
    pub fn metadata_path(&self) -> String {
        if self.path == "/" {
            return ROOT_METADATA_PATH.to_owned();
        }
        format!("{ROOT_METADATA_PATH}{}", self.path)
    }

    /// The absolute URL of [`Self::metadata_path`], for the `resource_metadata` challenge parameter.
    #[must_use]
    pub fn metadata_url(&self) -> String {
        format!("{}{}", self.origin, self.metadata_path())
    }
}
```

`lib.rs`: `pub mod resource;` and `pub use resource::{ROOT_METADATA_PATH, ResourceUri, ResourceUriError};`.
Place the tests module from Step 1 at the bottom with `#[allow(clippy::unwrap_used)]` (the
tests use `.unwrap_err()`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-oidc resource`
Expected: 9 passed.

- [ ] **Step 5: Sabotage**

Remove the `url.as_str() != input` check -> `a_non_canonical_spelling...` fails.
Change `byte.is_ascii_alphanumeric() || ...` to also allow `%` -> `route_metacharacters...` fails.
Drop the `loopback` term (accept any `http`) -> `loopback_may_use_plain_http...` fails.

**Security review points:** header injection (CR/LF/quote/backslash rejected before
parsing); aud substring tricks cannot arise because the value is compared whole; axum route
injection (`{`, `*`) closed by the path whitelist; `localhost.evil.example` is not loopback
(it is a `Domain`, compared whole); Host-header independence (the URI is configuration, never
derived from the request).

- [ ] **Step 6: Verify block, then commit**

```bash
git add crates/mecmcp-oidc
git commit -m "feat(oidc): ResourceUri canonical resource identifier (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~270 lines (about 120 tests).

---

### Task 3: `CallerCtx.oauth` and `OAuthIdentity` (and the mechanical fix-up)

Satisfies requirement 7 (carrying side) and 8 (the context holds no token).

**Files:**
- Create: `crates/mecmcp-auth/src/oauth.rs`
- Modify: `crates/mecmcp-auth/src/lib.rs` (`pub mod oauth;` + exports)
- Modify: `crates/mecmcp-auth/src/store.rs` (struct :110-170, `From<&TokenEntry>` :172-194, constructor, tests)
- Modify: `crates/mecmcp-auth/src/entry.rs:260-270` (reserved name prefix)
- Modify (mechanical, compiler-driven): every `CallerCtx { .. }` struct literal. The list from `grep -rln 'verified_approver: None' --include='*.rs' crates` is 34 files / ~60 sites, but that grep also matches `Attribution { .. }` literals which must **not** change; follow the compiler (`error[E0063]: missing field oauth`), not the grep.

**Interfaces:**
- Produces:
  - `pub struct OAuthIdentity { pub issuer: String, pub subject: String, pub client_id: Option<String> }` (`Debug, Clone, PartialEq, Eq`)
  - `pub const OAUTH_TOKEN_NAME_PREFIX: &str = "oauth:"`
  - `OAuthIdentity::token_name(&self) -> String` (`"oauth:" + subject`)
  - `CallerCtx { pub oauth: Option<OAuthIdentity>, .. }` (`None` from `From<&TokenEntry>`)
  - `CallerCtx::<G>::oauth(identity: OAuthIdentity, devices: ScopeSet, tools: ScopeSet, actor_type: ActorType) -> CallerCtx<G>`: `grant: None`, `verified_approver: None`, `oidc_subject: None`, fresh `request_id`.

`CallerCtx` has no field for a credential and this task adds none; the new test pins that
by exhaustive destructuring, so adding a `token`/`bearer` field later fails to compile
there and forces a decision.

- [ ] **Step 1: Write the failing tests**

In `crates/mecmcp-auth/src/store.rs` tests module:

```rust
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
        assert!(ctx.grant.is_none(), "OAuth callers never hold a vendor grant");
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
            OAuthIdentity { issuer: "i".into(), subject: "s".into(), client_id: None },
            ScopeSet::Allowlist(vec![]),
            ScopeSet::Allowlist(vec![]),
            crate::ActorType::Unknown,
        );
        let CallerCtx {
            token_name: _, devices: _, tools: _, grant: _, provider: _, provider_tier: _,
            on_behalf_of: _, actor_type: _, oidc_subject: _, verified_approver: _,
            client_name: _, model_id: _, session_id: _, request_id: _, oauth: _,
        } = ctx;
    }
```

(in `entry.rs` tests, next to the existing name-validation tests)

```rust
    #[test]
    fn the_oauth_name_prefix_is_reserved() {
        let (_, mut entry) = sample_entry();   // use the helper the neighbouring tests use
        entry.name = "oauth:alice".to_owned();
        let error = entry.validate().unwrap_err().to_string();
        assert!(error.contains("reserved"), "{error}");
    }
```

(If the neighbouring name tests build the entry differently, copy that construction; the
assertion is what matters.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-auth 2>&1 | tail`
Expected: compile error (`OAuthIdentity` not found).

- [ ] **Step 3: Implement**

`crates/mecmcp-auth/src/oauth.rs`:

```rust
//! The identity of a caller authenticated by an OAuth access token.

/// Reserved prefix of every [`crate::CallerCtx::token_name`] minted for an OAuth caller.
///
/// [`crate::TokenEntry::validate`] refuses a static token name with this prefix, so a
/// static token and an OAuth caller can never share a name, a rate-limit bucket, or an
/// owner/approver identity key in `mecmcp-changeset`.
pub const OAUTH_TOKEN_NAME_PREFIX: &str = "oauth:";

/// Who an OAuth access token says the caller is. Deliberately three short strings and
/// nothing else: the token itself, and every other claim, are dropped after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthIdentity {
    /// The `iss` the token was verified against.
    pub issuer: String,
    /// The token's `sub` (validated by the transport: non-empty, <= 128 bytes, no
    /// whitespace or control characters).
    pub subject: String,
    /// `client_id` / `azp`, when the token carried one.
    pub client_id: Option<String>,
}

impl OAuthIdentity {
    /// The non-secret name used for rate limiting and attribution.
    #[must_use]
    pub fn token_name(&self) -> String {
        format!("{OAUTH_TOKEN_NAME_PREFIX}{}", self.subject)
    }
}
```

`store.rs`: add to `CallerCtx` (after `request_id`):

```rust
    /// Set when this caller was authenticated by an OAuth access token rather than a
    /// static token. Holds the issuer, subject and client id only; **never the token**.
    pub oauth: Option<crate::oauth::OAuthIdentity>,
```
`oauth: None,` in `From<&TokenEntry<G>>`, and

```rust
impl<G: Grant> CallerCtx<G> {
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
}
```

(merge into the existing `impl<G: Grant> CallerCtx<G>` block rather than adding a second one).
`entry.rs` validate, after the whitespace check:

```rust
        if self.name.starts_with(crate::oauth::OAUTH_TOKEN_NAME_PREFIX) {
            return Err(EntryError::Invalid(format!(
                "token name '{}' uses the reserved '{}' prefix",
                self.name,
                crate::oauth::OAUTH_TOKEN_NAME_PREFIX
            )));
        }
```
`lib.rs`: `pub mod oauth;` and `pub use oauth::{OAUTH_TOKEN_NAME_PREFIX, OAuthIdentity};`.

Then drive the compiler: `cargo build --workspace --all-targets --all-features 2>&1 | grep -A3 'E0063'` and add
`oauth: None,` to each `CallerCtx` literal it names (after the `request_id` / last field).
Do not add it to `Attribution` literals.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --workspace --locked --features mecmcp-audit/test-util,mecmcp-changeset/test-util,mecmcp-transport/test-util`
Expected: all pass, including the 3 new `mecmcp-auth` tests and the entry test.

- [ ] **Step 5: Sabotage**

Delete the `starts_with` block in `TokenEntry::validate` -> `the_oauth_name_prefix_is_reserved`
fails. Add a field `pub token: String` to `CallerCtx` (and `token: String::new()` to
`CallerCtx::oauth`) -> `caller_ctx_has_no_credential_field` stops compiling; revert.

**Security review points:** the context cannot carry the credential (compile-time pinned);
identity-key collision with static tokens closed by the reserved prefix; this is a
public-struct change: downstream vendor repos that build `CallerCtx` literals in tests need
the same one-line fix, called out in the CHANGELOG (Task 12).

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates
git commit -m "feat(auth): CallerCtx.oauth identity and reserved oauth: name prefix (#498)

Adds the field to the ~60 CallerCtx literals mechanically; no behaviour change
for static tokens.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~100 lines of real change + ~60 mechanical `oauth: None,` lines + ~45 tests = ~210.

---

### Task 4: `Principal::OAuth`, persisted principal and audit fields

Satisfies requirement 7 (audit records show `sub` and `client_id`).

**Files:**
- Modify: `crates/mecmcp-audit/src/attribution.rs` (`Principal` :11-24, `Display`, `from_caller` principal at ~:334)
- Modify: `crates/mecmcp-audit/src/scope.rs` (`Drop` :150-262 event fields; tests :270+)
- Modify: `crates/mecmcp-changeset/src/records.rs:137-176` (`PersistedPrincipal`)
- Test: `crates/mecmcp-audit/src/attribution.rs` tests, `crates/mecmcp-audit/src/scope.rs` tests, `crates/mecmcp-changeset/tests/oauth_principal_roundtrip.rs` (new)

**Interfaces:**
- Consumes: `CallerCtx::oauth`, `OAuthIdentity` (Task 3).
- Produces:
  - `Principal::OAuth { issuer: String, subject: String, client_id: Option<String> }`; `Display` = `oauth:<escaped subject>`
  - audit event fields `oauth_issuer`, `oauth_subject`, `oauth_client_id` (empty string for non-OAuth callers, like the other optional fields)
  - `PersistedPrincipal::OAuth { issuer, subject, client_id }`, serialised as `{"type":"oauth","value":{...}}`

`caller = %principal` is emitted **unescaped** (`scope.rs:250`) and `Display` is also the
identity key in `mecmcp-changeset`. An OAuth subject is IdP-controlled free text, so
`Display` must escape; and the separate `oauth_*` fields exist so a SIEM can filter on the
`sub` and the client without parsing `caller`.

- [ ] **Step 1: Write the failing tests**

`attribution.rs` tests:

```rust
    #[test]
    fn from_caller_uses_the_oauth_principal_for_an_oauth_caller() {
        let ctx: mecmcp_auth::CallerCtx = mecmcp_auth::CallerCtx::oauth(
            mecmcp_auth::OAuthIdentity {
                issuer: "https://idp.example".into(),
                subject: "alice".into(),
                client_id: Some("odysseus".into()),
            },
            mecmcp_auth::ScopeSet::Allowlist(vec![]),
            mecmcp_auth::ScopeSet::Allowlist(vec![]),
            mecmcp_auth::ActorType::Agent,
        );
        let attribution = Attribution::from_caller(&ctx);
        assert_eq!(
            attribution.principal,
            Principal::OAuth {
                issuer: "https://idp.example".into(),
                subject: "alice".into(),
                client_id: Some("odysseus".into()),
            }
        );
        assert_eq!(attribution.principal.to_string(), "oauth:alice");
    }

    #[test]
    fn oauth_principal_display_cannot_forge_a_log_field_or_a_token_name() {
        let hostile = Principal::OAuth {
            issuer: "i".into(),
            subject: "x result=ok\nforged".into(),
            client_id: None,
        };
        let rendered = hostile.to_string();
        assert!(!rendered.contains('\n'), "{rendered:?}");
        assert!(!rendered.contains('='), "{rendered:?}");
        // Static token names cannot start with "oauth:" (Task 3), so no Token principal
        // can render to the same identity key as an OAuth one.
    }
```

`scope.rs` tests (uses the existing `run_with_capture`):

```rust
    #[test]
    fn an_oauth_caller_audit_event_carries_issuer_subject_and_client() {
        let ctx: CallerCtx<NoGrant> = CallerCtx::oauth(
            mecmcp_auth::OAuthIdentity {
                issuer: "https://idp.example".into(),
                subject: "alice".into(),
                client_id: Some("odysseus".into()),
            },
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            mecmcp_auth::ActorType::Agent,
        );
        let out = run_with_capture(|| {
            let mut scope = AuditScope::from_caller(&ctx, "get_device_list", "read", vec![]);
            scope.succeed();
        });
        assert!(out.contains("caller=oauth:alice"), "{out}");
        assert!(out.contains("oauth_subject=alice"), "{out}");
        assert!(out.contains("oauth_client_id=odysseus"), "{out}");
        assert!(out.contains("oauth_issuer=https://idp.example"), "{out}");
        assert!(out.contains("authorization=allowed"), "{out}");
    }

    #[test]
    fn a_token_caller_audit_event_has_empty_oauth_fields() {
        let out = run_with_capture(|| {
            let mut scope = AuditScope::from_caller(&ctx("ci"), "get_device_list", "read", vec![]);
            scope.succeed();
        });
        assert!(out.contains("oauth_subject= ") || out.contains("oauth_subject=\"\""), "{out}");
    }
```

(Match the empty-field rendering of the existing fields: look at how
`client_version=` renders in the neighbouring tests and copy that assertion shape.)

`crates/mecmcp-changeset/tests/oauth_principal_roundtrip.rs`:

```rust
use mecmcp_changeset::records::{PersistedAttribution, PersistedPrincipal};

#[test]
fn an_oauth_principal_survives_a_json_round_trip_as_a_tagged_variant() {
    let principal = PersistedPrincipal::OAuth {
        issuer: "https://idp.example".into(),
        subject: "alice".into(),
        client_id: Some("odysseus".into()),
    };
    let json = serde_json::to_value(&principal).expect("serialise");
    assert_eq!(
        json,
        serde_json::json!({
            "type": "oauth",
            "value": {"issuer": "https://idp.example", "subject": "alice", "client_id": "odysseus"}
        })
    );
    let back: PersistedPrincipal = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, principal);
}

#[test]
fn an_oauth_attribution_persists_as_oauth_not_as_a_token() {
    let attribution = mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::OAuth {
            issuer: "https://idp.example".into(),
            subject: "alice".into(),
            client_id: None,
        },
        ..mecmcp_audit::Attribution::stdio()
    };
    let persisted = PersistedAttribution::from(&attribution);
    assert!(matches!(persisted.principal, PersistedPrincipal::OAuth { .. }));
}
```

(Check the module path of `records` in `mecmcp-changeset/src/lib.rs`; the existing
`task8_round5_fixes_test.rs:12` imports `records::PersistedPrincipal`, copy that `use`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-audit -p mecmcp-changeset 2>&1 | tail`
Expected: compile errors, `Principal::OAuth` missing.

- [ ] **Step 3: Implement**

`attribution.rs`:

```rust
pub enum Principal {
    /// An authenticated bearer token, identified by its non-secret name.
    Token(String),
    /// A caller authenticated by an OAuth access token (mecmcp#498). Holds the
    /// verified `iss`, `sub` and `client_id` -- never the token.
    OAuth {
        /// The issuer the token was verified against.
        issuer: String,
        /// The token's `sub`.
        subject: String,
        /// `client_id` / `azp`, when present.
        client_id: Option<String>,
    },
    /// The stdio / `--allow-no-auth` path, where no credential was presented.
    Unauthenticated,
}
```

`Display`: `Principal::OAuth { subject, .. } => write!(f, "oauth:{}", crate::redact::escape_control_chars(subject)),`
`from_caller`: replace `principal: Principal::Token(ctx.token_name.clone()),` with

```rust
            principal: match &ctx.oauth {
                Some(identity) => Principal::OAuth {
                    issuer: identity.issuer.clone(),
                    subject: identity.subject.clone(),
                    client_id: identity.client_id.clone(),
                },
                None => Principal::Token(ctx.token_name.clone()),
            },
```

`scope.rs` `Drop`: compute

```rust
        let (oauth_issuer, oauth_subject, oauth_client_id) = match &self.attribution.principal {
            Principal::OAuth { issuer, subject, client_id } => (
                crate::redact::escape_control_chars(issuer),
                crate::redact::escape_control_chars(subject),
                crate::redact::escape_control_chars(client_id.as_deref().unwrap_or("")),
            ),
            _ => Default::default(),
        };
```
and add `oauth_issuer = %oauth_issuer, oauth_subject = %oauth_subject, oauth_client_id = %oauth_client_id,` to the `tracing::info!` after `caller`. `escape_control_chars` escapes `=` and `"`, **not** `:` or `/`, so the issuer URL stays readable (the test above asserts that).

`records.rs`:

```rust
    /// Caller authenticated by an OAuth access token (mecmcp#498).
    #[serde(rename = "oauth")]
    OAuth {
        /// Issuer the token was verified against.
        issuer: String,
        /// The token's `sub`.
        subject: String,
        /// `client_id` / `azp`, when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
    },
```
plus the `From<&Attribution>` arm. Compiler-driven: any other exhaustive `match` on
`Principal` (`cargo build --workspace --all-targets --all-features`) gets an `OAuth` arm
that behaves as `Token` does today (authenticated).

Downgrade note for the CHANGELOG: a state file containing an `oauth` principal cannot be
read by a binary from before this change. State files are only written for operations
begun by an OAuth caller, which cannot exist before this change.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --workspace --locked --features mecmcp-audit/test-util,mecmcp-changeset/test-util,mecmcp-transport/test-util`
Expected: all pass.

- [ ] **Step 5: Sabotage**

Replace the `from_caller` match with the old `Principal::Token(..)` line -> the
`from_caller_uses_the_oauth_principal...` and the audit-event test fail. Remove the
`escape_control_chars` call in `Display` -> the hostile-subject test fails.

**Security review points:** log injection via `sub` (escaped in `Display` and in the three
fields); `caller` was the one unescaped field, now safe for the new variant; persisted
state keeps the discriminator so an OAuth `alice` and a token named `alice` stay distinct.

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates
git commit -m "feat(audit,changeset): Principal::OAuth with sub and client_id in audit events (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~230 lines.

---

### Task 5: `resource_metadata` in 401 challenges (ungated)

Satisfies requirement 2. Deliberately **not** behind the feature: it is a plain optional
field on the response profile, so it is testable without a JWT stack and the later wiring
(Task 9) only has to call it.

**Files:**
- Modify: `crates/mecmcp-transport/src/auth.rs` (`BearerAuthError` :~16, `BearerResponseProfile` :~107-225, `unauthorized`/`invalid_token` :1149-1190, `validate_realm` :1360)
- Create: `crates/mecmcp-transport/tests/oauth_challenge.rs`

**Interfaces:**
- Produces:
  - `BearerAuthError::InvalidResourceMetadata(&'static str)`
  - `BearerResponseProfile::with_resource_metadata(self, url: impl Into<String>) -> Result<Self, BearerAuthError>`
  - Challenge shapes (resource metadata set):
    - missing/malformed header, detailed style: `Bearer realm="R", resource_metadata="U"`
    - failed credential, detailed: `Bearer realm="R", resource_metadata="U", error="invalid_token", error_description="The access token is invalid"`
    - failed credential / any 401, compact: `Bearer realm="R", resource_metadata="U", error="invalid_token"`
  - Unchanged when unset (byte-identical to today).

The `forbidden()` (403) challenge is intentionally unchanged: RFC 9728 s5.1 attaches the
parameter to the 401 that starts discovery.

- [ ] **Step 1: Write the failing tests**

`crates/mecmcp-transport/tests/oauth_challenge.rs`:

```rust
//! The `resource_metadata` parameter on 401 challenges (RFC 9728 s5.1, mecmcp#498).

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{BearerSyntax, NoGrant};
use mecmcp_transport::{
    BearerAuthenticator, BearerAuthError, BearerBoundary, BearerResponseProfile,
    BoundaryAccounting, LimitsConfig, apply_bearer_boundary,
};
use std::sync::Arc;
use tower::ServiceExt as _;

const METADATA_URL: &str =
    "https://mcp.example/.well-known/oauth-protected-resource/mcp";

fn app(profile: BearerResponseProfile) -> Router {
    let authenticator = BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
    apply_bearer_boundary(
        Router::new().route("/", post(|| async { "ok" })),
        BearerBoundary::new(authenticator, profile),
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    )
}

async fn challenge(app: Router, authorization: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let response = app
        .oneshot(builder.body(Body::from("{}")).expect("request"))
        .await
        .expect("response");
    let value = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("401 carries a challenge")
        .to_str()
        .expect("ASCII challenge")
        .to_owned();
    (response.status(), value)
}

#[tokio::test]
async fn every_401_names_the_metadata_document_when_configured() {
    let profile = BearerResponseProfile::detailed("test")
        .with_resource_metadata(METADATA_URL)
        .expect("valid URL");
    let (status, missing) = challenge(app(profile.clone()), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing,
        format!(r#"Bearer realm="test", resource_metadata="{METADATA_URL}""#)
    );

    let (_, bad_token) = challenge(app(profile), Some("Bearer nope")).await;
    assert_eq!(
        bad_token,
        format!(
            r#"Bearer realm="test", resource_metadata="{METADATA_URL}", error="invalid_token", error_description="The access token is invalid""#
        )
    );
}

#[tokio::test]
async fn the_compact_profile_carries_it_too() {
    let profile = BearerResponseProfile::compact("test")
        .with_resource_metadata(METADATA_URL)
        .expect("valid URL");
    let (_, value) = challenge(app(profile), None).await;
    assert_eq!(
        value,
        format!(r#"Bearer realm="test", resource_metadata="{METADATA_URL}", error="invalid_token""#)
    );
}

#[tokio::test]
async fn without_it_the_challenge_is_byte_identical_to_before() {
    let (_, missing) = challenge(app(BearerResponseProfile::detailed("test")), None).await;
    assert_eq!(missing, r#"Bearer realm="test""#);
    let (_, bad) = challenge(app(BearerResponseProfile::compact("test")), Some("Bearer x")).await;
    assert_eq!(bad, r#"Bearer realm="test", error="invalid_token""#);
}

#[test]
fn a_url_that_could_break_out_of_the_quoted_string_is_refused() {
    for hostile in [
        "https://h/\", error=\"insufficient_scope",
        "https://h/a\\b",
        "https://h/a\r\nSet-Cookie: x=1",
        "https://h/\u{e9}",
        "javascript:alert(1)",
        "/relative",
    ] {
        let result = BearerResponseProfile::detailed("test").with_resource_metadata(hostile);
        assert!(
            matches!(result, Err(BearerAuthError::InvalidResourceMetadata(_))),
            "{hostile:?} must be refused"
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --test oauth_challenge 2>&1 | tail`
Expected: compile error, `with_resource_metadata` not found.

- [ ] **Step 3: Implement**

In `auth.rs`:

```rust
pub enum BearerAuthError {
    /// Realm contains characters that cannot appear in HTTP header values.
    #[error("realm contains invalid characters: {0}")]
    InvalidRealm(&'static str),
    /// The resource-metadata URL is not an absolute http(s) URL, or contains
    /// characters that could break out of the quoted challenge parameter.
    #[error("resource_metadata URL is invalid: {0}")]
    InvalidResourceMetadata(&'static str),
}
```

Add `resource_metadata: Option<String>,` to `BearerResponseProfile` (set to `None` in
`try_detailed` and `try_compact`), then:

```rust
    /// Advertise an RFC 9728 protected-resource-metadata document in every 401
    /// challenge as `resource_metadata="<url>"`, so an OAuth client can discover the
    /// authorization server from the failure.
    ///
    /// # Errors
    /// Returns [`BearerAuthError::InvalidResourceMetadata`] unless `url` is an absolute
    /// `http(s)` URL of printable ASCII with no quote or backslash (the same header-safety
    /// rule the realm gets).
    pub fn with_resource_metadata(mut self, url: impl Into<String>) -> Result<Self, BearerAuthError> {
        let url = url.into();
        header_unsafe_reason(&url).map_or(Ok(()), |reason| {
            Err(BearerAuthError::InvalidResourceMetadata(reason))
        })?;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(BearerAuthError::InvalidResourceMetadata("not an absolute http(s) URL"));
        }
        self.resource_metadata = Some(url);
        Ok(self)
    }
```

Refactor `validate_realm` into a shared helper so both use one rule:

```rust
fn header_unsafe_reason(value: &str) -> Option<&'static str> {
    for byte in value.bytes() {
        if byte == b'"' { return Some("contains quotes"); }
        if byte == b'\\' { return Some("contains backslashes"); }
        if byte.is_ascii_control() { return Some("contains control characters"); }
        if !byte.is_ascii() { return Some("contains non-ASCII"); }
    }
    None
}

fn validate_realm(realm: String) -> Result<String, BearerAuthError> {
    match header_unsafe_reason(&realm) {
        Some(reason) => Err(BearerAuthError::InvalidRealm(reason)),
        None => Ok(realm),
    }
}
```

Challenge builders (replace the three `format!` sites in `unauthorized` / `invalid_token`):

```rust
/// `Bearer realm="R"` plus, when configured, `resource_metadata="U"`.
fn challenge_base(profile: &BearerResponseProfile) -> String {
    match &profile.resource_metadata {
        Some(url) => format!(r#"Bearer realm="{}", resource_metadata="{url}""#, profile.realm),
        None => format!(r#"Bearer realm="{}""#, profile.realm),
    }
}
```
`unauthorized` Detailed: `challenge_base(profile)`; `invalid_token` Detailed:
`format!(r#"{}, error="invalid_token", error_description="The access token is invalid""#, challenge_base(profile))`;
Compact: `format!(r#"{}, error="invalid_token""#, challenge_base(profile))`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --test oauth_challenge && cargo test --locked -p mecmcp-transport --test bearer_boundary --features test-util`
Expected: new tests pass; the existing `bearer_boundary` header assertions still pass (proving "unchanged when unset").

- [ ] **Step 5: Sabotage**

In `challenge_base`, ignore `resource_metadata` -> the first two tests fail. Delete the
`header_unsafe_reason` check in `with_resource_metadata` -> the hostile-URL test fails.

**Security review points:** header injection (quote, backslash, CR/LF, non-ASCII all
rejected; the value is validated at construction, so the hot path does no escaping and
cannot fail with `HeaderValue` conversion); no information is added to unauthenticated
responses beyond a URL the server serves publicly anyway.

- [ ] **Step 6: Verify block, then commit**

```bash
git add crates/mecmcp-transport
git commit -m "feat(transport): resource_metadata parameter on 401 challenges (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~210 lines (about 130 tests).

---

### Task 6: `oauth-resource` feature, scope map, resource config, CI

Satisfies requirement 5 (the mapping and its fail-closed rules) and the feature-flag part of 3.

**Files:**
- Modify: `crates/mecmcp-transport/Cargo.toml` (feature + `[[test]]` entries)
- Modify: `crates/mecmcp-transport/src/lib.rs` (gated module + exports)
- Create: `crates/mecmcp-transport/src/oauth_resource/mod.rs` (config only in this task)
- Create: `crates/mecmcp-transport/src/oauth_resource/scope_map.rs`
- Modify: `.github/workflows/ci.yml` (:59-66 step, :104-108 MSRV)

**Interfaces:**
- Consumes: `mecmcp_auth::{ScopeSet, ActorType}`, `mecmcp_oidc::{ResourceUri, is_scope_token}`.
- Produces (all behind `feature = "oauth-resource"`):
  - `OAuthScopeMap::from_json(&[u8]) -> Result<OAuthScopeMap, ScopeMapError>`
  - `OAuthScopeMap::load(&Path) -> Result<OAuthScopeMap, ScopeMapError>` (<= 64 KiB)
  - `OAuthScopeMap::map(&self, scopes: &[String], roles: &[String]) -> Option<MappedAuthority>`
  - `OAuthScopeMap::scopes_supported(&self) -> Vec<&str>`
  - `MappedAuthority { pub tools: ScopeSet, pub devices: ScopeSet, pub actor_type: ActorType }`
  - `ScopeMapError` (`thiserror`)
  - `OAuthResourceConfig::new(issuer: &str, resource: &str, scope_map: OAuthScopeMap) -> Result<Self, OAuthConfigError>` plus `with_audience(&str)`, `with_role_claim(&str)`, `with_require_at_jwt_typ(bool)`; accessors `issuer()`, `resource() -> &ResourceUri`, `audience() -> &str` (defaults to the resource string), `scope_map()`.

**Scope-map file format** (version-tagged JSON; the only supported spelling):

```json
{
  "version": 1,
  "actor_type": "agent",
  "scopes": {
    "junos:read":  { "tools": ["get_junos_config", "gather_device_facts"], "devices": ["srx-lab-1", "srx-lab-2"] },
    "junos:admin": { "tools": ["*"], "devices": ["*"] }
  },
  "roles": {
    "netops": { "tools": ["get_junos_config"], "devices": ["srx-lab-1"] }
  }
}
```

Rules: unknown fields rejected; `version` must be `1`; `tools` and `devices` both required in
every entry (`[]` = nothing); `["*"]` is the only wildcard spelling and is explicit; scope keys
must satisfy `is_scope_token`; role keys are 1-128 bytes without control characters; at least
one entry overall; at most 256 entries per table; per-entry validation is `ScopeSet::validate`.
Matching is exact and case-sensitive. A token's authority is the **union** over every
matching scope and role entry; if the union grants no tools the token maps to nothing (`None`).
`actor_type` defaults to `unknown` (honest: the server cannot know whether a human or an
agent holds the token).

- [ ] **Step 1: Write the failing tests**

`crates/mecmcp-transport/src/oauth_resource/scope_map.rs` tests module:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MAP: &str = r#"{
        "version": 1,
        "actor_type": "agent",
        "scopes": {
            "junos:read": {"tools": ["get_junos_config"], "devices": ["srx-1"]},
            "junos:ops":  {"tools": ["gather_device_facts"], "devices": ["srx-2"]},
            "junos:none": {"tools": [], "devices": []}
        },
        "roles": {"netops": {"tools": ["get_device_list"], "devices": ["srx-1"]}}
    }"#;

    fn map() -> OAuthScopeMap {
        OAuthScopeMap::from_json(MAP.as_bytes()).unwrap()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_mapped_scope_grants_exactly_what_the_file_says() {
        let authority = map().map(&strings(&["junos:read"]), &[]).unwrap();
        assert_eq!(authority.tools, ScopeSet::Allowlist(strings(&["get_junos_config"])));
        assert_eq!(authority.devices, ScopeSet::Allowlist(strings(&["srx-1"])));
        assert_eq!(authority.actor_type, mecmcp_auth::ActorType::Agent);
    }

    #[test]
    fn scopes_and_roles_union() {
        let authority = map()
            .map(&strings(&["junos:read", "junos:ops"]), &strings(&["netops"]))
            .unwrap();
        assert_eq!(
            authority.tools,
            ScopeSet::Allowlist(strings(&["get_junos_config", "gather_device_facts", "get_device_list"]))
        );
        assert_eq!(authority.devices, ScopeSet::Allowlist(strings(&["srx-1", "srx-2"])));
    }

    #[test]
    fn an_unmapped_scope_grants_nothing() {
        assert!(map().map(&strings(&["junos:admin"]), &[]).is_none());
        assert!(map().map(&strings(&["openid", "profile"]), &[]).is_none());
        assert!(map().map(&[], &[]).is_none());
    }

    #[test]
    fn matching_is_exact_and_case_sensitive() {
        for near_miss in ["JUNOS:READ", "junos:read ", "junos:rea", "junos:read2", "junos:*", "*"] {
            assert!(
                map().map(&strings(&[near_miss]), &[]).is_none(),
                "{near_miss:?} must not match"
            );
        }
    }

    #[test]
    fn an_entry_that_grants_no_tools_maps_to_nothing() {
        assert!(map().map(&strings(&["junos:none"]), &[]).is_none());
    }

    #[test]
    fn unknown_scopes_alongside_a_mapped_one_add_nothing() {
        let with_noise = map().map(&strings(&["openid", "junos:read", "evil"]), &[]).unwrap();
        let alone = map().map(&strings(&["junos:read"]), &[]).unwrap();
        assert_eq!(with_noise, alone);
    }

    #[test]
    fn an_explicit_wildcard_is_honoured_only_when_written() {
        let json = r#"{"version":1,"scopes":{"all":{"tools":["*"],"devices":["*"]}}}"#;
        let authority = OAuthScopeMap::from_json(json.as_bytes())
            .unwrap()
            .map(&strings(&["all"]), &[])
            .unwrap();
        assert_eq!(authority.tools, ScopeSet::Wildcard);
        assert_eq!(authority.devices, ScopeSet::Wildcard);
        assert_eq!(authority.actor_type, mecmcp_auth::ActorType::Unknown);
    }

    #[test]
    fn load_time_refusals() {
        let cases: &[(&str, &str)] = &[
            (r#"{"version":2,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#, "version"),
            (r#"{"version":1,"scopes":{"a":{"tools":["t"]}}}"#, "devices"),
            (r#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["d"],"extra":1}}}"#, "extra"),
            (r#"{"version":1,"extra":1,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#, "extra"),
            (r#"{"version":1,"scopes":{"two words":{"tools":["t"],"devices":["d"]}}}"#, "scope-token"),
            (r#"{"version":1,"scopes":{"":{"tools":["t"],"devices":["d"]}}}"#, "scope-token"),
            (r#"{"version":1,"scopes":{"a":{"tools":["t","t"],"devices":["d"]}}}"#, "duplicate"),
            (r#"{"version":1,"scopes":{"a":{"tools":["*","t"],"devices":["d"]}}}"#, "'*'"),
            (r#"{"version":1,"scopes":{},"roles":{}}"#, "grants nothing"),
            ("not json", "JSON"),
        ];
        for (json, needle) in cases {
            let error = OAuthScopeMap::from_json(json.as_bytes()).unwrap_err().to_string();
            assert!(error.contains(needle), "{json} -> {error}");
        }
    }

    #[test]
    fn scopes_supported_lists_scope_keys_sorted_and_not_roles() {
        assert_eq!(map().scopes_supported(), vec!["junos:none", "junos:ops", "junos:read"]);
    }

    #[test]
    fn load_refuses_an_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("map.json");
        std::fs::write(&path, vec![b' '; 70_000]).unwrap();
        assert!(OAuthScopeMap::load(&path).unwrap_err().to_string().contains("64 KiB"));
    }
}
```

`mod.rs` tests (config):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn map() -> OAuthScopeMap {
        OAuthScopeMap::from_json(
            br#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn audience_defaults_to_the_canonical_resource() {
        let config =
            OAuthResourceConfig::new("https://idp.example/realms/lab", "https://junos.example/mcp", map())
                .unwrap();
        assert_eq!(config.audience(), "https://junos.example/mcp");
        assert_eq!(config.clone().with_audience("junos-client").audience(), "junos-client");
    }

    #[test]
    fn an_insecure_or_hostile_issuer_is_refused() {
        for bad in ["http://idp.example", "idp.example", "https://idp.example/a b", "https://idp\n.example"] {
            assert!(
                OAuthResourceConfig::new(bad, "https://junos.example/mcp", map()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_bad_resource_is_refused() {
        assert!(OAuthResourceConfig::new("https://idp.example", "http://junos.example/mcp", map()).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource oauth_resource 2>&1 | tail`
Expected: "the package does not contain this feature: oauth-resource".

- [ ] **Step 3: Implement**

`Cargo.toml` (next to `verified-approver`):

```toml
# Gates OAuth 2.1 resource-server mode (mecmcp#498): RFC 9728 metadata, JWT access-token
# authentication as a second step after the static token store, and the claim -> scope map.
# Off by default for the same reason as `verified-approver`: it links `mecmcp-oidc` and its
# reqwest/rustls client into every server that does not need it. With the feature off the
# bearer middleware is unchanged.
oauth-resource = ["dep:mecmcp-oidc"]
```
and
```toml
# `oauth_resource.rs` drives signed-JWT requests through the real bearer boundary.
[[test]]
name = "oauth_resource"
required-features = ["oauth-resource", "test-util"]
```
(`oauth_challenge.rs` is ungated and needs no entry.)

`lib.rs`: after the `verified-approver` re-export:

```rust
#[cfg(feature = "oauth-resource")]
pub mod oauth_resource;
#[cfg(feature = "oauth-resource")]
pub use oauth_resource::{
    MappedAuthority, OAuthConfigError, OAuthResourceConfig, OAuthScopeMap, ScopeMapError,
};
```

`scope_map.rs`:

```rust
//! The server-side table turning verified OAuth claims into tool and device scopes.
//!
//! The table lives on the resource server (like `tokens.json`); a token cannot name its own
//! authority. Everything here fails closed: no default entry, no implicit wildcard,
//! no partial matching.

use mecmcp_auth::{ActorType, ScopeSet};
use mecmcp_oidc::is_scope_token;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 256;

/// Why a scope-map file was refused.
#[derive(Debug, thiserror::Error)]
pub enum ScopeMapError {
    /// Could not read the file.
    #[error("cannot read scope map: {0}")]
    Io(String),
    /// Larger than 64 KiB.
    #[error("scope map is larger than 64 KiB")]
    TooLarge,
    /// Not valid JSON of the expected shape (includes unknown and missing fields).
    #[error("scope map is not valid JSON of the expected shape: {0}")]
    Json(String),
    /// A structural rule was violated.
    #[error("scope map invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantSpec {
    tools: ScopeSet,
    devices: ScopeSet,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapFile {
    version: u32,
    #[serde(default)]
    actor_type: ActorType,
    #[serde(default)]
    scopes: BTreeMap<String, GrantSpec>,
    #[serde(default)]
    roles: BTreeMap<String, GrantSpec>,
}

/// What a verified token is allowed to do on this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedAuthority {
    /// Tools the caller may call.
    pub tools: ScopeSet,
    /// Devices the caller may address.
    pub devices: ScopeSet,
    /// Server-asserted actor type (from the file, not the token).
    pub actor_type: ActorType,
}

/// A validated scope map. See the module docs for the semantics.
#[derive(Debug, Clone)]
pub struct OAuthScopeMap {
    actor_type: ActorType,
    scopes: BTreeMap<String, GrantSpec>,
    roles: BTreeMap<String, GrantSpec>,
}

impl OAuthScopeMap {
    /// Parse and validate a scope-map document.
    ///
    /// # Errors
    /// Returns a [`ScopeMapError`] naming the first violated rule.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ScopeMapError> {
        let file: MapFile =
            serde_json::from_slice(bytes).map_err(|error| ScopeMapError::Json(error.to_string()))?;
        if file.version != 1 {
            return Err(ScopeMapError::Invalid(format!("unsupported version {}", file.version)));
        }
        if file.scopes.len() > MAX_ENTRIES || file.roles.len() > MAX_ENTRIES {
            return Err(ScopeMapError::Invalid(format!("more than {MAX_ENTRIES} entries in a table")));
        }
        if file.scopes.is_empty() && file.roles.is_empty() {
            return Err(ScopeMapError::Invalid(
                "the map grants nothing: define at least one scope or role".to_owned(),
            ));
        }
        for (name, spec) in &file.scopes {
            if !is_scope_token(name) {
                return Err(ScopeMapError::Invalid(format!("scope key {name:?} is not a valid scope-token")));
            }
            validate_spec(name, spec)?;
        }
        for (name, spec) in &file.roles {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err(ScopeMapError::Invalid(format!("role key {name:?} is out of range")));
            }
            validate_spec(name, spec)?;
        }
        Ok(Self { actor_type: file.actor_type, scopes: file.scopes, roles: file.roles })
    }

    /// Read and validate a scope-map file (at most 64 KiB).
    ///
    /// # Errors
    /// Returns a [`ScopeMapError`] if the file is unreadable, oversized, or invalid.
    pub fn load(path: &Path) -> Result<Self, ScopeMapError> {
        let metadata = std::fs::metadata(path).map_err(|error| ScopeMapError::Io(error.to_string()))?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(ScopeMapError::TooLarge);
        }
        let bytes = std::fs::read(path).map_err(|error| ScopeMapError::Io(error.to_string()))?;
        Self::from_json(&bytes)
    }

    /// The scope names this server understands, sorted, for `scopes_supported`.
    #[must_use]
    pub fn scopes_supported(&self) -> Vec<&str> {
        self.scopes.keys().map(String::as_str).collect()
    }

    /// The authority for a token carrying these scopes and roles, or `None` if it maps to
    /// nothing (no entry matched, or the union grants no tools).
    #[must_use]
    pub fn map(&self, scopes: &[String], roles: &[String]) -> Option<MappedAuthority> {
        let matched: Vec<&GrantSpec> = scopes
            .iter()
            .filter_map(|scope| self.scopes.get(scope))
            .chain(roles.iter().filter_map(|role| self.roles.get(role)))
            .collect();
        if matched.is_empty() {
            return None;
        }
        let mut tools = ScopeSet::Allowlist(Vec::new());
        let mut devices = ScopeSet::Allowlist(Vec::new());
        for spec in matched {
            tools = union(tools, &spec.tools);
            devices = union(devices, &spec.devices);
        }
        if tools.is_empty() || tools.validate("tools").is_err() || devices.validate("devices").is_err() {
            return None;
        }
        Some(MappedAuthority { tools, devices, actor_type: self.actor_type })
    }
}

fn validate_spec(name: &str, spec: &GrantSpec) -> Result<(), ScopeMapError> {
    spec.tools
        .validate("tools")
        .and_then(|()| spec.devices.validate("devices"))
        .map_err(|error| ScopeMapError::Invalid(format!("{name}: {error}")))
}

fn union(accumulated: ScopeSet, next: &ScopeSet) -> ScopeSet {
    match (accumulated, next) {
        (ScopeSet::Wildcard, _) | (_, ScopeSet::Wildcard) => ScopeSet::Wildcard,
        (ScopeSet::Allowlist(mut names), ScopeSet::Allowlist(more)) => {
            for name in more {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            ScopeSet::Allowlist(names)
        }
    }
}
```

(The union's size bound is enforced by `ScopeSet::validate`, which applies
`MAX_SCOPE_NAMES`.) `tempfile` is already a dev-dependency of the crate.

`mod.rs`:

```rust
//! OAuth 2.1 resource-server mode (mecmcp#498). See `docs/OAUTH.md`.

mod scope_map;

pub use scope_map::{MappedAuthority, OAuthScopeMap, ScopeMapError};

use mecmcp_oidc::{ResourceUri, ResourceUriError};

/// Why an [`OAuthResourceConfig`] was refused.
#[derive(Debug, thiserror::Error)]
pub enum OAuthConfigError {
    /// The issuer is not an `https` URL of printable ASCII.
    #[error("OAuth issuer must be an https URL of printable ASCII without spaces: {0:?}")]
    Issuer(String),
    /// The canonical resource URI is invalid.
    #[error(transparent)]
    Resource(#[from] ResourceUriError),
}

/// Static configuration of one server's OAuth resource-server mode.
#[derive(Debug, Clone)]
pub struct OAuthResourceConfig {
    issuer: String,
    resource: ResourceUri,
    audience: Option<String>,
    scope_map: OAuthScopeMap,
    role_claim: String,
    require_at_jwt_typ: bool,
}

impl OAuthResourceConfig {
    /// Validate and assemble a configuration. `issuer` is compared byte-for-byte with each
    /// token's `iss`, so it is *not* normalised: write it exactly as the IdP issues it.
    ///
    /// # Errors
    /// Returns [`OAuthConfigError`] for an unusable issuer or resource URI.
    pub fn new(issuer: &str, resource: &str, scope_map: OAuthScopeMap) -> Result<Self, OAuthConfigError> {
        let printable = issuer.bytes().all(|byte| byte.is_ascii_graphic());
        if !issuer.starts_with("https://") || !printable {
            return Err(OAuthConfigError::Issuer(issuer.to_owned()));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            resource: ResourceUri::parse(resource)?,
            audience: None,
            scope_map,
            role_claim: "roles".to_owned(),
            require_at_jwt_typ: false,
        })
    }

    /// Override the expected `aud` (for IdPs that can only emit a client id). Must be
    /// unique per server, or tokens are not bound to one server.
    #[must_use]
    pub fn with_audience(mut self, audience: &str) -> Self {
        self.audience = Some(audience.to_owned());
        self
    }

    /// The token claim carrying role/group names (default `roles`).
    #[must_use]
    pub fn with_role_claim(mut self, claim: &str) -> Self {
        self.role_claim = claim.to_owned();
        self
    }

    /// Require the RFC 9068 `typ: at+jwt` header.
    #[must_use]
    pub fn with_require_at_jwt_typ(mut self, required: bool) -> Self {
        self.require_at_jwt_typ = required;
        self
    }

    /// The issuer, exactly as configured.
    #[must_use]
    pub fn issuer(&self) -> &str { &self.issuer }
    /// The canonical resource URI.
    #[must_use]
    pub fn resource(&self) -> &ResourceUri { &self.resource }
    /// The audience tokens must carry: the override, else the canonical resource string.
    #[must_use]
    pub fn audience(&self) -> &str { self.audience.as_deref().unwrap_or_else(|| self.resource.as_str()) }
    /// The claim -> scope table.
    #[must_use]
    pub fn scope_map(&self) -> &OAuthScopeMap { &self.scope_map }
}
```

CI (`ci.yml`): change the isolated step to
`cargo test --locked -p mecmcp-transport --features test-util,verified-approver,oauth-resource`,
rename it "Run verified-approver and oauth-resource tests" and extend its comment: "oauth-resource
links the same `mecmcp-oidc` HTTP stack as `verified-approver`, so it is kept out of the
workspace `--all-features` test run for the same `otel` CryptoProvider reason." In the MSRV job
add after "Check workspace at MSRV":

```yaml
      - name: Check oauth-resource at MSRV
        # The feature is off in the workspace check above, so its code never compiles there.
        run: cargo check -p mecmcp-transport --all-targets --features oauth-resource,test-util
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource oauth_resource`
Expected: 13 passed. Then `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` (the `[[test]] oauth_resource` target does not exist yet; Cargo errors on a `[[test]]` with a missing file, so **create an empty-but-valid `tests/oauth_resource.rs` containing only `//! OAuth resource-server integration tests (filled in by later tasks).` in this task**).

- [ ] **Step 5: Sabotage**

Make `map()` return `Some` for an empty `matched` -> `an_unmapped_scope_grants_nothing` fails.
Make `union` return the left side on `(Wildcard, _)` only -> `scopes_and_roles_union`/wildcard
test fails. Replace `deny_unknown_fields` on `GrantSpec` -> `load_time_refusals` ("extra") fails.
Delete the `tools.is_empty()` guard -> `an_entry_that_grants_no_tools_maps_to_nothing` fails.

**Security review points:** scope injection (the map is looked up by whole-string equality;
spaces cannot reach it because Task 1 already dropped non-scope-tokens, and keys with spaces
are refused at load); privilege widening by a typo (every field explicit, unknown fields
rejected, no defaults for `tools`/`devices`); operator wildcard is written, never inferred;
file read bounded (64 KiB) so a hostile path cannot exhaust memory; `scopes_supported` lists
scope names only, never device or tool names (the metadata document is public).

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates/mecmcp-transport .github/workflows/ci.yml
git commit -m "feat(transport): oauth-resource feature, scope map and resource config (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~420 lines (about 170 tests). If review pressure demands it, split the CI
and `OAuthResourceConfig` into a following commit; the scope map is self-contained.

---

### Task 7: RFC 9728 protected-resource metadata router

Satisfies requirement 1.

**Files:**
- Create: `crates/mecmcp-transport/src/oauth_resource/metadata.rs`
- Modify: `crates/mecmcp-transport/src/oauth_resource/mod.rs` (`mod metadata; pub use metadata::metadata_router;`)

**Interfaces:**
- Consumes: `OAuthResourceConfig` (Task 6), `ResourceUri::metadata_path` / `ROOT_METADATA_PATH` (Task 2).
- Produces:
  - `pub fn metadata_document(config: &OAuthResourceConfig) -> serde_json::Value`
  - `pub fn metadata_router(config: &OAuthResourceConfig) -> axum::Router` serving `GET` on `config.resource().metadata_path()` and on `ROOT_METADATA_PATH` (once if they coincide), `Cache-Control: public, max-age=300`, no authentication.

Document: `{"resource": <canonical>, "authorization_servers": [<issuer>], "bearer_methods_supported": ["header"]}` plus `"scopes_supported"` only when the map defines scope keys. Nothing else: no tool, device, client or token information.

- [ ] **Step 1: Write the failing tests**

In `metadata.rs`:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::oauth_resource::OAuthScopeMap;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt as _;

    fn config(resource: &str) -> OAuthResourceConfig {
        let map = OAuthScopeMap::from_json(
            br#"{"version":1,"scopes":{"junos:read":{"tools":["get_junos_config"],"devices":["srx-secret-name"]}}}"#,
        )
        .unwrap();
        OAuthResourceConfig::new("https://idp.example/realms/lab", resource, map).unwrap()
    }

    async fn get(router: axum::Router, method: &str, path: &str) -> (StatusCode, String, Option<String>) {
        let response = router
            .oneshot(Request::builder().method(method).uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap(), cache)
    }

    #[tokio::test]
    async fn serves_the_rfc_9728_document_at_the_path_inserted_and_root_urls() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        for path in [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ] {
            let (status, body, cache) = get(router.clone(), "GET", path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(cache.as_deref(), Some("public, max-age=300"));
            let document: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                document,
                serde_json::json!({
                    "resource": "https://junos.example/mcp",
                    "authorization_servers": ["https://idp.example/realms/lab"],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["junos:read"],
                })
            );
        }
    }

    #[tokio::test]
    async fn a_resource_without_a_path_registers_the_root_route_once() {
        // axum panics on a duplicate route; this test is the guard.
        let router = metadata_router(&config("https://junos.example/"));
        let (status, _, _) = get(router, "GET", "/.well-known/oauth-protected-resource").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_document_discloses_no_tool_or_device_names() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        let (_, body, _) = get(router, "GET", "/.well-known/oauth-protected-resource").await;
        assert!(!body.contains("srx-secret-name"), "{body}");
        assert!(!body.contains("get_junos_config"), "{body}");
    }

    #[tokio::test]
    async fn only_get_is_allowed_and_other_paths_are_not_served() {
        let router = metadata_router(&config("https://junos.example/mcp"));
        let (status, _, _) = get(router.clone(), "POST", "/.well-known/oauth-protected-resource").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        let (status, _, _) = get(router, "GET", "/.well-known/oauth-protected-resource/other").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn scopes_supported_is_omitted_when_the_map_has_only_roles() {
        let map = OAuthScopeMap::from_json(
            br#"{"version":1,"roles":{"netops":{"tools":["t"],"devices":["d"]}}}"#,
        )
        .unwrap();
        let config = OAuthResourceConfig::new("https://idp.example", "https://junos.example/mcp", map).unwrap();
        assert!(metadata_document(&config).get("scopes_supported").is_none());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource metadata 2>&1 | tail`
Expected: compile error (`metadata_router` undefined).

- [ ] **Step 3: Implement**

```rust
//! RFC 9728 OAuth 2.0 Protected Resource Metadata.

use super::OAuthResourceConfig;
use axum::{Json, Router, http::header, routing::get};
use mecmcp_oidc::ROOT_METADATA_PATH;
use serde_json::{Value, json};
use std::sync::Arc;

/// The metadata document for `config`: resource, authorization server, bearer method, and
/// the scope names the map defines. Nothing that identifies a tool, device, or client.
#[must_use]
pub fn metadata_document(config: &OAuthResourceConfig) -> Value {
    let mut document = json!({
        "resource": config.resource().as_str(),
        "authorization_servers": [config.issuer()],
        "bearer_methods_supported": ["header"],
    });
    let supported = config.scope_map().scopes_supported();
    if !supported.is_empty() {
        document["scopes_supported"] = json!(supported);
    }
    document
}

/// A router serving the document, unauthenticated, at the RFC 9728 path-inserted URL for
/// the resource and at the root well-known URL. Merge it **outside** the bearer boundary.
#[must_use]
pub fn metadata_router(config: &OAuthResourceConfig) -> Router {
    let document = Arc::new(metadata_document(config));
    let handler = move || {
        let document = Arc::clone(&document);
        async move {
            (
                [(header::CACHE_CONTROL, "public, max-age=300")],
                Json((*document).clone()),
            )
        }
    };
    let specific = config.resource().metadata_path();
    let router = Router::new().route(&specific, get(handler.clone()));
    if specific == ROOT_METADATA_PATH {
        return router;
    }
    router.route(ROOT_METADATA_PATH, get(handler))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource metadata`
Expected: 5 passed.

- [ ] **Step 5: Sabotage**

Delete the `if specific == ROOT_METADATA_PATH` early return -> `a_resource_without_a_path...`
panics. Add `"tools": ...` to the document -> the disclosure test fails. Drop the root route
-> the first test fails on the second path.

**Security review points:** unauthenticated by design (RFC 9728), so the document is
constrained by test to public facts; `GET` only; the route paths come from `ResourceUri`,
which has already refused route metacharacters (Task 2); Host/Origin validation and the IP
rate limit still wrap it because it is merged before those layers (Task 9).

- [ ] **Step 6: Verify block, then commit**

```bash
git add crates/mecmcp-transport
git commit -m "feat(transport): RFC 9728 protected-resource metadata router (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~190 lines (about 110 tests).

---

### Task 8: `OAuthResource::authenticate` (verification, audience binding, claim mapping)

Satisfies requirements 4, 5 and 8 at the library level (the HTTP level is Task 9).

**Files:**
- Modify: `crates/mecmcp-transport/src/oauth_resource/mod.rs` (add `OAuthResource`, `OAuthRejection`, config accessors)
- Modify: `crates/mecmcp-transport/src/lib.rs` (export `OAuthResource`, `OAuthRejection`)
- Modify: `crates/mecmcp-transport/tests/oauth_resource.rs` (created empty in Task 6; fixtures + tests here)

**Interfaces:**
- Consumes: `OAuthResourceConfig`, `OAuthScopeMap::map`, `metadata_router` (Tasks 6-7); `mecmcp_oidc::{TokenVerifier, OidcConfig, TokenProfile, KeySource, VerificationFailure}`; `CallerCtx::oauth` (Task 3).
- Produces:
  - `OAuthResource::<G>::new(config: OAuthResourceConfig, source: Arc<dyn KeySource>) -> Self`
  - `OAuthResource::config(&self) -> &OAuthResourceConfig`
  - `OAuthResource::metadata_router(&self) -> axum::Router`
  - `async OAuthResource::authenticate(&self, token: &str) -> Result<CallerCtx<G>, OAuthRejection>`
  - `OAuthResourceConfig::role_claim(&self) -> &str`, `require_at_jwt_typ(&self) -> bool`
  - `#[non_exhaustive] enum OAuthRejection { Invalid(&'static str), Unmapped(OAuthIdentity), Unavailable(&'static str) }`
    where the `&'static str` is a stable reason code (`VerificationFailure::reason_code()` or one of `invalid_subject`, `keys_unavailable`, and in Task 10 `timeout`, `busy`).

Subject rule (`valid_subject`): 1-128 bytes, no whitespace, no control characters. It becomes
the rate-limit key and the changeset identity, so it is validated here rather than trusted.

- [ ] **Step 1: Write the failing tests**

`crates/mecmcp-transport/tests/oauth_resource.rs` (replace the placeholder; fixtures are the
`approver_assertion.rs` ones, trimmed to what is used):

```rust
//! Signed-JWT integration tests for OAuth resource-server mode (mecmcp#498).
//!
//! Ephemeral RSA keys, in-memory `KeySource`; no socket to an IdP is ever opened.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_auth::{ActorType, Grant, GrantError, ScopeSet};
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource};
use mecmcp_transport::{OAuthRejection, OAuthResource, OAuthResourceConfig, OAuthScopeMap};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const ISSUER: &str = "https://idp.lab.example/realms/lab";
const JUNOS: &str = "https://junos.lab.example/mcp";
const PANOS: &str = "https://panos.lab.example/mcp";
const KID: &str = "oauth-test-key";

const SCOPE_MAP: &str = r#"{
    "version": 1,
    "actor_type": "agent",
    "scopes": {
        "junos:read": {"tools": ["get_junos_config"], "devices": ["srx-1"]},
        "panos:read": {"tools": ["get_panos_config"], "devices": ["fw-1"]}
    },
    "roles": {"netops": {"tools": ["get_device_list"], "devices": ["srx-1"]}}
}"#;

#[derive(Debug, Clone)]
struct TestGrant;
impl Grant for TestGrant {
    type Action = ();
    fn allows_action(&self, _action: ()) -> bool { true }
    fn allows_subject(&self, _subject: &str) -> bool { true }
    fn validate(&self) -> Result<(), GrantError> { Ok(()) }
}

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestKey {
    let key_pair = KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation");
    let pkcs8_der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = key_pair.as_der().expect("PKCS8");
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.as_ref().to_vec()));
    let encoding_key = EncodingKey::from_rsa_pem(pem_text.as_bytes()).expect("PEM");
    let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256).expect("JWK");
    jwk.common.key_id = Some(kid.to_owned());
    TestKey { encoding_key, jwk }
}

fn sign(key: &TestKey, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("sign")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs(),
    )
    .expect("fits")
}

/// A well-formed RFC 9068 access token for `audience` carrying `scope`.
fn claims(audience: Value, scope: &str) -> Value {
    json!({
        "iss": ISSUER, "sub": "alice", "aud": audience,
        "exp": now() + 3600, "iat": now() - 10, "jti": "jti-1",
        "client_id": "odysseus", "scope": scope,
    })
}

/// Serves the key set from memory and counts JWKS fetches.
struct FixtureSource {
    jwks: JwkSet,
    fetches: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl KeySource for FixtureSource {
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        Ok(DiscoveryDocument {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/jwks"),
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            code_challenge_methods_supported: Vec::new(),
            id_token_signing_alg_values_supported: Vec::new(),
        })
    }
    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(self.jwks.clone())
    }
}

fn resource_for(resource: &str, key: &TestKey) -> (OAuthResource<TestGrant>, Arc<AtomicUsize>) {
    let fetches = Arc::new(AtomicUsize::new(0));
    let source = FixtureSource { jwks: JwkSet { keys: vec![key.jwk.clone()] }, fetches: Arc::clone(&fetches) };
    let config = OAuthResourceConfig::new(
        ISSUER,
        resource,
        OAuthScopeMap::from_json(SCOPE_MAP.as_bytes()).expect("map"),
    )
    .expect("config");
    (OAuthResource::new(config, Arc::new(source)), fetches)
}

#[tokio::test]
async fn a_mapped_token_becomes_the_caller_the_map_describes() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "openid junos:read"));

    let caller = junos.authenticate(&token).await.expect("authenticates");

    assert_eq!(caller.token_name, "oauth:alice");
    assert_eq!(caller.tools, ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]));
    assert_eq!(caller.devices, ScopeSet::Allowlist(vec!["srx-1".to_owned()]));
    assert_eq!(caller.actor_type, ActorType::Agent);
    assert!(caller.grant.is_none());
    let identity = caller.oauth.expect("OAuth identity recorded");
    assert_eq!(identity.issuer, ISSUER);
    assert_eq!(identity.subject, "alice");
    assert_eq!(identity.client_id.as_deref(), Some("odysseus"));
}

/// Requirement 4: a token minted for junos is refused by a panos-configured verifier.
/// The control assertion (junos accepts it) is what keeps this from passing vacuously.
#[tokio::test]
async fn a_junos_audience_token_is_refused_by_a_panos_resource() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let (panos, _) = resource_for(PANOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "junos:read panos:read"));

    assert!(junos.authenticate(&token).await.is_ok(), "control: the intended server accepts it");
    assert_eq!(
        panos.authenticate(&token).await.unwrap_err(),
        OAuthRejection::Invalid("wrong_audience"),
        "the same token, scopes included, must not work on another server"
    );
}

#[tokio::test]
async fn audience_must_equal_the_resource_not_resemble_it() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    for near_miss in [
        "https://panos.lab.example/mcp/extra",
        "https://panos.lab.example/mc",
        "https://panos.lab.example/mcp/",
        "xhttps://panos.lab.example/mcp",
        "https://panos.lab.example/mcp ",
        "https://PANOS.lab.example/mcp",
        "https://panos.lab.example",
        "panos.lab.example/mcp",
    ] {
        let token = sign(&key, &claims(json!(near_miss), "panos:read"));
        assert_eq!(
            panos.authenticate(&token).await.unwrap_err(),
            OAuthRejection::Invalid("wrong_audience"),
            "aud {near_miss:?}"
        );
    }
    let token = sign(&key, &claims(json!([JUNOS, "account"]), "panos:read"));
    assert_eq!(
        panos.authenticate(&token).await.unwrap_err(),
        OAuthRejection::Invalid("wrong_audience"),
        "an audience list that does not contain this server"
    );
}

/// Pinned behaviour, not an endorsement: a token whose `aud` lists this server among others
/// was issued for this server too. See docs/OAUTH.md ("Multi-audience tokens").
#[tokio::test]
async fn an_audience_list_containing_this_resource_is_accepted() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let token = sign(&key, &claims(json!(["account", PANOS]), "panos:read"));
    assert!(panos.authenticate(&token).await.is_ok());
}

#[tokio::test]
async fn an_unmapped_or_absent_scope_is_a_verified_token_that_grants_nothing() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    for scope in ["junos:admin", "openid profile", ""] {
        let token = sign(&key, &claims(json!(JUNOS), scope));
        match junos.authenticate(&token).await.unwrap_err() {
            OAuthRejection::Unmapped(identity) => assert_eq!(identity.subject, "alice"),
            other => panic!("scope {scope:?}: expected Unmapped, got {other:?}"),
        }
    }
    let mut no_scope_claim = claims(json!(JUNOS), "");
    no_scope_claim.as_object_mut().expect("object").remove("scope");
    let token = sign(&key, &no_scope_claim);
    assert!(matches!(junos.authenticate(&token).await.unwrap_err(), OAuthRejection::Unmapped(_)));
}

#[tokio::test]
async fn smuggled_scopes_do_not_escalate() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);

    // Tab / newline are not delimiters (RFC 6749 uses SP only): one invalid token, dropped.
    for injected in ["junos:read\tpanos:read", "junos:read\npanos:read", "junos:read,panos:read"] {
        let token = sign(&key, &claims(json!(JUNOS), injected));
        assert!(
            matches!(junos.authenticate(&token).await.unwrap_err(), OAuthRejection::Unmapped(_)),
            "{injected:?}"
        );
    }

    // A space *inside* an `scp` array element is not split into two scopes.
    let mut array_claims = claims(json!(JUNOS), "");
    let object = array_claims.as_object_mut().expect("object");
    object.remove("scope");
    object.insert("scp".to_owned(), json!(["junos:read panos:read"]));
    let token = sign(&key, &array_claims);
    assert!(matches!(junos.authenticate(&token).await.unwrap_err(), OAuthRejection::Unmapped(_)));

    // The legitimate scope still works beside a hostile one, and gains nothing from it.
    let token = sign(&key, &claims(json!(JUNOS), "junos:read panos:read"));
    let caller = junos.authenticate(&token).await.expect("junos:read maps");
    assert_eq!(caller.tools, ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]));
}

#[tokio::test]
async fn a_configured_role_claim_maps_too() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let mut with_role = claims(json!(JUNOS), "junos:read");
    with_role["roles"] = json!(["netops"]);
    let caller = junos.authenticate(&sign(&key, &with_role)).await.expect("maps");
    assert_eq!(
        caller.tools,
        ScopeSet::Allowlist(vec!["get_junos_config".to_owned(), "get_device_list".to_owned()])
    );
}

#[tokio::test]
async fn a_symmetric_algorithm_confusion_attempt_is_refused() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(KID.to_owned());
    let forged = jsonwebtoken::encode(
        &header,
        &claims(json!(JUNOS), "junos:read"),
        &EncodingKey::from_secret(b"anything-an-attacker-can-compute"),
    )
    .expect("sign");
    assert_eq!(
        junos.authenticate(&forged).await.unwrap_err(),
        OAuthRejection::Invalid("unsupported_algorithm")
    );
}

#[tokio::test]
async fn other_verification_failures_keep_distinct_reason_codes() {
    let key = generate_test_key(KID);
    let other_key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);

    let mut expired = claims(json!(JUNOS), "junos:read");
    expired["exp"] = json!(now() - 3600);
    let mut wrong_issuer = claims(json!(JUNOS), "junos:read");
    wrong_issuer["iss"] = json!("https://evil.example");
    let mut no_client = claims(json!(JUNOS), "junos:read");
    no_client.as_object_mut().expect("object").remove("client_id");

    let cases = [
        (sign(&key, &expired), "expired"),
        (sign(&key, &wrong_issuer), "wrong_issuer"),
        (sign(&other_key, &claims(json!(JUNOS), "junos:read")), "invalid_signature"),
        (sign(&key, &no_client), "missing_claim"),
    ];
    for (token, reason) in cases {
        assert_eq!(junos.authenticate(&token).await.unwrap_err(), OAuthRejection::Invalid(reason));
    }
}

#[tokio::test]
async fn a_subject_that_could_forge_an_identity_key_is_refused() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    for subject in ["", "alice bob", "alice\nbob", &"a".repeat(129)] {
        let mut hostile = claims(json!(JUNOS), "junos:read");
        hostile["sub"] = json!(subject);
        assert_eq!(
            junos.authenticate(&sign(&key, &hostile)).await.unwrap_err(),
            OAuthRejection::Invalid("invalid_subject"),
            "{subject:?}"
        );
    }
}

#[tokio::test]
async fn the_caller_context_does_not_contain_the_token() {
    let key = generate_test_key(KID);
    let (junos, _) = resource_for(JUNOS, &key);
    let token = sign(&key, &claims(json!(JUNOS), "junos:read"));
    let caller = junos.authenticate(&token).await.expect("authenticates");
    let rendered = format!("{caller:?}");
    for segment in token.split('.') {
        assert!(!rendered.contains(segment), "a token segment leaked into CallerCtx: {segment}");
    }
}
```

The test file needs `async-trait` (already a dev-dependency), `pem`, `aws-lc-rs`, `jsonwebtoken`
(all already dev-dependencies).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource --test oauth_resource 2>&1 | tail`
Expected: compile error, `OAuthResource` / `OAuthRejection` not found.

- [ ] **Step 3: Implement**

Add to `oauth_resource/mod.rs` (`mod metadata;` and the `metadata_router` re-export already exist from Task 7):

```rust
use mecmcp_auth::{CallerCtx, Grant, OAuthIdentity};
use mecmcp_oidc::{KeySource, OidcConfig, TokenProfile, TokenVerifier, VerificationFailure};
use std::marker::PhantomData;
use std::sync::Arc;

/// Why OAuth authentication did not produce a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OAuthRejection {
    /// The token failed verification. The code is stable and safe to log
    /// (`VerificationFailure::reason_code`, or `invalid_subject`).
    Invalid(&'static str),
    /// The token verified but its scopes and roles map to nothing on this server.
    Unmapped(OAuthIdentity),
    /// Verification could not be completed (IdP keys unavailable, timed out, or the
    /// verifier is saturated). The token is not judged invalid.
    Unavailable(&'static str),
}

/// OAuth 2.1 resource-server authentication for one server.
pub struct OAuthResource<G: Grant> {
    config: OAuthResourceConfig,
    verifier: TokenVerifier,
    _grant: PhantomData<fn() -> G>,
}

impl<G: Grant> OAuthResource<G> {
    /// Build the verifier from `config`; JWKS and discovery are fetched through `source`
    /// (pass `Arc::new(HttpKeySource::new(client))` in production, a fixture in tests).
    #[must_use]
    pub fn new(config: OAuthResourceConfig, source: Arc<dyn KeySource>) -> Self {
        let mut oidc = OidcConfig::new(config.issuer(), config.audience(), config.role_claim());
        oidc.token_profile = TokenProfile::AccessToken {
            require_at_jwt_typ: config.require_at_jwt_typ(),
        };
        Self { verifier: TokenVerifier::new(oidc, source), config, _grant: PhantomData }
    }

    /// The configuration this resource was built from.
    #[must_use]
    pub fn config(&self) -> &OAuthResourceConfig { &self.config }

    /// The RFC 9728 router for this resource (merge outside the bearer boundary).
    #[must_use]
    pub fn metadata_router(&self) -> axum::Router { metadata_router(&self.config) }

    /// Verify `token` and map it to a caller.
    ///
    /// The token is read, never stored: the returned context carries only the verified
    /// issuer, subject and client id.
    ///
    /// # Errors
    /// See [`OAuthRejection`].
    pub async fn authenticate(&self, token: &str) -> Result<CallerCtx<G>, OAuthRejection> {
        let claims = match self.verifier.verify(token).await {
            Ok(claims) => claims,
            Err(VerificationFailure::KeysUnavailable { .. }) => {
                return Err(OAuthRejection::Unavailable("keys_unavailable"));
            }
            Err(failure) => return Err(OAuthRejection::Invalid(failure.reason_code())),
        };
        if !valid_subject(&claims.subject) {
            return Err(OAuthRejection::Invalid("invalid_subject"));
        }
        let identity = OAuthIdentity {
            issuer: self.config.issuer().to_owned(),
            subject: claims.subject,
            client_id: claims.client_id,
        };
        let Some(authority) = self.config.scope_map().map(&claims.scopes, &claims.roles) else {
            return Err(OAuthRejection::Unmapped(identity));
        };
        Ok(CallerCtx::oauth(identity, authority.devices, authority.tools, authority.actor_type))
    }
}

/// 1-128 bytes, no whitespace, no control characters.
fn valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 128
        && !subject.chars().any(|character| character.is_control() || character.is_whitespace())
}
```

Config accessors: `pub fn role_claim(&self) -> &str { &self.role_claim }`,
`pub fn require_at_jwt_typ(&self) -> bool { self.require_at_jwt_typ }`.
Export `OAuthRejection, OAuthResource` from `lib.rs` next to the Task 6 exports.
Per `reason_code()` of `Malformed`/`UnknownKeyId` etc. the codes are the existing ones.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource --test oauth_resource`
Expected: 10 passed.

- [ ] **Step 5: Sabotage (each independently, restore after)**

1. In `OAuthResource::new`, build the `OidcConfig` with the literal audience `"x"` instead of
   `config.audience()` -> every test that expects success fails (the fixture is bound to the config).
2. Build the panos resource in `a_junos_audience_token_is_refused_by_a_panos_resource` with
   `JUNOS` as its resource string -> the final assertion must fail (the test is not vacuous).
3. Make `OAuthScopeMap::map` return a default authority when nothing matched ->
   `an_unmapped_or_absent_scope...` and `smuggled_scopes...` fail.
4. Make `valid_subject` always `true` -> `a_subject_that_could_forge_an_identity_key_is_refused` fails.
5. In Task 1's `extract_scopes`, split `scp` array elements on spaces ->
   `smuggled_scopes_do_not_escalate` fails.

**Security review points:** audience binding (exact; every near-miss tested); algorithm
confusion (HS256 with a guessable secret and the real `kid` is refused by the existing
allow-list, now pinned at this layer); scope smuggling; subject-as-identity-key forgery;
the context carries no credential (Debug rendering checked). `Unavailable` never reveals
token validity.

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates/mecmcp-transport
git commit -m "feat(transport): OAuthResource verifies access tokens and maps claims to a caller (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~400 lines (about 280 tests). If it overruns, move
`smuggled_scopes`, `a_symmetric_algorithm...` and `other_verification_failures...` to a
follow-up commit "test: adversarial token cases".

---

### Task 9: Middleware wiring (static first, then JWT) and router assembly

Satisfies requirements 2, 3 and the static-keeps-working requirement; this is where the
feature becomes observable over HTTP.

**Files:**
- Modify: `crates/mecmcp-transport/src/auth.rs` (`BearerBoundary` :~116-190, `apply_bearer_boundary` AuthState construction :513, `AuthState` :~540, `bearer_auth_middleware` :~566-600; new helpers beside `audit_approver_assertion_rejection`)
- Modify: `crates/mecmcp-transport/src/server.rs` (router assembly :~484-525)
- Modify: `crates/mecmcp-transport/tests/oauth_resource.rs` (append)

**Interfaces:**
- Consumes: `OAuthResource`, `OAuthRejection` (Task 8); `BearerResponseProfile::with_resource_metadata` (Task 5).
- Produces:
  - `BearerBoundary::with_oauth_resource(self, resource: Arc<OAuthResource<G>>) -> Self` (feature `oauth-resource`); also sets the profile's `resource_metadata` to `resource.config().resource().metadata_url()`
  - Behaviour: static `authenticate` first; on a miss, if an OAuth resource is installed, `authenticate(candidate).await`:
    - `Ok(caller)` -> proceeds exactly as a static caller does
    - `Invalid(reason)` -> 401 `invalid_token` (challenge carries `resource_metadata`), `tracing::warn!(reason, "oauth_rejected")`
    - `Unmapped(identity)` -> 403 `insufficient_scope` + a denied audit event for `Principal::OAuth` with reason `unmapped_scope`
    - `Unavailable(reason)` -> 503 `{"error":"temporarily_unavailable"}` with `Retry-After: 5`
  - `build_streamable_http_router` merges `resource.metadata_router()` next to the health router (outside the bearer boundary, inside Host/Origin validation and the IP rate limit).

Why 403 for an unmapped but valid token and not 401 (decision 5): the credential is good;
what is missing is authority, which is what RFC 6750 s3.1 `insufficient_scope` means, and a
client that sees 401 would discard and re-run the whole authorization flow for the same
empty result.

- [ ] **Step 1: Write the failing tests**

Append to `tests/oauth_resource.rs`:

```rust
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{BearerSyntax, CallerCtx};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting, LimitsConfig,
    apply_bearer_boundary,
};
use tower::ServiceExt as _;

const STATIC_TOKEN: &str = "static-secret";

fn static_caller() -> CallerCtx<TestGrant> {
    let mut caller = CallerCtx::oauth(
        mecmcp_auth::OAuthIdentity { issuer: "static".into(), subject: "ci".into(), client_id: None },
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        ActorType::Human,
    );
    // A static-token caller as the token store would build it: its own name, no OAuth identity.
    caller.token_name = "ci-static".to_owned();
    caller.oauth = None;
    caller
}

/// `/` behind the real bearer boundary: one static token, optionally the OAuth resource.
fn app(resource: Option<Arc<OAuthResource<TestGrant>>>) -> Router {
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == STATIC_TOKEN).then(static_caller)
    });
    let mut boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
    if let Some(resource) = resource {
        boundary = boundary.with_oauth_resource(resource);
    }
    let router = Router::new().route(
        "/",
        post(|Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
            json!({
                "token_name": caller.token_name,
                "tools": caller.tools.summary(),
                "client_id": caller.oauth.as_ref().and_then(|identity| identity.client_id.clone()),
            })
            .to_string()
        }),
    );
    apply_bearer_boundary(
        router,
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    )
}

async fn call(app: &Router, bearer: Option<&str>) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from("{}")).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().expect("ASCII").to_owned());
    let bytes = to_bytes(response.into_body(), 16 * 1024).await.expect("body");
    (status, challenge, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

const METADATA_PARAM: &str =
    r#"resource_metadata="https://panos.lab.example/.well-known/oauth-protected-resource/mcp""#;

#[tokio::test]
async fn static_tokens_keep_working_with_oauth_enabled() {
    let key = generate_test_key(KID);
    let (panos, fetches) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let (status, _, body) = call(&app, Some(STATIC_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_name"], "ci-static");
    assert_eq!(fetches.load(Ordering::SeqCst), 0, "a static hit must not touch the IdP");
}

#[tokio::test]
async fn a_valid_access_token_authenticates_over_http() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, _, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["token_name"], "oauth:alice");
    assert_eq!(body["tools"], "get_panos_config");
    assert_eq!(body["client_id"], "odysseus");
}

#[tokio::test]
async fn a_junos_token_presented_to_the_panos_server_gets_401_with_discovery() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let token = sign(&key, &claims(json!(JUNOS), "junos:read panos:read"));
    let (status, challenge, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_token");
    let challenge = challenge.expect("challenge");
    assert!(challenge.contains(METADATA_PARAM), "{challenge}");
    assert!(challenge.contains(r#"error="invalid_token""#), "{challenge}");
}

#[tokio::test]
async fn a_valid_token_with_no_mapped_authority_is_403_not_401() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let token = sign(&key, &claims(json!(PANOS), "openid"));
    let (status, challenge, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "insufficient_scope");
    assert_eq!(challenge.as_deref(), Some(r#"Bearer realm="test", error="insufficient_scope""#));
}

#[tokio::test]
async fn unauthenticated_requests_are_pointed_at_the_metadata_document() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    for bearer in [None, Some("not-a-jwt")] {
        let (status, challenge, _) = call(&app, bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(challenge.expect("challenge").contains(METADATA_PARAM));
    }
}

#[tokio::test]
async fn without_the_resource_installed_a_jwt_is_just_an_unknown_token() {
    let key = generate_test_key(KID);
    let app = app(None);
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, challenge, _) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!challenge.expect("challenge").contains("resource_metadata"));
}
```

Plus the assembly test (metadata is outside the bearer boundary; `/mcp` is not):

```rust
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, TransportIdentity, build_streamable_http_router,
    test_harness::serve_on_loopback,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct StubServer;
impl ServerHandler for StubServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("stub", "0.1"))
    }
}

#[tokio::test]
async fn the_assembled_router_serves_metadata_unauthenticated_and_guards_mcp() {
    let key = generate_test_key(KID);
    let (resource, _) = resource_for("http://127.0.0.1/mcp", &key);
    let authenticator =
        BearerAuthenticator::<TestGrant>::new(BearerSyntax::Strict, |_| None);
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("stub"))
        .with_oauth_resource(Arc::new(resource));
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::authenticated(
        TransportIdentity::new("stubmcp", "stub", "stub", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        boundary,
    );
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(StubServer), config)
        .expect("router builds");
    let served = serve_on_loopback(plan).await;
    let address = served.address;

    let (metadata_status, metadata_body, mcp_status, mcp_challenge) =
        tokio::task::spawn_blocking(move || {
            let agent: ureq::Agent =
                ureq::Agent::config_builder().http_status_as_error(false).build().into();
            let mut metadata = agent
                .get(&format!("http://{address}/.well-known/oauth-protected-resource/mcp"))
                .call()
                .expect("metadata request");
            let metadata_status = metadata.status().as_u16();
            let metadata_body = metadata.body_mut().read_to_string().expect("body");
            let mcp = agent
                .post(&format!("http://{address}/mcp"))
                .header("Content-Type", "application/json")
                .send("{}")
                .expect("mcp request");
            let challenge = mcp
                .headers()
                .get("www-authenticate")
                .map(|value| value.to_str().expect("ASCII").to_owned());
            (metadata_status, metadata_body, mcp.status().as_u16(), challenge)
        })
        .await
        .expect("blocking task");

    assert_eq!(metadata_status, 200, "metadata must be reachable without credentials");
    let document: Value = serde_json::from_str(&metadata_body).expect("JSON");
    assert_eq!(document["resource"], "http://127.0.0.1/mcp");
    assert_eq!(document["authorization_servers"], json!([ISSUER]));
    assert_eq!(mcp_status, 401);
    assert!(
        mcp_challenge.expect("challenge").contains("resource_metadata=\"http://127.0.0.1/.well-known/oauth-protected-resource/mcp\""),
    );

    shutdown.cancel();
    served.serving.await.expect("join").expect("clean shutdown");
}
```

(`ureq` 3 is an optional normal dependency enabled by `test-util`, which the `[[test]]`
requires; `tokio-util` and `rmcp` are normal dependencies, so integration tests can use
them. If `ureq`'s `body_mut().read_to_string()` spelling differs in the locked 3.x, adjust
to the pattern in `src/test_client.rs` and keep the assertions.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource --test oauth_resource 2>&1 | tail`
Expected: compile error, `with_oauth_resource` not found.

- [ ] **Step 3: Implement**

`auth.rs`, `BearerBoundary`: add

```rust
    #[cfg(feature = "oauth-resource")]
    oauth: Option<Arc<crate::oauth_resource::OAuthResource<G>>>,
```
(`None` in `new`, cloned in `Clone`), with

```rust
    /// Accept JWT access tokens as an additional credential (mecmcp#498).
    ///
    /// Static tokens are still tried first and are unaffected. Every 401 this boundary
    /// emits gains `resource_metadata="<url>"` pointing at the RFC 9728 document that
    /// `build_streamable_http_router` serves for `resource`.
    #[cfg(feature = "oauth-resource")]
    #[must_use]
    pub fn with_oauth_resource(
        mut self,
        resource: Arc<crate::oauth_resource::OAuthResource<G>>,
    ) -> Self {
        self.responses = self
            .responses
            .clone()
            .with_resource_metadata(resource.config().resource().metadata_url())
            .expect("a ResourceUri yields a header-safe absolute URL");
        self.oauth = Some(resource);
        self
    }

    /// The metadata router to merge outside the boundary, when OAuth mode is on.
    #[cfg(feature = "oauth-resource")]
    pub(crate) fn oauth_metadata_router(&self) -> Option<Router> {
        self.oauth.as_ref().map(|resource| resource.metadata_router())
    }
```
`AuthState` gains `#[cfg(feature = "oauth-resource")] pub oauth: Option<Arc<OAuthResource<G>>>`
and `apply_bearer_boundary` passes `oauth: boundary.oauth`. (`rg 'AuthState \{'` found only
that one construction site.)

Middleware: replace the `let Some(mut caller) = state.authenticator.authenticate(candidate) else {..};`
statement with

```rust
    #[cfg_attr(not(feature = "verified-approver"), allow(unused_mut))]
    let mut caller = match state.authenticator.authenticate(candidate) {
        Some(caller) => caller,
        None => match try_oauth(&state, candidate).await {
            OAuthOutcome::Authenticated(caller) => *caller,
            OAuthOutcome::Rejected(response) => return response,
            OAuthOutcome::NotApplicable => {
                tracing::warn!("auth_failed: no matching token");
                return invalid_token(&state.responses);
            }
        },
    };
```
and, below the middleware:

```rust
/// What the OAuth step decided about a candidate the static store did not recognise.
enum OAuthOutcome<G: Grant> {
    /// OAuth mode is off for this boundary: behave exactly as before.
    NotApplicable,
    Authenticated(Box<CallerCtx<G>>),
    Rejected(Response),
}

#[cfg(not(feature = "oauth-resource"))]
async fn try_oauth<G: Grant>(_state: &AuthState<G>, _candidate: &str) -> OAuthOutcome<G> {
    OAuthOutcome::NotApplicable
}

#[cfg(feature = "oauth-resource")]
async fn try_oauth<G: Grant>(state: &AuthState<G>, candidate: &str) -> OAuthOutcome<G> {
    use crate::oauth_resource::OAuthRejection;
    let Some(resource) = state.oauth.as_ref() else {
        return OAuthOutcome::NotApplicable;
    };
    match resource.authenticate(candidate).await {
        Ok(caller) => OAuthOutcome::Authenticated(Box::new(caller)),
        Err(OAuthRejection::Invalid(reason)) => {
            tracing::warn!(reason, "oauth_rejected");
            OAuthOutcome::Rejected(invalid_token(&state.responses))
        }
        Err(OAuthRejection::Unmapped(identity)) => {
            tracing::warn!(reason = "unmapped_scope", "oauth_rejected");
            let caller = CallerCtx::<G>::oauth(
                identity,
                mecmcp_auth::ScopeSet::Allowlist(Vec::new()),
                mecmcp_auth::ScopeSet::Allowlist(Vec::new()),
                mecmcp_auth::ActorType::Unknown,
            );
            let mut scope = AuditScope::from_caller(&caller, "oauth", "authenticate", Vec::new());
            scope.deny("unmapped_scope");
            OAuthOutcome::Rejected(forbidden(
                &state.responses.realm,
                "the token grants no access to this server",
            ))
        }
        Err(OAuthRejection::Unavailable(reason)) => {
            tracing::warn!(reason, "oauth_unavailable");
            OAuthOutcome::Rejected(service_unavailable())
        }
    }
}

/// 503 for "could not verify right now": the credential is not judged invalid.
fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "5")],
        axum::Json(json!({
            "error": "temporarily_unavailable",
            "error_description": "token verification is temporarily unavailable",
        })),
    )
        .into_response()
}
```
(`service_unavailable` is only used with the feature on; mark it
`#[cfg(feature = "oauth-resource")]` to avoid a dead-code warning.)

`server.rs`, in `build_streamable_http_router`, before `config.bearer` is moved:

```rust
    #[cfg(feature = "oauth-resource")]
    let oauth_metadata = config.bearer.as_ref().and_then(BearerBoundary::oauth_metadata_router);
```
and after the health router merge:

```rust
    // RFC 9728 metadata is public by design: merged after the bearer boundary was applied
    // to /mcp, so it is outside it, but before Host/Origin validation and the IP rate
    // limit below, so it is inside those.
    #[cfg(feature = "oauth-resource")]
    if let Some(metadata) = oauth_metadata {
        router = router.merge(metadata);
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource && cargo test --locked -p mecmcp-transport --features test-util`
Expected: all pass; with the feature **off** the full existing suite is unchanged (second command).

- [ ] **Step 5: Sabotage**

1. In `try_oauth`, return `NotApplicable` always -> `a_valid_access_token...` fails (401).
2. Swap the order so OAuth is tried before the static store -> `static_tokens_keep_working...`
   fails on the fetch-count assertion (this is the test that proves "static first").
3. Delete the `oauth_metadata` merge in `server.rs` -> the assembly test fails at the 200 assertion.
4. Merge the metadata router *inside* `apply_bearer_boundary` (before it) -> the same test
   fails with 401.
5. Map `Unmapped` to `invalid_token` -> `a_valid_token_with_no_mapped_authority...` fails.

**Security review points:** the static store is always consulted first; OAuth failure cannot
affect static traffic; the 403 path audits with `Principal::OAuth`; the metadata route sits
inside Host/Origin validation (DNS rebinding) and the IP rate limit; with the feature off
there is no new code path (the second test command). A valid OAuth caller then flows through
the *existing* approver-assertion block: because `oidc_subject` is `None`, such a caller
cannot bind an approver assertion (fails closed; see open question 4).

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates/mecmcp-transport
git commit -m "feat(transport): authenticate JWT access tokens after static tokens, serve RFC 9728 metadata (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~380 lines (about 230 tests).

---

### Task 10: Hardening: JWT-shape prefilter, bounded verification, no token passthrough

Satisfies the "no JWKS amplification" security point and requirement 8 at the HTTP level.

**Files:**
- Modify: `crates/mecmcp-transport/src/oauth_resource/mod.rs` (`looks_like_jwt`, semaphore, timeout, config knobs)
- Modify: `crates/mecmcp-transport/src/auth.rs` (`try_oauth` prefilter; strip `Authorization` after OAuth success)
- Modify: `crates/mecmcp-transport/tests/oauth_resource.rs` (append)

**Interfaces:**
- Produces:
  - `pub(crate) fn looks_like_jwt(candidate: &str) -> bool`: <= 8192 bytes, exactly three non-empty dot-separated segments, every byte base64url (`A-Za-z0-9-_`)
  - `OAuthResourceConfig::with_verify_timeout(Duration)` (default 3 s) and `with_max_concurrent_verifications(usize)` (default 32, minimum 1)
  - `authenticate` returns `Unavailable("busy")` when no permit is free and `Unavailable("timeout")` when verification exceeds the timeout
  - After a successful OAuth authentication the `Authorization` header is removed from the request before inner layers and handlers (rmcp copies request parts into tool contexts; nothing downstream can read the bearer)

Rationale (cache facts from `cache.rs:93-135`): fetches are already limited to one per
30 s backoff no matter how many tokens arrive, so a flood cannot multiply fetches. What it
*can* do is queue on the cache's mutex while a slow IdP fetch holds it. The prefilter keeps
non-JWT guesses off that path entirely; the semaphore and timeout bound how many requests wait
and for how long. Static-token traffic never enters this path.

- [ ] **Step 1: Write the failing tests**

Append to `tests/oauth_resource.rs`:

```rust
use std::time::{Duration, Instant};

struct HangingSource;

#[async_trait::async_trait]
impl KeySource for HangingSource {
    async fn fetch_discovery(&self, _issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        std::future::pending().await
    }
    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        std::future::pending().await
    }
}

fn hanging_resource(timeout: Duration, permits: usize) -> OAuthResource<TestGrant> {
    let config = OAuthResourceConfig::new(
        ISSUER,
        PANOS,
        OAuthScopeMap::from_json(SCOPE_MAP.as_bytes()).expect("map"),
    )
    .expect("config")
    .with_verify_timeout(timeout)
    .with_max_concurrent_verifications(permits);
    OAuthResource::new(config, Arc::new(HangingSource))
}

#[tokio::test]
async fn candidates_that_are_not_jwt_shaped_never_reach_the_idp() {
    let key = generate_test_key(KID);
    let (panos, fetches) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let long = format!("{}.{}.{}", "a".repeat(4000), "b".repeat(4000), "c".repeat(400));
    for guess in [
        "x".repeat(43),
        "a.b".to_owned(),
        "a.b.c.d".to_owned(),
        "a..c".to_owned(),
        "a.b.c d".to_owned(),
        long,
    ] {
        let (status, _, _) = call(&app, Some(guess.as_str())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{guess:.20}");
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn jwt_shaped_garbage_is_rejected_before_any_key_fetch() {
    let key = generate_test_key(KID);
    let (panos, fetches) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    for _ in 0..20 {
        let (status, _, _) = call(&app, Some("aaaa.bbbb.cccc")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 0, "decode_header fails first");
}

#[tokio::test]
async fn a_flood_of_unknown_kid_tokens_costs_one_fetch() {
    let key = generate_test_key(KID);
    let (panos, fetches) = resource_for(PANOS, &key);
    let app = app(Some(Arc::new(panos)));
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("not-in-the-jwks".to_owned());
    let token = jsonwebtoken::encode(&header, &claims(json!(PANOS), "panos:read"), &key.encoding_key)
        .expect("sign");
    for _ in 0..200 {
        let (status, _, _) = call(&app, Some(token.as_str())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(fetches.load(Ordering::SeqCst), 1, "the cache, not the request rate, drives fetches");
}

#[tokio::test]
async fn a_hanging_idp_yields_503_quickly_and_leaves_static_tokens_alone() {
    let key = generate_test_key(KID);
    let app = app(Some(Arc::new(hanging_resource(Duration::from_millis(50), 4))));
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));

    let started = Instant::now();
    let (status, _, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(started.elapsed() < Duration::from_secs(2));

    let (status, _, _) = call(&app, Some(STATIC_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "static tokens do not depend on the IdP");
}

#[tokio::test]
async fn verifications_beyond_the_permit_limit_are_refused_immediately() {
    let key = generate_test_key(KID);
    let resource = Arc::new(hanging_resource(Duration::from_secs(30), 1));
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));

    let holder = {
        let resource = Arc::clone(&resource);
        let token = token.clone();
        tokio::spawn(async move { resource.authenticate(&token).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await; // let it take the permit
    let started = Instant::now();
    assert_eq!(resource.authenticate(&token).await.unwrap_err(), OAuthRejection::Unavailable("busy"));
    assert!(started.elapsed() < Duration::from_millis(500), "must not queue behind the holder");
    holder.abort();
}

#[tokio::test]
async fn the_bearer_is_stripped_from_oauth_requests_and_absent_from_the_context() {
    let key = generate_test_key(KID);
    let (panos, _) = resource_for(PANOS, &key);
    let authenticator = BearerAuthenticator::<TestGrant>::new(BearerSyntax::Strict, |_| None);
    let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"))
        .with_oauth_resource(Arc::new(panos));
    let router = Router::new().route(
        "/",
        post(|request: Request<Body>| async move {
            let caller = request.extensions().get::<CallerCtx<TestGrant>>().expect("caller");
            json!({
                "authorization_present": request.headers().contains_key(header::AUTHORIZATION),
                "caller_debug": format!("{caller:?}"),
            })
            .to_string()
        }),
    );
    let app = apply_bearer_boundary(
        router,
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    );
    let token = sign(&key, &claims(json!(PANOS), "panos:read"));
    let (status, _, body) = call(&app, Some(token.as_str())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["authorization_present"], false, "no inner layer or handler may see the bearer");
    let debug = body["caller_debug"].as_str().expect("string");
    for segment in token.split('.') {
        assert!(!debug.contains(segment));
    }
}
```

Unit test in `oauth_resource/mod.rs` for the shape filter:

```rust
    #[test]
    fn looks_like_jwt_accepts_only_three_base64url_segments() {
        assert!(looks_like_jwt("aaa.bbb.ccc"));
        assert!(looks_like_jwt("a-_.B9.c"));
        for bad in ["", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b.", "a.b.c=", "a.b.c d", "a.b.é"] {
            assert!(!looks_like_jwt(bad), "{bad:?}");
        }
        assert!(!looks_like_jwt(&format!("a.b.{}", "c".repeat(9000))));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource 2>&1 | tail`
Expected: compile errors (`with_verify_timeout`, `looks_like_jwt` missing).

- [ ] **Step 3: Implement**

`mod.rs`:

```rust
/// Longest bearer the OAuth path will look at. A JWT with a handful of claims is well
/// under 2 KiB; the cap bounds what an unauthenticated caller can make us base64-decode.
const MAX_JWT_BYTES: usize = 8192;

/// Cheap shape test run before any async work: three non-empty base64url segments.
pub(crate) fn looks_like_jwt(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > MAX_JWT_BYTES {
        return false;
    }
    let mut segments = 0;
    for segment in candidate.split('.') {
        segments += 1;
        let clean = !segment.is_empty()
            && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !clean {
            return false;
        }
    }
    segments == 3
}
```
Config: add `verify_timeout: Duration` (3 s) and `max_concurrent_verifications: usize` (32) with
`with_verify_timeout(Duration)` and `with_max_concurrent_verifications(usize)` (`.max(1)`), and
getters. `OAuthResource` gets `permits: tokio::sync::Semaphore` built from the config.
`authenticate` begins:

```rust
        let Ok(_permit) = self.permits.try_acquire() else {
            return Err(OAuthRejection::Unavailable("busy"));
        };
        let verified = tokio::time::timeout(self.config.verify_timeout(), self.verifier.verify(token))
            .await
            .map_err(|_elapsed| OAuthRejection::Unavailable("timeout"))?;
        let claims = match verified { /* as before */ };
```
(A cancelled refresh leaves the cache's `last_attempt` set, so the next attempt waits out the
30 s backoff and meanwhile serves stale keys within `max_key_age` or fails closed. That is
the intended degradation.)

`auth.rs`, in `try_oauth` right after the `let Some(resource)` check:

```rust
    if !crate::oauth_resource::looks_like_jwt(candidate) {
        return OAuthOutcome::NotApplicable;
    }
```
and in the middleware, after the approver-assertion block and before the extension inserts:

```rust
    if caller.oauth.is_some() {
        // Token passthrough: rmcp copies request parts into tool contexts, so the bearer
        // must not survive authentication. Static-token requests are left as they were.
        request.headers_mut().remove(header::AUTHORIZATION);
    }
```
(`caller.oauth` is an `Option` on every build, so this needs no `cfg`.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-transport --features test-util,oauth-resource`
Expected: all pass, including every Task 9 test (the shape filter must not break them: their tokens are real JWTs).

- [ ] **Step 5: Sabotage**

1. Make `looks_like_jwt` return `true` -> `candidates_that_are_not_jwt_shaped...` fails only if
   the guesses reach a fetch; they do not (a malformed token fails `decode_header` first), so
   this sabotage is **expected to pass**. Record that result: it shows the prefilter's job is
   saving the permit and the decode, not the fetch, and that the real fetch guard is
   `decode_header`-before-`keys()` plus the cache. Then sabotage that instead: in `mecmcp-oidc`
   move `self.cache.keys().await?` above `decode_header` -> `jwt_shaped_garbage_is_rejected...`
   fails with a non-zero fetch count. Restore.
2. Remove the `remove(header::AUTHORIZATION)` -> `the_bearer_is_stripped...` fails.
3. Replace `try_acquire` with `acquire().await` -> `verifications_beyond_the_permit_limit...`
   hangs until timeout and fails its elapsed-time assertion.
4. Remove the `timeout` wrapper -> `a_hanging_idp_yields_503...` hangs (the harness test timeout kills it).

**Security review points:** unauthenticated amplification (shape prefilter, header-first
decode, cache-driven fetch, semaphore, timeout), all measured by counting fetches rather than
trusting the design; token passthrough (header stripped, context credential-free); the 503 is
indistinguishable by an unauthenticated caller from a busy server, and reveals nothing about
whether any token was valid.

- [ ] **Step 6: Verify block, then commit**

```bash
git add -A crates/mecmcp-transport
git commit -m "feat(transport): bound OAuth verification and strip the bearer after auth (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~330 lines (about 210 tests).

---

### Task 11: `OAuthResourceArgs` in `mecmcp-runtime`

Satisfies requirement 9.

**Files:**
- Modify: `crates/mecmcp-runtime/src/cli.rs` (new struct and error after `VerifiedApproverArgsError`, ~:450; tests near :1494-1600)
- Modify: `crates/mecmcp-runtime/src/lib.rs` (re-export, if `VerifiedApproverArgs` is re-exported there; mirror it)

**Interfaces:**
- Produces (flattenable like `VerifiedApproverArgs` / `ToolModeArgs`; **not** added to `Cli`, so no consumer breaks):
  - `OAuthResourceArgs { oauth_issuer: Option<String>, oauth_resource: Option<String>, oauth_scope_map: Option<PathBuf>, oauth_audience: Option<String>, oauth_role_claim: String ("roles"), oauth_require_at_jwt_typ: bool }`
  - `OAuthResourceArgs::enabled(&self) -> bool`
  - `OAuthResourceArgs::validate(&self) -> Result<(), OAuthResourceArgsError>`
  - `OAuthResourceArgs::audience_differs_from_resource(&self) -> bool` (for a startup warning)
- Consumed by each server (outside this repo): `validate()?`, then
  `OAuthScopeMap::load(path)`, `OAuthResourceConfig::new(issuer, resource, map)` (which does the full URI parse and may still reject), `.with_audience(..)`, `.with_role_claim(..)`, `.with_require_at_jwt_typ(..)`, `OAuthResource::new(config, Arc::new(HttpKeySource::new(client)))`, `BearerBoundary::with_oauth_resource(..)`.

`mecmcp-runtime` depends on neither `mecmcp-oidc` nor `mecmcp-transport`, so `validate()` does only string-level checks; the authoritative parse stays in `OAuthResourceConfig::new`, which every server must call at startup anyway.

Validation rules and why:
- **All-or-nothing:** `--oauth-issuer`, `--oauth-resource` and `--oauth-scope-map` are required together; any one alone is an error naming the missing ones. (A half-configured OAuth mode that silently does nothing is the worst outcome.)
- **`--oauth-require-at-jwt-typ`, `--oauth-audience` or a non-default `--oauth-role-claim` without the three required flags** is an error (`FlagWithoutOAuth`): they would otherwise be silently ignored.
- **Issuer must start with `https://`** (no exception; discovery refuses http).
- **Resource must start with `https://`, or be `http://` to `localhost`, `127.0.0.1` or `[::1]`** (decision 4: matches the transport's loopback treatment and what MCP clients accept for local development; everything else gets TLS).
- No env-var bindings: the three required values are deployment configuration written into a unit file, and an environment variable is one more place for them to silently differ from it.

- [ ] **Step 1: Write the failing tests**

```rust
    #[derive(Debug, Parser)]
    struct OAuthTestCli {
        #[command(flatten)]
        oauth: OAuthResourceArgs,
    }

    fn parse(extra: &[&str]) -> OAuthResourceArgs {
        let mut argv = vec!["test"];
        argv.extend_from_slice(extra);
        OAuthTestCli::parse_from(argv).oauth
    }

    const FULL: [&str; 6] = [
        "--oauth-issuer", "https://idp.example/realms/lab",
        "--oauth-resource", "https://junos.example/mcp",
        "--oauth-scope-map", "/etc/junosmcp/oauth-scopes.json",
    ];

    #[test]
    fn oauth_args_default_to_off_and_validate() {
        let args = parse(&[]);
        assert!(!args.enabled());
        assert_eq!(args.validate(), Ok(()));
        assert_eq!(args.oauth_role_claim, "roles");
    }

    #[test]
    fn a_complete_configuration_validates() {
        let args = parse(&FULL);
        assert!(args.enabled());
        assert_eq!(args.validate(), Ok(()));
        assert!(!args.audience_differs_from_resource());
    }

    #[test]
    fn a_partial_configuration_names_what_is_missing() {
        assert_eq!(
            parse(&["--oauth-issuer", "https://idp.example"]).validate(),
            Err(OAuthResourceArgsError::Incomplete(vec!["--oauth-resource", "--oauth-scope-map"]))
        );
        assert_eq!(
            parse(&["--oauth-scope-map", "/x.json"]).validate(),
            Err(OAuthResourceArgsError::Incomplete(vec!["--oauth-issuer", "--oauth-resource"]))
        );
    }

    #[test]
    fn modifier_flags_without_the_core_trio_are_errors_not_silently_ignored() {
        for flag in [
            vec!["--oauth-require-at-jwt-typ"],
            vec!["--oauth-audience", "x"],
            vec!["--oauth-role-claim", "groups"],
        ] {
            assert_eq!(parse(&flag).validate(), Err(OAuthResourceArgsError::FlagWithoutOAuth), "{flag:?}");
        }
    }

    #[test]
    fn the_issuer_must_be_https() {
        let mut argv = FULL.to_vec();
        argv[1] = "http://idp.example";
        assert_eq!(parse(&argv).validate(), Err(OAuthResourceArgsError::IssuerNotHttps));
    }

    #[test]
    fn the_resource_must_be_https_except_for_loopback() {
        for ok in [
            "https://junos.example/mcp",
            "http://localhost:8080/mcp",
            "http://127.0.0.1:8080/mcp",
            "http://[::1]:8080/mcp",
            "http://localhost/mcp",
        ] {
            let mut argv = FULL.to_vec();
            argv[3] = ok;
            assert_eq!(parse(&argv).validate(), Ok(()), "{ok}");
        }
        for bad in [
            "http://junos.example/mcp",
            "http://localhost.evil.example/mcp",
            "http://127.0.0.1.evil.example/mcp",
            "ftp://junos.example/mcp",
            "junos.example/mcp",
        ] {
            let mut argv = FULL.to_vec();
            argv[3] = bad;
            assert_eq!(parse(&argv).validate(), Err(OAuthResourceArgsError::ResourceNotHttps), "{bad}");
        }
    }

    #[test]
    fn an_audience_override_is_reported_so_the_server_can_warn() {
        let mut argv = FULL.to_vec();
        argv.extend(["--oauth-audience", "junos-client"]);
        let args = parse(&argv);
        assert_eq!(args.validate(), Ok(()));
        assert!(args.audience_differs_from_resource());
    }

    #[test]
    fn oauth_args_flatten_alongside_the_shared_cli_and_verified_approver_args() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[command(flatten)]
            verified_approver: VerifiedApproverArgs,
            #[command(flatten)]
            oauth: OAuthResourceArgs,
        }
        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            ["consumer-mcp", "--oidc-issuer", "https://approver-idp.example", "--oidc-audience", "a",
             "--oauth-issuer", "https://idp.example", "--oauth-resource", "https://h.example/mcp",
             "--oauth-scope-map", "/m.json"],
        )
        .expect("the --oidc-* and --oauth-* groups must not collide");
        assert_eq!(parsed.cli.oauth.oauth_issuer.as_deref(), Some("https://idp.example"));
        assert_eq!(parsed.cli.verified_approver.oidc_issuer.as_deref(), Some("https://approver-idp.example"));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --locked -p mecmcp-runtime oauth 2>&1 | tail`
Expected: compile error, `OAuthResourceArgs` not found.

- [ ] **Step 3: Implement**

```rust
/// OAuth 2.1 resource-server flags, for a server to `#[command(flatten)]` into its own CLI
/// (mecmcp#498).
///
/// Absent all of them a server behaves exactly as before. Kept off [`Cli`] for the reason
/// [`ToolModeArgs`] is: a new `Cli` field would break consumers that build it by struct
/// literal. This crate depends on neither `mecmcp-oidc` nor `mecmcp-transport`, so
/// [`validate`](Self::validate) is string-level only; the authoritative URI parse is
/// `mecmcp_transport::OAuthResourceConfig::new`, which the server calls next.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct OAuthResourceArgs {
    /// Issuer URL of the external authorization server (must be https). Tokens must carry
    /// exactly this `iss`. Required with `--oauth-resource` and `--oauth-scope-map`.
    #[arg(long)]
    pub oauth_issuer: Option<String>,

    /// This server's canonical resource URI (RFC 8707), e.g. `https://junos.lab.example/mcp`.
    /// Becomes the required token audience, the metadata `resource`, and (by path) the
    /// metadata route. https, or http for a loopback host only.
    #[arg(long)]
    pub oauth_resource: Option<String>,

    /// JSON file mapping token scopes and roles to this server's tools and devices.
    /// A token that maps to nothing is refused. See docs/OAUTH.md.
    #[arg(long)]
    pub oauth_scope_map: Option<std::path::PathBuf>,

    /// Expected `aud`, when the IdP cannot emit the resource URI (it defaults to
    /// `--oauth-resource`). Must be unique per server or tokens are not bound to one server.
    #[arg(long)]
    pub oauth_audience: Option<String>,

    /// Top-level claim carrying role or group names.
    #[arg(long, default_value = "roles")]
    pub oauth_role_claim: String,

    /// Require the RFC 9068 `typ: at+jwt` header on access tokens.
    #[arg(long)]
    pub oauth_require_at_jwt_typ: bool,
}

impl OAuthResourceArgs {
    /// Whether any core OAuth flag was given (the three required ones).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.oauth_issuer.is_some() || self.oauth_resource.is_some() || self.oauth_scope_map.is_some()
    }

    /// Whether `--oauth-audience` was set to something other than the resource URI.
    #[must_use]
    pub fn audience_differs_from_resource(&self) -> bool {
        match (&self.oauth_audience, &self.oauth_resource) {
            (Some(audience), Some(resource)) => audience != resource,
            _ => false,
        }
    }

    /// Cross-check the flags. See the type docs for the rules.
    ///
    /// # Errors
    /// Returns the first rule violated.
    pub fn validate(&self) -> Result<(), OAuthResourceArgsError> {
        let modifier_given = self.oauth_require_at_jwt_typ
            || self.oauth_audience.is_some()
            || self.oauth_role_claim != "roles";
        if !self.enabled() {
            if modifier_given {
                return Err(OAuthResourceArgsError::FlagWithoutOAuth);
            }
            return Ok(());
        }
        let missing: Vec<&'static str> = [
            ("--oauth-issuer", self.oauth_issuer.is_none()),
            ("--oauth-resource", self.oauth_resource.is_none()),
            ("--oauth-scope-map", self.oauth_scope_map.is_none()),
        ]
        .into_iter()
        .filter_map(|(flag, absent)| absent.then_some(flag))
        .collect();
        if !missing.is_empty() {
            return Err(OAuthResourceArgsError::Incomplete(missing));
        }
        if !self.oauth_issuer.as_deref().is_some_and(|issuer| issuer.starts_with("https://")) {
            return Err(OAuthResourceArgsError::IssuerNotHttps);
        }
        if !self.oauth_resource.as_deref().is_some_and(is_https_or_loopback_http) {
            return Err(OAuthResourceArgsError::ResourceNotHttps);
        }
        Ok(())
    }
}

/// `https://...`, or `http://` followed by exactly a loopback host (optionally `:port` and/or a path).
fn is_https_or_loopback_http(uri: &str) -> bool {
    if uri.starts_with("https://") {
        return true;
    }
    ["http://localhost", "http://127.0.0.1", "http://[::1]"].iter().any(|prefix| {
        uri.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
    })
}

/// An `OAuthResourceArgs` combination with no safe interpretation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OAuthResourceArgsError {
    /// Some, but not all, of the three required flags were given.
    #[error("OAuth resource-server mode needs --oauth-issuer, --oauth-resource and --oauth-scope-map together; missing {}", .0.join(", "))]
    Incomplete(Vec<&'static str>),
    /// An OAuth modifier flag was given with no OAuth configuration to modify.
    #[error("--oauth-audience, --oauth-role-claim and --oauth-require-at-jwt-typ have no effect without --oauth-issuer, --oauth-resource and --oauth-scope-map")]
    FlagWithoutOAuth,
    /// The issuer is not https.
    #[error("--oauth-issuer must be an https URL")]
    IssuerNotHttps,
    /// The resource is neither https nor loopback http.
    #[error("--oauth-resource must be an https URI (http is allowed only for localhost, 127.0.0.1 or [::1])")]
    ResourceNotHttps,
}
```
Re-export from `lib.rs` wherever `VerifiedApproverArgs` is re-exported (check `grep -n VerifiedApproverArgs crates/mecmcp-runtime/src/lib.rs`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --locked -p mecmcp-runtime`
Expected: all pass.

- [ ] **Step 5: Sabotage**

Drop the `rest.is_empty() || ...` guard (use `strip_prefix(..).is_some()`) -> the
`localhost.evil.example` / `127.0.0.1.evil.example` cases fail. Remove the `missing` check ->
`a_partial_configuration...` fails. Rename a flag to `--oidc-issuer` -> the flatten test fails
with a clap duplicate-argument panic.

**Security review points:** the `localhost.evil.example` prefix trick is tested; partial
configuration cannot silently leave a server in static-only mode while the operator believes
OAuth is on; `--oauth-scope-map` is a path only (contents are validated by the transport).

- [ ] **Step 6: Verify block, then commit**

```bash
git add crates/mecmcp-runtime
git commit -m "feat(runtime): flattenable OAuthResourceArgs (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~270 lines (about 120 tests).

---

### Task 12: Docs, threat model, changelog

Satisfies requirement 10. Docs are checked by `cargo doc` (intra-doc links in the new
rustdoc) and by a mechanical grep, because "the commands were never run by anything"
(memory: docs PRs need the gate too).

**Files:**
- Create: `docs/OAUTH.md`
- Modify: `docs/THREAT-MODEL.md` (trust-boundary list :43-50; threat table after T12 :~91; residual risk :~98-118; "Out of scope" :112-118)
- Modify: `docs/ONBOARDING.md` (one pointer after the verified-approver section, ~:260)
- Modify: `CHANGELOG.md` (new `## [Unreleased]` section above `## [0.28.4]`; the file has none today)
- Modify: `docs/AUDIT-FORWARDING-STANDARD.md` only if it lists the event fields: `grep -n 'client_call_id\|client_version' docs/AUDIT-FORWARDING-STANDARD.md`; if it does, add `oauth_issuer`, `oauth_subject`, `oauth_client_id` beside them.

**Interfaces:** none (prose). The doc must be consistent with the shipped names: flags
`--oauth-issuer --oauth-resource --oauth-scope-map --oauth-audience --oauth-role-claim --oauth-require-at-jwt-typ`;
feature `oauth-resource`; file format version `1`; reason codes from Tasks 1/8/10.

- [ ] **Step 1: Write the docs**

`docs/OAUTH.md` sections (write each in full; this is the outline with the non-obvious
content that must appear):

1. **What this is / is not.** Optional; static tokens keep working and are tried first;
   the authorization server stays external (no embedded login, consent, token issuance,
   dynamic client registration, or CIMD; those are the IdP's job).
2. **Build and enable.** `mecmcp-transport` feature `oauth-resource` (off by default; it links
   the `mecmcp-oidc` HTTP stack), the server flattens `OAuthResourceArgs`, calls `validate()`,
   builds `OAuthScopeMap::load` -> `OAuthResourceConfig::new` -> `OAuthResource::new(config,
   Arc::new(HttpKeySource::new(client)))` -> `BearerBoundary::with_oauth_resource`. Include the
   ~12-line wiring snippet as it will appear in a server's `main`.
3. **Operator setup, IdP-agnostic.** Numbered steps: (1) one *resource/audience per server*
   (`https://junos.lab.example/mcp`, `https://panos.lab.example/mcp`); (2) the client requests
   `resource=<that URI>` (MCP clients do this per the MCP authorization spec) and the IdP puts it
   in `aud`; if the IdP cannot, set an audience claim mapper to the URI, or as a last resort
   `--oauth-audience <client-id>` with one IdP client per server; (3) the IdP emits `scope`
   (space-delimited) or `scp`, `sub`, `iss`, `exp`, `iat`, `jti` and `client_id` or `azp`
   (RFC 9068; Keycloak emits `azp`, which is accepted); (4) role/group names as a **top-level**
   claim named by `--oauth-role-claim` (nested claims such as Keycloak's `realm_access.roles`
   are not read; add a token mapper that flattens them); (5) write the scope-map file and test
   with `curl`; (6) start the server and check `GET /.well-known/oauth-protected-resource/<path>`.
   Give Keycloak and Authentik as two short worked notes (Keycloak: "Audience" mapper with
   "Included Custom Audience" = the resource URI, a "Group Membership" mapper to a flat claim
   with full path off; Authentik: audience is the provider's client id, so create one provider
   per server and pass `--oauth-audience`) without claiming exact UI labels beyond what was
   verified; mark anything unverified "check your IdP's documentation".
4. **The scope-map file.** The Task 6 schema verbatim, the union rule, "unmapped grants
   nothing", "a token that maps to no tools is refused with 403", "no wildcard unless you write
   `[\"*\"]`", and the `actor_type` default of `unknown`.
5. **What clients see.** The status table: 401 `invalid_token` (+ `resource_metadata`), 403
   `insufficient_scope`, 503 `temporarily_unavailable` with `Retry-After`; plus the reason codes
   logged on `oauth_rejected` (`wrong_audience`, `expired`, `invalid_signature`,
   `unsupported_algorithm`, `wrong_token_type`, `missing_claim`, `invalid_subject`, `timeout`,
   `busy`, `keys_unavailable`, `unmapped_scope`) and what each usually means.
6. **Security properties and limits.** One token = one server (exact audience); how a stolen
   token is bounded (IdP-set `exp`; there is no revocation list in this version; keep access
   token lifetimes short); no token passthrough (header stripped, context credential-free);
   **OAuth callers hold no vendor grant**, so grant-gated mutations stay unavailable to them
   and write-capable access still needs a static token; **OAuth callers cannot bind
   approver assertions**; **JWKS rotation latency** up to `refresh_interval` (5 min) because
   an unknown `kid` does not force a refetch; **multi-audience tokens** are accepted when
   `aud` lists this server among others, so configure the IdP to issue single-audience tokens;
   audit shows `caller=oauth:<sub>`, `oauth_issuer`, `oauth_subject`, `oauth_client_id`.
7. **Troubleshooting** (a table keyed by the log reason code).
8. **Rollout.** Enable on one lab server first, keep static tokens, watch `oauth_rejected`,
   then widen.

`docs/THREAT-MODEL.md` edits:
- Add trust boundary **6. Client -> server, OAuth bearer (opt-in, #498)**: with
  `oauth-resource` a JWT from the configured issuer is accepted as the `/mcp` credential; the
  server fetches JWKS (boundary 5's channel); the token is verified once at the bearer
  boundary, mapped through the operator's scope map, and never forwarded or retained.
- Add table rows **T13** (token minted for one server replayed against another: exact
  audience binding, test names from Task 8; status ✅ where enabled) and **T14** (unauthenticated
  load on the verification path / IdP outage: shape prefilter, header-first decode, cache-driven
  fetch, bounded concurrency and timeout, static tokens unaffected; status 🟡 because there is
  no eager JWKS warm-up or revocation).
- Edit "Out of scope": remove "OIDC/OAuth as the MCP bearer credential" and rewrite the bullet
  to: "An embedded authorization server (login, consent, token issuance, dynamic client
  registration), token exchange, and retiring `actor_type: human` tokens outright. OAuth
  access tokens as the MCP bearer credential are **in scope** from #498 (boundary 6); step-up
  OIDC (#400) still only verifies identity at approval time."
- Add a residual-risk bullet: scope-map correctness is the operator's responsibility (a
  mapping that grants `["*"]` to a broad IdP group grants it to every member), and revocation
  is the IdP's `exp`.

`CHANGELOG.md` `## [Unreleased]`:
```markdown
## [Unreleased]

### Added

- **OAuth 2.1 resource-server mode** (mecmcp#498), opt-in per server. `mecmcp-transport`
  feature `oauth-resource` (off by default): RFC 9728 metadata at
  `/.well-known/oauth-protected-resource[/<path>]`, `resource_metadata` on 401 challenges,
  JWT access tokens accepted after the static token store misses, audience bound to the
  server's canonical resource URI (RFC 8707), and a fail-closed scope map
  (`docs/OAUTH.md`). `mecmcp-runtime::OAuthResourceArgs` supplies the CLI flags.
- **mecmcp-oidc:** `TokenProfile::AccessToken` (RFC 9068: requires `jti` and a client id,
  optionally `typ: at+jwt`), `VerifiedClaims::{scopes, client_id}`, `ResourceUri`.
- **mecmcp-audit:** `Principal::OAuth` and `oauth_issuer` / `oauth_subject` /
  `oauth_client_id` audit fields (empty for static-token callers).

### Changed

- **Breaking for source:** `mecmcp_auth::CallerCtx` has a new public field `oauth:
  Option<OAuthIdentity>`; code that builds it by struct literal (mostly vendor-repo tests)
  must add `oauth: None`. `mecmcp_audit::Principal` and
  `mecmcp_changeset::records::PersistedPrincipal` gain an `OAuth` variant; exhaustive
  matches need an arm. `BearerAuthError` gains `InvalidResourceMetadata`.
- `TokenEntry::validate` now rejects token names starting with `oauth:` (reserved).
```

- [ ] **Step 2: Mechanical checks (these are the "tests" for a docs task)**

```bash
# every flag in the doc exists in the CLI struct, and vice versa
for flag in $(grep -o -- '--oauth-[a-z-]*' docs/OAUTH.md | sort -u); do
  grep -q -- "${flag#--}" crates/mecmcp-runtime/src/cli.rs || echo "doc names a flag the CLI lacks: $flag"
done
# every reason code in the doc is produced by the code
for code in wrong_audience expired invalid_signature unsupported_algorithm wrong_token_type \
            missing_claim invalid_subject timeout busy keys_unavailable unmapped_scope; do
  grep -rq "\"$code\"" crates/mecmcp-oidc/src crates/mecmcp-transport/src || echo "no producer for $code"
done
# the scope-map example in the doc parses with the real loader
python3 - <<'PY'
import json,re,sys
text=open('docs/OAUTH.md').read()
block=re.search(r'```json\n(\{\s*"version".*?\})\n```',text,re.S)
sys.exit(0 if block and json.loads(block.group(1))["version"]==1 else 1)
PY
cargo doc --workspace --no-deps --locked
```
Expected: no output from the loops, python exits 0, `cargo doc` clean. Then paste the doc's
scope-map JSON into a scratch file and run it through `OAuthScopeMap::load` in a throwaway
`cargo test` (or the Task 6 `from_json` unit test, which uses the same text): a doc example
that the loader rejects is a bug in the doc.

- [ ] **Step 3: Sabotage**

Rename a flag in `OAUTH.md` -> the first loop prints it. Delete `"busy"` from the code ->
the second loop prints it.

- [ ] **Step 4: Verify block, then commit**

```bash
git add docs CHANGELOG.md
git commit -m "docs: OAuth resource-server operator guide, threat model, changelog (#498)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Estimated size: ~380 lines of prose.

---

## Per-server rollout (outside this repository)

Not part of this plan's commits; recorded so the work is not lost. After a mecmcp release
containing Tasks 1-12: each vendor repo (junos, panos, sdc, mist, proxmox, unifi) bumps the
mecmcp pin (twice for sdc, see memory: sdc pins mecmcp twice), enables the transport feature,
flattens `OAuthResourceArgs` beside `VerifiedApproverArgs`, adds the 8-line wiring from
`docs/OAUTH.md` section 2, and ships a sample `oauth-scopes.json`. Order: panos first (the
two-server audience test needs a second server), then junos. Hardware verification is not
needed for this feature (no device path changes), but run the MCP client end to end once
(Odysseus) against a lab IdP before tagging the vendor release; a green suite here proves the
verifier, not that a given IdP puts the resource URI in `aud`.

## Self-Review

**1. Spec coverage** (issue requirement -> task):
1. RFC 9728 endpoint outside the boundary -> Tasks 2 (URI/paths), 7 (document, router), 9 (assembly test proves it is outside the boundary and inside Host/Origin).
2. `resource_metadata` in 401s -> Task 5 (shape, escaping), Task 9 (set automatically by `with_oauth_resource`).
3. JWT as bearer, static first, async path, feature `oauth-resource`, off by default -> Task 6 (feature), Task 8 (verifier), Task 9 (middleware; design decision 1 justifies the concrete verifier over an async callback; sabotage 2 proves the order).
4. Audience bound (RFC 8707), junos token refused by panos -> Task 8 (`a_junos_audience_token_is_refused_by_a_panos_resource`, near-miss table), Task 9 (same at HTTP level).
5. Fail-closed claim -> CallerCtx mapping -> Task 6 (map file, union, unmapped grants nothing, no default wildcard), Task 8 (smuggling, unmapped), Task 9 (403 vs 401 per decision 5).
6. `scopes` / `client_id` on `VerifiedClaims`; access-token `iat`/`jti` handling via config -> Task 1 (`TokenProfile`; the ID-token path is untouched and pinned by a test).
7. Audit `Principal::OAuth` with sub and client id, carried by `CallerCtx` -> Tasks 3 (carry), 4 (principal, audit fields, persisted form).
8. No token passthrough -> Task 3 (exhaustive destructure: no credential field), Task 8 (Debug of context), Task 10 (header stripped; handler-level assertion).
9. `OAuthResourceArgs` with https validation -> Task 11 (loopback http decision 4).
10. Docs: threat model, operator guide, changelog -> Task 12.
Security review points: alg confusion (Task 8 HS256), aud substring (Task 8 table), scope injection (Tasks 1, 6, 8), `WWW-Authenticate` header injection (Task 5, Task 2), JWKS amplification (Task 10, counting source).

**2. Placeholder scan:** no TBD/TODO. Two places say "adjust if the locked version differs"
(the `ureq` body-read spelling in Task 9; the neighbouring-test helper name in Task 3's entry
test). Both name the exact file to copy the working spelling from. Task 10 sabotage 1 is
written as an *expected pass* with the reason, deliberately, so the executor does not "fix" it.

**3. Type consistency:** `OAuthIdentity { issuer, subject, client_id }` (Task 3) is used
identically in Tasks 4, 8, 9. `CallerCtx::oauth(identity, devices, tools, actor_type)` argument order
(devices before tools) is the same in Tasks 3, 4, 8, 9. `OAuthRejection::{Invalid(&'static str),
Unmapped(OAuthIdentity), Unavailable(&'static str)}` defined in Task 8, extended by reason
codes only in Task 10. `OAuthResourceConfig` builders: `with_audience`, `with_role_claim`,
`with_require_at_jwt_typ` (Task 6), `with_verify_timeout`, `with_max_concurrent_verifications`
(Task 10). `ResourceUri::{as_str, metadata_path, metadata_url}` and `ROOT_METADATA_PATH` (Task 2)
are what Tasks 7 and 9 call. Reason-code strings used in tests match `reason_code()` in
`error.rs` (`wrong_audience`, `unsupported_algorithm`, `expired`, `wrong_issuer`,
`invalid_signature`, `missing_claim`) plus the new `wrong_token_type`.

**Known gaps accepted in this plan:** no CORS headers on the metadata route (browser-hosted
MCP clients need them; none is in scope for #498's motivating case); no eager JWKS warm-up or
readiness check; no revocation; no nested role-claim paths.

## Open design questions (not resolvable from the code)

1. **Multi-audience tokens.** `jsonwebtoken` accepts a token whose `aud` array contains this
   server among others (pinned by a test). Requirement "valid on exactly one server" argues for
   rejecting arrays longer than one, but Keycloak adds `account` to `aud` by default, so
   rejecting would break the most common IdP. Decide: accept (as planned, documented), or add
   `--oauth-single-audience`.
2. **`typ: at+jwt` default.** Planned off (Keycloak default tokens are `typ: JWT`), recommended
   on in docs. Decide whether the secure default should be on with an opt-out.
3. **`actor_type` for OAuth callers.** Planned: from the scope-map file, default `unknown`.
   The server cannot tell a person from an agent holding the token; confirm `unknown` is
   acceptable where `actor_type: human` gates something (grep consumers before release).
4. **OAuth callers and change-set approval.** They carry no `oidc_subject`, so
   `bind_approver` refuses them (fail closed). Linking the OAuth `sub` to #400's
   `owner_subject` / verified approver is the natural next step but changes the two-person
   semantics; not done here. Confirm that deferral.
5. **Vendor grants.** OAuth callers get `grant: None`, so grant-gated mutations (PAN-OS XPath
   writes, Mist org/site writes) are unavailable to them. A scope-map `grant` field would need
   `OAuthScopeMap<G: Grant + DeserializeOwned>` and a per-vendor review. Confirm read-mostly
   is the intended v1.
6. **Nested role claims** (Keycloak `realm_access.roles`). `extract_roles` reads top-level
   claims only. Add a dotted-path option, or require an IdP mapper (planned)?
7. **JWKS rotation latency.** An unknown `kid` does not trigger a refetch (cache is purely
   time-driven, <= 5 min). A rotation can therefore reject valid tokens for up to
   `refresh_interval`. A bounded "refetch once on unknown kid" needs a change inside
   `mecmcp-oidc`'s cache (and its own amplification test); not in this plan.
8. **CORS** on the metadata route for browser-hosted clients.
