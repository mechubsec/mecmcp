# Verified human identity for change-set approvers: phased breakdown

**Issue:** MEC-351 · **Date:** 2026-09-28 · **Target release:** TBD (not scheduled)

This is a design spike, not an implementation plan. Per MEC-351 it exists to
break Roadmap §1 into sub-tasks small enough to size individually, so Kay can
schedule and sequence them. **No code changes ship with this document.**

## Problem, precisely

`ChangesetCoordinator::approve_change_set` already refuses an approval unless
`approver_actor_type == ActorType::Human` (CHANGELOG, the approval-gate work
under MEC-343/344/345). That closes the urgent gap: an agent can no longer
stand in as the second principal.

What it does not close: **`ActorType::Human` is an operator's claim, not a
verified fact.** Walking the actual types:

- `TokenEntry.actor_type` (`crates/mecmcp-auth/src/entry.rs`) is a field an
  operator writes into `tokens.json` by hand.
- `CallerCtx.on_behalf_of` (`crates/mecmcp-auth/src/store.rs:124`) is
  documented as "server-verified human identity" — but what the server
  verifies is only that the *token* is valid and *declares* that string. Nothing
  authenticates the human behind it: no IdP round-trip, no signature over an
  identity claim, no session. A shared token with `actor_type: human` lets
  anyone holding the bytes approve as whoever the file says.
- `Principal` (`crates/mecmcp-audit/src/attribution.rs:11`) today has exactly
  two variants, `Token(String)` and `Unauthenticated`. The roadmap text claims
  it is "already designed to carry either a token name or an OIDC subject" —
  that is aspirational, not current: there is no OIDC-subject variant, no
  OIDC crate in the dependency tree (`grep -rn oidc\|openidconnect\|jsonwebtoken
  Cargo.toml crates/*/Cargo.toml` returns nothing), and no JWT verification
  path anywhere in `mecmcp-auth`. First finding worth flagging back to Kay:
  **update the roadmap line so it stops describing unbuilt state as built.**

So the actual gap is: a bearer secret in a file asserts a name and a role,
and the server takes that assertion on faith. OIDC closes it by replacing
"the file says so" with "the customer's IdP says so, cryptographically,
per request or per session, with an expiry the operator does not control."

## Why this is L, not M

Four largely independent concerns are bundled in the roadmap's one paragraph,
each with its own failure modes and its own blast radius if got wrong:

1. Proving a JWT came from the customer's IdP and hasn't expired (discovery,
   JWKS rotation, signature verification, clock skew, audience/issuer checks).
2. Turning IdP claims into a `(device selector, tool set, action tier)` role —
   the roadmap's own scope model, which does not exist yet either (today's
   `ScopeSet` is wildcard-or-allowlist, not an expression language).
3. What a session *is* for a human caller of a protocol (MCP over HTTP) that
   was not designed with a browser redirect flow in mind, and how it expires.
4. Not breaking every existing token-based deployment on upgrade.

Each of these is independently gettable-wrong in a way that fails open (an
unverified approver) or fails closed (locks operators out of change control).
Per the house rule and the **fail closed** lens, each needs its own review and
its own test surface rather than landing as one diff.

## Phased breakdown

### Phase 1 — OIDC discovery and token verification (resource-server core)

> **Status (2026-10-26): built.** `mecmcp-oidc` (discovery, JWKS rotation, signature, `iss`,
> `aud`, `exp`/`nbf` checks, distinct logged rejection reasons) and the step-up approver
> assertion on top of it.

Add a `mecmcp-oidc` crate (or a module in `mecmcp-auth` behind a feature
flag — open question, see below) that can, given a configured issuer URL:

- Fetch and cache the OIDC discovery document and JWKS, with a bounded
  refresh interval and no unbounded retry against a customer IdP that is down.
- Verify a presented JWT's signature, `iss`, `aud`, `exp`, `nbf` against the
  cached keys.
- Produce a typed, minimal claim set (`sub`, configured group/role claim,
  `exp`) — nothing else is retained past the request.
- Do all of this with **zero network access required at build or test time**:
  fixture JWKS and fixture tokens, per the **offline-first** lens. A customer
  running fully air-gapped must still be able to build and run the test suite.

**Acceptance criteria**

- A forged signature, an expired token, a wrong-audience token, and a
  wrong-issuer token are each rejected with a distinct, logged reason — no
  single "auth failed" catch-all (needed for the audit trail this whole
  feature exists to produce).
- JWKS rotation (old `kid` retired, new `kid` added) is handled without a
  server restart.
- IdP unreachable at verification time fails the request closed, not open,
  and does not block already-authenticated bearer-token traffic — this must
  be additive to existing auth, not a single chokepoint.
- New dependency (JWT/OIDC crate) named and justified in the PR per the
  **dependency surface is attack surface** lens; a maintained, widely-used
  crate (e.g. one already used by other OIDC resource-server implementations
  in Rust) is preferred over hand-rolled JWT parsing.
- Runs and passes with network disabled.

### Phase 2 — Role-to-tenant mapping

> **Status (2026-10-26): built.** The selector grammar is a typed AST compiled at config
> load (`mecmcp_auth::selector`: `site=`, `vendor=`, `tag=`, `*` glob, exact bytes, a closed
> attribute alphabet so no lookalike can match), with adversarial isolation tests. IdP
> groups map to device scopes through the server-side OAuth scope map (`docs/OAUTH.md`
> section 4), and `device_selectors` narrow them by inventory attribute. Static `tokens.json`
> entries take the same `device_selectors`, which also scopes human approver roles, since
> approval already checks the approver's scope against the change set's one device
> (mecmcp#400). Not built: a role is a `(tools, devices)` pair; there is no separate "action
> tier" beyond the tool allowlist and the wildcard's exclusion of write tools.

Turn verified claims into the roadmap's `(device selector, tool set, action
tier)` role:

- Define the selector expression grammar (`site=emea-*`, `vendor=panos`,
  `tag=pci`) as a typed AST, not a string matched ad hoc at call sites —
  **parse, don't validate**, and per **make illegal states unrepresentable**,
  a selector that cannot compile should not be a runtime surprise on first
  use.
- Map an IdP group claim to a role via server-side configuration (never
  trust a client-asserted role directly) — the config lives on the resource
  server, mirroring how `tokens.json` is server-side today.
- Enforce structural tenant isolation: a role scoped to one site's selector
  must be provably incapable of matching another site's devices, not merely
  configured not to.

**Acceptance criteria**

- A role bound to `site=emea-*` cannot be made to match `site=apac-1` by any
  crafted claim value, selector edge case, or Unicode/case trick — this is
  the multi-tenant boundary the roadmap calls out as the safety-critical part
  and it needs adversarial test coverage, not happy-path tests.
- Selector compilation is a build/load-time step (config load), not deferred
  to per-request string matching.
- Depends on Phase 1 (needs verified claims) but not on Phase 3.

### Phase 3 — Session and token lifecycle for human callers

> **Status (2026-10-26): built as pass-through, not token exchange.** The server accepts the
> IdP's access token on every call (`docs/OAUTH.md`); it keeps no session store. The window
> after an IdP-side revoke is `min(token exp, iat + --oauth-max-token-lifetime-secs)` plus a
> 60 s skew allowance, a documented number, so set the ceiling. Introspection-based
> revocation is not built. A retried client cannot extend a session because there is none.
> Human callers who cannot do a browser flow keep using static tokens plus step-up.

MCP's existing transports (stdio, HTTP with bearer) were not built around a
browser-redirect OIDC flow. This phase decides and implements how a human's
proven identity turns into something usable across a session:

- Whether the server accepts a raw IdP-issued access token per call (thin,
  stateless, but a token this short-lived cross-cuts every MCP client's
  ability to hold and refresh it), or performs its own token exchange and
  issues a scoped session credential (fits the existing bearer-header
  transport unchanged, but adds session-store state and its own expiry bugs
  to get right).
- Expiry and revocation: a session must not outlive what the IdP would
  consider that user's authority (an offboarded user's existing session
  should not remain valid for its full nominal lifetime).
- Idempotent re-authentication: retried/reconnecting clients must not be
  able to extend a session past what the IdP granted.

**Acceptance criteria**

- An IdP-side revoke (or a group membership change) is reflected within a
  bounded, documented window — not "eventually," a number.
- No session outlives the shorter of the IdP token's own expiry and a
  server-configured ceiling.
- Depends on Phase 1; can proceed in parallel with Phase 2 once Phase 1
  lands, since role mapping and session mechanics touch different code paths.

### Phase 4 — Migration path for existing token-based approvers

> **Status (2026-10-26): built.** `tokens.json` loads unchanged with no OIDC configuration.
> Coexistence: a static `human` token bound to an `oidc_subject` plus a step-up assertion
> and an unbound token both approve, and the mechanism is recorded in three places: the
> evidence approval record's `metadata.approver_mechanism` (`token` or `oidc`, with the
> verified issuer and subject for `oidc`; always written), the `identity_mechanism` field of
> every audit line (`token`, `oauth`, `oidc-step-up`, or `none` on stdio), and the state-file
> approval record's `mechanism`, which is bound into the keyed v7 digest and so exists only
> under `--approval-digest-key-file`. The deprecation signal is
> `VerifiedApproverArgs::warn_unbound_human_tokens`; the operator turns on
> `--require-verified-approver` when ready, with no cutover date in code. The proposer side
> is closed too: `--require-verified-proposer` makes the owner's `owner_subject`
> IdP-verified rather than token-asserted (mecmcp#400).

- `tokens.json` keeps working unmodified for service automation — the
  roadmap is explicit that minted tokens stay for CI/agents/schedulers, and
  compatibility with existing deployed files is a repeated, hard constraint
  across this codebase already (`entry.rs`'s alias handling for `hash`/
  `routers`/`targets` is the precedent to match, not diverge from) — this
  phase must not reopen that compatibility problem.
- Decide and document the coexistence rule for a transition period: can a
  human token-holder and an OIDC-authenticated human both approve the same
  change set, and does the audit record distinguish "verified via IdP" from
  "asserted by file" so an auditor reading history after the cutover can
  tell which regime approved what.
- A deprecation signal (warning in logs, a flag in the token store) for
  human-actor-type tokens once OIDC is available for that tenant, without a
  hard cutover date baked into code — the customer, not the code, decides
  when to turn off the legacy path.

**Acceptance criteria**

- Existing `tokens.json` files load and authenticate exactly as before with
  zero OIDC configuration present — this feature must be strictly additive.
  (**Offline-first**: a customer who never configures an IdP sees no
  behavior change at all.)
- The audit record for an approval states which identity mechanism produced
  it, distinguishably, forever (not just during a transition window).
- Depends on Phases 1–3 being substantially complete; this is the rollout
  phase, not a parallel track.

## Sequencing and rough sizing

```
phase                                    depends on     rough size
────────────────────────────────────────────────────────────────────
1  discovery + token verification        —              M (1-1.5 wk)
2  role-to-tenant mapping                 1              M (1 wk)
3  session/token lifecycle                1              M (1 wk)
4  migration path                         1, 2, 3        S-M (3-5 days)
```

Phases 2 and 3 can run concurrently once Phase 1 lands. Total is consistent
with the report's original L (2-4 weeks) estimate for the bundled item; the
point of splitting it is that each phase above is independently reviewable,
independently testable, and independently shippable behind config that
defaults to off, rather than one L-sized PR that is unreviewable in one pass.

## Open questions for Kay (not resolved by this spike)

1. **Crate boundary** — new `mecmcp-oidc` crate vs. a feature-gated module in
   `mecmcp-auth`. Affects the dependency graph for servers that never want
   OIDC compiled in at all (fully offline deployments).
2. **Token-exchange vs. pass-through** (Phase 3's central decision) needs a
   design doc of its own before Phase 3 starts — it changes the transport
   contract for every MCP client, vendor server or not.
3. Which vendor server is the pilot? Recommend the one with the smallest
   existing `tokens.json` fleet (lowest migration blast radius if Phase 4's
   coexistence rule has a bug) — the operator-waiver spike's fleet survey
   method (`2026-08-14-operator-waiver-design.md`) is the right way to check
   before picking one.
4. Roadmap ROADMAP.md §1 currently overstates `Principal`'s current shape
   (see Problem section above) — recommend a one-line correction independent
   of this work, so the next reader doesn't inherit the same false premise.

## Recommendation

Do not schedule as one MEC item. Recommend Kay create four child issues
(one per phase above) under this issue, sized individually, with Phase 1
first and unblocked, Phases 2/3 next (parallelizable), Phase 4 last. This
issue (MEC-351) should track the epic; it should not itself carry an
implementation PR.
