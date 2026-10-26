# Threat model: mecmcp foundation

One page, for a SOC engineer deciding whether to run a mecmcp-based MCP server.
It covers the shared crates in this repository. Vendor-specific threats live in
each server's own threat model (see [Per-server delta](#per-server-delta)).
Verified against `main` at `029d1f5` on 2026-09-27.

**Status key:** ✅ mitigated in code · 🟡 partial, or opt-in only · ❌ not mitigated.
Every 🟡 or ❌ row names its open issue, or is accepted in [Residual risk](#residual-risk-accepted).

## Assets

- **Device credentials:** SSH keys, API keys and passwords held by the server.
- **MCP bearer tokens** and the device and tool scopes they grant.
- **Device configuration:** running and candidate. The server can change it.
- **Device output:** configs, routes, sessions and logs. These are topology and secrets.
- **Audit trail:** who did what to which device. Hash-chained and signed.
- **The build:** crates, lockfile, CI, container images.

## Trust boundaries

```text
LLM / MCP client ──(1)── mecmcp server ──(2)── network device / vendor API
                              │ ▲
                         (3)  │ │ (4)
                              ▼ │
                SSDF / journald / file      operator: tokens, inventory, flags
                              │
                         (5)  │
                              ▼
      IdP (JWKS: OAuth bearer verification, step-up assertions)
```

1. **Client → server.** Everything the model sends is untrusted, *even with a valid token*.
   That includes arguments, device names and config payloads. A prompt-injected model is
   a malicious client that holds that token's scopes.
2. **Server → device, and device → server.** Device output is untrusted input. It flows
   back to the model, where it can carry prompt-injection text.
3. **Server → audit sinks.** This is the only egress besides the managed devices, and it
   is off unless configured.
4. **Operator → server.** The operator is trusted. They set flags, tokens and inventory
   at startup. No MCP call can change the security posture.
5. **Server → IdP.** Opt-in ([#400](https://github.com/mechubsec/mecmcp/issues/400)): the core crates
   (`mecmcp-oidc`, `mecmcp-auth`, `mecmcp-changeset`, `mecmcp-transport`) can verify a
   `Mecmcp-Approver-Assertion` step-up header, fetching JWKS from the IdP to do it. A
   server opts in by flattening `VerifiedApproverArgs` into its own CLI, building an
   `ApproverAssertionVerifier`, and constructing its `ApproverIdentity` via
   `ApproverIdentity::from_attribution`; `rust-junosmcp` does (MEC-995). Where
   wired, no approver JWT, no raw claims and no IdP response ever flow back to the model
   or into a tool result — verification happens once at the bearer boundary, and only
   issuer+subject survive it. JWKS unreachable fails closed: approvals are refused, but
   reads and proposals on existing bearer tokens are unaffected.
6. **Client → server, OAuth bearer (opt-in, [#498](https://github.com/mechubsec/mecmcp/issues/498)).**
   With `mecmcp-transport`'s `oauth-resource` feature and `--oauth-issuer`, a JWT access token
   from the configured issuer is accepted as the `/mcp` credential after the static token
   store misses. The server fetches JWKS over boundary 5's channel. The token is verified
   once at the bearer boundary, mapped through the operator's scope map, and never
   forwarded or retained; only issuer, subject and client id survive it. See
   [`OAUTH.md`](OAUTH.md).

## Threats and mitigations

| # | Threat | Control | Status |
|---|---|---|---|
| T1 | **Prompt-injected tool call.** Via the user, a document or device output, the model is steered into a destructive call. | Per-token tool and device allowlists: [`mecmcp-auth/src/scope.rs`](../crates/mecmcp-auth/src/scope.rs). Two-person change sets, where the approver must differ from the owner and must echo the plan digest: [`mecmcp-changeset/src/changeset.rs`](../crates/mecmcp-changeset/src/changeset.rs). Plane-owned-device refusal and a command policy that is fail-closed by default; it runs **fail-open** in blocklist mode, which is selected explicitly or inferred for a legacy deny-rule config with no mode key (see T11): [`mecmcp-policy`](../crates/mecmcp-policy/src/lib.rs). **Nothing detects the injection itself.** | 🟡 |
| T2 | **Direct commit bypasses two-person control.** Each server also exposes single-call commit tools, gated only by token scope. | A second-approver rule and an `--allow-direct-commit` opt-in are in progress (internal MEC-12, no public issue yet). | ❌ |
| T3 | **Stolen or guessed bearer token.** | 256-bit tokens, a digest-only store and constant-time compare ([`mecmcp-auth/src/token.rs`](../crates/mecmcp-auth/src/token.rs)). Per-token rate, concurrency and session limits. Plain HTTP off-loopback, or no auth off-loopback, is refused at startup ([`mecmcp-runtime/src/cli_validate.rs`](../crates/mecmcp-runtime/src/cli_validate.rs)). | ✅ |
| T4 | **DNS rebinding.** A browser reaches a loopback server. | A Host/Origin allowlist applied to every route, `/metrics` included ([`mecmcp-transport/src/server.rs`](../crates/mecmcp-transport/src/server.rs)). | ✅ |
| T5 | **Metrics data escape.** | `/metrics` is off by default. When enabled it is **unauthenticated** and on the same listener as `/mcp`. Labels are the tool name and result, not devices ([`mecmcp-transport/src/metrics.rs`](../crates/mecmcp-transport/src/metrics.rs)). Making it loopback-only or token-gated, and adding `/healthz` and `/readyz`: [#377](https://github.com/mechubsec/mecmcp/issues/377). | 🟡 |
| T6 | **Audit data escape.** Device names, hosts and commands land in logs and SIEMs. | Per-field `drop`/`hmac` redaction, but **off by default** ([`mecmcp-audit/src/redact.rs`](../crates/mecmcp-audit/src/redact.rs)). The SSDF sink is off unless an endpoint is given. It **accepts `http://`**, so evidence and credentials can cross the network in clear ([`sinks/ssdf.rs`](../crates/mecmcp-audit/src/sinks/ssdf.rs)). Container images run unkeyed audit: [#376](https://github.com/mechubsec/mecmcp/issues/376). A shared entrypoint template and conformance check (`packaging/docker/audit-entrypoint.sh.tmpl`, R7 in `packaging/conformance`) now exist so an image can require-or-generate a keyed audit the way the LXC package does, but the five affected vendor repos have not adopted it yet — R7 warns rather than fails until each does. Whether a non-SSDF sink should exist: [#378](https://github.com/mechubsec/mecmcp/issues/378). | 🟡 |
| T7 | **Audit tampering by the host operator.** | Hash chain plus signing ([`mecmcp-audit/src/signing.rs`](../crates/mecmcp-audit/src/signing.rs)), checked by the `mecmcp-verify` binary. Off-host copies go to SSDF. | 🟡 |
| T8 | **Tool output leaks secrets to the model provider.** Configs carry hashes, PSKs and SNMP communities. | A shared `mecmcp-redact` crate (on by default, operator-only off switch) is built but not merged (internal MEC-11). Wiring it into the servers is internal MEC-14. **Today, tool output reaches the model unredacted.** | ❌ |
| T9 | **Secrets in files, logs or `Debug` output.** | `OutboundSecret` and `SecretBytes` never print their value. Files are read with `O_NOFOLLOW` plus owner/mode/size checks ([`mecmcp-secret/src/lib.rs`](../crates/mecmcp-secret/src/lib.rs)). | ✅ |
| T10 | **Supply chain.** A malicious crate or image. | Gitleaks, `cargo audit`, and `cargo deny` (advisories, licences, bans, sources) run in CI ([`security.yml`](../.github/workflows/security.yml)). **`Cargo.lock` is committed**, so the audited graph is the one actually shipped, not whatever the registry currently offers. Trivy filesystem scan runs on push, PR, and a weekly schedule. Per-crate CycloneDX SBOMs are generated and validated in CI and attached to each GitHub release ([`release-sbom.yml`](../.github/workflows/release-sbom.yml)); see [#379](https://github.com/mechubsec/mecmcp/issues/379). | ✅ |
| T11 | **Free-form command slips past the blocklist.** A model with command scope runs an operational command the operator did not list. | Library: fail-closed token-prefix allowlist mode (`CommandMode::Allowlist`, the default) exists in `mecmcp-policy` ([#390](https://github.com/mechubsec/mecmcp/pull/390)). Wired into rustjunosmcp (including PFE commands: [#465](https://github.com/mechubsec/rustjunosmcp/pull/465), [#473](https://github.com/mechubsec/rustjunosmcp/pull/473)) and rustpanosmcp ([#207](https://github.com/mechubsec/rustpanosmcp/pull/207)); both run fail-closed by default. Fail-open blocklist mode (`CommandMode::Blocklist`) remains for backwards compatibility. It is selected explicitly, **or inferred when an existing config has deny rules and no `mode` key** (a startup warning is logged). In that mode, any command no deny pattern matches runs, including abbreviations and re-spellings. | 🟡 |
| T12 | **MITM on the device channel (NETCONF/SSH, SCP).** An on-path host impersonates a device. It reads configs, returns forged output, and captures passwords (key auth does not hand over the key). | This repository has no NETCONF client. Each server uses `rustnetconf`. The shared SCP client supports strict `known_hosts`, trust-on-first-use (changed keys rejected) and pinned fingerprints, but it also offers `AcceptAll` and has no default, so each server chooses ([`mecmcp-scp/src/config.rs`](../crates/mecmcp-scp/src/config.rs)). In rustjunosmcp, `--ssh-accept-new-host-keys` currently sets NETCONF to `AcceptAll`, which is no verification at all: [rustjunosmcp#415](https://github.com/mechubsec/rustjunosmcp/issues/415). | 🟡 |
| T13 | **Token minted for one server replayed against another.** A token a user obtained for the junos server is presented to the panos server. | Exact audience binding: `aud` must equal the receiving server's canonical resource string (RFC 8707), with no substring or prefix match; the audience list form passes only if one element matches exactly. Pinned by `a_junos_audience_token_is_refused_by_a_panos_resource` and `audience_must_equal_the_resource_not_resemble_it` ([`oauth_resource.rs`](../crates/mecmcp-transport/tests/oauth_resource.rs)). Operator duty: one resource URI per server, and an IdP configured to issue single-audience tokens (a multi-audience token that lists this server is accepted). OAuth callers hold no vendor grant and cannot bind a verified approver. | ✅ where enabled |
| T14 | **Unauthenticated load on the verification path, or an IdP outage.** Junk or flooded JWT-shaped bearers drive signature checks and JWKS fetches. | Shape prefilter before any async work, header-first decode, cache-driven JWKS fetch (an unknown `kid` never forces a refetch), at most 32 concurrent verifications with a 3 s timeout and a refusal (503 `busy`/`timeout`/`keys_unavailable`) instead of a queue. Static tokens never reach the verifier. **No eager JWKS warm-up and no revocation list**: a stolen token lives until `exp` (or `iat` plus `--oauth-max-token-lifetime-secs`, if set), and a flood of JWT-shaped junk can briefly exhaust the permits for valid OAuth callers. | 🟡 |

## Residual risk (accepted)

- **Prompt injection is unsolved (T1).** Controls limit *what* a hijacked model can do
  (scopes, two-person approval). They cannot stop it trying. Give read-only
  tokens to any client that reads untrusted text.
- **"Two-person" means two tokens, not two humans, unless strict mode is on
  ([#400](https://github.com/mechubsec/mecmcp/issues/400)).** By default, one person
  holding two tokens can still approve their own change, and lab mode waives approval
  outright (the audit record shows `approval_waiver: "lab-mode"`, but the change is not
  blocked). The core crates now support a strict mode (`ChangesetCoordinator`'s
  `with_require_verified_approver`, surfaced to a CLI as `--require-verified-approver`)
  where the approve call must additionally carry a fresh IdP-issued assertion bound to a
  distinct IdP subject from the proposer's — see trust boundary (5) above — and refuses a
  lab-mode waiver, an operator waiver, and applying any pre-existing (non-`oidc`) approval
  outright rather than letting any of them bypass the check. `VerifiedApprover` itself is
  sealed (`#[non_exhaustive]`, no public constructor): the only way to produce one is
  `bind_approver` succeeding at the bearer boundary, so a server cannot build one from a
  tool argument. **Opt-in per server**:
  `rust-junosmcp` wires it (MEC-995); a server that does not flatten
  `VerifiedApproverArgs` and build its `ChangesetCoordinator` with it, or a deployment
  that leaves `--require-verified-approver` off, still has the two-tokens gap this paragraph opened
  with. The assertion only covers *who approved*; it does not scope *what*
  they may approve beyond the token's existing tool/device scopes. OAuth callers' device scopes can be
  narrowed by inventory attribute (`site`/`vendor`/`tag`, `docs/OAUTH.md` section 4), but
  selector-scoped *approver* roles (cluster/node/pool/controller) are not yet built
  (tracked separately, see #400).
- **The `jti` replay guard is durable only with `--approver-replay-store`.** With the
  flag set, each first-use `jti` is recorded (as a SHA-256, never the raw value) in an
  append log (0600, periodically compacted, not an audit record) and fsynced before the approval is granted; a failed write refuses
  the approval (`replay_store_unavailable`), and a malformed file refuses startup. Without
  it the guard is in-memory only: a restart inside `--approver-max-age-secs` (300s default)
  forgets used assertions, so a captured-but-not-yet-expired assertion could be replayed
  exactly once across a restart. Set the flag whenever `--require-verified-approver` is.
  The store is a local file: it does not protect a deployment whose state directory is
  rolled back or restored from a snapshot, and it is per-host (not shared across replicas).
- **`owner_subject` is token-asserted unless `--require-verified-proposer` is on.** The
  owner's bound `oidc_subject` (set via `token add --oidc-issuer/--oidc-subject`) is
  whatever the operator who ran that command typed in, not something the IdP vouches for
  at propose time. Strict approver mode refuses to approve a change set whose
  `owner_subject` went missing after proposal (MEC-994 W4), but it cannot detect one that
  was wrong from the start. With `--require-verified-proposer` (mecmcp#400) a proposal must
  carry a fresh `Mecmcp-Proposer-Assertion` whose subject equals the token's binding (or
  come from an OAuth caller, whose subject the IdP already vouched for); the change set
  records `owner_verified`, and approval refuses one that lacks it, so the two-person rule
  compares two IdP-verified subjects when `--require-verified-approver` is on as well.
  Residual limits: the proposer header is a separate header from the approver one (a
  proposer assertion never becomes approval evidence) but both draw on one `jti` replay
  set and the IdP cannot tell the two purposes apart, so an assertion minted for either
  role is good for exactly one use in either; `owner_verified`, like `owner_subject`, is in
  no digest until an approval signs the subject in, so someone who can edit the state file
  can set it; and the flag does nothing until the server passes it to
  `ChangesetCoordinator::with_require_verified_proposer`.
- **Scope-map correctness is the operator's job (T13).** A mapping that grants `["*"]` to a
  broad IdP group grants it to every member (write tools stay excluded from the wildcard).
  Revocation is the IdP's `exp`, capped by `--oauth-max-token-lifetime-secs` when set (docs/OAUTH.md section 6); there is no server-side revocation list. Write tools
  named in an entry are callable by every token that matches it, unless that token also
  matches an entry whose `tools` list contains `"*"`: the union is then the wildcard, which
  excludes write tools. Devices are intersected across matched entries (tools unioned), so
  one entry's tools never reach another entry's devices. A device wildcard (`"devices": ["*"]`) does not do this. `actor_type: "human"` is
  refused, so OAuth callers are never token-asserted human approvers. The audience must be
  the resource's own, not an OIDC login client's id, or that client's ID tokens become
  bearers (a body `typ: "ID"` is refused, other ID tokens are not).
- **The host operator is trusted.** Root on the host can read credentials and rewrite
  local audit. Only the off-host SSDF copy survives that.
- **Hosted model providers see tool output.** Even with T8 fixed, free text such as
  descriptions, banners and hostnames still reveals topology. For zero egress, run a
  local model.

## Out of scope

- Compromise of the managed device itself.
- The MCP client's own security.
- An embedded authorization server (login, consent, token issuance, dynamic client
  registration), token exchange, and retiring `actor_type: human` tokens outright. OAuth
  access tokens as the MCP bearer credential are **in scope** from
  [#498](https://github.com/mechubsec/mecmcp/issues/498) (boundary 6); step-up OIDC
  ([#400](https://github.com/mechubsec/mecmcp/issues/400)) still only verifies identity at
  approval time.
- Physical access.

## Per-server delta

Each server inherits T1–T14. What differs:

- **rustjunosmcp:** NETCONF/SSH to devices. Host-key trust, commit-confirmed defaults and the free-form command blocklist: see [its threat model](https://github.com/mechubsec/rustjunosmcp/blob/main/docs/THREAT-MODEL.md).
- **rustpanosmcp:** HTTPS with `X-PAN-KEY`. Has its own [`THREAT_MODEL.md`](https://github.com/mechubsec/rustpanosmcp/blob/main/THREAT_MODEL.md).
- **rustsdcmcp, rustmistmcp:** call the operator's vendor-cloud tenant. That egress is the managed system, not telemetry, but it does leave the site.
- **rustunifimcp, rustproxmoxmcp:** HTTPS to an on-site controller or hypervisor API. TLS trust is configured per server.
