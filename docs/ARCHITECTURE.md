# Architecture

How `mecmcp` is put together and how a vendor server sits on top of it.

`mecmcp` is a **library workspace, not a server.** It serves no MCP endpoint and
opens no socket. The one exception to "library" is `mecmcp-audit`, which ships
two operator binaries — `mecmcp-verify` and `mecmcp-audit-keygen` — and neither
listens on anything; both only read and write local files. Everything else here
is consumed by the per-vendor MCP servers, which are the things that actually
run.

The organising rule: *everything that is not NETCONF or a vendor's XML/REST API
lives here once.* Authentication, attribution, audit, transport hardening,
policy, inventory, change control. A vendor server is then only the part that is
genuinely vendor-specific — which is much smaller than it looks before the
extraction.

---

## 1. The crates

Fourteen crates, versioned together. The workspace version is the release unit;
a consumer pins one tag and gets a coherent set.

### Foundation

| Crate | What it owns |
|---|---|
| `mecmcp-secret` | Zeroizing outbound-credential type and a hardened loader that rejects symlinks, oversized values, and group/world-readable files. Unix-only, deliberately. |
| `mecmcp-auth` | Bearer tokens, digests, `ScopeSet`, `Grant`, `CallerCtx`. Free of vendor concepts — it knows names and opaque subjects, not what a subject *means*. |
| `mecmcp-audit` | `Attribution`, `Principal`, `AuditOutcome`, redaction, sinks. Also free of vendor concepts: it knows principals, not devices. |

### Boundary

| Crate | What it owns |
|---|---|
| `mecmcp-transport` | The whole protected `/mcp` endpoint: `build_streamable_http_router`, `serve_router`, `HostOriginPolicy`, bearer middleware, rate and concurrency limits, session caps, TLS, `ToolScopePreflight`. Also `test_client::McpClient` for integration tests. |
| `mecmcp-server` | The handler side: `authorize_call`, `authorize_tool`, `authorize_target`, `caller_from_extensions`, `filter_tools_for_scope`, and bounded result rendering (`tool_result`, `bounded_text`). |

### Domain

| Crate | What it owns |
|---|---|
| `mecmcp-inventory` | The `Inventory<D, P>` trait and a file-backed implementation that reads three on-disk schemas without forcing a migration. |
| `mecmcp-policy` | Generic glob rule engine for blocklist guardrails, generic over the action type so Junos and PAN-OS share it. Specificity-scored, with `Defaults` vs `Device` as the tiebreak. |
| `mecmcp-changeset` | Fingerprint-bound two-person change control: stage → digest → approve → apply, with indeterminate-outcome recovery and atomic persistence. |
| `mecmcp-device` | Cross-process device leases over `flock`, plus cancellation. |

### Outbound and process

| Crate | What it owns |
|---|---|
| `mecmcp-http` | Hardened outbound client: HTTPS-only, no redirects, no proxy autodiscovery, bounded concurrency, whole-request deadlines. |
| `mecmcp-scp` | SCP1 over SSH exec channels, for devices like Junos that disable SFTP. |
| `mecmcp-job` | Polling for async management-plane jobs: immediate first probe, capped backoff, cooperative cancellation, whole-operation deadline. |
| `mecmcp-openapi` | Bounded pagination and URL path expansion that rejects rather than repairs. |
| `mecmcp-runtime` | CLI parsing and provenance, validation, TLS bootstrap, signals, graceful shutdown, token subcommands. |

### Dependency shape

Throughout this section `──>` and `->` read **depends on**. (An earlier revision
of this diagram used the arrows the other way round, which is part of how the
errors below went unnoticed.)

Three crates form a spine:

```
mecmcp-audit ──> mecmcp-auth ──> mecmcp-secret
```

Seven crates depend on some subset of that spine, and on nothing else in the
workspace:

```
mecmcp-transport  -> audit, auth
mecmcp-server     -> audit, auth            a sibling of transport, not a layer on it
mecmcp-changeset  -> audit, secret
mecmcp-runtime    -> audit, auth, secret
mecmcp-http       -> secret
mecmcp-inventory  -> secret
mecmcp-scp        -> secret
```

Separately, touching none of the above:

```
mecmcp-job ──> mecmcp-device
mecmcp-openapi, mecmcp-policy  — no workspace dependencies at all
```

Fifteen edges, three levels deep. **`mecmcp-server` does not depend on
`mecmcp-transport`** — an earlier revision of this diagram drew that edge, and it
has never existed. The two are sibling consumers of the same two foundation
crates, which is why a consumer can take either without the other: rustjunosmcp
and rustpanosmcp both link transport and not server.

`mecmcp-secret` is the floor: **six crates depend on it directly**, and nine of
the fourteen have some path to it — the other three arrive through the spine.
There is no single ceiling:
nothing in the workspace depends on `transport`, `server`, `changeset` or
`runtime`, so those are linked by consumers rather than by each other. Four
crates depend on nothing else here at all — `secret`, `device`, `openapi` and
`policy`. Nothing in the tree knows a vendor's names, paths, headers, or status
codes.

---

## 2. The request lifecycle

This is the architecture. Everything else is support for it.

A `tools/call` arriving over streamable HTTP passes through, in this order:

```
TLS ─> IP rate limit ─> Host/Origin ─> auth ─> token rate ─> token concurrency
    ─> body limit ─> preflight ─> transport audit ─> target concurrency ─> handler
```

Two positions in that chain are easy to get backwards, and an earlier revision
of this file had both wrong. **The IP rate limit is outside Host/Origin**, not
inside it: `apply_ip_rate_limit` is attached *last* in
`build_streamable_http_router` so that it also covers `/metrics`, and in axum the
last layer applied is the first to run. **The transport audit precedes target
concurrency**, because `bearer_preflight_middleware` drops its `AuditScope`
before calling `next.run`, so it cannot carry the outcome of anything inside it.
That used to mean a request shed by target concurrency was recorded as a call
preflight *allowed* with `result=ok`, and nothing recorded the refusal —
[#370](https://github.com/mechubsec/mecmcp/issues/370). The boundary now
emits a second terminal event whenever the response is a 4xx or 5xx
(`refused_after_preflight`, `layer=post_dispatch`, plus the status), leaving the
preflight event and its `duration_ms` untouched.

The inner segment is not assembled by hand in each consumer. `apply_bearer_boundary`
in `crates/mecmcp-transport/src/auth.rs` installs it and **enforces the order**:

```text
auth → token_rate → token_concurrency → body_limit → preflight → target_concurrency → handler
```

Each position is load-bearing, and the rationale is recorded next to the function:

- **Auth is outermost** so an anonymous request cannot charge a token's budget.
- **Token rate and concurrency are non-buffering**, so they decide before the
  body is read.
- **The body limit precedes anything that buffers**, so preflight and target
  concurrency cannot be made to allocate without bound.
- **Preflight runs after token accounting**, so an out-of-scope request still
  consumes budget rather than being a free retry channel.
- **Target concurrency is innermost**, so an unauthorized request never acquires
  a per-device permit.

### Preflight

`ToolScopePreflight` (`crates/mecmcp-transport/src/preflight.rs`) parses the
JSON-RPC body, extracts the tool name and the configured target fields, and
denies with 403 before dispatch. It is generic over the argument shape, and
handles both `TargetValueShape::Scalar` and `TargetValueShape::NonEmptyArray`.
A consumer whose target is matched *directly* against the caller's scope
declares `TargetField`s and writes no preflight of its own: PAN-OS `device`,
SDC `tenant`, Proxmox `cluster`, UniFi `controller`.

**Two consumers do implement `ScopePreflight` themselves**, and an earlier
revision of this file wrongly named both as `TargetField` users. Junos nests its
device selector; Mist must canonicalise `org_id` into `org/<uuid>` before it can
be compared against a scope subject.

The deciding criterion is **what `TargetField` can express, not the shape of the
value**. Arrays are expressible (`NonEmptyArray`), and Mist's target is a plain
scalar string that still needs a custom preflight. Write one when the matching
needs nesting, normalisation, or any semantics beyond direct comparison —
not merely because the value is or is not a scalar.

### Audit by construction

Since 0.8.1 the bearer boundary emits a transport audit event for **every**
`tools/call` before dispatch. The point is the quantifier: a call is audited
because it crossed the transport, not because a handler author remembered to log
it.

The handler still emits its own, richer event — action, resolved device targets,
outcome — correlated by request id. The transport cannot know any of those, so
the two events are complementary rather than redundant.

One subtlety worth carrying forward: the tool name is read from an
attacker-controlled body, and it is parsed *before* preflight has decided whether
the caller may call anything at all. It is interned into a table capped at 256
entries of ≤128 bytes, restricted to `[A-Za-z0-9_-]`; anything else records as
`unregistered`. An earlier revision interned every parsed name for process
lifetime on the reasoning that tool names are "a finite, small set" — true of the
registry, false of a request field, and both a memory-exhaustion and an
unbounded-cardinality path.

### Handler-side authorization

The transport's decision is not the last word. A handler recovers its caller with
`caller_from_extensions` and re-checks via `authorize_call`.

Four rules in `crates/mecmcp-server/src/authorize.rs` are easy to get wrong and
are therefore encoded rather than documented elsewhere:

1. **A `None` caller is the stdio path and is authorized.** So a handler must
   pass the caller it actually recovered, never `None` on a lookup miss.
   `caller_from_extensions` reads two levels deep — the MCP layer carries
   `http::request::Parts` in its own extensions, and the bearer middleware put
   the caller in *those*. Reading only the outer map finds nothing, and under
   this rule that would authorize every call.
2. **Tool scope is checked before target scope.** A token with no right to
   `apply_change_set` is told exactly that, rather than being told which targets
   it may not touch. The narrower failure leaks less.
3. **A wildcard tool scope permits everything except the server's registered
   write tools.** `authorize_tool` takes that registry as a parameter because
   only the server knows it — and passing an empty slice silently turns every
   wildcard token into a writer.
4. **`whoami` is in every tool scope.** `ScopeSet::allows_tool` permits
   `WHOAMI_TOOL` for any scope, even an empty allowlist, so a token can always
   read its own name and expiry (mecmcp#580). It returns nothing else — never
   scopes, digests or other tokens. A server opts in by registering a `whoami`
   tool method that returns `mecmcp_server::whoami(caller)`.

`authorize_target` deliberately does **no** inventory lookup. It answers "is this
name inside the caller's scope", which is a question about the token. Whether the
name exists is a question about the inventory. Merging them would make an
out-of-scope target indistinguishable from an unknown one, which tells an
unauthorized caller which device names are real.

### Results are bounded, and a limit is a refusal

`tool_result` returns an MCP **error** when a successful value exceeds its
limits. It does not send a shortened value: a caller handed a silently truncated
result cannot tell it from a complete one. `bounded_text` is the other half, for
places that genuinely want a prefix — a log line, a preview — and it says so in
its return type.

---

## 3. The consumers

**Six** servers sit on this foundation, not the four this section listed for a
long time. Per-crate consumption and the full matrix live in
[`CRATE-MAP.md`](CRATE-MAP.md); this table is the shape and maturity.

| | junos | panos | sdc | mist | proxmox | unifi |
|---|---|---|---|---|---|---|
| Target | Junos / SRX **devices** | **PAN-OS** | Security Director **Cloud** | **Mist** cloud | **Proxmox VE** | **UniFi** Network |
| Outbound transport | NETCONF/SSH + SCP1 | HTTPS XML-API | HTTPS REST | HTTPS REST | HTTPS REST | HTTPS REST |
| Credential to upstream | SSH key or password | API key | `x-api-key` / `x-oauth2-token` | `Authorization: Token …` | API token | local admin |
| Maturity | **production** | **production** | lab tenant | lab tenant | **production** | **production** |
| Scope axes | device glob × tool | device × tool | tenant × tool | org/site × operation | cluster × tool | controller × tool |
| mecmcp crates | 10 | 7 | 6 | 10 | 11 | 10 |

Versions move every release wave, so they are deliberately not pinned here —
`CRATE-MAP.md` carries the current set, and each repo's own README is
authoritative at its version.

**rustjunosmcp** is the runtime-hardening reference — session pooling, device
leases, rate limits, audit redaction. Repo layout is flat: `rust-junosmcp`
(binary, MCP handler), `-core` (device manager, tools), `-auth`, `-srx-core`
(SRX workflows, behind the default `srx` feature).

**rustpanosmcp** is the change-control reference — the plan → digest → approve →
apply state machine that became `mecmcp-changeset`.

**rustsdcmcp** fronts the SASE management plane rather than a device, so one
action can touch a whole fleet; every mutation is therefore change-set gated. It
is lab-only pending replacement of its remaining compatibility shims with
upstream APIs shipped in one coherent release.

**rustmistmcp** carries an audited catalog of 1,059 Mist operations derived from
the upstream OpenAPI spec, classified by capability (ordinary read, privileged
read, create, update, delete, execute). It was a scaffold for a long time and is
described that way in older notes; it is not one now — it cut a production tag
and has served live read-only traffic. Its packaging is still pre-release
though, and it does carry a change-set write path
(`plan_mist_change` / `approve_mist_change_set` / `apply_mist_change_set`), so
it is neither a scaffold nor production-ready nor read-only.

### Why the pins differ

A consumer upgrades on its own schedule, so the fleet runs a spread of `mecmcp`
versions at any time. That is expected. What is *not* optional is reading the
upgrade notes for the versions being skipped — the 0.7.0 → 0.7.2 sequence in
particular shipped a graceful-drain fix whose first two attempts were both
inert, and both passed CI.

---

## 4. Conventions a consumer is expected to follow

- **Vendor logic only.** If a thing could be written the same way for another
  vendor, it belongs in `mecmcp`, not in the server.
- **Configure, don't reimplement.** Preflight, transport assembly, token
  subcommands and shutdown are parameterised precisely so a consumer passes
  arguments instead of forking behaviour.
- **Reads are direct; writes go through the change set.** Stage, digest, approve
  as a *distinct* principal, apply — refusing if the target drifted since it was
  planned.
- **Mutating tools are named explicitly in a scope.** Never reachable by
  wildcard.
- **Secrets are files with enforced modes**, loaded through `mecmcp-secret`, and
  never round-tripped through configuration JSON.

Packaging and installed layout are specified separately in
[`PACKAGING.md`](PACKAGING.md). Operating the servers is in
[`ONBOARDING.md`](ONBOARDING.md). Where the family is going is in
[`../ROADMAP.md`](../ROADMAP.md).
