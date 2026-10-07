<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">mecmcp</h1>

<p align="center"><strong>Vendor-neutral Rust foundation for enterprise network-security MCP servers</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

---

`mecmcp` is the shared crate family underneath mechub's per-vendor MCP servers.
Authentication, attribution, audit, transport hardening, policy, inventory,
change control — everything that is *not* NETCONF or XML-API — lives here once
and is consumed by every vendor server.

Every mechub MCP server is built on it:

| Server | Vendor | Device transport | Latest release | Status |
|---|---|---|---|---|
| [`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp) | Juniper Junos / SRX | NETCONF over SSH (`rustnetconf`) | [v0.27.3](https://github.com/mechubsec/rustjunosmcp/releases/tag/v0.27.3) | ![status](https://img.shields.io/badge/status-beta-yellow) |
| [`rustpanosmcp`](https://github.com/mechubsec/rustpanosmcp) | Palo Alto PAN-OS | HTTPS XML-API | [v0.14.0](https://github.com/mechubsec/rustpanosmcp/releases/tag/v0.14.0) | ![status](https://img.shields.io/badge/status-beta-yellow) |
| [`rustproxmoxmcp`](https://github.com/mechubsec/rustproxmoxmcp) | Proxmox VE | HTTPS REST API | [v0.10.0](https://github.com/mechubsec/rustproxmoxmcp/releases/tag/v0.10.0) | ![status](https://img.shields.io/badge/status-beta-yellow) |
| [`rustsdcmcp`](https://github.com/mechubsec/rustsdcmcp) | Juniper Security Director Cloud | HTTPS REST API | [v0.1.0](https://github.com/mechubsec/rustsdcmcp/releases/tag/v0.1.0) | ![status](https://img.shields.io/badge/status-alpha-orange) |
| [`rustmistmcp`](https://github.com/mechubsec/rustmistmcp) | HPE Juniper Mist | HTTPS REST API | [v0.3.2](https://github.com/mechubsec/rustmistmcp/releases/tag/v0.3.2) | ![status](https://img.shields.io/badge/status-alpha-orange) |
| [`rustunifimcp`](https://github.com/mechubsec/rustunifimcp) | Ubiquiti UniFi Network | HTTPS REST API | [v0.6.0](https://github.com/mechubsec/rustunifimcp/releases/tag/v0.6.0) | ![status](https://img.shields.io/badge/status-alpha-orange) |
| [`rustfortimcp`](https://github.com/mechubsec/rustfortimcp) | Fortinet FortiGate | HTTPS REST API | unreleased | ![status](https://img.shields.io/badge/status-planned-lightgrey) |
| [`rustopnsmcp`](https://github.com/mechubsec/rustopnsmcp) | OPNsense | HTTPS REST API | unreleased | ![status](https://img.shields.io/badge/status-planned-lightgrey) |

Each server keeps only its vendor transport and tools; everything above the
device boundary comes from `mecmcp`, so a hardening fix lands once and reaches
every server on its next release. Status reflects honest maturity: no server is
tagged stable yet, and all run in the maintainer's lab, not production.


## Status

**0.10.0 — operator waivers are a kind, bounded, and expire (#275).**
Every waiver was a lab-mode waiver by construction — the digest bound the literal
string `"lab-mode-waived"`, so *a bounded, ticketed exception granted under a
control that is still on* and *someone switching the control off entirely*
were recorded identically. `reason` was free text that nothing verified and
nothing bound.

The fix: `WaiverKind` (`LabMode` / `OperatorFile` / `OperatorTool`,
`#[non_exhaustive]`); `expires_at_unix` and `ticket`, both digest-bound;
`compute_waiver_digest_v3`, which hashes a serialized tuple with a
domain-separation marker instead of a `|`-joined string, so no field value can
shift a boundary; schema v3; a new `waive_approval_operator`; and expiry
enforced at apply, at both the pre-guard and post-guard gates.

**Breaking:** `WaiverRecord` struct-literal construction now needs `kind` (plus
the two new `Option` fields `expires_at_unix` and `ticket`), and `validate_state`
takes a version argument. Consumers that only call `waive_approval` need no change.
Checked across the consumer repos: none constructs a `WaiverRecord`, references
`WaiverKind`, or calls `validate_state`, so upgrading is a dependency bump with
no code changes. Bump **both** strings on each entry — a `version = "0.9.x"`
requirement does not accept `0.10.0`, so changing only `tag = "v0.9.1"` leaves
the dependency unresolvable.

**No data migration:** a live survey of the Junos and PAN-OS production guests,
The SDC guest and both rehearsal rigs found 28
change sets and **zero** waiver records, so changing the waiver digest invalidates
nothing that exists. The neighbouring approval digest was deliberately left alone
for that reason and is tracked as #283. Any state file containing a waiver is now
written as version 3; files with no waivers still select v1/v2 exactly as before.

**0.9.1 — test consumers can serve a plan on an ephemeral loopback port (#280).**
0.9.0 sealed the `Router` inside `ServePlan`, so `serve_router` became the only
way to serve one. Four consumer migrations worked around that by cloning the
listener token and driving `serve_router` in a background task, then racing their
client against the bind to discover the port from the OS. The harness extracts
that pattern: `mecmcp_transport::test_harness::serve_on_loopback` takes a
`ServePlan` and returns the bound `SocketAddr`, so the client can dial it
immediately. Loopback-only, as the control on inadmissible listeners is the
signature `serve_router` moved to the right of.

**0.9.0 also warns when a revoke has not reached the server (#266).**
`token revoke` removed the entry, printed `revoked '<name>'` and exited 0 —
while a running server kept its store in memory and went on accepting the
credential until signalled. Measured live: the token still returned 200
immediately after the revoke, and 401 only after SIGHUP. The caching stays,
deliberately — a failed reload must not take authentication offline — but
`revoke` and `rotate` now say plainly that the credential is not dead yet and
name `--server-pid`. Rotate needs it more than revoke: without the reload the
server still accepts the *old* secret. The exit code stays 0, because the
revoke did succeed.

**0.9.0 — listener validation is unskippable (#273).** `mecmcp_runtime::cli_validate`
refused two configurations that matter — unauthenticated off-loopback and
off-loopback with no Origin allowlist — but had no call site anywhere in the repo,
so a consumer could serve unauthenticated on the LAN and nothing failed. This is
the third instance of a class fixed in 0.8.1 (audit unskippable) and 0.8.3
(`client_name` correct but unwired).

The fix: authentication became a constructor choice (`authenticated` /
`unauthenticated` + `NoAuthAcknowledgement`), `build_streamable_http_router`
returns a `ServePlan` rather than a bare router, and `serve_router` refuses an
inadmissible listener before it binds. Four refusals exist —
`UnauthenticatedOffLoopback`, `InsecureBindNotAcknowledged`, `AllowedHostRequired`,
`AllowedOriginRequired` — each with the condition stated in the error message.
Loopback is exempt from all of them. **`--allow-no-auth` does not permit an
off-loopback bind**: `serve_router` refuses that regardless.

`cli_validate` remains a courtesy pre-check. It fails a bad CLI before anything
is constructed, and its messages name the flags rather than the transport
concepts. But it is no longer the control — skipping it costs a startup refusal
instead of an open port. The generic `validate_with_origin_policy` is gone,
folded into `validate`, which now always requires an Origin allowlist
off-loopback.

**Breaking:** consumers must migrate their `main.rs`. See Upgrading to 0.9.0 below.

### Upgrading to 0.9.0

**mecmcp-transport 0.9.0:**

- **Authentication as a constructor choice.** The old builder flow is gone:

  Before:
  ```rust
  let config = HttpTransportConfig::new(identity, limits, host_origin, shutdown)
      .with_bearer(boundary);
  ```

  After (authenticated):
  ```rust
  let config = HttpTransportConfig::authenticated(
      identity,
      limits,
      host_origin,
      shutdown,
      boundary,
  );
  ```

  After (unauthenticated):
  ```rust
  let config = HttpTransportConfig::unauthenticated(
      identity,
      limits,
      host_origin,
      shutdown,
      NoAuthAcknowledgement::operator_allowed_no_auth(),
  );
  ```

- **`build_streamable_http_router` returns `ServePlan`, not `(Router, HttpShutdown)`.**
  The plan carries the router, the shutdown, and the policy `serve_router` must
  check. Extract what you need from the plan **before** passing it to
  `serve_router`, which takes it by value:

  Before:
  ```rust
  let (router, shutdown) = build_streamable_http_router(factory, config)?;
  serve_router(router, addr, tls, shutdown, timeout).await?;
  ```

  After:
  ```rust
  let plan = build_streamable_http_router(factory, config)?;
  // Clone the listener token before moving the plan (if wiring SIGTERM):
  let listener_token = plan.shutdown().listener().clone();
  serve_router(plan, addr, tls, timeout).await?;
  ```

- **Off-loopback listeners now require `--allowed-origin`.** This is a behavior
  change: an empty Origin allowlist is currently valid and disables Origin
  checking by design. Fleet survey (2026-08-13) found exactly one affected
  deployment. **The Junos production guest (`rust-junosmcp`) binds `0.0.0.0` with `--allowed-host`
  and no `--allowed-origin`, and will be refused at startup on 0.9.0.** Add
  `--allowed-origin` to its drop-in override before installing the 0.9.0 binary.
  It is tagged `protected`: snapshot it first. The PAN-OS guests
  (`rust-panosmcp`) already pass an Origin allowlist and are unaffected; the
  Mist, SDC and rehearsal guests bind `127.0.0.1` and are exempt.

**0.8.3 — 0.8.2's client name never actually reached anyone. Upgrade past 0.8.2.**
The propagation was correct and unreachable. The middleware reads the captured
`clientInfo` out of `BoundaryAccounting.session_tracker`;
`BoundaryAccounting::new` leaves that `None`, and `build_streamable_http_router`
never called `with_session_tracker`. Every consumer goes through that assembly,
so every one of them kept emitting `client_name=""` exactly as before 0.8.2
shipped.

Found by bumping a consumer to 0.8.2 and reading a real audit event, not by any
test here. Nothing in this repo could see it: the middleware unit tests build a
`BoundaryAccounting` directly, and the end-to-end test attaches a tracker by
hand — both prove the middleware works *when wired*, neither observes the
assembly that does the wiring. The missing harness is tracked in #251.

Also fixes the workspace lint: `cargo clippy --all-targets` had been failing on
111 `unwrap_used` errors in test code, so every PR was red regardless of its own
diff.

Additive over 0.8.2. If you are on 0.8.2 for `client_name`, you need this.

**0.8.2 — the MCP client name reaches the audit record (#53).**
`AgentIdentity.client_name` existed but nothing populated it, so every audit
event emitted `"client_name":""`. MCP's `initialize` already carries
`clientInfo`, which needs no client cooperation beyond the standard handshake.
It is now captured onto the session and attached to the transport audit event
for every `tools/call` on that session.

The name is client-asserted and stays that way: it is never added to
`token_verified_fields`, so a caller's claim cannot be read back as
server-verified. Like the tool name, it arrives from a request body, so it is
interned into a bounded table — 64 entries — rather than leaked per distinct
value. An unknown session leaves the field empty; nothing is invented, and no
placeholder is substituted.

This identifies the *client program*, not the model and not the user.
`claude-code` tells you the request came from Claude Code and says nothing about
which model drove it. `model_id` and `session_id` remain unwired.

Additive over 0.8.1. Consumers get the field populated with no code change once
they move their pin; nothing is required of them.

**0.8.1 — audit by construction (#32), with the tool name bounded.**
The bearer boundary now emits a transport audit event for every `tools/call`
before dispatch, so a tool is audited because it went through the transport, not
because someone remembered. Handlers still emit their own enriched event —
action, resolved device targets, outcome — correlated by request id; the
transport cannot know any of those. (**The correlation described here did not
work until #269.** `Attribution::from_caller` minted a fresh request id on every
call, so through 0.8.8 the two events for one request carried different ids and
could not be joined.)

The tool name is read from the request body, which is attacker-controlled and is
parsed *before* the preflight has decided whether the caller may call anything.
It is interned into a table capped at 256 entries of at most 128 bytes each,
restricted to `[A-Za-z0-9_-]`; anything else records as `unregistered`. An
earlier revision leaked every parsed name for the life of the process on the
reasoning that tool names are "a finite, small set" — true of the registry,
false of a request field, and both a memory-exhaustion and an
unbounded-cardinality path.

**0.8.0 — extraction milestone 4: generic scope preflight + shared test client.**
Four consumers (Junos, PAN-OS, SDC, Mist) had near-identical preflights differing
only in argument field names (Junos: `router`/`routers`, PAN-OS: `device`, SDC:
`tenant`, Mist: org/site). `ToolScopePreflight` is the generic implementation,
configured with `TargetField`s. Also added: `test_client::McpClient`, a shared
SSE-aware HTTP client for integration tests, replacing product-local helpers.

### Upgrading to 0.8.0

**mecmcp-transport 0.8.0:**
- **New exports:** `MalformedArgumentsPolicy`, `MalformedTargetPolicy`,
  `TargetValueShape`, `TargetField`, `ToolScopePreflight` (#109–113, #142–147).
  Configure with `TargetField::scalar("device")` or custom shapes.
- **New `test_client` module:** `McpClient` for integration tests (#184). Handles
  initialize handshake, SSE parsing, and session ID tracking.
- All workspace crates bumped to `0.8.0`. Update path dependencies.

**Breaking:** None. All additions are additive. Existing preflight implementations
continue to work.

**0.7.3 — axum-server 0.8, dropping the unmaintained `rustls-pemfile`.**
0.7.2 put `axum-server` into every consumer's tree, which brought
`rustls-pemfile` with it and tripped RUSTSEC-2025-0134 (unmaintained) in two
consumer pipelines. 0.8 drops that dependency outright, so the fix belongs here
rather than as an ignore entry repeated in each consumer. Its `from_tcp` and
`from_tcp_rustls` are now fallible; a failure there is reported as
`HttpServeError::Bind`.

**0.7.2 — the drain can now actually deliver a response.** 0.7.1 made SIGTERM
reach `serve_router`, but rmcp was still handed the *same* token as the
listener, so it ended every session the instant shutdown began — and an MCP
response travels back over its session's SSE stream. An in-flight call at
SIGTERM received 28 bytes of SSE preamble and nothing else, indistinguishable
from being dropped outright. rmcp now gets its own token, cancelled when the
drain deadline expires rather than when it starts.

**Breaking:** `build_streamable_http_router` returns `(Router, HttpShutdown)`
and `serve_router` takes that `HttpShutdown` — the two tokens must stay paired,
so they are one type rather than a bare `CancellationToken`. Note the
consequence: while any SSE stream is open, shutdown takes the full
`shutdown_timeout`. Keep it well under systemd's `TimeoutStopSec`.

**0.7.1 — the 0.7.0 drain never fired. Upgrade past 0.7.0.** `ShutdownSignal`'s
`Future` impl rebuilt `CancellationToken::cancelled()` on every poll and dropped
it at the end of the poll, deregistering the waker it had just installed. Nothing
ever woke the task, so `subscribe().await` never completed and SIGTERM never
reached `serve_router`. Caught on a lab box, not in CI: the four existing unit
tests all wrapped the signal in `tokio::time::timeout`, whose own timer re-polled
the task at the deadline — by which point the token was already cancelled, so
they passed against a future that could not complete. The new test parks a task
on the signal with the token as its only wake source.

**0.7.0 — extraction milestone 3: HTTP transport assembly.** A consumer no
longer hand-assembles its router: `HostOriginPolicy`, `HttpTransportConfig`,
`build_streamable_http_router` and `serve_router` compose the whole protected
`/mcp` endpoint, and **`serve_router` finally takes a shutdown signal** so
`systemctl restart` drains in-flight calls instead of dropping them.
`rustsdcmcp` can delete `compat/http.rs`. Milestone 4 (preflight) remains.

### Upgrading to 0.7.0

- `streamable_http_server_config` merged the body-cap and host/origin concerns;
  the replacement is exported as **`build_rmcp_server_config`**.
- **`build_streamable_http_router` returns `(Router, CancellationToken)`.** Pass
  that token to `serve_router` — the pairing is what keeps rmcp's SSE sessions
  and the listener draining on the same signal.
- `GracefulShutdown::new` returns `Result`, and now handles SIGTERM as well as
  SIGINT. The signal is latched, so one arriving before a subscriber attaches is
  still observed.
- `HttpServeError::Serve` carries the address that failed.

`HostOriginPolicy` has only an `Enforced` variant: there is deliberately no way
to disable the Host allowlist, which is the DNS-rebinding guard
(RUSTSEC-2026-0189). Note that **Host and Origin treat a portless allowlist entry
differently, on purpose** — a portless `Host` entry matches any port, because
`--allowed-host 192.0.2.10` must keep working on `:30031`, while a portless
`Origin` entry matches only a portless browser Origin, because wildcarding there
would widen the policy.

**0.6.1 — twelve crates; `mecmcp-scp` added.** A native SCP1 file-transfer
client for devices that disable SFTP-over-SSH (Junos among them), so a server
can move files without spawning `scp` — which is what lets a consumer run on a
distroless image with no shell. Unix-only, gated at the module export. Additive:
nothing from 0.6.0 changed.

**0.6.0 — eleven crates; extraction milestone 2 landed.** The cloud-foundations
programme (#90) shipped `mecmcp-secret`, `mecmcp-http`, `mecmcp-job` and
`mecmcp-openapi`; `mecmcp-changeset` gained multi-target change sets;
`mecmcp-server` (milestone 1) and now the bearer boundary (milestone 2) replace
what consumers were reimplementing locally. Milestones 3 (HTTP transport
assembly) and 4 (preflight) remain.

Not published to crates.io. Consumers depend on this repository directly and pin
an exact version.

### Upgrading to 0.6.0

> **Superseded in part by 0.7.0's transport assembly.** This section documents
> the consumer applying the bearer boundary and the per-IP rate limit by hand,
> which was correct at 0.6.0. Since 0.7.0, `build_streamable_http_router` does
> all three itself — it applies the boundary, applies the IP rate limit, and
> builds the `BoundaryAccounting`. **On 0.7.0 or later, do not apply them
> yourself: you get both layers twice, which silently halves the per-IP budget
> and stacks the boundary.**
>
> The pattern below is the 0.6.0 pattern, kept for readers upgrading through
> this release. **It is not a complete recipe for hand-assembling a router on
> 0.7.0+**, and it is not an alternative to `build_streamable_http_router`.
> Beyond the double-apply, it omits two things the builder installs:
>
> - **Host and Origin validation outside `/mcp`.** `build_rmcp_server_config`
>   gives rmcp the Host allowlist, but that only guards the service nested at
>   `/mcp`. The builder additionally layers this crate's own Host/Origin
>   middleware over the *entire* router, which is what stops a DNS-rebinding
>   attacker page — whose request lands on the victim's own loopback
>   interface and so passes the `/metrics` loopback gate — from reading
>   `/metrics` with a foreign Host header. That middleware is private and
>   installed only by
>   `build_streamable_http_router`. A hand assembly therefore keeps the Host
>   guard on `/mcp` and loses it everywhere else — and loses Origin checking
>   entirely, since `build_rmcp_server_config` deliberately empties rmcp's
>   `allowed_origins` on the assumption that this crate will check it. (An
>   empty `allowed_origins` disables the Origin check by design, builder or
>   not; the loss bites a consumer who configured one.)
> - **The session tracker.** From 0.8.3 the builder wires it via
>   `authenticated_accounting`, which calls `with_session_tracker`.
>   `BoundaryAccounting::new` alone leaves `session_tracker` as `None`, and
>   passing a tracker to `ConcurrencyState` does not populate the field the
>   audit preflight reads — so a hand assembly on 0.8.3+ emits an empty
>   `client_name`. This is the 0.8.3 defect: 0.8.2 shipped
>   `with_session_tracker` without the builder calling it. Releases before
>   0.8.2 had neither the field nor client-name propagation at all.
>
> Use `build_streamable_http_router` on 0.7.0+.

**Extraction milestone 2: the bearer boundary.** All 22 issues (#96, #97,
#103–#108, #118, #129–#141) land in this tag, because partial availability
would mean a consumer maintaining both paths. `rustsdcmcp` can now delete
`compat/bearer.rs` rather than adapt it.

**New API.** `mecmcp-auth` gains `BearerSyntax`, `BearerHeaderError` and
`parse_bearer_header`. `mecmcp-transport` gains `BearerAuthenticator`,
`BearerBoundary`, `BearerResponseProfile`, `apply_bearer_boundary`,
`AuthenticatedToken` and `CallerScopes`.

**Breaking, in the order a consumer will hit them:**

1. **`ScopePreflight::check` takes `CallerScopes<'_>`, not `&CallerCtx`.** The
   scope-only view is what lets one `dyn`-safe implementation serve
   `CallerCtx<G>` for any grant type. Field access is identical; change the
   parameter type. **All three servers implement this trait** —
   `rust-panosmcp/src/http_transport.rs`, `rust-junosmcp/src/http_transport.rs`,
   and `rustsdcmcp`'s compat copy.
2. **`apply_bearer_boundary` takes a `BoundaryAccounting`,** not a closure. The
   crate now owns the layer order rather than accepting an opaque
   `FnOnce(Router) -> Router` it cannot inspect.
3. **`concurrency_middleware` is deprecated,** split into
   `token_concurrency_middleware` (non-buffering, runs before the body limit)
   and `target_concurrency_middleware` (buffering, runs after authorization).
   Consumers passing `BoundaryAccounting` call neither directly.
4. **`apply_rate_limit` is deprecated,** split into `apply_ip_rate_limit`
   (outside the boundary, before authentication) and `apply_token_rate_limit`
   (inside it, after authentication).
5. **A 403's `WWW-Authenticate` no longer carries the preflight reason.** It is
   a fixed `error="insufficient_scope"`, with the reason in the JSON body — a
   reason containing a quote corrupted the challenge, and a control character
   turned an intended 403 into a 500.
6. **`BearerResponseProfile` gains `try_detailed`/`try_compact`** returning
   `Result`. Use those for a configuration value; the infallible constructors
   take `&'static str`.

The boundary builds everything from `authenticate` inwards, so a consumer cannot
get that part wrong. **At 0.6.x, per-IP rate limiting was the one layer the
consumer still applied itself**, because it must run *before* authentication — a
request with a missing, malformed or unknown token has no identity to charge, and
metering it is what stops an authentication flood.

**Pre-0.7.0 only.** At 0.7.0 and later `build_streamable_http_router` applies
both layers; running this by hand as well double-applies them. This snippet is
not the 0.7.0+ hand-assembly recipe either — see the note at the head of this
section for what it leaves out.

```rust
let limits = Arc::new(limits_config);
let accounting = BoundaryAccounting::new(
    ConcurrencyState::new(&limits, target_keys, Some(session_tracker)),
    Arc::clone(&limits),
);

let app = apply_bearer_boundary(app, boundary, accounting);
let app = apply_ip_rate_limit(app, &limits); // outermost: runs first
```

Use `BoundaryAccounting::none()` for a deployment with no per-token accounting.

Axum runs the last-applied layer first, so `apply_ip_rate_limit` must be applied
*after* `apply_bearer_boundary` to sit outside it. On a hand-assembled router,
omitting it leaves unauthenticated requests unmetered.

The resulting order — unchanged at 0.7.0+, where the router builder produces it
rather than the consumer:

```
IP rate limit → authenticate → token rate limit → token concurrency
  → body limit → preflight → target concurrency → handler
```

**Security fixes worth naming**, all found by review rather than by tests:

- Per-token concurrency and session caps were bypassed for grant-bearing
  callers — `concurrency_middleware` looked up `CallerCtx<NoGrant>` while the
  boundary inserted `CallerCtx<G>`, and extension lookup is type-specific.
- A preflight rejection cost the caller nothing, and an unauthenticated request
  charged no per-IP bucket, so both could be flooded for free.
- A token scoped to target A could acquire target B's concurrency permit before
  the scope check rejected it, starving authorized B traffic.
- `body_limit` was defeated whenever per-target concurrency buffered the request
  ahead of the cap.

### Upgrading to 0.5.0

**Breaking for consumers only because of the rmcp major: `rmcp 2` → `rmcp 3.1.1`.**
Nothing in this workspace's own API changed shape. A consumer must bump its own
`rmcp` dependency in the same commit — cargo will not unify a 2.x and a 3.x rmcp,
so a partial upgrade is a build failure rather than a subtle one.

**What the rmcp major actually is.** rmcp 3.x implements the 2026-07-28 MCP
revision, but it is not the forced cutover the spec summaries suggest. The
`initialize` handshake and `Mcp-Session-Id` are *not* removed: rmcp runs both
protocols side by side and `StreamableHttpServerConfig::legacy_session_mode`
defaults to `true`, which is the pre-2026-07-28 flow. Statelessness is opt-in,
per request, keyed on the version the client declares.

Consumer-visible changes:

| Change | Action |
|---|---|
| `StreamableHttpServerConfig::stateful_mode` renamed to `legacy_session_mode` | Rename the field; same default (`true`), same behaviour |
| `SessionManager` gained `event_store()` | Defaulted, so nothing breaks — but see below if you wrap a manager |
| `Mcp-Method` / `Mcp-Name` header validation | Now enforced **by the SDK** for clients declaring `>= 2026-07-28`. No middleware needed |
| **`StreamableHttpServerConfig::max_request_body_bytes` is new, and defaults to 4 MiB** | **Stop calling `StreamableHttpServerConfig::default()`. Call `mecmcp_transport::streamable_http_server_config(&limits)` instead.** |

Everything else is source-compatible. This migration changed neither the MSRV
(1.88 at the time; 1.89 today) nor the edition (2024) — the workspace already
required both.

**The body limit is the one that bites silently.** rmcp 3 enforces its own 4 MiB
request-body cap *inside* the service, after this crate's `apply_body_limit`
layer has already accepted the request. `LimitsConfig::max_request_body_bytes`
defaults to 10 MiB here, so on a plain `default()` every request between 4 and
10 MiB starts failing with a 413 from a limit the operator never set and cannot
see in their own config. `streamable_http_server_config` derives it from
`LimitsConfig` and maps `0` (unlimited) to `usize::MAX`.

> **Superseded by 0.7.0.** The `&limits`-only `streamable_http_server_config` is
> `#[deprecated]` since 0.7.0, replaced by
> `build_rmcp_server_config(&policy, &limits, shutdown)`, which took the Host
> allowlist and the shutdown token alongside the body cap. On 0.7.0 or later
> `build_streamable_http_router` calls it for you, so a consumer using the
> builder needs no call at all. Note that it populates rmcp's `allowed_hosts`
> but deliberately leaves `allowed_origins` empty — Origin is checked by this
> crate's own middleware, which only the builder installs, and only when an
> Origin allowlist is configured.

**Session capacity is now protocol-aware.** rmcp computes
`use_session = legacy_session_mode && is_legacy_request(..)`, so a client
declaring `2026-07-28` is routed statelessly *even though `legacy_session_mode`
is `true`* — and a stateless POST carries no `Mcp-Session-Id` because there is no
session. The old classifier (`POST` without that header) would therefore have
charged every ordinary `tools/call` from a modern client against
`--max-sessions` and `--max-sessions-per-token`, handing out 503s after
`max_sessions` calls. `is_session_creating` now also requires the absence of an
`MCP-Protocol-Version` at or above `2026-07-28`. No consumer action needed.

**One security note on the new header validation.** rmcp only enforces
`Mcp-Method`/`Mcp-Name` when the request declares protocol `>= 2026-07-28`; a
client declaring an older version simply omits them. So the headers are an
optimisation, not a control. **The scope preflight remains the authorization
boundary** — do not move an authorization decision up to a header a client can
decline to send by claiming to be old.

### Fixed in 0.5.0: `LimitedSessionManager` answered for the manager it wraps

`LimitedSessionManager` overrode 8 of the 10 `SessionManager` methods and
inherited the defaults for `restore_session` (`NotSupported`) and, as of rmcp 3,
`event_store` (`None`). Because it is a *wrapper*, inheriting those defaults meant
reporting "restore unsupported, no event store" **on behalf of the inner
manager**, discarding whatever that manager actually provided.

Latent until now — both current consumers wrap `LocalSessionManager`, which
supplies neither — and it would have stayed silent when it did bite: the symptom
is SSE resumability quietly not working, not a compile error or a log line.

`event_store` is now forwarded. `restore_session` is now an **explicit refusal**
rather than an inherited one — same answer, stated on purpose.

That asymmetry is deliberate. Forwarding `event_store` touches no limit and
undoes a real rmcp 3 regression. Forwarding `restore_session` looked like the
same two-line change and is not: every limit this wrapper enforces is applied on
the *create* path, and a restore arrives by a different route.

- **Per-token cap.** The concurrency middleware classifies a request as
  session-creating with `POST && !contains("mcp-session-id")`. A restore
  necessarily carries that header, so no token slot is reserved. A restored
  session would raise only the global count — letting one token restore its old
  sessions *and* create a full `max_sessions_per_token` on top.
- **Idle and lifetime timeouts.** The reaper closes the inner in-memory session
  but cannot delete an entry from an rmcp `session_store` it does not own. A
  reaped id could be restored with fresh timestamps, repeatedly, which does not
  weaken the timeouts so much as remove them.
- **Overload response.** A cap rejection on the restore path would surface as a
  generic 500 rather than the stable 503 + `Retry-After`.

Refusing costs nothing today — `LocalSessionManager`, which both consumers wrap,
returns `NotSupported` anyway. Doing it properly needs reaper tombstoning, a
token reservation on the restore path, generation-safe registration and
cancellation-safe cleanup; that is tracked separately. Until then an honest
refusal beats a cap that quietly does not hold.

### Upgrading to 0.4.0

**Additive: one new crate, `mecmcp-server`, and nothing else changed.** The minor
bump is because a new crate is new API, not because anything broke — a consumer
that does not want it can stay pinned at `v0.3.9` indefinitely.

`mecmcp-server` is #199's milestone 1: the vendor-neutral helpers every MCP tool
handler in this family needs, which three servers were each carrying their own
copy of.

| Group | Items |
|---|---|
| Rendering a result | `tool_result`, `tool_error`, `ResultFormat`, `ResultLimits`, `BoundedText`, `bounded_text` |
| Authorizing a call | `authorize_call`, `authorize_tool`, `authorize_target`, `AuthorizationError`, `caller_from_extensions`, `filter_tools_for_scope`, `audit_scope` |

Two behaviours to know before adopting, both documented at the call site:

- **`tool_result` refuses an oversized success rather than truncating it.** A
  caller handed a shortened value cannot tell it from a complete one.
  `bounded_text` is for the places that genuinely want a prefix.
- **A `None` caller is authorized for everything**, because that is the stdio
  path, which has no bearer token. On an authenticated path a handler must pass
  the caller it recovered — passing `None` on a lookup miss authorizes the call.

This lets `rustsdcmcp` delete `compat/server.rs` and `rustsdcmcp-core/src/compat.rs`,
332 of its 1,162 compat lines. The remaining groups — bearer boundary, HTTP
transport assembly, preflight — are tracked in #199.

### Upgrading to 0.3.9

A correctness release: every finding from the codex review of 0.3.8's unreviewed
window, nine P1 and twelve P2. Four changes need a consumer's attention.

| Change | What a consumer must do |
|---|---|
| `TokenStoreFile::set_scopes` gained a `grant: Option<G>` parameter | pass `None` to leave the stored grant alone — a `NoGrant` consumer always wants `None`. This is a plain arity change, so the compiler will find every call site |
| `TargetError` gained `MissingPrimary` | nothing unless you match the enum exhaustively; a target set must now contain the record's own `device` |
| `try_parse_from`, `parse_with_provenance` and `ParsedCli` are generic over the consumer's parser | nothing if you use `parse_for`; `ParsedCli` defaults to `Cli`. **Servers with flags of their own should now flatten `Cli` into their own struct and pass that** — the previous API could not parse a vendor flag at all |
| `ChangeSetRecord::validate_target_set` and `validate_preview` are enforced at insert and load | a preview's `digest` must be built with the new `preview_digest`; a hand-written value is refused |

Behaviour changes worth knowing about, none of which need code:

- A **multi-target change set now survives a restart.** It was written with the
  five-tuple digest and re-verified with the four-tuple, so every one was
  rejected on the next load. Single-target digests are unchanged, byte for byte.
- `max_targets_per_set` and `max_preview_bytes` are enforced. They were read by
  nothing before, so a deployment relying on the old non-enforcement would now
  see refusals.
- `set-scopes` asks for `--yes` in two more cases: any grant replacement, and a
  tool scope moving from `*` to an allowlist. Both are escalations — the tool
  wildcard deliberately withholds the server's write tools, so naming one grants
  what the wildcard withheld.
- An expiry sweep no longer retires a change set whose apply is in flight, and it
  is persisted even when the insert that triggered it is refused.
- `init_tracing` no longer drops the rotation handle when the consumer already
  installed a `log` logger.

On-disk state is unchanged from 0.3.8 in both directions.

### Upgrading to 0.3.8

This release is **breaking at the source level**, and needs a deliberate upgrade
rather than a version-string change:

| Change | What a consumer must do |
|---|---|
| `OperationLimits` gained public fields | struct-literal construction needs `..OperationLimits::default()` |
| `ChangeSetRecord` gained required `targets` and `preview` fields | it has no `Default`, so `..Default::default()` does not compile — add `targets: Vec::new(), preview: None` to every literal |
| `mecmcp-secret` is now Unix-only | nothing on Linux; the crate refuses to compile elsewhere by design |
| `mecmcp-auth` and `mecmcp-inventory` read their files through the shared hardened loader | `tokens.json` and `devices.json` **must** be mode 0600, a regular file, and owned by the service user — inventory had no such check before |

On-disk state is compatible in both directions **only while no change set holds
targets or a preview**. Either one gates the file to version 2, and 0.3.7's
`ChangeSetRecord` is `deny_unknown_fields`, so it rejects the whole file — the
absence of multi-target sets alone is not enough, because `preview` does it too.
A 0.3.8 deployment using neither still writes version-1 files that the previous
binary reads.

**Verify the deployed files before rolling out.** A `tokens.json` or
`devices.json` that has drifted to 0644 loaded fine under 0.3.7 and will be
refused at startup by 0.3.8.

## Documents

| Document | What it is |
|---|---|
| [`ANALYSIS.md`](ANALYSIS.md) | Side-by-side teardown of both repos — what is duplicated, what is asymmetric, what stays vendor-specific |
| [`PLAN.md`](PLAN.md) | Program-level extraction plan: crate map, phase sequencing, decisions, exit criteria (historical — the plan is delivered) |
| [`ROADMAP.md`](ROADMAP.md) | What "enterprise grade" means at 150 engineers and 4,000 multi-vendor firewalls |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How `mecmcp` is put together and how a vendor server sits on top of it — the crate tiers and the request lifecycle |
| [`docs/CRATE-MAP.md`](docs/CRATE-MAP.md) | **Start here for the whole picture.** What each of the fourteen crates does, the dependency graph, and which crates each vendor server actually consumes — with diagrams |
| [`docs/PACKAGING.md`](docs/PACKAGING.md) | How a mechub MCP server is delivered and installed — container base, LXC, README requirements |
| [`docs/AUDIT-FORWARDING-STANDARD.md`](docs/AUDIT-FORWARDING-STANDARD.md) | **Standard.** How every server ships its audit trail off the host: JSON emission rules (normative) and the hash-chained ClickHouse sink (#292) |
| [`docs/superpowers/plans/`](docs/superpowers/plans/) | Executable per-phase implementation plans |

## The crate family

| Crate | Responsibility | Extracted from |
|---|---|---|
| `mecmcp-auth` | Token mint/digest/verify, `tokens.json` load + hot-reload, scopes, grants, caller context | both (union) |
| `mecmcp-audit` | Attribution, audit events, redaction, pluggable sinks | rustjunosmcp |
| `mecmcp-transport` | Streamable-HTTP: host/Origin checks, bearer middleware, rate limits, concurrency + session caps, metrics | rustjunosmcp `limits/` + rustpanosmcp scope preflight |
| `mecmcp-runtime` | CLI skeleton, TLS bootstrap, signals, graceful shutdown | both (union) |
| `mecmcp-policy` | Compiled allow/deny rule engine over command and config subjects | rustjunosmcp `policy.rs` |
| `mecmcp-inventory` | Device registry as a trait — file today, database and NetBox later | both (generalized) |
| `mecmcp-device` | Connection lease/pool, per-device concurrency, cancellation, timeouts | rustjunosmcp |
| `mecmcp-changeset` | Plan → digest → approve → apply → verify, two-principal enforcement, indeterminate recovery | rustpanosmcp `mutation.rs` |
| `mecmcp-secret` | Outbound credential type (zeroizing, unprintable) and hardened env/file loader | new — see #90 |
| `mecmcp-job` | Cancellable job polling: immediate first probe, capped backoff, whole-operation deadline | new — see #90 |
| `mecmcp-http` | Outbound HTTP client: HTTPS-only, no redirects, no proxy, bounded concurrency, whole-request deadline, sensitive headers | new — see #90 |
| `mecmcp-openapi` | Whole-segment path expansion and bounded pagination — rejects, never clamps | new — see #90 |
| `mecmcp-intent` | Vendor-neutral policy/object model with per-vendor rendering | new — see ROADMAP |

### Remote listeners fail closed

A Streamable HTTP listener bound off-loopback must supply `--allowed-host`, and
an allowlist of blank strings does not count. An empty Host allowlist is not
"accept whatever the operator forgot to configure" — it is a DNS-rebinding and
Host-confusion surface.

`--allowed-origin` is required only by consumers whose transport actually
applies browser-Origin policy, via `validate_with_origin_policy`. Requiring it
everywhere refused a deployed server whose transport applies only `allowed_host`
— and any dummy value would have satisfied it while enabling nothing. That is
the failure `docs/PACKAGING.md` names: a flag that is present but ignored is
worse than one that is absent, because the operator cannot tell.

Loopback binds are exempt. A listener on `127.0.0.1` or `::1` is already bounded
by the host, and requiring the flags there would break every stdio and
local-HTTP deployment for nothing.

Vendor servers keep their protocol adapters, XML parsers, and vendor workflows.
For `mecmcp-http` specifically, that means endpoint catalogs, header names, payload
schemas, terminal job states, and retry policy stay in the product repository —
the shared crate owns only the transport posture.

### The audit trail leaves the host

An audit record that only exists on the machine that produced it is not an audit
trail. Every server emits JSON to a file and forwards it to the security event
store.

Transport is a **direct, hash-chained write into `ssdf.audit`**, per SSDF's
merged evidence contract — not syslog. Every other link in this chain is
tamper-evident by construction: plan digests bind approvals, approvals name a
distinct principal, `token_verified_fields` separates vouched-for provenance from
asserted. An unchained final hop would discard that guarantee at the point an
auditor relies on it.

Emission rules are normative today; the sink is tracked in
[#292](https://github.com/mechubsec/mecmcp/issues/292). The standard —
including why the cheaper syslog path was rejected — is in
[`docs/AUDIT-FORWARDING-STANDARD.md`](docs/AUDIT-FORWARDING-STANDARD.md).

## License

Licensed under [MIT](LICENSE).
