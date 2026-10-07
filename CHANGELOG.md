# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **How to read the entries below 0.21.0.** This file was added on 2026-08-26,
> after 0.20.0 shipped. Those entries are reconstructed from commit *subjects*,
> so they are accurate about *what changed* and terse about *why it mattered* —
> unlike the hand-written notes in the sibling servers' changelogs. Where an
> entry is not enough, the commit range in the matching GitHub release is the
> source.
>
> Two exceptions, both deliberate. The **Security** entries were written by hand
> after reading the commit bodies, because classifying by subject alone missed
> them and classifying by body text mislabelled two features as security fixes.
> And the bold prefix is the commit's *scope*, which is usually a crate but is
> sometimes an area — `deps`, `plan`, `packaging`, `spec`.
>
> Release commits — the `chore(release): X.Y.Z` and `bump workspace to X.Y.Z`
> subjects that carry only a number — are omitted. Two early version bumps
> are kept, at 0.3.8, because their subjects record *why* the version moved:
> `Workspace 0.1.6 for the ConnectInfo fix` marks the release consumers had
> to pin past a broken rate limiter, and `Bump intra-workspace dependency
> pins to 0.2.0` repaired dependency resolution.
>
> Entries from 0.21.0 onward should be written by hand at release time.

## [Unreleased]

### Fixed

- **mecmcp-auth: token add, rotate, rescope, and revoke no longer re-validate
  every token's device/tool scopes against the current build's known names**
  (MEC-2225), only the entry actually being minted or changed. A stale
  reference left on one token by unrelated inventory or tool-surface drift
  could previously block credential-rotation operations on every other token
  in the same file.

## [0.26.1] - 2026-10-03

### Security

- **mecmcp-redact: Junos XML pass now derives its extra secret-element set
  from the same closed key vocabulary the text pass uses** (MEC-1459,
  mecmcp#486), instead of a separately hand-maintained one-entry list, so
  the two redaction passes cannot drift apart on which Junos-specific
  element names are secret-bearing. Hardens Junos XML redaction coverage
  to match the text pass; consumers should upgrade.

### Fixed

- **mecmcp-redact: strengthened the key-exemption marker-collision
  regression test** (MEC-1244, mecmcp#485). The previous test input shape
  would not have caught the earlier guard/unguard-based implementation's
  bug, so it was not actually pinning the fix it was meant to protect.
- **docs/THREAT-MODEL: corrected stale T1/T11 rows** (mecmcp#488) that
  described blocklist-mode fail-open behavior as explicit opt-in only;
  rustjunosmcp and rustpanosmcp also infer blocklist mode for pre-existing
  configs with deny rules and no mode key.

## [0.26.0] - 2026-10-02

### Security

- **mecmcp-redact: hardened text redaction against a reachable panic on
  certain input** (MEC-770). `redact_text` (and the XML/JSON entry points,
  which share the same core) could panic instead of returning on some
  device-sourced tool output, which could abort the handling server
  process. Present in v0.24.0 and v0.24.1. Fixed with a regression test
  covering the text, XML, and JSON entry points; consumers should upgrade.

### Added

- **mecmcp-policy: new opt-in `xml_path` module for hierarchy-aware,
  fail-closed policy evaluation on parsed XML** (mecmcp#419). Servers must
  call it to benefit; the existing rule evaluation is unchanged in this
  release. Adoption in each server is a follow-up.

- **mecmcp-redact: `Profile` extension hooks for vendor-specific
  wholesale-redact and key-exemption rules** (MEC-1244, part of MEC-1231).
  Some vendor servers need two kinds of policy this crate's generic scan
  doesn't cover on its own: withholding a field's value wholesale rather
  than key/value scanning it, for a vendor-rendered body a best-effort scan
  isn't guaranteed to cover, and exempting field names that collide with
  the denylist by substring but are not secrets in that vendor's schema.
  Both are now generic capabilities any server can declare: a `Profile`
  carries `wholesale_redact_keys` and `key_exemptions` lists, and
  `redact_json_value_with_profile` applies them around the existing generic
  scan without narrowing it. Migrating a server's local implementation onto
  this is tracked separately, pending design review.

- **mecmcp-redact: `mecmcp-redact` CLI binary and a shared tool-output
  redaction coverage helper** (MEC-1231). A new `cli` feature exposes a
  `mecmcp-redact` binary that runs the same `redact_text`/`redact_json_str`/
  `redact_xml_str` engine every server already links, over stdin/stdout, for
  non-Rust consumers that cannot depend on the crate directly (`--format
  text|json|xml`; exits non-zero rather than passing through unparsed input,
  matching the library's fail-closed contract). A new `test-util` feature
  exposes `testing::tools_leaking_secrets`, generalizing the
  hand-rolled-per-server "does any tool's rendered output contain a planted
  fixture secret" assertion (the same way `mecmcp-audit`'s `test-util`
  generalized audit-coverage checking) so each server's own coverage test can
  call one shared function instead of re-deriving it.

- **mecmcp-server: `OutputRedaction::AlreadyRedacted`, a quiet skip for
  output a caller redacted itself** (MEC-1168). `SkipForInternalRead` was
  being reused by a handler whose result *did* come from a vendor device but
  had already been redacted before reaching `tool_result` — typically to
  protect a field like a pagination `continuation_token` that
  `OutputRedaction::Apply`'s unconditional `redact_json_value` would
  otherwise strip (MEC-440 B1). That reuse made `tool_result` log a `WARN`
  `tool_output_redaction_skipped` audit event naming the wrong function on
  every such call, even though the value genuinely was redacted — alert
  fatigue and an inaccurate audit trail, not a data leak (Low severity,
  found in review of rustsdcmcp#203 / MEC-1160). `AlreadyRedacted` skips
  `tool_result`'s own redaction pass exactly as `SkipForInternalRead` does,
  but emits no audit event, since there is nothing for an operator to be
  warned about instead at `WARN`. It does carry `tool` and `redacted_by`
  fields and logs its own `DEBUG`-level `tool_output_redacted_by_caller`
  event naming both, so an operator can still enumerate every call site that
  bypassed central redaction for vendor-device data, just without the
  per-call `WARN` noise (addressed in review, MEC-1181: a silent bypass with
  no audit trail at all was the wrong tradeoff for data that came from a
  device). Existing call sites are unaffected; adopting it in place of
  `SkipForInternalRead` is a separate, per-caller change.

- **mecmcp-redact: a PAN-OS `Profile`, and fixtures proving representative
  PAN-OS secret shapes are redacted.** Adds PAN-OS fixtures alongside
  MEC-711's Mist fixtures, and a PAN-OS `Profile` whose `key_exemptions` and
  opt-in BGP route-community exemption let a handful of non-secret
  operational and routing-policy fields survive for PAN-OS callers
  specifically, without loosening the default denylist for every other
  vendor server. Hardens redaction coverage in both the JSON and XML paths.

- **mecmcp-redact: a Junos redaction profile for support-bundle
  artefacts** (MEC-1245). Ports `rustjunosmcp`'s support-bundle redaction
  coverage into a `junos` module: XML redaction extended with a
  Junos-specific element rule on the shared quick-xml walk, a
  set-statement-aware line-oriented redactor for non-XML support-bundle
  text, and a dispatcher that selects the XML vs. text path by the
  artefact's shape, running the text pass as a floor under both and
  failing closed when XML-shaped input cannot be parsed. Extends Junos
  field coverage in the shared, vendor-agnostic denylist.
  `rustjunosmcp` adopting this as a thin wrapper is a follow-up PR in
  that repo.

## [0.25.0] - 2026-09-30

### Changed

- **docs: close out the filesystem-layout standard across all six vendor
  servers** (MEC-988, mecmcp#356, follow-on to #28 and #6).
  `docs/FILESYSTEM-LAYOUT.md` was missing `rustmistmcp` entirely and still
  carried `rustsdcmcp` as an open "verify and document" TODO. A 2026-09-07
  rebuild of all twelve MCP test rigs hit the exact `tokens.json`
  config-vs-state divergence this document exists to prevent, twice
  (`rustproxmoxmcp` restarted against a path the file wasn't at;
  `rustmistmcp`'s token store had moved out from under a restored drop-in).
  Verified against the code in all six repos rather than assumed:
  `rustjunosmcp`, `rustsdcmcp`, `rustproxmoxmcp`, and `rustmistmcp` resolve
  their configured token path against their own canonical `/var/lib/<svc>`
  location with a byte-exact comparison, fall back to the legacy `/etc`
  path only when that exact canonical path was configured, and fail
  startup outright for any other missing path — no silent fallback for a
  typo or a deliberately different store. `rustpanosmcp` has no such
  resolver: it loads whatever path is configured and only warns (never
  reads) if an un-migrated legacy store exists elsewhere. `rustunifimcp`
  shipped `/var/lib`-only from its first release and never had an `/etc`
  token store to migrate away from. No mutable credential or state file
  remains under `/etc/<svc>` on any of the six. `rustproxmoxmcp` and
  `rustunifimcp` also use an abbreviated directory/service-user base
  (`proxmoxmcp`, `unifimcp`) rather than the full binary name — a documented
  naming exception, not a compliance gap. Two residual follow-ups, not
  fixed here: `rustunifimcp` has no dedicated regression test pinning its
  already-loud failure on a missing token file, and `rustpanosmcp` could
  adopt the shared `resolve_tokens_with` resolver the other four share.

### Added

- **mecmcp-secret: shared naming derivation and single-pass credential-file
  validation** (MEC-987). Two additions that give the six mechub MCP servers
  a common source of truth instead of six independent decisions:
  - `naming::ServerNaming::derive` computes `/etc/<short_name>`,
    `/var/lib/<short_name>`, and the service-user string from one short name,
    with `naming::known` fixing the short name for each of the six servers
    today (`jmcp`, `panosmcp`, `sdcmcp`, `proxmoxmcp`, `mistmcp`,
    `unifimcp`) and documenting the rule a seventh server follows.
  - `validate::validate_credential_files` checks every credential-adjacent
    file a server cares about in one pass and returns every offender
    together, instead of the existing single-file loaders' fail-on-first
    behaviour. The required mode per file is data
    (`validate::CredentialFileRole::required_mode`) the loader owns, not a
    constant duplicated in each repo's setup docs -- `Secret` requires
    `0600`, `ConfigNoSecret` (files that are operator-authored and hold no
    secret material, like `rustsdcmcp`'s `sdc.json`) requires `0640`.
  Consuming servers are unaffected until they opt in: nothing existing
  changed, resolve_token_path's `/etc` fallback still governs the
  tokens.json migration path per server.

- **mecmcp-audit: optional OpenTelemetry trace export, and a generic
  HTTPS/JSON forward sink for closed evidence segments** (MEC-459). Two
  independent, off-by-default additions:
  - `AuditConfig::otel` (`--otel-endpoint`/`--otel-service-name` at the CLI
    layer) exports spans over OTLP/HTTP when set -- traces only, not
    metrics: this workspace records metrics through the `metrics` crate, not
    the OpenTelemetry metrics API, so an OTel meter provider would export on
    a timer with nothing ever recorded to it. Building the exporter needs
    `mecmcp-audit`'s new `otel` Cargo feature (~90 extra crates, so it is not
    a default dependency); setting `AuditConfig::otel` without that feature
    fails startup loudly rather than silently dropping the export, matching
    the existing `--audit-log-file` rule (#158). The OTLP client only speaks
    plain `http://` **to a loopback IP literal** -- a non-loopback host or a
    hostname (even one that would resolve to loopback) is refused at
    export-setup time, the same rule `SsdfSinkConfig`/`ForwardSinkConfig`
    apply to their own endpoints, and for the same reason: this sits outside
    `AuditRedaction`'s reach, so a plaintext endpoint reachable off-host would
    leak span attributes and event bodies to anyone on the path. The layer
    also carries its own filter, defaulting to `info` and overridable only
    via `MECMCP_OTEL_FILTER` (never `RUST_LOG`, since turning up local
    debug logging must not also turn up what leaves the host over OTLP), with
    exporter-client traffic (`opentelemetry*`, `hyper`, `reqwest`, `h2`)
    always suppressed to avoid an export feedback loop. See
    `mecmcp-audit::otel` for the full reasoning (decision D4).
  - `EvidenceConfig::forward_sink` (`--audit-forward-endpoint` and friends)
    ships the same hash-chained `ClosedSegment` SSDF ships to a second,
    best-effort destination -- a SIEM, a log collector, an object-lock
    bucket's HTTP front end. This is not the unchained syslog path
    `docs/AUDIT-FORWARDING-STANDARD.md` rejected: `prev_hash`/`head_hash`
    travel with every record, so a receiver can still detect a dropped or
    altered one. SSDF stays the chain of record; a forward-sink failure is
    logged and never affects `EvidenceService::delivery_degraded` or
    `shutdown`'s result. Retry backoff is non-blocking -- a segment not yet
    due for retry is skipped rather than slept out -- since this sink shares
    a thread with the SSDF drain loop and an in-line sleep would delay SSDF's
    own next delivery pass behind it. `EvidenceService::start_with_transports`
    lets SSDF and the forward sink use independent transports, since the two
    endpoints are typically different hosts with different trust anchors
    (`EvidenceArgs::ca_file` vs. `EvidenceArgs::forward_ca_file`);
    `start_with_transport` (singular) still exists and shares one transport
    for the cases where that is fine.
  Both are `None`/off by default, so existing SSDF-only and non-OTel
  deployments are unaffected.
  - **Breaking (source, not binary):** `AuditConfig` gained an `otel` field
    and `EvidenceConfig` gained a `forward_sink` field; neither struct is
    `#[non_exhaustive]` or `Default`, so any struct literal constructing
    either needs a new field (`None` preserves prior behavior). A downstream
    server wiring up `--otel-endpoint` must map it into `AuditConfig::otel`
    itself -- nothing in this repo does that automatically.

- **redact: `Untrusted<T>` marks device/controller-sourced content before it
  reaches a model** (MEC-511). Device text (hostnames, descriptions, error
  bodies) previously flowed into tool output with nothing distinguishing it
  from operator input or this codebase's own text. `Untrusted::new` wraps a
  value at the point it's read from a vendor response; `render_tagged`
  delimits it for inclusion in a tool result, neutralizing any attempt by the
  content itself to forge a matching closing delimiter.
  `mecmcp-server::tool_error_with_untrusted_detail` is the new sanctioned
  entry point for a tool handler's error path, and `mecmcp-changeset`'s
  device-transaction error formatting (`apply.rs`) is migrated as the
  reference example.

### Changed

- **BREAKING — mecmcp-server: `tool_result` takes an `OutputRedaction`
  argument and redacts every successful value by default** (MEC-1020,
  closes mechubsec/mecmcp#398). Previously this crate only re-exported
  `Untrusted`, and a handler had to remember to call `mecmcp-redact` on its
  own output; a new tool that forgot shipped an unredacted value. `tool_result`
  now redacts `Ok` values unconditionally unless the caller passes
  `OutputRedaction::SkipForInternalRead { tool, reason }`, a per-call opt-out
  (there is no `Default` impl and no process-wide flag) that emits a
  `target: "audit"` `WARN` naming the tool and reason, for data that never
  touched a device (e.g. this process's own audit log). `tool_error` and
  `tool_error_with_untrusted_detail` redact their text unconditionally too,
  with no opt-out — a device error routinely echoes the config line that
  triggered it, so the error path needs the same default as the success
  path. Every existing call site in this crate passes `OutputRedaction::Apply`
  or `Apply`-equivalent behaviour; the six vendor server repos that already
  call `mecmcp-redact` on their own paths will need their own follow-up to
  adopt the new argument next time they bump this crate.
  **Also note:** `ResultFormat::PrettyJson` now serializes through
  `serde_json::Value` on its way to the redactor, so struct field order in
  the rendered JSON is alphabetical rather than declaration order; any
  golden fixture that asserts exact JSON text will need updating.

- **BREAKING — http/openapi: request paths are typed; the raw-URL
  constructor is feature-gated** (MEC-510). `mecmcp-openapi::expand_path` now
  returns `ExpandedPath` instead of `String` — a type with no public
  constructor other than a successful expansion, so `let s: String =
  expand_path(..)?` no longer compiles (use `.as_str()` or `.to_string()`).
  `mecmcp-http` gains `HttpRequest::with_base_and_path(method, base,
  &ExpandedPath)`, which joins the path onto an operator-configured base and
  rejects a base that carries its own path, query, or fragment (put a prefix
  such as `/api2/json` in the template instead). `HttpRequest::new(method,
  &str)` is renamed `HttpRequest::from_absolute_url` and is only available
  behind the non-default `absolute-url` feature, for full URLs that are not
  path-templated (OIDC discovery/JWKS); `mecmcp-oidc` enables it. Vendor
  servers should migrate REST calls to `with_base_and_path` and should not
  enable `absolute-url`.

### Security

- **mecmcp-server: a tool's error path could leak a device secret that a
  new tool's success path was already protected against** (MEC-1020, part
  of mechubsec/mecmcp#398's review). Before this change, `tool_error` and
  `tool_error_with_untrusted_detail` passed their text through unredacted,
  so a Junos commit-check failure or a PAN-OS API error body that quoted
  the offending config line (a pre-shared key, an SNMP community string)
  reached the model verbatim, even though the same value in a success
  result was already redacted by the `Changed` entry above. Both functions
  now redact unconditionally.

- **mecmcp-server: `tool_error_with_untrusted_detail` could drop its own
  closing trust-boundary tag** (MEC-1020, review follow-up on
  mechubsec/mecmcp#458). The function redacted `detail`, rendered it inside
  `<untrusted-device-content>` markup, then passed the whole tagged string
  through `tool_error`, which redacted it a second time. `redact_text`'s PEM
  handling drops every line after an unterminated `-----BEGIN ... -----`
  header, so device text containing one consumed everything after it,
  including the closing tag, on the second pass. No secret leaked -- this
  failed safe on data -- but a client or model that trusts the tag boundary
  would read an untagged block as unbounded. Each piece is now redacted
  exactly once before the tag is built.

- **mecmcp-redact: `redact_text` could still drop a closing trust-boundary
  tag on a real production path** (MEC-1020, review follow-up on
  mechubsec/mecmcp#458, R2). Fixing the previous entry moved the redundant
  redaction pass out of `mecmcp-server`, but `mecmcp-changeset` already tags
  a device error with `Untrusted::render_tagged` *before* the error reaches
  `tool_error` (`CoordinatorError`'s message carries the tag), so
  `tool_error`'s single, now-necessary pass over that string still ran into
  the same unterminated-`BEGIN` case. `text::redact` now recognizes a
  `</untrusted-device-content id="...">` closing tag as ending an open PEM
  block even without a matching `END` line -- the tag's body is escaped by
  `render_tagged`, so a line in this exact shape can only be the wrapper's
  own closing tag, never forged device text. No secret leaked; this closes
  the same fail-safe gap for the call sites that tag before returning an
  error.

## [0.24.1] - 2026-09-28

> **Upgrade note.** This patch release changes a default: servers that relied
> on `LimitsConfig::default()` being unmetered now get per-IP and per-token
> rate limits (below). Set either pair to `0`/`0` to keep the old behaviour.

### Changed

- **transport: `LimitsConfig::default()` now rate-limits by default**
  (MEC-347). Per-IP and per-token rate limits were `0` (disabled) out of the
  box, so a fresh install ran fully unmetered until an operator opted in.
  Defaults are now `max_requests_per_second_per_ip: 50` /
  `max_request_burst_per_ip: 100` and `max_requests_per_second_per_token: 20`
  / `max_request_burst_per_token: 40`. Set either pair to `0`/`0` to disable
  that axis, as before.

### Maintenance

- **ci:** the build-test job builds with `--locked` (#396).
- **transport:** stale comments that described `Cargo.lock` as gitignored
  are corrected (#395).
- **hygiene:** canonical shared gitleaks vendor rules added (MEC-30, #388);
  personal email domain in test fixtures replaced with a synthetic one (#391).

## [0.24.0] - 2026-09-28

### Added

- **transport: `/healthz` and `/readyz`** (MEC-48, mecmcp#377). Both are
  unauthenticated, always mounted, and return no device or customer data.
  `/healthz` reports the process is up with no dependency check. `/readyz`
  runs the consumer-supplied `ReadinessCheck`s registered with
  `HttpTransportConfig::with_readiness_check` — 200 when all pass (including
  when none are configured), 503 listing the failed check names otherwise. A
  probe's failure reason is `&'static str`, not `String`: since `/readyz` is
  unauthenticated, the type keeps a probe from formatting a runtime value
  (a path, an I/O error) into the response body — log that detail
  server-side instead. `mecmcp-transport` ships no checks of its own; each
  consuming server wires in audit-sink-writable and inventory-loaded checks
  as a follow-up.
- **`mecmcp-policy`: fail-closed allowlist mode (MEC-92).** `Policy::new` now takes a `CommandMode` (`Allowlist` or `Blocklist`) that governs the commands and pfe_commands domains; the config domain is unchanged. `Allowlist` is the default and refuses everything until entries are added: entries are literal whitespace-token prefixes (never globs — `*`, `?`, `[` in an entry are a compile-time error via `compile_allowlist_entries`), abbreviations are never expanded, and a piped command needs every `|` stage after the first to match a separate `allowed_pipes` list that defaults to empty. `;`, `>`, `<`, a backtick, or a newline anywhere refuses the command outright. `Blocklist` keeps the pre-MEC-92 fail-open behaviour byte-for-byte, for callers that request it explicitly — nothing in the crate maps an absent mode to `Blocklist`. **Breaking API change:** `Decision` gained a `DenyAllowlist` variant (any exhaustive match on `Decision` needs a new arm), and `Policy::new` takes a `CommandMode` plus `CommandDomain<A>` (blocklist + allowlist bundle) instead of bare `DomainRules<A>` for the commands/pfe_commands parameters. `Decision` is now `#[must_use]` and gained `is_allowed()`, which is true only for `Decision::Allow`; callers must gate on `is_allowed()` or match all three variants exhaustively — matching only `Decision::Deny` and treating everything else as allowed silently lets `DenyAllowlist` refusals through. Library only — no MCP server wires this up yet; that's tracked in the sibling MEC-88 consumer tasks.
- **mecmcp-audit:** `DirectCommitPolicy`, a shared gate for tools that mutate a device with no change-set approval at all. Off by default: refuses direct-commit tools identically over stdio and HTTP, since the policy is a process-level setting and never reads caller context. When an operator enables it, it logs loudly at startup and tags every use in the `AuditScope` audit trail.

### Changed

- **transport: `/metrics` defaults to loopback-only** (MEC-48, mecmcp#377).
  **Behaviour change:** a peer that is not `127.0.0.1`/`::1` now gets a 403
  from `/metrics`, regardless of any MCP bearer token it presents — where
  previously any peer that passed the Host/Origin allowlist and IP rate limit
  could reach it. A loopback peer that also carries a request-forwarding
  header (`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) is
  treated as non-loopback, since a same-host reverse proxy — the deployment
  shape this project documents for its own servers — otherwise makes every
  forwarded caller look loopback at the TCP layer. Loopback detection also
  now canonicalizes the peer address first, so an IPv4-mapped IPv6 address
  (`::ffff:127.0.0.1`, seen on a dual-stack listener) is recognized as
  loopback rather than refused. Call the new
  `HttpTransportConfig::with_metrics_token` to also admit a non-loopback peer
  presenting a dedicated metrics bearer token (checked independently of the
  MCP token store, so an MCP token still never grants `/metrics`). See
  `docs/METRICS.md` for the Prometheus scrape config migration, including the
  reverse-proxy caveat.
- **mecmcp-changeset:** `ChangesetCoordinator::approve_change_set` now takes an `approver_actor_type: mecmcp_audit::ActorType` argument and refuses the approval unless it is `Human`. House rule: deterministic code decides, a human approves — an agent or an unattributed caller (`Agent` or `Unknown`, which is what a stdio session with no caller context carries) could always be blocked from *proposing* a change set's own approval by the pre-existing owner check, but nothing stopped it from standing in as the *second* principal. This is a breaking change for every caller of `approve_change_set`.
- **DOCKER-STANDARD template examples now use mechubsec image names** —
  updated from `ghcr.io/fastrevmd-lab/<binary>` to `ghcr.io/mechubsec/<reponame>`
  to match the org migration.

### Changed

- **Raised MSRV to 1.89** and removed the `aes` pin from the CI msrv job that PR #344 added. All six consumer repos are moving to 1.89 in parallel PRs, so the objection that blocked raising the floor in #344 no longer stands.
- **`mecmcp-transport`: `test_client` and `test_harness` moved behind a `test-util` feature** (mecmcp#387). Neither is part of the crate's default public API anymore, and the `ureq` dependency they pulled in is no longer part of the normal (non-`test-util`) dependency graph. **Breaking change** for any consumer that used them: add `features = ["test-util"]` to the `mecmcp-transport` dev-dependency entry.
- **`mecmcp-http`: a configured private CA now replaces the public root store instead of adding to it** (mecmcp#387). `extra_root_certificates`, when non-empty, is passed through `tls_certs_only` rather than `tls_certs_merge`/`add_root_certificate`, matching "private CA means private CA only." **Behaviour change** for any deployment that relied on the previous additive semantics (a private CA trusted *alongside* the public roots): to keep public trust, configure no `extra_root_certificates`.

## [0.23.1] - 2026-09-05

### Added

- `packaging/lxc/build-minimal-rootfs.sh` and `MINIMAL-LXC-ROOTFS.md`, the result
  of the #347 spike. Builds a Debian rootfs for an LXC running one
  mecmcp-family service under systemd, keeping glibc and systemd deliberately.
  Measured against a real deployed guest: **257 -> 146 packages, 911 -> 260 MB**,
  and one fewer listening network service. Verified on hardware -- the service
  starts, every directive that was enforced before is still enforced (read from
  `/proc`, not from `systemctl show`), hostname resolution is unchanged, a real
  NETCONF call reaches a vSRX on Junos 24.4R1.9, and the `pct exec` operator path
  of editing `devices.json` and sending `SIGHUP` still works. `IPAddressDeny` is
  the one exception and is called out in the document: it is reported by
  `systemctl show` and is not enforced in an unprivileged LXC, which is true of
  the stock guests too and is not changed by this image. The template carries no
  SSH host keys: they are stripped at build time and regenerated once on first
  boot, so guests built from it do not share a server identity.

### Fixed

- **changeset, auth, inventory: conditional chown to survive systemd's
  `SystemCallFilter=~@privileged`** (#351). The ownership-preserving `chown` in
  `write_state`, `write_atomic` (tokens), and `migrate` (inventory) was
  unconditional: it ran even when the effective uid and gid already matched the
  destination file's owner. Under a systemd unit carrying
  `SystemCallFilter=~@privileged`, the kernel does not return `EPERM` — it kills
  the process with **SIGSYS**, which neither `let _ =` nor `map_err` can catch.
  Observed on rustunifimcp 0.3.0: the second change-set state write killed the
  server mid-request (`status=31/SYS`, kernel audit `syscall=92` = chown), systemd
  restarted it, and the approval was lost. The SDC guest (the sdc guest) carries the
  same filter and was exposed. Now only calls `chown` when the ownership would
  actually change: a service writing its own state file makes no syscall, while
  the offline-recovery case (sudo over a service-owned file, where the uids differ
  and no seccomp filter applies) still works.

## [0.23.0] - 2026-08-30

### Security

- **An approval now binds the preview the approver was shown**
  (rustproxmoxmcp#56). Consent was evidenced against the *actions*; what an
  approver read was the *preview*, rendered from those actions and stored beside
  them with its own digest. Nothing joined the two, so the stored text could be
  replaced — text *and* digest together — and every check still passed.
  `compute_approval_digest_v5` adds the preview digest to the signed tuple.

  Bound in the approval rather than in the plan digest, which is what the issue
  proposes. The plan digest is created before the preview exists, and every
  stored approval binds it, so recomputing it would invalidate them all — and
  re-signing would assert that those approvers consented to a binding that did
  not exist when they approved. That is the laundering #275 refused for waivers.

  What it does **not** do, stated because the distinction matters: it does not
  verify the preview is a faithful *rendering* of the actions, and it does not
  prove the bound preview is the one the approver read (`approve_change_set`
  signs whatever is stored when it is called). Both are recorded on the issue.

- **A granted two-person approval is now immutable, and so is the preview it
  binds.** Five separate write paths could previously reach the same end: swap
  the preview in-process, rewrite the artifact under its own digest, downgrade
  the v5 approval to v4 and then swap, sign an inconsistent preview at approve,
  or remove the approval entirely and let `apply` accept the record through its
  legacy `approver` field. Stated now as three invariants in
  `check_change_set_write` rather than as guards on the paths that were found.

- **The raw persistence surface no longer reaches `Applying`** (#341).
  `write_state` was re-exported from the crate root, so a consumer could build a
  record already in `Applying` — with `apply_without_handle` set, or a `task_id`
  — write it, and have `ChangesetCoordinator::load` accept it. `load` validates
  structure, not lifecycle provenance, so "one approval permits at most one
  apply" stopped holding by construction. `write_state` is `pub(crate)`;
  `write_state_for_test` sits behind the existing `test-util` feature.

- **Unknown top-level keys in an inventory file are refused** (#340). A
  credential placed at the top level was neither used nor rejected — it sat
  there while the operator believed it was configured.

### Added

- **`Atomicity`, so a vendor can declare what its transactions guarantee**
  (#335). `DeviceTransaction` was derived from two vendors that both have
  candidate configuration and promised all three guarantees on every vendor's
  behalf. The default guarantees **nothing**: an optimistic default would hand a
  claim of atomicity, dry-run validation and reliable rollback to every
  implementation that has not considered the question — including rustsdcmcp's
  five, where SDC has no candidate store at all.

### Changed

- **`compute_approval_digest` is now `compute_approval_digest_v4`**, and
  `ApprovalRecord` carries `digest_version`. The version travels with the record
  rather than the file, because v4 approvals must never be promoted to v5: doing
  so would claim their approvers consented to a preview binding that did not
  exist. State-file schema 6 gates a file containing any v5 approval.

- **An unsupported version is reported as one.** `deny_unknown_fields` on the
  inventory envelopes fired before the version check, so a document on a future
  schema was told to delete a field its schema requires — an error naming an
  action that is destructive and wrong.

- **The MSRV job pins `aes`.** `Cargo.lock` is gitignored, so the job resolves
  fresh every run; `aes` 0.9.3 declared `rust-version = 1.89` and made the 1.88
  floor unsatisfiable on every open PR, with no commit behind it.

### Upgrading

Breaking for consumers. `ApprovalRecord` gains a public field, so struct
literals need `digest_version` — 4 for anything hand-built, and the `Default`
is 4. `compute_approval_digest` is renamed; `write_state` moves behind
`test-util` as `write_state_for_test`.

**Records approved after the upgrade write schema 6, which binaries below it
refuse.** Deliberate, and the same gate v4 used: a v1-v5 reader would recompute
the v4 tuple for a v5 approval and reject the file. A deployment that has
approved nothing since upgrading keeps writing the version it wrote before.

## [0.22.0] - 2026-08-27

### Security

- **One approval now permits at most one apply**, as a property of this crate
  rather than of whoever remembered the right method (#339). Reading `Approved`
  with `change_set()` and then writing `Applying` with `update_change_set()` was
  two operations with the lock released between them, so two applies could both
  pass the check and both execute — and the second write could land on top of an
  `Applied` from the first, erasing the outcome.

  `claim_change_set_for_apply` does the check and the transition under one lock
  and is the only route into `Applying`. `change_set_transition_allowed` is a
  closed table: anything unnamed is refused, so intermediate states no longer
  reach `Applying` the long way round. `insert_change_set` creates `Planned`
  only and refuses an existing id. `update_change_set_from` refuses a write
  whose observed state has moved, so a stale cancellation cannot erase a claim.

  For a destroy this was close to harmless — a second destroy of an absent guest
  fails. It matters for operations that are not idempotent, which is what
  unblocks rustproxmoxmcp#57.

### Added

- **`ApplyHandle` and `ChangeSetRecord::apply_without_handle`.** `Applying` with
  no task handle meant two opposite things: usually the process died before
  writing one, so nothing started and `Failed` at load is right — but some
  applies never have a handle to write, and there the same state means the
  command may well have run and only the device knows. Calling that `Failed`
  asserts an outcome nobody observed, on an operation that is not idempotent.
  Such a record now stays `Applying` across a restart: detectable, not
  recoverable, and a human looks. That also keeps the approval spent.

### Changed — **state-file schema version 5**

- A file carrying `apply_without_handle` declares version 5, which 0.21.0 and
  earlier refuse outright. That is deliberate: `ChangeSetRecord` is
  `deny_unknown_fields`, so an older binary would otherwise read the file as a
  supported schema and then reject the record on the unknown field. **A rollback
  below 0.22.0 cannot read a state file written while a handleless apply was in
  flight.** The marker is cleared once the record settles, so a file only carries
  it for the duration of such an apply.

### Upgrade note for consumers

- `Approved -> Applying` through `update_change_set` is now refused. Any server
  doing that must call `claim_change_set_for_apply`; this crate's own
  `apply_change_set` was migrated in the same change.
- `insert_change_set` accepts `Planned` only.
- `Applied -> Failed` remains permitted — rustjunosmcp's `settle_change_set`
  depends on it, since `Applied` is written before diff, validation and commit.


## [0.21.0] - 2026-08-27

First hand-written entry, as the header below asks for.

### Security

- **audit** — `RUST_LOG` can no longer switch the audit trail off (#330).
  `init_tracing` attached the environment filter to the tracing *registry*,
  where it decides whether an event exists at all, so it gated the audit file
  and journald sinks as well as the console. A `RUST_LOG` value that names a
  target — the ordinary way to turn up logging for one crate — produces a
  filter that does not enable the `audit` target, and every `target: "audit"`
  event was discarded while the operation it described still happened.

  Measured on rust-proxmoxmcp: widening a token's scope wrote one audit line
  with `RUST_LOG` unset and **zero** under `RUST_LOG=rust_proxmoxmcp=debug`.
  The token store was updated both times and stderr stayed empty.

  This reached every server, since `init_tracing` is the single entry point all
  five use — tool calls, change-set approvals, applies, evidence emission.

  The filter now sits on the console layer. The audit layers keep their own
  `is_audit` filters and declare no max-level hint, so registry interest
  resolves to *sometimes* rather than *never* and audit events reach them
  whatever the environment says. `RUST_LOG` can still make logging noisier and
  can no longer make the security trail disappear.

  **Consumers should take this release.** No API changed, so the bump is a
  dependency update, but until it is taken the trail stays switchable.


## [0.20.0] - 2026-08-25

### Added

- **changeset** — Record the vendor task handle for an in-flight apply

### Changed

- Move the pinned toolchain to 1.98.0

### Fixed

- **changeset** — Do not settle an apply that still has a task handle
- **changeset** — Drop an empty task handle at every boundary it crosses

## [0.19.0] - 2026-08-25

### Fixed

- **audit** — Add capture sentinel to detect broken tracing mechanism
- **audit** — Capture by thread-local buffer, not by swapping subscribers

### Documentation

- follow-up block A design (captures, dependency coverage, egress)
- Implementation plan for follow-up block A
- Record block A outcome — seven tasks, five issues closed

## [0.18.0] - 2026-08-24

### Fixed

- **testutil** — Serialise run_with_capture against the global interest cache

### Documentation

- Fleet cleanup sprint design (2026-08-24)
- Record the sprint outcome, including where the plan was wrong

## [0.17.0] - 2026-08-24

### Added

- mecmcp 0.17.0 - fleet-shared improvements

### Fixed

- **audit** — Tighten by bitmask, not magnitude
- **auth,audit** — Surface permission errors, accept multiple live secrets, fix umask brittleness
- **auth** — One file, one stale-secret finding

## [0.16.0] - 2026-08-23

### Fixed

- **audit** — A receipt names who executed, not who proposed (0.16.0)

## [0.15.0] - 2026-08-23

### Fixed

- **runtime** — The CA refusal explained the wrong flag (0.14.2)
- **runtime** — Mark EvidenceArgsError non_exhaustive

## [0.14.1] - 2026-08-23

### Fixed

- **runtime** — The trust anchor belongs with the evidence flags (0.14.1)

## [0.14.0] - 2026-08-23

### Added

- **auth** — Accept targets as a scope spelling and expose neutral APIs (#91)
- **transport** — Carry client_version and client_call_id to handlers (#304)
- **auth** — Refuse a wildcard target scope beside a target-scoped grant (rustmistmcp#17)
- **inventory** — Emit the canonical envelope, explicitly (#48)
- **audit** — Produce evidence records at the lifecycle points (#292)
- **changeset** — Emit evidence at the four lifecycle points (#292)
- **audit** — Join the recorder to the SSDF sink (#292)
- **audit** — Give the sink a drain, and order the startup reads
- **runtime** — Give every server the evidence-pipeline flags
- **transport** — A TLS transport for the evidence sink

### Changed

- Drop an unused Read import from the chunked-response test
- **transport** — A read-only probe for evidence TLS reachability

### Fixed

- **digest** — Give approvals an unambiguous encoding (#283)
- **transport** — Withhold the call id for a batch, and keep ClientExtras open (#304)
- **transport** — Keep the audited element's call id on the transport event (#304)
- **testutil** — Rebuild the interest cache before capturing (#305)
- **testutil** — Keep the capture from being cached away (#305)
- **auth** — Check scope agreement on the mutated token, not the whole store
- **inventory** — Make migration lossless, safe to run, and abort on drift (#48)
- **ssdf-sink** — Dedup by high-water mark, not by an insert the writer cannot run (#292)
- **ssdf-sink** — Make the high-water mark a safe statement of what landed (#292)
- **ssdf-sink** — Bound a chunk before allocating it (#292)
- **recorder** — Produce evidence SSDF can actually verify (#292)
- **recorder** — Key context by changeset, resume the tier chain, close the flush race (#292)
- **recorder** — Reconcile the resume head with the outbox, evict the oldest (#292)
- **audit** — Resume from the newest segment produced, not the newest pending
- **audit** — Fail the apply when its intent record cannot be persisted
- **audit** — Close four gaps the gate found in the lifecycle emission
- **audit** — Serialize flushes, persist receipts, and complete waiver evidence
- **audit** — Recover a torn ledger tail, omit absent waiver fields
- **audit** — Repair a torn ledger tail in bytes, and keep the load streaming
- **audit** — Send an insert deduplication token (ssdf#49)
- **audit** — Make the dedup token injective for any identifier
- **audit** — Stop the service losing segments, hiding failures, and stalling
- **runtime** — Require an explicit --ssdf-audit-server-id
- **runtime** — Four config defects the gate found in EvidenceArgs
- **audit** — Shutdown must not abandon segments on the first error
- **runtime** — Reject a blank chain identity, and order run ids again
- **transport** — Take the crypto provider rather than constructing it
- **transport** — Probe must refuse http, and record why shutdown continues
- **runtime** — Order run ids below process-start resolution

### Documentation

- Fix intra-doc link left by the digest rename (#283)
- Say plainly that a store write canonicalizes scope aliases (#91)
- **audit** — Record what the trail sits in, not just how it is emitted (rustjunosmcp#299)

## [0.13.0] - 2026-08-19

### Added

- **audit** — Capture the client version and per-call id (rustjunosmcp#267)

## [0.12.0] - 2026-08-16

### Added

- **transport** — Capture provenance from per-request _meta (#288)
- **auth,runtime** — Add `token set-provenance` (#289)
- **audit** — Carry the approver and change set on Attribution (rustjunosmcp#307)

### Fixed

- **changeset** — Retire a change set whose waiver has lapsed (#284)
- **transport** — Make interning race-free, unflaking model_id_is_interned

### Documentation

- Make ECS-over-TCP audit forwarding a family standard
- Transport is the hash-chained ClickHouse sink, not syslog

## [0.11.0] - 2026-08-16

### Added

- **transport,audit** — Carry client-asserted model_id and session_id into attribution (#267)

### Fixed

- **changeset** — Reject the digest separator in owner and approver (#283)
- **test** — Add real end-to-end provenance test, make unit tests honest

### Documentation

- **transport** — Document stateless-path provenance limitation

## [0.10.0] - 2026-08-14

### Added

- **changeset** — WaiverRecord gains a digest-bound kind, expiry and ticket (#275)  
  **Breaking change.**
- **changeset** — Add the v3 waiver digest binding kind, expiry and ticket (#275)
- **changeset** — Schema v3 for operator waivers, v1/v2 still readable (#275)  
  **Breaking change.**
- **changeset** — Refuse apply when a waiver has expired (#275)
- **changeset** — Add waive_approval_operator alongside the lab-mode path (#275)

### Changed

- **changeset** — Add v3 waiver round-trip and version-dependence test (#275)
- **changeset** — Isolate pre/post-guard waiver expiry checks
- **changeset** — Remove two tests that could never run (#275)
- **changeset** — Forge each v3-only waiver field on its own (#275)

### Fixed

- **changeset** — Correct waiver expiry boundary and extract duplicate check
- Three v1/v2 waiver defects — metadata forgery, load/save bricking, vacuous test
- **changeset** — Make waiver expiry tests provably diagonal
- **changeset** — Reject v1/v2 waivers with edited reason or both approver+waived
- **changeset** — Say "device guard", not "device lock", in the expiry errors (#275)

### Documentation

- **packaging** — --lab-mode is CLI-only, never product configuration
- Open the release programme and record the SD unification decision
- Resolve the SD On-Prem credential question
- Mark Phases 0 and 1 complete
- Record Phase 2's findings
- Mark Phase 2 complete — all six consumers on v0.9.1
- Record phases 3-5 outcomes and two scoping corrections
- Record the Junos production outage and the flag-wiring defect class
- **spec** — Operator waivers with a digest-bound kind (#275)
- **plan** — Implementation plan for operator waivers (#275)
- **changeset** — Correct ApprovalRecord digest and waived field docs (#275)
- **readme** — Fix the 0.9.1 issue citation and state the upgrade shape (#275)

## [0.9.1] - 2026-08-13

### Added

- **transport** — Add a supported test harness for ServePlan

## [0.9.0] - 2026-08-13

### Added

- **audit** — Add Junos native device log parser
- **transport** — Add operator acknowledgement types (#273)
- **transport** — Add listener admission checks (#273)
- **transport** — Make authentication a constructor choice (#273)  
  **Breaking change.**
- **transport** — Refuse inadmissible listeners in serve_router (#273)  
  **Breaking change.**

### Changed

- Ignore subagent-driven-development scratch dir
- **transport** — Migrate call sites to ServePlan and serve_router (#273)
- **transport** — Guard that the pre-0.9.0 constructors stay removed (#273)
- **transport** — Document compile-fail fixture brittleness and regeneration procedure
- **runtime** — Collapse cli_validate and demote it to a pre-check (#273)  
  **Breaking change.**
- **transport** — sabotage-verify the listener refusals (#273)
- Apply rustfmt across the #273 branch

### Fixed

- **audit** — Correlate transport and handler events by request_id
- **transport** — Add compile_fail doctests to prove consent types are unconstructible (#273)
- **transport** — Migrate doctests to new constructors (#273)
- **runtime** — Warn when a revoke or rotate has not reached the server

### Documentation

- **readme** — Mark 0.6.0 manual wiring superseded by 0.7.0 assembly
- **readme** — Stop endorsing hand-assembly as a 0.7.0+ path
- **readme** — Correct the Origin and session-tracker caveats
- **readme** — Scope the Host guard to /mcp and the tracker defect to 0.8.2
- **spec** — Design for unskippable listener validation (#273)
- **plan** — Implementation plan for unskippable listener validation (#273)
- 0.9.0 upgrade notes for unskippable listener validation (#273)
- **transport** — Resolve two broken intra-doc links

## [0.8.8] - 2026-08-12

### Changed

- **transport** — Drive build_streamable_http_router end-to-end

### Fixed

- **transport** — Settle the preflight audit outcome after the check, not before

## [0.8.7] - 2026-08-11

### Added

- Expose client name through CallerCtx for handler audit events (#262)
- **changeset** — Review view — expose stored actions on request
- **runtime** — Add WebApproverArgs for server-common approver flag

## [0.8.6] - 2026-08-11

### Added

- **inventory,changeset** — vendor-neutral config authority tracking (#260)

## [0.8.5] - 2026-08-10

### Added

- **changeset** — Add cancel_change_set lifecycle operation

### Changed

- **changeset** — Add provenance round-trip integration test
- Fix clippy lints in verify_golden_fixtures test

## [0.8.4] - 2026-08-10

### Added

- **audit** — Add ssdf sink with durable outbox and delivery ledger
- **audit** — Add mecmcp-verify CLI with run-manifest completeness

### Fixed

- **audit** — Complete ssdf sink - real HTTP, wired backoff, server-side dedup
- **audit** — Fmt blocker + test improvements
- **audit** — Path traversal, empty-run false positive, duplicate segment_seq
- **changeset,audit** — Unify join format and per-record row_hash

## [0.8.3] - 2026-08-10

### Added

- **changeset** — Add commit metadata hook for device-side provenance
- **mecmcp-audit** — Evidence records and hash-chained segments
- **audit** — Add ed25519 signing over closed segment heads

### Fixed

- **mecmcp-audit** — Address 4 critical review findings
- **mecmcp-audit** — Envelope mismatch validation in append()
- **audit** — Address signing security and usability findings
- **lint** — Gate test-only unwraps so the workspace lint passes again (#249)
- **transport** — Give the bearer boundary the session tracker (#250)

## [0.8.2] - 2026-08-09

### Added

- **transport** — Capture clientInfo from MCP initialize (#53)
- **transport** — Capture clientInfo from MCP initialize (#53) (#239)
- **audit** — Propagate captured client name into audit events (#53) (#241)

### Documentation

- Standardize filesystem layout across MCP servers (#28) (#235)
- Standardize release artifacts across MCP servers (#30) (#236)
- Standardize Docker documentation across MCP servers (#31) (#237)
- Add ARCHITECTURE.md and ONBOARDING.md (#240)

## [0.8.1] - 2026-08-08

### Added

- **transport** — transport-level audit for every tools/call (#32) (#233)  
  **Breaking change.**

## [0.8.0] - 2026-08-07

### Added

- **transport** — Extraction milestone 4 — generic scope preflight + shared test client (#232)  
  **Breaking change.**

## [0.7.3] - 2026-08-07

### Changed

- **deps** — axum-server 0.8, dropping the unmaintained rustls-pemfile (#231)  
  **Breaking change.**

### Security

- **deps** — Dropped `rustls-pemfile`, which [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134) marks unmaintained, by moving to axum-server 0.8. It was failing the supply-chain gate.

## [0.7.2] - 2026-08-07

### Fixed

- **transport** — Give rmcp its own token so the drain can deliver a response (#230)  
  **Breaking change.**

## [0.7.1] - 2026-08-07

### Fixed

- **runtime** — Hold the wait future across polls so shutdown actually fires (#229)  
  **Breaking change.**

## [0.7.0] - 2026-08-07

### Added

- **transport** — Extraction milestone 3 — HTTP transport assembly (#114-#117,#148-#154,#156) (#227)  
  **Breaking change.**

### Changed

- Ignore docs/codex.thoughts

### Security

- **transport** — The assembled transport owns Host and Origin validation ([RUSTSEC-2026-0189](https://rustsec.org/advisories/RUSTSEC-2026-0189)), so consumers inherit the DNS-rebinding guard instead of each writing one. Host validation always carries the loopback allowlist; a non-loopback listener is refused unless both allowed hosts and allowed origins are configured, while a loopback bind may leave Origin validation off.

## [0.6.1] - 2026-08-07

### Added

- **mecmcp-scp** — Add SCP1 file-transfer client for legacy SSH devices (#225)
- **mecmcp-scp** — Handle OpenSSH marker lines (@revoked, @cert-authority) and add SSH liveness deadlines (#226)

### Security

- **scp** — The SCP1 client is built on russh 0.62.5, patched against CVE-2026-68930. The workspace pins `russh >=0.62.5, <0.63` for this reason; `Cargo.lock` is gitignored, so the floor cannot be relaxed to `"0.62"` without exposing consumers.

## [0.6.0] - 2026-08-07

### Added

- Extract the bearer boundary into mecmcp-auth and mecmcp-transport (#223)

## [0.5.0] - 2026-08-05

### Added

- **transport** — Adopt rmcp 3.1.1, fix LimitedSessionManager forwarding, release 0.5.0 (#221)  
  **Breaking change.**

## [0.4.0] - 2026-08-05

### Added

- Add mecmcp-server with the bounded result helpers (#217)
- Add the scope authorization half of mecmcp-server (#219)

### Documentation

- Record the set_scopes break the 0.3.9 notes missed (#216)

## [0.3.9] - 2026-08-05

### Added

- Report the consumer's version, and make CLI provenance visible (#204)
- Expose set-scopes, and let it reach the mutation grant (#205)

### Fixed

- Fail closed on an unopenable audit file, and allow lossless rotation (#200)
- Make off-loopback Host/Origin validation fail closed (#201)
- Stop an expired change set locking a principal out of its device (#202)
- Bound the wait queue to prevent unbounded memory use (#203)
- Require Origin only where the transport enforces it (#206)
- Confirm the two scope changes that quietly widened authority (#207)
- Keep the expiry sweep off in-flight applies, and make it durable (#208)
- Parse the consumer's CLI, and walk the whole command tree (#209)
- Close the path-expansion bypass, and stop mislabelling decoded bytes (#211)
- Enforce the multi-target and preview invariants that were declared but never checked (#210)
- Stop a pre-existing log logger costing the rotation handle (#212)
- Give the saturation tests a release signal that latches (#213)

### Documentation

- Correct two upgrade claims that would strand a consumer (#214)

## [0.3.8] - 2026-07-31

### Added

- mecmcp-auth — Phase 1 of the shared crate extraction (#1)
- **mecmcp-auth** — Add token lifecycle operations (add/rotate/revoke) (#2)
- **auth** — set_scopes — change a token's scopes without touching its secret (#3)
- mecmcp-audit — Phase 2 of the shared crate extraction (#12)
- **mecmcp-inventory** — Add canonical envelope with legacy readers (#46)
- **changeset** — Define DeviceTransaction trait with confirmed-commit support (#51)
- **mecmcp-changeset** — Add operation/changeset validation (Task 4) (#55)
- **Phase 5 Task 5** — Add ChangesetCoordinator with restart recovery (#56)
- **Phase 5 Task 6** — Add change-set approval gate with tamper-evident approvals (#57)
- **changeset** — lab-mode approval waiver that records a waiver, not an approver (#54) (#58)
- **changeset** — Port indeterminate-operation recovery (Phase 5 Task 9) (#59)
- **auth,audit** — Bind provenance to the token, and mark which fields are verified (#52) (#61)
- **changeset** — single-operation lifecycle (Phase 5 Task 8) (#64)
- **changeset** — Apply an approved change set (Phase 5 Task 7) (#65)
- **changeset** — Add a device-lock primitive to DeviceTransaction (#78)
- **changeset** — Expose an operations snapshot for post-load recovery (#83)
- **changeset** — Make staged-restart recovery a load-time vendor policy (#84)
- **changeset** — Report why approval was waived (#95)
- Add mecmcp-secret crate for outbound credentials (#171) (#172)
- Add mecmcp-http hardened outbound client (#90 phase 2a) (#178)
- Stream response bodies under a hard limit (#90 phase 2b) (#180)
- Extract one hardened file reader, sized and scoped for documents (#183)
- Adopt the shared hardened reader in auth and inventory (#185)
- Make mecmcp-secret Unix-only instead of faking cross-platform support (#188)
- Harden the change-set state read, and fix two overflows it exposed (#189)
- Add mecmcp-job, cancellable polling with capped backoff (#90 phase 3) (#191)
- Add mecmcp-openapi, whole-segment paths and bounded pagination (#90 phase 4) (#194)
- multi-target change sets (#90 phase 5) (#196)

### Changed

- Gate the repo with build/lint/test, MSRV, and supply-chain checks (#9)
- Build at the declared MSRV, and widen the MSRV job to --all-targets (#10)
- Install cargo-deny directly; document the distroless spawn constraint (#13)
- Phase 5 implementation plan: mecmcp-changeset (#16)
- Phase 3a: mecmcp-transport — the vendor-neutral hardening layer (#22)
- Workspace 0.1.6 for the ConnectInfo fix (#24)
- Phase 3b: mecmcp-runtime implementation plan (#36)
- Phase 3b Tasks 1-4: mecmcp-runtime crate (#38)
- Phase 4: mecmcp-policy, mecmcp-inventory, mecmcp-device (#41)
- Standardize on device terminology (BREAKING: router→device) (#44)  
  **Breaking change.**
- Phase 5 Tasks 1-2: scaffold mecmcp-changeset crate (#49)
- Ignore the .claude worktree scratch directory
- Review each commit of a pull request with codex (#72)
- Feat/share provenance parsing (#76)
- Fix/86 flaky concurrency tests (#88)
- **audit** — Assert tool-registry audit coverage from one place (#92)
- **ci** — Drop the API-billed Codex review workflow (#161)

### Fixed

- **auth** — Preserve the on-disk envelope version — rollback safety (#4)
- **auth** — Make device validation optional, keep tool validation strict (#5)
- **audit** — Make the metrics exporter test-only; it was breaking consumer TLS (#15)
- **transport** — Missing ConnectInfo 500'd every request (#23)
- **plan** — Task 1 would have created a third copy of the TLS loader (#37)
- **inventory** — The Inventory trait could not be implemented (#42)
- Bump intra-workspace dependency pins to 0.2.0 (#45)
- **changeset** — Stop requiring an HTTPS endpoint from every vendor (#70)
- **auth** — Preserve the token file's owner across a rewrite (#74)
- **changeset** — re-check cancellation in diff, validate, and before commit (#81)
- **changeset** — Allow offline resolution of any non-terminal operation (#87)
- Keep consumer grant types through token lifecycle commands (#170)
- Bound and sanitise error causes, and correct the HTTP/2 record (#182)

### Documentation

- mecmcp analysis, program plan, roadmap, and phase-1 auth plan
- Pin the phase-1 toolchain to 1.97.0, not the 1.88 MSRV floor
- Record Phase 0 as complete with as-built findings
- State the rollback path as snapshot-based (#8)
- Add the packaging standard (#11)
- Lock Debian 13 and the logging baseline into the packaging standard (#25)
- Record the consumer-owned-choices rule in Global constraints (#34)
- Mark Phase 3 complete, with the findings worth carrying forward (#39)
- Phase 4 implementation plan — policy, inventory, device (#40)
- Mark Phase 4 complete, with the findings worth carrying forward (#43)
- **phase5** — Task 10's state-file migration is unnecessary
- **changeset** — Document the crate, weighted toward what an operator hits (#67)
- **plan** — Record Phase 5's real status and what it taught (#68)
- **plan** — Phase 5 complete, exit criterion demonstrated on hardware (#73)
- **plan** — Correct Phase 5's recorded status (#82)
- **plan** — Record the PAN-OS half of Phase 5 as verified (#85)
- **packaging** — Declare runtime dependencies and the LXC/image asymmetry (#93)
- **packaging** — Make the change-set CLI a cross-server standard (#155)

## Before 0.3.8 — the component-named tags

The workspace has always shared one version: members carry
`version.workspace = true`, and the tags below name the *component the release
was about*, not a separately versioned crate. `changeset-v0.2.2`, for example,
tags the whole workspace at version 0.2.2.

- `auth-v0.1.0` … `auth-v0.1.4`
- `audit-v0.1.0`, `audit-v0.1.5`
- `transport-v0.1.5`, `transport-v0.1.6`
- `runtime-v0.1.6`
- `devices-v0.2.0`, `inventory-v0.2.1`
- `changeset-v0.2.2` … `changeset-v0.3.7`
- `phase4-v0.1.6`, `phase4-v0.1.7` — note the tag name is a phase, not a
  version: `phase4-v0.1.7` tags workspace version **0.1.6**
- `salvage/extraction-transport-20260728` — a preservation tag for a divergent
  pre-0.3.8 lineage, not a release

They have no GitHub release attached, and consumers pin the unified `vX.Y.Z`
tags instead.

**Keep every mecmcp crate in a consumer on one ref.** Cargo keys a git
dependency on the ref, so when the *same* package arrives through two of them
the graph carries two copies and their types do not unify — the failure this
project actually hit was two `mecmcp-auth` copies and therefore two
incompatible `CallerCtx` types, pulled in because `mecmcp-audit` depends on
`mecmcp-auth`. Crates with no internal mecmcp dependency would not duplicate on
their own, so the rule is a policy rather than a law of Cargo; it is cheap to
follow and the failure it prevents is confusing to diagnose.
