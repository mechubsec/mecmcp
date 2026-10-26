# Audit forwarding standard

**Status:** emission rules are **normative now**. Transport is **implemented**
— the direct hash-chained ClickHouse (SSDF) sink described in Part 2 first
shipped in mecmcp **0.14.0** (2026-08-23; see
[`CHANGELOG.md`](../CHANGELOG.md)) — see
[#292](https://github.com/mechubsec/mecmcp/issues/292) for the
implementation history. It carries the change-lifecycle evidence records
(proposal, approval, apply intent, receipt); the per-call tool audit stream
(Part 1's `audit.jsonl`) is not forwarded and stays on the host. SSDF is the
chain of record for those records; an optional, additive
[forward sink](#a-second-destination-the-generic-forward-sink) (MEC-459) can
ship the same chained records to a second off-host destination alongside it.
Syslog forwarding was designed, staged and rejected — see
[Why not syslog](#why-not-syslog-to-the-existing-collector) below. See
[Enabling it](#enabling-it) to turn it on for a server.

## Why this exists

An audit record that only exists on the machine that produced it is not an audit
trail. It is a log file on a box whose operator is the party the record is about.

The family already emits good records — server-verified `actor_type`, `provider`
and `on_behalf_of`, kept deliberately distinct from client-asserted fields via
`token_verified_fields`. The gap is transport: those records terminate on the MCP
host.

## Part 1 — Emission (normative)

Every server, regardless of how the records are later shipped:

1. **`--audit-format json`.** Always. The `text` format is for reading in a
   terminal; it is not a parse target and must never be forwarded. Five of the
   fifteen deployed servers were emitting `text`.
2. **`--audit-log-file <state-dir>/audit.jsonl`.** journald-only is not
   sufficient — the file is the operator-facing artifact and the natural spool
   source. Eleven of fifteen were journald-only.
3. **Rotate it.** The file grows without bound; the server never truncates it.

These rules are transport-independent and hold under any of the options below.

## Part 2 — Transport

**Decision: direct ClickHouse sink, hash-chained.** SSDF is the schema steward;
the contract is theirs:

- [`audit-evidence-contract-v1.md`](https://github.com/mechubsec/ssdf/blob/main/docs/audit-evidence-contract-v1.md)
- [`audit-evidence-ingestion.md`](https://github.com/mechubsec/ssdf/blob/main/docs/audit-evidence-ingestion.md)

Records are written by `mecmcp-audit` directly into `ssdf.audit` over the
ClickHouse HTTP interface, carrying `prev_hash`/`row_hash` so that deletion or
modification of a row is detectable.

Implementation history and design requirements are tracked in
[#292](https://github.com/mechubsec/mecmcp/issues/292). The dedup guard
question — the contract's `INSERT … WHERE NOT EXISTS (SELECT …)` cannot run
under the write identity, which SSDF grants INSERT-only on purpose — is
resolved: the sink reads a high-water mark under a separate, SELECT-only
identity instead (ssdf#47; see
[`sinks/ssdf.rs`](../crates/mecmcp-audit/src/sinks/ssdf.rs)).

The sink ships `ClosedSegment`s from the evidence recorder
([`recorder.rs`](../crates/mecmcp-audit/src/recorder.rs)) — the four
change-lifecycle record types. It does not carry the per-call tool audit
stream from Part 1: nothing feeds `audit.jsonl` into `SsdfSink` today, so
those records stay on the MCP host.

### Enabling it

Off by default and inert unless configured. Pass `--ssdf-audit-endpoint
<url>` — for example on rustjunosmcp — plus the paired credential and
identity flags (`EvidenceArgs` in
[`mecmcp-runtime/src/cli.rs`](../crates/mecmcp-runtime/src/cli.rs) has the
full set); a server started without `--ssdf-audit-endpoint` runs its evidence
pipeline as a no-op. The sink itself lives in
[`crates/mecmcp-audit/src/sinks/ssdf.rs`](../crates/mecmcp-audit/src/sinks/ssdf.rs).

### A second destination: the generic forward sink

SSDF stays the schema steward and the chain of record, but a deployment that
wants a copy of the same evidence trail somewhere else off-host — a SIEM, a
log collector, an object-lock bucket's HTTP front end — can enable
`ForwardSink` (MEC-459) alongside it: `--audit-forward-endpoint <url>` plus
`--audit-forward-outbox`/`--audit-forward-ledger` (`--audit-forward-token-file`
for a bearer token; see `EvidenceArgs` in
[`mecmcp-runtime/src/cli.rs`](../crates/mecmcp-runtime/src/cli.rs)).

It also runs **without SSDF** (mecmcp#378): set `--audit-forward-endpoint` and
omit `--ssdf-audit-endpoint`, still giving `--ssdf-audit-server-id` (the chain
identity, validated the same way) plus the signing key, segment size and
interval flags, which are shared. The forward sink is then the only
destination and the chain of record. Differences from the alongside-SSDF
arrangement: the recorder is **fail-closed** on the forward spool (an error
refuses the operation, as `spooling_to` does for SSDF), the chain resumes
across restarts from the newest segment in the forward outbox (append-only,
never pruned; a rebuilt host with an empty outbox starts a new root, because
there is no remote head to ask), and `delivery_degraded` reports the forward
sink. Consumers build it with `EvidenceArgs::into_pipeline_config` and
`EvidenceService::start_pipeline`; `into_config` is SSDF-only and refuses a
forward endpoint on its own.

SSDF and the forward endpoint are usually different hosts with different
trust anchors, so a deployment enabling both over `https://` should start the
pipeline with `EvidenceService::start_with_transports`, giving the SSDF
transport `EvidenceArgs::ca_file()` and the forward transport
`EvidenceArgs::forward_ca_file()`. `start_with_transport` (singular) shares
one transport between both sinks and exists for the loopback-`http://`,
same-trust-anchor, and test cases where that is fine.

This is **not** the syslog path rejected below: it ships the same
hash-chained `ClosedSegment` SSDF ships, `prev_hash`/`head_hash` intact, as a
single JSON POST per segment rather than an unchained line in a table anyone
with write access can edit undetectably. Alongside SSDF it is additive and
best-effort — a forward-sink failure is logged and never affects SSDF's own
delivery or `EvidenceService::delivery_degraded`. See
[`crates/mecmcp-audit/src/sinks/forward.rs`](../crates/mecmcp-audit/src/sinks/forward.rs)
for the full reasoning and the local-ledger-only dedup caveat versus SSDF's
own high-water-mark guarantee.

### Why not syslog to the existing collector

A syslog path — `rsyslog` `imfile` tailing the JSON file, forwarding over TCP to
a new Vector source — was designed, staged and rejected. It is worth recording
why, because it is the obvious answer and it is cheaper:

**For it.** No code change in `mecmcp-audit`. Reuses the collector already
ingesting five device sources. `rsyslog`'s disk-assisted queue gives durability
for free — a collector restart or reboot buffers rather than discards.

**Against it, decisively.** The records are unchained. Anyone with write access
to the collector or the events table can edit history undetectably. Every other
link in this chain is tamper-evident by construction: plan digests bind
approvals, approvals name a distinct principal, `token_verified_fields`
separates vouched-for provenance from asserted. Shipping the trail over an
unchained final hop discards that guarantee at exactly the point an auditor
relies on it.

It also lands in `ssdf.events` — the device-telemetry table — rather than
`ssdf.audit`, where SSDF's own MCP servers already write their tool-call trail.
Two tables for one question is a reporting trap.

**What carries over.** If the direct sink ever needs a local spool, `rsyslog`'s
queue semantics are the reference: unlimited retry, disk-assisted, and
`saveOnShutdown` so a reboot does not discard the backlog. Durability was the one
thing the syslog design got right for free, and the direct sink has to build it
deliberately.

## Field mapping

Owned by the SSDF contract, not restated here. Two rules are called out because
getting them wrong produces a record that looks stronger than it is:

- **The observer is the MCP host**, never the managed device. The device is a
  target field. Conflating them collides with that device's own syslog stream,
  which arrives by a different path with different semantics.
- **`token_verified_fields` must survive into the record.** It names which
  provenance fields the *token* vouched for. Everything else in that group —
  `client_name`, `model_id`, `session_id` — is client-asserted and authenticated
  by nothing. An auditor who cannot tell them apart has been misled.

## Correlation

`request_id` is the join key. It appears on both audit records for a call — the
transport preflight event and the handler event — and, for Junos, in the device's
commit comment as `request.id=`. That is what links an MCP action to the change
it made on the device.

## Part 3 — At rest (normative)

Emission and transport are only worth as much as what the events sit in. Applied
to every deployed server 2026-08-20 (rustjunosmcp#299).

### Sealing

journald Forward Secure Sealing is enabled on every server, via a drop-in at
`/etc/systemd/journald.conf.d/10-audit-sealing.conf`:

```ini
[Journal]
Storage=persistent
Seal=yes
```

plus `journalctl --setup-keys --interval=1month`. Sealing proves integrity only
from the moment the keys exist, so it is the first thing to enable and the one
item on this list that cannot be applied retroactively.

**`journalctl --setup-keys` fails on a minimal Debian 13 image** with
`Failed to generate key pair: Operation not supported`, even though
`systemctl --version` reports `+GCRYPT`. systemd 257 *dlopens* libgcrypt, and
the image does not ship it; the real error is one line above, in
`SYSTEMD_LOG_LEVEL=debug` output — `libgcrypt.so.20 is not installed`.
`apt-get install libgcrypt20` is the whole fix. Nothing about the message points
there, so it is recorded here.

The verification key is printed once. It belongs **off** the machine: capture it
to a root-only file and move it, rather than letting it scroll past in a
terminal.

### Sinks

`--audit-journald` and `--audit-log-file` are additive, not alternatives. A
server that needs the standalone JSONL — `mecmcp-verify` and the bench read it
directly — runs **both**, so the same events get FSS coverage without taking the
file away. That is the resolution of the "per-guest sink question": no server has to
choose.

### Redaction

`--audit-redact <field>=hmac` with `--audit-hmac-key-file`, the key passed **by
path** so it can never appear in `ps` output or a unit file, mode 0600 and owned
by the service user. Pseudonymised values are stable
(`devices=hmac:63206a19…`), so correlation survives export while the inventory
does not leave the box.

Enabling it is a one-way door: events written before it are cleartext and will
not correlate with pseudonymised ones written after. Enable it on a server
before its trail matters, not after.

### Retention

Stated, not inherited, at
`/etc/systemd/journald.conf.d/20-audit-retention.conf`:

```ini
[Journal]
SystemMaxUse=512M
SystemKeepFree=256M
MaxRetentionSec=90day
MaxFileSec=1day
```

Without these, journald sizes itself to 10% of the filesystem and discards
silently — how far back the trail reaches becomes a property of disk pressure
rather than a decision. The tighter of `MaxRetentionSec` and `SystemMaxUse`
wins, so raising one alone silently keeps less than it claims.

JSONL sinks get the equivalent through logrotate: `daily`, `rotate 14`,
`compress`, `copytruncate`, `create 0600 <service> <service>`. The mode matters
— an audit file every account on the box can read is not an audit trail.

## Known gaps

- **Central forwarding via `systemd-journal-upload`/rsyslog is deliberately
  not configured.** The destination this family wants is the hash-chained
  SSDF sink (shipped in 0.14.0, #292; see [Enabling it](#enabling-it)), and
  standing up a second, unchained forwarding path beside it is the thing
  [Why not syslog](#why-not-syslog-to-the-existing-collector) exists to avoid.
  A deployment that wants a second, off-host copy of the same chained
  records can enable
  [the generic forward sink](#a-second-destination-the-generic-forward-sink)
  (MEC-459) instead.
- **The per-call audit stream is not forwarded off-host.** Only
  change-lifecycle evidence (proposal, approval, apply intent, receipt)
  reaches `ssdf.audit`; Part 1's `audit.jsonl` — the per-call tool-call
  trail — stays on the MCP host with no chained off-host copy.
- **The device-side record omits the approver.** A two-person apply commits
  naming only the applier — see
  [rustjunosmcp#307](https://github.com/mechubsec/rustjunosmcp/issues/307).
- **Retention and journald sealing** are done — see Part 3
  ([rustjunosmcp#299](https://github.com/mechubsec/rustjunosmcp/issues/299)).
