# Shared state for high availability: change sets, locks, sessions

**Issue:** mecmcp#409 · **Date:** 2026-10-26 · **Status:** deferred, design only

This is a design spike. **No code changes ship with this document.** Per the
issue, no Proxmox customer has asked for HA and a single instance is acceptable
for most shops, so this exists to make the eventual decision cheap, not to
schedule work. Size stays L.

## Problem, precisely

Every server in the family runs as exactly one process. The family keeps its
safety properties (one writer per change set, one holder per device, one
audit chain per run) by relying on that. Running two active instances behind
a load balancer does not degrade gracefully: some state is protected only by
in-process mutexes, and some by a lock whose scope is one host. This
document inventories each, says what breaks, and picks the cheapest design
that keeps the safety properties.

## Inventory of per-process / per-host state

Severity: **S** = safety (wrong or unaudited change reaches a device),
**A** = availability (requests fail or users re-authenticate), **C** =
convenience (limits drift, nothing wrong is done).

| State | Where | Scope today | Two active instances | Sev |
|---|---|---|---|---|
| Change-set state | `ChangesetCoordinator.state: Mutex<ChangesetState>` (`crates/mecmcp-changeset/src/coordinator.rs:223`), persisted by `persistence.rs` | Loaded once into memory; file is the only copy | Each instance holds a private snapshot and never re-reads. A change set created or approved on A is invisible to B; B's next persist overwrites A's | S |
| Single-writer guard | `StateFileLock::try_acquire_owner` on `<state>.owner`, held in `_owner_lock` (`coordinator.rs:243`, `state_lock.rs`) | `flock(2)`, one kernel | On one host it **already refuses** a second instance: this is the correct failure. On NFS/shared FS, `flock` semantics are filesystem-dependent and cannot be assumed | S |
| Read-modify-write lock | `StateFileLock::acquire` on `<state>.lock` (`state_lock.rs`, MEC-540) | `flock(2)` | Serializes writers on one host only. It guards the file, not the in-memory snapshot, so it does not fix the stale-snapshot problem above | S |
| Per-endpoint op guard | `endpoint_locks: Mutex<BTreeMap<..>>`, `device_guard` (`coordinator.rs:224,641`) | In-process tokio mutex | Two instances apply to the same device concurrently | S |
| Device lock | `FlockDeviceLock` (`crates/mecmcp-device/src/flock.rs`), files named by SHA-256 of device name under `/var/lib/mecmcp/device-locks` | `flock(2)` on a local dir | Mutual exclusion across processes on **one host** only. Two hosts hold the same device lock simultaneously; the "kernel releases on death" property has no analogue across hosts | S |
| MCP sessions | rmcp `LocalSessionManager` wrapped by `LimitedSessionManager` (`crates/mecmcp-transport/src/session.rs`) | In-memory map | A request carrying `mcp-session-id` that lands on the other instance gets 404 and the client must re-initialize. `restore_session` returns `RestoreOutcome::NotSupported` by design (`session.rs:625-670`): restore would bypass the per-token cap and reaper | A |
| Session caps | `LimitedSessionManager` count + per-token counts (`session.rs`), `ConcurrencyState` (`concurrency.rs:30`) | In-process | Effective caps multiply by N | C |
| Rate limiter | token buckets `Arc<Mutex<BucketMap>>` (`rate_limit.rs:205`) | In-process | Effective rate is N times configured; per-IP keying also depends on `trusted_proxies` / `X-Forwarded-For` being right behind the LB | C |
| jti replay store | `ReplayStore` append log, fsync before the approval returns (`approver_replay_store.rs`, #400) | One local file, loaded at open, in-memory map | A replayed approver assertion presented to the *other* instance is accepted: its map has never seen the jti. This is a **new** shared-state hole from 0.29.2 | S |
| Token store | `ArcSwap<TokenStore>` hot-reload of `tokens.json` (`crates/mecmcp-auth/src/file.rs:149`) | Per-process reload | Each instance reloads independently. A revoked token is live on a lagging instance for up to one reload interval; `mint`/`rotate` write one host's file | S (revocation lag), A |
| Audit chain / evidence | `EvidenceRecorder`: "One recorder per `(server_id, run_id)`"; a second recorder "forks the chain, and a fork verifies as two valid chains rather than as an error" (`crates/mecmcp-audit/src/recorder.rs:15-21`) | In-process head, per-run | Two writers sharing a `server_id` produce undetectable forks, so evidence can silently omit an apply. Distinct `server_id`s per instance are safe by construction | S |
| Delivery ledger | `sinks/delivery_ledger.rs` | Local file | Per-instance; harmless if each instance has its own `server_id`, wrong if shared | C |
| Idempotency cache | none found in `crates/` | n/a | Nothing to share. Retried applies are handled by change-set state (so they inherit its severity) | n/a |
| Auth-failure tracker | none separate from the rate limiter (`rate_limit.rs`) | n/a | Same as rate limiter | C |
| Job polling | `mecmcp-job` poll loops | In-process | A job started on A is polled by A only; status calls on B cannot see it | A |

Two findings worth recording:

1. The audit-chain doc comment is the most honest sentence in the codebase
   about this topic. Whatever design is chosen must make "two recorders on one
   run" structurally impossible, because nothing downstream can detect it.
2. The 0.29.2 replay store made the HA gap *larger*, not smaller: before it,
   a restart already forgot jtis; now the store is durable on one host and
   meaningless on a second.

## Options

### (a) Active/passive with shared storage and fencing

One instance serves; a standby is started only when the active is fenced.
State directories (`/var/lib/mecmcp/*`) live on storage only the active
mounts, or on a replicated block device.

- **Fixes:** every row above, by keeping the invariant the code already
  assumes (exactly one process). The existing `.owner` flock becomes the
  last line of defence, not the first.
- **Needs:** a fencing story. Without it, a partitioned old active that
  still believes it is active is the two-writer case. Proxmox gives this for
  free for guests: HA manager with a guest on shared or replicated storage
  fences by watchdog and restarts the guest elsewhere. Outside Proxmox, a
  lease with a monotonically increasing fencing token that the device-lock
  path and state writes check.
- **Does not fix:** session loss on failover (clients re-initialize; the
  stateless protocol revision, `2026-07-28`, already referenced in
  `concurrency.rs:467`, removes most of this pain), and no horizontal
  scaling.
- **Cost:** near zero code. Runbook, a `--standby` start mode that waits on
  the `.owner` lock rather than exiting, and a documented requirement that
  the state dir not be on NFS unless the filesystem's `flock` is proven.

### (b) Active/active with an external store

All state moves to a shared store: change sets, device locks, jti,
rate buckets, token store, evidence heads.

- **Fixes:** everything, including scale-out.
- **Store choice.** ClickHouse is already in the stack for SSDF but is wrong
  here: no transactions, no compare-and-set, eventual merges. A
  linearizable store is required for locks and the jti check: Postgres
  (advisory locks, `SELECT ... FOR UPDATE`, `INSERT ... ON CONFLICT` for
  jti) or etcd (leases, txn). Postgres is the smaller step for operators.
- **Cost, honestly:** this is the issue's "Size L" and then some. It adds a
  network dependency to a family whose rule is offline-first, makes every
  state change a distributed-systems problem (lease expiry during a slow
  device commit is the classic one: the lock is lost mid-apply), forces the
  evidence chain onto a single-writer-per-run election anyway (so it still
  needs (a)'s fencing for that component), and adds a database to the
  threat model and the SBOM. Per-device lock lease expiry must be longer
  than the longest commit, which on Junos with commit-confirmed is minutes.

### (c) Sticky sessions with per-instance state

LB pins a client or token to an instance; state stays local.

- **Fixes:** MCP session 404s and (mostly) per-instance rate limits.
- **Does not fix:** anything marked **S**. Change-set state, device locks,
  jti replay and audit forks are all cross-client; stickiness by client does
  not make two clients' changes to one device serialize. This is the option
  that looks like HA and reintroduces the lost-update bug MEC-540 fixed.
  Rejected on safety grounds; acceptable only as a supplement to (b).

## Recommendation

**Option (a): active/passive, with fencing, shipped as a documented
topology plus a small amount of code.** It keeps the one-writer invariant
the whole safety story (change-set lifecycle, evidence chain, device locks,
replay store) was built on, costs a few hundred lines rather than a new
dependency, preserves offline-first, and matches what "a single instance is
acceptable for most Proxmox shops" implies about the audience: they want
fast recovery, not scale-out. Cost accepted: failover is seconds to a
minute, sessions are lost on failover, throughput does not scale, and the
operator owns fencing. Revisit (b) only if a customer needs scale-out, not
just survival.

## Phased plan

Each phase is independently shippable and **default off**; nothing changes
for a single-instance deployment.

### Phase 0: document the supported topology

- `docs/` runbook: Proxmox HA guest, shared/replicated state volume,
  required mounts, why not NFS.
- Acceptance: a reader can stand up an active/passive pair on pve2/pve3
  from the doc; a failover drill is recorded in the runbook.
- Tests: none (docs). A drill checklist, run once against the lab rigs.

### Phase 1: standby mode and ownership

- `--standby` / `[ha] mode = "standby"`: startup blocks on
  `StateFileLock::try_acquire_owner` with backoff, serves `/healthz` as
  not-ready until it wins, then loads state. Today a second instance exits
  with the owner error; that stays the default.
- Load order: take owner lock, **then** read state, replay store and token
  file, **then** open evidence. Never the reverse.
- Acceptance: with the active alive, standby never reads state; after the
  active is killed (SIGKILL), standby is ready within the poll interval and
  sees every change set the active persisted.
- Tests that prove the race is impossible, not unlikely:
  - Process-level: spawn N=8 instances against one state dir; assert
    exactly one holds the owner lock at any sampled instant, across 1000
    random SIGKILL/restart cycles, and that the persisted state is monotone
    (no change-set state ever moves backward).
  - Sabotage: delete the `try_acquire_owner` call, rerun, assert the test
    fails (per the repo's habit: prove the test can fail).

### Phase 2: fencing token

- A lease file (`<state>.lease`) carrying a monotonically increasing epoch,
  incremented by whoever takes the owner lock. State writes, device-lock
  acquisition and replay-store appends carry the epoch and refuse if a
  higher epoch is on disk. Closes the partitioned-old-active case that
  `flock` alone cannot, notably on non-local filesystems.
- Acceptance: a stale instance that is SIGSTOPped, superseded, then resumed
  cannot persist a change set, take a device lock, or record a jti.
- Tests: SIGSTOP/SIGCONT test as above; a loom-free deterministic test where
  a fake clock and fake filesystem interleave "old active resumes mid
  `write_state`" and assert the write is rejected. Sabotage: drop the epoch
  comparison, assert failure.

### Phase 3: session continuity (optional)

- Make the stateless protocol revision the supported client path for HA, and
  document that legacy sessions are lost on failover. No shared session
  store: `restore_session` stays `NotSupported` because restore bypasses
  the caps (`session.rs:625-670`).
- Acceptance: a client on `MCP-Protocol-Version >= 2026-07-28` survives
  failover without re-initialize.
- Tests: transport test issuing the same sessionless call to old and new
  instance.

### Phase 4: option (b) components, only if un-deferred for scale-out

Not planned. If needed, order by safety: jti store, then device locks, then
change-set state, with the evidence chain last and election-based. Each
needs the Phase 2 epoch semantics reimplemented as store leases.

## Non-goals

- Active/active in this milestone; scale-out throughput.
- Sticky sessions as a safety mechanism.
- A shared audit chain across instances. Each instance keeps its own
  `server_id`, or runs under the single-active guarantee.
- Cross-site / multi-region.
- Changing the device-side model (Proxmox cluster HA, SRX chassis cluster
  are the devices' own concern).
- Shipping a fencing agent. We document and consume what Proxmox HA or
  keepalived provide.

## Trigger for un-deferring

A customer states an availability requirement the single instance cannot
meet (recovery time or maintenance windows), per the issue. Phase 0 and 1
should then be scheduled together; Phase 4 needs a separate scale-out
request.

## Open questions

1. Is "failover in under a minute, sessions lost" an acceptable promise, or
   does any customer need in-flight apply continuity? An apply in progress
   when the active dies is today recovered by `recovery.rs`; is that
   sufficient under failover?
2. Is a shared filesystem (NFS/CephFS) in scope? If yes, Phase 2's epoch is
   mandatory, not optional, since `flock` there is not trustworthy.
3. Are the fleet's LXC guests expected to be the HA unit (Proxmox HA on
   the container), or do customers run bare-metal Linux with keepalived?
   This decides whether Phase 0 is Proxmox-specific.
4. Should an HA-capable deployment give each instance a distinct `server_id`
   for evidence, and does the SSDF verifier treat that as one logical
   server? Today it groups by `(tier, server_id)`.
5. Token revocation lag (reload interval) matters more under HA. Do we want
   a reload-on-demand signal as part of Phase 1?
6. Does the jti replay store need a retention bump on failover (assertion
   lifetime is the floor)?
