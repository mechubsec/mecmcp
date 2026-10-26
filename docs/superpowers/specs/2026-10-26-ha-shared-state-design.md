# Shared state for high availability: change sets, locks, sessions

**Issue:** mecmcp#409 · **Date:** 2026-10-26 · **Status:** Proposed — not scheduled; #409 stays deferred until customer demand

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

**State paths.** Paths in this document are relative to each service's own
state dir, per `docs/FILESYSTEM-LAYOUT.md` (`/var/lib/jmcp`,
`/var/lib/rust-panosmcp`, `/var/lib/proxmoxmcp`, ...). `/var/lib/mecmcp` appears
only as the library default constant and is not used by packaged services.

Severity: **S** = safety (wrong or unaudited change reaches a device),
**A** = availability (requests fail or users re-authenticate), **C** =
convenience (limits drift, nothing wrong is done).

| State | Where | Scope today | Two active instances | Sev |
|---|---|---|---|---|
| Change-set state | `ChangesetCoordinator.state: Mutex<ChangesetState>` (`crates/mecmcp-changeset/src/coordinator.rs:223`), persisted by `persistence.rs` | Loaded once into memory; file is the only copy | Each instance holds a private snapshot and never re-reads. A change set created or approved on A is invisible to B; B's next persist overwrites A's | S |
| Single-writer guard | `StateFileLock::try_acquire_owner` on `<state>.owner`, held in `_owner_lock` (`coordinator.rs:243`, `state_lock.rs`) | `flock(2)`, one kernel | On one host it **already refuses** a second instance: this is the correct failure. On NFS/shared FS, `flock` semantics are filesystem-dependent and cannot be assumed | S |
| Read-modify-write lock | `StateFileLock::acquire` on `<state>.lock` (`state_lock.rs`, MEC-540) | `flock(2)` | Serializes writers on one host only. It guards the file, not the in-memory snapshot, so it does not fix the stale-snapshot problem above | S |
| Per-endpoint op guard | `endpoint_locks: Mutex<BTreeMap<..>>`, `device_guard` (`coordinator.rs:224,641`) | In-process tokio mutex | Two instances apply to the same device concurrently | S |
| Device lock | `FlockDeviceLock` (`crates/mecmcp-device/src/flock.rs`), files named by SHA-256 of device name; `DEFAULT_DEVICE_LOCK_DIR` is `/var/lib/mecmcp/device-locks`, but packaged services use their own state dir (below) | `flock(2)` on a local dir | Mutual exclusion across processes on **one host** only. Two hosts hold the same device lock simultaneously; the "kernel releases on death" property has no analogue across hosts | S |
| MCP sessions | rmcp `LocalSessionManager` wrapped by `LimitedSessionManager` (`crates/mecmcp-transport/src/session.rs`) | In-memory map | A legacy request carrying `mcp-session-id` that lands on the other instance gets 404 and the client must re-initialize. `restore_session` returns `RestoreOutcome::NotSupported` by design (`session.rs:625-670`): restore would bypass the per-token cap and reaper | A |
| Session caps | `LimitedSessionManager` count + per-token counts (`session.rs`), `ConcurrencyState` (`concurrency.rs:30`) | In-process | Effective caps multiply by N | C |
| Rate limiter | token buckets `Arc<Mutex<BucketMap>>` (`rate_limit.rs:205`) | In-process | Effective rate is N times configured; per-IP keying also depends on `trusted_proxies` / `X-Forwarded-For` being right behind the LB | C |
| jti replay store | `ReplayStore` append log, fsync before the approval returns (`approver_replay_store.rs`, #400) | One local file, loaded at open, in-memory map | A replayed approver assertion presented to the *other* instance is accepted: its map has never seen the jti. This is a **new** shared-state hole from 0.29.2 | S |
| Token store | `ArcSwap<TokenStore>` (`crates/mecmcp-auth/src/file.rs:149`), reloaded on **SIGHUP**, not on a timer (README 0.9.0, #266) | Per-process | `token revoke --server-pid` signals one process; every other replica keeps accepting the revoked credential until it is signalled too. Rotate is worse: replicas still accept the old secret | S |
| Device inventory | `FileInventory` holds `devices` in an `Arc<RwLock>` until an explicit `reload()` (`crates/mecmcp-inventory/src/file.rs:34,70`) | Per-process | A standby that loaded inventory at boot, or a new active after takeover, serves a stale device set/policy unless it reloads after acquiring ownership | S |
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

### (a) Active/passive with fenced shared storage

One instance serves; a standby takes over only after the old active is
**provably dead**. State directories live on storage only the active has
writable.

- **Fixes:** every row above, by keeping the invariant the code assumes
  (exactly one process). The `.owner` flock stays as a same-host last line.
- **Fencing must be real.** A lease-file epoch is *not* fencing. A paused
  old active (SIGSTOP, VM freeze, long GC-like stall) that already passed an
  epoch check, or already holds a device lock, can resume after the new
  active publishes epoch N+1 and still write stale state or commit to a
  device. Plain files give no atomic compare-and-set across hosts; the
  device does not validate our epoch; keepalived/VRRP moves an address, it
  does not stop the old process. Required instead: the old active is
  killed or isolated *before* the standby takes the state, by **Proxmox HA
  fencing (hardware/software watchdog self-fence, or STONITH)**, or a
  linearizable lease that the *protected resource* enforces. State what each
  side can enforce: our state files and replay store can refuse stale
  writers only if the storage layer does (fenced block device, exclusive
  mount); Junos/PAN-OS/Proxmox devices **cannot** validate a fencing token,
  so for device commits only process death (fencing) prevents a late
  commit. An epoch in the code is defence in depth, never the guarantee.
- **Storage must be shared or synchronously replicated.** Proxmox
  asynchronous storage replication (ZFS replication) is **rejected**: after
  failover the guest boots from a snapshot older than the active's last
  writes, resurrecting approvals, forgetting spent jtis and un-revoking
  tokens, which re-enables a replayed approval or a duplicate device action.
  Acceptable: shared storage (Ceph RBD, SAN) or a synchronously replicated
  device, with the volume attached to one guest at a time.
- **Does not fix:** session loss on failover (clients re-initialize; the
  stateless revision `2026-07-28`, `concurrency.rs:467`, removes most of
  this) and no horizontal scaling.
- **Cost:** modest code (standby start mode, readiness gate, ordered
  takeover) plus an operator runbook; fencing is the operator's.

### (b) Active/active with an external store

All state moves to a shared store: change sets, device locks, jti,
rate buckets, token store, evidence heads.

- **Fixes:** the state rows, plus scale-out, **once sessions are handled**:
  `LimitedSessionManager::restore_session` returns `NotSupported`, so legacy
  sessions 404 on another replica and per-token session caps multiply by
  replica count. B must also require the stateless protocol, or sticky
  routing, or a shared session manager (which reopens the cap bypass at
  `session.rs:625-670`) before it can claim every row. Token revocation
  needs a shared version notification or signalling every replica.
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

**Option (a): active/passive with watchdog/STONITH fencing and shared or synchronously replicated storage, shipped as a documented
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

- `docs/` runbook: Proxmox HA guest with watchdog fencing, shared or
  synchronously replicated state volume (async replication forbidden),
  required mounts, why not NFS.
- Acceptance: a reader can stand up an active/passive pair on pve2/pve3
  from the doc; a failover drill is recorded in the runbook.
- Tests: none (docs). A drill checklist, run once against the lab rigs.

### Phase 1: standby mode, readiness gate, ordered takeover

- `[ha] mode = "standby"`: startup retries `StateFileLock::try_acquire_owner`
  with backoff. Today a second instance exits with the owner error; that
  stays the default.
- **Readiness.** `/healthz` is unconditional liveness (`health.rs:54`, no
  dependency consulted) and must stay so; `/readyz` runs `ReadinessCheck`s
  and can return 503 (`health.rs:72-97`). Add an ownership check that fails
  until this process holds the owner lock. The load balancer / HA manager
  gates traffic on `/readyz`, never `/healthz`.
- **Configuration is not on the shared volume.** `docs/FILESYSTEM-LAYOUT.md:40-55`
  keeps `devices.json`, `audit-hmac.key`, `credentials.env` and TLS material
  in `/etc/<binary-name>/`, outside `/var/lib/<binary-name>/`. Reloading the
  standby's *local* `devices.json` at takeover can therefore load a stale
  inventory/policy that the active has since changed. Require either
  configuration on the shared volume (or a symlink/bind of `/etc/<svc>` to
  it) or synchronous config distribution, **and** a config-version check:
  a hash/version marker lives on the shared volume and is written
  **only by the config-distribution step** (the operator's deploy/sync of
  `/etc/<svc>`), never by the server on reload. Every reload, including
  takeover, is **compare-only**: the node's loaded config hash must equal
  the existing marker or `/readyz` stays 503. A missing or mismatched
  marker means not ready, never "assume current", and a node never
  publishes a marker from its own loaded config, so a stale standby cannot
  self-certify v1 over the active's v2. There is **no**
  server-side marker-publication command, now or optional. The
  config-distribution step must hold the deployment lock and replace the
  marker with an atomic rename. **Before the rename it quiesces the owner**:
  it asks the server to stop admitting `/mcp` requests (503 + `Retry-After`)
  and waits until the in-flight count reaches zero; only then does it rename
  the marker and trigger the reload, and admission resumes once the loaded
  hash equals the new marker. Admission and the in-flight counter share one
  lock with the quiesce flag, so no request can pass the check under H1 and
  run after the marker becomes H2.
- **`/readyz` is not enough.** The readiness check gates only the
  load-balancer's view (`health.rs:72-84`), not `/mcp`, so requests could
  still run on stale or premature config. While the loaded hash differs
  from the marker (including during any config reload), `/mcp` returns 503
  with `Retry-After`; in-flight requests finish (drain), new ones are
  refused, and service resumes only when loaded hash == marker. This
  applies on the active too: a config edit on the shared volume pauses new
  requests until the active has reloaded to match.
- **Takeover order:** acquire owner lock, then read state file, replay store
  and `tokens.json`, then **(re)load `FileInventory` and config** (explicit
  `reload()`, `file.rs:70`; it does not refresh itself) and verify the
  config version, then open the
  evidence recorder, then report ready. A standby never serves from data
  read before it owned the lock.
- Acceptance: while the active lives the standby is not ready and has read
  no state; after fenced death of the active the standby is ready only
  after inventory reload, and sees every change set the active persisted.
- Tests (deterministic, not sampled): a test hook records every
  critical-section entry and exit with a global sequence number; any
  overlap of two owners fails the run. Contenders are released from a
  barrier at the acquisition call, so a brief dual-owner window cannot hide
  between samples. Run N=8 contenders over 1000 kill/restart cycles and
  assert persisted state is monotone. A readiness test asserts `/readyz`
  is 503 for a non-owner while `/healthz` is 200, and that inventory
  reload happens-before ready, and that a standby whose local
  `devices.json` differs from the shared version file stays 503. Add a deterministic interleaving test (fake clock, barrier between
  "marker replaced" and "reload completes"): a request arriving after
  quiesce gets 503 + `Retry-After`; a request admitted before quiesce
  completes before the rename (the rename waits for in-flight = 0); a request
  that passes the admission check immediately before quiesce is set is either
  counted in-flight (and drained) or refused, never run after the rename; so no
  request ever executes under a hash != marker. Add a test where a stale
  standby takes ownership and reloads: the marker must be byte-identical
  afterwards and the node not ready.
- Sabotage check, **separate** test run: delete the `try_acquire_owner`
  call; the overlap test must fail. Likewise remove the inventory reload;
  the stale-inventory test must fail; so must a run with the version check
  removed.

### Phase 2: defence-in-depth epoch (not fencing)

- A lease file carries a monotonic epoch bumped by whoever takes the owner
  lock; state writes and replay appends refuse if a higher epoch is on
  disk. This narrows, but cannot close, the paused-writer window: a writer
  paused between the check and the write is stopped only by fencing
  (Phase 0 requirement) or by storage that rejects the stale writer.
- Acceptance: documented as best-effort; a SIGSTOPped, superseded, resumed
  instance that has not yet been fenced is refused at the next check.
- Tests: deterministic interleaving with a fake filesystem for "old active
  resumes after the check" must be shown to **still write** on plain files,
  and the doc says so; the guarantee is asserted only for a fencing-capable
  storage fake. Separate sabotage run drops the epoch comparison.

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
- Shipping a fencing agent. We document and consume what Proxmox HA
  (watchdog/STONITH) provides. keepalived/VRRP alone is **excluded**: it
  moves an address and does not stop the old process. Bare metal is
  supported only with an independent watchdog or STONITH device in front
  of the takeover; VRRP may sit beside it for the address, never in place
  of it.

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
   the container), or do customers run bare metal? Bare metal is only in
   scope with an independent watchdog/STONITH; is that acceptable, or is
   Phase 0 Proxmox-only?
4. Should an HA-capable deployment give each instance a distinct `server_id`
   for evidence, and does the SSDF verifier treat that as one logical
   server? Today it groups by `(tier, server_id)`.
5. Token reload is SIGHUP-driven, so revocation under any multi-replica
   topology needs every replica signalled or a shared version notification.
   Which? (Under (a) only the active needs it, but a standby must reload
   at takeover, covered in Phase 1.)
6. Does the jti replay store need a retention bump on failover (assertion
   lifetime is the floor)?
7. Codex review (dd6a316) asserted a `/var/lib/mecmcp` state path; verified:
   it is only the `DEFAULT_DEVICE_LOCK_DIR` constant in
   `crates/mecmcp-device/src/flock.rs`, packaged services use per-service
   dirs. Does each service pass its own dir to `FlockDeviceLock` in its
   repo? Not checked here (consumers live outside this repo).
