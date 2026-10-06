# Filesystem layout standard for mechub MCP servers

**Part of [#6](https://github.com/mechubsec/mecmcp/issues/6).** Reconfirmed and
closed out across all six vendor servers by
[#356](https://github.com/mechubsec/mecmcp/issues/356), which followed on
[#28](https://github.com/mechubsec/mecmcp/issues/28) — see
[Status: all six servers verified compliant](#status-all-six-servers-verified-compliant-356)
at the bottom.

## Problem

The two shipping servers chose different layouts:

| | rust-junosmcp | rust-panosmcp |
|---|---|---|
| **Config dir** | `/etc/jmcp` | `/etc/rust-panosmcp` |
| **Service user** | `jmcp` | `rust-panosmcp` |
| **State dir** | `/var/lib/jmcp` | `/var/lib/rust-panosmcp` |
| **Inventory** | `/etc/jmcp/devices.json` | `/etc/rust-panosmcp/devices.json` |
| **Tokens (junos)** | `/etc/jmcp/tokens.json` | n/a |
| **Tokens (panos)** | n/a | `/var/lib/rust-panosmcp/tokens.json` |

Neither is wrong in isolation, but an operator managing both types them differently for no technical reason. Any shared tooling — backup scripts, config management, log shipping, monitoring — needs a per-vendor path table.

The placement of `tokens.json` diverges across servers **and within the same server** between deployments. The PAN-OS production guest keeps tokens at `/var/lib/rust-panosmcp/tokens.json`; the shipped installer would create them at `/etc/rust-panosmcp/tokens.json`. The Junos production guest keeps them at `/etc/jmcp/tokens.json`.

This has already caused operational friction: upgrading the old PAN-OS test rig (now retired) required correcting a systemd drop-in that pointed at the wrong path, because production (the PAN-OS production guest) and the installer disagreed on the canonical location.

## The config vs state split

**`tokens.json` is state, not config.** The server rewrites it on `token add`, `token rotate`, and `token revoke`. By FHS and systemd-tmpfiles principles:

- `/etc/<svc>`: files the operator edits and the server only reads
- `/var/lib/<svc>`: files the server writes

The current split puts a server-written file under `/etc`, which is why an atomic write there needs the **directory** writable — a subtlety that surfaced as a confusing `Permission denied ... at path "/etc/jmcp/.tokens-KNnZkm.tmp"` when only the files, not the directory, had been chowned.

## Standard layout

```
/etc/<binary-name>/
    devices.json                          # read-only inventory (operator-edited)
    audit-hmac.key                        # HMAC key for redaction (mode 0600)
    credentials.env                       # API keys, tenant IDs (mode 0600)
    *.crt, *.key                          # TLS if applicable (keys mode 0600)

/var/lib/<binary-name>/
    tokens.json                           # server-written token state (mode 0600)
    changeset-state.json                  # change-set lifecycle state
    mutation-state.json                   # PAN-OS change-set state
    device-leases/                        # Junos device-lease directory
    staging/                              # Junos file-transfer staging
    srx-staging/                          # Junos SRX support-bundle staging
    audit.jsonl                           # local audit log (if not journald-only)
```

**Service name == binary name.** Use the full crate name as the binary, service, and directory name. No abbreviations unless inherited from an already-deployed system.

| Repo | Binary | Service user | Config | State |
|---|---|---|---|---|
| `RustJunosMCP` | `rust-junosmcp` | `rust-junosmcp` | `/etc/rust-junosmcp` | `/var/lib/rust-junosmcp` |
| `rust-panosmcp` | `rust-panosmcp` | `rust-panosmcp` | `/etc/rust-panosmcp` | `/var/lib/rust-panosmcp` |
| `rustsdcmcp` | `rustsdcmcp` | `rustsdcmcp` | `/etc/rustsdcmcp` | `/var/lib/rustsdcmcp` |
| `rustproxmoxmcp` | `rust-proxmoxmcp` | `proxmoxmcp` | `/etc/proxmoxmcp`\* | `/var/lib/proxmoxmcp`\* |
| `rustunifimcp` | `rustunifimcp` | `unifimcp` | `/etc/unifimcp`\* | `/var/lib/unifimcp`\* |
| `rustmistmcp` | `rustmistmcp` | `rustmistmcp` | `/etc/rustmistmcp` | `/var/lib/rustmistmcp` |
| `rustopnsmcp` | `rustopnsmcp` | `rustopnsmcp` | `/etc/rustopnsmcp` | `/var/lib/rustopnsmcp` |

\* `rustproxmoxmcp` and `rustunifimcp` ship with an abbreviated directory/service-user
base (`proxmoxmcp`, `unifimcp`) that drops the `rust(-)` prefix from the binary name —
a second, deliberate naming exception alongside `jmcp` below, not a rule violation to
fix. Every other column (config vs. state split, `tokens.json` placement) still holds.

## The `jmcp` exception

**the Junos production guest** (the live Junos deployment on the hypervisor node) uses `/etc/jmcp`, `/var/lib/jmcp`, and service user `jmcp`. This predates the standard and is **protected from breaking changes** per PLAN.md.

The standard requires `rust-junosmcp` to honour the existing paths **if present**, and use the standard paths on a fresh install:

```rust
// Example path resolution (conceptual — actual implementation in mecmcp-server)
let config_dir = if Path::new("/etc/jmcp/devices.json").exists() {
    "/etc/jmcp"           // legacy deployment
} else {
    "/etc/rust-junosmcp"  // standard layout
};

let state_dir = if Path::new("/var/lib/jmcp").exists() {
    "/var/lib/jmcp"
} else {
    "/var/lib/rust-junosmcp"
};
```

**No new deployments use the abbreviated form.** A fresh install of `RustJunosMCP` deploys as `rust-junosmcp`, not `jmcp`. The exception exists only to prevent breaking the existing Junos deployment.

## the PAN-OS production guest: the tokens.json discrepancy

**the PAN-OS production guest** (live PAN-OS on the hypervisor node) keeps `tokens.json` at `/var/lib/rust-panosmcp/tokens.json`, which is correct under this standard. However, **the shipped installer as of 0.4.0 would create it at `/etc/rust-panosmcp/tokens.json`**, which is wrong.

### Migration for rust-panosmcp

The `rust-panosmcp` installer must:

1. Check `/var/lib/rust-panosmcp/tokens.json` first (production layout)
2. If absent, check `/etc/rust-panosmcp/tokens.json` (old installer layout)
3. If found in `/etc`, **do not move it automatically** — print a warning and exit:

```
WARNING: tokens.json found at /etc/rust-panosmcp/tokens.json (deprecated location).

The standard location is /var/lib/rust-panosmcp/tokens.json. To migrate:

  sudo systemctl stop rust-panosmcp
  sudo mv /etc/rust-panosmcp/tokens.json /var/lib/rust-panosmcp/tokens.json
  sudo chown rust-panosmcp:rust-panosmcp /var/lib/rust-panosmcp/tokens.json
  sudo chmod 0600 /var/lib/rust-panosmcp/tokens.json
  # Update the unit file or drop-in to point to the new path
  sudo systemctl daemon-reload
  sudo systemctl start rust-panosmcp
```

4. On a fresh install, create `tokens.json` at `/var/lib/rust-panosmcp/tokens.json` only.

**The unit file ships with the standard path** (`--tokens-file /var/lib/rust-panosmcp/tokens.json`). A deployment with tokens in `/etc` must use a drop-in to override it until migrated.

## Why tokens must be in /var/lib

1. **FHS compliance:** `/etc` is for static config; `/var/lib` is for variable state that survives reboots. Tokens are minted, rotated, and revoked by the server.

2. **Atomic writes need directory ownership:** The server writes `tokens.json` atomically via a temp file in the same directory. If the directory is `/etc/<svc>` with mode 0750 and group ownership (as is correct for a config dir where the operator may need to read other files), the service user cannot create the temp file:

   ```
   Permission denied (os error 13) at path "/etc/jmcp/.tokens-KNnZkm.tmp"
   ```

   Fixing this means making `/etc/<svc>` mode 0700 owned by the service user, which blocks root's ability to edit `devices.json` and other config without `sudo -u <svc>`, which is wrong.

3. **Separate backup/restore flows:** Config in `/etc` goes into config management (tracked, versioned, immutable deployments). State in `/var/lib` goes into operational backups (frequent, encrypted, retained). Tokens are secrets that belong in the latter, not the former.

## Permissions

| File | Mode | Owner | Group | Reason |
|---|---|---|---|---|
| `/etc/<svc>/` | 0750 | root | `<svc>` | Config dir readable by service |
| `/etc/<svc>/devices.json` | 0600 | `<svc>` | `<svc>` | Operator edits as root, service reads; `read_hardened_file` refuses any group- or world-accessible inventory |
| `/etc/<svc>/audit-hmac.key` | 0600 | `<svc>` | `<svc>` | Secret, service rewrites (on rotate) |
| `/etc/<svc>/credentials.env` | 0600 | `<svc>` | `<svc>` | API keys |
| `/var/lib/<svc>/` | 0700 | `<svc>` | `<svc>` | State dir, service writes |
| `/var/lib/<svc>/tokens.json` | 0600 | `<svc>` | `<svc>` | mecmcp-auth enforces this |
| `/var/lib/<svc>/*.json` | 0600 | `<svc>` | `<svc>` | All state files |

**The 0600 requirement on tokens.json is enforced by mecmcp-auth.** If the file is group- or world-readable, the server refuses to start:

```
Error: token file /var/lib/<svc>/tokens.json is readable by group or world (mode: 0640)
```

An installer that creates the file with a looser mode produces a service that will not start. This is deliberate: it is safer to refuse than to start insecurely.

## systemd-sysusers and systemd-tmpfiles

Every repo ships:

- `packaging/systemd/<binary>.sysusers`
- `packaging/systemd/<binary>.tmpfiles`

### Example sysusers file (rust-panosmcp.sysusers)

```
u rust-panosmcp - "PAN-OS MCP service" /var/lib/rust-panosmcp /usr/sbin/nologin
```

### Example tmpfiles file (rust-panosmcp.tmpfiles)

```
d /etc/rust-panosmcp          0750 root           rust-panosmcp -
d /var/lib/rust-panosmcp      0700 rust-panosmcp  rust-panosmcp -
```

The installer calls:

```bash
systemd-sysusers packaging/systemd/<binary>.sysusers
systemd-tmpfiles --create packaging/systemd/<binary>.tmpfiles
```

## Installer requirements

Every `packaging/lxc/install.sh` must:

1. Create the service user via `systemd-sysusers`
2. Create directories via `systemd-tmpfiles`
3. If `tokens.json` does not exist at the standard location, create it:
   ```bash
   printf '%s\n' '{"version":1,"tokens":[]}' > /var/lib/<svc>/tokens.json
   ```
4. `chmod 0600` the token file
5. `chown <svc>:<svc>` the token file
6. If `audit-hmac.key` does not exist, generate it:
   ```bash
   umask 077
   head -c 32 /dev/urandom > /etc/<svc>/audit-hmac.key
   chown <svc>:<svc> /etc/<svc>/audit-hmac.key
   ```
7. Never overwrite existing state files (`tokens.json`, `changeset-state.json`, `mutation-state.json`)
8. Print the next steps, including paths to edit

## Deployed systems: what changes

### the Junos production guest (rust-junosmcp on the hypervisor node) — NO CHANGE REQUIRED

The existing `/etc/jmcp` and `/var/lib/jmcp` layout is **locked in** and remains supported. The standard requires new code to detect and honour these paths when present.

### the PAN-OS production guest (rust-panosmcp on the hypervisor node) — tokens.json already correct

`tokens.json` is already at `/var/lib/rust-panosmcp/tokens.json`, which is the standard location. **No migration needed.**

The shipped unit file as of 0.5.0+ must reference `/var/lib/rust-panosmcp/tokens.json` by default. If an older deployment has a drop-in pointing elsewhere, that drop-in will continue to work (it overrides the shipped unit).

### the SDC guest (rustsdcmcp on the hypervisor node) — verified compliant

Confirmed via #356: `rustsdcmcp` matches the standard (`/etc/rustsdcmcp`,
`/var/lib/rustsdcmcp`, `tokens.json` in `/var/lib`). `main.rs` resolves the
configured token path against the canonical `/var/lib/rustsdcmcp/tokens.json`
with a byte-exact comparison (not `Path` equality, which would normalize away
a typo'd trailing separator) and falls back to a legacy path only when the
configured path is exactly the canonical one — an explicit custom path that is
absent fails outright rather than silently reactivating an unrelated store.
`scripts/verify-packaging.sh` asserts the unit's `ExecStart`, `ReadOnlyPaths`,
and `ReadWritePaths` against this layout on every CI run, so a regression
fails the build instead of surfacing at the next restart.

### the Mist guest (rustmistmcp) — tokens.json moved between releases, drop-in broke

`rustmistmcp`'s `tokens.json` moved from `/etc/rustmistmcp/` to
`/var/lib/rustmistmcp/` between releases without a compatibility shim. A
systemd drop-in restored from an older backup still pointed at the `/etc`
path, and the service would not start until the path was corrected by hand —
the same class of failure as the PAN-OS case above, just discovered via a
restore instead of a fresh install.

`rustmistmcp` now carries the same canonical/legacy resolver as
`rustsdcmcp` and `rustproxmoxmcp`: the shipped unit's `--tokens-file` points at
`/var/lib/rustmistmcp/tokens.json`, and if that canonical path is what was
configured but the file isn't there yet, the resolver looks for a store at the
old `/etc/rustmistmcp/tokens.json` location and warns loudly (`tracing::warn!`
naming both paths) rather than either refusing outright or silently starting
with an empty store. A configured path that is neither the canonical location
nor found at all still fails startup — the fallback exists only to bridge the
one specific rename, not to paper over an arbitrary missing file.

## New deployments

All new MCP servers (`rustproxmoxmcp`, `rustunifimcp`, `rustmistmcp`, and any
future vendors) adopt the config-vs-state split from day one:

- Config in `/etc/<dir-base>`
- State in `/var/lib/<dir-base>`
- `tokens.json` in `/var/lib/<dir-base>/tokens.json`
- Service user == directory base

`rustmistmcp` also matches binary name == service name == directory base
exactly. `rustproxmoxmcp` and `rustunifimcp` shipped with the abbreviated
directory base noted above (`proxmoxmcp`, `unifimcp`) instead of the full
binary name — accepted as a naming exception, not fixed retroactively, since
renaming a live service's config/state directories is itself a migration
with the same operational risk this document exists to avoid. Any future
vendor should use the full binary name as the directory base unless there is
a comparable reason not to.

## Decision: directory base and devices.json mode

**Status:** recommended by the rustopnsmcp v1.0 plan, awaiting board
confirmation. Until confirmed, the recommendation below is what new code
follows.

**Directory base.** A new server uses its full binary name as the directory
base and service user: `/etc/<binary>`, `/var/lib/<binary>`, user
`<binary>`. `rustopnsmcp` is therefore `/etc/rustopnsmcp`,
`/var/lib/rustopnsmcp`, user `rustopnsmcp`. The short names `jmcp`,
`proxmoxmcp` and `unifimcp` are deployed exceptions and are not a rule for new
servers. `mecmcp_secret::naming::known` records each server's base, and its
rule text says the same thing as this section.

**devices.json mode.** `0600`, owned by the service user. This is what
`mecmcp_inventory::FileInventory::load` enforces through
`mecmcp_secret::read_hardened_file`: any group- or world-accessible inventory
is refused, and so is one owned by another non-root uid. An operator edits it
as root (root may read any owner's file). An installer must create it `0600`
and `chown <svc>:<svc>` it. `0640 root:<svc>`, which this document used to
give, produces a service that refuses to start.

`crates/mecmcp-inventory/tests/filesystem_layout_doc.rs` fails if this
section or the Permissions table drifts from the loader.

## Verification

For each repo, the packaging tests must assert:

1. The sysusers file declares the correct user and home directory
2. The tmpfiles file declares the correct directories with correct modes
3. The unit file references the standard paths for `--tokens-file`, `--state-file`, etc.
4. The installer creates `tokens.json` at the standard location with mode 0600
5. The installer does not overwrite existing `tokens.json`

See `rustsdcmcp/scripts/verify-packaging.sh` for a reference implementation of these checks.

## Status: all six servers verified compliant (#356)

A 2026-09-07 rebuild of all twelve test rigs across the six servers hit the
exact class of failure this document was written to prevent, twice —
`rustproxmoxmcp` and `rustmistmcp` both failed a restart or drop-in restore
because the configured `tokens.json` path and the file's actual location
disagreed. [#356](https://github.com/mechubsec/mecmcp/issues/356) tracked
closing that gap for good. As of this update, every vendor server has been
verified against the standard in this document:

| Repo | Config | State (`tokens.json`) | Canonical/legacy fallback |
|---|---|---|---|
| `rust-junosmcp` | `/etc/jmcp`\* | `/var/lib/jmcp`\* | `resolve_tokens_with` |
| `rust-panosmcp` | `/etc/rust-panosmcp` | `/var/lib/rust-panosmcp` | no resolver — the configured path is used verbatim and fails if absent; the legacy `/etc` store is never read automatically, only warned about if present and not the configured path (`main.rs:92`) + stale-secret scan |
| `rustsdcmcp` | `/etc/rustsdcmcp` | `/var/lib/rustsdcmcp` | `resolve_tokens_with` + stale-secret scan |
| `rustproxmoxmcp` | `/etc/proxmoxmcp` | `/var/lib/proxmoxmcp` | `resolve_tokens_with` + stale-secret scan |
| `rustmistmcp` | `/etc/rustmistmcp` | `/var/lib/rustmistmcp` | `resolve_tokens_with` + stale-secret scan |
| `rustunifimcp` | `/etc/unifimcp` | `/var/lib/unifimcp` | none needed — shipped `/var/lib`-only from its first release, never had an `/etc` token store to migrate away from |
| `rustopnsmcp` | `/etc/rustopnsmcp` | `/var/lib/rustopnsmcp` | none needed -- ships `/var/lib`-only from its first release (verified at its P2 packaging gate, not yet released) |

\* `rust-junosmcp` also honours the locked-in `jmcp` exception paths; see
above.

`rust-junosmcp`, `rustsdcmcp`, `rustproxmoxmcp`, and `rustmistmcp` implement
the same `resolve_tokens_with` pattern: the configured path is used verbatim
and fails if absent, **except** when it is byte-exact-equal to the server's
own canonical `/var/lib` path, in which case an absent canonical file falls
back to the legacy `/etc` location with a `tracing::warn!` naming both paths.
A typo, or a deliberately different custom path, never reaches the fallback —
it fails startup immediately, which is the fail-loud behavior a bad drop-in
restore needs surfaced at start time rather than discovered mid-incident.
Each of these four servers carries unit tests exercising exactly this: the
fallback firing, a custom path never falling back, and a trailing-slash
spelling of the canonical path not reaching the fallback either
(`grep -r canonical_path_falls_back_to_an_existing_legacy_store` in any of
their `main.rs` files).

`rust-panosmcp` does not have this resolver. Its configured `--tokens-file`
path is loaded as given, with no automatic fallback to the legacy `/etc`
location; if a legacy store is present at `/etc/rust-panosmcp/tokens.json`
and is *not* the configured path, startup logs a `tracing::warn!` naming it
as a stale, un-migrated copy, but never reads from it. An operator restoring
a PAN-OS rig from an old drop-in that still points at the `/etc` path gets a
working start (the file is read from wherever it's configured to be), not a
silent, warned fallback to `/var/lib` the way the other four behave. Bringing
`rust-panosmcp` in line with the shared resolver is tracked separately, not
part of this doc update.

No mutable credential or state file remains under `/etc/<svc>` on any of the
six servers as of this update. Files that do live under `/etc` across the
fleet (`devices.json`/`sdc.json`/`clusters.json`/`controllers.json`,
`audit-hmac.key`, `credentials.env`/`secrets.env`, TLS material, `waivers.json`)
are all either operator-edited or, in the case of `audit-hmac.key`, generated
once at install time and never rewritten by the server — both fit this
document's definition of config (immutable across restarts), not state.

**Residual gap, tracked for a follow-up, not blocking #356:** `rustunifimcp`
already fails loudly on a missing `tokens.json` — `TokenStoreFile::load`
names the path in its error and there is no silent fallback to fall back
*to* — but unlike its five siblings it has no dedicated regression test
pinning that behavior, because it never needed the canonical/legacy resolver
in the first place. A short test asserting the load error names the
configured path would close that gap without inventing a migration path this
server never had.
