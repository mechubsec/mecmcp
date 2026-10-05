# Onboarding

For someone who has been handed one of these MCP servers and needs it answering
calls. Assumes no prior contact with the family.

`mecmcp` itself is a library workspace — there is nothing here to run. What you
run is a vendor server. Because they all consume the same runtime crate, they
share a CLI shape, a token model, and a file layout; learn one and the others
cost minutes rather than hours.

The per-repo `README.md` is authoritative for exact flags at that repo's version.
This document is the shape they have in common and the parts that are easy to get
wrong.

---

## 0. Pick the right server

| You need to reach | Server | Status |
|---|---|---|
| Juniper SRX / Junos devices, directly | **rustjunosmcp** | Production |
| Palo Alto firewalls | **rustpanosmcp** | Production |
| Security Director Cloud (SASE portal) | **rustsdcmcp** | **Lab only** |
| Juniper Mist cloud | **rustmistmcp** | **Lab only** — packaging pre-release |

Only the first two should be pointed at production gear. `rustsdcmcp` is fine
against a lab tenant. `rustmistmcp` has cut a production tag and served live
read-only tenant traffic, so it is no longer the scaffold older notes describe —
but its packaging is explicitly **pre-release**: the TLS, Host/Origin and
bad-bearer rows of its own `PACKAGING_ACCEPTANCE.md` are unproven, and the one
lab run used no TLS and no off-loopback bind. Keep it on a lab tenant until
those pass.

**It is not read-only.** It registers `plan_mist_change`,
`approve_mist_change_set` and `apply_mist_change_set`, with mutations scoped to
batch-1 WAN edge operations. Scope tokens accordingly — a grant written on the
assumption that Mist cannot write is wrong.

---

## 1. The five steps

Every server in the family follows the same sequence.

### Step 1 — Describe the backend

One JSON file naming what the server may talk to.

| Server | File | Contains |
|---|---|---|
| rustjunosmcp | `/etc/jmcp/devices.json` | Per-device IP, port, username, SSH auth (key path or password), optional command blocklist |
| rustsdcmcp | `/etc/rustsdcmcp/sdc.json` | One tenant: endpoint, `expected_tenant_id`, `credential_env`, `auth_scheme`, timeouts, page caps |
| rustmistmcp | `/etc/rustmistmcp/mist.json` | Regional endpoint, `credential_file`, `allowed_orgs` |

Two rules that bite immediately:

- **The upstream credential never goes in this file.** SDC names an environment
  variable; Mist names a separate 0600 file. The loader rejects symlinks,
  oversized values, and anything group- or world-readable — the server refuses to
  start rather than running with a weak secret.
- **Modes are enforced, not advised.** 0600 for anything holding a secret, 0640
  for a service-readable profile. Wrong mode is a startup failure, and this is
  deliberate.

Each repo ships an example to copy (`devices.json.example`, `sdc.json`,
`mist.example.json`). Start from it.

### Step 2 — Mint a scoped token

Bearer tokens authenticate MCP *clients* to the server. They are unrelated to the
credential the server uses upstream.

```bash
rust-junosmcp token add \
  --tokens-file /etc/jmcp/tokens.json \
  --name ops \
  --routers 'edge-*' \
  --tools get_router_list,gather_device_facts,execute_junos_command
```

The secret is printed **once**. Only its SHA-256 digest is stored, so a lost
secret is reissued, never recovered.

Same subcommands everywhere: `token add | list | revoke | rotate | set-scope`.

> **The one thing to get right.** `--tools '*'` grants **read-only tools only.**
> Every mutating tool must be named explicitly. This is enforced in
> `mecmcp-server`, not per repo: a wildcard scope permits everything except the
> server's registered write tools. If you find yourself surprised that a wildcard
> token cannot commit, that is the design working.
>
> Mist extends the same idea to *privileged reads* — `get_mist_self`,
> `list_mist_wlans`, `search_mist_audit_logs` and friends are outside wildcard
> too.

Scopes have at least two axes: **which tools** and **which targets** (devices,
tenant, or org/site UUIDs). Both are checked, tool first.

The target axis accepts three spellings in `tokens.json`, all landing in the
same field with the same rules: `devices` (canonical), `routers` (what
rustjunosmcp wrote before extraction), and `targets` (for management-plane
servers, whose scope entries are tenants or sites rather than devices).
Whichever you write, the file **serializes back as `devices`** — the alias is
vocabulary, not a schema variant. Note what that means for lifecycle
operations: `rotate`, `add`, `revoke` and `set-scopes` rewrite the whole
document, so the first one to run **canonicalizes your aliases to `devices`**.
The scopes are identical either way; only the spelling in the file changes, and
it changes once. In code, `TokenEntry::targets()`,
`CallerCtx::targets()` and `filter_target_names` are the neutral names for the
device-named APIs, which remain available and behave identically.

### Step 3 — Run the server

```bash
rust-junosmcp \
  --device-mapping /etc/jmcp/devices.json \
  --transport streamable-http \
  --host 127.0.0.1 --port 30030 \
  --tokens-file /etc/jmcp/tokens.json
```

Add `--tls-cert` / `--tls-key` and `--allowed-host` for anything that leaves
loopback. **`--allowed-host` must track the address clients actually dial** — a
mismatch is rejected at the Host/Origin check before auth even runs.

For a local desktop client, drop the HTTP flags entirely and use
`--transport stdio`. There is no network boundary in that mode, and consequently
no bearer check — which is exactly why the HTTP path exists for everything else.

In practice you do not run this by hand. Each repo ships a systemd unit and an
installer under `packaging/`, plus a digest-pinned distroless container image.
See [`PACKAGING.md`](PACKAGING.md) for the delivery standard and
[`../ROADMAP.md`](../ROADMAP.md) for where it is heading.

### Step 4 — Point a client at it

- **Transport:** streamable HTTP
- **URL:** `http://<host>:<port>/mcp` (`https://` with TLS)
- **Header:** `Authorization: Bearer <secret from step 2>`

**First move after connecting: call `tools/list`.** The response is filtered to
what your token can actually invoke, so it tells you your real surface rather
than the server's catalogue. Likewise `get_device_list` returns only in-scope
devices. If a tool you expected is missing, the token is the place to look, not
the server.

### Step 5 — Operate

- **Change config, then `systemctl kill -s HUP <service>`.** Inventory and token
  files hot-reload; no restart, no dropped sessions.
- **Rescope without reissuing:** `token set-scope --name ops --tools …` keeps the
  digest and creation time, so clients keep working with the secret they have.
- **Snapshot before upgrading.** For the homelab LXCs this is the whole rollback
  plan — there is no standby host.
- **Read the upgrade notes for versions you are skipping.** Not optional in this
  family: the 0.7.0–0.7.2 sequence shipped a graceful-drain fix whose first two
  attempts were inert and both passed CI.

---

## 2. Making a change

Reads are direct. Writes are not, and the difference is the point of the whole
design.

A mutating call goes through a fingerprint-bound change set:

```
stage/prepare ──> digest ──> approve ──> apply
                              (a different principal)
```

- **Prepare does not write.** It previews and produces a digest bound to the
  target's current state.
- **Approval is of an exact digest**, by a principal distinct from the one that
  prepared it. Same token for both is refused.
- **Apply refuses if the target drifted** since planning. The fingerprint is what
  makes that detectable rather than hoped for.
- Approvals expire (TTL), and state persists across restarts, so a restart
  mid-flow does not lose or silently re-authorise work.

Junos additionally supports confirmed commit, so a change that costs you your own
reachability rolls itself back.

`--lab-mode` waives the second principal for lab work. It records
`approver: null` with `approval_waiver: "lab-mode"` — it never fabricates an
approver, so a lab record cannot be mistaken for a reviewed one later.

### Step-up approval: verified human identity ([#400](https://github.com/mechubsec/mecmcp/issues/400))

Without configuration, "two principals" means two *tokens* — one person holding
both a proposer and an approver token can approve their own change. Step-up
approval closes that by requiring the approve call to additionally carry a
fresh JWT from your IdP, bound to a specific token and checked against the
proposer's identity. The approver's existing bearer token is unchanged; the
JWT is an extra assertion, sent as `Mecmcp-Approver-Assertion`, never as
`Authorization` and never as a tool argument.

**This is a core-library capability, not yet a feature of any server in this
repository.** `mecmcp-oidc`, `mecmcp-auth`, `mecmcp-changeset` and
`mecmcp-transport` all support it, but a server must opt in explicitly — flatten
`mecmcp_runtime::cli::VerifiedApproverArgs` into its own CLI (it is standalone,
like `WebApproverArgs`, not part of the shared `Cli`), call its `validate`
alongside the server's own CLI validation, construct an
`ApproverAssertionVerifier`, and build every `ApproverIdentity` it passes to
`approve_change_set`/`create_change_set` via `ApproverIdentity::from_attribution`
rather than constructing one by hand. `rust-junosmcp` is the planned first
server to do this (MEC-994 W8); the commands below use it as the running
example of what that integration will look like, not something it supports
today.

`mecmcp-transport`'s verifier sits behind its `verified-approver` feature
(off by default, so a server that never configures this path does not link
`mecmcp-oidc`'s `reqwest`/rustls HTTP client). A server that enables it
alongside `otel` must install a process-wide rustls `CryptoProvider` at
startup itself — the workspace deliberately ships no default provider (see
`docs/CRATE-MAP.md`'s decision D4) — or the two features' independently
selected rustls backends conflict.

**1. Register an app in your IdP.** Any OIDC provider that can issue a JWT
*access* token (not an ID token — the server verifies it as a bearer
assertion, not an OIDC login flow) works. Note the issuer URL and, if your IdP
enforces one, the audience (`aud`) the access token is minted for.

**2. Put the approver's role or group in a token claim**, e.g. `roles` or
`groups`, containing a value you'll designate as the approver role
(`approver` by default).

**3. Bind each approver's existing token to their IdP subject:**

```bash
rust-junosmcp token add --tokens-file /etc/jmcp/tokens.json --name alice \
  --actor-type human --tools approve_change_set --devices '*' \
  --oidc-issuer https://idp.example.com/ --oidc-subject alice@example.com
```

The subject is whatever unique, stable identifier your IdP puts in the JWT's
`sub` claim — not necessarily an email. Only issuer+subject are ever stored;
never bind a display name.

**4. Start the server with the verifier configured:**

```bash
rust-junosmcp --oidc-issuer https://idp.example.com/ \
  --oidc-audience <your-aud> \
  --oidc-role-claim roles --approver-role approver \
  --approver-max-age-secs 300 \
  --approval-digest-key-file /etc/jmcp/approval-digest.key \
  --require-verified-approver
```

`--require-verified-approver` is the enforcement switch: with it set, a
`human` token with no assertion cannot approve, and an owner token with no
`oidc_subject` cannot even propose. Leave it off to roll out the issuer and
bindings first and watch for rejections before enforcing. The server refuses
to start if `--require-verified-approver` is set without `--oidc-issuer`,
without `--approval-digest-key-file`, or together with `--lab-mode`; and
refuses to start on `--oidc-issuer` with no `--oidc-audience` regardless of
`--require-verified-approver`, since `OidcConfig` has no sensible default for
it.

**5. The approving client presents the header on the approve call** — how it
obtains that JWT (interactive login, device-code flow, whatever your IdP
supports) is between the approver and their IdP; the server only ever sees
and verifies the resulting token.

This does not replace scoping: it verifies *who* approved, not *what* they
may approve beyond their token's existing tool and device scopes. Selector-scoped
approver roles are a later phase of #400 and are not built yet.

---

## 3. Per-server notes

### rustjunosmcp — 0.17.0, production

35 tools with default features: 26 Junos plus 9 SRX (`srx` feature, on by
default). Build with `--no-default-features` for the 26-tool Junos-only surface.

Beyond the common five steps:

- **Host keys are verified by default** against `--known-hosts-file`. Populate it
  with `scripts/scan-known-hosts.sh` before first connection.
  `--ssh-accept-new-host-keys` is opt-in TOFU and a deliberate downgrade.
- **File transfer needs SSH key auth**, not password.
- `--staging-dir` is the host side of `transfer_file` / `fetch_file`;
  `--device-lease-dir` holds the cross-process locks that stop two callers
  running destructive operations on one device.
- The shipped unit binds loopback and sets `--inventory-readonly`, which rejects
  `add_device` and `reload_devices` at runtime. Overriding that is a site
  decision — make it consciously.

### rustsdcmcp — 0.1.0, lab only

22 tools: 17 read, 5 mutating. Single-tenant per process; at startup the server
verifies the credential's tenant against `expected_tenant_id` and refuses calls
on a mismatch.

There is no direct deploy tool, and that is not an oversight — SDC governs a
fleet, so one action can reach many devices. Deployment is
`prepare_sdc_policy_deploy` → `approve_sdc_change_set` → `apply_sdc_change_set`,
digest-bound throughout.

Listener is loopback-only; reach it over an SSH tunnel:

```bash
ssh -N -L 30032:127.0.0.1:30032 <host>
```

Public release is blocked on replacing its remaining compatibility shims with
upstream APIs landing in one coherent `mecmcp` release.

### rustmistmcp — lab only, mostly-read tool surface with change-set writes

38 registered tools over a catalog of 1,059 audited Mist operations. Three of
them are the mutating change-set path — `plan_mist_change`,
`approve_mist_change_set`, `apply_mist_change_set` — with a fourth,
`get_mist_change_set`, reading its state. Mutations are scoped to batch-1 WAN
edge operations.

Scoping is three-deep: profile `allowed_orgs`, then the token's tool scope, then
a grant naming `allowed_operations`, `actions` (capabilities), and `subjects`
(`org/<uuid>` or `site/<uuid>`, lowercase hyphenated, non-nil). Tokens from
`token add` are **grantless by default** — a grant is added to `tokens.json` by
hand, which is why the server is currently useful for reading the design rather
than for operating anything.

Do not deploy it against a production org.

---

## 4. When something is refused

| Symptom | Cause |
|---|---|
| 401 | No bearer, malformed bearer, or unknown digest |
| 403, tool named | Tool outside the token's tool scope |
| 403, target named | Tool allowed, target outside the token's target scope |
| Rejected before auth | Host or Origin header not in the allowed set |
| Tool missing from `tools/list` | Not in scope — the list is filtered per caller |
| Wildcard token cannot write | Working as designed; name write tools explicitly |
| Server will not start | A secret file is group/world-readable, a symlink, or oversized |
| Apply refused | Target drifted since prepare, or approval expired, or approver is the preparer |

Denials name the token, never the secret or its digest, so the same line is
actionable for both the caller reading the error and the operator reading the
audit log.

Every `tools/call` produces two correlated audit events — one from the transport
before dispatch, one from the handler with the resolved action and targets. If
you are reconstructing what happened, start from the request id and expect both.
