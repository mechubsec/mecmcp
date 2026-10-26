# OAuth 2.1 resource-server mode

Opt-in per server ([#498](https://github.com/mechubsec/mecmcp/issues/498)). A server can accept a
JWT access token from an external authorization server as its `/mcp` bearer credential,
alongside the static tokens it already has.

> **Upgrade break.** Static token names starting with `oauth:` are now reserved. A token
> file containing one **fails to load as a whole** (every token is refused, not just that
> one). Rename any such token before upgrading.
>
> **Rollback break.** Once an OAuth caller has created a change set, a pre-0.29 binary
> refuses the change-set state file (`unknown variant "oauth"`). Snapshot the guest (or copy
> the state file) before upgrading; to roll back, stop the server, restore that pre-upgrade
> state file, then start the old binary. Restoring it discards **all** change-set state
> since the snapshot, not only new change sets: approvals, cancellations, apply statuses
> and operation records of existing change sets rewind too, while device changes applied
> in that window stay applied. Reconcile against the devices before restarting.

## 1. What this is, and is not

- Optional. With no `--oauth-*` flags a server behaves exactly as before. Static tokens
  are tried first; only a bearer that matches none and *looks like a JWT* reaches the
  OAuth verifier.
- The authorization server stays external. There is no embedded login, consent, token
  issuance, dynamic client registration or client-ID metadata documents. Those are the
  IdP's job. This is also not the step-up approver assertion of
  [#400](https://github.com/mechubsec/mecmcp/issues/400).
- The server serves RFC 9728 protected-resource metadata and adds `resource_metadata` to
  its 401 challenges, so MCP clients can discover the IdP.

## 2. Build and enable

`mecmcp-transport` feature `oauth-resource` (off by default; it links the `mecmcp-oidc`
HTTP stack). The server flattens `mecmcp_runtime::cli::OAuthResourceArgs` into its CLI and wires:

```rust
oauth.validate()?; // flag consistency; the transport does the authoritative URI parse
if let (Some(issuer), Some(resource), Some(map_path)) =
    (&oauth.oauth_issuer, &oauth.oauth_resource, &oauth.oauth_scope_map)
{
    let scope_map = OAuthScopeMap::load(map_path)?;
    let mut config = OAuthResourceConfig::new(issuer, resource, scope_map)?
        .with_role_claim(&oauth.oauth_role_claim)
        .with_require_at_jwt_typ(oauth.oauth_require_at_jwt_typ);
    if let Some(secs) = oauth.oauth_max_token_lifetime_secs {
        config = config.with_max_token_lifetime(Duration::from_secs(secs));
    }
    if let Some(audience) = &oauth.oauth_audience {
        config = config.with_audience(audience);
    }
    let source = Arc::new(HttpKeySource::new(http_client)); // mecmcp-http client
    boundary = boundary.with_oauth_resource(Arc::new(OAuthResource::new(config, source)));
}
```

The metadata routes are merged outside the bearer boundary by
`build_streamable_http_router`; nothing else to wire. The verification timeout (3 s) and
concurrent-verification limit (32) are not flags.

## 3. Operator setup (IdP-agnostic)

1. **One resource per server.** Give each server its own URI, e.g.
   `https://junos.lab.example/mcp` and `https://panos.lab.example/mcp`.
2. **The client requests `resource=<that URI>`** (MCP clients do, per the MCP authorization
   spec) and the IdP puts it in `aud`. If the IdP cannot, add an audience claim mapper that
   emits the URI. As a last resort pass `--oauth-audience <client-id>` with one IdP client
   per server; the audience must still be unique per server.
   **Give the resource its own audience, never the client id of an OIDC login client.** An ID
   token issued to that client carries the same `aud` and would pass as an access token
   (Keycloak's body `typ: "ID"` is refused, other IdPs' ID tokens are not), and it must
   differ from the approver-assertion audience. Turn on `--oauth-require-at-jwt-typ` if
   your IdP supports it.
3. **Claims.** The IdP must emit `iss`, `sub`, `exp`, `iat`, `jti`, a `scope` claim
   (a space-delimited string; an array there grants nothing; `scp`, a string or an array,
   is read when `scope` is absent) and `client_id` (or `azp`,
   which Keycloak emits). These are RFC 9068 access-token claims; `jti` and a client id
   are required.
4. **Roles/groups** as a **top-level** claim named by `--oauth-role-claim` (default
   `roles`). Nested claims such as Keycloak's `realm_access.roles` are not read; add a
   token mapper that flattens them.
5. **Write the scope-map file** (section 4) and test with `curl`:

   ```fish
   curl -s --max-time 5 -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://junos.lab.example/mcp
   ```

6. **Start the server** and check discovery:

   ```fish
   curl -s https://junos.lab.example/.well-known/oauth-protected-resource/mcp
   ```

Start flags (all three of the first are required together; the rest are optional and are
an error without them):

```text
--oauth-issuer https://idp.lab.example/realms/lab
--oauth-resource https://junos.lab.example/mcp
--oauth-scope-map /etc/junosmcp/oauth-scopes.json
--oauth-audience junos-client
--oauth-role-claim groups
--oauth-require-at-jwt-typ
--oauth-max-token-lifetime-secs 900
```

- `--oauth-issuer`: https with a host, and no userinfo, query or fragment; compared
  byte-for-byte with `iss`, so write it exactly as the IdP issues it.
- `--oauth-resource`: https, or http for a loopback host only. It must already be
  canonical, and the error shows the canonical form. A bare origin canonicalises to
  `https://host/` **with the trailing slash**, and that is then the audience.
- `--oauth-audience`: overrides the required `aud`. The default is the canonical resource
  string. See the warning in step 2: never an OIDC login client's id.
- `--oauth-role-claim`: not a registered claim name (`sub`, `iss`, `aud`, `scope`, ...).
- `--oauth-require-at-jwt-typ`: requires the `typ: at+jwt` (or `application/at+jwt`) header. Off
  by default because some IdPs (Keycloak by default) sign access tokens with `typ: JWT`;
  turn it on wherever your IdP supports it.
- `--oauth-max-token-lifetime-secs`: a ceiling, above zero, on how long any access token
  is honoured: a token whose `exp - iat` exceeds it is refused (`token_lifetime_exceeded`),
  whatever the IdP issued. Off by default. **Recommended** (900 is a sensible start): it
  caps the revocation window described in section 6.

**Audience matching is exact.** `aud` must equal the canonical resource string
byte-for-byte (no trailing-slash or case tolerance). A multi-valued `aud` is accepted only
if one element matches exactly. Keycloak adds `account` to `aud` by default, so
configure the IdP to issue single-audience tokens where you can.

Worked notes (verify the labels in your IdP version; check your IdP's documentation):

- **Keycloak:** an "Audience" mapper with "Included Custom Audience" set to the resource URI;
  a "Group Membership" mapper to a flat claim with the full path turned off. Keycloak puts
  the client in `azp`, which is accepted.
- **Authentik:** the audience is the provider's client id, so create one provider per
  server and pass `--oauth-audience`.

## 4. The scope-map file

Lives on the server like `tokens.json`; a token cannot name its own authority. Maximum
64 KiB, 256 entries per table, unknown fields refused, duplicate keys refused.

The file decides every OAuth caller's tool and device authority, so it is integrity-checked
at load: mode `0640` or tighter, owned by the service user or root, a regular file, and not
a symlink (`chmod 0640` and `chown root:<service group>` is the usual layout). A looser mode,
another owner or a symlink refuses to start. A root process accepts any owner.

```json
{
  "version": 1,
  "actor_type": "unknown",
  "scopes": {
    "junos:read": { "tools": ["get_junos_config", "get_device_list"], "devices": ["*"] },
    "junos:lab": { "tools": ["get_junos_config", "load_and_commit_config"], "devices": ["lab-srx1"] }
  },
  "roles": {
    "netops": { "tools": ["get_junos_config"], "devices": ["*"] }
  }
}
```

- A token's **tools** are the **union** of every entry its `scope` values and role-claim
  values match (exact string match only); its **devices** are the **intersection** of
  those entries' device sets, with `["*"]` as the identity. One entry's tools never reach
  another entry's devices: a token holding both `junos:read` and `junos:lab` above gets
  `get_junos_config` and `load_and_commit_config` on `lab-srx1` **only**, not the write
  tool on every device. The cost: such a token loses the reads outside the narrowest
  device set, and disjoint device sets leave it **no devices** (its tools stay, every
  device-addressed call is refused). Give distinct device reach to separate tokens (IdP
  clients or scopes requested separately). A single matched entry is unaffected.
- **Unmapped grants nothing.** There is no default entry and no implicit wildcard; `["*"]`
  is a wildcard only where you write it. A scope key may not be `*`.
- Scope keys must be RFC 6749 scope-tokens (printable ASCII, no space, `"` or `\`) of
  1-128 bytes; a longer key refuses the whole file at load.
- A token that matches nothing, or whose union grants no tools, is refused with **403**.
- **A tool wildcard never grants write tools.** `"tools": ["*"]` allows every non-write
  tool. The union with a tool wildcard is the wildcard, so a token that matches **any**
  entry whose `tools` list contains `"*"` loses the write tools named in its other
  entries. A token that must write may match only entries without `"*"` in `tools`.
  `"devices": ["*"]` is unaffected: an entry naming a write tool with all devices is a
  valid all-device write grant.
- At most 64 scopes are read from a token; any beyond that are silently dropped.
- Role keys are 1-128 bytes of printable ASCII (spaces allowed, e.g. `Domain Admins`).
- `actor_type` (`agent` or `unknown`) is asserted by the file for every OAuth caller. The
  default is `unknown`: the server cannot tell a person from an agent holding the token.
  `human` is **refused at load**: OAuth cannot prove a human (no verified-approver
  binding), and one value would also cover client-credentials accounts, making them
  token-asserted human approvers.
- The role claim must be IdP-controlled (groups/roles), never a claim users can edit
  (`name`, `preferred_username`, `email`).

### Device selectors (attribute-scoped devices)

An entry may add `device_selectors` to narrow its `devices` to inventory devices by
attribute, e.g. a role that may touch only the EMEA lab:

```text
"roles": { "emea-netops": { "tools": ["get_junos_config"], "devices": ["*"],
                            "device_selectors": ["site=emea-*", "vendor=junos"] } }
```

- **Grammar.** `key=value`; `key` is `site`, `vendor` or `tag` (anything else refuses the
  file at load). `value` is 1-64 bytes of `[A-Za-z0-9._-]` with `*` as the only
  metacharacter (no `?`, classes or regex; `**` refused). A device matches an entry when it
  is named by `devices` **and** satisfies **every** selector (AND). Selectors only narrow;
  they never add a device `devices` does not name. 1-8 selectors per entry.
- **Matching.** Exact bytes, no case folding, no Unicode normalization. `*` matches zero or
  more characters of the alphabet, **including `-`, `.` and `_`**: `emea-*` matches
  `emea-1`, `emea-lon-2` and `emea-`, never `emea`, `emea1`, `xemea-1`, `EMEA-1`. Put the
  separator before `*` (`emea-*`, not `emea*`) or `emea*` also matches `emea2`. A device
  without the attribute matches nothing, even `site=*`. `tag=` matches if any tag does.
- **Attributes** come from the device inventory, never the token. A consumer adds an
  optional `"attributes": {"site": "emea-lon", "vendor": "junos", "tags": ["pci"]}` object
  to each device entry (`mecmcp_auth::DeviceAttrs`; unknown keys and values outside the
  alphabet fail the inventory load), implements `mecmcp_auth::DeviceAttributeSource` over
  its live inventory, and passes it with `OAuthResource::with_device_attributes`. Without
  a source, a selector entry grants **no devices**.
- **Resolution** happens on each authentication against the inventory's current contents,
  so a SIGHUP reload (a device moving site, a retired device) takes effect on the next
  request, against one snapshot of the attributes taken per authentication (every matched
  entry sees the same inventory generation). Each entry resolves to a device-name allowlist,
  so the intersection rule above applies unchanged. The 256-name cap applies to the final
  intersected allowlist, not to each entry: a token whose result exceeds it is refused
  (403). An already-issued token is not re-resolved mid-request. An explicit
  `"device_selectors": null` is refused at load (only omitting the key means no selectors).
- **Claims never become selectors.** A role or scope claim is only a lookup key into this
  file (exact string); `site=*` in a claim maps nothing unless that exact string is a key
  you wrote. Selectors come only from `device_selectors` here.
- **Isolation guarantee and limits.** Attribute values and selector literals share the
  alphabet above, enforced when they are constructed, so no control, bidi, zero-width,
  fullwidth or non-ASCII lookalike can exist to match a literal or be absorbed by `*`. The
  guarantee is only as good as the inventory's `site` labels: a mislabelled or unlabelled
  device is placed (or not placed) by the label alone. Selector scoping of
  verified-approver roles is not built.

#### Static tokens

A `tokens.json` entry may carry the same `device_selectors` (grammar, AND, narrowing and
fail-closed rules as above; an explicit `null` is refused at load, as is an expression that
does not compile). Mint one with `token add --device-selector 'site=emea-*'` (repeatable).

```text
{ "name": "emea-ro", "devices": ["*"], "device_selectors": ["site=emea-*"], ... }
```

Resolution is the consumer's: it builds the caller with
`CallerCtx::from_entry_with_attributes(entry, Some(&inventory))` on each authentication
(one attribute snapshot per call). The plain `CallerCtx::from(entry)` has no source, so a
selector entry **grants no devices** through it: a server that has not adopted attributes
refuses, rather than ignores, the narrowing. Upgrade every binary that reads or rewrites the
store before adding selectors: an older build ignores the field and, on `token rotate` or
`set-scopes`, drops it, widening the token to every device its `devices` names.

## 5. What clients see

| Status | When | Notes |
| --- | --- | --- |
| 401 `invalid_token` | missing or bad token | `WWW-Authenticate` carries `resource_metadata="<url>"` |
| 403 `insufficient_scope` | verified, but maps to no tools | audited as a denied `oauth`/`authenticate` event |
| 503 `temporarily_unavailable` | could not verify right now | `Retry-After: 5`; the token is not judged invalid |

Every refusal logs a reason code (`oauth_rejected` for 401/403, `oauth_unavailable` for 503):

| Reason | Usually means |
| --- | --- |
| `wrong_audience` | `aud` is not exactly this server's resource string (or `--oauth-audience`) |
| `wrong_issuer` | `iss` differs from `--oauth-issuer` |
| `expired` / `not_yet_valid` | outside `exp` / `nbf`, with a fixed 60 s clock-skew leeway; check clocks |
| `invalid_signature` | signed by a key the issuer does not publish |
| `unsupported_algorithm` | not RS/PS256-512, ES256/384 or EdDSA (never HS*, never `none`) |
| `unknown_key_id` | `kid` not in the cached JWKS (see rotation, section 6) |
| `malformed_jwt` | JWT-shaped but undecodable |
| `wrong_token_type` | `--oauth-require-at-jwt-typ` is on and `typ` is not `at+jwt`, or the body `typ` claim is `ID` (an ID token) |
| `missing_claim` / `missing_issued_at` | no `jti`, client id (`client_id`/`azp`), `sub` or `iat` |
| `token_lifetime_exceeded` | `--oauth-max-token-lifetime-secs` is set and `exp - iat` is longer than it; shorten the IdP's access-token lifetime or raise the ceiling |
| `invalid_subject` | `sub` is not 1-128 bytes of printable ASCII without spaces |
| `invalid_client_id` | `client_id`/`azp` is not 1-128 bytes of printable ASCII without spaces |
| `unmapped_scope` | token valid, scope map grants no tools (403) |
| `keys_unavailable` | the IdP's discovery or JWKS endpoint failed (503) |
| `timeout` | verification exceeded 3 s, usually a slow IdP (503) |
| `busy` | all 32 verification permits in use (503) |

Audit events for the auth decision use component `oauth`, operation `authenticate`.
Per-call audit records (`AuditScope`) for an OAuth caller carry
`caller=oauth:<escaped issuer>:<escaped subject>` plus `oauth_issuer`, `oauth_subject` and
`oauth_client_id` (empty for static-token callers). Operational `audit`-target events
(sink flush, startup warnings) do not carry these fields.

## 6. Security properties and limits

- **One token, one server.** Exact audience binding; a token minted for the junos server
  is refused by the panos server (`wrong_audience`).
- **Bounded theft and revocation window.** The server keeps no session and no revocation
  list: it accepts the IdP's access token on every call, so a user the IdP has offboarded
  keeps working until the token they already hold expires. The window is
  `min(token exp, iat + --oauth-max-token-lifetime-secs)` plus the 60 s clock-skew leeway;
  the IdP's refresh then fails, so no new token is issued. Without the ceiling the window is
  whatever lifetime the IdP issued, so set it. A stricter IdP-side revoke (introspection) is
  not implemented.
- **Audit shows the mechanism.** An OAuth caller's records carry `caller=oauth:...` and
  `oauth_issuer`/`oauth_subject` (above); a static token's carry its token name and empty
  `oauth_*` fields; a verified approver's carry the `oidc` approver fields.
- **No token passthrough.** The `Authorization` header is removed after authentication and
  the caller context carries no credential, only issuer, subject and client id.
- **Token size.** The existing 4096-byte `Authorization` header cap applies, so tokens
  over about 4 KiB are not supported.
- **Identity key.** The change-set owner and approver identity of an OAuth caller is
  `oauth:<escaped issuer>:<escaped subject>`, so the same `sub` from two IdPs are
  different owners. Rate limiting keys on `oauth:<sub>`.
- **Write tools are granted by the scope map.** An OAuth caller gets exactly the tools its
  entries name, **write tools included** (e.g. `load_and_commit_config` above), so map
  write tools as carefully as you would grant them in `tokens.json`. A `"tools": ["*"]`
  wildcard never grants write tools, and a token that also matches an entry with `"*"` in
  `tools` loses its named write tools (section 4); `"devices": ["*"]` does not. Devices
  intersect across matched entries, so a write entry is never widened to another entry's
  devices. The exception: OAuth
  callers hold **no vendor grant**, so grant-gated operations (e.g. PAN-OS XPath writes,
  Mist org/site writes) need a static token. They also cannot bind a verified approver, so
  they cannot approve under `--require-verified-approver`.
- **JWKS rotation latency.** An unknown `kid` does not force a refetch; keys refresh at most
  every 5 minutes, so a rotation can reject valid tokens for up to that long.
- **Verification load.** Non-JWT-shaped bearers never reach the verifier, and the
  JWKS fetch is cache-driven. Verification is bounded to 32 at once with a 3 s timeout.
  A flood of JWT-shaped junk can briefly exhaust the permits (503 `busy` for up to 3 s),
  so valid OAuth callers retry. Static tokens are unaffected.
- No CORS headers on the metadata route.

## 7. Troubleshooting

| Symptom | Check |
| --- | --- |
| 401, log `wrong_audience` | decode the token; `aud` must equal the canonical resource string exactly (`https://host/` for a bare origin) |
| 401, `missing_claim` | the IdP omits `jti` or the client id; add mappers |
| 401, `wrong_token_type` | IdP signs `typ: JWT`; fix the IdP or drop `--oauth-require-at-jwt-typ` |
| 403 right after login | scope-map keys must match the token's `scope`/role values exactly |
| 503 `keys_unavailable` | the server cannot reach `<issuer>/.well-known/openid-configuration` over https |
| every static token refused after upgrade | a token named `oauth:*` is in the token file; rename it |
| `invalid_subject` | the IdP uses an email-with-space or very long `sub`; use a stable opaque id |

## 8. Rollout

Enable on one lab server first, keep the static tokens, watch `oauth_rejected` and
`oauth_unavailable`, then widen server by server. A green test suite proves the
verifier, not that your IdP puts the resource URI in `aud`: run a real MCP client against
the IdP once before relying on it.

Before upgrading, snapshot the guest or copy the change-set state file. Rolling back to a
pre-0.29 binary after an OAuth caller has created a change set requires restoring that
pre-upgrade state file, which rewinds all change-set state since the snapshot (see the
rollback break at the top).
