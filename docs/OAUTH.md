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

- A token's authority is the **union** of every entry its `scope` values and role-claim
  values match, exact string match only.
- **Unmapped grants nothing.** There is no default entry and no implicit wildcard; `["*"]`
  is a wildcard only where you write it. A scope key may not be `*`.
- Scope keys must be RFC 6749 scope-tokens (printable ASCII, no space, `"` or `\`) of
  1-128 bytes; a longer key refuses the whole file at load.
- A token that matches nothing, or whose union grants no tools, is refused with **403**.
- **Wildcard never grants write tools.** `"tools": ["*"]` allows every non-write tool.
  The union with a wildcard is the wildcard, so a token that matches **any** `["*"]` entry
  loses the write tools named in its other entries. A token that must write may match
  only entries without `"*"`.
- At most 64 scopes are read from a token; any beyond that are silently dropped.
- Role keys are 1-128 bytes of printable ASCII (spaces allowed, e.g. `Domain Admins`).
- `actor_type` (`agent` or `unknown`) is asserted by the file for every OAuth caller. The
  default is `unknown`: the server cannot tell a person from an agent holding the token.
  `human` is **refused at load**: OAuth cannot prove a human (no verified-approver
  binding), and one value would also cover client-credentials accounts, making them
  token-asserted human approvers.
- The role claim must be IdP-controlled (groups/roles), never a claim users can edit
  (`name`, `preferred_username`, `email`).

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
- **Bounded theft window.** The only bound is the IdP's `exp`. There is no revocation
  list in this version; keep access-token lifetimes short.
- **No token passthrough.** The `Authorization` header is removed after authentication and
  the caller context carries no credential, only issuer, subject and client id.
- **Token size.** The existing 4096-byte `Authorization` header cap applies, so tokens
  over about 4 KiB are not supported.
- **Identity key.** The change-set owner and approver identity of an OAuth caller is
  `oauth:<escaped issuer>:<escaped subject>`, so the same `sub` from two IdPs are
  different owners. Rate limiting keys on `oauth:<sub>`.
- **Write tools are granted by the scope map.** An OAuth caller gets exactly the tools its
  entries name, **write tools included** (e.g. `load_and_commit_config` above), so map
  write tools as carefully as you would grant them in `tokens.json`. A `["*"]` wildcard
  never grants write tools, and a token that also matches a wildcard entry loses its named
  write tools (section 4). The exception: OAuth
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
