# mecmcp-client (#637) and cross-server plan digest (#636) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship, as mecmcp 0.35.0, a shared session-aware streamable-HTTP MCP client crate (`mecmcp-client`, adopted by `mecmcp-approve`) and a domain-tagged cross-server plan digest with a new approval-record digest version that binds it.

**Architecture:** Part A adds one crate that wraps whichever transport the Task 1 spike justifies (rmcp client vs hand-rolled over `reqwest`), with hardened token loading from `mecmcp-secret`, a response cap, per-call timeouts and escaped untrusted text. Part B adds `plan.rs` to `mecmcp-changeset` (pure digest + verification, no server stack), approval digest v8 (keyed HMAC = v7 fields + `plan_digest`), a coordinator method that verifies membership, and an optional `plan_digest` on the existing approval evidence record. Family servers adopt Part B in their own repos after the tag (follow-up issues, Task R).

**Tech Stack:** Rust 1.89 / edition 2024, rmcp 3.10 (lock) , reqwest 0.13 (`rustls-no-provider`), tokio, serde_json, sha2/hmac, wiremock-free in-process rmcp server from `mecmcp-transport` (`test-util`).

**Spec:** GitHub issues mechubsec/mecmcp#637 and #636; recon `/tmp/claude-1000/-home-mharman-Projects-mecmcp/9ad6c2fc-26b3-4a54-bc37-76ff13b7a5d4/scratchpad/recon/mecmcp-636-637.md`.

## Decisions needed (resolve before Task 6 / Task 1 respectively)

1. **Where `server_id` comes from.** Options: (a) reuse the existing `mecmcp_audit::EvidenceConfig::server_id` (`crates/mecmcp-audit/src/service.rs:28`, charset `[A-Za-z0-9_-]` via `mecmcp_audit::validate_server_id`, `evidence.rs:216`); (b) derive from the TLS certificate name; (c) a token audience. **Recommend (a).** It is already configured, validated, unique per process ("one process per `server_id`") and already names the server in the evidence chain, so the plan member, the chain and the audit trail agree on one name. (b) is wrong: servers sit behind a TLS terminator / DNS aliases (610 to .230 etc.), the process cannot see the name a client dialled, and a cert rename would silently change plan identity. (c) does not exist: bearer tokens carry no audience. Cost of (a): the digest is only as trustworthy as the operator's config, and renaming `server_id` strands pending plans (acceptable, plans are short-lived). The coordinator takes `own_server_id` as an argument rather than storing it (Task 8), so vendors pass their existing evidence `server_id`.
2. **Persisted-state migration risk of the new digest version.** Approval digest v8 adds `ApprovalRecord.plan_digest` (`deny_unknown_fields`, `records.rs:567`). Pre-0.35.0 binaries reject any state file containing it, and `persistence.rs` selects the file schema version by content (currently max 9, `persistence.rs:752`), so v8 needs file schema **10**, written only once a plan-bound approval exists. Consequences: (i) a fleet that never uses plan approval keeps writing exactly what it writes today (the ten stored digests on LXC 608 and every v4-v7 record stay byte-identical, verified by Task 7 tests); (ii) the first plan approval makes the state file unreadable by older binaries, so **rolling back after the first plan-bound approval needs the pre-upgrade snapshot or the state file edited by hand**; deploy runbook must say so; (iii) a 0.35.0 server reading a v8 record also needs the approval digest key, so plan approval is **refused when no key is configured** (v8 is keyed-only, like v7). Recommend: ship exactly that, and deploy to one test rig (611) first.
3. **Planner identity across servers.** The issue says "planner cannot approve its own plan", but change-set `owner` is a per-server token name (`alice-junos` vs `alice-unifi`). Recommend: the plan digest does **not** carry a planner field; each server enforces its existing owner != approver and owner-subject != approver-subject checks on its own member (the OIDC subject covers cross-server identity in strict mode). Cross-server planner identity outside OIDC is not enforceable by mecmcp; document it as a known limit in Task 9.
4. **Plan-level evidence shape.** Options: new `EvidenceRecord` variant (old `mecmcp-verify` and golden fixtures would not know it) vs an optional `plan_digest` on the existing approval evidence record. Recommend the optional field (skipped when `None`, so existing records hash identically). A "plan record" is then the set of per-server approval records sharing a `plan_digest`; no cross-server writer exists.
5. **mecmcp-client must not depend on `mecmcp-transport`** (it drags server code, rmcp server features). Recommend duplicating the one string constant `Mecmcp-Approver-Assertion` in the client and pinning equality with a test in `mecmcp-approve` (which already depends on both). Alternative (moving the const to `mecmcp-secret`/a new tiny crate) is a wider change for one string.
6. **Plan size and `order` semantics.** Recommend `1..=32` members, `order` must equal 1-based position (contiguous, ascending), duplicates of `(server_id, change_set_id)` rejected. Ordering is bound by the digest but **enforced only by the orchestrator** (out of scope per #636).
7. **Lab mode.** Recommend waived approvals do NOT bind a plan digest in the record (waiver digest v3 untouched); `plan_digest` appears only in the evidence record, with waiver kind `lab_mode` (`records.rs:670`). Confirm.
8. **rmcp pin.** Lock has 3.10.0; registry also holds 3.11.0. Recommend staying on 3.10 for this release (two-version conflict is the family bug; run `cargo tree -d | grep rmcp` in Task 1 and Task 2).

## Global Constraints

- rust-version 1.89, edition 2024; workspace lints (`[lints] workspace = true`) on every new crate; `version.workspace = true`, intra-workspace deps pinned `version = "0.34.0"` until Task R bumps all to 0.35.0.
- MCP servers are Linux-only: no non-Unix fallbacks in token loading.
- HTTPS only, no redirects, no skip-verify, no env proxy (match `mecmcp-http` rules, `crates/mecmcp-http/src/lib.rs:158`); `extra_root_certificates` non-empty REPLACES the root store.
- Tokens/assertions: never in `Debug`, `Display`, errors or logs; wrap in `mecmcp_secret::OutboundSecret`.
- Do not change the byte layout of any existing digest: `change_set_digest*`, approval v4-v7, waiver v1-v3, the empty-targets four-tuple rule (`digest.rs:62`).
- Golden digest vectors are computed independently (python `hashlib`/`hmac` or `openssl dgst`), recorded as literals with the command in a comment; never produced by the function under test.
- Verify with the repo's own CI commands (fmt, clippy `--workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --locked --features mecmcp-audit/test-util,mecmcp-changeset/test-util,mecmcp-transport/test-util`, transport extra line, `cargo doc`, fuzz `cargo check`, MSRV, no-lockfile job). Plain `cargo test` skips required-features targets.
- `Cargo.lock` and `fuzz/Cargo.lock` move with every dependency change.
- One commit per task, each < ~400 lines; Codex review gate per commit (skill `codex-review-gate`); a task near 400 lines should expect CI rather than a local gate run. Sabotage each guard (delete the integration point) and re-run; for Python restores delete stale `__pycache__` if used.
- No new required-check names carrying versions.

## Review Focus

- Server returns an SSE stream that never ends / a body past the cap: client must abort with `ResponseTooLarge`/`Timeout`, not hang or buffer (Task 3).
- Server reply carrying ANSI/OSC escapes in tool text or JSON-RPC error message: never reaches a terminal raw (Task 2, 3, 5).
- Token file that is group-readable, a symlink, empty, or has a trailing newline: refused / stripped exactly like `mecmcp_secret::load_from_file` (Task 2).
- `tools/list` pagination with a cursor loop that never terminates, and replies lacking or carrying `ttlMs`/`cacheScope` (Task 4).
- Plan with duplicate members, wrong `order`, uppercase/short digest, 33 members, `|` or space in `server_id` (Task 6).
- Plan whose member digest matches but whose `device` or `server_id` differs from the record (Task 8).
- v8 state file read by a deployment with no approval key, or with `plan_digest` on a non-v8 record (Task 7).
- Existing v4-v7 and waiver state files load and re-save byte-identically (Task 7).

---

# Part A: mecmcp-client (#637), Tasks 1-5

### Task 1: Spike: does rmcp 3.10's client emit the 2026-07-28 stateless wire form? (time-box 2 hours, no merge)

**Files:**
- Create (scratch, not committed): `/tmp/.../scratchpad/spike-client/` standalone crate OR `crates/mecmcp-client/examples/spike.rs` on a throwaway local branch; delete afterwards.
- Output: a 15-line findings comment on #637 and a one-line edit to this plan's Task 2 `Cargo.toml` choice.

**Interfaces:**
- Produces: decision `TRANSPORT = rmcp | handrolled` consumed by Tasks 2-4.

Static evidence already in hand: rmcp 3.10.0 has `transport-streamable-http-client` + `-reqwest` features, `src/transport/common/mcp_headers.rs`, header consts `HEADER_MCP_METHOD`, `HEADER_MCP_NAME`, `HEADER_MCP_PROTOCOL_VERSION` (`transport/common/http_header.rs:1-10`), `ClientRequestMetadata` carrying `client_info`/`client_capabilities` set when `!protocol_version.has_initialize()` (`service/client.rs:310,1000`), and a `StreamableHttpClientTransportConfig::allow_stateless` flag (`streamable_http_client.rs:2123`). The spike proves it on the wire.

- [ ] **Step 1: Capture what rmcp sends.** Start a raw `tokio::net::TcpListener` HTTP/1.1 stub (or `mecmcp-transport`'s `test_harness`, `--features test-util`) that logs request headers and bodies and answers `initialize`/`tools/list`/`tools/call` with canned 2026-07-28 JSON (bytes copied from `crates/mecmcp-transport/src/client_info.rs:493-503` and the `tools/list` ttlMs/cacheScope shape in memory `tools-list-cache-descriptor.md`). Drive it with `rmcp` `StreamableHttpClientTransport::with_client(reqwest::Client, config)` + `().serve(transport)` using `ClientInfo` declaring `ProtocolVersion::V_2026_07_28`, `uri` = the stub, `auth_header` = a dummy token, `custom_headers` containing `Mecmcp-Approver-Assertion: x`.
- [ ] **Step 2: Check the checklist** against the captured request for `tools/call`: `MCP-Protocol-Version: 2026-07-28`; `Mcp-Method: tools/call`; `Mcp-Name: <tool>`; body `params._meta` has `io.modelcontextprotocol/protocolVersion`, `.../clientInfo`, `.../clientCapabilities`; no `Mcp-Session-Id` sent or required; `Authorization: Bearer` present; the custom assertion header present on that one call only (rmcp custom headers are per-transport, not per-call: record whether per-call is possible); response as plain JSON AND as `text/event-stream` both parse; also run the same client against a legacy stub (`2025-11-25`: initialize + `Mcp-Session-Id`).
- [ ] **Step 3: Check the controls we need that rmcp may not give**: response-size cap during streaming, per-call timeout, redirect refusal and root-store replacement (supplied by our own `reqwest::Client`, so fine), unique JSON-RPC ids, per-call header injection (needed so the approver assertion goes ONLY on the approve call; `custom_headers` is transport-wide, so a second `McpClient` connect with the assertion is the fallback), and whether `rmcp` pulls a second `reqwest`/`rustls` provider (`cargo tree -d`, `cargo tree -i rustls`).
- [ ] **Step 4: Decide.**
  - **Branch R (rmcp) if** the checklist items in Step 2 all pass AND a size cap can be enforced by wrapping our own `reqwest::Client`-backed `StreamableHttpClient` impl (the trait is public, `streamable_http_client.rs:2351` shows a custom impl) AND `cargo tree -d` shows no duplicate rustls/reqwest. Tasks 2-4 use `rmcp::ServiceExt` + `RunningService<RoleClient, _>`; `Cargo.toml` gains `rmcp = { version = "3", default-features = false, features = ["client", "transport-streamable-http-client", "transport-streamable-http-client-reqwest"] }`.
  - **Branch H (hand-rolled) if** any Step 2 header/`_meta` is missing, a second TLS provider appears, or the cap/per-call header cannot be enforced. Tasks 2-4 build a minimal client over `reqwest` + `rmcp::model` types only (same posture as today's `mcp.rs`): POST per request with the recipe in memory `rmcp-stateless-request-recipe.md` (headers + `_meta`), unique ids from an `AtomicU64`, response read via `bytes_stream()` with a running cap, SSE `data:` frame parser limited to the single response event for the request id. Legacy (initialize + `Mcp-Session-Id`) is implemented only if Step 2's legacy run shows a family server still needs it; `ProtocolMode::Auto` then degrades to Stateless2026 only (see Task 3 note).
- [ ] **Step 5: Record the decision**: comment on #637 with the captured header list (tokens redacted) and the chosen branch; update Tasks 2-4 `Cargo.toml` lines below in this file. Clean up the scratch crate. Expected: nothing committed.

### Task 2: Crate skeleton: `ClientConfig`, `BearerToken`, `UntrustedText`, `ClientError`

**Files:**
- Create: `crates/mecmcp-client/Cargo.toml`, `crates/mecmcp-client/src/lib.rs`, `src/config.rs`, `src/token.rs`, `src/untrusted.rs`, `src/error.rs`
- Modify: `Cargo.toml:2` (add `"crates/mecmcp-client"` to `members`), `Cargo.lock`
- Test: unit tests in each file; `crates/mecmcp-client/tests/token_file.rs`

**Interfaces:**
- Consumes: `mecmcp_secret::{OutboundSecret, SecretLimits, SecretError, load_from_file, load_from_env}`; `mecmcp_approve::terminal::terminal_safe` logic (copied then deleted from approve in Task 5).
- Produces (all `pub`, JSDoc-style doc comments required):
  ```rust
  pub struct ClientConfig {
      pub url: url::Url,                       // validated https only, no userinfo
      pub token: BearerToken,
      pub ca_pem: Vec<String>,                 // non-empty replaces root store
      pub connect_timeout: Duration,           // default 10s
      pub request_timeout: Duration,           // default 30s, per call
      pub max_response_bytes: usize,           // default 8 MiB
      pub max_tool_pages: usize,               // default 32 (Task 4)
      pub protocol: ProtocolMode,              // Auto | Stateless2026 | Legacy
      pub client_name: String, pub client_version: String,
  }
  impl ClientConfig { pub fn new(url: &str, token: BearerToken) -> Result<Self, ClientError>; }
  pub enum ProtocolMode { Auto, Stateless2026, Legacy }
  pub struct BearerToken(OutboundSecret);      // Debug prints "BearerToken(<redacted>)"
  impl BearerToken {
      pub fn from_file(path: &Path) -> Result<Self, ClientError>; // load_from_file
      pub fn from_env(var: &str) -> Result<Self, ClientError>;
      pub fn from_secret(secret: OutboundSecret) -> Self;
  }
  pub struct UntrustedText(String);
  impl UntrustedText { pub fn new(raw: impl Into<String>) -> Self; pub fn raw(&self) -> &str; }
  // Display + Debug render terminal-safe text (C0 except \n \t, DEL, C1 escaped as \u{xx})
  #[non_exhaustive] pub enum ClientError {
      Config{field:&'static str}, Token(String /*SecretError display, path only*/), Tls, Connect,
      Timeout{operation:String}, Http{status:u16}, Protocol(String),
      Rpc{code:i64, message:UntrustedText}, Tool{content:UntrustedText},
      ResponseTooLarge{limit:usize}, Decode, Closed,
  }
  ```
  `ClientError: std::error::Error + Send + Sync`; no variant holds a token, an assertion or a raw `reqwest::Error` URL (strip with `without_url()`).

- [ ] **Step 1: Write failing tests.** `token_file.rs`: `rejects_group_readable_token_file` (0640 -> `Err(ClientError::Token(_))`), `rejects_symlink_token_file`, `strips_one_trailing_newline` (file `"abc\n"` loads `expose()=="abc"`), `rejects_empty_token_file`, `debug_never_contains_token` (format `{:?}` of config and error contains neither the secret nor "Bearer"). `untrusted.rs`: port the four `terminal.rs` tests (ANSI cursor/erase, newline/tab kept, unicode kept, DEL/C1 escaped) plus `display_escapes_osc8_hyperlink`. `config.rs`: `rejects_http_scheme`, `rejects_userinfo_in_url`, `rejects_zero_timeout`.
- [ ] **Step 2: Run and see them fail.** `cargo test -p mecmcp-client --locked` Expected: unresolved crate / compile errors.
- [ ] **Step 3: Implement** the types above. `from_file` calls `mecmcp_secret::load_from_file(path, SecretLimits::default())` (do not re-implement 0600/owner/symlink rules; ownership rule: effective uid or root). `ClientConfig::new` uses `url::Url::parse`, requires `scheme()=="https"`, empty username/password, no fragment. Cargo deps: `mecmcp-secret`, `url`, `thiserror`, `serde_json`, `tokio` (`time`), plus the Task 1 transport deps. NO dependency on `mecmcp-transport`, `mecmcp-http`'s concurrency queue, or any server feature (Decision 5). Use `mecmcp-http` only if Branch H wants its `HttpClientConfig`/CA parsing; otherwise build the `reqwest::Client` in Task 3 with the same rules.
- [ ] **Step 4: Run tests** Expected: PASS. Then `cargo tree -p mecmcp-client -d` shows no duplicate rmcp/reqwest/rustls; `cargo tree -p mecmcp-client | grep -c mecmcp-transport` prints 0.
- [ ] **Step 5: Sabotage** `from_file` (swap for `std::fs::read_to_string`): `rejects_group_readable_token_file` must fail; restore.
- [ ] **Step 6: Commit** `feat(client): mecmcp-client skeleton, token loading, untrusted text (#637)`.

### Task 3: Transport: `connect`, `call_tool`, timeouts, response cap, assertion header

**Files:**
- Create: `crates/mecmcp-client/src/client.rs`, `src/http.rs`, `tests/inprocess_server.rs`, `tests/support/mod.rs`
- Modify: `crates/mecmcp-client/src/lib.rs`, `crates/mecmcp-client/Cargo.toml` (dev-dep `mecmcp-transport = { path = "../mecmcp-transport", features = ["test-util"] }` ONLY under `[dev-dependencies]`)
- Modify: `.github/workflows/ci.yml:57` test line if a new feature flag is introduced (avoid one)

**Interfaces:**
- Consumes: Task 2 types.
- Produces:
  ```rust
  pub struct McpClient { /* inner transport, cfg */ }
  pub struct ToolOutput { pub structured: Option<serde_json::Value>, pub text: Vec<UntrustedText>, pub is_error: bool }
  impl McpClient {
      pub async fn connect(config: ClientConfig) -> Result<Self, ClientError>; // Auto: try 2026-07-28 stateless, fall back to initialize+session
      pub async fn call_tool(&self, name: &str, args: serde_json::Map<String, serde_json::Value>) -> Result<ToolOutput, ClientError>;
      pub async fn call_tool_with_assertion(&self, name: &str, args: Map<String, Value>, assertion: &OutboundSecret) -> Result<ToolOutput, ClientError>;
      pub async fn close(self);
  }
  pub const APPROVER_ASSERTION_HEADER: &str = "Mecmcp-Approver-Assertion"; // duplicated on purpose, pinned in Task 5
  ```
  `call_tool` returns `Ok` for `isError:true` results (`ToolOutput.is_error`), and `Err(ClientError::Tool)` only via a helper `ToolOutput::into_result()` so adopters choose; `mecmcp-approve` keeps its current "error becomes ApproveError" via that helper.

- [ ] **Step 1: Test harness.** `tests/support/mod.rs` boots an in-process family-style server using `mecmcp_transport::test_harness` (the loopback harness behind `test-util`; read its current public API first) with a trivial `echo` tool returning text + `structured_content`, over plain loopback HTTP is not allowed by the client's https-only rule: the harness test serves TLS with a generated CA (`rcgen` dev-dep) and the client gets that CA in `ca_pem`. If the harness cannot serve TLS, add a `#[cfg(test)]`-only `ClientConfig::danger_allow_http_for_tests` is NOT acceptable (no skip-verify/relaxation in the public API); instead terminate TLS in the test with `tokio-rustls` in front of the harness.
- [ ] **Step 2: Write failing tests** (`inprocess_server.rs`), each naming its assertion:
  - `stateless_call_sends_required_headers_and_meta`: server-side capture asserts `MCP-Protocol-Version == "2026-07-28"`, `Mcp-Method == "tools/call"`, `Mcp-Name == "echo"`, the three `_meta` keys present, no `Mcp-Session-Id`, `Authorization == "Bearer <token>"`.
  - `legacy_server_gets_initialize_and_session_id` (Auto fallback): second call reuses the `Mcp-Session-Id`; `close()` sends DELETE.
  - `sse_response_is_parsed` and `plain_json_response_is_parsed`.
  - `response_over_cap_is_rejected_while_streaming`: server streams > `max_response_bytes` with no Content-Length; expect `ResponseTooLarge` and that the server observed the connection closed before sending everything.
  - `slow_server_times_out_per_call`: `request_timeout = 200ms`, server sleeps 2s -> `Timeout{operation:"tools/call echo"}`; a following call on the same client still works.
  - `http_401_maps_to_http_error_without_token_in_message` (assert `!format!("{err} {err:?}").contains(token)`).
  - `host_mismatch_421_is_reported_as_http_421`.
  - `redirect_is_not_followed` (server 302 to another host: expect `Http{status:302}`, second host receives nothing).
  - `assertion_header_only_on_the_assertion_call`: plain `call_tool` after `call_tool_with_assertion` carries no `Mecmcp-Approver-Assertion`.
  - `rpc_error_message_is_escaped`: server error message `"\u{1b}[2Kboom"` -> `format!("{err}")` has no `\u{1b}`.
  - `concurrent_calls_use_distinct_jsonrpc_ids`.
- [ ] **Step 3: Run, see fail** `cargo test -p mecmcp-client --locked --test inprocess_server`.
- [ ] **Step 4: Implement** `src/http.rs`: `build_reqwest_client(&ClientConfig) -> Result<reqwest::Client, ClientError>` with `redirect::Policy::none()`, `.no_proxy()`, `https_only(true)`, `connect_timeout`, HTTP/1.1, `tls_built_in_root_certs(false)` + each `ca_pem` via `Certificate::from_pem` when non-empty, mirroring `mecmcp-http` `build_client` (`crates/mecmcp-http/src/lib.rs:1794`; read it for the exact builder calls) and requiring an installed rustls `aws-lc-rs` provider (fail with `ClientError::Tls` and a message naming `install_default`, as `HttpClient::new` does at `:1054`). `src/client.rs`:
  - Branch R: wrap `rmcp` `StreamableHttpClientTransport::with_client(client, StreamableHttpClientTransportConfig{ uri, auth_header: Some(token), allow_stateless: true, custom_headers: ..})`; implement the cap by supplying a `StreamableHttpClient` wrapper that counts bytes on the response stream; per-call timeout via `tokio::time::timeout` around `peer.call_tool`; assertion calls use a second short-lived transport so the header never rides on other calls (Task 1 Step 3 outcome).
  - Branch H: `send_request(method, params, per_call_headers) -> Result<Value, ClientError>`, ids from `AtomicU64` (start at 1), stateless headers/`_meta` per the recipe memory, body read via `bytes_stream()` summing against `max_response_bytes`, SSE parsing taking only the `data:` event whose `id` matches; legacy mode: one `initialize` + `notifications/initialized` guarded by `tokio::sync::OnceCell`, session id stored, `close()` DELETE.
  - Both: map `reqwest::Error` via `without_url()`; `is_timeout()` -> `Timeout`; `ToolOutput.text` built from `Text` content blocks as `UntrustedText`; non-text blocks become a fixed `"[image content omitted]"`-style marker (same strings as `mcp.rs` `render_text`, `mcp.rs:127`).
- [ ] **Step 5: Run tests** Expected: PASS. Then `cargo clippy -p mecmcp-client --all-targets --locked -- -D warnings`.
- [ ] **Step 6: Sabotage** one at a time, rerun the named test, restore: remove the byte-count check (cap test must fail); remove `Policy::none()` (redirect test); remove `Mcp-Name` insertion (stateless header test); send the assertion on every call (assertion test); skip `UntrustedText` escaping (rpc_error test).
- [ ] **Step 7: Commit** `feat(client): stateless and legacy transport, caps, timeouts, assertion header (#637)` (~400 lines; if over, split `http.rs` + config into its own commit).

### Task 4: `list_tools` (bounded cursor loop) and typed `call_tool_as`

**Files:**
- Modify: `crates/mecmcp-client/src/client.rs`, `crates/mecmcp-client/src/lib.rs`
- Test: `crates/mecmcp-client/tests/list_tools.rs`

**Interfaces:**
- Consumes: Task 3 `McpClient`, `ClientConfig::max_tool_pages`.
- Produces:
  ```rust
  impl McpClient {
      pub async fn list_tools(&self) -> Result<Vec<rmcp::model::Tool>, ClientError>;
      pub async fn call_tool_as<T: serde::de::DeserializeOwned>(&self, name: &str, args: Map<String, Value>) -> Result<T, ClientError>; // from structured_content; Decode if absent; Tool if is_error
  }
  ```

- [ ] **Step 1: Failing tests:** `follows_cursors_to_the_end` (3 pages); `stops_at_max_tool_pages_with_protocol_error` (server returns a self-referencing `nextCursor`); `tolerates_ttl_and_cache_scope` (2026-07-28 reply with `ttlMs`,`cacheScope`) and `legacy_reply_without_them`; `call_tool_as_decodes_structured_content`; `call_tool_as_tool_error_is_err_tool_with_escaped_content`; `call_tool_as_missing_structured_is_decode_error`; `list_tools_total_bytes_capped` (each page respects `max_response_bytes`).
- [ ] **Step 2: Run, fail.** **Step 3: Implement** the loop (break on `None` cursor, error `Protocol("tools/list cursor loop exceeded N pages")` otherwise; reject a repeated cursor immediately). Do not cache; ignore the cache descriptor beyond parsing it.
- [ ] **Step 4: Run tests, clippy.** **Step 5: Sabotage** the page bound (loop test must hang-fail under the 5s test timeout; use `tokio::time::timeout` in the test) and restore. **Step 6: Commit** `feat(client): list_tools and typed call_tool_as (#637)`.

### Task 5: Migrate `mecmcp-approve` onto `mecmcp-client`

**Files:**
- Modify: `crates/mecmcp-approve/Cargo.toml` (add `mecmcp-client`; keep `mecmcp-transport` only for the const-equality test or as a dev-dependency; drop the now-unused direct `rmcp`/`reqwest` features if nothing else needs them: `oidc.rs`/`http_bridge.rs` still need `reqwest`), `crates/mecmcp-approve/src/lib.rs:80,111`, `src/mcp.rs`, `src/error.rs` (the `ToolCall*` variants map from `ClientError`), `src/terminal.rs` (delegate to `UntrustedText`; keep `terminal_safe` as a thin wrapper used by `print` paths so output is identical), `src/cli.rs:53-63,174` (token via `BearerToken::from_file`/`from_env`; the OIDC access-token fallback uses `BearerToken::from_secret`)
- Test: existing `mcp.rs` in-file tests move to `crates/mecmcp-approve/tests/client_adoption.rs`

**Interfaces:**
- Consumes: `McpClient::{connect, call_tool, call_tool_with_assertion}`, `ToolOutput::into_result`, `ClientError`.
- Produces: `mcp::call_tool` removed; `mcp::render_text(&ToolOutput) -> String` and `mcp::structured_digest(&ToolOutput) -> Option<String>` keep their current behaviour (`render_text` at `mcp.rs:127`; signature changes from `&CallToolResult`).

- [ ] **Step 1: Write failing tests first** (adoption): `approve_flow_uses_one_client_and_assertion_only_on_approve` against the in-process server (preview call has no assertion header, approve call has `Mecmcp-Approver-Assertion == id_token`); `approver_assertion_header_matches_transport_const` (`assert_eq!(mecmcp_client::APPROVER_ASSERTION_HEADER, mecmcp_transport::APPROVER_ASSERTION_HEADER)`); `terminal_escape_regression` (port `mcp.rs:171-206`); `rpc_error_display_unchanged` snapshot (the pre-migration `ApproveError` strings captured before editing).
- [ ] **Step 2: Capture baseline**: `cargo test -p mecmcp-approve --locked 2>&1 | tail` and save the existing error-string assertions; they must still pass unmodified.
- [ ] **Step 3: Implement** the migration: build one `McpClient` after login in `lib.rs` (`ClientConfig` from `args.server_url`, optional `--ca-file` is NOT added; existing behaviour used the system root store, so `ca_pem` stays empty), map `ClientError` to the existing `ApproveError` variants (`Timeout`/`Http`->`ToolCallSend`, `Rpc`->`ToolCallRpcError { message: <already escaped> }`, `Tool`->`ToolCallToolError`, `Decode`->`ToolCallDecode`) so no user-visible string changes; delete `JsonRpcRequest/Response` and the hand-rolled POST. Update the `mcp.rs:1-12` module comment (decision reversed).
- [ ] **Step 4: Run** `cargo test -p mecmcp-approve --locked` and `cargo clippy -p mecmcp-approve --all-targets --locked -- -D warnings`. Expected: PASS; net diff negative.
- [ ] **Step 5: Real-wire check (optional, only if rig 611 is started for this and stopped after)**: run `mecmcp-approve` preview-only against test rig 611 (`61N -> .23N`, odd = labmode) using a read tool; record outcome in the PR description. Do NOT approve on a 900-series guest.
- [ ] **Step 6: Commit** `refactor(approve): use mecmcp-client, delete private tools/call POST (#637)`.

---

# Part B: cross-server plan digest (#636), Tasks 6-9

### Task 6: Plan digest function and golden vector (`mecmcp-changeset/src/plan.rs`)

**Files:**
- Create: `crates/mecmcp-changeset/src/plan.rs`, `crates/mecmcp-changeset/tests/plan_digest_test.rs`
- Modify: `crates/mecmcp-changeset/src/lib.rs` (`pub mod plan;` + re-exports)

**Interfaces:**
- Consumes: `digest::validate_digest`, `digest::DigestError`, `mecmcp_audit::validate_server_id` (dependency already present: changeset depends on audit).
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct PlanMember { pub order: u32, pub server_id: String, pub device: String, pub change_set_id: String, pub digest: String }
  pub const PLAN_DIGEST_DOMAIN: &str = "mecmcp-plan-v1";
  pub const MAX_PLAN_MEMBERS: usize = 32;
  pub fn plan_digest(members: &[PlanMember]) -> Result<String, DigestError>;     // validates, then sha256 of serde_json::to_vec(&(PLAN_DIGEST_DOMAIN, members_as_arrays))
  pub fn verify_plan_membership(members: &[PlanMember], claimed_plan_digest: &str, own_server_id: &str, own_change_set_id: &str, own_device: &str, own_change_set_digest: &str) -> Result<(), DigestError>;
  ```
  Canonical bytes: `["mecmcp-plan-v1", [[1,"junos-a","srx1","cs-1","sha256:..."], [2,"unifi-a",...]]]` (JSON arrays only, length framed, no separators; each member serialized as a 5-element array, not an object, so field order cannot drift). Output `sha256:<64 lowercase hex>`.

- [ ] **Step 1: Compute the golden vector independently.** Run (python3 -I, no repo imports):
  `python3 -I -c 'import hashlib,json; m=[[1,"junos-lab","srx1","cs-aaa","sha256:"+"a"*64],[2,"unifi-lab","udm1","cs-bbb","sha256:"+"b"*64]]; b=json.dumps(["mecmcp-plan-v1",m],separators=(",",":")).encode(); print(b.decode()); print("sha256:"+hashlib.sha256(b).hexdigest())'` and cross-check with `printf '%s' '<bytes>' | openssl dgst -sha256`. Paste the literal bytes and digest into the test with the command in a comment.
- [ ] **Step 2: Write failing tests** (`plan_digest_test.rs`): `golden_vector_matches_independent_computation`; `reordering_members_changes_digest` (swap order values and positions); `changing_any_one_field_changes_digest` (table over the 5 fields); `rejects_empty_plan`; `rejects_more_than_32_members`; `rejects_duplicate_server_and_change_set`; `rejects_non_contiguous_or_misnumbered_order` (orders 1,3; or 2,1); `rejects_bad_member_digest` (uppercase hex, short, no prefix); `rejects_server_id_with_pipe_or_space_or_empty` (use `validate_server_id`); `membership_ok_for_exact_match`; `membership_fails_when_own_digest_differs`; `membership_fails_when_device_differs`; `membership_fails_when_server_absent`; `membership_fails_when_claimed_digest_is_not_recomputed_digest`; `serde_rejects_unknown_member_field`.
- [ ] **Step 3: Run, fail.** `cargo test -p mecmcp-changeset --locked --test plan_digest_test`.
- [ ] **Step 4: Implement** per signatures; membership uses `subtle::ConstantTimeEq` for the digest comparison like `verify_approval_digest_v7`.
- [ ] **Step 5: Run** the CI test line (Global Constraints) for `-p mecmcp-changeset`. **Step 6: Sabotage:** drop the domain tag (golden test fails); drop order validation (misnumbered test fails); restore.
- [ ] **Step 7: Commit** `feat(changeset): cross-server plan digest and membership check (#636)`.

### Task 7: Approval digest v8 (keyed, binds `plan_digest`) and persistence, without touching v4-v7

**Files:**
- Modify: `crates/mecmcp-changeset/src/digest.rs` (add `compute_approval_digest_v8`, `verify_approval_digest_v8` after v7 at `:462/:502`), `records.rs:567` (`ApprovalRecord.plan_digest: Option<String>`, `#[serde(default, skip_serializing_if = "Option::is_none")]`), `persistence.rs` (read validation near `:323-350`, digest match near `:379` and the unsupported-version arm at `:483`, writer version selection at `:752`; add schema **10**), every `ApprovalRecord { .. }` literal (`changeset.rs:491,681,832`, `apply.rs:792`) gets `plan_digest: None`
- Test: `crates/mecmcp-changeset/tests/approval_v8_test.rs`, golden state fixtures under `crates/mecmcp-changeset/tests/fixtures/` (copies of existing v4-v9 state files must be re-used, not edited)

**Interfaces:**
- Consumes: Task 6 nothing at compile time (only a `&str` plan digest).
- Produces:
  ```rust
  pub fn compute_approval_digest_v8(key:&[u8], change_set_id:&str, plan_digest:&str /*change-set digest*/, cross_server_plan_digest:&str, preview_digest:Option<&str>, owner:&str, approver:&str, approved_at_unix:u64, mechanism:&str, approver_oidc:Option<(&str,&str)>, owner_subject:Option<(&str,&str)>) -> String; // HMAC-SHA256 over serde_json tuple with domain "mecmcp-approval-v8" + the v7 tuple fields + cross_server_plan_digest
  pub fn verify_approval_digest_v8(.., candidate:&str) -> bool; // constant time
  ```
  Naming note: the existing parameter called `plan_digest` in v4-v7 means the change-set digest; v8's new field is named `cross_server_plan_digest` in code and `plan_digest` only on the serialized `ApprovalRecord` field (document this in the doc comment to avoid confusion).
  Persistence rules: `plan_digest` is present iff `digest_version == 8`; v8 requires the approval key (`verify` returns `Err` naming the missing key); the keyed-downgrade gate at `:346` becomes `matches!(version, 6 | 7 | 8)`; the existing `mechanism/issuer/subject require v7` rule at `:323` becomes `!matches!(version, 7 | 8)`; writer selects file schema `10` only if any approval has `digest_version >= 8`, otherwise unchanged (9/8/...).

- [ ] **Step 1: Compute golden HMAC vector independently** with python `hmac.new(key, canonical_bytes, hashlib.sha256)` over the hand-written JSON tuple (domain first); cross-check `printf ... | openssl dgst -sha256 -hmac KEY`. Literal in the test.
- [ ] **Step 2: Write failing tests:** `v8_golden_vector`; `v8_differs_from_v7_for_same_inputs` (domain separation); `v8_binds_plan_digest` (changing it fails verify); `v7_golden_vectors_unchanged` and `v4_v5_v6_golden_vectors_unchanged` (compute with python at the same time, they must equal the existing literals if present, otherwise add); `v8_state_file_roundtrips_at_schema_10`; `deployment_without_plan_approvals_still_writes_schema_9` (state with a v7 approval serializes `"version": 9`) and same for v4-only state keeping its current version; `old_fixture_files_load_and_resave_byte_identical` (every file in `tests/fixtures` that is a state file: load -> save -> `assert_eq!` bytes, run before and after the change); `v8_without_key_is_rejected_on_load`; `plan_digest_on_a_v7_record_is_rejected`; `v8_record_missing_plan_digest_is_rejected`; `tampered_plan_digest_in_state_file_fails_load`; `unkeyed_v5_downgrade_of_a_v8_record_is_rejected_when_key_present`.
- [ ] **Step 3: Run, fail.** **Step 4: Implement** as specified; keep all v4-v7 match arms and docs untouched, add the v8 arm and update the `ApprovalRecord::digest_version` doc comment with v8.
- [ ] **Step 5: Run** the CI test line and `cargo clippy -p mecmcp-changeset --all-targets --all-features --locked -- -D warnings`.
- [ ] **Step 6: Sabotage:** remove the `plan_digest`-iff-v8 check (the two rejection tests fail); change `10` back to `9` in the writer (schema test fails); restore.
- [ ] **Step 7: Commit** `feat(changeset): approval digest v8 binding a cross-server plan digest (#636)`.

### Task 8: Coordinator `approve_change_set_in_plan` and evidence field

**Files:**
- Modify: `crates/mecmcp-changeset/src/changeset.rs` (new method next to `approve_change_set`, `:282`; refactor the shared checks into a private fn only if it removes duplication without touching the existing method's behaviour), `crates/mecmcp-audit/src/evidence.rs:43` (`ApprovalRecord` gains `plan_digest: Option<String>`, skipped when `None`) and `recorder.rs:434` (`approval_with_identity` gains the optional argument via a new `approval_with_plan` wrapper, keeping the old signature)
- Test: `crates/mecmcp-changeset/tests/plan_approval_test.rs` (`required-features = ["test-util"]`, add the `[[test]]` stanza like `preview_binding_test`), `crates/mecmcp-audit/tests/plan_evidence_test.rs`

**Interfaces:**
- Consumes: Task 6 `PlanMember`, `plan_digest`, `verify_plan_membership`; Task 7 `compute_approval_digest_v8`, `ApprovalRecord.plan_digest`; existing `ApproverIdentity` (`approver.rs:12`).
- Produces:
  ```rust
  pub struct PlanCitation { pub plan_digest: String, pub members: Vec<PlanMember> }
  impl Coordinator {
      pub async fn approve_change_set_in_plan(&self, change_set_id: String, device: String, approver: &ApproverIdentity, expected_digest: String, citation: &PlanCitation, own_server_id: &str) -> Result<ChangeSetOutput, CoordinatorError>;
  }
  ```
  Behaviour: runs the identical gate sequence as `approve_change_set` (digest format, self-approval, non-human, strict verified approver, state, expiry, digest match, preview validation), THEN `verify_plan_membership(.., own_server_id, &change_set_id, &device, &record.digest)`; requires `approval_digest_key().is_some()` else `CoordinatorError::new("approval_digest_key", "plan-bound approval requires a keyed approval digest ...")`; writes digest v8 with `plan_digest = Some(..)`. Lab-mode waiver path `waive_approval` unchanged (Decision 7); a new optional `plan_digest` is only forwarded to the evidence record by the vendor.

- [ ] **Step 1: Failing tests:** `approves_when_member_present_and_records_v8`; `rejects_when_plan_digest_does_not_match_members`; `rejects_member_digest_mismatch_with_record`; `rejects_wrong_server_id` (own id not in plan); `rejects_wrong_device`; `rejects_without_approval_key`; `self_approval_still_rejected_in_plan`; `non_human_still_rejected_in_plan`; `expired_change_set_rejected_in_plan`; `existing_approve_change_set_behaviour_unchanged` (reuse an existing v7 test input, assert the same digest); `audit`: `approval_evidence_without_plan_hashes_identically_to_before` (golden chain hash from a fixture captured before the change) and `approval_evidence_with_plan_digest_chains`.
- [ ] **Step 2: Run, fail.** **Step 3: Implement.** **Step 4: Run** CI test line incl. audit/changeset/transport features; fuzz `cargo check --manifest-path fuzz/Cargo.toml --bins`.
- [ ] **Step 5: Sabotage:** delete the `verify_plan_membership` call (three rejection tests fail); delete the key requirement (key test fails); restore.
- [ ] **Step 6: Commit** `feat(changeset,audit): plan-cited approval and plan digest in approval evidence (#636)`.

### Task 9: Docs and design note

**Files:**
- Modify: `docs/ARCHITECTURE.md`, `docs/CRATE-MAP.md` (new `mecmcp-client` row, `plan.rs` mention), `docs/THREAT-MODEL.md` (plan-digest section: binds server_id/order/device/digest; does not enforce apply order; planner-identity limit from Decision 3; rollback hazard from Decision 2), `README.md` crate list
- No code. Every command in the docs is run once and the output spot-checked (docs PRs need the gate; memory `docs-prs-need-the-gate-too`).

- [ ] **Step 1:** write the sections, including a worked example with the Task 6 golden vector and a runnable `python3 -I` one-liner a vendor can use to cross-check their digest.
- [ ] **Step 2:** run each documented command; fix mismatches. **Step 3:** `cargo doc --workspace --no-deps --locked` clean. **Step 4: Commit** `docs: mecmcp-client and cross-server plan digest (#636, #637)`.

---

# Release

### Task R: Release 0.35.0 and file vendor follow-ups

**Files:**
- Modify: `Cargo.toml:6` (`0.35.0`), every `crates/*/Cargo.toml` intra-workspace `version = "0.34.0"` pins (see `git show 2f10880 --stat` for the exact set, plus `mecmcp-client`), `Cargo.lock`, `fuzz/Cargo.lock`, `CHANGELOG.md` (hand-written `## [0.35.0] - <date>` entry: Added `mecmcp-client`, plan digest, approval digest v8, evidence `plan_digest`; Changed `mecmcp-approve` on the shared client; **Upgrade note: schema 10 / rollback hazard / key required**), `README.md` current-release line (separate follow-up PR as #635 did)
- Verify the new crate appears in `release-sbom.yml` (glob `crates/*/*.cdx.json`, no edit expected) and `scripts`/workflow conformance checks (`ci.yml:129-133`); note downstream pins (memory `sdc-packaging-pins-mecmcp-twice`: tag guard + SBOM guard, five files in rustsdcmcp) in the PR body.

- [ ] **Step 1:** bump versions, update changelog; minor bump because the public API of `mecmcp-changeset` (`ApprovalRecord` gains a field) and a new crate. Measure release notes against `v0.34.0`, not intermediate commits.
- [ ] **Step 2:** run the full CI command list locally (Global Constraints), incl. MSRV `cargo +1.89 check --workspace --locked` and the no-lockfile job command from `ci.yml:97-118`.
- [ ] **Step 3:** release PR `release: v0.35.0`, merge, tag `v0.35.0` on main, README bump PR. No fleet deploy is needed for this tag (library crates; family servers adopt on their own release).
- [ ] **Step 4: File follow-up issues** (do not plan their code), each referencing the tag, Decision 1 (`server_id` = evidence `server_id`), Decision 2 (schema 10, key required, rollback hazard) and the `PlanCitation`/`approve_change_set_in_plan` API:
  - **rustjunosmcp:** add optional `plan_digest` + `plan_members` params to `approve_junos_change_set`, call `approve_change_set_in_plan` with the evidence `server_id`, forward `plan_digest` to evidence; confirm `approval_digest_key` is configured on 609/950/610/611; test on rigs 610 (twoperson) and 611 (labmode) incl. the rollback caveat.
  - **rustunifimcp:** same for `unifi_approve_change_set`.
  - **rustproxmoxmcp:** same for `approve_proxmox_change_set` (`change_set.rs:162` `expected_digest` area); 971-class token scope check.
  - **mecintent (M3, external consumer):** compute the plan digest with `mecmcp_changeset::plan` (pin by git tag), use `mecmcp-client`; orchestrate ordered apply with stop-on-failure.
  - **fleet:** one cross-server end-to-end on rigs (even = twoperson, odd = labmode) across two servers; start rigs only for the test and stop them after.
  - Out of scope for all: sdc/panos/mist (other approval flows; PLN-003).

---

## Self-review notes

- Coverage: #637 bullets map to Tasks 2 (token rules, untrusted text, typed errors), 3 (transport, assertion header, timeouts, caps), 4 (`tools/list`), 5 (approve migration); #636 bullets map to 6 (digest), 7-8 (verify membership, record, evidence), 8 (lab mode unchanged, planner check via existing owner rule), orchestration explicitly out of scope.
- Known unpinned items an implementer must read first: `mecmcp_transport::test_harness` public API (Task 3), `mecmcp-http` `build_client` internals (Task 3), exact `[[test]]` stanza names (Task 8). Each task says where.
- Task sizes: Tasks 3 and 7 are the largest (~400); split as noted if they exceed it.
