//! Load-shedding concurrency middleware for global, per-token, and per-target
//! limits. Permits are attached to the response body (`GuardedBody`) so they
//! release at end-of-stream — rmcp runs the tool lazily while the SSE body is
//! polled, so a permit held only across the response future would release too
//! early.

use crate::config::LimitsConfig;
use crate::metrics;
use crate::overload::overload_response;
use crate::target::{TargetLimiter, extract_targets};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::LengthLimitError;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::limit::RequestBodyLimitLayer;

/// Shared concurrency state, cheaply cloneable.
#[derive(Clone)]
pub struct ConcurrencyState {
    global: Arc<Semaphore>,
    max_global: usize,
    /// Map grows unbounded with the number of distinct token names ever seen.
    /// In typical deployments, it is bounded by the token store's stable size
    /// (hot-reloads replace tokens atomically, not additively). If high-churn
    /// dynamic token provisioning becomes a use case, add LRU eviction or
    /// periodic cleanup of semaphores with zero permits in use.
    per_token: Arc<DashMap<String, Arc<Semaphore>>>,
    max_per_token: usize,
    per_target: TargetLimiter,
    max_per_target: usize,
    target_keys: Vec<String>,
    sessions: Option<Arc<crate::session::SessionTracker>>,
}

impl ConcurrencyState {
    /// Build from config. `sessions` enables the `session_cap` early-shed.
    pub fn new(
        cfg: &LimitsConfig,
        target_keys: Vec<String>,
        sessions: Option<Arc<crate::session::SessionTracker>>,
    ) -> Self {
        let global_permits = if cfg.max_inflight_requests > 0 {
            cfg.max_inflight_requests
        } else {
            1
        };
        Self {
            global: Arc::new(Semaphore::new(global_permits)),
            max_global: cfg.max_inflight_requests,
            per_token: Arc::new(DashMap::new()),
            max_per_token: cfg.max_inflight_requests_per_token,
            per_target: TargetLimiter::new(cfg.max_inflight_requests_per_device),
            max_per_target: cfg.max_inflight_requests_per_device,
            target_keys,
            sessions,
        }
    }

    fn token_sem(&self, token: &str) -> Arc<Semaphore> {
        self.per_token
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_token.max(1))))
            .clone()
    }
}

/// Axum middleware enforcing global + per-token concurrency with load-shed (non-buffering).
///
/// This middleware checks global and per-token concurrency limits without reading the
/// request body. It MUST run before the body limit layer to prevent unauthenticated
/// flooding and before per-target concurrency (which buffers the body).
///
/// **Execution order:** auth → token_rate → **token_concurrency** → body_limit → preflight → target_concurrency
pub async fn token_concurrency_middleware(
    State(state): State<ConcurrencyState>,
    req: Request,
    next: Next,
) -> Response {
    let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();
    let session_creating = is_session_creating(&req);
    let mut token_session_reservation = None;

    if state.max_global > 0 {
        match state.global.clone().try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(
                    limit = "global_concurrency",
                    max = state.max_global,
                    "request shed"
                );
                return overload_response("global_concurrency");
            }
        }
    }

    if state.max_per_token > 0
        && let Some(token) = crate::caller::token_name(req.extensions())
    {
        let sem = state.token_sem(token);
        match sem.try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(limit = "token_concurrency", token = %token, max = state.max_per_token, "request shed");
                return overload_response("token_concurrency"); // global permit drops here
            }
        }
    }

    if let Some(tracker) = &state.sessions
        && session_creating
        && tracker.at_capacity()
    {
        tracing::warn!(limit = "session_cap", "request shed");
        return overload_response("session_cap");
    }

    if session_creating
        && let Some(tracker) = state.sessions.as_ref()
        && let Some(token) = crate::caller::token_name(req.extensions())
    {
        match tracker.try_reserve_token(token.to_owned()) {
            Ok(reservation) => token_session_reservation = reservation,
            Err(capacity) => {
                tracing::warn!(
                    limit = "token_session_cap",
                    token = %token,
                    current = capacity.current,
                    max = capacity.max,
                    "request shed"
                );
                let mut response = overload_response("token_session_cap");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }

    let (mut resp, session_cap_rejected) = if session_creating {
        crate::session::scope_session_cap_rejection(next.run(req)).await
    } else {
        (next.run(req).await, false)
    };

    if session_cap_rejected {
        tracing::warn!(
            limit = "session_cap",
            "request shed after manager registration race"
        );
        resp = overload_response("session_cap");
    }

    if let Some(reservation) = token_session_reservation
        && resp.status().is_success()
    {
        match resp
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        {
            Some(session_id) => {
                let id: rmcp::transport::common::server_side_http::SessionId =
                    Arc::from(session_id);
                let _ = reservation.commit(id);
            }
            None => tracing::warn!(
                limit = "token_session_cap",
                "successful initialize candidate returned no valid session id"
            ),
        }
    }

    attach_permits(resp, permits)
}

/// Axum middleware enforcing per-target concurrency with load-shed (buffering).
///
/// This middleware buffers the request body to extract target device names,
/// then checks per-target concurrency limits. It MUST run AFTER body limit
/// (so buffering is bounded) and AFTER preflight/authorization (so unauthorized
/// requests never acquire target permits).
///
/// **Execution order:** auth → token_rate → token_concurrency → body_limit → preflight → **target_concurrency**
pub async fn target_concurrency_middleware(
    State(state): State<ConcurrencyState>,
    mut req: Request,
    next: Next,
) -> Response {
    let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();

    if state.max_per_target > 0 {
        let (rebuilt, targets) = match inspect_target_devices(req, &state.target_keys).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        req = rebuilt;

        match state.per_target.try_acquire(&targets) {
            Ok(mut target_permits) => permits.append(&mut target_permits),
            Err(target) => {
                tracing::warn!(
                    limit = "target_concurrency",
                    target = %target,
                    max = state.max_per_target,
                    "request shed"
                );
                let mut response = overload_response("target_concurrency");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }

    attach_permits(next.run(req).await, permits)
}

/// Axum middleware enforcing global + per-token + per-target concurrency with load-shed.
///
/// **DEPRECATED:** Use `token_concurrency_middleware` before body limit and
/// `target_concurrency_middleware` after preflight instead. This combined middleware
/// cannot be correctly ordered when per-target limits are enabled: the buffering
/// `inspect_target_devices` call would run before the body limit layer.
#[deprecated(
    since = "0.6.0",
    note = "Use token_concurrency_middleware + target_concurrency_middleware split"
)]
pub async fn concurrency_middleware(
    State(state): State<ConcurrencyState>,
    mut req: Request,
    next: Next,
) -> Response {
    let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();
    let session_creating = is_session_creating(&req);
    let mut token_session_reservation = None;

    if state.max_global > 0 {
        match state.global.clone().try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(
                    limit = "global_concurrency",
                    max = state.max_global,
                    "request shed"
                );
                return overload_response("global_concurrency");
            }
        }
    }

    if state.max_per_token > 0
        && let Some(token) = crate::caller::token_name(req.extensions())
    {
        let sem = state.token_sem(token);
        match sem.try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => {
                tracing::warn!(limit = "token_concurrency", token = %token, max = state.max_per_token, "request shed");
                return overload_response("token_concurrency"); // global permit drops here
            }
        }
    }

    if let Some(tracker) = &state.sessions
        && session_creating
        && tracker.at_capacity()
    {
        tracing::warn!(limit = "session_cap", "request shed");
        return overload_response("session_cap");
    }

    if session_creating
        && let Some(tracker) = state.sessions.as_ref()
        && let Some(token) = crate::caller::token_name(req.extensions())
    {
        match tracker.try_reserve_token(token.to_owned()) {
            Ok(reservation) => token_session_reservation = reservation,
            Err(capacity) => {
                tracing::warn!(
                    limit = "token_session_cap",
                    token = %token,
                    current = capacity.current,
                    max = capacity.max,
                    "request shed"
                );
                let mut response = overload_response("token_session_cap");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }

    if state.max_per_target > 0 {
        let (rebuilt, targets) = match inspect_target_devices(req, &state.target_keys).await {
            Ok(result) => result,
            Err(response) => return response,
        };
        req = rebuilt;

        match state.per_target.try_acquire(&targets) {
            Ok(mut target_permits) => permits.append(&mut target_permits),
            Err(target) => {
                tracing::warn!(
                    limit = "target_concurrency",
                    target = %target,
                    max = state.max_per_target,
                    "request shed"
                );
                let mut response = overload_response("target_concurrency");
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                return response;
            }
        }
    }

    let (mut resp, session_cap_rejected) = if session_creating {
        crate::session::scope_session_cap_rejection(next.run(req)).await
    } else {
        (next.run(req).await, false)
    };
    if session_cap_rejected {
        tracing::warn!(
            limit = "session_cap",
            "request shed after manager registration race"
        );
        resp = overload_response("session_cap");
    }
    if let Some(reservation) = token_session_reservation
        && resp.status().is_success()
    {
        match resp
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        {
            Some(session_id) => {
                let id: rmcp::transport::common::server_side_http::SessionId =
                    Arc::from(session_id);
                let _ = reservation.commit(id);
            }
            None => tracing::warn!(
                limit = "token_session_cap",
                "successful initialize candidate returned no valid session id"
            ),
        }
    }
    attach_permits(resp, permits)
}

// Rust 1.98's `clippy::result_large_err` flags the 128-byte `Response` in the
// `Err` position and suggests boxing it. Boxing would achieve nothing here: a
// `Result` is as large as its largest variant, and the `Ok` variant is the
// bigger one. Measured on this toolchain: `Response` 128 bytes,
// `(Request, Vec<String>)` 264, and the `Result` is 264 either way — boxing the
// error leaves it at 264 and adds a heap allocation on the rejection path.
//
// The `Err` is a fully-formed HTTP rejection (413 or 400) handed back for early
// return, which is the natural currency of this layer.
#[allow(clippy::result_large_err)]
async fn inspect_target_devices(
    req: Request,
    target_keys: &[String],
) -> Result<(Request, Vec<String>), Response> {
    if req.method() != Method::POST {
        return Ok((req, Vec::new()));
    }

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            if is_length_limit_error(&error) {
                tracing::warn!(error = %error, "request body rejected while extracting target devices");
                // Return marked 413 so it's counted and normalized to JSON
                return Err(crate::auth::marked_body_limit_response());
            } else {
                tracing::warn!(error = %error, "request body stream failed while extracting target devices");
                return Err(StatusCode::BAD_REQUEST.into_response());
            }
        }
    };
    let targets = extract_targets(&bytes, target_keys);
    Ok((Request::from_parts(parts, Body::from(bytes)), targets))
}

fn is_length_limit_error(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<LengthLimitError>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

/// A session-creating request = a *legacy* POST without an `Mcp-Session-Id`
/// header.
///
/// The protocol check is not cosmetic. Under rmcp 3, `handle_post` computes
/// `use_session = legacy_session_mode && is_legacy_request(..)`, so a client
/// declaring `2026-07-28` is routed statelessly **even though
/// `legacy_session_mode` is `true`** — and a stateless POST carries no
/// `Mcp-Session-Id`, because there is no session. Counting those as
/// session-creating would charge every ordinary `tools/call` against
/// `--max-sessions` and `--max-sessions-per-token`, so a modern client would
/// start collecting 503s the moment it made `max_sessions` calls, and each one
/// would leave a spurious reservation behind.
///
/// `MCP-Protocol-Version` is the cheap discriminator: rmcp requires it on every
/// request from a modern client and validates it itself. Matching on the header
/// rather than reparsing the body keeps this from drifting against rmcp's own
/// (body- and `_meta`-aware) definition, and it is correct in both directions —
/// a legacy client never sends `>= 2026-07-28`, so its initialize still counts;
/// a modern client always does, so its stateless calls never do.
///
/// This governs a *resource limit*, not an authorization decision. The scope
/// preflight remains the security boundary.
///
/// **Known divergence, accepted deliberately.** rmcp permits a modern client to
/// omit `MCP-Protocol-Version` on its *first* `initialize`, reading
/// `params.protocolVersion` from the body instead. This classifier is
/// header-only, so it counts that one request as session-creating and would shed
/// it with a 503 if the cap were already full. The alternative is parsing the
/// JSON body here to recover the version, which duplicates rmcp's
/// body-and-`_meta`-aware `is_legacy_request` in a second place — and a
/// divergent copy of protocol detection is a worse long-run failure than a
/// conservative count. The blast radius is one request per client, only at
/// capacity, and it errs toward over-counting rather than letting a limit
/// silently lapse. Revisit alongside the `MCP-Protocol-Version` work in #166.
fn is_session_creating(req: &Request) -> bool {
    req.method() == axum::http::Method::POST
        && !req.headers().contains_key("mcp-session-id")
        && !declares_stateless_protocol(req.headers())
}

/// True when the client declares a protocol revision at or after the stateless
/// core (`2026-07-28`). Unparseable or absent means legacy.
fn declares_stateless_protocol(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("mcp-protocol-version")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|version| version >= rmcp::model::ProtocolVersion::STANDARD_HEADERS.as_str())
}

async fn observe_body_limit_response(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        // Check if already marked (from inspect_target_devices or other origins)
        if response
            .extensions()
            .get::<crate::auth::BodyLimitMarker>()
            .is_none()
        {
            // Unmarked tower-http response: mark it and count it here
            metrics::record_limit_hit("request_body", "request_rejected");
            response
                .extensions_mut()
                .insert(crate::auth::BodyLimitMarker);
        }
        // Marked responses: already counted at their origin, do nothing
    }
    response
}

/// Apply the request-body size limit as the outermost concern. `0` disables.
pub fn apply_body_limit(router: axum::Router, cfg: &LimitsConfig) -> axum::Router {
    if cfg.max_request_body_bytes > 0 {
        router
            .layer(RequestBodyLimitLayer::new(cfg.max_request_body_bytes))
            .layer(axum::middleware::from_fn(observe_body_limit_response))
    } else {
        router
    }
}

/// Move the held permits into the response body so they release at end-of-stream.
fn attach_permits(resp: Response, permits: Vec<OwnedSemaphorePermit>) -> Response {
    if permits.is_empty() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    Response::from_parts(
        parts,
        Body::new(GuardedBody {
            inner: body,
            _permits: permits,
        }),
    )
}

/// Response body wrapper that owns concurrency permits until the body ends.
struct GuardedBody {
    inner: Body,
    _permits: Vec<OwnedSemaphorePermit>,
}

impl HttpBody for GuardedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // axum::body::Body is Unpin, so GuardedBody is Unpin.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(deprecated)] // Tests for old concurrency_middleware and old streamable_http_server_config
mod tests {
    use super::*;
    use crate::config::streamable_http_server_config;

    fn post_with(headers: &[(&str, &str)]) -> Request {
        let mut builder = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    /// A pre-2026-07-28 client still opens a session, so its initialize must
    /// keep consuming session capacity.
    #[test]
    fn legacy_initialize_still_counts_as_session_creating() {
        assert!(is_session_creating(&post_with(&[])));
        assert!(is_session_creating(&post_with(&[(
            "mcp-protocol-version",
            "2025-06-18"
        )])));
    }

    /// rmcp 3 routes a 2026-07-28 client's POSTs statelessly even with
    /// `legacy_session_mode = true`, and a stateless POST carries no
    /// Mcp-Session-Id. Counting those would charge every tools/call against
    /// --max-sessions, so a modern client would start collecting 503s after
    /// max_sessions ordinary calls.
    #[test]
    fn stateless_post_from_a_modern_client_does_not_consume_session_capacity() {
        assert!(!is_session_creating(&post_with(&[(
            "mcp-protocol-version",
            "2026-07-28"
        )])));
    }

    /// A request already carrying a session id was never session-creating.
    #[test]
    fn request_with_a_session_id_is_never_session_creating() {
        assert!(!is_session_creating(&post_with(&[(
            "mcp-session-id",
            "abc"
        )])));
    }

    /// rmcp 3 enforces its own body limit inside the service, after
    /// apply_body_limit has accepted the request. If the two disagree, requests
    /// between them are rejected by a limit the operator never configured.
    #[test]
    fn server_config_body_limit_tracks_limits_config() {
        let cfg = LimitsConfig {
            max_request_body_bytes: 9 * 1024 * 1024,
            ..LimitsConfig::default()
        };
        assert_eq!(
            streamable_http_server_config(&cfg).max_request_body_bytes,
            9 * 1024 * 1024,
            "rmcp's 4 MiB default must not silently override the configured limit"
        );
    }

    #[test]
    fn server_config_maps_unlimited_to_usize_max() {
        let cfg = LimitsConfig {
            max_request_body_bytes: 0,
            ..LimitsConfig::default()
        };
        assert_eq!(
            streamable_http_server_config(&cfg).max_request_body_bytes,
            usize::MAX,
            "0 means unlimited here; rmcp has no spelling for it"
        );
    }
    use axum::Router;
    use axum::body::Bytes;
    use axum::routing::{get, post};
    use mecmcp_auth::{CallerCtx, ScopeSet};
    use serde_json::{Value, json};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::{Barrier, Notify, Semaphore};
    use tokio::time::timeout;
    use tower::ServiceExt as _; // oneshot

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);

    fn ctx(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_string(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    fn target_keys() -> Vec<String> {
        vec![
            "device".to_owned(),
            "device_name".to_owned(),
            "devices".to_owned(),
            "device_names".to_owned(),
        ]
    }

    fn initialize_request(token: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "limits-test", "version": "1"}
                    }
                })
                .to_string(),
            ))
            .unwrap();
        request.extensions_mut().insert(ctx(token));
        request
    }

    fn token_session_state(max: usize) -> (ConcurrencyState, Arc<crate::session::SessionTracker>) {
        let cfg = LimitsConfig {
            max_inflight_requests: 0,
            max_inflight_requests_per_token: 0,
            max_inflight_requests_per_device: 0,
            max_sessions: 0,
            max_sessions_per_token: max,
            ..Default::default()
        };
        let tracker = Arc::new(crate::session::SessionTracker::new(&cfg));
        (
            ConcurrencyState::new(&cfg, target_keys(), Some(tracker.clone())),
            tracker,
        )
    }

    fn tool_request(arguments: Value) -> Request<Body> {
        Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("mcp-session-id", "test-session")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": arguments}
                })
                .to_string(),
            ))
            .unwrap()
    }

    /// The mechanism behind mecmcp#86, pinned deterministically.
    ///
    /// The CI failures could not be reproduced locally — the old code passed
    /// forty consecutive runs under deliberate CPU load — because the losing
    /// window is a few instructions wide and depends on the runner's scheduling.
    /// So rather than chase the symptom, this pins the primitive's semantics,
    /// which is what the fix actually relies on.
    ///
    /// `notify_waiters` stores nothing: a notification sent before a task
    /// registers is gone forever, and that task then waits indefinitely. A
    /// `Semaphore` permit persists, so the same ordering is harmless. In the
    /// middleware tests the "task" is a request handler that has signalled
    /// `entered` but not yet reached its await.
    #[tokio::test(flavor = "multi_thread")]
    async fn notify_waiters_is_lost_when_nobody_is_registered_yet_but_a_permit_is_not() {
        // Notify: the wake-up happens before anyone waits, and is dropped.
        let notify = Arc::new(Notify::new());
        notify.notify_waiters();
        let missed = timeout(Duration::from_millis(150), notify.notified())
            .await
            .is_err();
        assert!(
            missed,
            "notify_waiters must not be observable by a later waiter; if this ever \
             passes, the flaky-test fix rests on a false premise"
        );

        // Semaphore: the same ordering, and the permit is still there.
        let release = Arc::new(Semaphore::new(0));
        release.add_permits(1);
        let acquired = timeout(Duration::from_millis(150), release.acquire_owned())
            .await
            .expect("a permit granted before the waiter arrived must still be available");
        acquired.expect("semaphore closed").forget();
    }

    /// A handler that announces entry, then blocks until `release` grants a permit.
    ///
    /// `release` is a `Semaphore` rather than a `Notify` deliberately.
    /// `Notify::notify_waiters` wakes only tasks already registered and stores
    /// nothing, so a handler that had signalled `entered` but not yet reached its
    /// await would miss the wake-up entirely and block until the test timed out.
    /// That window is tiny and load-dependent, which is exactly why it surfaced as
    /// a flaky CI failure rather than a reproducible one (mecmcp#86).
    ///
    /// Semaphore permits persist, so the test cannot lose the race however the two
    /// tasks interleave.
    fn blocking_post_router(release: Arc<Semaphore>, entered: Arc<Notify>) -> Router {
        Router::new().route(
            "/mcp",
            post(move || {
                let release = release.clone();
                let entered = entered.clone();
                async move {
                    entered.notify_one();
                    release
                        .acquire_owned()
                        .await
                        .expect("release semaphore closed")
                        .forget();
                    "ok"
                }
            }),
        )
    }

    fn target_state(max_per_target: usize) -> ConcurrencyState {
        ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 0,
                max_inflight_requests_per_token: 0,
                max_inflight_requests_per_device: max_per_target,
                max_sessions: 0,
                ..Default::default()
            },
            target_keys(),
            None,
        )
    }

    /// A handler that blocks until `release` grants a permit, so we can pin permits.
    ///
    /// See [`blocking_post_router`] for why this is a `Semaphore`.
    fn blocking_router(release: Arc<Semaphore>) -> Router {
        Router::new().route(
            "/mcp",
            get(move || {
                let release = release.clone();
                async move {
                    release
                        .acquire_owned()
                        .await
                        .expect("release semaphore closed")
                        .forget();
                    "ok"
                }
            }),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_token_session_cap_binds_response_and_isolates_tokens() {
        let (state, tracker) = token_session_state(1);
        let app = Router::new()
            .route(
                "/mcp",
                post({
                    let tracker = tracker.clone();
                    move |axum::Extension(caller): axum::Extension<CallerCtx>| {
                        let tracker = tracker.clone();
                        async move {
                            let session_id = format!("{}-session", caller.token_name);
                            let tracked_id = Arc::from(session_id.as_str());
                            tracker.note_session_created(&tracked_id);
                            assert!(tracker.try_register(tracked_id, std::time::Instant::now()));
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("mcp-session-id", session_id)
                                .body(Body::empty())
                                .unwrap()
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                concurrency_middleware,
            ));

        let first = app
            .clone()
            .oneshot(initialize_request("alice"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        drop(first);

        let shed = app
            .clone()
            .oneshot(initialize_request("alice"))
            .await
            .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(shed.headers().get("retry-after").unwrap(), "1");
        assert_eq!(
            shed.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(shed.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "overloaded", "limit": "token_session_cap"})
        );

        let bob = app
            .clone()
            .oneshot(initialize_request("bob"))
            .await
            .unwrap();
        assert_eq!(bob.status(), StatusCode::OK);
        tracker.unregister(&Arc::from("alice-session"));
        let alice_again = app.oneshot(initialize_request("alice")).await.unwrap();
        assert_eq!(alice_again.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_initialize_releases_token_session_reservation() {
        let (state, tracker) = token_session_state(1);
        let active_in_handler = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/mcp",
                post({
                    let active_in_handler = active_in_handler.clone();
                    let calls = calls.clone();
                    let tracker = tracker.clone();
                    move || {
                        let active_in_handler = active_in_handler.clone();
                        let calls = calls.clone();
                        let tracker = tracker.clone();
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            active_in_handler
                                .lock()
                                .unwrap()
                                .push(tracker.active_for_token("alice"));
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                concurrency_middleware,
            ));

        let first = app
            .clone()
            .oneshot(initialize_request("alice"))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(tracker.active_for_token("alice"), 0);

        let second = app.oneshot(initialize_request("alice")).await.unwrap();
        assert_eq!(second.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(tracker.active_for_token("alice"), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(*active_in_handler.lock().unwrap(), vec![1, 1]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_initialize_releases_token_session_reservation() {
        let (state, tracker) = token_session_state(1);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new()
            .route(
                "/mcp",
                post({
                    let entered = entered.clone();
                    let release = release.clone();
                    let tracker = tracker.clone();
                    move || {
                        let entered = entered.clone();
                        let release = release.clone();
                        let tracker = tracker.clone();
                        async move {
                            entered.notify_one();
                            timeout(TEST_TIMEOUT, release.notified())
                                .await
                                .expect("initialize handler was not released");
                            let session_id = Arc::from("alice-cancel-session");
                            tracker.note_session_created(&session_id);
                            assert!(tracker.try_register(session_id, std::time::Instant::now()));
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("mcp-session-id", "alice-cancel-session")
                                .body(Body::empty())
                                .unwrap()
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                concurrency_middleware,
            ));

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(initialize_request("alice"))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("first initialize did not enter the handler");
        assert_eq!(tracker.active_for_token("alice"), 1);

        first.abort();
        let cancelled = timeout(TEST_TIMEOUT, first)
            .await
            .expect("aborted initialize task did not finish")
            .expect_err("aborted initialize unexpectedly completed");
        assert!(cancelled.is_cancelled());
        assert_eq!(tracker.active_for_token("alice"), 0);

        let second_app = app.clone();
        let second = tokio::spawn(async move {
            second_app
                .oneshot(initialize_request("alice"))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("replacement initialize did not enter the handler");
        release.notify_one();
        let response = timeout(TEST_TIMEOUT, second)
            .await
            .expect("replacement initialize did not finish")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn marked_session_cap_response_is_isolated_and_releases_token_reservation() {
        let (recorder, handle) = crate::metrics::test_recorder("junosmcp");
        let recorder_guard = ::metrics::set_default_local_recorder(&recorder);
        let (state, tracker) = token_session_state(1);
        let barrier = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/mcp",
                post({
                    let barrier = barrier.clone();
                    let calls = calls.clone();
                    move |axum::Extension(caller): axum::Extension<CallerCtx>| {
                        let barrier = barrier.clone();
                        let calls = calls.clone();
                        async move {
                            let call = calls.fetch_add(1, Ordering::SeqCst);
                            if call < 2 {
                                barrier.wait().await;
                            }
                            if caller.token_name == "marked" {
                                crate::session::mark_session_cap_rejected();
                            }
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state,
                concurrency_middleware,
            ));

        let marked_app = app.clone();
        let marked = tokio::spawn(async move {
            marked_app
                .oneshot(initialize_request("marked"))
                .await
                .unwrap()
        });
        let plain_app = app.clone();
        let plain = tokio::spawn(async move {
            plain_app
                .oneshot(initialize_request("plain"))
                .await
                .unwrap()
        });
        let marked = timeout(TEST_TIMEOUT, marked)
            .await
            .expect("marked initialize did not finish")
            .unwrap();
        let plain = timeout(TEST_TIMEOUT, plain)
            .await
            .expect("plain initialize did not finish")
            .unwrap();

        assert_eq!(marked.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(marked.headers().get("retry-after").unwrap(), "1");
        assert!(marked.headers().get("mcp-session-id").is_none());
        let body = axum::body::to_bytes(marked.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "overloaded", "limit": "session_cap"})
        );
        assert_eq!(plain.status(), StatusCode::INTERNAL_SERVER_ERROR);
        drop(plain);

        let later_plain = app.oneshot(initialize_request("plain")).await.unwrap();
        assert_eq!(later_plain.status(), StatusCode::INTERNAL_SERVER_ERROR);
        drop(later_plain);
        assert_eq!(tracker.active_for_token("marked"), 0);
        assert_eq!(tracker.active_for_token("plain"), 0);
        assert_eq!(tracker.pending_reservation_count(), 0);

        drop(recorder_guard);
        handle.run_upkeep();
        let text = handle.render();
        let client_rejections = text
            .lines()
            .filter(|line| {
                line.starts_with("junosmcp_limit_hits_total{")
                    && line.contains("limit=\"session_cap\"")
                    && line.contains("event=\"request_rejected\"")
            })
            .collect::<Vec<_>>();
        assert_eq!(client_rejections.len(), 1, "unexpected metrics:\n{text}");
        assert!(client_rejections[0].ends_with(" 1"));
        assert!(
            !text.contains("event=\"session_registration_rejected\""),
            "unexpected manager rejection metric:\n{text}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_target_sheds_same_target_and_isolates_different_target() {
        let release = Arc::new(Semaphore::new(0));
        let entered = Arc::new(Notify::new());
        let app = blocking_post_router(release.clone(), entered.clone()).layer(
            axum::middleware::from_fn_with_state(target_state(1), concurrency_middleware),
        );

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(tool_request(json!({"device": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("first request did not enter the handler");

        let same = timeout(
            Duration::from_millis(200),
            app.clone()
                .oneshot(tool_request(json!({"device_name": "r1"}))),
        )
        .await
        .expect("same-target request queued instead of being shed")
        .unwrap();
        assert_eq!(same.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(same.headers().get("retry-after").unwrap(), "1");
        assert_eq!(
            same.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(same.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"error": "overloaded", "limit": "target_concurrency"})
        );

        let other_app = app.clone();
        let other = tokio::spawn(async move {
            other_app
                .oneshot(tool_request(json!({"device": "r2"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("different-target request did not enter the handler");

        // Two handlers are blocked: the first-target request and the
        // different-target one.
        release.add_permits(2);
        let first = timeout(TEST_TIMEOUT, first)
            .await
            .expect("first request did not finish")
            .unwrap();
        let other = timeout(TEST_TIMEOUT, other)
            .await
            .expect("different-target request did not finish")
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(other.status(), StatusCode::OK);
        drop(first);
        drop(other);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn target_permit_lives_until_response_body_is_dropped() {
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(target_state(1), concurrency_middleware),
        );

        let first = app
            .clone()
            .oneshot(tool_request(json!({"device": "r1"})))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let shed = app
            .clone()
            .oneshot(tool_request(json!({"device": "r1"})))
            .await
            .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(first);
        let admitted = app
            .oneshot(tool_request(json!({"device": "r1"})))
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn aborted_request_releases_target_permit() {
        let release = Arc::new(Semaphore::new(0));
        let entered = Arc::new(Notify::new());
        let app = blocking_post_router(release.clone(), entered.clone()).layer(
            axum::middleware::from_fn_with_state(target_state(1), concurrency_middleware),
        );

        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(tool_request(json!({"device": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("first request did not enter the handler");

        first.abort();
        let cancelled = timeout(TEST_TIMEOUT, first)
            .await
            .expect("aborted request task did not finish")
            .expect_err("aborted request unexpectedly completed");
        assert!(cancelled.is_cancelled());

        let second_app = app.clone();
        let second = tokio::spawn(async move {
            second_app
                .oneshot(tool_request(json!({"device": "r1"})))
                .await
                .unwrap()
        });
        timeout(TEST_TIMEOUT, entered.notified())
            .await
            .expect("target permit was not released after request cancellation");

        // Only the replacement handler is blocked; the original request was
        // aborted, so its handler future was dropped.
        release.add_permits(1);
        let response = timeout(TEST_TIMEOUT, second)
            .await
            .expect("replacement request did not finish")
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_json_is_replayed_unchanged() {
        let app = Router::new()
            .route("/mcp", post(|body: Bytes| async move { body }))
            .layer(axum::middleware::from_fn_with_state(
                target_state(1),
                concurrency_middleware,
            ));
        let original = Bytes::from_static(b"not-json");
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from(original.clone()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        let replayed = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(replayed, original);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn streamed_body_over_outer_limit_stays_413() {
        let (recorder, handle) = crate::metrics::test_recorder("junosmcp");
        let _guard = ::metrics::set_default_local_recorder(&recorder);

        let cfg = LimitsConfig {
            max_request_body_bytes: 8,
            max_inflight_requests: 0,
            max_inflight_requests_per_token: 0,
            max_inflight_requests_per_device: 1,
            max_sessions: 0,
            ..Default::default()
        };
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(
                ConcurrencyState::new(&cfg, target_keys(), None),
                concurrency_middleware,
            ),
        );
        let app = apply_body_limit(app, &cfg);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/mcp")
                    .body(Body::from("ok"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let stream = futures::stream::iter([Ok::<_, Infallible>(Bytes::from_static(
            b"more-than-eight-bytes",
        ))]);
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from_stream(stream))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        drop(_guard);
        handle.run_upkeep();
        let text = handle.render();
        let line = text
            .lines()
            .find(|line| line.starts_with("junosmcp_limit_hits_total{"))
            .expect("request-body counter sample");
        assert!(line.contains("limit=\"request_body\""));
        assert!(line.contains("event=\"request_rejected\""));
        assert!(line.ends_with(" 1"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fallible_body_stream_is_bad_request_not_payload_too_large() {
        let app = Router::new().route("/mcp", post(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(target_state(1), concurrency_middleware),
        );
        let stream = futures::stream::iter([Err::<Bytes, _>(std::io::Error::other(
            "request body stream failed",
        ))]);
        let request = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/mcp")
            .body(Body::from_stream(stream))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn global_concurrency_sheds_over_limit() {
        let state = ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 1,
                max_inflight_requests_per_token: 0,
                ..Default::default()
            },
            target_keys(),
            None,
        );
        let release = Arc::new(Semaphore::new(0));
        let app = blocking_router(release.clone()).layer(axum::middleware::from_fn_with_state(
            state,
            concurrency_middleware,
        ));

        // First request occupies the only permit (held on the blocked handler).
        let app2 = app.clone();
        let inflight = tokio::spawn(async move {
            app2.oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second concurrent request must be shed with 503.
        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers().get("retry-after").unwrap(), "1");

        // Release the first; its permit frees.
        release.add_permits(1);
        let first = timeout(TEST_TIMEOUT, inflight)
            .await
            .expect("global-limited request did not finish")
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        // A new request now succeeds (permit freed at end-of-body).
        // Drain the first response body first to release its GuardedBody permit.
        let _ = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_token_isolated() {
        let state = ConcurrencyState::new(
            &LimitsConfig {
                max_inflight_requests: 0,
                max_inflight_requests_per_token: 1,
                ..Default::default()
            },
            target_keys(),
            None,
        );
        let release = Arc::new(Semaphore::new(0));
        let app = blocking_router(release.clone()).layer(axum::middleware::from_fn_with_state(
            state,
            concurrency_middleware,
        ));

        // token "a" occupies its single per-token permit.
        let app_a = app.clone();
        let inflight = tokio::spawn(async move {
            let mut req = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
            req.extensions_mut().insert(ctx("a"));
            app_a.oneshot(req).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // second "a" request is shed...
        let mut req_a2 = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
        req_a2.extensions_mut().insert(ctx("a"));
        let resp_a2 = app.clone().oneshot(req_a2).await.unwrap();
        assert_eq!(resp_a2.status(), StatusCode::SERVICE_UNAVAILABLE);

        // ...but token "b" still has its own permit (isolated from "a").
        // Start token "b" request before releasing token "a" to prove isolation.
        let app_b = app.clone();
        let req_b_task = tokio::spawn(async move {
            let mut req_b = Request::builder().uri("/mcp").body(Body::empty()).unwrap();
            req_b.extensions_mut().insert(ctx("b"));
            app_b.oneshot(req_b).await.unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Release both and verify "b" succeeded.
        release.add_permits(2);
        let _ = timeout(TEST_TIMEOUT, inflight)
            .await
            .expect("token a request did not finish")
            .unwrap();
        let resp_b = timeout(TEST_TIMEOUT, req_b_task)
            .await
            .expect("token b request did not finish")
            .unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
    }
}
