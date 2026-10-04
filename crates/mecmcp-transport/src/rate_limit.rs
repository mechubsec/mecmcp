//! Per-token and per-IP request-rate limiting using a token-bucket algorithm.

use crate::config::LimitsConfig;
use crate::overload::rate_limited_response;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderName;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Non-standard but de facto universal header a reverse proxy sets to the
/// original client address. Not in `axum::http::header` because it was never
/// standardized (`Forwarded` per RFC 7239 is, but no deployed proxy this crate
/// has to interoperate with emits it).
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Resolve the address used as the per-IP rate-limit key.
///
/// Returns `peer` unchanged unless `peer` itself is inside `trusted_proxies`
/// **and** the request carries a well-formed `X-Forwarded-For` header. This
/// ordering is the entire security property: an untrusted peer's own
/// `X-Forwarded-For` header is never consulted, so it cannot spoof its way
/// into a different rate-limit bucket than its real address.
///
/// When trusted, every `X-Forwarded-For` header line is collected (a proxy
/// may add its own header line rather than appending to an existing one),
/// each line's comma-separated entries are walked **right to left**, and the
/// first entry that does not itself parse into a `trusted_proxies` address is
/// used. Deployed reverse proxies (nginx, Traefik, Caddy, ALB) *append* the
/// real client to any value the client already sent, so the rightmost
/// untrusted entry — not the leftmost — is the one the trusted proxy actually
/// recorded. Walking from the right also resolves multi-hop trusted chains
/// without special-casing. If an entry fails to parse, or every entry is
/// trusted, the walk falls back to `peer` rather than skipping the bad entry
/// — an unparsable value is exactly where a spoofed one would hide.
/// Only `pub` (not `pub(crate)`) because `fuzz/` is a separate crate outside
/// this workspace and needs a public path to reach it; the `#[doc(hidden)]`
/// re-export in `lib.rs` keeps it out of the crate's documented API.
pub fn resolve_rate_limit_ip(
    peer: IpAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    // Canonicalize first: a dual-stack listener reports an IPv4 peer as
    // `::ffff:a.b.c.d`, which would never match an IPv4 `trusted_proxies`
    // CIDR even when the same host is intended. Mirrors the loopback check in
    // `metrics.rs` (MEC-48).
    let peer = peer.to_canonical();
    if !trusted_proxies
        .iter()
        .any(|network| network.contains(&peer))
    {
        return peer;
    }

    let mut entries: Vec<&str> = Vec::new();
    for value in headers.get_all(&X_FORWARDED_FOR) {
        // A non-visible-ASCII header line is exactly the "unparsable entry"
        // case the doc above promises to fail closed on: skipping it (rather
        // than falling back to `peer`) would silently drop it from the
        // right-to-left walk instead of stopping the walk at it.
        let Ok(value) = value.to_str() else {
            return peer;
        };
        entries.extend(value.split(','));
    }

    for entry in entries.into_iter().rev() {
        // Canonicalize each parsed entry for the same reason `peer` is
        // canonicalized above: a trusted proxy on a dual-stack socket can
        // write its own address as `::ffff:a.b.c.d`, which would otherwise
        // both dodge the `trusted_proxies` match (letting a trusted hop's own
        // address leak through as the "client") and produce a rate-limit key
        // that differs from the same host's IPv4 form.
        let Ok(addr) = entry
            .trim()
            .parse::<IpAddr>()
            .map(|addr| addr.to_canonical())
        else {
            return peer;
        };
        if !trusted_proxies
            .iter()
            .any(|network| network.contains(&addr))
        {
            return addr;
        }
    }

    peer
}

/// Maximum number of per-IP buckets before LRU eviction begins.
///
/// An unbounded map keyed by source IP is trivial to exhaust via spoofed or
/// rotating addresses. This cap matches PAN-OS's deployed `MAX_IP_WINDOWS = 8_192`.
/// When the map is full and a new IP arrives, the oldest-accessed entry is evicted.
const MAX_IP_BUCKETS: usize = 8_192;

/// Maximum number of per-token buckets before LRU eviction begins.
///
/// Deployed configurations have bounded token sets, but a malformed or hostile
/// bearer header could still drive unbounded growth. This cap matches PAN-OS's
/// deployed `MAX_TOKEN_WINDOWS = 2_048`. When the map is full and a new token
/// arrives, the oldest-accessed entry is evicted.
const MAX_TOKEN_BUCKETS: usize = 2_048;

/// Nanosecond scale factor for token-bucket arithmetic.
const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateDecision {
    Allowed,
    Limited { retry_after_secs: u64 },
}

#[derive(Debug)]
struct Bucket {
    available_units: u128,
    last_refill: Instant,
}

impl Bucket {
    fn full(burst: u64, now: Instant) -> Self {
        Self {
            available_units: capacity_units(burst),
            last_refill: now,
        }
    }

    fn check(&mut self, now: Instant, rate: u64, burst: u64) -> RateDecision {
        if let Some(elapsed) = now.checked_duration_since(self.last_refill) {
            self.available_units = self
                .available_units
                .saturating_add(refill_units(elapsed, rate))
                .min(capacity_units(burst));
            self.last_refill = now;
        }

        if self.available_units >= TOKEN_SCALE {
            self.available_units -= TOKEN_SCALE;
            return RateDecision::Allowed;
        }

        let deficit_units = TOKEN_SCALE - self.available_units;
        let wait_ns = deficit_units.div_ceil(u128::from(rate));
        let retry_secs = wait_ns.div_ceil(TOKEN_SCALE).max(1);
        RateDecision::Limited {
            retry_after_secs: u64::try_from(retry_secs).unwrap_or(u64::MAX),
        }
    }
}

/// Bounded LRU map for rate-limit buckets.
///
/// When the map reaches `max_size` and a new key arrives, the entry with the
/// oldest `last_access` timestamp is evicted before inserting the new bucket.
#[derive(Debug)]
struct BucketMap {
    buckets: HashMap<String, (Bucket, Instant)>,
    max_size: usize,
}

impl BucketMap {
    fn new(max_size: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            max_size,
        }
    }

    fn check(&mut self, key: &str, now: Instant, rate: u64, burst: u64) -> RateDecision {
        if !self.buckets.contains_key(key)
            && self.buckets.len() >= self.max_size
            && let Some(oldest_key) = self
                .buckets
                .iter()
                .min_by_key(|(_, (_, last_access))| last_access)
                .map(|(k, _)| k.to_owned())
        {
            self.buckets.remove(&oldest_key);
        }

        let (bucket, last_access) = self
            .buckets
            .entry(key.to_owned())
            .or_insert_with(|| (Bucket::full(burst, now), now));
        *last_access = now;
        bucket.check(now, rate, burst)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[derive(Clone)]
struct RateLimitState {
    ip_buckets: Arc<Mutex<BucketMap>>,
    token_buckets: Arc<Mutex<BucketMap>>,
    ip_rate_per_second: u64,
    ip_burst: u64,
    token_rate_per_second: u64,
    token_burst: u64,
    trusted_proxies: Arc<[IpNet]>,
}

impl RateLimitState {
    /// Whether the per-IP dimension is configured.
    fn ip_rate_limit_enabled(&self) -> bool {
        self.ip_rate_per_second > 0 && self.ip_burst > 0
    }

    fn new(config: &LimitsConfig) -> Self {
        debug_assert!(
            config.ip_rate_limit_enabled() || config.token_rate_limit_enabled(),
            "rate limiting must be enabled for at least one dimension"
        );
        Self {
            ip_buckets: Arc::new(Mutex::new(BucketMap::new(MAX_IP_BUCKETS))),
            token_buckets: Arc::new(Mutex::new(BucketMap::new(MAX_TOKEN_BUCKETS))),
            ip_rate_per_second: config.max_requests_per_second_per_ip,
            ip_burst: config.max_request_burst_per_ip,
            token_rate_per_second: config.max_requests_per_second_per_token,
            token_burst: config.max_request_burst_per_token,
            trusted_proxies: Arc::from(config.trusted_proxies.as_slice()),
        }
    }

    fn check_ip(&self, ip: &str, now: Instant) -> RateDecision {
        if self.ip_rate_per_second == 0 || self.ip_burst == 0 {
            return RateDecision::Allowed;
        }
        self.ip_buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(ip, now, self.ip_rate_per_second, self.ip_burst)
    }

    fn check_token(&self, token: &str, now: Instant) -> RateDecision {
        if self.token_rate_per_second == 0 {
            return RateDecision::Allowed;
        }
        self.token_buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(token, now, self.token_rate_per_second, self.token_burst)
    }
}

/// Warn exactly once that per-IP limiting is configured but unreachable.
///
/// Once, not per request: a server mounted without `ConnectInfo` would otherwise
/// emit this on every single request and bury everything else in the log.
fn warn_missing_connect_info_once() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "per-IP rate limiting is configured but no ConnectInfo is present; \
             per-IP limits are NOT being enforced. Serve the router with \
             `into_make_service_with_connect_info::<SocketAddr>()` to enable them. \
             Per-token limiting is unaffected."
        );
    });
}

/// `ConnectInfo` is **optional**, deliberately.
///
/// As a required extractor it rejects with `500 Internal Server Error` whenever
/// the peer address is absent — which is not an error condition, it is a
/// property of how the server was mounted. A router served without
/// `into_make_service_with_connect_info`, or exercised via `oneshot` in a test,
/// has no `ConnectInfo`, and turning that into a 500 converts a mounting nuance
/// into a total outage on every request. That is exactly what happened when
/// rustpanosmcp first adopted this crate: every request 500'd, including ones
/// that should have been 401.
///
/// Absence is not attacker-controllable — `ConnectInfo` is inserted by the
/// server's own make-service, never by the client — so skipping the per-IP
/// dimension when it is missing is safe. Per-token limiting still applies. The
/// misconfiguration is surfaced by a warning rather than by failing closed.
async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let now = Instant::now();

    // Read from extensions rather than taking `ConnectInfo` as an extractor: a
    // required extractor rejects with 500 when the peer address is absent, and
    // `Option<ConnectInfo<_>>` needs `OptionalFromRequestParts`, which axum does
    // not provide for it. Extensions is where the make-service puts it anyway.
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    if peer.is_none() && state.ip_rate_limit_enabled() {
        warn_missing_connect_info_once();
    }
    let ip = peer
        .map(|peer| resolve_rate_limit_ip(peer, request.headers(), &state.trusted_proxies))
        .map(|ip| ip.to_string());

    if let Some(ip) = ip.as_deref()
        && let RateDecision::Limited { retry_after_secs } = state.check_ip(ip, now)
    {
        tracing::warn!(
            limit = "ip_rate",
            ip = ip,
            rate = state.ip_rate_per_second,
            burst = state.ip_burst,
            retry_after_secs,
            "request rate limited by IP"
        );
        return rate_limited_response("ip_rate", retry_after_secs);
    }

    if let Some(token) = crate::caller::token_name(request.extensions())
        && let RateDecision::Limited { retry_after_secs } = state.check_token(token, now)
    {
        tracing::warn!(
            limit = "token_rate",
            token = %token,
            rate = state.token_rate_per_second,
            burst = state.token_burst,
            retry_after_secs,
            "request rate limited by token"
        );
        return rate_limited_response("token_rate", retry_after_secs);
    }

    next.run(request).await
}

/// Per-IP rate limiting middleware (must run BEFORE authentication).
///
/// Checks only the IP dimension. Unauthenticated requests (missing/malformed/unknown
/// tokens) are rate-limited by their source IP, preventing authentication floods
/// and warning-log spam from driving unbounded work.
///
/// This middleware MUST run before authentication so that 401 responses consume
/// the source IP's budget.
async fn ip_rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let now = Instant::now();

    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    if peer.is_none() && state.ip_rate_limit_enabled() {
        warn_missing_connect_info_once();
    }
    let ip = peer
        .map(|peer| resolve_rate_limit_ip(peer, request.headers(), &state.trusted_proxies))
        .map(|ip| ip.to_string());

    if let Some(ip) = ip.as_deref()
        && let RateDecision::Limited { retry_after_secs } = state.check_ip(ip, now)
    {
        tracing::warn!(
            limit = "ip_rate",
            ip = ip,
            rate = state.ip_rate_per_second,
            burst = state.ip_burst,
            retry_after_secs,
            "request rate limited by IP"
        );
        return rate_limited_response("ip_rate", retry_after_secs);
    }

    next.run(request).await
}

/// Per-token rate limiting middleware (must run AFTER authentication).
///
/// Checks only the per-token dimension. Requires `AuthenticatedToken` to be present
/// in request extensions (inserted by the bearer authentication layer).
///
/// This middleware MUST run after authentication so it can see the authenticated
/// token identity.
async fn token_rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let now = Instant::now();

    if let Some(token) = crate::caller::token_name(request.extensions())
        && let RateDecision::Limited { retry_after_secs } = state.check_token(token, now)
    {
        tracing::warn!(
            limit = "token_rate",
            token = %token,
            rate = state.token_rate_per_second,
            burst = state.token_burst,
            retry_after_secs,
            "request rate limited by token"
        );
        return rate_limited_response("token_rate", retry_after_secs);
    }

    next.run(request).await
}

/// Apply per-IP rate limiting middleware (must run BEFORE authentication).
///
/// If per-IP limiting is disabled in the config, the router is returned unchanged.
///
/// This middleware checks only the source IP dimension and must run BEFORE
/// authentication so that unauthenticated requests (missing/malformed/unknown tokens)
/// consume the IP's budget, preventing authentication floods.
pub fn apply_ip_rate_limit(router: Router, config: &LimitsConfig) -> Router {
    if !config.ip_rate_limit_enabled() {
        return router;
    }
    router.layer(axum::middleware::from_fn_with_state(
        RateLimitState::new(config),
        ip_rate_limit_middleware,
    ))
}

/// Apply per-token rate limiting middleware (must run AFTER authentication).
///
/// If per-token limiting is disabled in the config, the router is returned unchanged.
///
/// This middleware checks only the per-token dimension and must run AFTER
/// authentication so it can see `AuthenticatedToken` in request extensions.
pub fn apply_token_rate_limit(router: Router, config: &LimitsConfig) -> Router {
    if !config.token_rate_limit_enabled() {
        return router;
    }
    router.layer(axum::middleware::from_fn_with_state(
        RateLimitState::new(config),
        token_rate_limit_middleware,
    ))
}

/// Apply per-IP and per-token rate limiting middleware to the router.
///
/// **DEPRECATED:** Use `apply_ip_rate_limit` and `apply_token_rate_limit` separately
/// to control their placement relative to authentication. IP rate limiting must run
/// BEFORE authentication (so unauthenticated requests consume IP budget), while
/// per-token rate limiting must run AFTER authentication (to see the token identity).
///
/// This function applies both dimensions together, which prevents correct ordering
/// when used with bearer authentication. It is retained for backward compatibility
/// with consumers that do not use bearer authentication.
///
/// If both limits are disabled in the config, the router is returned unchanged.
#[deprecated(
    since = "0.6.0",
    note = "Use apply_ip_rate_limit and apply_token_rate_limit separately"
)]
pub fn apply_rate_limit(router: Router, config: &LimitsConfig) -> Router {
    if !config.ip_rate_limit_enabled() && !config.token_rate_limit_enabled() {
        return router;
    }
    router.layer(axum::middleware::from_fn_with_state(
        RateLimitState::new(config),
        rate_limit_middleware,
    ))
}

fn capacity_units(burst: u64) -> u128 {
    u128::from(burst).saturating_mul(TOKEN_SCALE)
}

fn refill_units(elapsed: Duration, rate: u64) -> u128 {
    elapsed.as_nanos().saturating_mul(u128::from(rate))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, deprecated)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use axum::routing::post;
    use mecmcp_auth::{CallerCtx, ScopeSet};
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    fn caller(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_owned(),
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

    fn request(token: Option<&str>, addr: SocketAddr) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .extension(ConnectInfo(addr))
            .body(Body::empty())
            .unwrap();
        if let Some(token) = token {
            request.extensions_mut().insert(caller(token));
        }
        request
    }

    fn state(ip_rate: u64, ip_burst: u64, token_rate: u64, token_burst: u64) -> RateLimitState {
        RateLimitState::new(&LimitsConfig {
            max_requests_per_second_per_ip: ip_rate,
            max_request_burst_per_ip: ip_burst,
            max_requests_per_second_per_token: token_rate,
            max_request_burst_per_token: token_burst,
            ..Default::default()
        })
    }

    fn addr(ip: &str) -> SocketAddr {
        format!("{ip}:1234").parse().unwrap()
    }

    #[test]
    fn fresh_bucket_admits_exact_burst_then_limits() {
        let state = state(0, 0, 2, 3);
        let now = Instant::now();
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", now),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn partial_refill_reaches_exact_token_boundary() {
        let state = state(0, 0, 2, 1);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(250)),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[test]
    fn long_idle_refill_is_capped_at_burst() {
        let state = state(0, 0, 4, 2);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        let later = start + Duration::from_secs(60);
        assert_eq!(state.check_token("alice", later), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", later), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", later),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn token_names_are_isolated() {
        let state = state(0, 0, 1, 1);
        let now = Instant::now();
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert!(matches!(
            state.check_token("alice", now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(state.check_token("bob", now), RateDecision::Allowed);
    }

    #[test]
    fn ip_addresses_are_isolated() {
        let state = state(1, 1, 0, 0);
        let now = Instant::now();
        assert_eq!(state.check_ip("192.168.1.1", now), RateDecision::Allowed);
        assert!(matches!(
            state.check_ip("192.168.1.1", now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(state.check_ip("192.168.1.2", now), RateDecision::Allowed);
    }

    #[test]
    fn per_ip_bucket_map_evicts_lru_when_full() {
        let mut map = BucketMap::new(3);
        let now = Instant::now();
        map.check("ip1", now, 1, 1);
        map.check("ip2", now + Duration::from_millis(1), 1, 1);
        map.check("ip3", now + Duration::from_millis(2), 1, 1);
        assert_eq!(map.len(), 3);

        // Access ip2 to make ip1 the LRU
        map.check("ip2", now + Duration::from_millis(3), 1, 1);

        // Adding ip4 should evict ip1
        map.check("ip4", now + Duration::from_millis(4), 1, 1);
        assert_eq!(map.len(), 3);
        assert!(!map.buckets.contains_key("ip1"));
        assert!(map.buckets.contains_key("ip2"));
        assert!(map.buckets.contains_key("ip3"));
        assert!(map.buckets.contains_key("ip4"));
    }

    #[test]
    fn sustained_rate_never_exceeds_ceiling_across_window_boundary() {
        // This is the property test that validates D1: the token bucket must
        // prevent the 2× rate spike a fixed window admits at the boundary.
        let state = state(0, 0, 10, 5);
        let mut now = Instant::now();
        let mut admitted = 0;
        let mut rejected = 0;

        // Drain the burst
        for _ in 0..5 {
            if state.check_token("client", now) == RateDecision::Allowed {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 5);

        // Sustain for 10 seconds at the exact refill rate (10/s)
        for _ in 0..100 {
            now += Duration::from_millis(100);
            match state.check_token("client", now) {
                RateDecision::Allowed => admitted += 1,
                RateDecision::Limited { .. } => rejected += 1,
            }
        }

        // Total admitted: burst (5) + refill over 10s (10/s × 10s = 100) = 105
        assert_eq!(admitted, 105);
        assert_eq!(rejected, 0);

        // Now attempt 20 requests instantly (simulating a window-boundary burst)
        for _ in 0..20 {
            match state.check_token("client", now) {
                RateDecision::Allowed => admitted += 1,
                RateDecision::Limited { .. } => rejected += 1,
            }
        }

        // The bucket should have no tokens left, so all 20 are rejected
        assert_eq!(admitted, 105);
        assert_eq!(rejected, 20);
    }

    #[test]
    fn concurrent_checks_admit_exactly_the_burst() {
        const BURST: usize = 8;
        let state = Arc::new(state(0, 0, 1, BURST as u64));
        let barrier = Arc::new(std::sync::Barrier::new(BURST * 2));
        let now = Instant::now();
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..BURST * 2)
                .map(|_| {
                    let state = state.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        state.check_token("alice", now) == RateDecision::Allowed
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, BURST);
    }

    #[test]
    fn refill_arithmetic_saturates() {
        assert_eq!(refill_units(Duration::MAX, u64::MAX), u128::MAX);
    }

    #[test]
    fn earlier_instant_does_not_move_refill_clock_backward() {
        let state = state(0, 0, 2, 1);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert!(matches!(
            state.check_token("alice", start + Duration::from_millis(250)),
            RateDecision::Limited { .. }
        ));
        assert!(matches!(
            state.check_token("alice", start),
            RateDecision::Limited { .. }
        ));
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn middleware_returns_exact_429_and_isolates_tokens_and_ips() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let limited = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            limited.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"token_rate"}"#
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("bob"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.2")))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_ip_rate_limit_enforced_before_token_limit() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let limited = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"ip_rate"}"#
        );

        // Different IP is allowed even with same token
        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.2")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancellation_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let entered = Arc::new(Notify::new());
        let never_release = Arc::new(Notify::new());
        let handler = {
            let entered = entered.clone();
            let never_release = never_release.clone();
            move || {
                let entered = entered.clone();
                let never_release = never_release.clone();
                async move {
                    entered.notify_one();
                    never_release.notified().await;
                    StatusCode::OK
                }
            }
        };
        let app = apply_rate_limit(Router::new().route("/", post(handler)), &config);
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
        });
        entered.notified().await;
        first.abort();
        let _ = first.await;

        let second = app
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn downstream_error_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::INTERNAL_SERVER_ERROR })),
            &config,
        );

        let first = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let second = app
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// Regression: a router with no `ConnectInfo` must still serve.
    ///
    /// `ConnectInfo` was previously a required extractor, so its absence
    /// rejected with 500 — on *every* request, including ones that should have
    /// been 401. That is not hypothetical: it is what rustpanosmcp saw the first
    /// time it adopted this crate, because its tests drive the router with
    /// `oneshot`, which has no peer address. A server mounted without
    /// `into_make_service_with_connect_info` would have behaved the same way in
    /// production.
    #[tokio::test]
    async fn missing_connect_info_does_not_500() {
        use axum::routing::get;
        use tower::ServiceExt as _;

        let config = LimitsConfig {
            max_requests_per_second_per_ip: 100,
            max_request_burst_per_ip: 100,
            max_requests_per_second_per_token: 100,
            max_request_burst_per_token: 100,
            ..LimitsConfig::default()
        };
        let app = apply_rate_limit(Router::new().route("/", get(|| async { "ok" })), &config);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "absent ConnectInfo must skip per-IP limiting, not fail the request"
        );
    }

    fn request_with_forwarded_for(addr: SocketAddr, forwarded_for: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/")
            .extension(ConnectInfo(addr));
        if let Some(value) = forwarded_for {
            builder = builder.header("x-forwarded-for", value);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn untrusted_peer_forwarded_for_is_ignored() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "10.0.0.99".parse().unwrap());
            map
        };
        let peer: IpAddr = "203.0.113.5".parse().unwrap();
        // No trusted proxies configured at all: the header must never be consulted.
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[]), peer);
    }

    #[test]
    fn peer_outside_trusted_proxy_range_is_not_honored() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "10.0.0.99".parse().unwrap());
            map
        };
        let peer: IpAddr = "203.0.113.5".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        // The header names a trusted-looking CIDR, but the *peer* is not in it.
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[trusted]), peer);
    }

    #[test]
    fn trusted_proxy_forwarded_for_is_honored() {
        // "10.0.0.1" is the trusted proxy's own address (it equals `peer`
        // below), so the walk skips it and uses "198.51.100.7" — the real
        // client address the proxy recorded — as the rate-limit key.
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "198.51.100.7, 10.0.0.1".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            resolve_rate_limit_ip(peer, &headers, &[trusted]),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    /// Deployed reverse proxies (nginx `$proxy_add_x_forwarded_for`, Traefik,
    /// Caddy, ALB) append the real client to whatever value the client itself
    /// sent — they do not replace it. The leftmost entry is therefore
    /// attacker-controlled, not the proxy's own record; only the rightmost
    /// untrusted entry can be relied on.
    #[test]
    fn trusted_proxy_single_header_client_appended_is_honored() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "1.1.1.1, 203.0.113.9".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            resolve_rate_limit_ip(peer, &headers, &[trusted]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    /// HAProxy's `option forwardfor` adds a *second* `X-Forwarded-For` header
    /// line rather than appending to an existing one. `HeaderMap::get` only
    /// sees the first line; the resolver must use `get_all` to see both.
    #[test]
    fn trusted_proxy_multiple_header_lines_uses_all_of_them() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.append("x-forwarded-for", "2.2.2.2".parse().unwrap());
            map.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            resolve_rate_limit_ip(peer, &headers, &[trusted]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    /// Multi-hop chain: an inner trusted proxy's own entry is skipped, and
    /// the walk continues past it to the real client further left.
    #[test]
    fn trusted_proxy_multi_hop_chain_skips_trusted_inner_hop() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "203.0.113.9, 10.0.0.2".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(
            resolve_rate_limit_ip(peer, &headers, &[trusted]),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_proxy_with_malformed_forwarded_for_falls_back_to_peer() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[trusted]), peer);
    }

    /// A spoofed entry hiding behind a malformed one must not be skipped over:
    /// the walk stops and falls back to `peer` at the first unparsable entry.
    #[test]
    fn trusted_proxy_malformed_entry_after_real_client_falls_back_to_peer() {
        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "203.0.113.9, not-an-ip".parse().unwrap());
            map
        };
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[trusted]), peer);
    }

    /// Acceptance criterion: an untrusted peer's forged `X-Forwarded-For` does
    /// not let it evade its own per-IP rate-limit bucket.
    ///
    /// Without trusted-proxy support the header is inert either way, so the
    /// meaningful assertion is that two *different* untrusted peers spoofing
    /// the *same* `X-Forwarded-For` value are still limited independently —
    /// if the header were honored, they would collide into one bucket and
    /// only the first would be limited.
    #[tokio::test]
    async fn forged_forwarded_for_from_untrusted_peer_does_not_share_a_bucket() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            trusted_proxies: Vec::new(),
            ..Default::default()
        };
        let app = apply_ip_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        // Peer A claims to be 9.9.9.9 via a forged header.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("9.9.9.9")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Peer A is now rate-limited on its own real address.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("9.9.9.9")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Peer B, a different real address, also claiming 9.9.9.9, is unaffected
        // by A's limit — proving the forged header never became the bucket key.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.2"),
                    Some("9.9.9.9")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    /// Acceptance criterion: a configured trusted proxy's forwarded IP does
    /// drive the per-IP rate-limit bucket.
    #[tokio::test]
    async fn trusted_proxy_forwarded_for_drives_the_rate_limit_bucket() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            trusted_proxies: vec!["192.168.1.0/24".parse().unwrap()],
            ..Default::default()
        };
        let app = apply_ip_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        // The proxy (192.168.1.1, trusted) forwards two different real clients.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("203.0.113.10")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Same forwarded client through the same trusted proxy: limited on the
        // forwarded address, not the proxy's own (shared) address.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("203.0.113.10")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // A different forwarded client through the same trusted proxy is
        // unaffected — the bucket key is the forwarded address, isolated per
        // real client rather than collapsed onto the proxy's address.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("203.0.113.11")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    /// F2 regression: an IPv4-mapped (`::ffff:a.b.c.d`) entry must resolve to
    /// the same rate-limit key as its plain-IPv4 form, both when it is the
    /// trusted proxy's own address (must be skipped, not returned as the
    /// "client") and when it is the client address itself (must not open a
    /// second bucket for the same host).
    #[test]
    fn forwarded_for_entries_are_canonicalized() {
        let trusted: IpNet = "10.0.0.0/8".parse().unwrap();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let expected: IpAddr = "203.0.113.7".parse().unwrap();

        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert(
                "x-forwarded-for",
                "203.0.113.7, ::ffff:10.0.0.9".parse().unwrap(),
            );
            map
        };
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[trusted]), expected);

        let headers = {
            let mut map = http::HeaderMap::new();
            map.insert("x-forwarded-for", "::ffff:203.0.113.7".parse().unwrap());
            map
        };
        assert_eq!(resolve_rate_limit_ip(peer, &headers, &[trusted]), expected);
    }

    /// F1 regression: a client behind a trusted proxy cannot evade its bucket
    /// by rotating the value it prepends to `X-Forwarded-For` — only the
    /// rightmost, proxy-appended entry is trusted as the rate-limit key.
    #[tokio::test]
    async fn trusted_proxy_client_rotating_leftmost_value_still_limited() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            trusted_proxies: vec!["192.168.1.0/24".parse().unwrap()],
            ..Default::default()
        };
        let app = apply_ip_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("1.1.1.1, 203.0.113.9")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Same real client (rightmost entry unchanged), different spoofed
        // leftmost value: still hits the same bucket and is limited.
        assert_eq!(
            app.clone()
                .oneshot(request_with_forwarded_for(
                    addr("192.168.1.1"),
                    Some("9.9.9.9, 203.0.113.9")
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
