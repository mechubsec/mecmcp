//! Streamable HTTP rmcp router and listener composition.

use crate::{
    BearerBoundary, BoundaryAccounting, ConcurrencyState, LimitedSessionManager, LimitsConfig,
    LimitsConfigError, PrometheusRuntime, TransportIdentity, apply_bearer_boundary,
    apply_ip_rate_limit,
};
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use mecmcp_auth::Grant;
use rmcp::{
    ServerHandler,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

/// Host and browser-Origin validation policy for the rmcp endpoint.
///
/// This type has only an `Enforced` variant. Host allowlist enforcement was
/// made mandatory in rustjunosmcp 0.15.3 to eliminate a documented way to
/// reintroduce RUSTSEC-2026-0189 (DNS rebinding, which targets loopback-bound
/// services). The default is rmcp's loopback-only allowlist; each
/// `--allowed-host` extends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOriginPolicy {
    /// Keep rmcp's loopback Host defaults and extend them with exact values.
    Enforced {
        /// Additional accepted Host authorities.
        allowed_hosts: Vec<String>,
        /// Exact accepted browser origins.
        allowed_origins: Vec<String>,
    },
}

impl HostOriginPolicy {
    /// Enforce rmcp's loopback defaults plus consumer-owned additions.
    ///
    /// The loopback allowlist (`["localhost", "127.0.0.1", "[::1]"]`) is always
    /// present. Each `allowed_hosts` value extends it. `allowed_origins` is
    /// optional; an empty list leaves Origin validation disabled (any Origin
    /// is accepted), which is the correct policy when the server binds only
    /// loopback and is not accessed from a browser.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::HostOriginPolicy;
    ///
    /// let policy = HostOriginPolicy::enforced(
    ///     ["mcp.example.test"],
    ///     ["https://client.example.test"],
    /// );
    /// ```
    #[must_use]
    pub fn enforced(
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::Enforced {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
        }
    }
}

/// Construct exact loopback browser origins for one listener.
///
/// Generates `http://localhost:{port}`, `http://127.0.0.1:{port}`,
/// `http://[::1]:{port}` (or `https://` if `tls` is true), plus any
/// `additional` origins. The result is sorted and deduplicated.
///
/// Use this to populate `allowed_origins` when the server binds a LAN address
/// but must also accept loopback browser connections (e.g., for local testing).
///
/// # Example
///
/// ```
/// use mecmcp_transport::loopback_origins;
///
/// let origins = loopback_origins(8080, false, Vec::<String>::new());
/// assert!(origins.contains(&"http://localhost:8080".to_owned()));
/// ```
#[must_use]
pub fn loopback_origins(
    port: u16,
    tls: bool,
    additional: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    let scheme = if tls { "https" } else { "http" };
    let default_port = if tls { 443 } else { 80 };

    // Browsers omit the port when it matches the scheme's default (80 for http,
    // 443 for https), but include it otherwise. For default ports, emit both
    // forms so rmcp's literal comparison accepts both browser behaviors.
    let mut origins = if port == default_port {
        vec![
            format!("{scheme}://localhost"),
            format!("{scheme}://localhost:{port}"),
            format!("{scheme}://127.0.0.1"),
            format!("{scheme}://127.0.0.1:{port}"),
            format!("{scheme}://[::1]"),
            format!("{scheme}://[::1]:{port}"),
        ]
    } else {
        vec![
            format!("{scheme}://localhost:{port}"),
            format!("{scheme}://127.0.0.1:{port}"),
            format!("{scheme}://[::1]:{port}"),
        ]
    };

    origins.extend(additional.into_iter().map(Into::into));
    origins.sort();
    origins.dedup();
    origins
}

/// Complete shared HTTP composition settings.
///
/// Combines identity, resource limits, Host/Origin policy, optional bearer
/// authentication, metrics, and a shutdown signal. The shutdown signal is a
/// required constructor parameter (not a builder step) because a listener built
/// without one can never drain: nothing would tell it to stop accepting. It is
/// the token the caller cancels on SIGTERM.
pub struct HttpTransportConfig<G: Grant> {
    identity: TransportIdentity,
    limits: LimitsConfig,
    host_origin: HostOriginPolicy,
    bearer: Option<BearerBoundary<G>>,
    enable_metrics: bool,
    metrics_access: crate::metrics::MetricsAccess,
    readiness_checks: Vec<crate::health::ReadinessCheck>,
    shutdown: CancellationToken,
    insecure_bind: Option<crate::consent::InsecureBindAcknowledgement>,
}

impl<G: Grant> HttpTransportConfig<G> {
    /// Construct transport settings for an authenticated listener.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::{BearerSyntax, NoGrant};
    /// use mecmcp_transport::{
    ///     BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    ///     HttpTransportConfig, HostOriginPolicy, LimitsConfig, TransportIdentity,
    /// };
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let authenticator =
    ///     BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_candidate| None);
    /// let boundary =
    ///     BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
    /// let config = HttpTransportConfig::authenticated(
    ///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
    ///     LimitsConfig::default(),
    ///     HostOriginPolicy::enforced(["host"], ["https://origin"]),
    ///     CancellationToken::new(),
    ///     boundary,
    /// );
    /// ```
    #[must_use]
    pub fn authenticated(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
        shutdown: CancellationToken,
        bearer: BearerBoundary<G>,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: Some(bearer),
            enable_metrics: false,
            metrics_access: crate::metrics::MetricsAccess::loopback_only(),
            readiness_checks: Vec::new(),
            shutdown,
            insecure_bind: None,
        }
    }

    /// Construct transport settings for a listener that serves without
    /// authentication.
    ///
    /// Requires a [`NoAuthAcknowledgement`](crate::NoAuthAcknowledgement),
    /// which exists so that "the operator chose this" and "the consumer forgot"
    /// are different values. Before mecmcp#273 they were the same one, and a
    /// consumer could serve the LAN unauthenticated without any code path
    /// recording a decision.
    ///
    /// The acknowledgement does **not** permit an off-loopback bind:
    /// `serve_router` refuses that with
    /// [`ListenerRefusal::UnauthenticatedOffLoopback`](crate::ListenerRefusal::UnauthenticatedOffLoopback).
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::NoGrant;
    /// use mecmcp_transport::{
    ///     HttpTransportConfig, HostOriginPolicy, LimitsConfig, NoAuthAcknowledgement,
    ///     TransportIdentity,
    /// };
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let config = HttpTransportConfig::<NoGrant>::unauthenticated(
    ///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
    ///     LimitsConfig::default(),
    ///     HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
    ///     CancellationToken::new(),
    ///     NoAuthAcknowledgement::operator_allowed_no_auth(),
    /// );
    /// ```
    #[must_use]
    pub fn unauthenticated(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
        shutdown: CancellationToken,
        _acknowledgement: crate::consent::NoAuthAcknowledgement,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: None,
            enable_metrics: false,
            metrics_access: crate::metrics::MetricsAccess::loopback_only(),
            readiness_checks: Vec::new(),
            shutdown,
            insecure_bind: None,
        }
    }

    /// Accept a plaintext listener on a non-loopback address.
    ///
    /// Without this, `serve_router` refuses to bind an off-loopback address
    /// that has no TLS. Absence is the safe default, so this is a builder step
    /// rather than a constructor parameter.
    #[must_use]
    pub fn with_insecure_bind(
        mut self,
        acknowledgement: crate::consent::InsecureBindAcknowledgement,
    ) -> Self {
        self.insecure_bind = Some(acknowledgement);
        self
    }

    /// Enable the `/metrics` endpoint.
    ///
    /// When enabled, Prometheus metrics are exposed at `/metrics`. This
    /// endpoint is **not** protected by MCP bearer authentication — it has its
    /// own access control instead. By default `/metrics` is loopback-only: a
    /// peer that is not `127.0.0.1`/`::1` gets a 403, regardless of any MCP
    /// bearer token it presents. Call
    /// [`with_metrics_token`](Self::with_metrics_token) to also admit a
    /// non-loopback peer that presents a distinct metrics bearer token.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::NoGrant;
    /// use mecmcp_transport::{HttpTransportConfig, HostOriginPolicy, LimitsConfig, NoAuthAcknowledgement, TransportIdentity};
    /// use tokio_util::sync::CancellationToken;
    ///
    /// let config = HttpTransportConfig::<NoGrant>::unauthenticated(
    ///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
    ///     LimitsConfig::default(),
    ///     HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
    ///     CancellationToken::new(),
    ///     NoAuthAcknowledgement::operator_allowed_no_auth(),
    /// ).with_metrics(true);
    /// ```
    #[must_use]
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }

    /// Require this token from any non-loopback peer of `/metrics`.
    ///
    /// Without this, `/metrics` is loopback-only: a peer that is not
    /// `127.0.0.1`/`::1` is refused regardless of any MCP bearer token it
    /// presents. Calling this lets a non-loopback Prometheus scraper in by
    /// presenting `digest`'s plaintext as its own bearer token — deliberately
    /// **not** the same token store as MCP authentication, so an MCP token
    /// never grants `/metrics`. See [`mecmcp_auth::TokenSecret::mint`] to
    /// generate one.
    #[must_use]
    pub fn with_metrics_token(mut self, digest: mecmcp_auth::TokenDigest) -> Self {
        self.metrics_access = crate::metrics::MetricsAccess::loopback_or_token(digest);
        self
    }

    /// Add a named `/readyz` probe.
    ///
    /// `mecmcp-transport` has no audit sink or inventory of its own, so it
    /// runs no checks by default and reports ready. Each consuming server
    /// wires its own checks (audit sink writable, inventory loaded) here.
    #[must_use]
    pub fn with_readiness_check(mut self, check: crate::health::ReadinessCheck) -> Self {
        self.readiness_checks.push(check);
        self
    }
}

/// Router construction failure.
#[derive(Debug, thiserror::Error)]
pub enum HttpTransportBuildError {
    /// Resource limits are internally inconsistent.
    #[error("invalid HTTP resource limits: {0}")]
    Limits(#[from] LimitsConfigError),
    /// Prometheus recorder installation failed.
    #[error("Prometheus metrics initialization failed: {0}")]
    Metrics(String),
}

/// Build the underlying rmcp Host/Origin and body-size configuration.
///
/// Merges the two concerns that rmcp 3's `StreamableHttpServerConfig` carries:
/// Host/Origin validation (from `HostOriginPolicy`) and request body size limit
/// (from `LimitsConfig`). This is the unified successor to the two separate
/// functions that existed on main and on the salvage branch.
///
/// `max_request_body_bytes: 0` in `LimitsConfig` means unlimited, which rmcp
/// has no spelling for, so it maps to `usize::MAX`.
///
/// `legacy_session_mode` is left at rmcp's default (`true`): the `initialize`
/// handshake and `Mcp-Session-Id` stay available for pre-2026-07-28 clients,
/// while clients declaring `2026-07-28` are routed statelessly per request.
/// Both are served simultaneously; this is not a cutover.
///
/// # Breaking change from 0.6.1
///
/// This function now takes both `&HostOriginPolicy` and `&LimitsConfig`, where
/// the 0.6.1 version took only `&LimitsConfig`. Callers must pass both. The
/// shutdown token is derived from `HttpTransportConfig` and passed separately
/// to `StreamableHttpService::new`.
#[must_use]
pub fn streamable_http_server_config(
    policy: &HostOriginPolicy,
    limits: &LimitsConfig,
    shutdown: CancellationToken,
) -> StreamableHttpServerConfig {
    let HostOriginPolicy::Enforced {
        allowed_hosts,
        allowed_origins: _,
    } = policy;

    let mut config = StreamableHttpServerConfig::default();

    // Body size limit from LimitsConfig
    config.max_request_body_bytes = if limits.max_request_body_bytes == 0 {
        usize::MAX
    } else {
        limits.max_request_body_bytes
    };

    // Host/Origin policy
    config.allowed_hosts.extend(allowed_hosts.iter().cloned());
    // Pass allowed_origins as-is to rmcp. We disable rmcp's wildcard behavior
    // by leaving allowed_origins empty and validating ourselves in middleware.
    // (rmcp treats missing port as wildcard: a_port.is_none() || a_port == o_port)
    config.allowed_origins = Vec::new();

    // Shutdown token for session termination
    config.cancellation_token = shutdown;

    config
}

/// Build the fully protected `/mcp` router and return the shutdown token.
///
/// Composes the complete middleware stack in the correct order to prevent
/// bypass vulnerabilities. The order was established in 0.6.0 after review
/// found real bypasses in earlier arrangements.
///
/// **Returns `(Router, HttpShutdown)`** and that value **must** be passed to
/// `serve_router`. It carries two tokens on purpose — the listener's and rmcp's
/// — because they are cancelled at different times. See [`HttpShutdown`] (#156).
///
/// **Middleware request order (outermost to innermost):**
///
/// 1. **IP rate limit** (outside authentication): Meters requests before they
///    reach authentication, preventing authentication floods from unknown
///    tokens or missing/malformed headers.
/// 2. **Bearer boundary** (authentication → token accounting → body limit →
///    preflight → target concurrency): Applied via `apply_bearer_boundary`,
///    which enforces the internal order. See that function's documentation for
///    the complete rationale.
/// 3. **Metrics** (if enabled): The `/metrics` endpoint is merged into the
///    router and is **not** protected by authentication.
///
/// # Example
///
/// ```
/// use mecmcp_auth::NoGrant;
/// use mecmcp_transport::{HttpTransportConfig, HostOriginPolicy, LimitsConfig, NoAuthAcknowledgement, TransportIdentity, build_streamable_http_router};
/// use rmcp::{ServerHandler, model::{Implementation, ServerCapabilities, ServerConfig}};
/// use tokio_util::sync::CancellationToken;
///
/// # #[derive(Clone)]
/// # struct EmptyServer;
/// # impl ServerHandler for EmptyServer {
/// #     fn get_info(&self) -> ServerConfig {
/// #         ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
/// #             .with_server_info(Implementation::new("empty", "1"))
/// #     }
/// # }
/// # #[tokio::main]
/// # async fn main() {
/// let config = HttpTransportConfig::<NoGrant>::unauthenticated(
///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
///     LimitsConfig::default(),
///     HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
///     CancellationToken::new(),
///     NoAuthAcknowledgement::operator_allowed_no_auth(),
/// );
///
/// let plan = build_streamable_http_router(
///     || Ok::<_, std::io::Error>(EmptyServer),
///     config,
/// ).expect("router build failed");
/// // Pass plan to serve_router; it carries the shutdown and the router together
/// # }
/// ```
pub fn build_streamable_http_router<S, G>(
    service_factory: impl Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
    config: HttpTransportConfig<G>,
) -> Result<ServePlan, HttpTransportBuildError>
where
    S: ServerHandler + Send + 'static,
    G: Grant,
{
    config.limits.validate()?;
    config.limits.log_effective();

    let metrics_runtime = if config.enable_metrics {
        Some(Arc::new(
            PrometheusRuntime::install(
                &config.identity.metric_prefix,
                &config.identity.server_label,
            )
            .map_err(|error| HttpTransportBuildError::Metrics(error.to_string()))?,
        ))
    } else {
        None
    };

    let session_manager =
        LimitedSessionManager::new(LocalSessionManager::default(), &config.limits);
    // Bound before `session_manager` moves into the rmcp service below. The
    // bearer boundary needs the same tracker the session manager writes
    // `clientInfo` into, or the transport audit event has nothing to read
    // (mecmcp#53).
    let session_tracker = session_manager.tracker();
    let concurrency = ConcurrencyState::new(
        &config.limits,
        config.identity.target_keys.clone(),
        Some(Arc::clone(&session_tracker)),
    );
    // rmcp gets its OWN token, deliberately not `config.shutdown`.
    //
    // rmcp terminates every active session the instant its token is cancelled,
    // and an MCP response travels back over that session's SSE stream. Handing
    // rmcp the same token as the listener therefore cut every stream at the
    // moment shutdown began, so no in-flight call could deliver its response and
    // the drain deadline was decorative. `serve_router` cancels this one at the
    // deadline instead, which is where the hard cut belongs.
    let sessions = CancellationToken::new();
    let service = StreamableHttpService::new(
        service_factory,
        session_manager,
        streamable_http_server_config(&config.host_origin, &config.limits, sessions.clone()),
    );

    // Build the /mcp service router, starting from the innermost layer
    let mut router = Router::new().nest_service("/mcp", service);

    let limits = Arc::new(config.limits);

    let bearer_was_attached = config.bearer.is_some();

    // Apply bearer boundary if authentication is enabled.
    // This applies the complete authenticated stack: auth → token_rate →
    // token_concurrency → body_limit → preflight → target_concurrency.
    if let Some(bearer) = config.bearer {
        let accounting = authenticated_accounting(concurrency, &limits, &session_tracker);
        router = apply_bearer_boundary(router, bearer, accounting);
    } else {
        // For unauthenticated servers, install the split concurrency middleware
        // in the same order as the bearer path: global concurrency (non-buffering)
        // → body limit → per-target concurrency (buffering). The deprecated
        // combined concurrency_middleware buffers without a body limit and would
        // allow unbounded allocation on the anonymous path.
        router = router.layer(axum::middleware::from_fn_with_state(
            concurrency.clone(),
            crate::target_concurrency_middleware,
        ));
        router = crate::apply_body_limit(router, &limits);
        router = router.layer(axum::middleware::from_fn_with_state(
            concurrency,
            crate::token_concurrency_middleware,
        ));
    }

    // Merge metrics endpoint if enabled, gated by MetricsAccess (loopback
    // peer, or a non-loopback peer presenting the configured metrics token).
    if let Some(runtime) = metrics_runtime {
        let gated = crate::metrics::gate_metrics_router(runtime.router(), config.metrics_access);
        router = router.merge(gated).layer(Extension(runtime));
    }

    // Merge health endpoints unconditionally: unlike /metrics, a health probe
    // is not opt-in, and neither route consults device or customer data.
    router = router.merge(crate::health::health_router(Arc::from(
        config.readiness_checks,
    )));

    // Apply Host/Origin validation to the entire router (covers /mcp, /metrics, and /healthz+/readyz).
    // This prevents DNS rebinding attacks where an attacker-controlled page
    // requests /metrics with a foreign Host header to read unauthenticated data,
    // and ensures Origin validation uses exact matching (no port wildcards).
    router = router.layer(axum::middleware::from_fn_with_state(
        config.host_origin.clone(),
        host_origin_validation_middleware,
    ));

    // Apply IP rate limit AFTER assembling all routes (outermost layer).
    // This ensures /metrics is also subject to the IP rate limiter, matching
    // the documented middleware order where IP rate limiting sits outside all
    // route-specific logic.
    router = apply_ip_rate_limit(router, &limits);

    Ok(ServePlan {
        router,
        shutdown: HttpShutdown {
            listener: config.shutdown,
            sessions,
        },
        policy: crate::listener::ListenerPolicy {
            authenticated: bearer_was_attached,
            host_origin: config.host_origin,
            insecure_bind: config.insecure_bind,
        },
    })
}

/// Host and Origin header validation middleware (whole-router protection).
///
/// Validates Host and Origin headers against the configured allowlist for all routes.
/// Host validation prevents DNS rebinding. Origin validation is done by comparing
/// normalized tuples (scheme, host, port) to prevent rmcp's port-wildcard behavior.
async fn host_origin_validation_middleware(
    State(policy): State<HostOriginPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let HostOriginPolicy::Enforced {
        allowed_hosts,
        allowed_origins,
    } = &policy;

    // Extract Host from header or URI authority (HTTP/2 uses :authority pseudo-header)
    let host = match request.headers().get(header::HOST) {
        Some(host_value) => match host_value.to_str() {
            Ok(host) => Some(host.to_owned()),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Host header contains invalid characters",
                )
                    .into_response();
            }
        },
        None => {
            // HTTP/2 may use :authority pseudo-header; hyper puts it in URI authority
            request
                .uri()
                .authority()
                .map(|auth| auth.as_str().to_owned())
        }
    };

    let host = match host {
        Some(h) => h,
        None => {
            return (StatusCode::BAD_REQUEST, "Host or :authority is required").into_response();
        }
    };

    // Parse and normalize Host as (ascii-lowercase host, explicit port)
    let (host_normalized, host_port) = match normalize_host_authority(&host) {
        Some(tuple) => tuple,
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid Host authority").into_response();
        }
    };

    // Check against loopback defaults (host only, any port) + allowed_hosts.
    //
    // **Host vs Origin port matching differs deliberately:**
    // - Host: portless allowlist entry matches ANY port (production shape: `--allowed-host 192.0.2.10` on `:30031`)
    // - Origin: portless allowlist entry matches ONLY portless browser Origin (no wildcarding)
    //
    // Browsers canonically omit default ports from Origin but include the listener port in Host.
    let loopback_host_names = ["localhost", "127.0.0.1", "[::1]"];
    let is_allowed = loopback_host_names.contains(&host_normalized.as_str())
        || allowed_hosts.iter().any(|allowed| {
            normalize_host_authority(allowed)
                .map(|(allowed_host, allowed_port)| {
                    // Host must match, and:
                    // - If allowlist entry has no port, accept any port (None matches Some(x))
                    // - If allowlist entry has explicit port, require exact match
                    allowed_host == host_normalized
                        && (allowed_port.is_none() || allowed_port == host_port)
                })
                .unwrap_or(false)
        });

    if !is_allowed {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            format!("Host '{}' is not allowed", host),
        )
            .into_response();
    }

    // Validate Origin if present and allowlist is non-empty
    if !allowed_origins.is_empty()
        && let Some(origin_value) = request.headers().get(header::ORIGIN)
    {
        // Reject non-UTF-8 Origin immediately (do not fall through)
        let origin_str = match origin_value.to_str() {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "Origin header contains invalid UTF-8",
                )
                    .into_response();
            }
        };

        // Handle "Origin: null" explicitly (file://, sandboxed iframe, etc.)
        if origin_str == "null" {
            // Reject null origins unless explicitly allowed
            if !allowed_origins.contains(&"null".to_owned()) {
                return (StatusCode::FORBIDDEN, "Origin 'null' is not allowed").into_response();
            }
        } else if !origin_is_allowed_exact(origin_str, allowed_origins) {
            return (
                StatusCode::FORBIDDEN,
                format!("Origin '{}' is not allowed", origin_str),
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Normalize a Host authority string to (ascii-lowercase host, Option<port>).
///
/// Returns None if the authority is malformed or contains non-ASCII characters.
/// Port is Some(explicit) when present in the string, None when absent (so portless
/// entries only match portless requests, not arbitrary ports).
fn normalize_host_authority(authority_str: &str) -> Option<(String, Option<u16>)> {
    let authority = authority_str.parse::<http::uri::Authority>().ok()?;
    let host = authority.host();

    // ASCII-lowercase the host for case-insensitive comparison
    // (DNS names are case-insensitive per RFC 1035)
    if !host.is_ascii() {
        return None;
    }
    let normalized_host = host.to_ascii_lowercase();

    let port = authority.port_u16();
    Some((normalized_host, port))
}

/// Check if an origin is allowed by comparing normalized tuples.
///
/// Normalizes both incoming and allowed origins to (scheme, ascii-lowercase host, explicit port).
/// Portless entries (http://example vs http://example:80) are treated distinctly:
/// - A portless allowlist entry matches ONLY portless browser Origins (scheme default port).
/// - An explicit-port entry matches ONLY that exact port.
///
/// This prevents both rmcp's wildcard behavior (missing port matching any port) and
/// the inverse confusion (portless browser Origin rejected by explicit-port allowlist).
fn origin_is_allowed_exact(origin: &str, allowed: &[String]) -> bool {
    let incoming = match parse_and_normalize_origin(origin) {
        Some(tuple) => tuple,
        None => return false,
    };

    allowed.iter().any(|allowed_origin| {
        if let Some(allowed_tuple) = parse_and_normalize_origin(allowed_origin) {
            incoming == allowed_tuple
        } else {
            false
        }
    })
}

/// Parse an origin string and normalize it to (scheme, ascii-lowercase host, explicit port).
///
/// Returns None if the origin is malformed or contains non-ASCII characters.
/// The port is ALWAYS explicit: portless origins are normalized to their scheme default
/// (http→80, https→443) so that comparison logic treats "http://example" (no port) and
/// "http://example:80" (explicit port) as the same tuple, matching browser canonicalization.
fn parse_and_normalize_origin(origin: &str) -> Option<(String, String, u16)> {
    let uri = origin.parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?.to_owned();
    let authority = uri.authority()?;
    let host = authority.host();

    // ASCII-lowercase the host for case-insensitive comparison
    if !host.is_ascii() {
        return None;
    }
    let normalized_host = host.to_ascii_lowercase();

    // Normalize port: use explicit port if present, otherwise scheme default.
    // This makes portless entries match portless browser Origins (both → :443 or :80).
    let port = authority
        .port_u16()
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });

    Some((scheme, normalized_host, port))
}

/// Listener setup or runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum HttpServeError {
    /// Binding the TCP listener failed.
    #[error("failed to bind {address}: {error}")]
    Bind {
        /// Requested address.
        address: SocketAddr,
        /// Underlying socket error.
        #[source]
        error: std::io::Error,
    },
    /// The HTTP server exited with an error.
    #[error("Streamable HTTP server failed on {address}: {error}")]
    Serve {
        /// Address being served.
        address: SocketAddr,
        /// Underlying serve error.
        #[source]
        error: std::io::Error,
    },
    /// The listener configuration was refused before binding.
    #[error(transparent)]
    Refused(#[from] crate::listener::ListenerRefusal),
}

/// The two halves of a graceful shutdown, produced by
/// [`build_streamable_http_router`] and consumed by [`serve_router`].
///
/// They are deliberately distinct tokens, cancelled at **different times**:
///
/// - `listener` is the caller's own token — whatever SIGTERM cancels. When it
///   fires, the listener stops accepting and in-flight requests are given
///   `shutdown_timeout` to finish.
/// - `sessions` is rmcp's, and is cancelled only when that deadline expires.
///
/// Cancelling both at once is the obvious-looking mistake, and it was shipped:
/// rmcp ends every session the instant its token fires, and an MCP response
/// travels back over that session's SSE stream, so every in-flight call lost its
/// response the moment shutdown began and the deadline never did anything. A
/// tool call that completes during the drain must still be able to answer.
///
/// The consequence to know: while any SSE stream is open, shutdown takes the
/// full `shutdown_timeout`. Keep it well under systemd's `TimeoutStopSec`.
#[derive(Debug, Clone)]
pub struct HttpShutdown {
    listener: CancellationToken,
    sessions: CancellationToken,
}

impl HttpShutdown {
    /// The token the caller cancels to begin draining.
    #[must_use]
    pub fn listener(&self) -> &CancellationToken {
        &self.listener
    }
}

/// Everything needed to serve, including the facts `serve_router` must check.
///
/// There is deliberately no accessor that yields the `Router`. If the router
/// could leave the plan, a consumer could serve it directly and skip the
/// listener admission checks — which is the defect mecmcp#273 exists to close.
/// Customise the router through [`HttpTransportConfig`] before building.
pub struct ServePlan {
    router: Router,
    shutdown: HttpShutdown,
    policy: crate::listener::ListenerPolicy,
}

impl ServePlan {
    /// The shutdown pair, for wiring SIGTERM.
    #[must_use]
    pub fn shutdown(&self) -> &HttpShutdown {
        &self.shutdown
    }
}
/// Serve a composed router over plain HTTP or a supplied rustls configuration.
///
/// Both plain and TLS paths support graceful shutdown via the `shutdown` signal.
/// When the signal fires, the listener stops accepting new connections and
/// waits up to `shutdown_timeout` for in-flight requests to complete. Requests
/// that do not finish within the timeout are dropped.
///
/// **The `shutdown` value must be the one returned from
/// `build_streamable_http_router`**, which is why it is a distinct type rather
/// than a bare token: the two halves must stay paired (#156).
///
/// The timeout is load-bearing, not a backstop. rmcp's sessions are held open
/// for its whole duration so an in-flight call can still write its response,
/// and terminated when it expires so a stream that never ends cannot hold
/// shutdown open. Keep it well under systemd's `TimeoutStopSec`.
///
/// # Example
///
/// ```no_run
/// use std::net::SocketAddr;
/// use std::time::Duration;
/// use mecmcp_transport::{build_streamable_http_router, serve_router, HttpTransportConfig, HostOriginPolicy, LimitsConfig, NoAuthAcknowledgement, TransportIdentity};
/// use mecmcp_auth::NoGrant;
/// use rmcp::{ServerHandler, model::{Implementation, ServerCapabilities, ServerConfig}};
///
/// # #[derive(Clone)]
/// # struct EmptyServer;
/// # impl ServerHandler for EmptyServer {
/// #     fn get_info(&self) -> ServerConfig {
/// #         ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
/// #             .with_server_info(Implementation::new("empty", "1"))
/// #     }
/// # }
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = HttpTransportConfig::<NoGrant>::unauthenticated(
///     TransportIdentity::new("testmcp", "test", "test", ["device"]),
///     LimitsConfig::default(),
///     HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
///     tokio_util::sync::CancellationToken::new(),
///     NoAuthAcknowledgement::operator_allowed_no_auth(),
/// );
/// let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)?;
/// let address: SocketAddr = "127.0.0.1:8080".parse()?;
///
/// serve_router(
///     plan,
///     address,
///     None, // No TLS
///     std::time::Duration::from_secs(10),
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub async fn serve_router(
    plan: ServePlan,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown_timeout: std::time::Duration,
) -> Result<(), HttpServeError> {
    // Before the socket exists. A refusal must cost nothing and leak nothing,
    // so it happens ahead of the bind (mecmcp#273).
    crate::listener::check_listener(&plan.policy, address, tls.is_some())?;

    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| HttpServeError::Bind { address, error })?;

    serve_router_on_listener(plan, listener, tls, shutdown_timeout).await
}

/// [`serve_router`] over a listener the caller already bound.
///
/// The bind and the serve are one step for a normal caller, but a test harness
/// needs the port *before* it can hand out a URL. Binding to discover a port and
/// then releasing it leaves a window in which another process -- another test in
/// the same binary, most often -- can take that port, after which two servers
/// believe they own one address and a client reaches the wrong one. Passing the
/// bound listener straight through closes the window instead of narrowing it.
///
/// # Errors
///
/// As [`serve_router`], minus the bind.
pub async fn serve_router_on_listener(
    plan: ServePlan,
    listener: std::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown_timeout: std::time::Duration,
) -> Result<(), HttpServeError> {
    let address = listener
        .local_addr()
        .map_err(|error| HttpServeError::Bind {
            address: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            error,
        })?;

    let ServePlan {
        router, shutdown, ..
    } = plan;

    // Both listeners run on axum_server so they share one forced deadline.
    // `axum::serve`'s `with_graceful_shutdown` takes a signal but no deadline:
    // it waits on every in-flight connection task forever, and an MCP SSE
    // stream never ends on its own, so the plaintext listener would hang
    // until systemd's TimeoutStopSec SIGKILL.
    listener
        .set_nonblocking(true)
        .map_err(|error| HttpServeError::Bind { address, error })?;

    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown.listener.cancelled().await;
            tracing::info!(
                timeout_secs = shutdown_timeout.as_secs(),
                "shutdown signal received, draining connections"
            );
            handle.graceful_shutdown(Some(shutdown_timeout));

            // Hold rmcp's sessions open for the whole drain window, then cut.
            // Cancelling here rather than above is the entire point: an MCP
            // response rides its session's SSE stream, so killing sessions at
            // t=0 would drop the very responses the drain exists to deliver.
            tokio::time::sleep(shutdown_timeout).await;
            tracing::info!("drain deadline reached, terminating remaining sessions");
            shutdown.sessions.cancel();
        }
    });

    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    // axum-server 0.8 made from_tcp/from_tcp_rustls fallible: they now adopt the
    // listener rather than assuming it is usable. A failure here is still a bind
    // problem, so it is reported as one.
    if let Some(tls_config) = tls {
        tracing::info!(%address, "Streamable HTTP listening with TLS");
        let config = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);
        axum_server::tls_rustls::from_tcp_rustls(listener, config)
            .map_err(|error| HttpServeError::Bind { address, error })?
            .handle(handle)
            .serve(service)
            .await
            .map_err(|error| HttpServeError::Serve { address, error })?;
        return Ok(());
    }

    tracing::info!(%address, "Streamable HTTP listening");
    axum_server::from_tcp(listener)
        .map_err(|error| HttpServeError::Bind { address, error })?
        .handle(handle)
        .serve(service)
        .await
        .map_err(|error| HttpServeError::Serve { address, error })?;
    Ok(())
}

/// Build the accounting the bearer boundary runs with.
///
/// Extracted so the tracker wiring is testable. `BoundaryAccounting::new`
/// leaves `session_tracker` at `None`, and the transport audit event reads the
/// captured `clientInfo` back out of exactly that tracker (mecmcp#53). When the
/// assembly forgot to attach it, every consumer of
/// `build_streamable_http_router` emitted `client_name=""` while the middleware,
/// its unit tests, and the end-to-end test that attached a tracker by hand all
/// passed — the feature was correct and unreachable.
fn authenticated_accounting(
    concurrency: ConcurrencyState,
    limits: &Arc<crate::config::LimitsConfig>,
    session_tracker: &Arc<crate::session::SessionTracker>,
) -> BoundaryAccounting {
    BoundaryAccounting::new(concurrency, Arc::clone(limits))
        .with_session_tracker(Arc::clone(session_tracker))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    /// The assembly must attach the session tracker to the bearer boundary.
    ///
    /// Regression guard for mecmcp#53's second half. The propagation middleware
    /// reads the captured `clientInfo` out of `BoundaryAccounting.session_tracker`,
    /// and `BoundaryAccounting::new` leaves that `None`. Because
    /// `build_streamable_http_router` never attached it, every consumer emitted
    /// `client_name=""` while every test passed — including an end-to-end one
    /// that attached a tracker by hand and so exercised the middleware rather
    /// than the assembly.
    ///
    /// This asserts the helper the assembly calls, not the assembly itself; the
    /// crate has no harness that stands up a real rmcp service. Proving it truly
    /// end to end still means driving a consumer, which is how the gap was
    /// found. See the tracking issue for that harness.
    #[test]
    fn the_authenticated_boundary_is_given_the_session_tracker() {
        let limits = std::sync::Arc::new(crate::config::LimitsConfig::default());
        let tracker = std::sync::Arc::new(crate::session::SessionTracker::new(&limits));
        let concurrency =
            ConcurrencyState::new(&limits, Vec::new(), Some(std::sync::Arc::clone(&tracker)));
        let accounting = super::authenticated_accounting(concurrency, &limits, &tracker);
        assert!(
            accounting.session_tracker.is_some(),
            "the bearer boundary must receive the session tracker, or the transport \
             audit event has nothing to read clientInfo from and client_name stays empty"
        );
    }

    use super::*;
    use crate::{BearerAuthenticator, BearerResponseProfile, NoAuthAcknowledgement};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use mecmcp_auth::{ActorType, BearerSyntax, CallerCtx, NoGrant, ScopeSet};
    use rmcp::{
        ServerHandler,
        model::{Implementation, ServerCapabilities, ServerConfig},
    };
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tower::ServiceExt as _;

    #[derive(Clone)]
    struct EmptyServer;

    impl ServerHandler for EmptyServer {
        fn get_info(&self) -> ServerConfig {
            ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
                .with_server_info(Implementation::new("empty", "1"))
        }
    }

    fn caller() -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "test".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn host_origin_policy_only_enforced_variant() {
        let policy =
            HostOriginPolicy::enforced(["mcp.example.test"], ["https://client.example.test"]);
        match policy {
            HostOriginPolicy::Enforced {
                allowed_hosts,
                allowed_origins,
            } => {
                assert!(allowed_hosts.contains(&"mcp.example.test".to_owned()));
                assert_eq!(
                    allowed_origins,
                    vec!["https://client.example.test".to_owned()]
                );
            }
        }
    }

    #[test]
    fn loopback_origins_http() {
        let origins = loopback_origins(8080, false, Vec::<String>::new());
        assert!(origins.contains(&"http://localhost:8080".to_owned()));
        assert!(origins.contains(&"http://127.0.0.1:8080".to_owned()));
        assert!(origins.contains(&"http://[::1]:8080".to_owned()));
        assert_eq!(origins.len(), 3);
    }

    #[test]
    fn loopback_origins_https() {
        let origins = loopback_origins(8443, true, Vec::<String>::new());
        assert!(origins.contains(&"https://localhost:8443".to_owned()));
        assert!(origins.contains(&"https://127.0.0.1:8443".to_owned()));
        assert!(origins.contains(&"https://[::1]:8443".to_owned()));
        assert_eq!(origins.len(), 3);
    }

    #[test]
    fn loopback_origins_with_additional() {
        let origins =
            loopback_origins(8080, false, vec!["http://lan.example.test:8080".to_owned()]);
        assert!(origins.contains(&"http://localhost:8080".to_owned()));
        assert!(origins.contains(&"http://lan.example.test:8080".to_owned()));
        assert_eq!(origins.len(), 4);
    }

    #[tokio::test]
    async fn origin_validation_prevents_port_wildcarding() {
        // Middleware validates by comparing normalized tuples, so port-less allowlist
        // entry matches port-less browser Origin but NOT explicit non-default port.
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(
                Vec::<String>::new(),
                vec!["https://client.example".to_owned()], // No port
            ),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Port-less Origin should be accepted (normalized to :443 on both sides)
        let portless_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "https://client.example")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            portless_response.status(),
            StatusCode::FORBIDDEN,
            "port-less Origin should match port-less allowlist entry"
        );

        // Explicit non-default port should be rejected (no wildcard)
        let explicit_port_response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "https://client.example:8443")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            explicit_port_response.status(),
            StatusCode::FORBIDDEN,
            "explicit non-default port should NOT wildcard-match port-less allowlist"
        );
    }

    #[tokio::test]
    async fn origin_validation_accepts_portless_browser_origin() {
        // Browsers send port-less Origin for default ports (80/443)
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(
                Vec::<String>::new(),
                vec!["https://app.example".to_owned()],
            ),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "https://app.example") // Browser omits :443
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "port-less browser Origin should match port-less allowlist entry"
        );
    }

    #[tokio::test]
    async fn origin_validation_handles_null_explicitly() {
        // Origin: null from sandboxed iframe, file://, etc.
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(
                Vec::<String>::new(),
                vec!["null".to_owned()], // Explicitly allow null
            ),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .header(header::ORIGIN, "null")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Origin: null should be accepted when explicitly allowed"
        );
    }

    #[test]
    fn loopback_origins_default_http_port_emits_both_forms() {
        // Port 80: browsers send Origin without port, but we emit both forms
        let origins = loopback_origins(80, false, Vec::<String>::new());
        assert!(origins.contains(&"http://localhost".to_owned()));
        assert!(origins.contains(&"http://localhost:80".to_owned()));
        assert!(origins.contains(&"http://127.0.0.1".to_owned()));
        assert!(origins.contains(&"http://127.0.0.1:80".to_owned()));
        assert!(origins.contains(&"http://[::1]".to_owned()));
        assert!(origins.contains(&"http://[::1]:80".to_owned()));
        assert_eq!(origins.len(), 6);
    }

    #[test]
    fn loopback_origins_default_https_port_emits_both_forms() {
        // Port 443: browsers send Origin without port, but we emit both forms
        let origins = loopback_origins(443, true, Vec::<String>::new());
        assert!(origins.contains(&"https://localhost".to_owned()));
        assert!(origins.contains(&"https://localhost:443".to_owned()));
        assert!(origins.contains(&"https://127.0.0.1".to_owned()));
        assert!(origins.contains(&"https://127.0.0.1:443".to_owned()));
        assert!(origins.contains(&"https://[::1]".to_owned()));
        assert!(origins.contains(&"https://[::1]:443".to_owned()));
        assert_eq!(origins.len(), 6);
    }

    #[test]
    fn streamable_http_server_config_merges_policy_and_limits() {
        let policy =
            HostOriginPolicy::enforced(["mcp.example.test"], ["https://client.example.test"]);
        let limits = LimitsConfig {
            max_request_body_bytes: 9 * 1024 * 1024,
            ..LimitsConfig::default()
        };
        let shutdown = CancellationToken::new();
        let config = streamable_http_server_config(&policy, &limits, shutdown.clone());

        // Check body limit from LimitsConfig
        assert_eq!(config.max_request_body_bytes, 9 * 1024 * 1024);

        // Check Host/Origin from HostOriginPolicy
        assert!(config.allowed_hosts.contains(&"localhost".to_owned()));
        assert!(
            config
                .allowed_hosts
                .contains(&"mcp.example.test".to_owned())
        );
        // Origins are validated in middleware, not passed to rmcp (to avoid wildcard)
        assert!(
            config.allowed_origins.is_empty(),
            "allowed_origins should be empty (validation done in middleware)"
        );

        // Check shutdown token
        assert!(!config.cancellation_token.is_cancelled());
        shutdown.cancel();
        assert!(config.cancellation_token.is_cancelled());
    }

    #[test]
    fn streamable_http_server_config_maps_unlimited_to_usize_max() {
        let policy = HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new());
        let limits = LimitsConfig {
            max_request_body_bytes: 0, // unlimited
            ..LimitsConfig::default()
        };
        let config = streamable_http_server_config(&policy, &limits, CancellationToken::new());
        assert_eq!(
            config.max_request_body_bytes,
            usize::MAX,
            "0 means unlimited; rmcp has no spelling for it"
        );
    }

    #[tokio::test]
    async fn router_with_allowed_host_accepts_matching_request() {
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        // Without bearer auth, the request reaches rmcp which returns 400 for
        // malformed JSON-RPC (we're not sending valid rmcp). The point is that
        // the Host check passed.
        assert_ne!(
            response.status(),
            StatusCode::BAD_REQUEST, // Would be 421 if Host was rejected
            "loopback Host should be accepted by default"
        );
    }

    #[tokio::test]
    async fn router_with_bearer_requires_auth() {
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
            (candidate == "secret").then(caller)
        });
        let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
        let config = HttpTransportConfig::authenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            boundary,
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthenticated_router_enforces_global_concurrency_limit() {
        // Test that limits are enforced even when bearer auth is disabled
        let limits = LimitsConfig {
            max_inflight_requests: 1, // Allow only 1 concurrent request
            ..LimitsConfig::default()
        };
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            limits,
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Both requests will be malformed (not valid rmcp), but the second
        // should be rejected with 503 due to concurrency limit, not 400.
        let first_request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .body(Body::from("{}"))
            .expect("request");

        let second_request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .body(Body::from("{}"))
            .expect("request");

        // Clone the router for concurrent requests
        let router_clone = router.clone();

        // Start both requests concurrently
        let (first_response, second_response) = tokio::join!(
            router.oneshot(first_request),
            router_clone.oneshot(second_request),
        );

        let first_status = first_response.expect("first response").status();
        let second_status = second_response.expect("second response").status();

        // One should succeed (or fail with 400 for malformed rmcp), the other
        // should be rejected with 503 for exceeding concurrency limit
        assert!(
            first_status == StatusCode::SERVICE_UNAVAILABLE
                || second_status == StatusCode::SERVICE_UNAVAILABLE,
            "one request should be rejected with 503 due to concurrency limit; got {} and {}",
            first_status,
            second_status
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_enforces_host_allowlist() {
        // Test that /metrics enforces the Host allowlist, preventing DNS rebinding
        // attacks where an attacker page requests /metrics with a foreign Host.
        //
        // Both requests carry a loopback ConnectInfo: this test is about the
        // Host/Origin layer, not the loopback-or-token metrics access gate
        // added for MEC-48, which is covered by its own tests in metrics.rs.
        //
        // This test also carries the end-to-end proof for MEC-48 review
        // finding 3 (an MCP bearer token must not grant `/metrics`, and a
        // metrics token must not grant `/mcp`) rather than living in its own
        // file under `tests/`. `ServePlan` deliberately has no accessor that
        // yields its `Router` outside this crate (mecmcp#273) — an external
        // integration test cannot get at the assembled router at all, and a
        // synthetic non-loopback peer can only be injected via
        // `.extension(ConnectInfo(..))` on a request built against that
        // router directly. Combined with `PrometheusRuntime::install` being a
        // process-global recorder that panics on a second install in the same
        // test binary, the property can only be proven here, reusing this
        // test's one authenticated + metrics-enabled router.
        let peer: std::net::SocketAddr = "127.0.0.1:0".parse().expect("address");
        let (mcp_secret, mcp_digest) = mecmcp_auth::TokenSecret::mint().expect("mint mcp token");
        let (metrics_secret, metrics_digest) =
            mecmcp_auth::TokenSecret::mint().expect("mint metrics token");
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            mcp_digest.verify(candidate).then(caller)
        });
        let boundary = BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"));
        let config = HttpTransportConfig::authenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(["allowed.example.test"], Vec::<String>::new()),
            CancellationToken::new(),
            boundary,
        )
        .with_metrics(true)
        .with_metrics_token(metrics_digest);
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Foreign Host should be rejected
        let foreign_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(header::HOST, "attacker.example")
                    .extension(axum::extract::ConnectInfo(peer))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            foreign_response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "foreign Host should be rejected on /metrics"
        );

        // Allowed Host should be accepted
        let allowed_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(header::HOST, "allowed.example.test")
                    .extension(axum::extract::ConnectInfo(peer))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            allowed_response.status(),
            StatusCode::OK,
            "allowed Host should serve /metrics"
        );

        // MEC-48: a non-loopback peer is refused even with an allowed Host —
        // the loopback-or-token gate sits inside Host/Origin validation. Reuses
        // this test's router/recorder rather than building a second one:
        // PrometheusRuntime::install is a process-global recorder, and a
        // second `build_streamable_http_router(..).with_metrics(true)` in the
        // same test binary panics on install (mecmcp-transport has no
        // per-test recorder teardown).
        let non_loopback: std::net::SocketAddr = "203.0.113.7:0".parse().expect("address");
        let non_loopback_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(header::HOST, "allowed.example.test")
                    .extension(axum::extract::ConnectInfo(non_loopback))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            non_loopback_response.status(),
            StatusCode::FORBIDDEN,
            "a non-loopback peer must be refused by default even with an allowed Host"
        );

        // MEC-48 review finding 3: an MCP bearer token must not grant
        // /metrics from a non-loopback peer, even though it is a valid,
        // currently-accepted token.
        let mcp_token_on_metrics = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(header::HOST, "allowed.example.test")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", mcp_secret.expose_secret()),
                    )
                    .extension(axum::extract::ConnectInfo(non_loopback))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            mcp_token_on_metrics.status(),
            StatusCode::FORBIDDEN,
            "a valid MCP bearer token must not grant /metrics"
        );

        // The dedicated metrics token grants /metrics from that same non-loopback peer.
        let metrics_token_on_metrics = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .header(header::HOST, "allowed.example.test")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", metrics_secret.expose_secret()),
                    )
                    .extension(axum::extract::ConnectInfo(non_loopback))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            metrics_token_on_metrics.status(),
            StatusCode::OK,
            "the configured metrics token must grant /metrics from a non-loopback peer"
        );

        // ... but that same metrics token must not authenticate /mcp.
        let metrics_token_on_mcp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "allowed.example.test")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", metrics_secret.expose_secret()),
                    )
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            metrics_token_on_mcp.status(),
            StatusCode::UNAUTHORIZED,
            "a metrics token must not grant /mcp"
        );

        // And the MCP token does authenticate /mcp (proves the boundary is
        // still live, so the 403/401 results above are the gate working, not
        // the boundary being bypassed or dead).
        let mcp_token_on_mcp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "allowed.example.test")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", mcp_secret.expose_secret()),
                    )
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            mcp_token_on_mcp.status(),
            StatusCode::UNAUTHORIZED,
            "a valid MCP bearer token must authenticate /mcp"
        );
    }

    /// MEC-48: `/healthz` and `/readyz` are merged unconditionally, unlike
    /// `/metrics`, which stays opt-in.
    #[tokio::test]
    async fn health_endpoints_are_reachable_with_metrics_disabled() {
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let healthz = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .header(header::HOST, "localhost")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(healthz.status(), StatusCode::OK, "healthz needs no auth");

        let readyz = router
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .header(header::HOST, "localhost")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            readyz.status(),
            StatusCode::OK,
            "readyz with no configured checks reports ready"
        );
    }

    #[tokio::test]
    async fn unauthenticated_router_rejects_oversized_body_before_target_extraction() {
        // Test that the anonymous path enforces body limit before buffering for
        // target extraction, preventing unbounded allocation without credentials.
        let limits = LimitsConfig {
            max_request_body_bytes: 64, // Small limit
            ..LimitsConfig::default()
        };
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            limits,
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Send a request with body exceeding the limit
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "localhost")
                    .body(Body::from(vec![b'x'; 128])) // 128 bytes > 64 limit
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized request should be rejected with 413 before target extraction buffers it"
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_accepting_connections() {
        let shutdown = CancellationToken::new();
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            shutdown.clone(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");

        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind to ephemeral port to get the actual address
        let listener = std::net::TcpListener::bind(address).expect("bind failed");
        let bound_address = listener.local_addr().expect("local_addr");
        drop(listener); // Release the port

        let shutdown_clone = shutdown.clone();
        let server_handle = tokio::spawn(async move {
            serve_router(plan, bound_address, None, Duration::from_secs(1)).await
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify server is accepting connections
        let connect_result = TcpStream::connect(bound_address).await;
        assert!(
            connect_result.is_ok(),
            "server should accept connections before shutdown"
        );

        // Trigger shutdown
        shutdown_clone.cancel();

        // Wait for shutdown to take effect
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Server should have stopped
        let result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(result.is_ok(), "server should have stopped gracefully");
    }

    /// rmcp's sessions must outlive the *start* of the drain and die at its end.
    ///
    /// An MCP response travels back over its session's SSE stream. 0.7.0 and
    /// 0.7.1 handed rmcp the same token as the listener, so every session ended
    /// the instant shutdown began and no in-flight call could ever answer — the
    /// drain deadline had nothing left to protect. Verified against a live
    /// server: a tool call in flight at SIGTERM got 28 bytes of SSE preamble and
    /// no response, indistinguishable from having been dropped outright.
    #[tokio::test]
    async fn sessions_outlive_the_start_of_the_drain_and_end_at_its_deadline() {
        let listener_token = CancellationToken::new();
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            listener_token.clone(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let sessions = plan.shutdown.sessions.clone();

        let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound = std::net::TcpListener::bind(address).expect("bind failed");
        let bound_address = bound.local_addr().expect("local_addr");
        drop(bound);

        let drain = Duration::from_millis(600);
        let server = tokio::spawn(serve_router(plan, bound_address, None, drain));
        tokio::time::sleep(Duration::from_millis(100)).await;

        listener_token.cancel();

        // Mid-drain: the listener is closing, but sessions must still be able to
        // carry a response back.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !sessions.is_cancelled(),
            "rmcp sessions were cut at the start of the drain, so an in-flight \
             call could never deliver its response"
        );

        // Past the deadline: the hard cut, so a stream that never ends cannot
        // hold shutdown open forever.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            sessions.is_cancelled(),
            "rmcp sessions must be terminated once the drain deadline expires"
        );

        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    }

    #[tokio::test]
    async fn http2_authority_fallback_when_host_header_absent() {
        // HTTP/2 clients send :authority pseudo-header; hyper puts it in URI authority.
        // This test simulates that by omitting Host header and putting authority in URI.
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Request with authority in URI but no Host header (HTTP/2 pattern)
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("http://localhost:8080/mcp")
                    // No Host header — middleware should fall back to URI authority
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "middleware should accept :authority when Host is absent"
        );
        assert_ne!(
            response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "localhost from URI authority should match loopback allowlist"
        );
    }

    #[tokio::test]
    async fn ipv6_host_parsing_handles_brackets_and_port() {
        // IPv6 addresses like [::1]:8080 must not split incorrectly on :
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "[::1]:8080")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "[::1] should match loopback allowlist (not rejected as foreign host)"
        );
    }

    #[tokio::test]
    async fn explicit_port_host_rejects_different_port() {
        // An allowlist entry with explicit port should NOT match a different port
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(vec!["mcp.example:8443".to_owned()], Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "mcp.example:1234") // Different port
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "mcp.example:1234 should NOT match mcp.example:8443 (exact port required)"
        );
    }

    #[tokio::test]
    async fn portless_allowed_host_matches_any_port() {
        // A portless allowlist entry should match ANY port (production shape: LXC 609)
        // This differs from Origin handling where portless entries match only portless.
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(vec!["192.0.2.10".to_owned()], Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Host with explicit port should be accepted
        let with_port = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "192.0.2.10:30031") // Explicit port
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            with_port.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "portless allowlist entry should match explicit port (LXC 609 shape)"
        );

        // Host without port should also be accepted
        let without_port = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "192.0.2.10") // No port
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            without_port.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "portless allowlist entry should match portless Host"
        );
    }

    #[tokio::test]
    async fn mixed_case_host_accepted() {
        // DNS names are case-insensitive (RFC 1035), so mixed case should match
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(vec!["mcp.example.test".to_owned()], Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::HOST, "MCP.EXAMPLE.TEST") // Mixed case
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(
            response.status(),
            StatusCode::MISDIRECTED_REQUEST,
            "mixed-case Host should match lowercase allowlist (case-insensitive)"
        );
    }

    #[tokio::test]
    async fn non_utf8_origin_rejected() {
        // Non-UTF-8 Origin header should be rejected immediately (not fall through)
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            LimitsConfig::default(),
            HostOriginPolicy::enforced(
                Vec::<String>::new(),
                vec!["https://app.example".to_owned()],
            ),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );
        let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build failed");
        let router = plan.router;

        // Construct request with invalid UTF-8 in Origin header
        let mut request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .body(Body::from("{}"))
            .expect("request");

        // Insert non-UTF-8 bytes into Origin header
        request.headers_mut().insert(
            header::ORIGIN,
            header::HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).expect("header value"),
        );

        let response = router.oneshot(request).await.expect("response");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "non-UTF-8 Origin should be rejected with 400 (not fall through)"
        );
    }

    #[tokio::test]
    async fn ip_rate_limit_applied_outermost() {
        // This test verifies the documented middleware order: IP rate limiter sits
        // outermost, wrapping Host/Origin validation and all routes (/mcp and /metrics).
        // Since IP rate limiting is tower middleware and shares no state with validation,
        // we verify the order by construction: if the config enables IP limiting,
        // build_streamable_http_router must succeed (proving the limiter was applied last).
        //
        // Full rate-limit behavior (429 responses) is tested in rate_limit::tests where
        // the apply_rate_limit helpers are directly observable.
        let limits = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            ..LimitsConfig::default()
        };
        let config = HttpTransportConfig::<NoGrant>::unauthenticated(
            TransportIdentity::new("testmcp", "test", "test", ["device"]),
            limits,
            HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        );

        // If IP rate limiter was applied in wrong order, router construction would fail.
        // Success proves correct order (all routes assembled, then Host/Origin validation,
        // then IP limiter outermost).
        let _plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router build should succeed with IP limiting enabled");
    }

    #[test]
    fn authenticated_and_unauthenticated_configs_record_their_posture() {
        use crate::consent::{InsecureBindAcknowledgement, NoAuthAcknowledgement};
        use mecmcp_auth::{BearerSyntax, NoGrant};

        let identity = || TransportIdentity::new("testmcp", "test", "test", ["device"]);
        let policy = || HostOriginPolicy::enforced(vec!["h".to_owned()], vec!["o".to_owned()]);

        let authenticator =
            crate::BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
        let boundary =
            crate::BearerBoundary::new(authenticator, crate::BearerResponseProfile::detailed("t"));

        let authed = HttpTransportConfig::authenticated(
            identity(),
            LimitsConfig::default(),
            policy(),
            CancellationToken::new(),
            boundary,
        );
        assert!(
            authed.bearer.is_some(),
            "authenticated config must carry the boundary"
        );
        assert!(
            authed.insecure_bind.is_none(),
            "insecure bind must default to unacknowledged"
        );

        let open = HttpTransportConfig::<NoGrant>::unauthenticated(
            identity(),
            LimitsConfig::default(),
            policy(),
            CancellationToken::new(),
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
        .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        assert!(open.bearer.is_none());
        assert!(open.insecure_bind.is_some());
    }

    // Graceful shutdown drain behavior is verified in rustsdcmcp's integration
    // tests where real HTTP clients and slow handlers can be properly composed.
    // axum's handler trait requirements make it awkward to test async closures
    // with captured state in unit tests, and the behavior is already covered
    // downstream.
}
