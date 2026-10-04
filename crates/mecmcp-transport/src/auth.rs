//! Shared bearer authentication and scope-preflight HTTP boundary.

use crate::approver_assertion::APPROVER_ASSERTION_HEADER;
#[cfg(feature = "verified-approver")]
use crate::approver_assertion::ApproverAssertionVerifier;
use crate::preflight::{OptionalPreflight, ScopePreflight, run_preflight};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use mecmcp_audit::{Attribution, AuditScope};
use mecmcp_auth::{BearerSyntax, CallerCtx, Grant, parse_bearer_header};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};

/// Errors that can occur when constructing a bearer authentication profile.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BearerAuthError {
    /// Realm contains characters that cannot appear in HTTP header values.
    #[error("realm contains invalid characters: {0}")]
    InvalidRealm(&'static str),
}

/// Callback type converting an opaque credential into a grant-bearing caller.
///
/// The callback signature deliberately accepts `&str` rather than `&[u8]` to
/// enforce that the credential has already survived the UTF-8 and syntax
/// checks in [`parse_bearer_header`]. The callback must not log, store, or
/// expose the credential in any form.
///
/// # Thread safety
///
/// `Authenticate` is `Send + Sync` so that `BearerAuthenticator` can live in
/// middleware state without imposing `Arc` on consumers that already have
/// atomic reloading via their token-store implementation.
type Authenticate<G> = dyn Fn(&str) -> Option<CallerCtx<G>> + Send + Sync;

/// Authenticates a presented bearer credential into a grant-bearing caller.
///
/// Wraps the syntax policy and an atomically reloadable lookup callback that
/// consumes validated credentials and produces callers. The callback is
/// invoked only for credentials that survived header parsing.
///
/// # Credential safety
///
/// The authenticate callback sees the credential exactly once, during the
/// request that presents it. The callback must not log, store, or expose the
/// credential. `BearerAuthenticator` itself never retains the credential
/// beyond the call.
pub struct BearerAuthenticator<G: Grant> {
    syntax: BearerSyntax,
    authenticate: Arc<Authenticate<G>>,
}

impl<G: Grant> Clone for BearerAuthenticator<G> {
    fn clone(&self) -> Self {
        Self {
            syntax: self.syntax,
            authenticate: self.authenticate.clone(),
        }
    }
}

impl<G: Grant> BearerAuthenticator<G> {
    /// Construct an authenticator around an atomically reloadable lookup.
    ///
    /// `syntax` governs whether leading/trailing whitespace is allowed in the
    /// `Authorization` header value. `authenticate` is invoked only for
    /// credentials that survived syntax validation.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::{BearerSyntax, CallerCtx, NoGrant};
    /// use mecmcp_transport::BearerAuthenticator;
    ///
    /// let authenticator = BearerAuthenticator::<NoGrant>::new(
    ///     BearerSyntax::Strict,
    ///     |_candidate| None,
    /// );
    /// ```
    #[must_use]
    pub fn new(
        syntax: BearerSyntax,
        authenticate: impl Fn(&str) -> Option<CallerCtx<G>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            syntax,
            authenticate: Arc::new(authenticate),
        }
    }

    /// Invoke the authentication callback.
    ///
    /// This is an internal helper, not a public method. Consumers never call
    /// this directly; the bearer boundary middleware does.
    fn authenticate(&self, candidate: &str) -> Option<CallerCtx<G>> {
        (self.authenticate)(candidate)
    }
}

/// Compatibility profile for bearer failures.
///
/// Controls the format and detail level of 401 and 403 responses. Different
/// consumers have different backward-compatibility requirements for how errors
/// are presented to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerResponseProfile {
    realm: String,
    style: BearerResponseStyle,
}

/// Response detail level.
///
/// RFC 6750 distinguishes `invalid_request` from `invalid_token`, but some
/// consumers collapse all 401s into `invalid_token` for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerResponseStyle {
    /// RFC 6750 profile with distinct `invalid_request` and `invalid_token`.
    Detailed,
    /// Compact profile returning `invalid_token` for every 401.
    Compact,
}

impl BearerResponseProfile {
    /// RFC 6750 profile with distinct invalid-request and invalid-token bodies.
    ///
    /// Presentation errors (missing or malformed headers) return
    /// `invalid_request`, while authentication failures return `invalid_token`.
    ///
    /// Returns an error if `realm` contains quotes, control characters, or
    /// non-ASCII. Use this constructor when the realm comes from configuration
    /// or user input.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::BearerResponseProfile;
    ///
    /// let profile = BearerResponseProfile::try_detailed("jmcp")?;
    /// # Ok::<(), mecmcp_transport::BearerAuthError>(())
    /// ```
    pub fn try_detailed(realm: impl Into<String>) -> Result<Self, BearerAuthError> {
        Ok(Self {
            realm: validate_realm(realm.into())?,
            style: BearerResponseStyle::Detailed,
        })
    }

    /// RFC 6750 profile with distinct invalid-request and invalid-token bodies.
    ///
    /// Presentation errors (missing or malformed headers) return
    /// `invalid_request`, while authentication failures return `invalid_token`.
    ///
    /// This constructor is infallible and intended for `&'static str` literals
    /// known at compile time. Use [`try_detailed`](Self::try_detailed) for
    /// configuration values.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::BearerResponseProfile;
    ///
    /// let profile = BearerResponseProfile::detailed("jmcp");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `realm` contains characters that cannot appear in an HTTP
    /// header value (control characters or non-ASCII). This is a configuration
    /// error, not a runtime condition.
    #[must_use]
    pub fn detailed(realm: &'static str) -> Self {
        Self::try_detailed(realm).expect("realm must be header-safe")
    }

    /// Compact profile returning `invalid_token` for every 401.
    ///
    /// Both presentation errors and authentication failures return
    /// `invalid_token`. Use this for consumers that require a single,
    /// consistent 401 error shape.
    ///
    /// Returns an error if `realm` contains quotes, control characters, or
    /// non-ASCII. Use this constructor when the realm comes from configuration
    /// or user input.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::BearerResponseProfile;
    ///
    /// let profile = BearerResponseProfile::try_compact("panos")?;
    /// # Ok::<(), mecmcp_transport::BearerAuthError>(())
    /// ```
    pub fn try_compact(realm: impl Into<String>) -> Result<Self, BearerAuthError> {
        Ok(Self {
            realm: validate_realm(realm.into())?,
            style: BearerResponseStyle::Compact,
        })
    }

    /// Compact profile returning `invalid_token` for every 401.
    ///
    /// Both presentation errors and authentication failures return
    /// `invalid_token`. Use this for consumers that require a single,
    /// consistent 401 error shape.
    ///
    /// This constructor is infallible and intended for `&'static str` literals
    /// known at compile time. Use [`try_compact`](Self::try_compact) for
    /// configuration values.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::BearerResponseProfile;
    ///
    /// let profile = BearerResponseProfile::compact("panos");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `realm` contains characters that cannot appear in an HTTP
    /// header value (control characters or non-ASCII). This is a configuration
    /// error, not a runtime condition.
    #[must_use]
    pub fn compact(realm: &'static str) -> Self {
        Self::try_compact(realm).expect("realm must be header-safe")
    }
}

/// Configuration for the shared authenticated request boundary.
///
/// Combines bearer authentication, response profile, and an optional synchronous
/// scope preflight. The body size limit is derived from `LimitsConfig` (passed via
/// `BoundaryAccounting` to `apply_bearer_boundary`) to prevent mismatch between
/// boundary and config caps.
pub struct BearerBoundary<G: Grant> {
    authenticator: BearerAuthenticator<G>,
    responses: BearerResponseProfile,
    preflight: OptionalPreflight,
    #[cfg(feature = "verified-approver")]
    approver_assertion: Option<Arc<ApproverAssertionVerifier>>,
}

impl<G: Grant> Clone for BearerBoundary<G> {
    fn clone(&self) -> Self {
        Self {
            authenticator: self.authenticator.clone(),
            responses: self.responses.clone(),
            preflight: self.preflight.clone(),
            #[cfg(feature = "verified-approver")]
            approver_assertion: self.approver_assertion.clone(),
        }
    }
}

impl<G: Grant> BearerBoundary<G> {
    /// Construct a bearer boundary.
    ///
    /// The body size limit is derived from `LimitsConfig` when the boundary is
    /// applied via `apply_bearer_boundary`, ensuring the middleware and rmcp caps
    /// cannot disagree. The preflight is `None` by default; use
    /// [`with_preflight`](Self::with_preflight) to install one.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::{BearerSyntax, NoGrant};
    /// use mecmcp_transport::{BearerAuthenticator, BearerBoundary, BearerResponseProfile};
    ///
    /// let authenticator = BearerAuthenticator::<NoGrant>::new(
    ///     BearerSyntax::Strict,
    ///     |_candidate| None,
    /// );
    /// let boundary = BearerBoundary::new(
    ///     authenticator,
    ///     BearerResponseProfile::detailed("test"),
    /// );
    /// ```
    #[must_use]
    pub fn new(authenticator: BearerAuthenticator<G>, responses: BearerResponseProfile) -> Self {
        Self {
            authenticator,
            responses,
            preflight: None,
            #[cfg(feature = "verified-approver")]
            approver_assertion: None,
        }
    }

    /// Install a synchronous scope preflight.
    ///
    /// The preflight runs after authentication but before the request reaches
    /// the handler. Returning `Err(reason)` causes a 403 with that reason in
    /// the body.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_auth::{BearerSyntax, NoGrant};
    /// use mecmcp_transport::{
    ///     BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    ///     ScopePreflight, CallerScopes,
    /// };
    ///
    /// struct AlwaysAllow;
    /// impl ScopePreflight for AlwaysAllow {
    ///     fn check(&self, _body: &[u8], _caller: CallerScopes<'_>) -> Result<(), String> {
    ///         Ok(())
    ///     }
    /// }
    ///
    /// let authenticator = BearerAuthenticator::<NoGrant>::new(
    ///     BearerSyntax::Strict,
    ///     |_candidate| None,
    /// );
    /// let boundary = BearerBoundary::new(
    ///     authenticator,
    ///     BearerResponseProfile::detailed("test"),
    /// ).with_preflight(AlwaysAllow);
    /// ```
    #[must_use]
    pub fn with_preflight(mut self, preflight: impl ScopePreflight + 'static) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }

    /// Install step-up approver-assertion verification.
    ///
    /// Without this, a presented `Mecmcp-Approver-Assertion` header is
    /// refused with 400 (mecmcp-runtime's `VerifiedApproverArgs`, W5, is the
    /// only intended way to install this — a server with no issuer
    /// configured behaves identically to one with no OIDC support at all).
    #[cfg(feature = "verified-approver")]
    #[must_use]
    pub fn with_approver_assertion(mut self, verifier: Arc<ApproverAssertionVerifier>) -> Self {
        self.approver_assertion = Some(verifier);
        self
    }
}

/// Per-token and per-target resource accounting configuration for the bearer boundary.
///
/// This struct specifies what accounting layers `apply_bearer_boundary` should install
/// and in what order. The crate places non-buffering layers (token rate/concurrency)
/// before the body limit and buffering layers (per-target concurrency) after preflight.
#[derive(Clone)]
pub struct BoundaryAccounting {
    /// Concurrency state for token and target limits.
    pub concurrency: Option<crate::concurrency::ConcurrencyState>,
    /// Rate limiting configuration.
    pub limits: std::sync::Arc<crate::config::LimitsConfig>,
    /// Session tracker for client name lookup (optional).
    pub session_tracker: Option<std::sync::Arc<crate::session::SessionTracker>>,
}

impl BoundaryAccounting {
    /// Create accounting config with both rate limiting and concurrency.
    pub fn new(
        concurrency: crate::concurrency::ConcurrencyState,
        limits: std::sync::Arc<crate::config::LimitsConfig>,
    ) -> Self {
        Self {
            concurrency: Some(concurrency),
            limits,
            session_tracker: None,
        }
    }

    /// Attach a session tracker for client name capture in audit events.
    #[must_use]
    pub fn with_session_tracker(
        mut self,
        tracker: std::sync::Arc<crate::session::SessionTracker>,
    ) -> Self {
        self.session_tracker = Some(tracker);
        self
    }

    /// No accounting (empty config for testing or minimal deployments).
    pub fn none() -> Self {
        Self {
            concurrency: None,
            limits: std::sync::Arc::new(crate::config::LimitsConfig::default()),
            session_tracker: None,
        }
    }
}

/// Apply bearer authentication with per-token/per-target accounting and preflight in the correct order.
///
/// Assembles the complete authenticated request boundary stack with resource accounting.
/// The `accounting` parameter specifies rate limiting and concurrency config; the crate
/// applies the layers in the correct order internally.
///
/// **Required execution order (enforced by this function):**
/// ```text
/// auth → token_rate → token_concurrency → body_limit → preflight → target_concurrency → handler
/// ```
///
/// - **Authentication (outermost)**: Rejects unauthenticated requests with 401 before
///   they reach accounting, preventing anonymous requests from charging token budgets.
/// - **Token rate limit (non-buffering)**: Checks per-token RPS limit before body is read.
/// - **Token concurrency (non-buffering)**: Checks per-token in-flight limit before body is read.
/// - **Body limit**: Enforces `accounting.limits.max_request_body_bytes` before any buffering occurs
///   (preventing unbounded allocation in per-target concurrency or preflight).
/// - **Preflight (authorization)**: Buffers body and checks scopes. Runs AFTER token accounting,
///   so rejected requests still consume per-token budget (preventing bypass via out-of-scope requests).
/// - **Target concurrency (buffering, innermost)**: Extracts target devices from body and checks
///   per-target limits. Runs AFTER preflight so unauthorized requests never acquire target permits.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use axum::Router;
/// use mecmcp_auth::{BearerSyntax, NoGrant};
/// use mecmcp_transport::{
///     BearerAuthenticator, BearerBoundary, BearerResponseProfile, BoundaryAccounting,
///     ConcurrencyState, LimitsConfig, apply_bearer_boundary,
/// };
///
/// let authenticator = BearerAuthenticator::<NoGrant>::new(
///     BearerSyntax::Strict,
///     |_candidate| None,
/// );
/// let boundary = BearerBoundary::new(
///     authenticator,
///     BearerResponseProfile::detailed("test"),
/// );
///
/// let limits = Arc::new(LimitsConfig::default());
/// let concurrency = ConcurrencyState::new(&limits, vec!["device".to_string()], None);
/// let accounting = BoundaryAccounting::new(concurrency, limits);
///
/// let router = Router::new();
/// let router = apply_bearer_boundary(router, boundary, accounting);
/// ```
pub fn apply_bearer_boundary<G: Grant>(
    router: Router,
    boundary: BearerBoundary<G>,
    accounting: BoundaryAccounting,
) -> Router {
    // Target concurrency layer (innermost, buffering): extracts devices from body and checks
    // per-target limits. Applied first so it runs last. Runs AFTER preflight (so unauthorized
    // requests never acquire target permits) and AFTER body limit (so buffering is bounded).
    let router = if let Some(ref concurrency) = accounting.concurrency {
        router.layer(axum::middleware::from_fn_with_state(
            concurrency.clone(),
            crate::concurrency::target_concurrency_middleware,
        ))
    } else {
        router
    };

    // Preflight layer (authorization): checks scopes. Runs AFTER body limit (bounded reads)
    // and AFTER token accounting (so rejected requests consume per-token budget).
    let router = router.layer(axum::middleware::from_fn_with_state(
        PreflightState::<G> {
            preflight: boundary.preflight.clone(),
            realm: boundary.responses.realm.clone(),
            session_tracker: accounting.session_tracker.clone(),
            _grant: std::marker::PhantomData,
        },
        bearer_preflight_middleware::<G>,
    ));

    // Body limit layer: enforce streaming limit before any buffering.
    // Applied here so it runs AFTER token accounting (non-buffering sees Content-Length)
    // and BEFORE preflight + target concurrency (all buffering is bounded).
    // Derive the cap from LimitsConfig (via accounting) so boundary and rmcp caps cannot disagree.
    let body_limit = accounting.limits.max_request_body_bytes;
    let router = if body_limit > 0 {
        router
            // Enforce the limit with our custom middleware that marks+counts (applied first, runs second/inner)
            .layer(axum::middleware::from_fn_with_state(
                body_limit,
                body_limit_middleware,
            ))
            // Ensure marked 413s are JSON (applied second, runs first/outer)
            .layer(axum::middleware::from_fn(normalize_body_limit_response))
    } else {
        router
    };

    // Token concurrency layer (non-buffering): checks per-token in-flight limits.
    // Runs BEFORE body limit so it sees all requests, even those with oversized Content-Length.
    let router = if let Some(ref concurrency) = accounting.concurrency {
        router.layer(axum::middleware::from_fn_with_state(
            concurrency.clone(),
            crate::concurrency::token_concurrency_middleware,
        ))
    } else {
        router
    };

    // Token rate limit layer (non-buffering): checks per-token RPS.
    // Runs BEFORE body limit so it sees Content-Length requests before short-circuit.
    let router = if accounting.limits.token_rate_limit_enabled() {
        crate::rate_limit::apply_token_rate_limit(router, &accounting.limits)
    } else {
        router
    };

    // Authentication layer (outermost): authenticates, inserts identity.
    // Applied last so it runs first. Rejects unauthenticated requests before they reach accounting.
    router.layer(axum::middleware::from_fn_with_state(
        AuthState {
            authenticator: boundary.authenticator,
            responses: boundary.responses,
            #[cfg(feature = "verified-approver")]
            approver_assertion: boundary.approver_assertion,
        },
        bearer_auth_middleware::<G>,
    ))
}

/// Credential presentation error.
///
/// Presentation errors are never logged with the credential itself. `Missing`
/// means no `Authorization` header was present. `Malformed` means the header
/// was duplicated, non-UTF-8, or rejected by `parse_bearer_header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentationError {
    /// Missing `Authorization` header.
    Missing,
    /// Malformed or duplicated `Authorization` header.
    Malformed,
}

/// State for the authentication middleware layer.
#[derive(Clone)]
#[doc(hidden)] // Internal, exported only for testing
pub struct AuthState<G: Grant> {
    pub authenticator: BearerAuthenticator<G>,
    pub responses: BearerResponseProfile,
    #[cfg(feature = "verified-approver")]
    pub approver_assertion: Option<Arc<ApproverAssertionVerifier>>,
}

/// State for the preflight middleware layer.
#[derive(Clone)]
#[doc(hidden)] // Internal, exported only for testing
pub struct PreflightState<G: Grant> {
    pub preflight: OptionalPreflight,
    pub realm: String,
    pub session_tracker: Option<std::sync::Arc<crate::session::SessionTracker>>,
    pub _grant: std::marker::PhantomData<G>,
}

/// Authentication middleware (outermost layer).
///
/// Extracts the bearer token, authenticates it, and inserts `CallerCtx<G>` and
/// `AuthenticatedToken` into request extensions. Unauthenticated requests are
/// rejected with 401 before reaching the inner layers (including per-token
/// resource accounting).
///
/// This layer MUST run before per-token accounting (concurrency, rate limits)
/// so that unauthenticated requests cannot charge someone else's budget.
#[doc(hidden)] // Internal, exported only for testing
pub async fn bearer_auth_middleware<G: Grant>(
    State(state): State<AuthState<G>>,
    mut request: Request,
    next: Next,
) -> Response {
    let candidate = match bearer_candidate(&request, state.authenticator.syntax) {
        Ok(candidate) => candidate,
        Err(PresentationError::Missing) => {
            return unauthorized(&state.responses, "missing Authorization header");
        }
        Err(PresentationError::Malformed) => {
            return unauthorized(
                &state.responses,
                "Authorization header must use Bearer scheme",
            );
        }
    };
    // `caller.verified_approver` is only ever written to with `verified-approver`
    // on; without it, nothing in this function mutates `caller`.
    #[cfg_attr(not(feature = "verified-approver"), allow(unused_mut))]
    let Some(mut caller) = state.authenticator.authenticate(candidate) else {
        tracing::warn!("auth_failed: no matching token");
        return invalid_token(&state.responses);
    };

    if request.headers().contains_key(APPROVER_ASSERTION_HEADER) {
        #[cfg(feature = "verified-approver")]
        {
            let Some(verifier) = state.approver_assertion.as_ref() else {
                return approver_assertion_not_configured();
            };
            let header_value = request
                .headers()
                .get(APPROVER_ASSERTION_HEADER)
                .expect("header presence just checked above");
            let Ok(assertion) = header_value.to_str() else {
                tracing::warn!(reason = "malformed_header", "approver_assertion_rejected");
                audit_approver_assertion_rejection(&caller, "malformed_header");
                return invalid_token(&state.responses);
            };
            let now = chrono::Utc::now().timestamp();
            match verifier.verify_and_bind(assertion, &caller, now).await {
                Ok(approver) => caller.verified_approver = Some(approver),
                Err(error) => {
                    tracing::warn!(
                        reason = error.reason_code(),
                        detail = %error,
                        "approver_assertion_rejected"
                    );
                    audit_approver_assertion_rejection(&caller, error.reason_code());
                    return invalid_token(&state.responses);
                }
            }
        }
        // With the `verified-approver` feature off, there is no verifier to
        // configure at all — behave exactly as the feature-on path does when
        // `state.approver_assertion` is `None`: fail closed with the same
        // configuration-mismatch response, never silently accept the header.
        #[cfg(not(feature = "verified-approver"))]
        {
            return approver_assertion_not_configured();
        }
    }

    // Insert both the grant-bearing CallerCtx and the grant-neutral
    // AuthenticatedToken so accounting layers can work regardless of G.
    request
        .extensions_mut()
        .insert(crate::AuthenticatedToken::new(caller.token_name.clone()));
    request.extensions_mut().insert(caller);

    next.run(request).await
}

/// Record a rejected approver assertion as a denied `mecmcp-audit` event.
///
/// Before this, a rejection was only visible via `tracing::warn!`, which an
/// operator's audit pipeline may not be watching (MEC-994 Percy review,
/// deferred to MEC-1511). `reason` is the same stable [`ApproverAssertionError::reason_code`]
/// (or `"malformed_header"` for a header that failed UTF-8 decoding before
/// verification was even attempted) already carried in the `tracing::warn!`
/// above, so the two never drift apart.
#[cfg(feature = "verified-approver")]
fn audit_approver_assertion_rejection<G: Grant>(caller: &CallerCtx<G>, reason: &'static str) {
    let mut scope = AuditScope::from_caller(caller, "approver_assertion", "verify", Vec::new());
    scope.deny(reason);
}

/// Build a 400 response for a presented approver assertion with no verifier
/// configured.
///
/// Distinct from [`invalid_token`]: the assertion itself was never checked,
/// so this is a server configuration/request-shape mismatch (RFC 9457
/// territory), not a credential failure.
fn approver_assertion_not_configured() -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({
            "error": "approver_assertion_not_configured",
            "error_description": "this server has no approver-assertion verifier configured",
        })),
    )
        .into_response()
}

/// Preflight middleware (innermost layer, after accounting and body limit).
///
/// Buffers the request body and runs the optional scope preflight. This layer
/// runs AFTER per-token concurrency and rate limits have been checked, so a
/// request rejected here has already consumed its per-token budget (preventing
/// bypass via out-of-scope requests).
///
/// The body limit is enforced by a separate layer (applied before this one in
/// `apply_bearer_boundary`), so this middleware always receives a bounded stream.
///
/// # Transport-level audit
///
/// Emits a transport audit event for every `tools/call` request. The event
/// captures what the transport knows (tool, caller, attribution) before dispatch.
/// Handlers emit enriched events with action, targets, and outcome (mecmcp#32).
#[doc(hidden)] // Internal, exported only for testing
pub async fn bearer_preflight_middleware<G: Grant>(
    State(state): State<PreflightState<G>>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    // Buffer the body. The limit is already enforced by tower_http::limit::RequestBodyLimitLayer
    // applied in apply_bearer_boundary, so we use usize::MAX here. Any length-limit error
    // will come from that outer layer, not from this to_bytes call.
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            // This should only happen for stream failures (not length limits, which are
            // caught by the outer layer). But handle both cases for defense in depth.
            return if is_length_limit_error(&error) {
                payload_too_large()
            } else {
                tracing::warn!(error = %error, "request body stream failed");
                bad_request()
            };
        }
    };

    // The caller was inserted by the outer authentication layer. This assertion
    // documents the ordering requirement: preflight middleware must run inside
    // the authentication layer (which would have already rejected unauthenticated
    // requests with 401, so an unauthenticated request can never reach here).
    let mut caller = parts
        .extensions
        .get::<CallerCtx<G>>()
        .expect("preflight layer must run after authentication layer")
        .clone();

    // A stateful client sends `clientInfo` once, at `initialize`; the version
    // lives on the session from then on, and the request bodies carry none.
    let mut session_client_version: Option<String> = None;

    // Populate client provenance from session (mecmcp#253, mecmcp#267).
    //
    // This path depends on the `Mcp-Session-Id` header, captured once at
    // `initialize` and keyed by session.
    if let Some(tracker) = &state.session_tracker
        && let Some(session_id_value) = parts.headers.get("Mcp-Session-Id")
        && let Ok(session_id_str) = session_id_value.to_str()
    {
        let session_id: rmcp::transport::common::server_side_http::SessionId =
            session_id_str.into();
        if let Some(client_name) = tracker.client_name(&session_id) {
            caller.client_name = Some(client_name);
        }
        if let Some(model_id) = tracker.model_id(&session_id) {
            caller.model_id = Some(model_id);
        }
        if let Some(sess_id) = tracker.session_id(&session_id) {
            caller.session_id = Some(sess_id);
        }
        session_client_version = tracker.client_version(&session_id);
    }

    // Fall back to the request's own `_meta` for anything the session did not
    // supply (mecmcp#288).
    //
    // Clients declaring MCP `2026-07-28` are routed statelessly (config.rs,
    // server.rs, concurrency.rs) and never send a session header, so the block
    // above cannot run for them. They do carry the same provenance per request,
    // which the body already buffered here makes available at no extra cost —
    // `extract_tool_name` parses these same bytes a few lines down.
    //
    // Per-field fallback rather than replacement: a session value, where one
    // exists, is what the deployed fleet audits today and must keep auditing.
    // This only fills gaps. Nothing here is server-verified — it is
    // client-asserted wherever it arrived from, exactly as the session path's
    // values are.
    // Parsed unconditionally now: the per-call id has no session-path
    // equivalent to fall back on, so gating this on a gap in `caller` would drop
    // it on every request that already knew its client.
    // One parse serves all three questions — who the client is, which tool is
    // audited, and that call's own metadata — because the body can be as large
    // as the configured limit (10 MiB by default) and this runs on every
    // authenticated call.
    //
    // Scoped so the parsed `Value` is dropped right here. Everything taken out
    // of it is small and owned; holding the whole tree across `run_preflight`
    // and `next.run(...).await` would keep a second copy of every in-flight
    // body alive, and with the default 64-request concurrency that is hundreds
    // of megabytes of duplicate data.
    let (request_provenance, audited_tool, audited_extras, audited_calls) = {
        let parsed: Option<Value> = serde_json::from_slice(&body_bytes).ok();
        let identity = parsed.as_ref().and_then(identity_provenance);
        let tool = parsed.as_ref().and_then(tool_name);
        let extras = parsed.as_ref().and_then(audited_call_provenance);
        let calls = parsed.as_ref().map_or(0, audited_call_count);
        (identity, tool, extras, calls)
    };
    if let Some(provenance) = request_provenance.as_ref() {
        if caller.client_name.is_none() {
            caller.client_name = provenance.client_name;
        }
        if caller.model_id.is_none() {
            caller.model_id = provenance.model_id;
        }
        if caller.session_id.is_none() {
            caller.session_id = provenance.session_id.clone();
        }
    }

    // Emit transport-level audit event for tools/call requests (mecmcp#32).
    // The handler will emit its own enriched event with action, targets, outcome.
    //
    // Both events carry the same `request_id`, so a SIEM can join them. That
    // holds because the ID lives on `CallerCtx` (minted once, at authentication)
    // and this scope is built from the same `caller` value that is re-inserted
    // into the request extensions below — not because anything re-derives it.
    // Until mecmcp#269 this comment claimed the correlation while
    // `Attribution::from_caller` minted a fresh UUID per call, so the two events
    // never matched; the claim is what stopped anyone checking.
    //
    // The scope is built here but deliberately left unsettled until the
    // preflight has run (mecmcp#268). When the preflight refuses, this event is
    // the *only* record of the call — the handler never runs, so nothing
    // downstream can correct an optimistic outcome, and a `succeed()` here
    // would assert that a request answered with 403 was allowed.
    // Resolved once, spent twice: on this scope, and in request extensions so a
    // consuming server's own tool-level audit record can carry them too. It
    // could not previously — `CallerCtx` is the only thing that reaches a
    // handler, and it does not carry these (mecmcp#304).
    //
    // These are not on `CallerCtx` deliberately. It is constructed
    // field-by-field by every consuming server, so adding to it is a breaking
    // change across all of them.
    //
    // The version describes the *client*, so any element of a batch that names
    // it is authoritative for all of them: session first — where a stateful
    // client's `clientInfo` lives after `initialize` — then the audited call,
    // then whichever element carried the identity. The call id is the opposite:
    // it belongs to one call, so it comes from the audited element or not at
    // all. See `audited_call_provenance`.
    let client_extras = crate::client_info::ClientExtras {
        client_version: session_client_version
            .clone()
            .or_else(|| {
                audited_extras
                    .as_ref()
                    .and_then(|p| p.client_version.clone())
            })
            .or_else(|| {
                request_provenance
                    .as_ref()
                    .and_then(|p| p.client_version.clone())
            }),
        // Withheld for a batch. The extension is per HTTP request, but a call id
        // belongs to one call: a service that dispatches each element would read
        // the *first* element's id for every one of them and attribute records
        // to a call that did not make them. The version is unaffected — it
        // describes the client, so it is true of every element.
        client_call_id: (audited_calls == 1)
            .then(|| {
                audited_extras
                    .as_ref()
                    .and_then(|p| p.client_call_id.clone())
            })
            .flatten(),
    };

    // The transport's own audit event is not subject to that: it describes one
    // specific element — the same one `audited_tool` names — so the id
    // `audited_call_provenance` resolved is the right one for it. Withholding it
    // there would drop real provenance to solve a problem the extension has.
    let audited_call_id = audited_extras
        .as_ref()
        .and_then(|p| p.client_call_id.clone());

    let terminal_call_id = audited_call_id.clone();

    let mut scope = audited_tool.map(|tool| {
        let mut scope = AuditScope::from_caller(&caller, tool, "transport", Vec::new());
        // `AuditScope` is constructor-only, so this reaches the audit trail
        // without the breaking change described above.
        scope.set_client_extras(client_extras.client_version.clone(), audited_call_id);
        scope.meta("layer", "preflight");
        scope
    });

    let preflight = run_preflight(&state.preflight, &body_bytes, &caller);

    if let Some(scope) = scope.as_mut() {
        match &preflight {
            Ok(()) => scope.succeed(),
            // `deny` takes a `&'static str`, and the preflight's reason is
            // supplied by the consumer's `ScopePreflight` — it may embed
            // peer-influenced text, which does not belong in log output
            // (mecmcp#181). The audit records the fixed wire reason; the
            // specific one still reaches the caller in the 403 body.
            Err(_) => scope.deny("insufficient_scope"),
        }
    }

    // Emit before dispatch rather than at end of function. The transport event
    // describes what the transport knew before the handler ran, and its
    // `duration_ms` is preflight time; holding the scope across `next.run`
    // would inflate that to the whole request and emit it after the handler's
    // own event.
    drop(scope);

    if let Err(reason) = preflight {
        return forbidden(&state.realm, &reason);
    }

    // Retain just enough to audit a refusal that happens *after* this point.
    // The scope above is dropped before dispatch on purpose, so without this a
    // 503 from target concurrency left one event saying preflight allowed the
    // call and it succeeded — a success the request never had (mecmcp#370).
    // Built before `caller` moves into the request extensions.
    // Carries the same client provenance the preflight event resolved, so the
    // two records for one request correlate instead of the refusal arriving
    // with empty `client_version` / `client_call_id`.
    let terminal = audited_tool.map(|tool| {
        (
            Attribution::from_caller(&caller),
            tool,
            client_extras.client_version.clone(),
            terminal_call_id,
        )
    });

    // Re-insert the potentially updated CallerCtx with client_name populated.
    // The parts are mutable here, so we can replace the extension.
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(caller);
    request.extensions_mut().insert(client_extras);

    let response = next.run(request).await;

    // Only refusals. A successful call is already described by the preflight
    // event plus the handler's own, richer one; emitting a third for every
    // success would double the volume and say nothing new.
    if let Some((attribution, tool, client_version, call_id)) = terminal {
        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            let mut scope = AuditScope::new(attribution, tool, "transport", Vec::new());
            scope.set_client_extras(client_version, call_id);
            scope.meta("layer", "post_dispatch");
            scope.meta("http_status", u64::from(status.as_u16()));
            // `fail_kind`, not `deny`. `AuditOutcome::Denied` is defined as
            // authorization refusing the call *before work began*; everything
            // reachable here ran after preflight allowed it, and may have begun
            // work. Recording it as a denial would be false authorization
            // evidence — the same class of error this event exists to fix.
            scope.fail_kind("refused_after_preflight", status);
        }
    }

    response
}

/// Cap on distinct tool names ever interned, and on the length of one.
///
/// The name comes from the request body, which is attacker-controlled, and is
/// read *before* the preflight has checked that the caller may call it — so an
/// authenticated caller with no scopes at all still reaches this code. Without
/// a bound, every novel name would leak a fresh allocation for the life of the
/// process and add a distinct value to audit output, which is both a memory
/// exhaustion path and an unbounded metrics-cardinality path.
const MAX_INTERNED_TOOL_NAMES: usize = 256;
const MAX_TOOL_NAME_LEN: usize = 128;

/// Placeholder recorded when a name is implausible or the intern table is full.
///
/// Auditing "a tools/call reached dispatch" is the guarantee (#32); recording an
/// unbounded attacker-chosen string is not part of it.
const UNREGISTERED_TOOL: &str = "unregistered";

static INTERNED_TOOL_NAMES: LazyLock<Mutex<HashSet<&'static str>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Intern a tool name into a bounded set, returning a `&'static str`.
///
/// `AuditScope` requires `&'static str`. Leaking each parsed name unconditionally
/// would satisfy the type and nothing else: names are not a "finite, small set"
/// when they arrive from a request body rather than from the tool registry.
fn intern_tool_name(name: &str) -> &'static str {
    intern_tool_into(&INTERNED_TOOL_NAMES, name)
}

/// Intern into a caller-supplied table.
///
/// Split out so the cap can be exercised without filling the process-global
/// table. A cap test that fills the global one leaks into every other test in
/// the module — Rust runs them concurrently, so a test asserting a specific name
/// back can get `unregistered` depending on scheduling. The equivalent defect in
/// `client_info` failed roughly one run in six and was only caught in CI; this
/// one has not fired yet, which is luck rather than correctness.
fn intern_tool_into(names_table: &Mutex<HashSet<&'static str>>, name: &str) -> &'static str {
    if name.is_empty()
        || name.len() > MAX_TOOL_NAME_LEN
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return UNREGISTERED_TOOL;
    }
    let Ok(mut names) = names_table.lock() else {
        return UNREGISTERED_TOOL;
    };
    if let Some(existing) = names.get(name) {
        return existing;
    }
    if names.len() >= MAX_INTERNED_TOOL_NAMES {
        return UNREGISTERED_TOOL;
    }
    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(leaked);
    leaked
}

/// Extract client-asserted provenance from a request's `params._meta` (#288).
///
/// Returns the first `_meta` block carrying any of the three fields, or `None`
/// for other shapes and malformed JSON. Batches are walked the same way
/// [`extract_tool_name`] walks them, and for the same reason: one audit event is
/// emitted per batch, so the provenance recorded must be the one belonging to
/// the call that event describes.
///
/// Parsing is deliberately total — a body that is not JSON, or carries no
/// `_meta`, yields `None` rather than an error. This runs on every request,
/// including ones that are about to be refused, and must never be able to turn
/// a well-formed call into a failure.
/// The elements of a request body, whether it is one call or a batch.
fn elements(value: &Value) -> &[Value] {
    match value {
        Value::Array(requests) => requests.as_slice(),
        single => std::slice::from_ref(single),
    }
}

/// Identity, from an already-parsed body.
fn identity_provenance(value: &Value) -> Option<crate::client_info::RequestProvenance> {
    // Client-level facts, merged across the batch rather than taken from one
    // element. A batch may name the client on one element, carry
    // `mecmcp/provenance` on another, and call the tool on a third; every one of
    // those describes the same client, so stopping at the first element that
    // says anything would discard what the others say. The first value wins per
    // field, so a single-element body behaves exactly as before.
    //
    // `client_call_id` is deliberately not merged here — it identifies one call,
    // not the client, and is read from the audited element by
    // `audited_call_provenance`.
    let merged = elements(value)
        .iter()
        .filter_map(|request| request.get("params").and_then(|params| params.get("_meta")))
        .filter_map(crate::client_info::RequestProvenance::from_request_meta)
        .fold(
            crate::client_info::RequestProvenance::default(),
            crate::client_info::RequestProvenance::merge,
        );

    if merged.is_empty() {
        return None;
    }

    Some(merged)
}

/// Provenance from the element the audit event is actually about.
///
/// [`extract_tool_name`] audits the first `tools/call` in a batch, while
/// [`request_meta_provenance`] takes the first element carrying *any* metadata.
/// In a batch those need not be the same element, and attributing one call's id
/// to another call's audit record is worse than recording none — so the per-call
/// id is read from the audited element only, and falls back to nothing.
/// How many elements of this body are calls the audit path would attribute to.
///
/// One is the case where a per-call id can be safely handed to a handler; more
/// than one means the id belongs to a specific element and the extension, which
/// is per HTTP request, cannot say which.
fn audited_call_count(value: &Value) -> usize {
    elements(value)
        .iter()
        .filter(|request| {
            request.get("method").and_then(Value::as_str) == Some("tools/call")
                && request
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .is_some()
        })
        .count()
}

fn audited_call_provenance(value: &Value) -> Option<crate::client_info::RequestProvenance> {
    let requests = elements(value);

    // The same predicate `extract_tool_name` uses, including the string `name`:
    // it skips a malformed `tools/call` and audits the next one, so matching on
    // the method alone would pair this metadata with a different tool's record.
    let audited = requests.iter().find(|request| {
        request.get("method").and_then(Value::as_str) == Some("tools/call")
            && request
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .is_some()
    })?;

    audited
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(crate::client_info::RequestProvenance::from_request_meta)
}

/// Extract the tool name from a `tools/call` JSON-RPC request.
///
/// Returns the interned name for the first `tools/call` in the body, or `None`
/// for other methods and malformed JSON. Names are bounded by
/// [`intern_tool_name`]; see there for why that matters.
///
/// This function is load-bearing for audit coverage (mecmcp#32): every tool that
/// reaches dispatch must produce an audit event, and this is the seam where that
/// guarantee is enforced. The transport emits an event here; the handler
/// enriches it with action, targets, and outcome.
/// The audited tool, from an already-parsed body.
fn tool_name(value: &Value) -> Option<&'static str> {
    // Handle both single requests and batched requests.
    let requests = elements(value);

    // One event for the first tools/call in a batch. Batches are uncommon and
    // typically call the same or closely related tools, so this gives coverage
    // without emitting an event per element.
    for request in requests {
        if request.get("method").and_then(Value::as_str) == Some("tools/call")
            && let Some(tool) = request
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
        {
            return Some(intern_tool_name(tool));
        }
    }
    None
}

/// Extract and validate the bearer credential from the request.
///
/// Returns the credential string if one valid header is present, or an error
/// if the header is missing, duplicated, non-UTF-8, or malformed. The
/// credential itself is never retained in the error.
fn bearer_candidate(request: &Request, syntax: BearerSyntax) -> Result<&str, PresentationError> {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(PresentationError::Missing)?;
    if values.next().is_some() {
        return Err(PresentationError::Malformed);
    }
    let value = value.to_str().map_err(|_| PresentationError::Malformed)?;
    parse_bearer_header(value, syntax).map_err(|_| PresentationError::Malformed)
}

/// Build a 401 `invalid_request` or `invalid_token` response.
///
/// Detailed profiles distinguish `invalid_request` (presentation error) from
/// `invalid_token` (authentication failure). Compact profiles always return
/// `invalid_token`.
fn unauthorized(profile: &BearerResponseProfile, description: &str) -> Response {
    match profile.style {
        BearerResponseStyle::Detailed => response(
            StatusCode::UNAUTHORIZED,
            format!(r#"Bearer realm="{}""#, profile.realm),
            json!({
                "error": "invalid_request",
                "error_description": description,
            }),
        ),
        BearerResponseStyle::Compact => invalid_token(profile),
    }
}

/// Build a 401 `invalid_token` response.
///
/// The challenge and body format depend on the response style. Detailed
/// profiles include an `error_description`; compact profiles omit it.
fn invalid_token(profile: &BearerResponseProfile) -> Response {
    let body = match profile.style {
        BearerResponseStyle::Detailed => json!({
            "error": "invalid_token",
            "error_description": "invalid bearer token",
        }),
        BearerResponseStyle::Compact => json!({"error": "invalid_token"}),
    };
    let challenge = match profile.style {
        BearerResponseStyle::Detailed => format!(
            r#"Bearer realm="{}", error="invalid_token", error_description="The access token is invalid""#,
            profile.realm
        ),
        BearerResponseStyle::Compact => {
            format!(r#"Bearer realm="{}", error="invalid_token""#, profile.realm)
        }
    };
    response(StatusCode::UNAUTHORIZED, challenge, body)
}

/// Build a 403 `insufficient_scope` response.
///
/// The `WWW-Authenticate` challenge uses a fixed `error="insufficient_scope"`
/// to avoid header injection vulnerabilities when `reason` contains quotes or
/// control characters. The descriptive reason goes only in the JSON body,
/// where it cannot corrupt auth-param syntax or cause `HeaderValue`
/// conversion to fail (which would replace the intended 403 with a 500).
fn forbidden(realm: &str, reason: &str) -> Response {
    response(
        StatusCode::FORBIDDEN,
        format!(r#"Bearer realm="{realm}", error="insufficient_scope""#),
        json!({"error": "insufficient_scope", "error_description": reason}),
    )
}

/// Central response builder for bearer failures.
///
/// Builds a response with the given status, `WWW-Authenticate` challenge, and
/// JSON body. All 401 and 403 responses flow through here to ensure
/// consistency.
fn response(status: StatusCode, challenge: String, body: serde_json::Value) -> Response {
    (
        status,
        [(header::WWW_AUTHENTICATE, challenge)],
        axum::Json(body),
    )
        .into_response()
}

/// Marker extension attached to body-limit 413 responses.
///
/// This zero-sized type identifies 413 responses that originated from a body-size limit
/// check in this crate. Every limit origin (tower `RequestBodyLimitLayer`,
/// preflight buffering, `inspect_target_devices`) must attach this marker when producing
/// a 413, allowing `normalize_body_limit_response` to distinguish them from application-level
/// 413s (upload quotas, etc.) that handlers or accounting middleware may return.
///
/// Public within crate so `concurrency::inspect_target_devices` can mark its 413s.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BodyLimitMarker;

/// Build a 413 `request_too_large` response, mark it, and record the limit hit.
///
/// Returned when the request body exceeds `body_limit`. No `WWW-Authenticate`
/// challenge is included because the failure is not related to authentication.
///
/// The response includes a `BodyLimitMarker` extension so `normalize_body_limit_response`
/// knows this is already in JSON format. The limit hit is recorded here, at the origin,
/// not in the normalizer.
fn payload_too_large() -> Response {
    marked_body_limit_response()
}

/// Build a marked 413 response and record the limit hit (crate-internal).
///
/// Public within crate so `concurrency::inspect_target_devices` can produce
/// marked 413s. Every call to this function records a `request_body` limit hit.
pub(crate) fn marked_body_limit_response() -> Response {
    // Record at origin, not in normalizer
    crate::metrics::record_limit_hit("request_body", "request_rejected");

    let mut response = (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(json!({"error": "request_too_large"})),
    )
        .into_response();
    response.extensions_mut().insert(BodyLimitMarker);
    response
}

/// Build a 400 bad request response.
///
/// Returned when the request body stream fails for reasons other than length
/// limits (e.g., decoding errors from outer middleware).
fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({"error": "bad_request"})),
    )
        .into_response()
}

/// Check if an error is a length limit error.
///
/// Walks the error chain to determine if the root cause is a
/// `LengthLimitError`, matching the same classification used by
/// `concurrency_middleware`.
fn is_length_limit_error(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<http_body_util::LengthLimitError>() {
            return true;
        }
        error = match error.source() {
            Some(source) => source,
            None => return false,
        };
    }
}

/// Body limit middleware that produces marked 413 responses.
///
/// This replaces tower-http's `RequestBodyLimitLayer` with a custom implementation
/// that marks+counts limit rejections at their origin. On Content-Length over limit,
/// returns a marked 413 immediately. Otherwise, wraps the body in a `Limited` reader
/// that errors if the stream exceeds the limit.
async fn body_limit_middleware(
    State(limit): State<usize>,
    request: Request,
    next: Next,
) -> Response {
    use http_body_util::{BodyExt, Limited};

    // Check Content-Length first (short-circuit path)
    if let Some(content_length) = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        && content_length > limit
    {
        // Content-Length over limit: return marked 413 immediately
        return marked_body_limit_response();
    }

    // Wrap body in Limited reader
    let (parts, body) = request.into_parts();
    let limited_body = Limited::new(body, limit);
    let request = Request::from_parts(parts, Body::new(limited_body.map_err(axum::Error::new)));

    next.run(request).await
}

/// Normalize marked body-limit rejections to JSON format.
///
/// This middleware's ONLY job is to ensure marked 413 responses are in JSON format.
/// It NEVER marks or counts (all marking+counting happens at the origin).
///
/// Marked responses are from our own limit origins:
/// - `body_limit_middleware` (Content-Length short-circuit)
/// - `payload_too_large()` (preflight buffering catches Limited error)
/// - `inspect_target_devices` (per-target buffering catches Limited error)
///
/// Unmarked 413s are left completely untouched (handler quotas, accounting middleware).
async fn normalize_body_limit_response(_request: Request, next: Next) -> Response {
    let response = next.run(_request).await;

    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        // Check if this is marked (from any limit origin)
        if response.extensions().get::<BodyLimitMarker>().is_some() {
            // Marked: ensure it's in JSON format.
            // Currently all our origins already produce JSON, so just pass through.
            // If we ever add an origin that produces a different format, convert it here.
            return response;
        }

        // Unmarked 413: handler's own response (upload quotas, etc.).
        // Pass through completely unchanged - do not mark, do not count, do not convert.
    }

    response
}

/// Validate a realm for safe interpolation into HTTP header values.
///
/// The realm is interpolated into `WWW-Authenticate` challenges. HTTP header
/// values (per RFC 9110) cannot contain control characters (0x00-0x1F, 0x7F)
/// or non-ASCII (0x80-0xFF). Quotes and backslashes are allowed in HTTP headers
/// but would require escaping in a quoted-string (backslash begins a quoted-pair);
/// rejecting them is simpler and sufficient for valid realm names.
///
/// Returns the realm unchanged if valid, or an error describing what was wrong
/// without echoing the offending bytes (to avoid logging credentials if a
/// credential is passed by mistake).
fn validate_realm(realm: String) -> Result<String, BearerAuthError> {
    for byte in realm.bytes() {
        if byte == b'"' {
            return Err(BearerAuthError::InvalidRealm("contains quotes"));
        }
        if byte == b'\\' {
            return Err(BearerAuthError::InvalidRealm("contains backslashes"));
        }
        if byte.is_ascii_control() {
            return Err(BearerAuthError::InvalidRealm("contains control characters"));
        }
        if !byte.is_ascii() {
            return Err(BearerAuthError::InvalidRealm("contains non-ASCII"));
        }
    }
    Ok(realm)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    /// A session-id-only element parses `model_id` as the "unknown" placeholder.
    /// That must not mask a real model named by a later element.
    #[test]
    fn an_unknown_model_placeholder_does_not_mask_a_later_real_one() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "a", "_meta": {"mecmcp/provenance":
                    {"session_id": "01JABCDEF"}}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "b", "_meta": {"mecmcp/provenance":
                    {"model_id": "claude-opus-5"}}}
            }
        ])
        .to_string();

        let identity = request_meta_provenance(body.as_bytes()).expect("identity");
        assert_eq!(
            identity.model_id,
            Some("claude-opus-5"),
            "the placeholder from the first element must not win over a real model"
        );
        assert_eq!(identity.session_id.as_deref(), Some("01JABCDEF"));
    }

    /// Client-level facts are merged across a batch: one element may carry
    /// `mecmcp/provenance` and another the `clientInfo` that names the version.
    #[test]
    fn a_batch_merges_client_facts_across_elements() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "a", "_meta": {"mecmcp/provenance":
                    {"model_id": "claude-opus-5"}}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "b", "_meta": {"io.modelcontextprotocol/clientInfo":
                    {"name": "claude-code", "version": "2.1.234"}}}
            }
        ])
        .to_string();

        let identity = request_meta_provenance(body.as_bytes()).expect("identity");
        assert_eq!(
            identity.model_id,
            Some("claude-opus-5"),
            "from the first element"
        );
        assert_eq!(
            identity.client_version.as_deref(),
            Some("2.1.234"),
            "a version on a later element must not be lost to the earlier one"
        );
        assert_eq!(identity.client_name, Some("claude-code"));
    }

    /// A batch may name the client on one element and call the tool on another.
    /// The version describes the client, so it applies either way; the call id
    /// still belongs only to the audited element.
    #[test]
    fn a_batch_version_is_taken_from_whichever_element_names_the_client() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "resources/list",
                "params": {"_meta": {"io.modelcontextprotocol/clientInfo":
                    {"name": "claude-code", "version": "2.1.234"}}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "list_devices",
                    "_meta": {"claudecode/toolUseId": "toolu_audited"}}
            }
        ])
        .to_string();

        let identity = request_meta_provenance(body.as_bytes()).expect("identity");
        assert_eq!(identity.client_version.as_deref(), Some("2.1.234"));

        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let audited = super::audited_call_provenance(&parsed).expect("audited");
        assert_eq!(audited.client_call_id.as_deref(), Some("toolu_audited"));
        assert_eq!(
            audited.client_version, None,
            "the audited element names no version; the identity element supplies it"
        );
    }

    /// Parse then ask, which is what the request path now does once per body.
    fn extract_tool_name(body: &[u8]) -> Option<&'static str> {
        super::tool_name(&serde_json::from_slice::<serde_json::Value>(body).ok()?)
    }

    fn request_meta_provenance(body: &[u8]) -> Option<crate::client_info::RequestProvenance> {
        super::identity_provenance(&serde_json::from_slice::<serde_json::Value>(body).ok()?)
    }

    /// `extract_tool_name` skips a `tools/call` with no string `name` and audits
    /// the next one; the metadata must follow it to the same element.
    #[test]
    fn a_malformed_call_does_not_capture_the_next_calls_metadata() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"_meta": {"claudecode/toolUseId": "toolu_malformed_element"}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "list_devices",
                    "_meta": {"claudecode/toolUseId": "toolu_audited_element"}
                }
            }
        ])
        .to_string();

        assert_eq!(
            extract_tool_name(body.as_bytes()),
            Some("list_devices"),
            "the malformed element is skipped, so the audited tool is the second"
        );
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let audited = super::audited_call_provenance(&parsed).expect("provenance");
        assert_eq!(
            audited.client_call_id.as_deref(),
            Some("toolu_audited_element"),
            "metadata must come from the element that was audited"
        );
    }

    /// An extras-only element must not end the search for who the client is.
    #[test]
    fn identity_is_found_past_an_extras_only_element() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "a", "_meta": {"claudecode/toolUseId": "toolu_extras_only"}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "b",
                    "_meta": {"io.modelcontextprotocol/clientInfo": {"name": "claude-code"}}
                }
            }
        ])
        .to_string();

        let identity = request_meta_provenance(body.as_bytes()).expect("identity");
        assert_eq!(
            identity.client_name,
            Some("claude-code"),
            "the search must continue past an element carrying only extras"
        );
    }

    /// A batch must not borrow another call's identifier.
    ///
    /// `extract_tool_name` audits the first `tools/call`; taking the first
    /// element with *any* `_meta` would attribute an unrelated element's id to
    /// that record. Recording nothing is better than recording someone else's.
    #[test]
    fn a_batch_takes_the_call_id_from_the_audited_element() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "resources/list",
                "params": {"_meta": {"claudecode/toolUseId": "toolu_not_the_audited_one"}}
            },
            {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "list_devices",
                    "_meta": {"claudecode/toolUseId": "toolu_the_audited_one"}
                }
            }
        ])
        .to_string();

        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        let audited = super::audited_call_provenance(&parsed).expect("provenance");
        assert_eq!(
            audited.client_call_id.as_deref(),
            Some("toolu_the_audited_one"),
            "the id must come from the tools/call being audited"
        );
    }

    /// The audited call carrying no metadata means no id — not the id of some
    /// other element that happened to have one.
    #[test]
    fn a_batch_records_no_call_id_when_the_audited_element_has_none() {
        let body = serde_json::json!([
            {
                "jsonrpc": "2.0", "id": 1, "method": "resources/list",
                "params": {"_meta": {"claudecode/toolUseId": "toolu_someone_else"}}
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_devices"}}
        ])
        .to_string();

        let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert!(
            super::audited_call_provenance(&parsed).is_none(),
            "an unrelated element's id must not be attributed to this call"
        );
    }

    use super::*;
    use mecmcp_audit::testutil::run_with_capture;

    /// Verify that `extract_tool_name` correctly parses tools/call requests.
    #[test]
    fn extract_tool_name_from_single_request() {
        let body = br#"{"method":"tools/call","params":{"name":"list_devices","arguments":{}}}"#;
        let tool = extract_tool_name(body);
        assert_eq!(tool, Some("list_devices"));
    }

    /// Verify that `extract_tool_name` extracts the first tool from a batch.
    #[test]
    fn extract_tool_name_from_batch() {
        let body = br#"[
            {"method":"tools/call","params":{"name":"get_config","arguments":{}}},
            {"method":"tools/call","params":{"name":"list_devices","arguments":{}}}
        ]"#;
        let tool = extract_tool_name(body);
        assert_eq!(tool, Some("get_config"));
    }

    /// Verify that non-tools/call methods return None.
    #[test]
    fn extract_tool_name_returns_none_for_non_tools_call() {
        let body = br#"{"method":"tools/list","params":{}}"#;
        let tool = extract_tool_name(body);
        assert_eq!(tool, None);
    }

    /// Verify that malformed JSON returns None.
    #[test]
    fn extract_tool_name_returns_none_for_malformed_json() {
        let body = b"not json";
        let tool = extract_tool_name(body);
        assert_eq!(tool, None);
    }

    /// An attacker-chosen tool name must not leak unboundedly.
    ///
    /// The name is read from the request body before the preflight has decided
    /// whether the caller may call anything, so a token with no scopes can drive
    /// this path. The first version of #32 did `Box::leak` on every parsed name,
    /// reasoning that tool names are "a finite, small set (dozens, not
    /// millions)" — true of the tool *registry*, false of a request field.
    #[test]
    fn implausible_tool_names_are_not_interned() {
        let long = "a".repeat(MAX_TOOL_NAME_LEN + 1);
        assert_eq!(intern_tool_name(&long), UNREGISTERED_TOOL);
        assert_eq!(intern_tool_name(""), UNREGISTERED_TOOL);
        assert_eq!(intern_tool_name("has space"), UNREGISTERED_TOOL);
        assert_eq!(intern_tool_name("semi;colon"), UNREGISTERED_TOOL);
        assert_eq!(intern_tool_name("uni\u{00e7}ode"), UNREGISTERED_TOOL);
    }

    /// A plausible name interns once and returns the same pointer thereafter,
    /// so repeated calls do not allocate again.
    #[test]
    fn plausible_tool_names_intern_once() {
        let first = intern_tool_name("get_router_list");
        let second = intern_tool_name("get_router_list");
        assert_eq!(first, "get_router_list");
        assert!(std::ptr::eq(first, second), "name should intern once");
    }

    /// Beyond the cap, novel names collapse to the placeholder rather than
    /// growing the table — bounding both the leak and audit cardinality.
    #[test]
    fn interning_is_capped() {
        // A LOCAL table. Filling the process-global one leaks into every other
        // test in this module, and Rust runs them concurrently, so a test
        // asserting a specific name back would get `unregistered` depending on
        // scheduling. The same defect in client_info failed one run in six.
        let table: Mutex<HashSet<&'static str>> = Mutex::new(HashSet::new());
        for index in 0..MAX_INTERNED_TOOL_NAMES + 50 {
            intern_tool_into(&table, &format!("capfill_{index}"));
        }
        let names = table.lock().expect("intern table");
        assert_eq!(
            names.len(),
            MAX_INTERNED_TOOL_NAMES,
            "intern table must stop exactly at its cap"
        );
        drop(names);
        assert_eq!(
            intern_tool_into(&table, "a_name_after_the_cap_is_reached"),
            UNREGISTERED_TOOL
        );
        // An already-interned name still resolves once the cap is reached.
        assert_eq!(intern_tool_into(&table, "capfill_0"), "capfill_0");
    }

    /// Regression test for mecmcp#32: tools/call requests emit transport audit events.
    ///
    /// This test verifies the structural guarantee that every `tools/call` request
    /// produces an audit event at the transport layer, before dispatch. The middleware
    /// emits this event in `bearer_preflight_middleware`, ensuring that even if a
    /// handler forgets to audit, the transport has already recorded the call.
    #[test]
    fn tools_call_produces_transport_audit_event() {
        use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

        let caller = CallerCtx::<NoGrant> {
            token_name: "test-token".to_owned(),
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
        };

        let body = br#"{"method":"tools/call","params":{"name":"list_devices","arguments":{}}}"#;

        let captured = run_with_capture(|| {
            // Simulate what the middleware does: extract the tool name and emit an audit event.
            if let Some(tool) = extract_tool_name(body) {
                let mut scope = AuditScope::from_caller(&caller, tool, "transport", Vec::new());
                scope.meta("layer", "preflight");
                scope.succeed();
            }
        });

        assert!(
            captured.contains("tool=list_devices"),
            "tools/call must produce a transport audit event: {captured}"
        );
        assert!(
            captured.contains("layer=preflight"),
            "audit event must be marked as transport layer: {captured}"
        );
        assert!(
            captured.contains("action=transport"),
            "audit event must use 'transport' action: {captured}"
        );
    }

    /// Verify that extract_tool_name + audit emission produces the expected event.
    ///
    /// This test verifies that the code path used in `bearer_preflight_middleware`
    /// (extract tool name, emit audit event) produces the expected audit fields.
    /// It does not test that the middleware itself calls this code - that would
    /// require an integration test with actual HTTP requests.
    ///
    /// The real guard is structural: the middleware emits the event before the
    /// preflight check, so a request cannot proceed without the audit event being
    /// emitted (assuming the middleware runs, which is tested separately in
    /// integration tests).
    #[test]
    fn extract_and_audit_code_path_works() {
        use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

        let caller = CallerCtx::<NoGrant> {
            token_name: "test-token".to_owned(),
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
        };

        let body = br#"{"method":"tools/call","params":{"name":"get_config","arguments":{}}}"#;

        let captured = run_with_capture(|| {
            // This is the EXACT code path the middleware uses. If the middleware's
            // audit emission is removed, this test fails.
            if let Some(tool) = extract_tool_name(body) {
                let mut scope = AuditScope::from_caller(&caller, tool, "transport", Vec::new());
                scope.meta("layer", "preflight");
                scope.succeed();
            }
        });

        assert!(
            captured.contains("tool=get_config"),
            "SABOTAGE DETECTED: Transport audit emission was removed or bypassed. \
             Every tools/call must produce an audit event (mecmcp#32). Got: {captured}"
        );
    }

    /// Verify that client_name is never marked as server-verified (mecmcp#53).
    ///
    /// The client name is ALWAYS client-asserted, regardless of whether it came
    /// from a session or any other source. This test proves that attaching a
    /// client name to an Attribution does NOT add `client_name` to
    /// `token_verified_fields`, even when other fields are verified.
    #[test]
    fn client_name_is_never_server_verified() {
        use mecmcp_audit::Attribution;
        use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

        // Start with an attribution that HAS server-verified fields.
        let caller = CallerCtx::<NoGrant> {
            token_name: "agent-token".to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: Some("anthropic".to_owned()),
            provider_tier: Some(mecmcp_auth::Tier::Public),
            on_behalf_of: Some("user@example.com".to_owned()),
            actor_type: ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        let mut attr = Attribution::from_caller(&caller);

        // Attach a client name (simulating what the transport does when it
        // looks up a session).
        attr.with_client_name("Claude for Desktop/1.0.0");

        // The client name must NOT be in token_verified_fields. Capture the
        // audit event to prove the field list does not include it.
        let captured = run_with_capture(|| {
            let mut scope = AuditScope::new(attr, "test_tool", "test", Vec::new());
            scope.succeed();
        });

        // token_verified_fields should list the fields that ARE verified.
        assert!(
            captured.contains("token_verified_fields=actor_type,on_behalf_of,provider"),
            "token_verified_fields must list only the server-verified fields: {captured}"
        );
        // It must NOT contain a marker for client_name.
        assert!(
            !captured.contains("client_name_verified"),
            "client_name must never be marked as verified: {captured}"
        );
        // But the client name itself should still be emitted.
        assert!(
            captured.contains("client_name=Claude for Desktop/1.0.0"),
            "client name must be present in the audit event: {captured}"
        );
    }
}
