//! Vendor-neutral streamable-HTTP hardening layer for mechub MCP servers.
//!
//! This crate provides host/Origin validation, bearer middleware, rate limits,
//! concurrency and session caps, overload responses, metrics, and TLS loading.
//! Every consumer-owned choice — metric names, target argument keys, realm,
//! server label — is passed as a parameter rather than baked in.

mod approver_assertion;
mod auth;
mod caller;
mod client_info;
mod concurrency;
mod config;
mod consent;
pub mod evidence_transport;
mod health;
mod identity;
mod listener;
mod metrics;
mod overload;
pub mod preflight;
mod rate_limit;
mod server;
mod session;
mod target;
// Test-only surface (issue #184, mecmcp#357): the loopback client and serving
// harness a consumer's integration tests use. Gated on the feature rather
// than `any(test, ...)`: `test_client` calls into the optional `ureq`
// dependency, which `cfg(test)` alone does not pull in, so a plain
// `cargo test` with no features would compile the module against a crate
// that is not there. `cargo test -p mecmcp-transport --features test-util`
// (or a consumer's dev-dependency doing the same) is what exercises this
// code; a release build enables neither, which is what keeps `ureq` and this
// scaffolding out of `cargo tree -e normal`.
#[cfg(feature = "test-util")]
pub mod test_client;
#[cfg(feature = "test-util")]
pub mod test_harness;
pub mod tls;

pub use approver_assertion::{
    APPROVER_ASSERTION_HEADER, ApproverAssertionError, ApproverAssertionVerifier,
};
pub use auth::{
    BearerAuthError, BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    BearerResponseStyle, BoundaryAccounting, apply_bearer_boundary,
};
pub use client_info::{ClientExtras, ClientInfo, RequestProvenance};

// Internal types and functions exported only for testing
#[doc(hidden)]
pub mod tests {
    pub use crate::auth::{
        AuthState, PreflightState, bearer_auth_middleware, bearer_preflight_middleware,
    };
}
// Internal function exported only for `fuzz/` (MEC-790): the crate's own
// unit tests reach `resolve_rate_limit_ip` as a `super::` sibling, but the
// out-of-workspace fuzz crate can only reach it through a public path. Not
// part of the crate's real API -- same rationale as `tests` above.
#[doc(hidden)]
pub mod fuzz {
    pub use crate::rate_limit::resolve_rate_limit_ip;
}
pub use caller::AuthenticatedToken;
#[allow(deprecated)]
pub use concurrency::{
    ConcurrencyState, apply_body_limit, concurrency_middleware, target_concurrency_middleware,
    token_concurrency_middleware,
};
#[allow(deprecated)]
pub use config::{LimitsConfig, LimitsConfigError, streamable_http_server_config};
pub use consent::{InsecureBindAcknowledgement, NoAuthAcknowledgement};
pub use health::ReadinessCheck;
pub use identity::TransportIdentity;
pub use listener::ListenerRefusal;
pub use metrics::PrometheusRuntime;
pub use overload::overload_response;
pub use preflight::{
    CallerScopes, MalformedArgumentsPolicy, MalformedTargetPolicy, OptionalPreflight,
    ScopePreflight, TargetField, TargetValueShape, ToolScopePreflight,
};
#[allow(deprecated)]
pub use rate_limit::{apply_ip_rate_limit, apply_rate_limit, apply_token_rate_limit};
pub use server::{
    HostOriginPolicy, HttpServeError, HttpShutdown, HttpTransportBuildError, HttpTransportConfig,
    ServePlan, build_streamable_http_router, loopback_origins, serve_router,
    streamable_http_server_config as build_rmcp_server_config,
};
pub use session::{LimitedSessionManager, LimitedSessionManagerError, SessionTracker};
pub use target::{TargetLimiter, extract_targets};
pub use tls::{TlsError, load as load_tls, load_with_client_auth as load_tls_with_client_auth};
