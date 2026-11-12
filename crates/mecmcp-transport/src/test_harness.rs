//! Serve a [`ServePlan`] on loopback for integration tests.
//!
//! # Why this exists
//!
//! [`ServePlan`] deliberately offers no way to extract its `Router`
//! (mecmcp#273): if the router could leave the plan, a consumer could serve it
//! directly and skip the listener admission checks, which is the defect that
//! design closes.
//!
//! That opacity has a cost this crate has to pay for, not push downstream. When
//! 0.9.0 landed, four consumer repositories had integration tests that drove the
//! router through `tower::ServiceExt::oneshot`. With the router sealed, two
//! deleted those tests, one disabled four files and relaxed `unsafe_code` from
//! `forbid` to `warn`, and one wrote an `unsafe` helper that assumed the
//! struct's field layout and segfaulted. Every one of those is worse than the
//! problem it solved.
//!
//! The supported answer is to serve the plan for real and talk to it over HTTP —
//! which also tests more than `oneshot` did, since it exercises the bind path
//! and the listener refusals. This module makes that a one-liner so nobody has
//! to reinvent it, or route around it.
//!
//! Test-only. Never reachable from a release build.

use crate::server::{HttpServeError, ServePlan, serve_router_on_listener};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// A plan served on a loopback port, with the handle that stops it.
#[derive(Debug)]
pub struct ServedPlan {
    /// The bound address. Dial this.
    pub address: SocketAddr,
    /// The serve task. Await it after cancelling the shutdown token.
    pub serving: JoinHandle<Result<(), HttpServeError>>,
}

/// Serve `plan` on an ephemeral loopback port and return where to reach it.
///
/// Loopback is exempt from every listener refusal, so a plan that would be
/// refused off-loopback still serves here — which is what makes this usable for
/// testing handler behaviour. To test the refusals themselves, call
/// [`crate::server::serve_router`] directly with a non-loopback address.
///
/// # Panics
///
/// Panics if no loopback port can be bound, which in a test means the
/// environment is broken rather than the code under test.
///
/// # Example
///
/// ```no_run
/// # async fn example(plan: mecmcp_transport::ServePlan) {
/// let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
/// // dial served.address over HTTP, assert on real responses
/// # }
/// ```
pub async fn serve_on_loopback(plan: ServePlan) -> ServedPlan {
    serve_on_loopback_with_timeout(plan, Duration::from_millis(50)).await
}

/// [`serve_on_loopback`] with an explicit drain timeout.
///
/// # Panics
///
/// Panics if no loopback port can be bound.
pub async fn serve_on_loopback_with_timeout(
    plan: ServePlan,
    shutdown_timeout: Duration,
) -> ServedPlan {
    serve_on_loopback_inner(plan, None, shutdown_timeout)
}

/// [`serve_on_loopback`] over TLS, for tests of the `Some(config)` listener path.
///
/// # Panics
///
/// Panics if no loopback port can be bound.
pub async fn serve_on_loopback_tls(plan: ServePlan, tls: Arc<rustls::ServerConfig>) -> ServedPlan {
    serve_on_loopback_inner(plan, Some(tls), Duration::from_millis(50))
}

fn serve_on_loopback_inner(
    plan: ServePlan,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown_timeout: Duration,
) -> ServedPlan {
    // Bind once and keep it. The port is discovered and used by the same
    // listener, so there is no window in which anything else can take it.
    //
    // This used to bind, read the port, drop the listener and let `serve_router`
    // re-bind. Between the drop and the re-bind another test in the same binary
    // could win the port; two harnesses then believed they owned one address,
    // and a client dialing "its" server reached the other one and was refused
    // with a 401 at initialize, because that server had never heard of its
    // bearer token. Rare locally, regular under CI's parallelism.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("no loopback port available for the test harness");
    let address = listener
        .local_addr()
        .expect("bound listener has no local address");

    let serving = tokio::spawn(serve_router_on_listener(
        plan,
        listener,
        tls,
        shutdown_timeout,
    ));

    // The socket is already bound and its backlog is accepting, so a caller may
    // dial immediately. The old sleep existed to cover the re-bind gap.

    ServedPlan { address, serving }
}
