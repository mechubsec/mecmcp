//! Forward-only evidence pipeline (mecmcp#378, option 2): no SSDF, the forward
//! sink is the whole destination.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::evidence::ClosedSegment;
use mecmcp_audit::sinks::ssdf::{HttpRequest, HttpTransport, SsdfSinkConfig, SsdfSinkError};
use mecmcp_audit::{EvidenceConfig, EvidenceService, ForwardOnlyConfig, ForwardSinkConfig};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Accepts everything (answering SSDF reads with an empty chain) unless told to
/// refuse.
#[derive(Default)]
struct Collector {
    refuse: AtomicBool,
}

impl HttpTransport for Collector {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(SsdfSinkError::Http("collector down".to_owned()));
        }
        if request.url.contains("SELECT") {
            return Ok("0\t0\n".to_owned());
        }
        Ok(String::new())
    }
}

fn forward_config(dir: &Path) -> ForwardSinkConfig {
    ForwardSinkConfig {
        endpoint: "http://collector.example/audit".to_owned(),
        bearer_token: None,
        outbox_path: dir.join("forward-outbox.ndjson"),
        ledger_path: dir.join("forward-ledger.json"),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    }
}

fn forward_only(dir: &Path, run_id: &str) -> ForwardOnlyConfig {
    ForwardOnlyConfig {
        server_id: "junos-950".to_owned(),
        run_id: run_id.to_owned(),
        records_per_segment: 1,
        delivery_interval: Duration::from_millis(20),
        forward: forward_config(dir),
        signing_key_path: None,
    }
}

fn outbox_segments(dir: &Path) -> Vec<ClosedSegment> {
    std::fs::read_to_string(dir.join("forward-outbox.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// A forward config whose outbox is a write-sealed memfd: every append fails
/// with EPERM, the one portable way to fail an fsynced write from a test. The
/// returned fd keeps the memfd alive.
fn sealed_forward_config(dir: &Path) -> (ForwardSinkConfig, std::os::fd::OwnedFd) {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use std::os::fd::AsRawFd;
    let memfd = memfd_create("forward-outbox", MemfdFlags::ALLOW_SEALING).unwrap();
    fcntl_add_seals(&memfd, SealFlags::WRITE).unwrap();
    let mut config = forward_config(dir);
    config.outbox_path = format!("/proc/self/fd/{}", memfd.as_raw_fd()).into();
    (config, memfd)
}

/// The chain resumes across a restart: run 2 attaches to run 1's last head,
/// even though run 1's segments were all delivered (delivery never prunes the
/// outbox the head is read from).
#[test]
fn forward_only_resumes_one_chain_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    for run_id in ["run-1", "run-2"] {
        let service = EvidenceService::start_forward_only(
            forward_only(dir.path(), run_id),
            Arc::new(Collector::default()),
        )
        .unwrap();
        let recorder = service.recorder();
        recorder.proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:d");
        recorder
            .apply_intent("req-2", "cs-1", "vsrx-ci", "alice")
            .unwrap();
        service.shutdown().unwrap();
    }

    let segments = outbox_segments(dir.path());
    let last_of_first = segments
        .iter()
        .rfind(|segment| segment.run_id == "run-1")
        .expect("run 1 produced segments");
    let first_of_second = segments
        .iter()
        .find(|segment| segment.run_id == "run-2")
        .expect("run 2 produced segments");
    assert_eq!(
        first_of_second.prev_hash, last_of_first.head_hash,
        "a restart must continue the chain, not start a second root"
    );
}

/// With no SSDF copy, the forward spool is the only record, so a spool failure
/// must refuse the operation.
#[test]
fn forward_only_spool_failure_is_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (forward, _memfd) = sealed_forward_config(dir.path());
    let service = EvidenceService::start_forward_only(
        ForwardOnlyConfig {
            forward,
            ..forward_only(dir.path(), "run-1")
        },
        Arc::new(Collector::default()),
    )
    .unwrap();

    let refused = service
        .recorder()
        .apply_intent("req-1", "cs-1", "vsrx-ci", "alice");

    assert!(refused.is_err(), "the apply must not proceed untraced");
}

/// Alongside SSDF the forward copy stays best-effort: the same failure must not
/// stop the operation.
#[test]
fn ssdf_plus_forward_spool_failure_stays_best_effort() {
    let dir = tempfile::tempdir().unwrap();
    let (forward, _memfd) = sealed_forward_config(dir.path());
    let service = EvidenceService::start_with_transport(
        EvidenceConfig {
            server_id: "junos-950".to_owned(),
            run_id: "run-1".to_owned(),
            records_per_segment: 1,
            delivery_interval: Duration::from_millis(20),
            sink: SsdfSinkConfig {
                endpoint: "http://ch.example:8123".to_owned(),
                database: "ssdf".to_owned(),
                username: "u".to_owned(),
                password: mecmcp_secret::OutboundSecret::new_unchecked("w".to_owned()),
                verify_username: "v".to_owned(),
                verify_password: mecmcp_secret::OutboundSecret::new_unchecked("v".to_owned()),
                outbox_path: dir.path().join("outbox.ndjson"),
                ledger_path: dir.path().join("ledger.json"),
                initial_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(2),
            },
            signing_key_path: None,
            forward_sink: Some(forward),
        },
        Arc::new(Collector::default()),
    )
    .unwrap();

    service
        .recorder()
        .apply_intent("req-1", "cs-1", "vsrx-ci", "alice")
        .expect("a failing second copy must not refuse the operation");
}

/// The drain delivers, and a refusing collector marks the pipeline degraded --
/// here the forward sink is the chain of record, so it drives the flag.
#[test]
fn forward_only_delivers_and_reports_degraded() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(Collector::default());
    transport.refuse.store(true, Ordering::SeqCst);
    let service =
        EvidenceService::start_forward_only(forward_only(dir.path(), "run-1"), transport.clone())
            .unwrap();
    service
        .recorder()
        .apply_intent("req-1", "cs-1", "vsrx-ci", "alice")
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !service.delivery_degraded() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(service.delivery_degraded());

    // Recovery clears it, and shutdown's flush completes without error.
    transport.refuse.store(false, Ordering::SeqCst);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while service.delivery_degraded() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!service.delivery_degraded());
    service.shutdown().unwrap();
}
