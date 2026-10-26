//! Generic HTTPS/JSON forward sink for closed evidence segments.
//!
//! [`SsdfSink`](crate::sinks::ssdf::SsdfSink) is the durable, hash-chain-aware
//! destination and stays the source of truth. This sink is a second,
//! **additive** destination for the same [`ClosedSegment`]s -- a SIEM, a log
//! collector, an object-lock bucket sitting behind an HTTPS front end -- for
//! deployments that want a copy of the evidence trail somewhere other than
//! SSDF as well.
//!
//! ## Why this is not the syslog path the audit-forwarding standard rejects
//!
//! [`docs/AUDIT-FORWARDING-STANDARD.md`](https://github.com/mechubsec/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md)
//! rejected `rsyslog` forwarding of the per-call tool-audit stream because that
//! path is **unchained**: it lands bare JSON lines in a table anyone with
//! write access can edit undetectably, discarding the one property the whole
//! evidence trail exists to provide. This sink does not reintroduce that gap --
//! it ships the same [`ClosedSegment`] the SSDF sink ships, `prev_hash` and
//! `head_hash` intact, so a receiver that checks the chain can still detect a
//! dropped or altered record. What it does *not* do is SSDF's own
//! high-water-mark dedup (there is no `ssdf_audit_verify`-equivalent read
//! identity for an arbitrary collector); dedup here is local-ledger-only,
//! which is a weaker guarantee against redelivery after a lost ledger, not
//! against tampering. Operators who need SSDF's exact guarantees use SSDF;
//! this exists for everyone else who currently has nothing off-host at all.
//!
//! ## Forward-only mode
//!
//! SSDF is not required (mecmcp#378, option 2).
//! [`EvidenceService::start_forward_only`](crate::EvidenceService::start_forward_only)
//! makes this sink the pipeline's only destination, so operators without SSDF
//! still get the chained log off-host. There the forward spool is the sole
//! durable record, so the recorder is fail-closed on it, and the chain resumes
//! from [`ForwardSink::produced_head`]. Alongside SSDF it stays best-effort.
//!
//! ## Background delivery
//!
//! As [`SsdfSink`](crate::sinks::ssdf::SsdfSink): no background thread.
//! Callers invoke [`ForwardSink::attempt_delivery`] on a timer and
//! [`ForwardSink::shutdown_flush`] on graceful stop.

use crate::evidence::ClosedSegment;
use crate::sinks::delivery_ledger::{DeliveryLedger, DeliveryStatus, SegmentId};
use crate::sinks::ssdf::{HttpRequest, HttpTransport, ProducedHead, dedup_token};
use mecmcp_secret::OutboundSecret;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub use crate::sinks::ssdf::{DeliveryReport, SsdfSinkError as ForwardSinkError};

/// Configuration for [`ForwardSink`].
#[derive(Clone)]
pub struct ForwardSinkConfig {
    /// The collector's HTTPS (or loopback HTTP) endpoint. One `ClosedSegment`
    /// is POSTed per request, as a single JSON object -- not NDJSON, so an
    /// ordinary HTTPS ingestion endpoint (a SIEM webhook, an object-lock
    /// bucket's HTTP front end) can accept it without a ClickHouse-shaped
    /// client.
    pub endpoint: String,
    /// Bearer token for the `Authorization` header. `None` sends no
    /// `Authorization` header at all -- some collectors sit behind a
    /// network-level control instead.
    pub bearer_token: Option<OutboundSecret>,
    /// Durable outbox for segments not yet confirmed delivered.
    pub outbox_path: PathBuf,
    /// Delivery ledger, kept separate from the outbox so delivery bookkeeping
    /// never mutates the hashed records.
    pub ledger_path: PathBuf,
    /// Initial retry backoff.
    pub initial_backoff: Duration,
    /// Maximum retry backoff.
    pub max_backoff: Duration,
}

impl std::fmt::Debug for ForwardSinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardSinkConfig")
            .field("endpoint", &self.endpoint)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .field("outbox_path", &self.outbox_path)
            .field("ledger_path", &self.ledger_path)
            .field("initial_backoff", &self.initial_backoff)
            .field("max_backoff", &self.max_backoff)
            .finish()
    }
}

/// A generic HTTPS/JSON destination for closed evidence segments.
///
/// See the module docs for how this differs from [`SsdfSink`](crate::sinks::ssdf::SsdfSink)
/// and from the rejected syslog design.
pub struct ForwardSink {
    config: ForwardSinkConfig,
    outbox: Arc<Mutex<OutboxState>>,
    ledger: Arc<Mutex<DeliveryLedger>>,
    transport: Arc<dyn HttpTransport>,
}

struct OutboxState {
    file: File,
    path: PathBuf,
}

impl ForwardSink {
    /// Create a new forward sink with a custom transport.
    ///
    /// The transport decides TLS: `StdHttpTransport` (from
    /// [`crate::sinks::ssdf`]) refuses anything but loopback HTTP, so a real
    /// remote endpoint needs a TLS-capable transport such as
    /// `mecmcp-transport`'s `EvidenceHttpTransport`, which already implements
    /// [`HttpTransport`] and is reused unchanged here.
    ///
    /// Unlike [`SsdfSink`](crate::sinks::ssdf::SsdfSink), this sink never
    /// blocks a delivery pass on backoff: it shares a thread with the SSDF
    /// drain loop (see `service::drain_until_stopped`), and a
    /// sleeping forward pass would delay the next SSDF attempt behind it.
    /// [`attempt_delivery`](Self::attempt_delivery) instead skips a segment
    /// whose backoff has not yet elapsed and revisits it on the next pass.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardSinkError`] if the outbox or ledger cannot be opened.
    pub fn new_with_transport(
        config: ForwardSinkConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ForwardSinkError> {
        let outbox_path = std::path::absolute(&config.outbox_path)?;
        let ledger_path = std::path::absolute(&config.ledger_path)?;

        // Same 0600-or-tighten handling as the SSDF outbox: this file carries
        // full evidence records, and a systemd unit without `UMask=0077`
        // would otherwise leave it group- or world-readable.
        let outbox_file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&outbox_path)?;
        let current_mode = outbox_file.metadata()?.permissions().mode();
        if current_mode & 0o177 != 0 {
            outbox_file.set_permissions(Permissions::from_mode(0o600))?;
        }

        let outbox = Arc::new(Mutex::new(OutboxState {
            file: outbox_file,
            path: outbox_path,
        }));
        let ledger = Arc::new(Mutex::new(DeliveryLedger::open(&ledger_path)?));

        Ok(Self {
            config,
            outbox,
            ledger,
            transport,
        })
    }

    /// Spool a closed segment to the durable outbox.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardSinkError`] if the outbox cannot be written or the
    /// ledger cannot be updated.
    pub fn spool(&self, segment: ClosedSegment) -> Result<(), ForwardSinkError> {
        let mut outbox = self.outbox.lock().expect("outbox mutex not poisoned");
        let mut line = serde_json::to_string(&segment).map_err(|e| {
            ForwardSinkError::InvalidSegment(format!("failed to serialize segment: {e}"))
        })?;
        line.push('\n');
        outbox.file.write_all(line.as_bytes())?;
        outbox.file.sync_all()?;

        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };
        self.ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .mark_pending(id)?;
        Ok(())
    }

    /// The head of the newest segment this writer has **produced**, for
    /// `server_id`, read from the outbox.
    ///
    /// Mirrors [`SsdfSink::produced_head`](crate::sinks::ssdf::SsdfSink::produced_head):
    /// the outbox is append-only and never pruned (delivery is tracked in the
    /// separate ledger), so file order is production order and the last
    /// matching line is the newest segment, delivered or not. It is what a
    /// forward-only pipeline resumes from; `None` means nothing produced here.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardSinkError`] if the outbox cannot be read or decoded.
    pub fn produced_head(&self, server_id: &str) -> Result<Option<ProducedHead>, ForwardSinkError> {
        Ok(self
            .load_outbox()?
            .into_iter()
            .rfind(|segment| segment.server_id == server_id)
            .map(|segment| ProducedHead::new(segment.head_hash)))
    }

    /// Attempt delivery of every segment the ledger does not already show as
    /// delivered.
    ///
    /// A segment skipped because its backoff has not elapsed is still
    /// undelivered, so it is counted in `failed`; `degraded()` clears only once
    /// the backlog is actually delivered.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardSinkError`] if the outbox cannot be read.
    pub fn attempt_delivery(&self) -> Result<DeliveryReport, ForwardSinkError> {
        let mut segments = self.load_outbox()?;
        // Oldest first, matching the SSDF sink -- there is no ordering
        // requirement of SSDF's kind here (no server-side high-water mark to
        // stay monotonic against), but sending in produced order keeps a
        // collector's own view in the order the trail actually happened.
        segments.sort_by(|left, right| {
            (&left.server_id, &left.run_id, left.segment_seq).cmp(&(
                &right.server_id,
                &right.run_id,
                right.segment_seq,
            ))
        });

        let mut report = DeliveryReport::default();
        for segment in segments {
            let id = SegmentId {
                server_id: segment.server_id.clone(),
                run_id: segment.run_id.clone(),
                segment_seq: segment.segment_seq,
            };
            let status = self
                .ledger
                .lock()
                .expect("ledger mutex not poisoned")
                .status(&id)
                .cloned();
            if matches!(status, Some(DeliveryStatus::Delivered { .. })) {
                continue;
            }

            let attempts = match &status {
                Some(DeliveryStatus::Failed { attempts, .. }) => *attempts,
                _ => 0,
            };
            // Non-blocking backoff: a segment whose last failure has not aged
            // past its backoff window is left for the next pass rather than
            // sleeping here. This sink shares a thread with the SSDF drain
            // loop, so a `sleep` here would delay SSDF's own next delivery
            // attempt behind however many forward segments are backed off.
            if let Some(DeliveryStatus::Failed { failed_at, .. }) = &status {
                let due = chrono::DateTime::parse_from_rfc3339(failed_at)
                    .map(|failed_at| {
                        let backoff = chrono::Duration::from_std(self.compute_backoff(attempts))
                            .unwrap_or_else(|_| chrono::Duration::zero());
                        chrono::Utc::now().signed_duration_since(failed_at) >= backoff
                    })
                    // An unparsable timestamp cannot prove the backoff has
                    // elapsed, but must not wedge the segment forever either
                    // -- attempt it and let a fresh failure record a fresh,
                    // parsable timestamp.
                    .unwrap_or(true);
                if !due {
                    // Still failing, merely not due: count it so a pass that
                    // skips every backed-off segment does not read as healthy
                    // (forward-only `delivery_degraded` is derived from this).
                    report.failed += 1;
                    continue;
                }
            }

            match self.deliver_segment(&segment) {
                Ok(()) => {
                    let delivered_at = chrono::Utc::now().to_rfc3339();
                    self.ledger
                        .lock()
                        .expect("ledger mutex not poisoned")
                        .mark_delivered(id, delivered_at)?;
                    report.delivered += 1;
                }
                Err(error) => {
                    let failed_at = chrono::Utc::now().to_rfc3339();
                    self.ledger
                        .lock()
                        .expect("ledger mutex not poisoned")
                        .mark_failed(id, failed_at, error.to_string(), attempts + 1)?;
                    report.failed += 1;
                    // Unlike the SSDF sink, a failure here does not block later
                    // segments of the same run: this is a best-effort second
                    // copy, not the chain of record, so holding the rest of a
                    // run back for a collector outage would grow the outbox for
                    // no correctness benefit.
                }
            }
        }
        Ok(report)
    }

    fn compute_backoff(&self, attempts: u64) -> Duration {
        let base_ms = self.config.initial_backoff.as_millis() as u64;
        let max_ms = self.config.max_backoff.as_millis() as u64;
        let exp_ms = base_ms.saturating_mul(2u64.saturating_pow(attempts.saturating_sub(1) as u32));
        Duration::from_millis(std::cmp::min(exp_ms, max_ms))
    }

    /// Flush all pending deliveries on shutdown, best-effort.
    ///
    /// # Errors
    ///
    /// Returns [`ForwardSinkError`] only if the outbox cannot be read; a
    /// delivery failure is recorded in the ledger and does not fail this call.
    pub fn shutdown_flush(&self) -> Result<(), ForwardSinkError> {
        let _ = self.attempt_delivery()?;
        Ok(())
    }

    fn load_outbox(&self) -> Result<Vec<ClosedSegment>, ForwardSinkError> {
        let outbox = self.outbox.lock().expect("outbox mutex not poisoned");
        let file = File::open(&outbox.path)?;
        let reader = BufReader::new(file);
        let mut segments = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let segment: ClosedSegment = serde_json::from_str(&line).map_err(|e| {
                ForwardSinkError::InvalidSegment(format!("failed to parse segment: {e}"))
            })?;
            segments.push(segment);
        }
        Ok(segments)
    }

    fn deliver_segment(&self, segment: &ClosedSegment) -> Result<(), ForwardSinkError> {
        let body = serde_json::to_vec(segment).map_err(|e| {
            ForwardSinkError::InvalidSegment(format!("failed to serialize segment: {e}"))
        })?;

        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "X-Mecmcp-Dedup-Token".to_string(),
                dedup_token(&segment.server_id, &segment.run_id, segment.segment_seq),
            ),
        ];
        if let Some(token) = &self.config.bearer_token {
            headers.push((
                "Authorization".to_string(),
                format!("Bearer {}", token.expose()),
            ));
        }

        let request = HttpRequest {
            url: self.config.endpoint.clone(),
            method: "POST".to_string(),
            headers,
            body,
        };
        self.transport.send(&request)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::evidence::{
        ChainSegment, EvidenceRecord, GENESIS_PREV_HASH, ProposalRecord, append, close,
    };
    use crate::sinks::ssdf::HttpRequest as SsdfHttpRequest;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    struct MockTransport {
        requests: Arc<StdMutex<Vec<SsdfHttpRequest>>>,
        should_fail: bool,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                requests: Arc::new(StdMutex::new(Vec::new())),
                should_fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                requests: Arc::new(StdMutex::new(Vec::new())),
                should_fail: true,
            }
        }
        fn requests(&self) -> Vec<SsdfHttpRequest> {
            self.requests
                .lock()
                .expect("mock mutex not poisoned")
                .clone()
        }
    }

    impl HttpTransport for MockTransport {
        fn send(&self, request: &HttpRequest) -> Result<String, ForwardSinkError> {
            if self.should_fail {
                return Err(ForwardSinkError::Http("mock transport failure".to_string()));
            }
            self.requests
                .lock()
                .expect("mock mutex not poisoned")
                .push(request.clone());
            Ok(String::new())
        }
    }

    fn make_test_config(dir: &TempDir, endpoint: &str) -> ForwardSinkConfig {
        ForwardSinkConfig {
            endpoint: endpoint.to_string(),
            bearer_token: Some(OutboundSecret::new_unchecked("test-token".to_string())),
            outbox_path: dir.path().join("forward-outbox.jsonl"),
            ledger_path: dir.path().join("forward-ledger.jsonl"),
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_secs(1),
        }
    }

    fn make_test_segment(seq: u64) -> ClosedSegment {
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "server_test".to_string(),
            seq,
            GENESIS_PREV_HASH.to_string(),
        );
        append(
            &mut seg,
            EvidenceRecord::Proposal(ProposalRecord {
                request_id: format!("req_{seq}"),
                changeset_id: "cs_test".to_string(),
                device_id: "dev_test".to_string(),
                principal: "agent:test".to_string(),
                diff_hash: "sha256:abcd1234".to_string(),
                timestamp: "2026-08-09T12:00:00Z".to_string(),
                run_id: String::new(),
                server_id: String::new(),
                segment_seq: 0,
                prev_hash: String::new(),
                metadata: None,
            }),
        )
        .unwrap();
        close(seg).unwrap()
    }

    #[test]
    fn debug_never_prints_the_bearer_token() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "https://collector.example/audit");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("test-token"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn spool_writes_to_outbox_and_marks_pending() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        let transport = Arc::new(MockTransport::new());
        let sink = ForwardSink::new_with_transport(config.clone(), transport).unwrap();

        let segment = make_test_segment(0);
        sink.spool(segment.clone()).unwrap();

        let outbox_content = std::fs::read_to_string(&config.outbox_path).unwrap();
        assert!(outbox_content.contains(&segment.run_id));
    }

    #[test]
    fn attempt_delivery_posts_json_with_bearer_and_dedup_token() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        let transport = Arc::new(MockTransport::new());
        let sink = ForwardSink::new_with_transport(config.clone(), transport.clone()).unwrap();

        let segment = make_test_segment(0);
        sink.spool(segment.clone()).unwrap();
        let report = sink.attempt_delivery().unwrap();
        assert_eq!(report.delivered, 1);
        assert_eq!(report.failed, 0);

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, "http://127.0.0.1:9/audit");
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v == "Bearer test-token")
        );
        assert!(
            requests[0]
                .headers
                .iter()
                .any(|(k, _)| k == "X-Mecmcp-Dedup-Token")
        );
        let body: ClosedSegment = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(body.head_hash, segment.head_hash);
        assert_eq!(body.prev_hash, segment.prev_hash);
    }

    #[test]
    fn a_delivered_segment_is_not_resent() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        let transport = Arc::new(MockTransport::new());
        let sink = ForwardSink::new_with_transport(config.clone(), transport.clone()).unwrap();

        sink.spool(make_test_segment(0)).unwrap();
        assert_eq!(sink.attempt_delivery().unwrap().delivered, 1);
        assert_eq!(sink.attempt_delivery().unwrap().delivered, 0);
        assert_eq!(
            transport.requests().len(),
            1,
            "must not resend a delivered segment"
        );
    }

    #[test]
    fn a_failed_delivery_stays_spooled_for_retry() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        let transport = Arc::new(MockTransport::failing());
        let sink = ForwardSink::new_with_transport(config, transport).unwrap();

        sink.spool(make_test_segment(0)).unwrap();
        let report = sink.attempt_delivery().unwrap();
        assert_eq!(report.delivered, 0);
        assert_eq!(report.failed, 1);
    }

    /// A pass that skips a still-failing segment (backoff not elapsed) must not
    /// report healthy: forward-only `delivery_degraded` is derived from it.
    #[test]
    fn a_segment_skipped_in_backoff_still_counts_as_failed() {
        let dir = TempDir::new().unwrap();
        let mut config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        config.initial_backoff = Duration::from_secs(3600);
        config.max_backoff = Duration::from_secs(3600);
        let sink =
            ForwardSink::new_with_transport(config, Arc::new(MockTransport::failing())).unwrap();
        sink.spool(make_test_segment(0)).unwrap();
        assert_eq!(sink.attempt_delivery().unwrap().failed, 1);

        let second = sink.attempt_delivery().unwrap();

        assert_eq!(second.delivered, 0);
        assert!(second.degraded(), "the backlog is still undelivered");
    }

    #[test]
    fn a_stalled_run_does_not_block_later_segments() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        // Unlike the SSDF sink, a failed delivery must not hold back later
        // segments of the same run: this is a best-effort second copy, not
        // the chain of record, so both segments must still be attempted in
        // the same pass even though delivery fails for both.
        let failing = Arc::new(MockTransport::failing());
        let sink = ForwardSink::new_with_transport(config, failing).unwrap();
        sink.spool(make_test_segment(0)).unwrap();
        sink.spool(make_test_segment(1)).unwrap();
        let report = sink.attempt_delivery().unwrap();
        assert_eq!(
            report.failed, 2,
            "both segments must be attempted, not just the first"
        );
    }

    #[test]
    fn backed_off_segments_are_skipped_without_blocking() {
        // Regression test for a review finding (MEC-459): attempt_delivery
        // used to sleep out each segment's backoff in-line, and this sink
        // shares a thread with the SSDF drain loop (drain_until_stopped), so
        // a large batch of backed-off segments delayed the next SSDF
        // delivery pass behind them. A long backoff (60s) makes any
        // remaining in-line sleep obvious: the second pass below must return
        // in well under that, proving segments not yet due are skipped
        // rather than waited out.
        let dir = TempDir::new().unwrap();
        let mut config = make_test_config(&dir, "http://127.0.0.1:9/audit");
        config.initial_backoff = Duration::from_secs(60);
        config.max_backoff = Duration::from_secs(60);
        let failing = Arc::new(MockTransport::failing());
        let sink = ForwardSink::new_with_transport(config, failing).unwrap();

        for seq in 0..10 {
            sink.spool(make_test_segment(seq)).unwrap();
        }

        let first = sink.attempt_delivery().unwrap();
        assert_eq!(first.failed, 10, "every segment gets a first attempt");

        let started = std::time::Instant::now();
        let second = sink.attempt_delivery().unwrap();
        let elapsed = started.elapsed();

        // Not re-attempted (the timing bound below), but still counted as
        // failed: the backlog is undelivered, so the pass must not look healthy.
        assert_eq!(second.delivered, 0);
        assert_eq!(second.failed, 10, "skipped segments are still failing");
        assert!(
            elapsed < Duration::from_secs(5),
            "a pass over segments still within their backoff window must not block: took {elapsed:?}"
        );
    }
}
