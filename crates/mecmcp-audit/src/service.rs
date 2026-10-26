//! The part that turns the evidence sink from a spool into a pipeline.
//!
//! [`SsdfSink`] can spool a segment durably and deliver it, and
//! [`EvidenceRecorder`] can produce segments — but nothing called
//! `attempt_delivery` outside the tests, so a deployed server would have
//! written evidence to disk forever and shipped none of it. From inside the
//! process that failure is indistinguishable from success: every record is
//! fsynced, every call returns `Ok`, and the outbox simply grows.
//!
//! This module owns the three things that make it a pipeline: the startup
//! sequence, a background drain, and a flush at shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::recorder::{EvidenceRecorder, RecorderConfig, resume_head};
use crate::signing::load_signing_key;
use crate::sinks::forward::{ForwardSink, ForwardSinkConfig};
use crate::sinks::ssdf::{HttpTransport, SsdfSink, SsdfSinkConfig, SsdfSinkError};
use std::path::PathBuf;

/// How a server configures its evidence pipeline.
#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    /// Identifies this writer's chain. **One process per `server_id`, one run
    /// at a time**: two containers sharing one fork the chain, and a fork
    /// verifies as two valid chains rather than as an error.
    pub server_id: String,
    /// Identifies this process lifetime within the writer's chain.
    pub run_id: String,
    /// Records per segment before one is closed and spooled.
    pub records_per_segment: usize,
    /// How often the drain runs. Delivery is also forced by `apply_intent` and
    /// by shutdown, so this only bounds how long an ordinary record waits.
    pub delivery_interval: Duration,
    /// Where the segments go.
    pub sink: SsdfSinkConfig,
    /// Path to an Ed25519 signing key (see [`crate::signing::load_signing_key`]
    /// for the file format and permission requirement).
    ///
    /// `None` means every segment this pipeline produces closes unsigned --
    /// a deployment that has not provisioned a key yet, not an error. When
    /// present, the key is loaded once at startup and every segment is
    /// signed automatically as it closes (MEC-457); there is no separate
    /// step to remember.
    pub signing_key_path: Option<PathBuf>,
    /// A second, best-effort destination for the same closed segments --
    /// a SIEM, a collector, an object-lock bucket -- beyond SSDF.
    ///
    /// `None` (the default) is the pipeline exactly as it existed before this
    /// field was added: SSDF only, no second sink built, no extra thread work.
    /// Its failures never affect [`EvidenceService::shutdown`]'s result or
    /// [`EvidenceService::delivery_degraded`], which both continue to describe
    /// the SSDF sink alone -- see [`crate::sinks::forward`] for why a second,
    /// weaker-guarantee sink is safe to add here without touching the chain of
    /// record.
    pub forward_sink: Option<ForwardSinkConfig>,
}

/// Configuration for a **forward-only** evidence pipeline: the same hash-chained
/// segments as [`EvidenceConfig`], shipped to a [`ForwardSink`] and nowhere else
/// (mecmcp#378, option 2) -- for operators without SSDF who still want the chain
/// off-host.
///
/// `server_id` keys the chain exactly as in [`EvidenceConfig`]; the same
/// one-process-per-`server_id` rule applies.
///
/// Unlike the SSDF+forward arrangement, the forward spool is the *only* durable
/// record here, so the recorder is fail-closed on it: a spool error refuses the
/// operation rather than leaving no trace.
#[derive(Debug, Clone)]
pub struct ForwardOnlyConfig {
    /// Identifies this writer's chain; see [`EvidenceConfig::server_id`].
    pub server_id: String,
    /// Identifies this process lifetime within the writer's chain.
    pub run_id: String,
    /// Records per segment before one is closed and spooled.
    pub records_per_segment: usize,
    /// How often the drain runs.
    pub delivery_interval: Duration,
    /// The one destination.
    pub forward: ForwardSinkConfig,
    /// Ed25519 signing key; see [`EvidenceConfig::signing_key_path`].
    pub signing_key_path: Option<PathBuf>,
}

/// Either shape of evidence pipeline, so one call path can start both.
///
/// `#[non_exhaustive]` so a further destination mix can be added without
/// breaking a consumer's `match`.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // built once at startup
pub enum EvidencePipelineConfig {
    /// SSDF as the chain of record, optionally with a best-effort forward copy.
    Ssdf(EvidenceConfig),
    /// Forward sink only, fail-closed on its spool.
    ForwardOnly(ForwardOnlyConfig),
}

/// The settings both pipeline shapes share.
struct Common {
    server_id: String,
    run_id: String,
    records_per_segment: usize,
    delivery_interval: Duration,
    signing_key_path: Option<PathBuf>,
}

/// A running evidence pipeline: recorder, sink, and the drain between them.
pub struct EvidenceService {
    recorder: Arc<EvidenceRecorder>,
    /// `None` in forward-only mode, where `forward` is the chain of record.
    sink: Option<Arc<SsdfSink>>,
    forward: Option<Arc<ForwardSink>>,
    stop: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
    /// Set when the drain hits an error, so shutdown can report that delivery
    /// was degraded rather than silently returning `Ok`.
    degraded: Arc<AtomicBool>,
}

impl EvidenceService {
    /// Start a pipeline against the real ClickHouse transport.
    ///
    /// # Errors
    ///
    /// Returns [`SsdfSinkError`] if the outbox or ledger cannot be opened, or
    /// if the startup reads fail. A failed read is deliberately fatal here: the
    /// alternative is starting a second root, which produces a fork that
    /// verifies as two valid chains and is therefore invisible downstream.
    pub fn start(config: EvidenceConfig) -> Result<Self, SsdfSinkError> {
        Self::start_with_transports(
            config,
            Arc::new(crate::sinks::ssdf::StdHttpTransport),
            Arc::new(crate::sinks::ssdf::StdHttpTransport),
        )
    }

    /// Start a pipeline where the SSDF sink and the forward sink share one
    /// transport, for tests.
    ///
    /// Production callers with a configured forward sink should prefer
    /// [`start_with_transports`](Self::start_with_transports): SSDF and the
    /// forward endpoint are typically different hosts with different trust
    /// anchors (SSDF's private CA vs. the forward collector's own -- see
    /// `mecmcp-runtime`'s `EvidenceArgs::forward_ca_file`), and a shared
    /// transport can only trust one of them.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub fn start_with_transport(
        config: EvidenceConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, SsdfSinkError> {
        Self::start_with_transports(config, Arc::clone(&transport), transport)
    }

    /// Start a pipeline with independent transports for the SSDF sink and the
    /// forward sink.
    ///
    /// Separate transports exist because the two destinations are typically
    /// different hosts with different trust anchors: SSDF's transport trusts
    /// SSDF's private CA (`--ssdf-audit-ca-file`), while a forward collector
    /// needs its own (`--audit-forward-ca-file`). Reusing SSDF's transport for
    /// the forward sink makes every `https://` forward delivery fail its TLS
    /// handshake unless the two happen to share a CA, with nothing but a
    /// `warn!` log to say why.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub fn start_with_transports(
        config: EvidenceConfig,
        ssdf_transport: Arc<dyn HttpTransport>,
        forward_transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, SsdfSinkError> {
        let stop = new_stop();
        let sink = Arc::new(SsdfSink::new_with_transport(
            config.sink.clone(),
            ssdf_transport,
            interruptible_sleep(&stop),
        )?);
        let forward = Self::build_forward(&config, forward_transport)?;
        let common = Common {
            server_id: config.server_id,
            run_id: config.run_id,
            records_per_segment: config.records_per_segment,
            delivery_interval: config.delivery_interval,
            signing_key_path: config.signing_key_path,
        };
        Self::from_sink(common, sink, forward, stop)
    }

    /// Start whichever pipeline `config` describes.
    ///
    /// `ssdf_transport` is unused in forward-only mode.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub fn start_pipeline(
        config: EvidencePipelineConfig,
        ssdf_transport: Arc<dyn HttpTransport>,
        forward_transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, SsdfSinkError> {
        match config {
            EvidencePipelineConfig::Ssdf(config) => {
                Self::start_with_transports(config, ssdf_transport, forward_transport)
            }
            EvidencePipelineConfig::ForwardOnly(config) => {
                Self::start_forward_only(config, forward_transport)
            }
        }
    }

    /// Start a forward-only pipeline (mecmcp#378, option 2).
    ///
    /// Resume mirrors the SSDF path with the remote read removed: deliver the
    /// outbox first, then continue from the newest head this writer *produced*
    /// ([`ForwardSink::produced_head`]). The forward outbox is append-only and
    /// never pruned, so that head survives delivery and restarts. A rebuilt host
    /// with an empty outbox starts a new root -- there is no remote to ask.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub fn start_forward_only(
        config: ForwardOnlyConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, SsdfSinkError> {
        let forward = Arc::new(ForwardSink::new_with_transport(config.forward, transport)?);
        let common = Common {
            server_id: config.server_id,
            run_id: config.run_id,
            records_per_segment: config.records_per_segment,
            delivery_interval: config.delivery_interval,
            signing_key_path: config.signing_key_path,
        };
        Self::assemble(common, None, Some(forward), new_stop())
    }

    fn build_forward(
        config: &EvidenceConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Option<Arc<ForwardSink>>, SsdfSinkError> {
        config
            .forward_sink
            .clone()
            .map(|forward_config| {
                ForwardSink::new_with_transport(forward_config, transport).map(Arc::new)
            })
            .transpose()
    }

    fn from_sink(
        common: Common,
        sink: Arc<SsdfSink>,
        forward: Option<Arc<ForwardSink>>,
        stop: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<Self, SsdfSinkError> {
        Self::assemble(common, Some(sink), forward, stop)
    }

    fn assemble(
        common: Common,
        sink: Option<Arc<SsdfSink>>,
        forward: Option<Arc<ForwardSink>>,
        stop: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<Self, SsdfSinkError> {
        // **Replay first, then read the tail.** A segment still in flight when
        // the last process died has not landed yet, so a tail read taken before
        // the replay returns that segment's predecessor; the next record
        // attaches there and the chain forks -- with nothing duplicated
        // anywhere in it, so `duplicate_row` never fires and the verifier
        // reports both branches clean. This ordering is the contract's
        // (ssdf#47) and it is the whole reason these two lines are not
        // interchangeable.
        let mut recorder_builder = match (&sink, &forward) {
            (Some(sink), forward) => {
                sink.attempt_delivery()?;
                let remote = sink.remote_head(&common.server_id)?;
                let local = sink.produced_head(&common.server_id)?;
                Self::recorder_for(&common, resume_head(remote, local))
                    .spooling_to_with_forward(Arc::clone(sink), forward.clone())
            }
            (None, Some(forward)) => {
                // Forward-only: no remote head to consult, and the same
                // replay-then-read order (harmless here, kept for parity).
                forward.attempt_delivery()?;
                let local = forward.produced_head(&common.server_id)?;
                Self::recorder_for(&common, resume_head(None, local))
                    .spooling_to_forward_only(Arc::clone(forward))
            }
            (None, None) => unreachable!("every constructor supplies a destination"),
        };
        if let Some(key_path) = &common.signing_key_path {
            let key = load_signing_key(key_path)?;
            recorder_builder = recorder_builder.with_signing_key(key);
        }
        let recorder = Arc::new(recorder_builder);

        let degraded = Arc::new(AtomicBool::new(false));
        let worker = {
            let sink = sink.clone();
            let forward = forward.clone();
            let stop = Arc::clone(&stop);
            let degraded = Arc::clone(&degraded);
            let interval = common.delivery_interval;
            std::thread::Builder::new()
                .name("evidence-delivery".to_owned())
                .spawn(move || {
                    drain_until_stopped(
                        sink.as_deref(),
                        forward.as_deref(),
                        &stop,
                        &degraded,
                        interval,
                    )
                })
                .map_err(SsdfSinkError::OutboxIo)?
        };

        Ok(Self {
            recorder,
            sink,
            forward,
            stop,
            worker: Some(worker),
            degraded,
        })
    }

    fn recorder_for(common: &Common, resume_from: Option<String>) -> EvidenceRecorder {
        EvidenceRecorder::new(RecorderConfig {
            server_id: common.server_id.clone(),
            run_id: common.run_id.clone(),
            resume_from,
            records_per_segment: common.records_per_segment,
        })
    }

    /// The recorder to hand to a coordinator via `with_evidence`.
    #[must_use]
    pub fn recorder(&self) -> Arc<EvidenceRecorder> {
        Arc::clone(&self.recorder)
    }

    /// Stop the drain and deliver whatever is still pending.
    ///
    /// # Errors
    ///
    /// Returns [`SsdfSinkError`] if the final flush fails. The records remain
    /// in the outbox and the next start replays them, so this is a report
    /// rather than a loss -- but it must be reported, because an operator
    /// stopping a server has no other signal that its trail is behind.
    pub fn shutdown(mut self) -> Result<(), SsdfSinkError> {
        self.signal_stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // Everything the recorder still holds, not just the open segment.
        // Only `apply_intent` and `result_receipt` flush, so a server whose
        // change sets are planned but not yet applied accumulates *finished*
        // segments in memory: `take_closed` is the difference between losing
        // them and shipping them. If one were dropped and a later segment did
        // get through, the chain would land with a missing predecessor -- a
        // hole that still verifies as a chain.
        let sink = self.sink.clone();
        let forward = self.forward.clone();
        let outcome = spool_everything(&self.recorder, move |segment| {
            let Some(sink) = &sink else {
                // Forward-only: the forward spool is the record, so its error
                // is the result.
                return forward
                    .as_ref()
                    .map_or(Ok(()), |forward| forward.spool(segment));
            };
            let result = sink.spool(segment.clone());
            if let Some(forward) = &forward
                && let Err(error) = forward.spool(segment)
            {
                // Best-effort, as everywhere else this sink appears: SSDF is
                // the chain of record, and `outcome` below reports on it
                // alone.
                tracing::warn!(
                    target: "audit",
                    %error,
                    "forward audit sink spool failed at shutdown; SSDF remains the durable record"
                );
            }
            result
        });
        let flushed = self
            .sink
            .as_ref()
            .map_or(Ok(()), |sink| sink.shutdown_flush());
        if let Some(forward) = &self.forward {
            if self.sink.is_none() {
                // Forward-only: the flush result is the pipeline's result.
                return outcome.and(forward.shutdown_flush());
            }
            // Best-effort: a forward-delivery failure at shutdown does not
            // change what this call reports, matching `delivery_degraded`
            // above, which also describes SSDF alone.
            if let Err(error) = forward.shutdown_flush() {
                tracing::warn!(target: "audit", %error, "forward audit sink flush failed at shutdown");
            }
        }
        outcome.and(flushed)
    }

    /// Whether the background drain has reported a delivery failure.
    #[must_use]
    pub fn delivery_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    fn signal_stop(&self) {
        let (lock, condvar) = &*self.stop;
        let mut stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        *stopped = true;
        condvar.notify_all();
    }
}

impl Drop for EvidenceService {
    fn drop(&mut self) {
        // A service dropped without `shutdown` still stops its thread. The
        // pending records stay in the outbox for the next run to replay, which
        // is why this does not try to flush: a Drop that performs network I/O
        // turns an ordinary teardown into an unpredictable stall.
        if self.worker.is_some() {
            self.signal_stop();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// Hand every segment the recorder still holds to `spool`, without stopping.
///
/// Two properties matter here and neither is obvious from the happy path.
///
/// **It must not stop at the first error.** `take_closed` *removes* the
/// segments from the recorder, so a `?` on the first one drops every segment
/// after it and skips the open one entirely -- they exist nowhere else, and the
/// service is being consumed. Losing the rest of the trail because one write
/// failed is the opposite of what a shutdown flush is for.
///
/// **A ledger error is not a spool failure.** `SsdfSink::spool` fsyncs the
/// segment and *then* marks it pending in a separate file; if only that second
/// step fails the record is already durable and `attempt_delivery` will still
/// find it, because delivery reads the outbox rather than the ledger. The drain
/// already classifies it that way in `spool_outcome`, and shutdown treating the
/// same condition as fatal would have made it lose records the running server
/// keeps.
///
/// The first genuine error is returned once everything has been attempted.
///
/// **On a genuine failure it keeps going, deliberately.** Stopping looks safer
/// -- it avoids putting segment N+1 in the outbox when N never landed -- but
/// the two outcomes are not equally visible, and visibility is the whole
/// product here:
///
/// - **Continue.** N is lost, N+1 lands. N+1's `prev_hash` names a row that is
///   not there, and `verify_audit.py`'s linkage check reports
///   `missing_predecessor`. Someone finds out.
/// - **Stop.** N through M are lost, and nothing after them is written. The
///   remote chain simply ends at N-1; the next run seeds from N-1 (the outbox
///   is what `produced_head` reads) and continues cleanly from there.
///   Verification is clean. Nobody ever finds out.
///
/// The second is the failure mode this entire subsystem exists to prevent --
/// SSDF's own contract calls a silently truncated chain worse than no chain,
/// because it still verifies. So a detectable hole beats a silent truncation,
/// and the error is returned either way.
pub(crate) fn spool_everything(
    recorder: &EvidenceRecorder,
    mut spool: impl FnMut(crate::evidence::ClosedSegment) -> Result<(), SsdfSinkError>,
) -> Result<(), SsdfSinkError> {
    let mut first_error = None;
    let mut attempt = |segment| match spool(segment) {
        Ok(()) => {}
        Err(SsdfSinkError::Ledger(error)) => {
            tracing::warn!(
                %error,
                "segment is durable in the outbox but the delivery ledger could not \
                 be updated; delivery is unaffected"
            );
        }
        Err(error) => {
            tracing::error!(%error, "an evidence segment could not be spooled at shutdown");
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    };

    for segment in recorder.take_closed() {
        attempt(segment);
    }
    if let Some(segment) = recorder.close_current() {
        attempt(segment);
    }

    first_error.map_or(Ok(()), Err)
}

/// A fresh stop signal.
fn new_stop() -> Arc<(Mutex<bool>, Condvar)> {
    Arc::new((Mutex::new(false), Condvar::new()))
}

/// A sleep for the sink's retry backoff that gives up once shutdown is asked
/// for.
///
/// The sink sleeps between attempts for a segment already marked failed. During
/// a ClickHouse outage that backoff grows to a minute, and a shutdown that
/// waits it out is a multi-minute stall -- at which point an operator reaches
/// for SIGKILL and loses exactly the open segment the final flush exists to
/// save. Returning early costs one wasted retry; the segment stays spooled
/// either way.
fn interruptible_sleep(stop: &Arc<(Mutex<bool>, Condvar)>) -> Arc<dyn Fn(Duration) + Send + Sync> {
    let stop = Arc::clone(stop);
    Arc::new(move |duration: Duration| {
        let (lock, condvar) = &*stop;
        let stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        if *stopped {
            return;
        }
        let _unused = condvar
            .wait_timeout(stopped, duration)
            .unwrap_or_else(|error| error.into_inner());
    })
}

/// Deliver on an interval until told to stop.
fn drain_until_stopped(
    sink: Option<&SsdfSink>,
    forward: Option<&ForwardSink>,
    stop: &(Mutex<bool>, Condvar),
    degraded: &AtomicBool,
    interval: Duration,
) {
    let (lock, condvar) = stop;
    loop {
        let mut stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        if !*stopped {
            // Condvar rather than sleep so shutdown does not wait out a long
            // interval -- with a 30s tick a plain sleep makes every restart
            // take up to 30s, and operators then reach for SIGKILL, which is
            // exactly when the flush matters.
            let (guard, _) = condvar
                .wait_timeout(stopped, interval)
                .unwrap_or_else(|error| error.into_inner());
            stopped = guard;
        }
        let should_stop = *stopped;
        drop(stopped);

        if let Some(sink) = sink {
            match sink.attempt_delivery() {
                // `Ok` describes the pass, not the segments: a pass in which every
                // segment was refused still returns `Ok`. Reading only the outer
                // result reports healthy while the outbox grows without limit.
                Ok(report) => {
                    degraded.store(report.degraded(), Ordering::SeqCst);
                    if report.degraded() {
                        tracing::warn!(
                            delivered = report.delivered,
                            failed = report.failed,
                            "some evidence segments were refused; they stay spooled for retry"
                        );
                    }
                }
                Err(error) => {
                    degraded.store(true, Ordering::SeqCst);
                    tracing::warn!(
                        %error,
                        "evidence delivery pass failed; segments stay spooled and will be retried"
                    );
                }
            }
        }

        // Best-effort, and deliberately not folded into `degraded`: that flag
        // describes the SSDF chain of record, which `delivery_degraded` is
        // documented to report alone. A struggling forward destination is
        // worth a log line, not a signal that changes how an operator reads
        // the pipeline's health.
        if let Some(forward) = forward {
            // Forward-only: this IS the chain of record, so it drives `degraded`.
            let primary = sink.is_none();
            match forward.attempt_delivery() {
                Ok(report) => {
                    if primary {
                        degraded.store(report.degraded(), Ordering::SeqCst);
                    }
                    if report.degraded() {
                        tracing::warn!(
                            delivered = report.delivered,
                            failed = report.failed,
                            "some segments were refused by the forward audit sink; they stay \
                             spooled there for retry"
                        );
                    }
                }
                Err(error) => {
                    if primary {
                        degraded.store(true, Ordering::SeqCst);
                    }
                    tracing::warn!(
                        %error,
                        "forward audit sink delivery pass failed; segments stay spooled there"
                    );
                }
            }
        }

        if should_stop {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::recorder::{EvidenceRecorder, RecorderConfig};

    fn recorder_holding(rolled: usize, plus_open: bool) -> EvidenceRecorder {
        let recorder = EvidenceRecorder::new(RecorderConfig {
            server_id: "srv".to_string(),
            run_id: "run".to_string(),
            resume_from: None,
            records_per_segment: 1,
        });
        for n in 0..rolled {
            recorder.proposal(
                &format!("r{n}"),
                &format!("c{n}"),
                "dev",
                "alice",
                "sha256:d",
            );
        }
        if plus_open {
            // records_per_segment is 1, so this rolls too; a segment stays open
            // only because the roll happens on the *next* append. Use a
            // recorder-visible fact instead: close_current() returns Some when
            // anything is unrolled.
        }
        recorder
    }

    /// A ledger-only failure must not stop the flush.
    ///
    /// `take_closed` removes the segments, so stopping at the first error drops
    /// every one after it -- and this particular error means the segment is
    /// already durable in the outbox, which is exactly why the running drain
    /// treats it as success.
    #[test]
    fn a_ledger_error_does_not_abandon_the_remaining_segments() {
        let recorder = recorder_holding(4, false);
        let mut seen = 0usize;

        let result = spool_everything(&recorder, |_segment| {
            seen += 1;
            Err(SsdfSinkError::Ledger(
                crate::sinks::delivery_ledger::LedgerError::InvalidEntry("full".to_owned()),
            ))
        });

        assert!(result.is_ok(), "a ledger-only error is not a spool failure");
        assert_eq!(
            seen, 4,
            "every held segment must be offered, not just the first"
        );
    }

    /// A failure part-way through must not silence the segments after it.
    ///
    /// Deliberate, and the opposite of what looks safe. Holding the successors
    /// back would leave the chain ending cleanly at the last good segment: the
    /// next run seeds from there and verification reports clean, so the loss is
    /// invisible. Letting them through leaves a `prev_hash` naming a row that
    /// is not present, which `verify_audit.py` reports as
    /// `missing_predecessor`. A detectable hole beats a silent truncation.
    #[test]
    fn a_failure_part_way_through_does_not_silence_the_rest() {
        let recorder = recorder_holding(4, false);
        let mut seen = 0usize;

        let result = spool_everything(&recorder, |_segment| {
            seen += 1;
            if seen == 2 {
                return Err(SsdfSinkError::Http("transient outbox failure".to_owned()));
            }
            Ok(())
        });

        assert!(result.is_err(), "the failure must still be reported");
        assert_eq!(
            seen, 4,
            "the segments after the failure were dropped, which ends the chain \
             cleanly at the last good one and hides the loss from verification"
        );
    }

    /// A real spool failure is reported, but only after everything is tried.
    #[test]
    fn a_real_failure_is_reported_after_every_segment_is_attempted() {
        let recorder = recorder_holding(3, false);
        let mut seen = 0usize;

        let result = spool_everything(&recorder, |_segment| {
            seen += 1;
            Err(SsdfSinkError::Http("disk gone".to_owned()))
        });

        assert!(result.is_err(), "a genuine failure must be reported");
        assert_eq!(
            seen, 3,
            "stopping early would drop segments that exist nowhere else"
        );
    }
}
