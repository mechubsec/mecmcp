//! A change moving through the coordinator must leave an evidence trail.
//!
//! The recorder and the sink both existed before this; nothing connected them
//! to a real change, so `ssdf.audit` held zero `evidence` rows and would have
//! kept holding zero however the sink was configured (mecmcp#292).

#![allow(clippy::unwrap_used)]

use mecmcp_audit::evidence::EvidenceRecord;
use mecmcp_audit::recorder::{EvidenceRecorder, RecorderConfig};
use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use std::sync::Arc;
use std::time::Duration;

fn coordinator_with_evidence() -> (ChangesetCoordinator, Arc<EvidenceRecorder>) {
    let recorder = Arc::new(EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        resume_from: None,
        records_per_segment: 64,
    }));
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap()
    .with_evidence(Arc::clone(&recorder));
    (coordinator, recorder)
}

fn fingerprint() -> String {
    format!("sha256:{}", "a".repeat(64))
}

/// Creating a change set is the proposal.
#[tokio::test]
async fn creating_a_change_set_records_a_proposal() {
    let (coordinator, recorder) = coordinator_with_evidence();

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
            None,
        )
        .await
        .unwrap();

    let closed = recorder.close_current().expect("a proposal was recorded");
    let EvidenceRecord::Proposal(proposal) = &closed.records()[0] else {
        panic!("expected a proposal");
    };
    assert_eq!(proposal.changeset_id, output.change_set_id);
    assert_eq!(proposal.device_id, "vsrx-ci");
    assert_eq!(proposal.principal, "agent:planner");
    assert_eq!(
        proposal.diff_hash, output.digest,
        "the proposal must bind the plan it proposed"
    );
}

/// Approving records the decision and the approver — the second person, which
/// is the whole point of two-person control.
#[tokio::test]
async fn approving_records_the_approver_and_the_decision() {
    let (coordinator, recorder) = coordinator_with_evidence();
    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
            None,
        )
        .await
        .unwrap();

    coordinator
        .approve_change_set(
            output.change_set_id.clone(),
            "vsrx-ci".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "user:alice".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            output.digest.clone(),
        )
        .await
        .unwrap();

    let closed = recorder.close_current().unwrap();
    let EvidenceRecord::Approval(approval) = &closed.records()[1] else {
        panic!("expected an approval");
    };
    assert_eq!(approval.approver, "user:alice");
    assert_eq!(approval.decision, "approved");
    assert_eq!(
        approval.device_id, "vsrx-ci",
        "the approval must name the device it approved, carried from the proposal"
    );
    assert_eq!(approval.diff_hash, output.digest);
}

/// A coordinator without a recorder must behave exactly as before: evidence is
/// a deployment choice, not a requirement.
#[tokio::test]
async fn a_coordinator_without_evidence_still_works() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
            None,
        )
        .await;

    assert!(output.is_ok(), "evidence must be optional");
}

/// A commit whose intent record cannot be persisted must not reach the device.
///
/// This is the fail-closed half of #292's "a sink that loses records is worse
/// than no sink, because the gap is invisible". `apply_intent` is written
/// *before* the device is touched precisely so a crash mid-commit still shows
/// the attempt; if that write cannot be made durable and the commit proceeds
/// anyway, the result is the one state the chain exists to rule out — a device
/// changed with no evidence that anyone tried.
mod refused_spool {
    use super::*;
    use async_trait::async_trait;
    use mecmcp_audit::Attribution;
    use mecmcp_audit::recorder::SpoolError;
    use mecmcp_changeset::{
        CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
    };
    use serde::{Deserialize, Serialize};
    pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_util::sync::CancellationToken;

    pub(super) const POLICY: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    pub(super) const ENDPOINT: &str = "https://device.example.com";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub(super) struct Action {
        pub(super) name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(super) struct Staged;

    #[derive(Debug, thiserror::Error)]
    #[error("device error")]
    pub(super) struct DeviceError;

    /// Counts commits so a test can assert none was sent, and stands in for a
    /// device that answers in a particular way.
    #[derive(Default)]
    pub(super) struct CountingTransaction {
        pub(super) commits: AtomicUsize,
        /// What the device reports back.
        pub(super) succeeded: bool,
        pub(super) details: Option<String>,
        /// When set, `commit` makes this directory unwritable before returning.
        ///
        /// The store must fail *after* the device has answered and nowhere else.
        /// Breaking it up front is no good: `commit_operation` persists the
        /// `Committing` transition first, so the failure would land before the
        /// device was touched and the post-answer path would never run. Doing it
        /// from inside `commit` puts the failure exactly in the window under
        /// test, deterministically.
        pub(super) break_store_on_commit: Option<std::path::PathBuf>,
    }

    #[async_trait]
    impl DeviceTransaction for CountingTransaction {
        type Action = Action;
        type Staged = Staged;
        type Diff = String;
        type Validation = String;
        type Error = DeviceError;

        async fn fingerprint(&self) -> Result<String, Self::Error> {
            Ok(format!("sha256:{}", "1".repeat(64)))
        }

        async fn stage(&self, _actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
            Ok(Staged)
        }

        async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
            Ok(String::new())
        }

        async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
            Ok(String::new())
        }

        async fn commit(
            &self,
            _staged: &Self::Staged,
            _attribution: &Attribution,
            _options: &CommitOptions,
        ) -> Result<CommitOutcome, Self::Error> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            if let Some(directory) = &self.break_store_on_commit {
                let mut permissions = std::fs::metadata(directory).unwrap().permissions();
                std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o555);
                std::fs::set_permissions(directory, permissions).unwrap();
            }
            Ok(CommitOutcome::Reconciled {
                succeeded: self.succeeded,
                job_id: None,
                details: self.details.clone(),
            })
        }

        async fn confirm_commit(
            &self,
            _operation_id: &str,
            _attribution: &Attribution,
        ) -> Result<CommitOutcome, Self::Error> {
            Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: None,
            })
        }

        async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
            Ok(RollbackOutcome {
                succeeded: true,
                details: None,
            })
        }
    }

    #[tokio::test]
    async fn a_commit_is_refused_when_its_intent_cannot_be_persisted() {
        let recorder = Arc::new(
            EvidenceRecorder::new(RecorderConfig {
                server_id: "mecmcp-test".to_string(),
                run_id: "run-001".to_string(),
                resume_from: None,
                records_per_segment: 64,
            })
            .with_spool(|_| Err(SpoolError::new("outbox unwritable"))),
        );
        let coordinator = ChangesetCoordinator::load(
            None,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap()
        .with_evidence(Arc::clone(&recorder));

        let transaction = CountingTransaction::default();
        let device_fingerprint = transaction.fingerprint().await.unwrap();
        let cancellation = CancellationToken::new();
        let staged = coordinator
            .stage_operation(
                "device-a",
                "owner-a",
                &device_fingerprint,
                ENDPOINT,
                &transaction,
                &[Action {
                    name: "one".to_owned(),
                }],
                "set",
                None,
                POLICY,
                None,
                &cancellation,
            )
            .await
            .unwrap();

        coordinator
            .validate_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                &transaction,
                &staged.staged,
                &cancellation,
            )
            .await
            .unwrap();

        let error = coordinator
            .commit_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                POLICY,
                &transaction,
                &staged.staged,
                &Attribution::stdio(),
                &CommitOptions::default(),
                &cancellation,
            )
            .await
            .expect_err("a commit with no durable intent record must be refused");

        assert_eq!(
            transaction.commits.load(Ordering::SeqCst),
            0,
            "no commit RPC may be sent when the intent record was not persisted: {error:?}"
        );
    }
}

/// A waived approval must appear in the trail as a waiver.
///
/// This is not an edge case in this fleet: every prod server runs `--lab-mode`,
/// so `waive_approval` is the path *every* real change takes. Emitting nothing
/// here leaves the external trail jumping straight from proposal to apply
/// intent, which is indistinguishable from an approval gate that was bypassed
/// rather than deliberately waived.
#[tokio::test]
async fn a_lab_mode_waiver_is_recorded_as_a_waiver() {
    let recorder = Arc::new(EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        resume_from: None,
        records_per_segment: 64,
    }));
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        true,
    )
    .unwrap()
    .with_evidence(Arc::clone(&recorder));

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
            None,
        )
        .await
        .unwrap();

    coordinator
        .waive_approval(
            output.change_set_id.clone(),
            "vsrx-ci".to_string(),
            "agent:planner".to_string(),
            output.digest.clone(),
        )
        .await
        .unwrap();

    let closed = recorder.close_current().expect("records were written");
    let EvidenceRecord::Approval(approval) = &closed.records()[1] else {
        panic!(
            "the waiver must follow the proposal: {:?}",
            closed.records()
        );
    };
    assert_eq!(
        approval.decision, "approved",
        "the waiver did authorize the apply, and the contract's decision column \
         admits only approved/rejected/empty"
    );
    assert_eq!(
        approval.approver, "",
        "no second person approved, and naming one would forge the very fact \
         two-person control exists to establish"
    );
    assert_eq!(
        approval.metadata.as_ref().and_then(|m| m.get("waived")),
        Some(&serde_json::json!("lab_mode")),
        "the trail must say the gate was waived, and why: {:?}",
        approval.metadata
    );
    let metadata = approval.metadata.as_ref().expect("waiver metadata");
    assert_eq!(
        metadata.get("ticket"),
        None,
        "a lab-mode waiver has no ticket, and a null one is not the same as no \
         key: a presence-based audit query counts it as ticketed. {metadata:?}"
    );
    assert_eq!(
        metadata.get("expires_at_unix"),
        None,
        "likewise the time box — an unbounded waiver must not look bounded-then-\
         emptied. {metadata:?}"
    );
}

/// Commit-path evidence: what the receipt says, and whether it is written at all.
#[cfg(unix)]
mod receipts {
    use super::refused_spool::*;
    use super::*;
    use mecmcp_audit::Attribution;
    use mecmcp_audit::evidence::EvidenceRecord;
    use mecmcp_changeset::{CommitOptions, DeviceTransaction};
    use tokio_util::sync::CancellationToken;

    /// Drive one change through stage, validate and commit, and hand back
    /// whatever evidence the coordinator produced.
    async fn commit_once(
        transaction: &CountingTransaction,
        store: Option<&std::path::Path>,
    ) -> (Arc<EvidenceRecorder>, Result<(), String>) {
        let recorder = Arc::new(EvidenceRecorder::new(RecorderConfig {
            server_id: "mecmcp-test".to_string(),
            run_id: "run-001".to_string(),
            resume_from: None,
            records_per_segment: 64,
        }));
        let coordinator = ChangesetCoordinator::load(
            store,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap()
        .with_evidence(Arc::clone(&recorder));

        let cancellation = CancellationToken::new();
        let fingerprint = transaction.fingerprint().await.unwrap();
        let staged = coordinator
            .stage_operation(
                "device-a",
                "owner-a",
                &fingerprint,
                ENDPOINT,
                transaction,
                &[Action {
                    name: "one".to_owned(),
                }],
                "set",
                None,
                POLICY,
                None,
                &cancellation,
            )
            .await
            .unwrap();
        coordinator
            .validate_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                transaction,
                &staged.staged,
                &cancellation,
            )
            .await
            .unwrap();

        let outcome = coordinator
            .commit_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                POLICY,
                transaction,
                &staged.staged,
                &Attribution::stdio(),
                &CommitOptions::default(),
                &cancellation,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string());

        (recorder, outcome)
    }

    fn receipt_of(recorder: &EvidenceRecorder) -> mecmcp_audit::evidence::ResultReceipt {
        let closed = recorder.close_current().expect("records were written");
        closed
            .records()
            .iter()
            .find_map(|record| match record {
                EvidenceRecord::ResultReceipt(receipt) => Some(receipt.clone()),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!(
                    "no receipt for a device that answered: {:?}",
                    closed.records()
                )
            })
    }

    /// A successful commit must not have its details filed as an error.
    ///
    /// `Reconciled { succeeded: true, details: Some(..) }` is the ordinary shape
    /// of a commit that carried a warning or a job note. Passing those details
    /// as the receipt's `error` populates the SSDF error column on a successful
    /// outcome, so anyone filtering the trail for failures gets every
    /// warning-bearing success back with them.
    #[tokio::test]
    async fn a_successful_commit_files_no_error() {
        let transaction = CountingTransaction {
            succeeded: true,
            details: Some("warning: mtu lowered".to_owned()),
            ..Default::default()
        };

        let (recorder, outcome) = commit_once(&transaction, None).await;
        outcome.expect("the commit succeeded");

        let receipt = receipt_of(&recorder);
        assert_eq!(receipt.outcome, "success");
        assert_eq!(
            receipt.error, None,
            "a successful commit has no error, whatever else it had to say"
        );
    }

    /// A failure still files its details as the error, which is the whole point
    /// of carrying them.
    #[tokio::test]
    async fn a_failed_commit_files_its_details_as_the_error() {
        let transaction = CountingTransaction {
            succeeded: false,
            details: Some("commit rejected: syntax".to_owned()),
            ..Default::default()
        };

        let (recorder, outcome) = commit_once(&transaction, None).await;
        outcome.expect("a refused commit is still a completed call");

        let receipt = receipt_of(&recorder);
        assert_eq!(receipt.outcome, "failure");
        assert_eq!(receipt.error.as_deref(), Some("commit rejected: syntax"));
    }

    /// The device answered, so the receipt must be written even when the local
    /// record cannot be.
    ///
    /// `self.update(record).await?` sits between the device answer and the
    /// receipt. When it fails — a full disk, a permission change — the `?`
    /// returns and the chain ends at apply intent for a commit that *did* reach
    /// the device. That is the worst gap available: evidence of an attempt with
    /// no outcome, at exactly the moment device state and local state have
    /// diverged and someone has to go and look.
    #[tokio::test]
    async fn a_device_answer_is_recorded_even_when_local_state_cannot_be_written() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("operations.json");
        let transaction = CountingTransaction {
            succeeded: true,
            details: None,
            break_store_on_commit: Some(directory.path().to_path_buf()),
            ..Default::default()
        };

        let (recorder, outcome) = commit_once(&transaction, Some(&store)).await;

        // Restore write access first, so the tempdir can clean itself up
        // whichever way the assertions below go.
        let mut permissions = std::fs::metadata(directory.path()).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(directory.path(), permissions).unwrap();

        assert!(
            outcome.is_err(),
            "the caller must still learn that local state was not written"
        );
        assert_eq!(
            transaction.commits.load(Ordering::SeqCst),
            1,
            "the device was touched, which is what makes the receipt mandatory"
        );
        let receipt = receipt_of(&recorder);
        assert_eq!(
            receipt.outcome, "success",
            "the receipt describes what the device did, not what the local store managed"
        );
    }
}

/// An operator waiver's time box and ticket must reach the trail.
///
/// These are the fields that make a bounded, ticketed exception distinguishable
/// from an open-ended one. Emitting only the kind and reason loses exactly what
/// an auditor needs to follow the exception back to what authorised it and to
/// see when it lapses.
#[tokio::test]
async fn an_operator_waiver_records_its_time_box_and_ticket() {
    use mecmcp_changeset::WaiverKind;

    let recorder = Arc::new(EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        resume_from: None,
        records_per_segment: 64,
    }));
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap()
    .with_evidence(Arc::clone(&recorder));

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
            None,
        )
        .await
        .unwrap();

    coordinator
        .waive_approval_operator(
            output.change_set_id.clone(),
            "vsrx-ci".to_string(),
            "agent:planner".to_string(),
            output.digest.clone(),
            WaiverKind::OperatorTool,
            "incident bridge".to_string(),
            Some(4_102_444_800),
            Some("CHG-1234".to_string()),
        )
        .await
        .unwrap();

    let closed = recorder.close_current().expect("records were written");
    let EvidenceRecord::Approval(approval) = &closed.records()[1] else {
        panic!(
            "the waiver must follow the proposal: {:?}",
            closed.records()
        );
    };
    let metadata = approval.metadata.as_ref().expect("waiver metadata");
    assert_eq!(
        metadata.get("waived"),
        Some(&serde_json::json!("operator_tool"))
    );
    assert_eq!(
        metadata.get("reason"),
        Some(&serde_json::json!("incident bridge"))
    );
    assert_eq!(
        metadata.get("ticket"),
        Some(&serde_json::json!("CHG-1234")),
        "the change-control reference is how the exception is traced back"
    );
    assert_eq!(
        metadata.get("expires_at_unix"),
        Some(&serde_json::json!(4_102_444_800u64)),
        "an exception with no visible time box reads as an open-ended one"
    );
}
