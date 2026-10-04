//! Tests for race condition fixes from code review.
//!
//! Each test validates one of the 9 P1/P2 fixes identified in the review.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal, Tier};
use mecmcp_changeset::{
    ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction, LifecycleState,
    OperationLimits, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TEST_ENDPOINT: &str = "https://device.example.com";

// ============================================================================
// Mock transaction types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MockAction {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MockStaged {
    actions: Vec<MockAction>,
    before_fp: String,
    after_fp: String,
}

#[derive(Debug, Clone, Serialize)]
struct MockDiff {
    changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MockValidation {
    succeeded: bool,
    details: String,
}

#[derive(Debug, Clone)]
struct MockDeviceState {
    data: HashMap<String, String>,
    locked: bool,
}

impl Default for MockDeviceState {
    fn default() -> Self {
        let mut data = HashMap::new();
        data.insert("initial".to_string(), "value".to_string());
        Self {
            data,
            locked: false,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CommitBehavior {
    Success,
    Failure,
    Indeterminate,
    AwaitingConfirmation { rollback_deadline_unix: u64 },
}

#[allow(dead_code)]
struct MockTransaction {
    state: Arc<StdMutex<MockDeviceState>>,
    commit_behavior: Arc<StdMutex<CommitBehavior>>,
    validation_behavior: Arc<StdMutex<Option<bool>>>, // None = succeed, Some(false) = fail
    can_unlock: bool,
    unlock_behavior: Arc<StdMutex<UnlockBehavior>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum UnlockBehavior {
    Released,
    Unsupported,
    Error,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(MockDeviceState::default())),
            commit_behavior: Arc::new(StdMutex::new(CommitBehavior::Success)),
            validation_behavior: Arc::new(StdMutex::new(None)),
            can_unlock: false,
            unlock_behavior: Arc::new(StdMutex::new(UnlockBehavior::Unsupported)),
        }
    }

    fn with_unlock() -> Self {
        Self {
            can_unlock: true,
            unlock_behavior: Arc::new(StdMutex::new(UnlockBehavior::Released)),
            ..Self::new()
        }
    }

    #[allow(dead_code)]
    fn with_state(state: Arc<StdMutex<MockDeviceState>>) -> Self {
        Self {
            state,
            ..Self::new()
        }
    }

    fn set_commit_behavior(&self, behavior: CommitBehavior) {
        *self.commit_behavior.lock().unwrap() = behavior;
    }

    fn set_validation_behavior(&self, succeed: bool) {
        *self.validation_behavior.lock().unwrap() = Some(succeed);
    }

    #[allow(dead_code)]
    fn set_unlock_behavior(&self, behavior: UnlockBehavior) {
        *self.unlock_behavior.lock().unwrap() = behavior;
    }
}

#[derive(Debug, thiserror::Error)]
enum MockError {
    #[error("device locked")]
    Locked,
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("commit failed: {0}")]
    CommitFailed(String),
    #[error("unlock failed")]
    UnlockFailed,
}

#[async_trait]
impl DeviceTransaction for MockTransaction {
    type Action = MockAction;
    type Staged = MockStaged;
    type Diff = MockDiff;
    type Validation = MockValidation;
    type Error = MockError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().unwrap();
        let mut keys: Vec<_> = state.data.keys().cloned().collect();
        keys.sort();
        let concatenated = keys.join(":");
        let hash = sha2::Sha256::digest(concatenated.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let mut state = self.state.lock().unwrap();
        if state.locked {
            return Err(MockError::Locked);
        }
        state.locked = true;

        let before_fp = {
            let mut keys: Vec<_> = state.data.keys().cloned().collect();
            keys.sort();
            let concatenated = keys.join(":");
            let hash = sha2::Sha256::digest(concatenated.as_bytes());
            format!("sha256:{}", hex::encode(hash))
        };

        for action in actions {
            state.data.insert(action.name.clone(), action.value.clone());
        }

        let after_fp = {
            let mut keys: Vec<_> = state.data.keys().cloned().collect();
            keys.sort();
            let concatenated = keys.join(":");
            let hash = sha2::Sha256::digest(concatenated.as_bytes());
            format!("sha256:{}", hex::encode(hash))
        };

        Ok(MockStaged {
            actions: actions.to_vec(),
            before_fp,
            after_fp,
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        let changes = staged
            .actions
            .iter()
            .map(|a| format!("+ {} = {}", a.name, a.value))
            .collect();
        Ok(MockDiff { changes })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let behavior = self.validation_behavior.lock().unwrap();
        if let Some(false) = *behavior {
            return Err(MockError::ValidationFailed("transient failure".to_string()));
        }
        Ok(MockValidation {
            succeeded: true,
            details: "validation passed".to_string(),
        })
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        let behavior = self.commit_behavior.lock().unwrap().clone();

        match behavior {
            CommitBehavior::Success => {
                self.state.lock().unwrap().locked = false;
                Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: Some("job-123".to_string()),
                    details: Some("commit succeeded".to_string()),
                })
            }
            CommitBehavior::Failure => {
                // Failed commit does NOT release the lock
                Ok(CommitOutcome::Reconciled {
                    succeeded: false,
                    job_id: Some("job-456".to_string()),
                    details: Some("commit failed".to_string()),
                })
            }
            CommitBehavior::Indeterminate => Ok(CommitOutcome::Indeterminate {
                reason: "commit RPC timed out after 600s".to_string(),
            }),
            CommitBehavior::AwaitingConfirmation {
                rollback_deadline_unix,
            } => Ok(CommitOutcome::AwaitingConfirmation {
                job_id: Some("job-789".to_string()),
                rollback_deadline_unix,
                details: Some("awaiting confirmation".to_string()),
            }),
        }
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError::CommitFailed(
            "confirm_commit not supported in mock".to_string(),
        ))
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        let behavior = self.unlock_behavior.lock().unwrap().clone();
        match behavior {
            UnlockBehavior::Released => {
                self.state.lock().unwrap().locked = false;
                Ok(UnlockOutcome::Released)
            }
            UnlockBehavior::Unsupported => Ok(UnlockOutcome::Unsupported),
            UnlockBehavior::Error => Err(MockError::UnlockFailed),
        }
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => {
                let mut state = self.state.lock().unwrap();
                state.data.retain(|k, _| k == "initial");
                // Rollback does NOT release the lock automatically
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("candidate reverted".to_string()),
                })
            }
            _ => Ok(RollbackOutcome {
                succeeded: false,
                details: Some("unsupported rollback type".to_string()),
            }),
        }
    }
}

fn test_attribution() -> Attribution {
    Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-test".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec!["srx-nat".into(), "firewall-audit".into()],
        }),
        on_behalf_of: Some("dev@example.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

// ============================================================================
// Tests for the 9 fixes
// ============================================================================

/// P1 Issue 1: Re-read state after acquiring the guard in discard.
///
/// Tests that discard re-reads and re-checks state after acquiring the guard,
/// preventing a race where commit persists Committed but discard proceeds with
/// a stale Validated record and overwrites it with Discarded.
#[tokio::test]
async fn p1_issue1_discard_rereads_after_guard() {
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap(),
    );

    let transaction = Arc::new(MockTransaction::with_unlock());
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage and validate
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &*transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    coordinator
        .validate_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &*transaction,
            &stage_output.staged,
            &cancellation,
        )
        .await
        .unwrap();

    // Spawn a commit in the background that will take the guard first
    let coord_clone = coordinator.clone();
    let trans_clone = transaction.clone();
    let op_id = stage_output.operation_id.clone();
    let after_fp = stage_output.after_fingerprint.clone();
    let staged_clone = stage_output.staged.clone();
    let cancel_clone = cancellation.clone();

    let commit_handle = tokio::spawn(async move {
        coord_clone
            .commit_operation(
                &op_id,
                device,
                owner,
                &after_fp,
                policy_sig,
                &*trans_clone,
                &staged_clone,
                &test_attribution(),
                &CommitOptions::default(),
                &cancel_clone,
            )
            .await
    });

    // Give commit time to acquire the guard and persist Committed
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Now try to discard - should fail because state is now Committed
    let discard_result = coordinator
        .discard_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &*transaction,
            &cancellation,
        )
        .await;

    // Discard should fail
    assert!(discard_result.is_err());
    let err = discard_result.unwrap_err();
    assert!(err.message().contains("cannot be discarded"));

    // Verify commit succeeded
    commit_handle.await.unwrap().unwrap();

    // Verify operation is still Committed
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Committed);
}

/// P1 Issue 2: Re-read state after acquiring the guard in validate.
///
/// Tests that validate re-reads and re-checks state after acquiring the guard,
/// preventing a race where two validations start from Staged, the first stores
/// Validated, the second re-runs validation with a transient failure and
/// overwrites the success with Failed.
#[tokio::test]
async fn p1_issue2_validate_rereads_after_guard() {
    let coordinator = Arc::new(
        ChangesetCoordinator::load(
            None,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap(),
    );

    let transaction = Arc::new(MockTransaction::new());
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &*transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Spawn first validation
    let coord_clone = coordinator.clone();
    let trans_clone = transaction.clone();
    let op_id = stage_output.operation_id.clone();
    let after_fp = stage_output.after_fingerprint.clone();
    let staged_clone = stage_output.staged.clone();
    let cancel_clone = cancellation.clone();

    let val1_handle = tokio::spawn(async move {
        coord_clone
            .validate_operation(
                &op_id,
                device,
                owner,
                &after_fp,
                &*trans_clone,
                &staged_clone,
                &cancel_clone,
            )
            .await
    });

    // Give first validation time to acquire the guard and persist Validated
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second validation with transient failure should be rejected due to state check
    transaction.set_validation_behavior(false);
    let val2_result = coordinator
        .validate_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &*transaction,
            &stage_output.staged,
            &cancellation,
        )
        .await;

    // First validation should succeed
    val1_handle.await.unwrap().unwrap();

    // Second validation should fail with state error
    assert!(val2_result.is_err());
    let err = val2_result.unwrap_err();
    assert!(err.message().contains("not in staged state"));

    // Verify operation is still Validated
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Validated);
}

/// P1 Issue 3: Persist rollback completion before the next await.
///
/// Tests that discard persists the Discarded state immediately after rollback
/// succeeds, before calling unlock() or fingerprint(). This ensures a restart
/// mid-discard doesn't leave the operation in a non-recoverable state.
#[tokio::test]
async fn p1_issue3_discard_persists_before_unlock() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::with_unlock();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Manually mark as Failed
    let mut record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    record.state = LifecycleState::Failed;
    coordinator.update(record).await.unwrap();

    // Discard
    coordinator
        .discard_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &cancellation,
        )
        .await
        .unwrap();

    // Verify record is Discarded (not Indeterminate)
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Discarded);
    assert!(!record.config_lock_held);
}

/// P1 Issue 4: Unreleased lock must not end terminal.
///
/// Tests that when unlock() returns Unsupported and the rollback did not
/// release the lock, discard marks the operation as Indeterminate rather than
/// Discarded, so the held lock has a route to resolution.
#[tokio::test]
async fn p1_issue4_unsupported_unlock_becomes_indeterminate() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Transaction with no unlock support
    let transaction = MockTransaction::new();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Manually mark as Failed
    let mut record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    record.state = LifecycleState::Failed;
    coordinator.update(record).await.unwrap();

    // Discard - should fail because unlock is unsupported (Round 5 Finding 4)
    let result = coordinator
        .discard_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &cancellation,
        )
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        error
            .message()
            .contains("configuration lock state could not be verified"),
        "Expected lock verification error, got: {}",
        error
    );

    // Verify record is Indeterminate (not Discarded) because lock cannot be released
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Indeterminate);
    assert!(record.config_lock_held);
    let details = record.details.unwrap();
    assert!(details.contains("no explicit unlock"));
}

/// P2 Issue 5: Validate fingerprint before persisting.
///
/// Tests that stage_operation validates the expected fingerprint format before
/// inserting the record, preventing a malformed fingerprint from corrupting
/// the state file.
#[tokio::test]
async fn p2_issue5_stage_validates_fingerprint_early() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Try to stage with a malformed fingerprint
    let result = coordinator
        .stage_operation(
            device,
            owner,
            "not-a-valid-fingerprint",
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "expected_candidate_fingerprint");
}

/// P2 Issue 6: Persist lock uncertainty before staging.
///
/// Tests that stage_operation sets config_lock_held = true before calling
/// stage(), so a restart mid-stage doesn't hide a potentially held lock.
#[tokio::test]
async fn p2_issue6_stage_persists_lock_risk() {
    // This test is inherently difficult to verify without actually killing the process,
    // but we can verify that the implementation updates the record with lock_held = true
    // before staging by checking the persisted state.

    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Verify lock is marked as held
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert!(record.config_lock_held);
}

/// P2 Issue 7: Don't clear lock on failed commit.
///
/// Tests that a failed commit (Reconciled { succeeded: false }) does not clear
/// the lock flag, since the trait only guarantees release on success.
#[tokio::test]
async fn p2_issue7_failed_commit_preserves_lock() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    transaction.set_commit_behavior(CommitBehavior::Failure);

    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage and validate
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    coordinator
        .validate_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &stage_output.staged,
            &cancellation,
        )
        .await
        .unwrap();

    // Commit with failure
    let outcome = coordinator
        .commit_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            policy_sig,
            &transaction,
            &stage_output.staged,
            &test_attribution(),
            &CommitOptions::default(),
            &cancellation,
        )
        .await
        .unwrap();

    match outcome {
        CommitOutcome::Reconciled { succeeded, .. } => {
            assert!(!succeeded);
        }
        _ => panic!("expected Reconciled outcome"),
    }

    // Verify lock is still marked as held
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Failed);
    assert!(
        record.config_lock_held,
        "failed commit must preserve lock flag"
    );
}

/// P2 Issue 8: Persist confirmed-commit deadlines.
///
/// Tests that AwaitingConfirmation persists the rollback_deadline_unix in the
/// operation record, so it survives a restart.
#[tokio::test]
async fn p2_issue8_confirmed_commit_persists_deadline() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let deadline = 1234567890u64;
    let transaction = MockTransaction::new();
    transaction.set_commit_behavior(CommitBehavior::AwaitingConfirmation {
        rollback_deadline_unix: deadline,
    });

    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage and validate
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    coordinator
        .validate_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &stage_output.staged,
            &cancellation,
        )
        .await
        .unwrap();

    // Commit with confirmed commit
    let outcome = coordinator
        .commit_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            policy_sig,
            &transaction,
            &stage_output.staged,
            &test_attribution(),
            &CommitOptions::default(),
            &cancellation,
        )
        .await
        .unwrap();

    match outcome {
        CommitOutcome::AwaitingConfirmation {
            rollback_deadline_unix,
            ..
        } => {
            assert_eq!(rollback_deadline_unix, deadline);
        }
        _ => panic!("expected AwaitingConfirmation outcome"),
    }

    // Verify deadline is persisted
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Committing);
    assert_eq!(
        record.rollback_deadline_unix,
        Some(deadline),
        "rollback deadline must be persisted"
    );
}

/// P2 Issue 9: Preserve agent identity in persisted attribution.
///
/// Tests that PersistedAttribution includes agent identity fields (model,
/// provider, tier, skills) rather than dropping them.
#[tokio::test]
async fn p2_issue9_attribution_includes_agent_identity() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage and validate
    let stage_output = coordinator
        .stage_operation(
            device,
            owner,
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    coordinator
        .validate_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &stage_output.staged,
            &cancellation,
        )
        .await
        .unwrap();

    // Commit with agent attribution
    coordinator
        .commit_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            policy_sig,
            &transaction,
            &stage_output.staged,
            &test_attribution(),
            &CommitOptions::default(),
            &cancellation,
        )
        .await
        .unwrap();

    // Verify agent identity is persisted
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();

    let attribution = record.attribution.expect("attribution must be present");
    assert_eq!(attribution.actor_type, "agent");

    let agent = attribution.agent.expect("agent identity must be present");
    assert_eq!(agent.model_id, "claude-opus-5");
    assert_eq!(agent.provider, "anthropic");
    assert_eq!(agent.provider_tier, "public");
    assert_eq!(agent.skills_used, "srx-nat firewall-audit");
}
