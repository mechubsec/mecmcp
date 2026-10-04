//! Task 8 tests: Single-operation lifecycle (stage/diff/validate/commit/discard).

#![allow(clippy::unwrap_used)]

/// A real https endpoint, because the coordinator now validates the scheme and
/// uses this as the device-guard key rather than deriving one from the name.
const TEST_ENDPOINT: &str = "https://device.example.com";

use async_trait::async_trait;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal, Tier};
use mecmcp_changeset::{
    ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction, LifecycleState,
    OperationLimits, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ============================================================================
// Mock transaction for testing
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

struct MockTransaction {
    state: Arc<Mutex<MockDeviceState>>,
    commit_behavior: Arc<Mutex<CommitBehavior>>,
    /// Whether this transaction reports an explicit unlock capability.
    can_unlock: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum CommitBehavior {
    Success,
    Failure,
    Indeterminate,
    Timeout,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDeviceState::default())),
            commit_behavior: Arc::new(Mutex::new(CommitBehavior::Success)),
            can_unlock: false,
        }
    }

    /// A transaction that really can release the configuration lock, as a
    /// vendor implementation with an explicit unlock RPC would.
    fn with_unlock() -> Self {
        Self {
            can_unlock: true,
            ..Self::new()
        }
    }

    fn with_state(state: Arc<Mutex<MockDeviceState>>) -> Self {
        Self {
            state,
            commit_behavior: Arc::new(Mutex::new(CommitBehavior::Success)),
            can_unlock: false,
        }
    }

    fn set_commit_behavior(&self, behavior: CommitBehavior) {
        *self.commit_behavior.lock().unwrap() = behavior;
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
enum MockError {
    #[error("device locked")]
    Locked,
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("commit failed: {0}")]
    CommitFailed(String),
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

        // Apply actions
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
                {
                    let mut state = self.state.lock().unwrap();
                    state.locked = false;
                }
                Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: Some("job-123".to_string()),
                    details: Some("commit succeeded".to_string()),
                })
            }
            CommitBehavior::Failure => {
                {
                    let mut state = self.state.lock().unwrap();
                    state.locked = false;
                }
                Ok(CommitOutcome::Reconciled {
                    succeeded: false,
                    job_id: Some("job-456".to_string()),
                    details: Some("commit failed".to_string()),
                })
            }
            CommitBehavior::Indeterminate => {
                // Lock state unknown - don't modify state
                Ok(CommitOutcome::Indeterminate {
                    reason: "commit RPC timed out after 600s".to_string(),
                })
            }
            CommitBehavior::Timeout => {
                // Simulate a timeout
                tokio::time::sleep(Duration::from_secs(100)).await;
                {
                    let mut state = self.state.lock().unwrap();
                    state.locked = false;
                }
                Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: None,
                    details: None,
                })
            }
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

    async fn unlock(&self) -> Result<mecmcp_changeset::UnlockOutcome, Self::Error> {
        if !self.can_unlock {
            return Ok(mecmcp_changeset::UnlockOutcome::Unsupported);
        }
        self.state.lock().unwrap().locked = false;
        Ok(mecmcp_changeset::UnlockOutcome::Released)
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => {
                let mut state = self.state.lock().unwrap();
                // Clear all non-initial data
                state.data.retain(|k, _| k == "initial");
                state.locked = false;
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
            skills_used: vec![],
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
// Tests
// ============================================================================

#[tokio::test]
async fn happy_path_stage_diff_validate_commit() {
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

    // Get initial fingerprint
    let initial_fp = transaction.fingerprint().await.unwrap();

    // 1. Stage an operation
    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];
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

    assert_eq!(stage_output.before_fingerprint, initial_fp);
    assert_ne!(stage_output.after_fingerprint, initial_fp);

    // Verify operation is in Staged state
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Staged);
    assert!(record.config_lock_held);

    // 2. Diff the operation
    let diff = coordinator
        .diff_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &stage_output.staged,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(diff.changes.len(), 1);
    assert!(diff.changes[0].contains("test-key"));

    // 3. Validate the operation
    let validation = coordinator
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

    assert!(validation.succeeded);

    // Verify operation is in Validated state
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Validated);

    // 4. Commit the operation
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
            assert!(succeeded);
        }
        _ => panic!("expected Reconciled outcome"),
    }

    // Verify operation is in Committed state
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Committed);
    assert!(!record.config_lock_held);
}

#[tokio::test]
async fn commit_with_indeterminate_outcome() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    transaction.set_commit_behavior(CommitBehavior::Indeterminate);

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

    // Commit with indeterminate outcome
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

    // Verify Indeterminate outcome
    match outcome {
        CommitOutcome::Indeterminate { reason } => {
            assert!(reason.contains("timed out") || reason.contains("timeout"));
        }
        _ => panic!("expected Indeterminate outcome, got {:?}", outcome),
    }

    // Verify operation is in Indeterminate state
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Indeterminate);
    assert!(record.details.is_some());
}

#[tokio::test]
async fn discard_after_failed_validation() {
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

    // Stage the operation
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

    // Manually mark as failed (simulating validation failure)
    let mut record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    record.state = LifecycleState::Failed;
    coordinator.update(record).await.unwrap();

    // Discard the operation - should fail because unlock is unsupported
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

    // Verify the discard failed (Round 5 Finding 4: unresolved discard must not return success)
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        error
            .message()
            .contains("configuration lock state could not be verified"),
        "Expected lock verification error, got: {}",
        error
    );

    // Verify operation is in Indeterminate state (P1 Issue 4 fix)
    // When unlock() returns Unsupported and the rollback did not release the lock,
    // the operation is marked Indeterminate rather than Discarded (terminal) so the
    // held lock has a route to resolution.
    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Indeterminate);

    // MockTransaction takes the default `unlock`, which reports Unsupported:
    // reverting a candidate does not release a configuration lock, and on PAN-OS
    // the commit lock outlives the revert. So the flag must be left standing and
    // the record must say why. Clearing it here is how a device ends up locked
    // against every later change while the state file reads clean.
    assert!(
        record.config_lock_held,
        "a transaction with no unlock support must not have its lock flag cleared"
    );
    let details = record.details.unwrap_or_default();
    assert!(
        details.contains("no explicit unlock"),
        "the record must explain why the lock state is unchanged, got: {details}"
    );
}

#[tokio::test]
async fn discard_clears_the_lock_when_the_transaction_can_unlock() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        std::time::Duration::from_secs(900),
        false,
    )
    .unwrap();
    let transaction = MockTransaction::with_unlock();
    let cancellation = CancellationToken::new();
    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:aaaa";

    let initial_fp = transaction.fingerprint().await.unwrap();
    let actions = vec![MockAction {
        name: "/config/test".to_string(),
        value: "test-value".to_string(),
    }];

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

    let record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Discarded);
    assert!(
        !record.config_lock_held,
        "an implementation that reports Released must clear the flag"
    );
}

#[tokio::test]
async fn diff_validate_commit_reject_fingerprint_mismatch() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let state = Arc::new(Mutex::new(MockDeviceState::default()));
    let transaction = MockTransaction::with_state(state.clone());

    let device = "test-device";
    let owner = "alice";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Stage the operation
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

    // Simulate another session changing the candidate
    {
        let mut s = state.lock().unwrap();
        s.data
            .insert("another-key".to_string(), "another-value".to_string());
    }

    // Diff should fail with fingerprint mismatch
    let diff_result = coordinator
        .diff_operation(
            &stage_output.operation_id,
            device,
            owner,
            &stage_output.after_fingerprint,
            &transaction,
            &stage_output.staged,
            &CancellationToken::new(),
        )
        .await;

    assert!(diff_result.is_err());
    let err = diff_result.unwrap_err();
    assert!(err.message().contains("candidate changed"));
}

#[tokio::test]
async fn operation_id_ownership_validation() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device";
    let owner1 = "alice";
    let owner2 = "bob";
    let policy_sig = "sha256:abcd1234";
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test-key".to_string(),
        value: "test-value".to_string(),
    }];

    // Alice stages an operation
    let stage_output = coordinator
        .stage_operation(
            device,
            owner1,
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

    // Bob tries to access Alice's operation
    let result = coordinator
        .record(&stage_output.operation_id, owner2, device)
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message().contains("not owned by this principal"));
}

#[tokio::test]
async fn discard_rejects_invalid_states() {
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

    // Manually mark as Committing
    let mut record = coordinator
        .record(&stage_output.operation_id, owner, device)
        .await
        .unwrap();
    record.state = LifecycleState::Committing;
    coordinator.update(record).await.unwrap();

    // Discard should fail
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
    let err = result.unwrap_err();
    assert!(err.message().contains("cannot be discarded"));
}

#[tokio::test]
async fn commit_rejects_non_validated_operation() {
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

    // Stage but don't validate
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

    // Try to commit without validating
    let result = coordinator
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
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message().contains("must validate successfully"));
}
