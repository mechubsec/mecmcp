//! Tests for the four review fixes from the fourth review round.
//!
//! Each test is designed to fail without the corresponding fix and pass with it.

#![allow(clippy::unwrap_used)]
#![allow(dead_code)]

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
use tokio::time::sleep;
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
enum RollbackBehavior {
    Success,
    Failure,
    Error,
    DelayThenSuccess(u64), // Delay in milliseconds
}

struct MockTransaction {
    state: Arc<StdMutex<MockDeviceState>>,
    rollback_behavior: Arc<StdMutex<RollbackBehavior>>,
    unlock_behavior: Arc<StdMutex<UnlockOutcome>>,
    stage_fails_after_lock: Arc<StdMutex<bool>>,
    diff_checks_state: Arc<StdMutex<bool>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(MockDeviceState::default())),
            rollback_behavior: Arc::new(StdMutex::new(RollbackBehavior::Success)),
            unlock_behavior: Arc::new(StdMutex::new(UnlockOutcome::Unsupported)),
            stage_fails_after_lock: Arc::new(StdMutex::new(false)),
            diff_checks_state: Arc::new(StdMutex::new(false)),
        }
    }

    fn with_rollback_error() -> Self {
        Self {
            rollback_behavior: Arc::new(StdMutex::new(RollbackBehavior::Error)),
            ..Self::new()
        }
    }

    fn with_delayed_rollback(delay_ms: u64) -> Self {
        Self {
            rollback_behavior: Arc::new(StdMutex::new(RollbackBehavior::DelayThenSuccess(
                delay_ms,
            ))),
            ..Self::new()
        }
    }

    fn with_stage_fails_after_lock() -> Self {
        Self {
            stage_fails_after_lock: Arc::new(StdMutex::new(true)),
            ..Self::new()
        }
    }

    fn with_diff_checks_state() -> Self {
        Self {
            diff_checks_state: Arc::new(StdMutex::new(true)),
            ..Self::new()
        }
    }

    fn fingerprint_from_state(&self) -> String {
        let state = self.state.lock().unwrap();
        let mut hasher = sha2::Sha256::new();
        for (k, v) in state.data.iter() {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    fn set_locked(&self, locked: bool) {
        let mut state = self.state.lock().unwrap();
        state.locked = locked;
    }

    fn is_locked(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.locked
    }

    fn commit_changes(&self) {
        let mut state = self.state.lock().unwrap();
        state.locked = false;
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mock transaction error: {0}")]
struct MockError(String);

#[async_trait]
impl DeviceTransaction for MockTransaction {
    type Action = MockAction;
    type Staged = MockStaged;
    type Diff = MockDiff;
    type Validation = MockValidation;
    type Error = MockError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.fingerprint_from_state())
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let before_fp = self.fingerprint_from_state();
        let mut state = self.state.lock().unwrap();
        state.locked = true;

        // Simulate failure after lock is acquired
        if *self.stage_fails_after_lock.lock().unwrap() {
            return Err(MockError("stage failed after lock".to_string()));
        }

        for action in actions {
            state.data.insert(action.name.clone(), action.value.clone());
        }
        drop(state);
        let after_fp = self.fingerprint_from_state();
        Ok(MockStaged {
            actions: actions.to_vec(),
            before_fp,
            after_fp,
        })
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // If configured, check that we're not being called on committed state
        if *self.diff_checks_state.lock().unwrap() {
            let state = self.state.lock().unwrap();
            if !state.locked {
                return Err(MockError("diff called on committed state".to_string()));
            }
        }
        Ok(MockDiff {
            changes: vec!["mock diff".to_string()],
        })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(MockValidation {
            succeeded: true,
            details: "mock validation".to_string(),
        })
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.locked = false;
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: None,
            details: Some("committed".to_string()),
        })
    }

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        let behavior = self.rollback_behavior.lock().unwrap().clone();
        match behavior {
            RollbackBehavior::Success => {
                let mut state = self.state.lock().unwrap();
                state.data.clear();
                state
                    .data
                    .insert("initial".to_string(), "value".to_string());
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("rolled back".to_string()),
                })
            }
            RollbackBehavior::Failure => Ok(RollbackOutcome {
                succeeded: false,
                details: Some("rollback rejected".to_string()),
            }),
            RollbackBehavior::Error => Err(MockError("rollback timeout".to_string())),
            RollbackBehavior::DelayThenSuccess(delay_ms) => {
                sleep(Duration::from_millis(delay_ms)).await;
                let mut state = self.state.lock().unwrap();
                state.data.clear();
                state
                    .data
                    .insert("initial".to_string(), "value".to_string());
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("rolled back after delay".to_string()),
                })
            }
        }
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        let outcome = self.unlock_behavior.lock().unwrap().clone();
        Ok(outcome)
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError("unsupported".to_string()))
    }
}

fn mock_attribution() -> Attribution {
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
        on_behalf_of: Some("test@example.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

// ============================================================================
// Fix #1 (P1): Persist in-flight state before issuing rollback RPC
// ============================================================================

#[tokio::test]
async fn test_discard_persists_before_rollback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Use a transaction with delayed rollback to simulate a crash window
    let transaction = MockTransaction::with_delayed_rollback(100);
    let before_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test".to_string(),
        value: "value".to_string(),
    }];

    let output = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &before_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            "policy123",
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Start a discard operation in the background, reusing the same
    // coordinator rather than loading a second one against the same path: a
    // second live coordinator on the same path is refused, because it holds
    // the state file's single-writer lock for its whole lifetime (MEC-540).
    let op_id = output.operation_id.clone();
    let after_fp = output.after_fingerprint.clone();

    let discard_task = tokio::spawn(async move {
        coordinator
            .discard_operation(
                &op_id,
                "device1",
                "owner1",
                &after_fp,
                &transaction,
                &CancellationToken::new(),
            )
            .await
    });

    // Give it time to persist the in-flight state but not complete the rollback
    sleep(Duration::from_millis(50)).await;

    // Read the state file to verify an in-progress record was persisted
    let state_contents = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&state_contents).unwrap();

    // The record should exist and be in a non-terminal state that indicates rollback is happening
    let operations = &parsed["state"]["operations"];
    let record = &operations[output.operation_id.as_str()];

    // Without the fix, this would still be "Staged" or "Failed"
    // With the fix, it should be "Indeterminate" before the rollback completes
    assert!(
        record["state"] == "indeterminate",
        "should persist indeterminate state before rollback completes"
    );

    // Let the discard complete - it should fail (Round 5 Finding 4)
    let result = discard_task.await.unwrap();
    assert!(result.is_err());
}

// ============================================================================
// Fix #2 (P1): Re-check cancellation after acquiring guard in discard
// ============================================================================

#[tokio::test]
async fn test_discard_cancellation_after_guard_acquisition() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let before_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test".to_string(),
        value: "value".to_string(),
    }];

    let output = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &before_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            "policy123",
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Create a cancellation token and cancel it immediately
    let token = CancellationToken::new();
    token.cancel();

    // Try to discard with the already-cancelled token
    let result = coordinator
        .discard_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &token,
        )
        .await;

    // Should fail with cancellation error, not proceed to rollback
    assert!(result.is_err(), "should fail on cancelled token");
    assert!(
        result.unwrap_err().message().contains("cancelled"),
        "should be a cancellation error"
    );

    // Verify no rollback was performed (device should still be locked)
    assert!(
        transaction.is_locked(),
        "rollback should not have been called when cancelled"
    );
}

// ============================================================================
// Fix #3 (P2): Re-check lifecycle state before diffing
// ============================================================================

#[tokio::test]
async fn test_diff_rejects_committed_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::with_diff_checks_state();
    let before_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test".to_string(),
        value: "value".to_string(),
    }];

    let output = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &before_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            "policy123",
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    let staged = transaction.stage(&actions).await.unwrap();

    // Validate and commit
    coordinator
        .validate_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &staged,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    coordinator
        .commit_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            "policy123",
            &transaction,
            &staged,
            &mock_attribution(),
            &CommitOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Now try to diff after commit - should fail
    let result = coordinator
        .diff_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &staged,
            &CancellationToken::new(),
        )
        .await;

    // Without the fix, this would proceed and call diff() on committed state
    // With the fix, it should reject the operation
    assert!(result.is_err(), "diff should fail on committed operation");
}

// ============================================================================
// Fix #4 (P2): Set device_touched only after lock-risk persist succeeds
// ============================================================================

#[tokio::test]
async fn test_stage_device_touched_after_lock_persist() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Transaction that fails during stage() after the lock-risk persist
    let transaction = MockTransaction::with_stage_fails_after_lock();
    let before_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        name: "test".to_string(),
        value: "value".to_string(),
    }];

    let result = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &before_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            None,
            "policy123",
            None,
            &CancellationToken::new(),
        )
        .await;

    // Should fail
    assert!(result.is_err(), "stage should fail");

    // The operation should exist in Indeterminate state because:
    // 1. Lock-risk persist succeeded (device_touched is set after this)
    // 2. stage() was called and failed
    // 3. Since device_touched is true, the operation is marked Indeterminate
    //
    // This is the CORRECT behavior - the fix ensures device_touched is set
    // AFTER the persist succeeds, so if the persist fails, device_touched
    // stays false and the operation is removed. But if the persist succeeds
    // and THEN stage() fails, we correctly mark it Indeterminate.

    let state_contents = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&state_contents).unwrap();
    let operations = &parsed["state"]["operations"];

    // Should have one operation in Indeterminate state
    assert_eq!(
        operations.as_object().unwrap().len(),
        1,
        "operation should be persisted when stage fails after lock-risk persist"
    );

    // Get the operation record
    let (op_id, op_record) = operations.as_object().unwrap().iter().next().unwrap();
    assert_eq!(
        op_record["state"], "indeterminate",
        "operation should be Indeterminate when stage fails after device is touched"
    );
    assert!(
        op_record["details"]
            .as_str()
            .unwrap()
            .contains("staging failed after the candidate was touched"),
        "details should explain the failure"
    );
    assert_eq!(
        op_record["config_lock_held"], true,
        "lock should be marked as held since we don't know if stage() acquired it"
    );

    // Verify the operation ID was returned in the error (so it can be resolved)
    assert!(
        result.unwrap_err().message().contains("stage failed"),
        "error should indicate stage failure"
    );

    // Clean up - verify we can find and resolve this operation. Drop the
    // first coordinator first: it holds the state file's single-writer lock
    // for its whole lifetime (MEC-540), which a second live coordinator on
    // the same path would otherwise be refused.
    drop(coordinator);
    let coord2 = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let record = coord2.record(op_id, "owner1", "device1").await.unwrap();
    assert_eq!(record.state, LifecycleState::Indeterminate);
}
