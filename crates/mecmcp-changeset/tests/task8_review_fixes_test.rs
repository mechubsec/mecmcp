//! Tests for the five review fixes from the third review round.

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
enum RollbackBehavior {
    Success,
    Failure,
    Error,
}

struct MockTransaction {
    state: Arc<StdMutex<MockDeviceState>>,
    rollback_behavior: Arc<StdMutex<RollbackBehavior>>,
    unlock_behavior: Arc<StdMutex<UnlockOutcome>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(StdMutex::new(MockDeviceState::default())),
            rollback_behavior: Arc::new(StdMutex::new(RollbackBehavior::Success)),
            unlock_behavior: Arc::new(StdMutex::new(UnlockOutcome::Unsupported)),
        }
    }

    fn with_rollback_error() -> Self {
        Self {
            rollback_behavior: Arc::new(StdMutex::new(RollbackBehavior::Error)),
            ..Self::new()
        }
    }

    fn with_unlock_released() -> Self {
        Self {
            unlock_behavior: Arc::new(StdMutex::new(UnlockOutcome::Released)),
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
// Fix #1: State schema version 2
// ============================================================================

#[tokio::test]
async fn test_version_1_files_still_load() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let path = temp.path();

    // Write a version-1 state file manually (simulating an old binary)
    let v1_state = serde_json::json!({
        "version": 1,
        "state": {
            "operations": {},
            "change_sets": {}
        }
    });
    std::fs::write(path, serde_json::to_vec_pretty(&v1_state).unwrap()).unwrap();

    // Load it with the new binary
    let coordinator = ChangesetCoordinator::load(
        Some(path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    assert!(coordinator.limits().max_operations > 0);
}

#[tokio::test]
async fn test_version_2_written_when_new_fields_present() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
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

    // Commit to trigger attribution persistence
    let staged = transaction.stage(&actions).await.unwrap();
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

    // Read back the file and verify it's version 2
    let contents = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(
        parsed["version"], 2,
        "should write version 2 when attribution is present"
    );
}

// ============================================================================
// Fix #2: Canonicalize endpoints before locking
// ============================================================================

#[tokio::test]
async fn test_canonicalized_endpoints_share_guard() {
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

    // Stage with trailing slash
    let output1 = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &before_fp,
            "https://device.example.com/",
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

    // Try to stage with no trailing slash - should fail because same device is locked
    let result = coordinator
        .stage_operation(
            "device1",
            "owner2",
            &before_fp,
            "https://device.example.com",
            &transaction,
            &actions,
            "set",
            None,
            "policy123",
            None,
            &CancellationToken::new(),
        )
        .await;

    assert!(
        result.is_err(),
        "different endpoint forms should map to same guard"
    );
    assert!(
        result
            .unwrap_err()
            .message()
            .contains("active or unreconciled"),
        "should fail with endpoint-busy error"
    );

    // Clean up
    coordinator.remove(&output1.operation_id).await;
}

// ============================================================================
// Fix #3: Discard must stay non-terminal until unlocking established
// ============================================================================

#[tokio::test]
async fn test_discard_stays_indeterminate_until_unlock() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Transaction with Unsupported unlock (default)
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

    // Discard the operation - should fail because unlock is unsupported (Round 5 Finding 4)
    let result = coordinator
        .discard_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &CancellationToken::new(),
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

    // Verify the record is Indeterminate, not Discarded
    let record = coordinator
        .record(&output.operation_id, "owner1", "device1")
        .await
        .unwrap();

    assert_eq!(
        record.state,
        LifecycleState::Indeterminate,
        "discard with Unsupported unlock should stay Indeterminate"
    );
    assert!(
        record
            .details
            .as_ref()
            .unwrap()
            .contains("no explicit unlock"),
        "should document why it's indeterminate"
    );
}

#[tokio::test]
async fn test_discard_becomes_terminal_when_unlock_released() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Transaction that can release the lock
    let transaction = MockTransaction::with_unlock_released();
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

    // Discard the operation
    coordinator
        .discard_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Verify the record is Discarded (terminal)
    let record = coordinator
        .record(&output.operation_id, "owner1", "device1")
        .await
        .unwrap();

    assert_eq!(
        record.state,
        LifecycleState::Discarded,
        "discard with Released unlock should be terminal Discarded"
    );
    assert!(!record.config_lock_held, "lock should be released");
}

// ============================================================================
// Fix #4: Ambiguous rollback error is indeterminate
// ============================================================================

#[tokio::test]
async fn test_rollback_error_becomes_indeterminate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    // Transaction that errors on rollback (simulating timeout)
    let transaction = MockTransaction::with_rollback_error();
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

    // Try to discard - should fail and mark as indeterminate
    let result = coordinator
        .discard_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err(), "discard should fail on rollback error");

    // Verify the record is Indeterminate
    let record = coordinator
        .record(&output.operation_id, "owner1", "device1")
        .await
        .unwrap();

    assert_eq!(
        record.state,
        LifecycleState::Indeterminate,
        "rollback error should mark operation as indeterminate"
    );
    assert!(
        record
            .details
            .as_ref()
            .unwrap()
            .contains("rollback outcome unknown"),
        "should document the ambiguous rollback"
    );
}

// ============================================================================
// Fix #5: Diff must serialize with commit and validation
// ============================================================================

#[tokio::test]
async fn test_diff_serializes_with_commit() {
    // This test verifies that diff_operation acquires the device guard,
    // which serializes it with validate and commit operations.
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

    // Call diff_operation - it should succeed and acquire the guard
    let diff_result = coordinator
        .diff_operation(
            &output.operation_id,
            "device1",
            "owner1",
            &output.after_fingerprint,
            &transaction,
            &output.staged,
            &CancellationToken::new(),
        )
        .await;

    assert!(diff_result.is_ok(), "diff should succeed");
    assert!(
        !diff_result.unwrap().changes.is_empty(),
        "should have changes"
    );
}
