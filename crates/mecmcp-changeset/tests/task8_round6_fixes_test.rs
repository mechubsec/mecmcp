//! Task 8 Round 6: Compatibility fixes for deployed state format.
//!
//! Five targeted fixes to restore compatibility with the deployed LXC 608 state file:
//! 1. Restore endpoint check alongside device check (prevent concurrent mutations)
//! 2. Persist vendor's primary target (`xpath`) in operation records
//! 3. Include operation id when post-stage write fails
//! 4. Keep known post-stage fingerprint in recovery record
//! 5. Clear lock flag on `AwaitingConfirmation` (Junos confirmed-commit)

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use mecmcp_audit::{ActorType, Attribution, Principal};
use mecmcp_changeset::{
    ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction, LifecycleState,
    OperationLimits, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const TEST_ENDPOINT: &str = "https://device.example.com";
const TEST_ENDPOINT2: &str = "https://device2.example.com";

// ============================================================================
// Mock transaction (minimal viable)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MockAction {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct MockStaged {
    #[allow(dead_code)]
    actions: Vec<MockAction>,
}

#[derive(Debug, Clone, Serialize)]
struct MockDiff {
    changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MockValidation {
    succeeded: bool,
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
enum CommitBehavior {
    Success,
    AwaitingConfirmation { rollback_deadline_unix: u64 },
}

struct MockTransaction {
    state: Arc<Mutex<MockDeviceState>>,
    commit_behavior: Arc<Mutex<CommitBehavior>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDeviceState::default())),
            commit_behavior: Arc::new(Mutex::new(CommitBehavior::Success)),
        }
    }

    fn compute_fingerprint(state: &MockDeviceState) -> String {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        let mut keys: Vec<_> = state.data.keys().cloned().collect();
        keys.sort();
        for key in &keys {
            hasher.update(key.as_bytes());
            hasher.update(state.data[key].as_bytes());
        }
        let hash = hasher.finalize();
        format!("sha256:{}", hex::encode(hash))
    }
}

#[derive(Debug, thiserror::Error)]
enum MockError {
    #[error("device error: {0}")]
    DeviceError(String),
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
        Ok(Self::compute_fingerprint(&state))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.locked = true;
        for action in actions {
            state.data.insert(action.name.clone(), action.value.clone());
        }
        Ok(MockStaged {
            actions: actions.to_vec(),
        })
    }

    async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(MockDiff {
            changes: vec!["mock change".to_string()],
        })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(MockValidation { succeeded: true })
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
                let mut state = self.state.lock().unwrap();
                state.locked = false;
                Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: Some("job-123".to_string()),
                    details: Some("commit succeeded".to_string()),
                })
            }
            CommitBehavior::AwaitingConfirmation {
                rollback_deadline_unix,
            } => {
                let mut state = self.state.lock().unwrap();
                state.locked = false;
                Ok(CommitOutcome::AwaitingConfirmation {
                    job_id: Some("job-456".to_string()),
                    rollback_deadline_unix,
                    details: Some("commit confirmed; awaiting confirmation".to_string()),
                })
            }
        }
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError::DeviceError(
            "confirm_commit not supported".to_string(),
        ))
    }

    async fn rollback(&self, _rollback_ref: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.data.clear();
        state
            .data
            .insert("initial".to_string(), "value".to_string());
        state.locked = false;
        Ok(RollbackOutcome {
            succeeded: true,
            details: Some("rollback succeeded".to_string()),
        })
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.locked = false;
        Ok(UnlockOutcome::Released)
    }
}

// ============================================================================
// Test 1: Restore endpoint check alongside device check
// ============================================================================

#[tokio::test]
async fn test_endpoint_check_prevents_concurrent_mutations() {
    // Two inventory names resolving to the same endpoint should not both pass the
    // one-active-operation check. The coordinator must compare canonical endpoints
    // in addition to comparing device names.

    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();
    let policy_sig = "sha256:deadbeef";

    // Stage operation 1 against device1
    let actions1 = vec![MockAction {
        name: "key1".to_string(),
        value: "value1".to_string(),
    }];
    let _output1 = coordinator
        .stage_operation(
            "device1",
            "owner1",
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions1,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Capture the after-fingerprint
    let after_fp1 = transaction.fingerprint().await.unwrap();

    // Try to stage operation 2 against device2, but with the SAME endpoint (case-insensitive variant)
    let actions2 = vec![MockAction {
        name: "key2".to_string(),
        value: "value2".to_string(),
    }];
    let result = coordinator
        .stage_operation(
            "device2", // different device name
            "owner2",
            &after_fp1,
            "HTTPS://device.example.com", // same endpoint, different case
            &transaction,
            &actions2,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await;

    // The second operation should be REJECTED because the canonical endpoint matches
    assert!(
        result.is_err(),
        "expected rejection due to matching endpoint"
    );
    let err = result.unwrap_err();
    assert!(
        err.message()
            .contains("already has an active or unreconciled operation"),
        "error message should mention active operation: {}",
        err.message()
    );
}

#[tokio::test]
async fn test_device_check_still_enforced() {
    // The device check should still prevent two operations on the same device,
    // even with different endpoints (e.g., management IP vs DNS name).

    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();
    let policy_sig = "sha256:deadbeef";

    // Stage operation 1
    let actions1 = vec![MockAction {
        name: "key1".to_string(),
        value: "value1".to_string(),
    }];
    coordinator
        .stage_operation(
            "device1",
            "owner1",
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions1,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    let after_fp1 = transaction.fingerprint().await.unwrap();

    // Try to stage operation 2 on the SAME device but different endpoint
    let actions2 = vec![MockAction {
        name: "key2".to_string(),
        value: "value2".to_string(),
    }];
    let result = coordinator
        .stage_operation(
            "device1", // same device
            "owner2",
            &after_fp1,
            TEST_ENDPOINT2, // different endpoint
            &transaction,
            &actions2,
            "set",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await;

    // Should be rejected due to device collision
    assert!(result.is_err(), "expected rejection due to same device");
    let err = result.unwrap_err();
    assert!(
        err.message()
            .contains("already has an active or unreconciled operation"),
        "error message: {}",
        err.message()
    );
}

// ============================================================================
// Test 2: Persist vendor's primary target (xpath)
// ============================================================================

#[tokio::test]
async fn test_xpath_persisted_in_operation_record() {
    // When staging an operation with a vendor-specific primary target (xpath for PAN-OS),
    // the coordinator must persist it in the operation record so a rolled-back v1 reader
    // can load the record. The production fixture has xpath on every operation.

    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();
    let policy_sig = "sha256:test";

    let actions = vec![MockAction {
        name: "address".to_string(),
        value: "192.0.2.1".to_string(),
    }];

    let xpath = Some(
        "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address",
    );

    let output = coordinator
        .stage_operation(
            "panosvm-test",
            "owner1",
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "set",
            xpath,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Retrieve the record and verify the xpath field is present
    let record = coordinator
        .record(&output.operation_id, "owner1", "panosvm-test")
        .await
        .unwrap();

    assert_eq!(
        record.xpath.as_deref(),
        xpath,
        "xpath should be persisted in the record"
    );
}

#[tokio::test]
async fn test_xpath_omitted_for_junos() {
    // Junos operations have no vendor target, so xpath should be None and omitted from serialization.

    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();
    let policy_sig = "sha256:test";

    let actions = vec![MockAction {
        name: "interface".to_string(),
        value: "ge-0/0/0".to_string(),
    }];

    let output = coordinator
        .stage_operation(
            "vsrx-test",
            "owner1",
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "configure",
            None, // Junos has no xpath
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    let record = coordinator
        .record(&output.operation_id, "owner1", "vsrx-test")
        .await
        .unwrap();

    assert_eq!(
        record.xpath, None,
        "xpath should be None for Junos operations"
    );
}

// ============================================================================
// Test 5: Clear lock flag on AwaitingConfirmation
// ============================================================================

#[tokio::test]
async fn test_awaiting_confirmation_clears_lock_flag() {
    // When a Junos commit returns `AwaitingConfirmation`, the transaction contract
    // guarantees the candidate lock was released (the commit succeeded provisionally).
    // The operation record must clear `config_lock_held` to reflect this.

    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&state_path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    *transaction.commit_behavior.lock().unwrap() = CommitBehavior::AwaitingConfirmation {
        rollback_deadline_unix: 1234567890,
    };

    let cancellation = CancellationToken::new();

    let initial_fp = transaction.fingerprint().await.unwrap();
    let policy_sig = "sha256:test";

    let actions = vec![MockAction {
        name: "interface".to_string(),
        value: "ge-0/0/0".to_string(),
    }];

    // Stage the operation
    let output = coordinator
        .stage_operation(
            "vsrx1",
            "owner1",
            &initial_fp,
            TEST_ENDPOINT,
            &transaction,
            &actions,
            "configure",
            None,
            policy_sig,
            None,
            &cancellation,
        )
        .await
        .unwrap();

    // Validate the operation
    let record = coordinator
        .record(&output.operation_id, "owner1", "vsrx1")
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Staged);
    assert!(record.config_lock_held, "lock should be held after staging");

    coordinator
        .validate_operation(
            &output.operation_id,
            "vsrx1",
            "owner1",
            &record.current,
            &transaction,
            &output.staged,
            &cancellation,
        )
        .await
        .unwrap();

    let record = coordinator
        .record(&output.operation_id, "owner1", "vsrx1")
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Validated);

    // Commit the operation
    let attribution = Attribution {
        principal: Principal::Token("test-token".to_string()),
        actor_type: ActorType::Human,
        on_behalf_of: None,
        change_ref: None,
        request_id: uuid::Uuid::new_v4(),
        agent: None,
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    };

    let outcome = coordinator
        .commit_operation(
            &output.operation_id,
            "vsrx1",
            "owner1",
            &record.current,
            policy_sig,
            &transaction,
            &output.staged,
            &attribution,
            &CommitOptions::default(),
            &cancellation,
        )
        .await
        .unwrap();

    // Verify outcome is AwaitingConfirmation
    match outcome {
        CommitOutcome::AwaitingConfirmation {
            rollback_deadline_unix,
            ..
        } => {
            assert_eq!(rollback_deadline_unix, 1234567890);
        }
        _ => panic!("expected AwaitingConfirmation outcome"),
    }

    // Retrieve the record and verify the lock flag is CLEARED
    let record = coordinator
        .record(&output.operation_id, "owner1", "vsrx1")
        .await
        .unwrap();

    assert!(
        !record.config_lock_held,
        "config_lock_held should be false after confirmed commit (transaction succeeded provisionally and released lock)"
    );

    // Also verify the rollback deadline was persisted
    assert_eq!(
        record.rollback_deadline_unix,
        Some(1234567890),
        "rollback_deadline_unix should be persisted"
    );
}
