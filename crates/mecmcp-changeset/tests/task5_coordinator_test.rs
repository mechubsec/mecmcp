//! Task 5 coordinator tests.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    coordinator::ChangesetCoordinator,
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::read_state,
    records::{ChangeSetRecord, OperationRecord, change_set_digest},
    types::OperationLimits,
};
use std::{path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

/// Stage the checked-in production fixture as a private (0600) temp file.
fn staged_production_fixture() -> (tempfile::TempDir, PathBuf) {
    let src: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "compat",
        "mutation-state-608.json",
    ]
    .iter()
    .collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join("mutation-state.json");
    std::fs::copy(&src, &dst).expect("copy fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture copy");
    }
    (dir, dst)
}

fn make_operation_record(
    id: &str,
    device: &str,
    endpoint: &str,
    state: LifecycleState,
) -> OperationRecord {
    OperationRecord {
        id: id.to_string(),
        owner: "test_owner".to_string(),
        device: device.to_string(),
        endpoint: endpoint.to_string(),
        action: serde_json::json!({"action": "set"}),
        xpath: None,
        actions: vec![serde_json::json!({"action": "set"})],
        change_set_id: None,
        current: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        state,
        job_id: None,
        details: None,
        config_lock_held: false,
        policy_signature: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    }
}

fn make_change_set_record(id: &str, state: ChangeSetState) -> ChangeSetRecord {
    let owner = "test_owner".to_string();
    let device = "test_device".to_string();
    let fingerprint =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let actions = vec![serde_json::json!({"action": "set"})];

    // Compute a valid digest for this change set
    let digest = change_set_digest(&owner, &device, &fingerprint, &actions).unwrap();

    ChangeSetRecord {
        id: id.to_string(),
        owner,
        device,
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state,
        approver: None,
        approval: None,
        expires_at_unix: 0,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

#[tokio::test]
async fn test_insert_and_reload_persists_operation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Create coordinator and insert an operation
    {
        let coordinator =
            ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();
        let operation = make_operation_record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_device",
            "https://device.example.com",
            LifecycleState::Staged,
        );
        coordinator.insert(operation.clone()).await.unwrap();
    }

    // Drop and reload the coordinator
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Verify the operation persisted and was converted to Indeterminate on restart.
    // Staged operations cannot be recovered because the opaque handle only exists
    // in memory and cannot be reconstructed after a restart.
    let record = coordinator
        .record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_owner",
            "test_device",
        )
        .await
        .unwrap();
    assert_eq!(
        record.state,
        LifecycleState::Indeterminate,
        "Staged must be converted to Indeterminate on restart"
    );
}

#[tokio::test]
async fn test_restart_recovery_marks_staging_indeterminate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Create coordinator and insert an operation in Staging state
    {
        let coordinator =
            ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();
        let operation = make_operation_record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_device",
            "https://device.example.com",
            LifecycleState::Staging,
        );
        coordinator.insert(operation.clone()).await.unwrap();
    }

    // Reload - should trigger recovery
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Verify the operation is now Indeterminate
    let record = coordinator
        .record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_owner",
            "test_device",
        )
        .await
        .unwrap();
    assert_eq!(record.state, LifecycleState::Indeterminate);
    assert!(
        record
            .details
            .as_ref()
            .unwrap()
            .contains("manual reconciliation required")
    );
}

#[tokio::test]
async fn test_restart_recovery_marks_applying_failed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Create coordinator and insert a change set in Applying state
    {
        let coordinator =
            ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();
        let change_set = make_change_set_record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            ChangeSetState::Applying,
        );
        coordinator
            .seed_change_set_for_test(change_set)
            .await
            .unwrap();
    }

    // Reload - should trigger recovery
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Verify the change set is now Failed
    let record = coordinator
        .change_set(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_device",
        )
        .await
        .unwrap();
    assert_eq!(record.state, ChangeSetState::Failed);
}

#[tokio::test]
async fn test_device_guard_serializes_same_endpoint() {
    let coordinator = ChangesetCoordinator::default();
    let cancellation = CancellationToken::new();

    // Acquire guard for endpoint
    let _guard1 = coordinator
        .device_guard("https://device.example.com", &cancellation)
        .await
        .unwrap();

    // Try to acquire second guard for same endpoint - should block
    // We'll use a timeout to verify it blocks
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        coordinator.device_guard("https://device.example.com", &cancellation),
    )
    .await;

    assert!(result.is_err(), "Second guard should timeout (blocked)");
}

#[tokio::test]
async fn test_device_guard_allows_different_endpoints() {
    let coordinator = ChangesetCoordinator::default();
    let cancellation = CancellationToken::new();

    // Acquire guards for two different endpoints concurrently
    let (guard1, guard2) = tokio::join!(
        coordinator.device_guard("https://device1.example.com", &cancellation),
        coordinator.device_guard("https://device2.example.com", &cancellation)
    );

    assert!(guard1.is_ok(), "First guard should succeed");
    assert!(guard2.is_ok(), "Second guard should succeed");
}

#[tokio::test]
async fn test_persist_failure_rolls_back_insert() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Make the directory read-only to force persist failure, after loading
    // the coordinator rather than before: load itself now needs to create
    // the state file's owner lock (MEC-540), so a directory that is already
    // read-only at load time fails construction, not just the write this
    // test means to exercise.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    }

    let operation = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "test_device",
        "https://device.example.com",
        LifecycleState::Staged,
    );

    // Insert should fail due to read-only directory
    let result = coordinator.insert(operation.clone()).await;
    assert!(result.is_err(), "Insert should fail on read-only directory");

    // Verify the operation is NOT in memory
    let record_result = coordinator
        .record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_owner",
            "test_device",
        )
        .await;
    assert!(
        record_result.is_err(),
        "Operation should not be in memory after failed insert"
    );

    // Clean up: restore permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[tokio::test]
async fn test_persist_failure_rolls_back_update() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Create coordinator and insert an operation
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();
    let mut operation = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "test_device",
        "https://device.example.com",
        LifecycleState::Staged,
    );
    coordinator.insert(operation.clone()).await.unwrap();

    // Make directory read-only to force persist failure
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    }

    // Try to update the operation
    operation.state = LifecycleState::Validated;
    let result = coordinator.update(operation.clone()).await;
    assert!(result.is_err(), "Update should fail on read-only directory");

    // Restore permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Verify the operation is still in Staged state (rollback succeeded)
    let record = coordinator
        .record(
            "0000000000000000000000000000000000000000000000000000000000000001",
            "test_owner",
            "test_device",
        )
        .await
        .unwrap();
    assert_eq!(
        record.state,
        LifecycleState::Staged,
        "Operation should still be Staged after failed update"
    );
}

#[tokio::test]
async fn test_capacity_limits_from_operation_limits() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Use custom limits with max_operations = 2
    let limits = OperationLimits {
        max_operations: 2,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_change_set_bytes: 256 * 1024,
        max_state_bytes: 8 * 1024 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(900);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Insert two operations (at capacity) for different devices
    let op1 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "device1",
        "https://device1.example.com",
        LifecycleState::Staged,
    );
    let op2 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000002",
        "device2",
        "https://device2.example.com",
        LifecycleState::Staged,
    );

    coordinator.insert(op1).await.unwrap();
    coordinator.insert(op2).await.unwrap();

    // Try to insert a third operation - should fail due to capacity
    let op3 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000003",
        "device3",
        "https://device3.example.com",
        LifecycleState::Staged,
    );
    let result = coordinator.insert(op3).await;
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("operation store is full"));
}

#[tokio::test]
async fn test_terminal_records_evicted_at_capacity() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Use custom limits with max_operations = 2
    let limits = OperationLimits {
        max_operations: 2,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_change_set_bytes: 256 * 1024,
        max_state_bytes: 8 * 1024 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(900);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false).unwrap();

    // Insert two operations in terminal states
    let op1 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "test_device",
        "https://device1.example.com",
        LifecycleState::Committed,
    );
    let op2 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000002",
        "test_device",
        "https://device2.example.com",
        LifecycleState::Discarded,
    );

    coordinator.insert(op1).await.unwrap();
    coordinator.insert(op2).await.unwrap();

    // Insert a third operation - should evict the terminal ones
    let op3 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000003",
        "test_device",
        "https://device3.example.com",
        LifecycleState::Staged,
    );
    coordinator.insert(op3).await.unwrap();

    // Verify op3 is present
    let record = coordinator
        .record(
            "0000000000000000000000000000000000000000000000000000000000000003",
            "test_owner",
            "test_device",
        )
        .await;
    assert!(record.is_ok(), "New operation should be present");
}

#[tokio::test]
async fn test_production_fixture_no_rewrite() {
    // This is the critical test: loading the 608 fixture must NOT rewrite the file
    let (_fixture_dir, fixture_path) = staged_production_fixture();

    // Record the original bytes
    let original_bytes = std::fs::read(&fixture_path).unwrap();

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Load the coordinator from the fixture
    let _coordinator =
        ChangesetCoordinator::load(Some(&fixture_path), limits, approval_ttl, false).unwrap();

    // Read the file again
    let after_bytes = std::fs::read(&fixture_path).unwrap();

    // Assert byte-identical
    assert_eq!(
        original_bytes, after_bytes,
        "Production fixture must be byte-identical after coordinator load (no recovery needed)"
    );
}

#[tokio::test]
async fn test_production_fixture_terminal_records_survive() {
    let (_fixture_dir, fixture_path) = staged_production_fixture();

    // Read the original state directly
    let original_state = read_state(&fixture_path, 8 * 1024 * 1024).unwrap();

    // Collect all operation states
    let original_op_states: Vec<_> = original_state
        .operations
        .iter()
        .map(|(id, record)| (id.clone(), record.state))
        .collect();

    let original_cs_states: Vec<_> = original_state
        .change_sets
        .iter()
        .map(|(id, record)| (id.clone(), record.state))
        .collect();

    let limits = OperationLimits::default();
    let approval_ttl = Duration::from_secs(900);

    // Load the coordinator
    let _coordinator =
        ChangesetCoordinator::load(Some(&fixture_path), limits, approval_ttl, false).unwrap();

    // Read the state again
    let after_state = read_state(&fixture_path, 8 * 1024 * 1024).unwrap();

    // Verify all operations kept their exact states
    for (id, original_state) in original_op_states {
        let after_record = after_state.operations.get(&id).unwrap();
        assert_eq!(
            original_state, after_record.state,
            "Operation {id} state must be unchanged"
        );
    }

    // Verify all change sets kept their exact states
    for (id, original_state) in original_cs_states {
        let after_record = after_state.change_sets.get(&id).unwrap();
        assert_eq!(
            original_state, after_record.state,
            "Change set {id} state must be unchanged"
        );
    }
}

#[tokio::test]
async fn test_one_active_operation_per_endpoint() {
    let coordinator = ChangesetCoordinator::default();

    let op1 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000001",
        "test_device",
        "https://device.example.com",
        LifecycleState::Staged,
    );
    coordinator.insert(op1).await.unwrap();

    // Try to insert a second operation on the same endpoint
    let op2 = make_operation_record(
        "0000000000000000000000000000000000000000000000000000000000000002",
        "test_device",
        "https://device.example.com",
        LifecycleState::Staged,
    );
    let result = coordinator.insert(op2).await;
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("already has an active or unreconciled operation"),
        "Expected active operation error, got: {}",
        error
    );
}
