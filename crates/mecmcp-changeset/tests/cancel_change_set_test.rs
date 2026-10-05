//! Tests for cancel_change_set lifecycle method.
//!
//! Covers:
//! 1. Owner can cancel their own Planned change set
//! 2. Approver can cancel an Approved change set
//! 3. Non-owner, non-approver cannot cancel
//! 4. Cannot cancel Applied change sets
//! 5. Cannot cancel Applying change sets
//! 6. Cancelling already-Cancelled is idempotent
//! 7. Cancelled change sets free the per-principal pending slot
//! 8. Cancelled change sets are terminal (evictable at capacity)

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{ApplyHandle, ChangeSetState, ChangesetCoordinator, OperationLimits};
use std::time::Duration;

/// Action type for test change sets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

/// Sets up a temporary coordinator with a clean state file.
fn setup_coordinator() -> (tempfile::TempDir, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    (dir, coordinator)
}

/// Generates a test fingerprint.
fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

/// Walk a freshly created change set to `target` through the real lifecycle.
///
/// These tests used to write the state directly, which the transition policy
/// now refuses — and refusing it is the point: `Planned -> Applied` was exactly
/// the shortcut that let an in-flight record be laundered back into a claimable
/// one. Reaching the state the way the server reaches it costs three lines and
/// keeps the setup honest.
async fn drive_to(
    coordinator: &ChangesetCoordinator,
    id: &str,
    device: &str,
    digest: &str,
    target: ChangeSetState,
) {
    coordinator
        .approve_change_set(
            id.to_owned(),
            device.to_owned(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_owned(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            digest.to_owned(),
        )
        .await
        .expect("approve");
    if target == ChangeSetState::Approved {
        return;
    }
    let claimed = coordinator
        .claim_change_set_for_apply(id, device, ApplyHandle::Expected)
        .await
        .expect("claim");
    if target == ChangeSetState::Applying {
        return;
    }
    let mut record = claimed;
    let observed = record.state;
    record.state = target;
    coordinator
        .update_change_set_from(observed, record)
        .await
        .expect("settle");
}

#[tokio::test]
async fn test_owner_can_cancel_planned_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    assert_eq!(created.state, ChangeSetState::Planned);

    // Cancel as alice (the owner)
    let cancelled = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel");

    assert_eq!(cancelled.state, ChangeSetState::Cancelled);
    assert_eq!(cancelled.change_set_id, created.change_set_id);
}

#[tokio::test]
async fn test_approver_can_cancel_approved_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Approve as bob
    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));

    // Cancel as bob (the approver)
    let cancelled = coordinator
        .cancel_change_set(
            approved.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
        )
        .await
        .expect("cancel");

    assert_eq!(cancelled.state, ChangeSetState::Cancelled);
}

#[tokio::test]
async fn test_non_owner_non_approver_cannot_cancel() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Attempt to cancel as charlie (neither owner nor approver)
    let result = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "charlie".to_string(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("owner or approver"));
}

#[tokio::test]
async fn test_cannot_cancel_applied_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Manually transition to Applied state by updating the record
    drive_to(
        &coordinator,
        &created.change_set_id,
        "device-a",
        &created.digest,
        ChangeSetState::Applied,
    )
    .await;

    // Attempt to cancel Applied change set
    let result = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("cannot cancel"));
    assert!(err.message().contains("applied"));
}

#[tokio::test]
async fn test_cannot_cancel_applying_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Manually transition to Applying state
    drive_to(
        &coordinator,
        &created.change_set_id,
        "device-a",
        &created.digest,
        ChangeSetState::Applying,
    )
    .await;

    // Attempt to cancel Applying change set
    let result = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("cannot cancel"));
    assert!(err.message().contains("applying"));
}

#[tokio::test]
async fn test_cancel_is_idempotent() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create and cancel as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    let cancelled1 = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel first time");

    assert_eq!(cancelled1.state, ChangeSetState::Cancelled);

    // Cancel again - should succeed idempotently
    let cancelled2 = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel second time");

    assert_eq!(cancelled2.state, ChangeSetState::Cancelled);
    assert_eq!(cancelled2.change_set_id, cancelled1.change_set_id);
}

#[tokio::test]
async fn test_cancelled_change_set_frees_pending_slot() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions.clone(),
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Try to create another as alice - should fail (pending slot occupied)
    let result = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions.clone(),
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message().contains("pending change set"));

    // Cancel the first change set
    coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel");

    // Now create another as alice - should succeed (slot freed)
    let created2 = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create after cancel");

    assert_eq!(created2.state, ChangeSetState::Planned);
    assert_ne!(created2.change_set_id, created.change_set_id);
}

#[tokio::test]
async fn test_cancelled_change_sets_are_evicted_at_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    // Create coordinator with low capacity
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 3, // Only allow 3 change sets
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create and cancel two change sets (terminal state)
    for i in 1..=2 {
        let created = coordinator
            .create_change_set(
                "device-a".to_string(),
                actions.clone(),
                format!("user{i}"),
                test_fingerprint(),
                "policy-sig".to_string(),
                None,
            )
            .await
            .expect("create");

        coordinator
            .cancel_change_set(
                created.change_set_id.clone(),
                "device-a".to_string(),
                format!("user{i}"),
            )
            .await
            .expect("cancel");
    }

    // Create a third Planned change set
    let created3 = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions.clone(),
            "user3".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create third");

    assert_eq!(created3.state, ChangeSetState::Planned);

    // Create a fourth - should trigger eviction of Cancelled records
    let created4 = coordinator
        .create_change_set(
            "device-b".to_string(),
            actions,
            "user4".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create fourth - should evict cancelled");

    assert_eq!(created4.state, ChangeSetState::Planned);

    // Verify the Cancelled records were evicted by checking total count
    let all_change_sets = coordinator.change_sets().await;
    assert_eq!(all_change_sets.len(), 2); // Only the two Planned ones remain
}

#[tokio::test]
async fn test_owner_can_cancel_expired_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Manually transition to Expired state
    let mut record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("get record");
    record.state = ChangeSetState::Expired;
    coordinator.update_change_set(record).await.expect("update");

    // Cancel the Expired change set - should succeed
    let cancelled = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel expired");

    assert_eq!(cancelled.state, ChangeSetState::Cancelled);
}

#[tokio::test]
async fn test_owner_can_cancel_failed_change_set() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    // Manually transition to Failed state
    drive_to(
        &coordinator,
        &created.change_set_id,
        "device-a",
        &created.digest,
        ChangeSetState::Failed,
    )
    .await;

    // Cancel the Failed change set - should succeed
    let cancelled = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel failed");

    assert_eq!(cancelled.state, ChangeSetState::Cancelled);
}
