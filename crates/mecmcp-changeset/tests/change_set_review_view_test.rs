//! Tests for change-set review view (actions exposure).
//!
//! Covers:
//! 1. Status without actions: actions field absent from serialized JSON
//! 2. Status with actions: returns the exact stored actions, action_count still correct
//! 3. A Cancelled/Applied set can also be read with actions (audit review of terminal sets)

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{ApplyHandle, ChangeSetState, ChangesetCoordinator, OperationLimits};
use std::time::Duration;

/// Action type for test change sets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
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

#[tokio::test]
async fn test_status_without_actions_field_absent() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![
        TestAction {
            action: "set".to_string(),
            target: "/config/system/hostname".to_string(),
        },
        TestAction {
            action: "set".to_string(),
            target: "/config/interfaces/ge-0/0/0".to_string(),
        },
    ];

    // Create change set
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

    // Get status without actions
    let status = coordinator
        .change_set_status(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status");

    // Verify action_count is correct
    assert_eq!(status.action_count, 2);

    // Serialize to JSON and verify actions field is absent
    let json = serde_json::to_value(&status).expect("serialize");
    assert!(!json.as_object().unwrap().contains_key("actions"));
}

#[tokio::test]
async fn test_status_with_actions_returns_stored_actions() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![
        TestAction {
            action: "set".to_string(),
            target: "/config/system/hostname".to_string(),
        },
        TestAction {
            action: "delete".to_string(),
            target: "/config/interfaces/ge-0/0/1".to_string(),
        },
        TestAction {
            action: "set".to_string(),
            target: "/config/security/policies".to_string(),
        },
    ];

    // Create change set
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

    // Get status with actions
    let status = coordinator
        .change_set_status_with_actions(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status with actions");

    // Verify action_count is correct
    assert_eq!(status.action_count, 3);

    // Serialize to JSON and verify actions field is present
    let json = serde_json::to_value(&status).expect("serialize");
    let json_actions = json
        .as_object()
        .unwrap()
        .get("actions")
        .expect("actions field present");

    // Verify the actions are present and correct
    let returned_actions: Vec<TestAction> =
        serde_json::from_value(json_actions.clone()).expect("deserialize actions");
    assert_eq!(returned_actions, actions);
}

#[tokio::test]
async fn test_cancelled_change_set_with_actions() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![
        TestAction {
            action: "set".to_string(),
            target: "/test/path1".to_string(),
        },
        TestAction {
            action: "delete".to_string(),
            target: "/test/path2".to_string(),
        },
    ];

    // Create change set
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

    // Cancel it
    let cancelled = coordinator
        .cancel_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
        )
        .await
        .expect("cancel");

    assert_eq!(cancelled.state, ChangeSetState::Cancelled);

    // Get status with actions for the cancelled set (audit review)
    let status = coordinator
        .change_set_status_with_actions(cancelled.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status with actions for cancelled");

    // Verify state is Cancelled
    assert_eq!(status.state, ChangeSetState::Cancelled);
    assert_eq!(status.action_count, 2);

    // Verify actions are returned
    let json = serde_json::to_value(&status).expect("serialize");
    let json_actions = json
        .as_object()
        .unwrap()
        .get("actions")
        .expect("actions field present");
    let returned_actions: Vec<TestAction> =
        serde_json::from_value(json_actions.clone()).expect("deserialize actions");
    assert_eq!(returned_actions, actions);
}

#[tokio::test]
async fn test_applied_change_set_with_actions() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create change set
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

    // Reach `Applied` the way the server does. Writing the state directly is
    // refused by the transition policy, and refusing it is the point: a record
    // that can be moved anywhere can be moved back into a claimable state.
    coordinator
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
    let mut record = coordinator
        .claim_change_set_for_apply(&created.change_set_id, "device-a", ApplyHandle::Expected)
        .await
        .expect("claim");
    let observed = record.state;
    record.state = ChangeSetState::Applied;
    coordinator
        .update_change_set_from(observed, record)
        .await
        .expect("settle");

    // Get status with actions for the applied set (audit review)
    let status = coordinator
        .change_set_status_with_actions(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status with actions for applied");

    // Verify state is Applied
    assert_eq!(status.state, ChangeSetState::Applied);
    assert_eq!(status.action_count, 1);

    // Verify actions are returned
    let json = serde_json::to_value(&status).expect("serialize");
    let json_actions = json
        .as_object()
        .unwrap()
        .get("actions")
        .expect("actions field present");
    let returned_actions: Vec<TestAction> =
        serde_json::from_value(json_actions.clone()).expect("deserialize actions");
    assert_eq!(returned_actions, actions);
}
