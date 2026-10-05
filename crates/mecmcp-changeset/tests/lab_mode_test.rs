//! Tests for lab mode — approval waiver without a second principal.
//!
//! Covers:
//! 1. waive_approval is refused when lab_mode=false
//! 2. With lab_mode=true, waive_approval succeeds and sets approver=None, waived=Some
//! 3. A waived record is programmatically distinguishable from a genuine approval
//! 4. A waived record round-trips through persistence and passes validate_state
//! 5. Tampering a waived record (inserting an approver) is rejected on load
//! 6. Only the change-set owner can waive
//! 7. Waiving a change set not in Planned state is refused
//! 8. Waiving after the approval TTL expires is refused and transitions to Expired

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, OperationLimits,
    persistence::{read_state, write_state_for_test},
};
use std::time::Duration;

/// Action type for test change sets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

/// Sets up a temporary coordinator with a clean state file.
fn setup_coordinator(lab_mode: bool) -> (tempfile::TempDir, ChangesetCoordinator) {
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

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, lab_mode)
        .expect("coordinator");

    (dir, coordinator)
}

/// Generates a test fingerprint.
fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[tokio::test]
async fn test_waive_approval_refused_when_lab_mode_disabled() {
    let (_dir, coordinator) = setup_coordinator(false);

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

    // Attempt to waive without lab mode
    let result = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("lab mode"));
}

#[tokio::test]
async fn test_waive_approval_succeeds_with_lab_mode() {
    let (dir, coordinator) = setup_coordinator(true);

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
    assert!(created.approver.is_none());

    // Waive as alice (the owner)
    let waived = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await
        .expect("waive");

    assert_eq!(waived.state, ChangeSetState::Approved);
    assert!(waived.approver.is_none(), "waived approval has no approver");

    // Read the state file and verify the waiver record
    let state_path = dir.path().join("state.json");
    let state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get(&created.change_set_id).unwrap();

    assert!(record.approval.is_some(), "approval record must be present");
    let approval = record.approval.as_ref().unwrap();
    assert!(
        approval.approver.is_none(),
        "waived approval has no approver"
    );
    assert!(
        approval.waived.is_some(),
        "waived approval has a waiver record"
    );
    assert_eq!(
        approval.waived.as_ref().unwrap().reason,
        "lab-mode",
        "waiver reason is lab-mode"
    );
}

#[tokio::test]
async fn test_waived_record_is_distinguishable_from_genuine_approval() {
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

    // Create two coordinators: one with lab mode, one without
    let coordinator_lab = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator lab");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create a waived change set
    let waived_cs = coordinator_lab
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

    coordinator_lab
        .waive_approval(
            waived_cs.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            waived_cs.digest.clone(),
        )
        .await
        .expect("waive");

    // A genuine two-person approval, in the same coordinator and the same state
    // file as the waiver above. That is the case issue #54 is actually about:
    // an auditor reading one state file must be able to tell the two kinds of
    // record apart. Comparing records from two separate files would not show it.
    let approved_cs = coordinator_lab
        .create_change_set(
            "device-b".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    coordinator_lab
        .approve_change_set(
            approved_cs.change_set_id.clone(),
            "device-b".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            approved_cs.digest.clone(),
        )
        .await
        .expect("approve");

    // Read the state file and verify the records are distinguishable in JSON
    let state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    // Serialize the approval records to JSON
    let approved_record = state.change_sets.get(&approved_cs.change_set_id).unwrap();
    let approved_json = serde_json::to_string(&approved_record.approval).unwrap();

    // Genuine approval: has "approver", no "waived"
    assert!(
        approved_json.contains("\"approver\""),
        "genuine approval has approver field in JSON"
    );
    assert!(
        !approved_json.contains("\"waived\""),
        "genuine approval has no waived field in JSON"
    );

    let waived_record = state.change_sets.get(&waived_cs.change_set_id).unwrap();
    let waived_json = serde_json::to_string(&waived_record.approval).unwrap();

    // Waived approval: the `approver` key is absent entirely, not merely empty.
    // `skip_serializing_if` is what guarantees that, and it is the property that
    // makes a waiver impossible to mistake for an approval by a reader that only
    // checks whether the field is present.
    assert!(
        !waived_json.contains("\"approver\""),
        "waived approval must omit the approver key entirely, got: {waived_json}"
    );
    assert!(
        waived_json.contains("\"waived\""),
        "waived approval has waived field in JSON, got: {waived_json}"
    );

    // And the two records really are byte-distinct in the one file.
    assert_ne!(
        approved_json, waived_json,
        "a waiver must not serialize identically to a genuine approval"
    );
}

#[tokio::test]
async fn test_waived_record_round_trips() {
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

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create and waive
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

    coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await
        .expect("waive");

    // Reload the coordinator — validate_state is called on load. Drop the
    // first coordinator first: it holds the state file's single-writer lock
    // for its whole lifetime (MEC-540), which a second live coordinator on
    // the same path would otherwise be refused.
    drop(coordinator);
    let coordinator2 = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    // Verify the waived record is still valid
    let status = coordinator2
        .change_set_status(created.change_set_id, "device-a".to_string())
        .await
        .expect("status");

    assert_eq!(status.state, ChangeSetState::Approved);
    assert!(status.approver.is_none());
}

#[tokio::test]
async fn test_tampering_waived_record_by_inserting_approver_is_rejected() {
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

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create and waive
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

    coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await
        .expect("waive");

    // Read the state file
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    // Tamper: insert an approver to make it look like a genuine two-person approval
    let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
    if let Some(approval) = &mut record.approval {
        approval.approver = Some("bob".to_string()); // tamper
    }

    // Write the tampered state back
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write tampered state");

    // Attempt to reload — must fail. The mutual exclusion check (defect 5 fix)
    // now rejects this earlier than the digest check, which is the correct
    // behavior: a record with both approver and waived is malformed.
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("both approver and waived"),
        "Expected 'both approver and waived', got: {error_message}"
    );
}

#[tokio::test]
async fn test_only_owner_can_waive() {
    let (_dir, coordinator) = setup_coordinator(true);

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

    // Attempt to waive as bob (non-owner)
    let result = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("owner can waive"));
}

#[tokio::test]
async fn test_waiving_non_planned_change_set_is_refused() {
    let (_dir, coordinator) = setup_coordinator(true);

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create and waive as alice
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

    coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await
        .expect("waive");

    // Attempt to waive again (now in Approved state)
    let result = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("not awaiting approval"));
}

#[tokio::test]
async fn test_waiving_after_ttl_expires_is_refused() {
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

    // Use a 1-second approval TTL so it expires immediately
    let approval_ttl = Duration::from_secs(1);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator");

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

    // Wait for expiry
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Attempt to waive after expiry
    let result = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("approval window expired"));

    // Verify the change set transitioned to Expired
    let status = coordinator
        .change_set_status(created.change_set_id, "device-a".to_string())
        .await
        .expect("status");

    assert_eq!(status.state, ChangeSetState::Expired);
}

/// A waived change set must say *why* it is approved without an approver.
///
/// `approver: None` is ambiguous on its own — it means both "nobody has
/// approved this yet" and "this was deliberately approved without review", and
/// those are very different facts to an operator or a SIEM (mecmcp#94).
#[tokio::test]
async fn a_waived_change_set_reports_the_waiver_reason() {
    let (_dir, coordinator) = setup_coordinator(true);

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

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

    assert_eq!(
        created.approval_waiver, None,
        "a change set still awaiting approval must not look waived"
    );

    let waived = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await
        .expect("waive");

    assert_eq!(
        waived.approver, None,
        "no approver may be fabricated for a waived change set"
    );
    assert_eq!(
        waived.approval_waiver.as_deref(),
        Some("lab-mode"),
        "the waiver reason must reach the caller, not only the state file"
    );
}
