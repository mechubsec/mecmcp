//! Tests for defects 4 and 5 in the waiver migration logic.
//!
//! Defect 4: The migration launders unauthenticated text into authenticated evidence.
//! The legacy v1/v2 digest doesn't cover `reason`, so edited text gets promoted to
//! signed v3 evidence on migration.
//!
//! Defect 5: The migration corrupts a genuine approval that has a `waived` object
//! injected. A record with both approver and waived passes validation (takes the
//! approver branch), then the migration overwrites the approver digest with a waiver
//! digest, making the file unloadable.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ApprovalRecord, ChangeSetRecord, ChangeSetState, WaiverKind, WaiverRecord,
    digest::{
        change_set_digest, compute_approval_digest_v4 as compute_approval_digest,
        compute_waiver_digest,
    },
    persistence::{ChangesetState, read_state},
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

/// Defect 4: A v1/v2 waiver with edited reason text must be rejected on load.
///
/// The legacy digest doesn't cover `reason`, so it can be edited freely. The
/// migration then computes a v3 digest that includes `reason`, promoting
/// unauthenticated text into signed evidence. This test ensures the check
/// rejects such files.
#[test]
fn defect_4_edited_reason_is_rejected_on_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    // Create a v1/v2 waiver with the edited reason
    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];
    let actions_json: Vec<serde_json::Value> = actions
        .into_iter()
        .map(|a| serde_json::to_value(a).expect("serialize"))
        .collect();

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let owner = "alice".to_string();
    let device = "device-a".to_string();
    let fingerprint = test_fingerprint();
    let approved_at = 1700000000u64;

    let digest =
        change_set_digest(&owner, &device, &fingerprint, &actions_json).expect("change_set_digest");

    // Compute the legacy waiver digest (which doesn't cover reason)
    let waiver_digest = compute_waiver_digest(&change_set_id, &digest, &owner, approved_at);

    // Create a waiver with EDITED reason text (not "lab-mode")
    let waiver = WaiverRecord {
        kind: WaiverKind::LabMode,
        reason: "edited-by-attacker".to_owned(), // ← the tampering
        expires_at_unix: None,
        ticket: None,
    };

    let record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: owner.clone(),
        device: device.clone(),
        expected_candidate_fingerprint: fingerprint,
        actions: actions_json,
        digest: digest.clone(),
        state: ChangeSetState::Approved,
        approver: None,
        approval: Some(ApprovalRecord {
            approver: None,
            approved_at_unix: approved_at,
            digest: waiver_digest,
            digest_version: 4,
            waived: Some(waiver),
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        expires_at_unix: approved_at + 3600,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id.clone(), record);
    let state = ChangesetState {
        operations: BTreeMap::new(),
        change_sets,
    };

    // Write as version 2 (legacy)
    let on_disk = serde_json::json!({
        "version": 2,
        "state": state
    });
    let bytes = serde_json::to_vec_pretty(&on_disk).expect("serialize");
    std::fs::write(&state_path, bytes).expect("write");

    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }

    // Attempt to load — must fail with the defect 4 check
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err(), "Expected rejection of edited reason");
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("unexpected reason"),
        "Expected 'unexpected reason' error, got: {error_message}"
    );
}

/// Defect 5: A record with both approver and waived must be rejected.
///
/// The validation logic checks approver first, so a record with both passes
/// validation. The migration then overwrites the approver digest with a waiver
/// digest, corrupting the record.
#[test]
fn defect_5_both_approver_and_waived_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];
    let actions_json: Vec<serde_json::Value> = actions
        .into_iter()
        .map(|a| serde_json::to_value(a).expect("serialize"))
        .collect();

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let owner = "alice".to_string();
    let approver = "bob".to_string();
    let device = "device-a".to_string();
    let fingerprint = test_fingerprint();
    let approved_at = 1700000000u64;

    let digest =
        change_set_digest(&owner, &device, &fingerprint, &actions_json).expect("change_set_digest");

    // Compute a VALID approver digest
    let approval_digest =
        compute_approval_digest(&change_set_id, &digest, &owner, &approver, approved_at);

    // Create an injected waiver
    let waiver = WaiverRecord {
        kind: WaiverKind::LabMode,
        reason: "lab-mode".to_owned(),
        expires_at_unix: None,
        ticket: None,
    };

    let record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: owner.clone(),
        device: device.clone(),
        expected_candidate_fingerprint: fingerprint,
        actions: actions_json,
        digest: digest.clone(),
        state: ChangeSetState::Approved,
        approver: Some(approver.clone()),
        approval: Some(ApprovalRecord {
            approver: Some(approver), // ← valid approver
            approved_at_unix: approved_at,
            digest: approval_digest, // ← valid approver digest
            digest_version: 4,
            waived: Some(waiver), // ← INJECTED waiver
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        expires_at_unix: approved_at + 3600,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id.clone(), record);
    let state = ChangesetState {
        operations: BTreeMap::new(),
        change_sets,
    };

    // Write as version 2
    let on_disk = serde_json::json!({
        "version": 2,
        "state": state
    });
    let bytes = serde_json::to_vec_pretty(&on_disk).expect("serialize");
    std::fs::write(&state_path, bytes).expect("write");

    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }

    // Attempt to load — must fail with mutual exclusion check
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(
        result.is_err(),
        "Expected rejection of both approver and waived"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("both approver and waived"),
        "Expected 'both approver and waived' error, got: {error_message}"
    );
}
