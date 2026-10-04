//! Integration tests for changeset persistence and lifecycle.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    digest::{validate_digest, validate_fingerprint},
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::{read_state, validate_state, write_state_for_test},
};
use std::path::PathBuf;

/// Stage the checked-in production fixture as a private (0600) temp file.
///
/// `read_state` refuses a state file that permits group/other access, which is
/// correct for a file holding approval evidence. Git cannot preserve mode 0600,
/// so a fresh clone checks the fixture out as 0644 and reading it in place fails
/// in CI while passing on a developer box with a stricter umask. Copy it to a
/// tempdir and tighten the mode first.
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

#[test]
fn test_lifecycle_state_serialization() {
    // Test all lifecycle states round-trip through serde
    let states = [
        LifecycleState::Staging,
        LifecycleState::Staged,
        LifecycleState::Validating,
        LifecycleState::Validated,
        LifecycleState::Committing,
        LifecycleState::Committed,
        LifecycleState::Discarded,
        LifecycleState::Failed,
        LifecycleState::Indeterminate,
    ];

    for state in states {
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: LifecycleState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
        assert_eq!(serialized, format!("\"{}\"", state.as_str()));
    }
}

#[test]
fn test_lifecycle_state_terminal() {
    assert!(LifecycleState::Committed.terminal());
    assert!(LifecycleState::Discarded.terminal());
    assert!(!LifecycleState::Staging.terminal());
    assert!(!LifecycleState::Staged.terminal());
    assert!(!LifecycleState::Validating.terminal());
    assert!(!LifecycleState::Validated.terminal());
    assert!(!LifecycleState::Committing.terminal());
    assert!(!LifecycleState::Failed.terminal());
    assert!(!LifecycleState::Indeterminate.terminal());
}

#[test]
fn test_changeset_state_serialization() {
    // Test all changeset states round-trip through serde
    let states = [
        ChangeSetState::Planned,
        ChangeSetState::Approved,
        ChangeSetState::Applying,
        ChangeSetState::Applied,
        ChangeSetState::Expired,
        ChangeSetState::Failed,
    ];

    for state in states {
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: ChangeSetState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
        assert_eq!(serialized, format!("\"{}\"", state.as_str()));
    }
}

#[test]
fn test_version_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Version 9 is the first unsupported one: 1-8 are readable. 4 became valid
    // with the unambiguous approval digest (mecmcp#283), 5 with the handleless
    // apply marker, 6 with the approval digest that binds the preview
    // (rustproxmoxmcp#56), 7 with the keyed approval digest (MEC-457), and 8
    // with the verified-approver identity fields (MEC-994). The point of this
    // test is that an *unknown future* version is refused rather than guessed
    // at, so it tracks the top of the supported range and moves with it.
    let invalid_version = serde_json::json!({
        "version": 9,
        "state": {
            "operations": {},
            "change_sets": {}
        }
    });
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&invalid_version).unwrap(),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Attempt to read it
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("unsupported changeset state version 9"),
        "Expected version error, got: {error_message}"
    );
}

#[test]
fn test_bare_operations_rejected() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Write a bare operations object without version wrapper
    let bare_format = serde_json::json!({
        "operations": {},
        "change_sets": {}
    });
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&bare_format).unwrap(),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Attempt to read it - should fail because version field is missing
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("invalid changeset state JSON"),
        "Expected JSON parse error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_uppercase() {
    let uppercase_digest =
        "sha256:ABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB";
    let result = validate_digest(uppercase_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected lowercase hex error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_short() {
    let short_digest = "sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890a"; // 63 chars
    let result = validate_digest(short_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected format error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_sha512_prefix() {
    let sha512_digest = "sha512:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    let result = validate_digest(sha512_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected sha256 prefix error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_uppercase() {
    let uppercase_fp = "sha256:ABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB";
    let result = validate_fingerprint(uppercase_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected lowercase hex error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_short() {
    let short_fp = "sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890a"; // 63 chars
    let result = validate_fingerprint(short_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected format error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_sha512_prefix() {
    let sha512_fp = "sha512:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    let result = validate_fingerprint(sha512_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected sha256 prefix error, got: {error_message}"
    );
}

#[test]
fn test_production_fixture_round_trip() {
    // This is THE critical test: the production file from LXC 608 must round-trip
    let (_fixture_dir, fixture_path) = staged_production_fixture();

    // Read the production fixture
    let state = read_state(&fixture_path, 8 * 1024 * 1024)
        .expect("production fixture must parse without error");

    // Verify exactly 6 operations and 6 change sets survive
    assert_eq!(
        state.operations.len(),
        6,
        "expected 6 operations from production fixture"
    );
    assert_eq!(
        state.change_sets.len(),
        6,
        "expected 6 change sets from production fixture"
    );

    // Verify all change sets have owner != approver, non-empty digest and fingerprint
    for (id, change_set) in &state.change_sets {
        assert!(
            change_set.approver.is_some(),
            "change set {id} must have an approver"
        );
        let approver = change_set.approver.as_ref().unwrap();
        assert_ne!(
            &change_set.owner, approver,
            "change set {id} owner and approver must be distinct"
        );
        assert!(
            !change_set.digest.is_empty(),
            "change set {id} must have a non-empty digest"
        );
        assert!(
            !change_set.expected_candidate_fingerprint.is_empty(),
            "change set {id} must have a non-empty fingerprint"
        );

        // Verify the digest is valid format
        validate_digest(&change_set.digest, "digest").expect("change set digest must be valid");

        // Note: We do NOT recompute the digest here because the actions are stored as
        // serde_json::Value, but the original digest was computed from vendor-specific
        // action types (PAN-OS ChangeSetAction). The serialization might differ due to
        // field ordering. Digest recomputation will be in Task 4 when we have the
        // full coordinator with vendor-specific action types.
    }

    // Read the original file as JSON for semantic comparison
    let original_bytes = std::fs::read(&fixture_path).unwrap();
    let original_value: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();

    // Re-serialize the parsed state
    let reserialized = serde_json::to_vec_pretty(&serde_json::json!({
        "version": 1,
        "state": state
    }))
    .unwrap();
    let reserialized_value: serde_json::Value = serde_json::from_slice(&reserialized).unwrap();

    // Compare as parsed JSON values (key order doesn't matter)
    assert_eq!(
        original_value, reserialized_value,
        "round-trip must produce semantically equal JSON"
    );
}

#[test]
fn test_state_validation() {
    let (_fixture_dir, fixture_path) = staged_production_fixture();

    let state = read_state(&fixture_path, 8 * 1024 * 1024).unwrap();

    // validate_state should pass for the production fixture
    validate_state(&state, 2).expect("production fixture must pass validation");
}

#[test]
fn test_round_trip_write_read() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Create a minimal valid state
    let state = mecmcp_changeset::ChangesetState {
        operations: Default::default(),
        change_sets: Default::default(),
    };

    // Write it
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write must succeed");

    // Read it back
    let loaded = read_state(&state_path, 8 * 1024 * 1024).expect("read must succeed");

    // Verify it matches
    assert_eq!(state.operations.len(), loaded.operations.len());
    assert_eq!(state.change_sets.len(), loaded.change_sets.len());
}

#[test]
fn test_tamper_detection_rejects_modified_actions() {
    // Load the production fixture
    let (_fixture_dir, fixture_path) = staged_production_fixture();

    // First verify the unmodified fixture loads successfully
    let original_state = read_state(&fixture_path, 8 * 1024 * 1024)
        .expect("unmodified production fixture must load");
    assert_eq!(original_state.change_sets.len(), 6);

    // Now tamper with one change set's actions in memory
    let temp_dir = tempfile::tempdir().unwrap();
    let tampered_path = temp_dir.path().join("tampered.json");

    let mut tampered_state = original_state.clone();
    // Modify the first change set's first action's xpath
    let first_change_set_id = tampered_state.change_sets.keys().next().unwrap().clone();
    let first_change_set = tampered_state
        .change_sets
        .get_mut(&first_change_set_id)
        .unwrap();
    if let Some(obj) = first_change_set
        .actions
        .get_mut(0)
        .and_then(|action| action.as_object_mut())
    {
        // Change the xpath value - this will invalidate the digest
        obj.insert(
            "xpath".to_string(),
            serde_json::Value::String("/tampered/xpath".to_string()),
        );
    }

    // Write the tampered state
    write_state_for_test(&tampered_path, &tampered_state, 8 * 1024 * 1024)
        .expect("write tampered state");

    // Attempt to read it - should fail with digest mismatch
    let result = read_state(&tampered_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("changeset state change-set digest mismatch"),
        "Expected digest mismatch error, got: {error_message}"
    );
}

#[test]
fn test_action_key_order_preserved() {
    // This test proves that preserve_order is working. Without it, serde_json::Value
    // uses BTreeMap which sorts keys alphabetically, breaking digest verification.

    let (_fixture_dir, fixture_path) = staged_production_fixture();

    // Read the production fixture
    let state = read_state(&fixture_path, 8 * 1024 * 1024).expect("production fixture must load");

    // Get a change set with actions
    let change_set = state.change_sets.values().next().unwrap();
    assert!(!change_set.actions.is_empty());

    let first_action = &change_set.actions[0];

    // Serialize the action
    let serialized = serde_json::to_string(first_action).unwrap();

    // The keys should appear in struct declaration order: action, xpath, element, destructive_confirmation
    // NOT alphabetically: action, destructive_confirmation, element, xpath
    // Check that "action" appears before "xpath" in the serialized form
    let action_pos = serialized.find("\"action\"").unwrap();
    let xpath_pos = serialized.find("\"xpath\"").unwrap();
    assert!(
        action_pos < xpath_pos,
        "Keys must preserve insertion order (action before xpath), not alphabetical order"
    );

    // Round-trip through write and read
    let temp_dir = tempfile::tempdir().unwrap();
    let roundtrip_path = temp_dir.path().join("roundtrip.json");
    write_state_for_test(&roundtrip_path, &state, 8 * 1024 * 1024).expect("write must succeed");
    let reloaded = read_state(&roundtrip_path, 8 * 1024 * 1024).expect("read must succeed");

    // Get the same change set after round-trip
    let reloaded_change_set = reloaded.change_sets.get(&change_set.id).unwrap();
    let reloaded_action = &reloaded_change_set.actions[0];

    // Serialize again
    let reloaded_serialized = serde_json::to_string(reloaded_action).unwrap();

    // The serialized form must be identical (same key order)
    assert_eq!(
        serialized, reloaded_serialized,
        "Action serialization must preserve key order across round-trip"
    );
}

/// The production fixture is evidence, and evidence must not be edited to suit
/// the code under test.
///
/// `mutation-state-608.json` is a verbatim copy of the live state file from
/// LXC 608. Its whole value is that it was written by the deployed PAN-OS
/// server and not by us: it is how this crate proves it can still load what is
/// actually on disk out there. A change that makes the fixture parse by
/// changing the fixture proves nothing at all.
///
/// This already happened once. A required `policy_signature` was added to
/// `ChangeSetRecord`, and rather than the field being made optional, the six
/// real change sets in this file were each given a fabricated all-zeros
/// signature so deserialization would succeed. The compatibility tests passed
/// and the coordinator would still have failed to start against the real file.
///
/// If this test fails, do not update the hash. Work out why the fixture needed
/// to change, and fix the code instead.
#[test]
fn production_fixture_is_unmodified() {
    use sha2::{Digest, Sha256};

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/compat/mutation-state-608.json");
    let bytes = std::fs::read(&fixture_path).expect("read production fixture");
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));

    assert_eq!(
        digest, "sha256:0123357eb0b55e6a9433f9477ff24411304e8a2278330223b939fc4a9e2e6c06",
        "the LXC 608 production fixture has been modified. It is a verbatim \
         copy of a live state file and is the only evidence this crate can \
         load real deployed state — if the code cannot parse it, change the \
         code, not the fixture."
    );
}
