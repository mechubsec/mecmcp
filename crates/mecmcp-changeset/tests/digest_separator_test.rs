//! Digest separator validation (interim mitigation for #283).
//!
//! `compute_approval_digest` and `compute_waiver_digest` join fields with a literal
//! `|` separator. If a principal identifier (owner or approver) contains `|`, two
//! different pairings hash identically:
//!
//! ```text
//! owner="a|b", approver="c"   ->  id|plan|a|b|c|timestamp
//! owner="a",   approver="b|c" ->  id|plan|a|b|c|timestamp
//! ```
//!
//! This is the opposite of tamper-evidence. The full fix (#283) is a versioned
//! tuple encoding; this test covers the interim mitigation that rejects `|` in
//! principals at both creation and load.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, ChangesetState as StateFile, OperationLimits,
    digest::{
        compute_approval_digest_legacy, compute_approval_digest_v4 as compute_approval_digest,
        validate_principal_for_digest,
    },
    persistence::{read_state, write_state_for_test},
    records::{ApprovalRecord, ChangeSetRecord},
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};

/// Write a state file at an explicit legacy schema version.
///
/// `write_state_for_test` stamps version 4 for any record carrying a real approval
/// (mecmcp#283), so it cannot produce the legacy shape these tests are about.
/// The separator rule now guards exactly one thing: verification of a record
/// written *before* v4, whose digest is the ambiguous `|`-joined encoding.
fn write_legacy_state_file(path: &std::path::Path, version: u64, state: &StateFile) {
    let payload = json!({
        "version": version,
        "state": {
            "operations": state.operations,
            "change_sets": state.change_sets,
        }
    });
    std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
    // `read_state` refuses a group- or world-readable state file, and it is
    // right to: this holds approval evidence.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

use tempfile::TempDir;

const LIMIT: u64 = 1024 * 1024;

/// Test action type.
#[derive(Debug, Clone, serde::Serialize)]
struct TestAction {
    action: String,
}

/// Documents the collision: two distinct pairings produce the same digest under
/// the current `|`-joined encoding. This test must continue to pass — it is a
/// statement about the encoding, not a bug to fix here. The full fix is #283.
#[test]
fn collision_exists_with_separator_in_principals() {
    let digest_a = compute_approval_digest_legacy("id", "plan", "a|b", "c", 1234567890);
    let digest_b = compute_approval_digest_legacy("id", "plan", "a", "b|c", 1234567890);
    assert_eq!(
        digest_a, digest_b,
        "the collision proves why the guard is needed"
    );
}

/// The validator rejects `|` in a principal identifier.
#[test]
fn validator_rejects_separator() {
    let result = validate_principal_for_digest("test_field", "foo|bar");
    assert!(result.is_err(), "value containing '|' must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("test_field"),
        "error must name the field: {err}"
    );
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
    assert!(
        err.contains("ambiguous"),
        "error must explain the consequence: {err}"
    );
}

/// The validator accepts a clean principal.
#[test]
fn validator_accepts_clean_principal() {
    assert!(
        validate_principal_for_digest("owner", "demo-agent").is_ok(),
        "clean owner must pass"
    );
    assert!(
        validate_principal_for_digest("approver", "demo-approver").is_ok(),
        "clean approver must pass"
    );
    assert!(
        validate_principal_for_digest("owner", "mechubbench").is_ok(),
        "another clean owner must pass"
    );
    assert!(
        validate_principal_for_digest("approver", "claude-reviewer").is_ok(),
        "another clean approver must pass"
    );
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn setup_coordinator() -> (TempDir, ChangesetCoordinator) {
    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(3600);

    let coord = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    (dir, coord)
}

/// Creating an approval with `|` in the approver is refused.
#[tokio::test]
async fn approval_creation_rejects_separator_in_approver() {
    let (_dir, coord) = setup_coordinator();

    let actions = vec![TestAction {
        action: "test".into(),
    }];

    let plan_result = coord
        .create_change_set(
            "device1".into(),
            actions,
            "clean-owner".into(),
            test_fingerprint(),
            "policy-sig".into(),
            None,
        )
        .await;
    assert!(plan_result.is_ok(), "plan with clean owner must succeed");
    let created = plan_result.unwrap();

    let approve_result = coord
        .approve_change_set(
            created.change_set_id.clone(),
            "device1".into(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bad|approver".into(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await;
    assert!(
        approve_result.is_err(),
        "approval with separator in approver must be rejected"
    );
    let err = approve_result.unwrap_err().to_string();
    assert!(err.contains("approver"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Creating an approval with `|` in the owner (inherited from the change set) is refused.
#[tokio::test]
async fn approval_creation_rejects_separator_in_owner() {
    let (_dir, coord) = setup_coordinator();

    let actions = vec![TestAction {
        action: "test".into(),
    }];

    let plan_result = coord
        .create_change_set(
            "device1".into(),
            actions,
            "bad|owner".into(),
            test_fingerprint(),
            "policy-sig".into(),
            None,
        )
        .await;
    assert!(plan_result.is_ok(), "plan can be created");
    let created = plan_result.unwrap();

    let approve_result = coord
        .approve_change_set(
            created.change_set_id.clone(),
            "device1".into(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "clean-approver".into(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await;
    assert!(
        approve_result.is_err(),
        "approval must be rejected when owner has separator"
    );
    let err = approve_result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a state file with `|` in the approver is refused.
#[test]
fn load_rejects_separator_in_approver() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest = mecmcp_changeset::digest::change_set_digest(
        "clean-owner",
        "device1",
        &fingerprint,
        &actions,
    )
    .unwrap();

    // Hand-craft a state file with a bad approver.
    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "clean-owner".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("bad|approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };
    let digest = compute_approval_digest_legacy(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "bad|approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("bad|approver".into()),
        approved_at_unix: 1234567890,
        digest,
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    // Version 3: the last schema whose approvals used the `|`-joined encoding.
    write_legacy_state_file(&path, 3, &state);

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading state with separator in approver must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("approver"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a state file with `|` in the owner is refused.
#[test]
fn load_rejects_separator_in_owner() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000002".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest =
        mecmcp_changeset::digest::change_set_digest("bad|owner", "device1", &fingerprint, &actions)
            .unwrap();

    // Hand-craft a state file with a bad owner.
    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "bad|owner".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("clean-approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };
    let digest = compute_approval_digest_legacy(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "clean-approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("clean-approver".into()),
        approved_at_unix: 1234567890,
        digest,
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    // Version 3: the last schema whose approvals used the `|`-joined encoding.
    write_legacy_state_file(&path, 3, &state);

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading state with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a v2 legacy waiver with `|` in the owner (with waived field) is refused.
///
/// Covers `persistence.rs:305` — the version < 3 path with a `waived` field present.
/// The fixture digest is valid for the piped owner, computed independently:
/// `printf '%s' '...|test|owner|...' | sha256sum`
#[test]
fn load_rejects_separator_in_owner_for_legacy_waiver_with_waived() {
    let fixture = include_str!("fixtures/waiver-v2-piped-owner.json");
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, fixture).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading v2 waiver with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a v2 legacy waiver with `|` in the owner (without waived field) is refused.
///
/// Covers `persistence.rs:316` — the `else` branch when `approval.waived` is absent.
/// The fixture digest is valid for the piped owner, computed independently:
/// `printf '%s' '...|bad|owner|...' | sha256sum`
#[test]
fn load_rejects_separator_in_owner_for_legacy_waiver_without_waived() {
    let fixture = include_str!("fixtures/waiver-v2-piped-owner-no-waived.json");
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, fixture).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading v2 waiver (no waived field) with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// A normal approval with clean values loads successfully.
#[test]
fn load_accepts_clean_approval() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000004".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest = mecmcp_changeset::digest::change_set_digest(
        "demo-agent",
        "device1",
        &fingerprint,
        &actions,
    )
    .unwrap();

    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "demo-agent".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("demo-approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };
    // What a current writer produces. `write_state_for_test` stamps version 4 for any
    // real approval, and v4 files verify under the tuple encoding.
    let digest = compute_approval_digest(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "demo-approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("demo-approver".into()),
        approved_at_unix: 1234567890,
        digest,
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    write_state_for_test(&path, &state, LIMIT).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_ok(),
        "clean approval must load: {:?}",
        result.unwrap_err()
    );
}

/// Validates all 10 real approval records from the live fleet (verified 2026-08-15).
#[test]
fn real_fleet_approvals_are_clean() {
    // LXC 950: 3 records (demo-agent/demo-approver)
    assert!(validate_principal_for_digest("owner", "demo-agent").is_ok());
    assert!(validate_principal_for_digest("approver", "demo-approver").is_ok());

    // LXC 960: 7 records
    // - 4 mechubbench/demo-approver
    assert!(validate_principal_for_digest("owner", "mechubbench").is_ok());
    assert!(validate_principal_for_digest("approver", "demo-approver").is_ok());

    // - 3 claude-writer/claude-reviewer
    assert!(validate_principal_for_digest("owner", "claude-writer").is_ok());
    assert!(validate_principal_for_digest("approver", "claude-reviewer").is_ok());
}

// ---- mecmcp#283: the encoding fix itself ----

/// The ambiguity the v4 encoding exists to remove.
///
/// Under the legacy encoding these two pairings hash identically, so an approval
/// digest was valid for a pairing it was never computed for. Asserting the
/// legacy collision as well as the v4 separation keeps the defect visible: if
/// someone "fixes" the legacy function instead of migrating, this test says so.
#[test]
fn v4_distinguishes_pairings_the_legacy_encoding_conflated() {
    let legacy_split_owner = compute_approval_digest_legacy("cs", "sha256:plan", "a|b", "c", 1);
    let legacy_split_approver = compute_approval_digest_legacy("cs", "sha256:plan", "a", "b|c", 1);
    assert_eq!(
        legacy_split_owner, legacy_split_approver,
        "the legacy encoding is ambiguous — that is the defect being migrated away from"
    );

    let split_owner = compute_approval_digest("cs", "sha256:plan", "a|b", "c", 1);
    let split_approver = compute_approval_digest("cs", "sha256:plan", "a", "b|c", 1);
    assert_ne!(
        split_owner, split_approver,
        "a serialized tuple encodes lengths, so no value can shift a boundary"
    );
}

/// Deterministic, and every field is bound.
#[test]
fn v4_is_stable_and_binds_every_field() {
    use compute_approval_digest as v4;

    let base = v4("cs", "sha256:plan", "owner", "approver", 7);
    assert_eq!(base, v4("cs", "sha256:plan", "owner", "approver", 7));
    for altered in [
        v4("other", "sha256:plan", "owner", "approver", 7),
        v4("cs", "sha256:other", "owner", "approver", 7),
        v4("cs", "sha256:plan", "other", "approver", 7),
        v4("cs", "sha256:plan", "owner", "other", 7),
        v4("cs", "sha256:plan", "owner", "approver", 8),
    ] {
        assert_ne!(base, altered, "every field must change the digest");
    }
}

/// v4 must not reproduce the legacy value: the marker and the encoding both
/// differ, so a legacy digest can never be presented as a v4 one.
#[test]
fn v4_never_equals_the_legacy_digest_for_the_same_inputs() {
    let legacy = compute_approval_digest_legacy("cs", "sha256:plan", "owner", "approver", 7);
    let v4 = compute_approval_digest("cs", "sha256:plan", "owner", "approver", 7);
    assert_ne!(legacy, v4);
}

/// A legacy approval must survive the upgrade, and come out re-signed.
///
/// This is the migration the fleet actually performs: ten real approval records
/// exist across LXC 950 and 960 (960 still on schema v1), all written under the
/// `|`-joined encoding. They verify under the legacy rule on load, are re-signed
/// to v4 in memory, and the next write stamps version 4 — so the following load
/// verifies under the tuple rule and still passes.
///
/// Re-signing launders nothing: the legacy digest already covered all five
/// fields v4 binds, so nothing previously unsigned is promoted. That is the
/// difference from the waiver migration, whose `reason` was outside the legacy
/// digest and needed a guard.
#[test]
fn a_legacy_approval_migrates_to_v4_and_still_verifies() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000009".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest = mecmcp_changeset::digest::change_set_digest(
        "demo-agent",
        "device1",
        &fingerprint,
        &actions,
    )
    .unwrap();

    let legacy_digest = compute_approval_digest_legacy(
        &change_set_id,
        &plan_digest,
        "demo-agent",
        "demo-approver",
        1234567890,
    );

    let record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "demo-agent".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("demo-approver".into()),
        approval: Some(ApprovalRecord {
            approver: Some("demo-approver".into()),
            approved_at_unix: 1234567890,
            digest: legacy_digest.clone(),
            digest_version: 4,
            waived: None,
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id.clone(), record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    // Schema v1, as LXC 960 holds today.
    write_legacy_state_file(&path, 1, &state);

    let loaded = read_state(&path, LIMIT).expect("a legacy approval must still load");
    let migrated = loaded.change_sets[&change_set_id]
        .approval
        .as_ref()
        .expect("approval");
    assert_ne!(
        migrated.digest, legacy_digest,
        "the record must be re-signed on load, or the next write leaves the file incoherent"
    );
    assert_eq!(
        migrated.digest,
        compute_approval_digest(
            &change_set_id,
            &plan_digest,
            "demo-agent",
            "demo-approver",
            1234567890,
        ),
        "re-signed under v4 over the same inputs"
    );

    // The round trip a running server performs: write what was loaded, read it
    // back. This is what fails if the migration is missing.
    write_state_for_test(&path, &loaded, LIMIT).unwrap();
    read_state(&path, LIMIT).expect("the migrated file must verify under v4");
}
