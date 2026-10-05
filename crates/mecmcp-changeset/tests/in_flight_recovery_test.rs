//! A change set whose apply was in flight at a crash must survive the reload.
//!
//! `load_with_recovery` settles non-terminal state at startup. For a change set
//! carrying a vendor task handle that is the wrong thing to do twice over: it
//! asserts an outcome nobody observed, and it hides the record from the caller
//! that would have gone and asked.

use mecmcp_changeset::{
    ChangeSetRecord, ChangeSetState, ChangesetCoordinator, ChangesetState, OperationLimits,
    change_set_digest,
    persistence::{read_state, write_state_for_test},
};
use std::time::Duration;

const ID: &str = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44";
const UPID: &str = "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:";

fn applying_record(task_id: Option<&str>) -> ChangeSetRecord {
    let owner = "owner-a".to_owned();
    let device = "pve3".to_owned();
    let fingerprint = format!("sha256:{}", "f".repeat(64));
    let actions = vec![serde_json::json!({"op": "destroy", "vmid": 617})];
    // Computed, not fabricated: the state file validates this digest on load,
    // and a hand-written one would fail for the wrong reason.
    let digest = change_set_digest(&owner, &device, &fingerprint, &actions).expect("digest");

    ChangeSetRecord {
        id: ID.to_owned(),
        owner,
        device,
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: ChangeSetState::Applying,
        approver: Some("approver-b".to_owned()),
        approval: None,
        expires_at_unix: u64::MAX,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: task_id.map(ToOwned::to_owned),
        apply_without_handle: false,
        owner_subject: None,
    }
}

fn write_applying(path: &std::path::Path, task_id: Option<&str>) {
    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert(ID.to_owned(), applying_record(task_id));
    write_state_for_test(path, &state, OperationLimits::default().max_state_bytes).expect("write");
}

/// The case the field exists for. A handle means the vendor operation is still
/// running, or has finished and holds its own answer — either way the record
/// must stay `Applying` so the caller can re-probe it.
#[tokio::test]
async fn an_apply_with_a_task_handle_survives_the_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    write_applying(&path, Some(UPID));

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    let records = coordinator.change_sets().await;
    let record = records.first().expect("one change set");

    assert_eq!(
        record.state,
        ChangeSetState::Applying,
        "a task-backed apply was settled at load, so nothing will ever re-probe it"
    );
    assert_eq!(
        record.task_id.as_deref(),
        Some(UPID),
        "the handle must survive alongside the state"
    );

    // The file must agree with memory, or a later load disagrees with this one.
    let on_disk = read_state(&path, OperationLimits::default().max_state_bytes).expect("read");
    assert_eq!(
        on_disk.change_sets[ID].state,
        ChangeSetState::Applying,
        "the file must match what the API reports"
    );
}

/// Without a handle there is genuinely nothing to ask, so the existing
/// behaviour stands. This pins that the fix is scoped and did not turn every
/// crashed apply into a permanent `Applying` record.
#[tokio::test]
async fn an_apply_without_a_handle_is_still_settled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    write_applying(&path, None);

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    let records = coordinator.change_sets().await;
    assert_eq!(
        records.first().expect("one change set").state,
        ChangeSetState::Failed,
        "a handleless apply has nothing to re-probe and must still be settled"
    );
}

/// An empty handle is dropped at the write boundary, not rejected at the read
/// boundary.
///
/// The distinction is the whole point. `write_state_for_test` does not validate, so
/// rejecting an empty handle on load would fire only on the *next* start and
/// would refuse the whole file — turning one bad handle into a server that
/// will not boot. Dropping it loses nothing, because an empty handle names no
/// vendor operation.
#[test]
fn an_empty_task_handle_is_dropped_on_write_and_the_file_still_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    write_applying(&path, Some(""));

    // The file must still load. A refusal here would be a boot failure.
    let state = read_state(&path, OperationLimits::default().max_state_bytes)
        .expect("a file with an empty handle must still load");

    assert_eq!(
        state.change_sets[ID].task_id, None,
        "the empty handle must have been dropped, not stored"
    );

    // And with no handle left, it writes as version 1 — an older binary can
    // still read it.
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse");
    assert_eq!(on_disk["version"], 1);
    assert!(
        on_disk["state"]["change_sets"][ID].get("task_id").is_none(),
        "task_id must be absent, not null"
    );
}

/// A file written by an older binary can still carry one, so recovery must
/// treat it as absent rather than preserve it.
#[tokio::test]
async fn recovery_settles_a_pre_existing_empty_handle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");

    // Written past the normaliser, the way an older binary would have.
    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert(ID.to_owned(), applying_record(Some("")));
    let json = serde_json::json!({ "version": 2, "state": state });
    std::fs::write(&path, serde_json::to_vec(&json).expect("serialise")).expect("write");
    // The store refuses a group- or world-readable state file, so a hand-made
    // one has to match what the library itself writes.
    std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("chmod");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("a legacy file with an empty handle must load, not brick the server");

    let records = coordinator.change_sets().await;
    assert_eq!(
        records.first().expect("one change set").state,
        ChangeSetState::Failed,
        "an empty handle has nothing to re-probe, so it must settle rather than \
         hold the pending slot forever"
    );
}

/// The API and the file must report the same record.
///
/// `write_state_for_test` normalises its own copy on the way to disk, so normalising
/// only there would leave the coordinator returning `Some("")` while the file
/// held `None` — and a restart would then observe a different record than the
/// running process reports.
#[tokio::test]
async fn the_coordinator_and_the_file_agree_after_an_empty_handle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    coordinator
        .seed_change_set_for_test(applying_record(Some("")))
        .await
        .expect("insert");

    let in_memory = coordinator.change_sets().await;
    assert_eq!(
        in_memory.first().expect("one record").task_id,
        None,
        "the coordinator handed back an empty handle it had already dropped on disk"
    );

    let on_disk = read_state(&path, OperationLimits::default().max_state_bytes).expect("read");
    assert_eq!(
        on_disk.change_sets[ID].task_id, None,
        "the file must agree with the API"
    );
}

/// Load is a boundary too, and the one an older file crosses.
///
/// A legacy record that is *not* `Applying` is never rewritten by the settling
/// loop, so without normalising on load it would keep its empty handle
/// indefinitely while `write_state_for_test` dropped it from the file — the same
/// memory/disk disagreement, on a record nothing else touches.
#[tokio::test]
async fn a_legacy_empty_handle_is_normalised_on_load_even_when_settled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");

    // An *Applied* record carrying an empty handle: terminal, so the settling
    // loop has no reason to touch it.
    let mut record = applying_record(Some(""));
    record.state = ChangeSetState::Applied;

    let mut state = ChangesetState::default();
    state.change_sets.insert(ID.to_owned(), record);
    let json = serde_json::json!({ "version": 2, "state": state });
    std::fs::write(&path, serde_json::to_vec(&json).expect("serialise")).expect("write");
    std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .expect("chmod");

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    let records = coordinator.change_sets().await;
    let loaded = records.first().expect("one record");
    assert_eq!(
        loaded.task_id, None,
        "the coordinator kept an empty handle that the file no longer has"
    );
    assert_eq!(
        loaded.state,
        ChangeSetState::Applied,
        "normalising the handle must not change the lifecycle state"
    );

    let on_disk = read_state(&path, OperationLimits::default().max_state_bytes).expect("read");
    assert_eq!(on_disk.change_sets[ID].task_id, None);
    assert_eq!(on_disk.change_sets[ID].state, ChangeSetState::Applied);
}
