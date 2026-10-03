//! An expired change set must not lock a principal out of its device (#193).
//!
//! Reported downstream as rustjunosmcp#255 against a live `vsrx-ci` deployment.
//! The guard lives here, so PAN-OS had the same gap — the reporter escaped only
//! by reading the state file on the container, which is not an API.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetRecord, ChangeSetState, ChangesetCoordinator, OperationLimits, change_set_digest,
};
use std::time::Duration;

const APPROVAL_TTL: Duration = Duration::from_secs(900);

fn load_coordinator(dir: &tempfile::TempDir) -> ChangesetCoordinator {
    ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        APPROVAL_TTL,
        false,
    )
    .unwrap()
}

/// A change set for `owner`/`device` that expires at `expires_at_unix`.
fn record(
    id_seed: &str,
    owner: &str,
    device: &str,
    state: ChangeSetState,
    expires_at_unix: u64,
) -> ChangeSetRecord {
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = change_set_digest(owner, device, &fingerprint, &actions).unwrap();
    ChangeSetRecord {
        id: format!("{id_seed:0>64}"),
        owner: owner.to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state,
        approver: None,
        approval: None,
        expires_at_unix,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The lockout itself: a stale record must not block a new change set.
#[tokio::test]
async fn an_expired_change_set_does_not_block_a_new_one() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    // Approved but long past its deadline — the state a change set is left in
    // when it expires without anyone attempting an apply.
    let stale = record(
        "a",
        "alice",
        "fw-01",
        ChangeSetState::Approved,
        now() - 3600,
    );
    coordinator.seed_change_set_for_test(stale).await.unwrap();

    let fresh = record("b", "alice", "fw-01", ChangeSetState::Planned, now() + 900);
    coordinator
        .insert_change_set(fresh)
        .await
        .expect("an expired change set must not lock the principal out");
}

/// A live pending change set must still block — the guard's actual purpose.
#[tokio::test]
async fn a_live_change_set_still_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let live = record("a", "alice", "fw-01", ChangeSetState::Approved, now() + 900);
    coordinator.seed_change_set_for_test(live).await.unwrap();

    let second = record("b", "alice", "fw-01", ChangeSetState::Planned, now() + 900);
    let error = coordinator.insert_change_set(second).await.unwrap_err();
    assert_eq!(error.field(), "change_set_id");
}

/// The refusal must name the blocker, or the operator has no next step.
#[tokio::test]
async fn the_refusal_names_the_blocking_change_set() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let live = record("a", "alice", "fw-01", ChangeSetState::Approved, now() + 900);
    let blocking_id = live.id.clone();
    coordinator.seed_change_set_for_test(live).await.unwrap();

    let second = record("b", "alice", "fw-01", ChangeSetState::Planned, now() + 900);
    let error = coordinator.insert_change_set(second).await.unwrap_err();

    let message = error.message();
    assert!(
        message.contains(&blocking_id),
        "the refusal must name the id; got: {message}"
    );
    assert!(
        message.contains("Approved"),
        "the refusal must name the state; got: {message}"
    );
    assert!(
        message.contains("expires at unix"),
        "the refusal must say when it expires; got: {message}"
    );
}

/// The expiry sweep must be durable, not merely ignored in the guard.
///
/// A record left `Approved` forever also never becomes eligible for the
/// capacity eviction, which retains only terminal states — so ignoring it in
/// the guard alone would leak store capacity.
#[tokio::test]
async fn expiring_a_change_set_is_persisted_and_visible() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let stale = record(
        "a",
        "alice",
        "fw-01",
        ChangeSetState::Approved,
        now() - 3600,
    );
    let stale_id = stale.id.clone();
    coordinator.seed_change_set_for_test(stale).await.unwrap();

    // Any insert triggers the sweep.
    let fresh = record("b", "alice", "fw-01", ChangeSetState::Planned, now() + 900);
    coordinator.insert_change_set(fresh).await.unwrap();

    let listed = coordinator.change_sets().await;
    let swept = listed
        .iter()
        .find(|c| c.id == stale_id)
        .expect("still present");
    assert_eq!(
        swept.state,
        ChangeSetState::Expired,
        "the stale record must be transitioned, not just skipped"
    );

    // And it survived a reload, so the file agrees with memory. Drop the
    // first coordinator first: it holds the state file's single-writer lock
    // for its whole lifetime (MEC-540), which this reload would otherwise
    // be refused against.
    drop(coordinator);
    let reloaded = load_coordinator(&dir);
    let after = reloaded.change_sets().await;
    let persisted = after.iter().find(|c| c.id == stale_id).expect("persisted");
    assert_eq!(persisted.state, ChangeSetState::Expired);
}

/// Enumeration is what makes the other two fixes reachable by an operator.
#[tokio::test]
async fn change_sets_can_be_enumerated() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);
    assert!(coordinator.change_sets().await.is_empty());

    coordinator
        .insert_change_set(record(
            "a",
            "alice",
            "fw-01",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .unwrap();
    coordinator
        .insert_change_set(record(
            "b",
            "bob",
            "fw-02",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .unwrap();

    let listed = coordinator.change_sets().await;
    assert_eq!(listed.len(), 2);
    // Returned as stored: filtering by device or owner is the consumer's scope
    // policy, not this crate's.
    let mut devices: Vec<&str> = listed.iter().map(|c| c.device.as_str()).collect();
    devices.sort_unstable();
    assert_eq!(devices, vec!["fw-01", "fw-02"]);
}

/// The per-principal scope is unchanged: a different owner was never blocked.
#[tokio::test]
async fn a_different_principal_is_unaffected() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    coordinator
        .seed_change_set_for_test(record(
            "a",
            "alice",
            "fw-01",
            ChangeSetState::Approved,
            now() + 900,
        ))
        .await
        .unwrap();

    coordinator
        .insert_change_set(record(
            "b",
            "bob",
            "fw-01",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .expect("the guard is per principal and device");
}

/// The deadline retires an unused approval, not a running apply.
///
/// `Applying` means a device transaction is in flight against the record. The
/// first version of the sweep used the same predicate as the blocking guard, so
/// an apply that crossed its TTL mid-flight — waiting on `stage()`, say — was
/// rewritten to `Expired` by any concurrent create. That freed the slot for a
/// second change set on the same principal and device and made the live record
/// evictable, so a crash left the running operation paired with an expired or
/// absent change set instead of the `Failed` state restart recovery assigns.
#[tokio::test]
async fn an_applying_change_set_is_not_retired_by_its_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let in_flight = record(
        "a",
        "alice",
        "fw-01",
        ChangeSetState::Applying,
        now() - 3600, // past its deadline, but the apply is still running
    );
    let in_flight_id = in_flight.id.clone();
    coordinator
        .seed_change_set_for_test(in_flight)
        .await
        .unwrap();

    // A concurrent create must not free the slot out from under the apply.
    let error = coordinator
        .insert_change_set(record(
            "b",
            "alice",
            "fw-01",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("already has a pending change set"),
        "got {error}"
    );

    let states = coordinator.change_sets().await;
    let live = states
        .iter()
        .find(|existing| existing.id == in_flight_id)
        .expect("the in-flight record must still be in the store");
    assert_eq!(
        live.state,
        ChangeSetState::Applying,
        "the deadline must not rewrite a record whose apply is in flight"
    );
}

/// The sweep is durable even when the insert that triggered it is refused.
///
/// Every check after the sweep returns early. Writing the expirations only on
/// the success path left memory reporting `Expired` while the file still said
/// `Approved`, so a restart resurrected the very blocker the sweep had just
/// retired — the #193 lockout, with the fix in place.
#[tokio::test]
async fn a_sweep_survives_a_refused_insert() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    // The blocker goes in first, and the stale record second. Order matters: a
    // later *successful* insert runs the same sweep and persists it on its own
    // success path, which would hide the bug this test exists for. The refused
    // insert below must be the first one whose sweep touches the stale record.
    let blocker = record("b", "bob", "fw-02", ChangeSetState::Planned, now() + 900);
    coordinator.seed_change_set_for_test(blocker).await.unwrap();

    // Retired by the sweep: past its deadline, owned by someone else. Already
    // stale when inserted — the sweep runs over the records already in the store,
    // so it does not retire the one being added.
    let stale = record(
        "a",
        "alice",
        "fw-01",
        ChangeSetState::Approved,
        now() - 3600,
    );
    let stale_id = stale.id.clone();
    coordinator.seed_change_set_for_test(stale).await.unwrap();

    coordinator
        .insert_change_set(record(
            "c",
            "bob",
            "fw-02",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .unwrap_err();

    // Reload from the file, which is what a restart sees. Drop the first
    // coordinator first: it holds the state file's single-writer lock for
    // its whole lifetime (MEC-540), which this reload would otherwise be
    // refused against.
    drop(coordinator);
    let restarted = load_coordinator(&dir);
    let states = restarted.change_sets().await;
    let stale = states
        .iter()
        .find(|existing| existing.id == stale_id)
        .expect("the retired record must still be on disk");
    assert_eq!(
        stale.state,
        ChangeSetState::Expired,
        "the sweep must be persisted even though the insert was refused"
    );

    // And the proof it matters: after the restart the retired record blocks
    // nothing.
    restarted
        .insert_change_set(record(
            "d",
            "alice",
            "fw-01",
            ChangeSetState::Planned,
            now() + 900,
        ))
        .await
        .expect("a retired record must not block after a restart");
}
