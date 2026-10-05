//! One approval must buy exactly one execution.
//!
//! Reading `Approved` and then writing `Applying` is two operations with the
//! lock released between them, so two applies could both read `Approved`, both
//! pass the check, and both run. For a destroy that is nearly harmless — the
//! second one fails against a guest that is already gone. For an operation that
//! executes an arbitrary command inside a guest it is not, and that is the
//! operation this primitive was added for.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, OperationLimits,
    change_set_digest,
};
use std::sync::Arc;
use std::time::Duration;

fn planned(id: &str) -> ChangeSetRecord {
    // A real digest, not a placeholder: the state file is digest-bound and
    // reload refuses a record whose digest does not match its own contents, so
    // a synthetic one never survives the restart these tests are about.
    let owner = "planner";
    let device = "vsrx-ci";
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "guest_exec"})];
    let digest = change_set_digest(owner, device, &fingerprint, &actions).unwrap();
    ChangeSetRecord {
        id: id.to_owned(),
        device: device.to_owned(),
        owner: owner.to_owned(),
        digest,
        expected_candidate_fingerprint: fingerprint,
        actions,
        state: ChangeSetState::Planned,
        expires_at_unix: u64::MAX,
        operation_id: None,
        approver: None,
        approval: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

/// Seed an `Approved` change set the way the server reaches one.
///
/// Insert now refuses anything but `Planned` — writing `Approved` straight in
/// was a creation door into the very states the policy governs, so the fixtures
/// have to walk the lifecycle like everything else.
async fn seed_approved(coord: &ChangesetCoordinator, id: &str) {
    let record = planned(id);
    let digest = record.digest.clone();
    coord.seed_change_set_for_test(record).await.unwrap();
    coord
        .approve_change_set(
            id.to_owned(),
            "vsrx-ci".to_owned(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "approver".to_owned(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            digest,
        )
        .await
        .expect("approve");
}

async fn coordinator(dir: &std::path::Path) -> Arc<ChangesetCoordinator> {
    Arc::new(
        ChangesetCoordinator::load(
            Some(&dir.join("state.json")),
            OperationLimits::default(),
            Duration::from_secs(3600),
            true,
        )
        .unwrap(),
    )
}

/// The claim is the whole point: exactly one caller may leave `Approved`.
///
/// A multi-threaded runtime and a barrier, both load-bearing. On the default
/// current-thread runtime the spawned tasks never interleave — each runs to
/// completion before the next is polled — so every task observes the state the
/// previous one left and the test passes whether or not the claim is atomic.
/// It has to be able to fail: with the lock released between the check and the
/// write, several tasks read `Approved` together and several claims win.
///
/// Repeated, because a race that can be lost is not one that is lost on every
/// run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn only_one_concurrent_claim_can_win() {
    const CLAIMANTS: usize = 16;
    const ROUNDS: usize = 40;

    for round in 0..ROUNDS {
        let dir = tempfile::tempdir().unwrap();
        let coord = coordinator(dir.path()).await;
        let id = "a".repeat(64);
        seed_approved(&coord, &id).await;

        // Every claimant waits here, so they hit the claim together rather
        // than in the order they were spawned.
        let gate = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
        let mut tasks = Vec::new();
        for _ in 0..CLAIMANTS {
            let coord = Arc::clone(&coord);
            let gate = Arc::clone(&gate);
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                coord
                    .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
                    .await
                    .is_ok()
            }));
        }

        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "round {round}: exactly one apply may claim an approval; {winners} \
             claims means the same approved command would have run {winners} times"
        );
        let record = coord.change_set(&id, "vsrx-ci").await.unwrap();
        assert_eq!(record.state, ChangeSetState::Applying);
    }
}

/// A loser must be able to tell "someone beat me" from "this expired".
#[tokio::test]
async fn a_losing_claim_is_told_which_state_it_lost_to() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    seed_approved(&coord, &"b".repeat(64)).await;

    coord
        .claim_change_set_for_apply(&"b".repeat(64), "vsrx-ci", ApplyHandle::Expected)
        .await
        .expect("the first claim wins");

    let error = coord
        .claim_change_set_for_apply(&"b".repeat(64), "vsrx-ci", ApplyHandle::Expected)
        .await
        .expect_err("the second claim must be refused");
    let message = error.to_string();
    assert!(
        message.contains("Applying"),
        "the refusal must name the state it lost to, got: {message}"
    );
}

/// The device check is not bypassed by the claim path.
#[tokio::test]
async fn a_claim_for_another_device_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    seed_approved(&coord, &"c".repeat(64)).await;

    assert!(
        coord
            .claim_change_set_for_apply(&"c".repeat(64), "some-other-guest", ApplyHandle::Expected)
            .await
            .is_err(),
        "a change set must not be claimable through another device's name"
    );
    let record = coord.change_set(&"c".repeat(64), "vsrx-ci").await.unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Approved,
        "a refused claim must not move the record"
    );
}

/// A handleless apply that dies mid-flight stays `Applying`, not `Failed`.
///
/// `Failed` asserts an outcome nobody observed. When the operation produces no
/// vendor handle, nothing but the device knows whether it ran, so the honest
/// state is the one that says "go and look" — and it also keeps the approval
/// spent, which is what stops a second execution.
#[tokio::test]
async fn a_handleless_apply_survives_a_restart_as_applying() {
    let dir = tempfile::tempdir().unwrap();
    {
        let coord = coordinator(dir.path()).await;
        seed_approved(&coord, &"d".repeat(64)).await;
        coord
            .claim_change_set_for_apply(&"d".repeat(64), "vsrx-ci", ApplyHandle::None)
            .await
            .unwrap();
        // The process dies here: no handle was ever written, because this
        // operation never produces one.
    }

    let reloaded = coordinator(dir.path()).await;
    let record = reloaded
        .change_set(&"d".repeat(64), "vsrx-ci")
        .await
        .unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Applying,
        "a handleless apply must not be settled as Failed: the command may have \
         run, and only the device knows"
    );
    assert!(record.apply_without_handle);
}

/// The existing rule still holds for applies that *should* have had a handle.
#[tokio::test]
async fn a_handle_expecting_apply_without_one_is_still_failed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let coord = coordinator(dir.path()).await;
        seed_approved(&coord, &"e".repeat(64)).await;
        coord
            .claim_change_set_for_apply(&"e".repeat(64), "vsrx-ci", ApplyHandle::Expected)
            .await
            .unwrap();
        // Died before the vendor accepted the operation, so nothing started.
    }

    let reloaded = coordinator(dir.path()).await;
    let record = reloaded
        .change_set(&"e".repeat(64), "vsrx-ci")
        .await
        .unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Failed,
        "an apply that was going to record a handle and did not never started"
    );
}

/// The claim must be the *only* way into `Applying`, or it is advisory.
///
/// The first version of this change added a safe path and left the unsafe one
/// open: `update_change_set` still replaced the record unconditionally, so the
/// original read-`Approved`/write-`Applying` sequence still worked and still
/// raced. Caught by the review gate.
#[tokio::test]
async fn update_change_set_cannot_perform_the_apply_transition() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "f".repeat(64);
    seed_approved(&coord, &id).await;

    let mut sneaky = coord.change_set(&id, "vsrx-ci").await.unwrap();
    sneaky.state = ChangeSetState::Applying;
    let error = coord
        .update_change_set(sneaky)
        .await
        .expect_err("Approved -> Applying must not be writable directly");
    assert!(
        error.to_string().contains("claim_change_set_for_apply"),
        "the refusal should name the method that owns this transition, got: {error}"
    );

    let record = coord.change_set(&id, "vsrx-ci").await.unwrap();
    assert_eq!(record.state, ChangeSetState::Approved);
}

/// A handleless in-flight apply must not be re-approved.
///
/// Whether the command ran is unknown, so re-opening it hands out a second
/// execution of something that may already have happened — the exact outcome
/// preserving `Applying` across a restart exists to prevent.
#[tokio::test]
async fn a_handleless_applying_record_cannot_be_returned_to_approved() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "9".repeat(64);
    seed_approved(&coord, &id).await;
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    let mut reopened = coord.change_set(&id, "vsrx-ci").await.unwrap();
    reopened.state = ChangeSetState::Approved;
    let error = coord
        .update_change_set(reopened)
        .await
        .expect_err("a handleless apply must not be re-approved");
    // The table refuses this outright now, for every `Applying` record rather
    // than only handleless ones: there is no edge back to `Approved` at all,
    // which is what keeps an approval spent once it has been claimed.
    assert!(
        error
            .to_string()
            .contains("not a permitted change-set transition"),
        "the refusal should come from the transition policy, got: {error}"
    );
    assert_eq!(
        coord.change_set(&id, "vsrx-ci").await.unwrap().state,
        ChangeSetState::Applying
    );
}

/// Every laundering route the review gate found, closed by one policy.
///
/// The version before this one rejected two *edges* and left the graph open.
/// Each case below reached `Applying`, or reached a claimable state from an
/// in-flight one, without ever writing the forbidden edge directly.
#[tokio::test]
async fn the_transition_policy_closes_the_indirect_routes() {
    use ChangeSetState as S;
    use mecmcp_changeset::change_set_transition_allowed as allowed;

    // Approved -> anything -> Applying: the intermediate hop is what made the
    // two-edge guard useless.
    for hop in [S::Failed, S::Planned, S::Cancelled, S::Expired, S::Applied] {
        assert!(
            !allowed(S::Approved, hop) || !allowed(hop, S::Applying),
            "Approved -> {hop:?} -> Applying is a route back into Applying"
        );
    }

    // Nothing returns to Approved. An approval is spent once claimed.
    for from in [S::Applying, S::Applied, S::Failed, S::Expired, S::Cancelled] {
        assert!(
            !allowed(from, S::Approved),
            "{from:?} -> Approved would make a spent approval claimable again"
        );
    }

    // Applying is reachable from nowhere in the table at all: the claim owns it.
    for from in [
        S::Planned,
        S::Approved,
        S::Applied,
        S::Failed,
        S::Expired,
        S::Cancelled,
    ] {
        assert!(
            !allowed(from, S::Applying),
            "{from:?} -> Applying must go through the claim, not the table"
        );
    }

    // ...while the lifecycle the servers actually use still works.
    assert!(allowed(S::Planned, S::Approved));
    assert!(allowed(S::Planned, S::Expired));
    assert!(allowed(S::Approved, S::Cancelled));
    assert!(allowed(S::Applying, S::Applied));
    assert!(allowed(S::Applying, S::Failed));
    assert!(allowed(S::Expired, S::Cancelled));
    assert!(allowed(S::Failed, S::Cancelled));
}

/// Clearing the handleless marker in place was the other laundering route:
/// `Applying(true) -> Applying(false)` is an allowed edge, and it would have
/// removed the only thing keeping that record out of reach.
#[tokio::test]
async fn the_handleless_marker_cannot_be_cleared_while_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "1".repeat(64);
    seed_approved(&coord, &id).await;
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    let mut laundered = coord.change_set(&id, "vsrx-ci").await.unwrap();
    laundered.apply_without_handle = false;
    let error = coord
        .update_change_set(laundered)
        .await
        .expect_err("the marker must not be clearable in flight");
    assert!(
        error.to_string().contains("second execution"),
        "got: {error}"
    );
    assert!(
        coord
            .change_set(&id, "vsrx-ci")
            .await
            .unwrap()
            .apply_without_handle
    );
}

/// Insert creates; it does not overwrite. Replacing a live record through that
/// door would skip the policy entirely.
#[tokio::test]
async fn insert_cannot_overwrite_a_live_record() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "2".repeat(64);
    seed_approved(&coord, &id).await;
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    // A different owner on purpose. The one-pending-per-principal check would
    // otherwise refuse this first, and that check is not the guarantee: it
    // matches on owner and device, so an overwrite that changes either slips
    // straight past it. This is the case the review gate named.
    let mut reset = planned(&id);
    reset.owner = "someone-else".to_owned();
    let error = coord
        .seed_change_set_for_test(reset)
        .await
        .expect_err("insert must not overwrite an existing record");
    assert!(
        error.to_string().contains("already exists"),
        "the id guard must be what refuses this, not the pending-principal \
         check, which an overwrite can sidestep by changing owner: {error}"
    );
    assert_eq!(
        coord.change_set(&id, "vsrx-ci").await.unwrap().state,
        ChangeSetState::Applying
    );
}

/// A write decided against a stale snapshot must not land.
///
/// Every lifecycle method reads, decides, then writes with the lock released in
/// between. A cancellation that decided a record was cancellable would
/// otherwise erase a claim that happened in that gap.
#[tokio::test]
async fn a_write_decided_against_a_stale_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "3".repeat(64);
    seed_approved(&coord, &id).await;

    // What a canceller read before deciding.
    let stale = coord.change_set(&id, "vsrx-ci").await.unwrap();
    // ...and the claim that beat it to the record.
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::Expected)
        .await
        .unwrap();

    let mut cancelled = stale.clone();
    cancelled.state = ChangeSetState::Cancelled;
    let error = coord
        .update_change_set_from(stale.state, cancelled)
        .await
        .expect_err("a decision made against Approved must not apply to Applying");
    assert!(error.to_string().contains("moved to"), "got: {error}");
    assert_eq!(
        coord.change_set(&id, "vsrx-ci").await.unwrap().state,
        ChangeSetState::Applying,
        "the claim must survive a stale cancellation"
    );
}

/// The production insert refuses a duplicate id, and does so under one lock.
///
/// The earlier test for this went through the test-only seeding door, so it
/// never exercised `insert_change_set` — and the first version of that guard
/// took its own lock, checked, released it, and inserted later, which is the
/// same check-then-act race the rest of this change removes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_inserts_of_one_id_do_not_both_land() {
    // Enough rounds that a broken implementation is caught reliably rather than
    // occasionally: at 25 it failed roughly one run in three, which is a test
    // that reports "fine" on code that is not.
    for round in 0..250 {
        let dir = tempfile::tempdir().unwrap();
        let coord = coordinator(dir.path()).await;
        let id = "7".repeat(64);

        let gate = Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for n in 0..8 {
            let coord = Arc::clone(&coord);
            let gate = Arc::clone(&gate);
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                let mut record = planned(&id);
                // Distinct owners, so the one-pending-per-principal guard is
                // not what refuses these. The id check has to be.
                record.owner = format!("owner-{n}");
                gate.wait().await;
                coord.insert_change_set(record).await.is_ok()
            }));
        }
        let mut landed = 0;
        for task in tasks {
            if task.await.unwrap() {
                landed += 1;
            }
        }
        assert_eq!(
            landed, 1,
            "round {round}: one id, one record; {landed} inserts landed, so a \
             later insert overwrote an earlier one"
        );
    }
}

/// `Applied` is written before diff, validation and commit, so a later failure
/// has to be able to correct it.
///
/// The closed table forbade this at first, which broke rustjunosmcp at runtime
/// while every test here stayed green: its `settle_change_set` exists to stop a
/// record claiming a change landed when it did not, on the grounds that a
/// wedged device is recoverable by an operator and a false `Applied` is not.
#[tokio::test]
async fn an_applied_record_can_still_be_corrected_to_failed() {
    use mecmcp_changeset::change_set_transition_allowed as allowed;
    assert!(allowed(ChangeSetState::Applied, ChangeSetState::Failed));
    // ...and it opens no way back to a claimable state.
    assert!(!allowed(ChangeSetState::Failed, ChangeSetState::Approved));
    assert!(!allowed(ChangeSetState::Failed, ChangeSetState::Applying));

    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "8".repeat(64);
    seed_approved(&coord, &id).await;
    let mut record = coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::Expected)
        .await
        .unwrap();
    let observed = record.state;
    record.state = ChangeSetState::Applied;
    coord
        .update_change_set_from(observed, record.clone())
        .await
        .unwrap();

    record.state = ChangeSetState::Failed;
    coord
        .update_change_set_from(ChangeSetState::Applied, record)
        .await
        .expect("a settled-too-early Applied must be correctable to Failed");
}

/// The handleless marker is cleared once the record leaves `Applying`.
///
/// It answers "is this in-flight outcome unknown?", so on a settled record it
/// is noise — and expensive noise, because its presence forces a schema version
/// an older binary cannot read.
#[tokio::test]
async fn the_handleless_marker_does_not_outlive_the_apply() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "a".repeat(63) + "b";
    seed_approved(&coord, &id).await;
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    let mut record = coord.change_set(&id, "vsrx-ci").await.unwrap();
    assert!(record.apply_without_handle, "set while in flight");

    // A caller that settles by writing `state` alone must not leave it behind.
    let observed = record.state;
    record.state = ChangeSetState::Failed;
    coord
        .update_change_set_from(observed, record)
        .await
        .unwrap();

    assert!(
        !coord
            .change_set(&id, "vsrx-ci")
            .await
            .unwrap()
            .apply_without_handle,
        "the marker must not outlive the apply it described"
    );
}

/// A file carrying the handleless marker must declare a version older readers
/// refuse.
///
/// `ChangeSetRecord` is `deny_unknown_fields`, so a binary that predates the
/// field rejects the whole file over it. 0.21.0 accepts versions 1..=4, and
/// version selection takes the highest match — so listing the field among the
/// version-2 conditions achieved nothing: a record with a real approval is
/// version 4 regardless, and 0.21.0 would read that as a supported schema and
/// then fail on the unknown field. The gate is only a gate if the version moves
/// past what the old reader accepts.
///
/// The specific number moved from 5 to 6 when approvals began binding the
/// preview digest (rustproxmoxmcp#56): a v5 approval is itself unreadable to
/// anything below schema 6, so an approved record now carries that version
/// before the marker is applied at all. The guarantee under test is unchanged —
/// the file must declare something a pre-marker binary refuses — and it is
/// asserted as that rather than as a literal, so the next version rule added
/// above it does not silently turn this test into a tautology.
#[tokio::test]
async fn a_handleless_apply_forces_a_state_file_version_older_readers_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let coord = coordinator(dir.path()).await;
    let id = "c".repeat(64);
    seed_approved(&coord, &id).await;

    let before: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let before_version = before["version"].as_u64().unwrap();
    assert_eq!(
        before_version, 6,
        "an approved record binds its preview (v5 approval digest), which is \
         itself unreadable below schema 6"
    );

    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let after_version = after["version"].as_u64().unwrap();
    assert!(
        after_version >= 5,
        "a file carrying apply_without_handle must declare at least version 5, \
         or a 0.21.0 binary reads it as supported and then rejects the record; \
         got {after_version}"
    );
    assert!(
        after_version >= before_version,
        "applying the marker must not lower the declared version"
    );
}
