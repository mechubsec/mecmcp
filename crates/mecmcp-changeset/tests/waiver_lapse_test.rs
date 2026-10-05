//! A lapsed waiver must retire its change set, not leave it reading `Approved`
//! (mecmcp#284).
//!
//! `apply_change_set` already refuses when the approving waiver has expired, but
//! it refuses without persisting anything. The record therefore stayed
//! `Approved` — still reported as approved, still occupying the owner's pending
//! slot for the device, and unreachable by `approve_change_set` /
//! `waive_approval`, which all require `Planned`. The error message told the
//! operator to obtain a fresh approval; the state machine refused to let them.
//!
//! The lapse predicate is shared with the apply gate deliberately. A sweep and a
//! gate that disagree about the boundary second would reintroduce exactly the
//! class of mismatch this issue is about.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::digest::compute_waiver_digest_v3;
use mecmcp_changeset::{
    ApprovalRecord, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, OperationLimits,
    WaiverKind, WaiverRecord, change_set_digest,
};
use std::time::Duration;

const APPROVAL_TTL: Duration = Duration::from_secs(900);
const DEVICE: &str = "vsrx-ci";
const OWNER: &str = "claude-test";

fn load_coordinator(dir: &tempfile::TempDir) -> ChangesetCoordinator {
    ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        APPROVAL_TTL,
        false,
    )
    .unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An `Approved` change set whose waiver expires at `waiver_expires_at`.
///
/// The change set's own deadline is set far in the future so nothing but the
/// waiver's expiry can retire it — otherwise a passing test would prove only
/// that the pre-existing change-set sweep still works.
fn waived_record(
    id_seed: &str,
    owner: &str,
    waiver_expires_at: Option<u64>,
    approved_at: u64,
) -> ChangeSetRecord {
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = change_set_digest(owner, DEVICE, &fingerprint, &actions).unwrap();
    let id = format!("{id_seed:0>64}");

    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "authorised exception".to_owned(),
        expires_at_unix: waiver_expires_at,
        ticket: Some("CHG0012345".to_owned()),
    };
    let approval_digest = compute_waiver_digest_v3(&id, &digest, owner, approved_at, &waiver);

    ChangeSetRecord {
        id,
        owner: owner.to_owned(),
        device: DEVICE.to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: ChangeSetState::Approved,
        approver: None,
        approval: Some(ApprovalRecord {
            approver: None,
            approved_at_unix: approved_at,
            digest: approval_digest,
            digest_version: 4,
            waived: Some(waiver),
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        expires_at_unix: now() + 86_400,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

/// The reported symptom: `get_change_set` keeps calling a dead approval live.
///
/// Fails before the fix because `change_set_status` only auto-expires records in
/// `Planned`, so an `Approved` record is returned untouched however long its
/// waiver has been lapsed.
#[tokio::test]
async fn lapsed_waiver_reports_expired_rather_than_approved() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let record = waived_record("a", OWNER, Some(now() - 60), now() - 600);
    let id = record.id.clone();
    coordinator.seed_change_set_for_test(record).await.unwrap();

    let status = coordinator
        .change_set_status(id, DEVICE.to_owned())
        .await
        .unwrap();

    assert_eq!(
        status.state,
        ChangeSetState::Expired,
        "a change set whose waiver has lapsed must not report Approved"
    );
}

/// A waiver with no expiry is what lab mode means. It must never be swept.
#[tokio::test]
async fn waiver_without_expiry_is_never_retired() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let record = waived_record("b", OWNER, None, now() - 600);
    let id = record.id.clone();
    coordinator.seed_change_set_for_test(record).await.unwrap();

    let status = coordinator
        .change_set_status(id, DEVICE.to_owned())
        .await
        .unwrap();

    assert_eq!(
        status.state,
        ChangeSetState::Approved,
        "a waiver with no expiry does not lapse"
    );
}

/// The second half of the defect: the dead record goes on blocking its device.
///
/// Fails before the fix because the insert-time sweep only consults the change
/// set's own `expires_at_unix`, which here is a day out.
#[tokio::test]
async fn lapsed_waiver_frees_the_owners_pending_slot() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    coordinator
        .seed_change_set_for_test(waived_record("c", OWNER, Some(now() - 60), now() - 600))
        .await
        .unwrap();

    // The replacement goes through the production door on purpose. Seeding it
    // skips the expiry sweep and the pending-slot check, which are exactly what
    // this test asserts about — it passed either way, which made it vacuous.
    let mut replacement = waived_record("d", OWNER, Some(now() + 600), now());
    replacement.state = ChangeSetState::Planned;
    replacement.approval = None;
    replacement.approver = None;
    coordinator
        .insert_change_set(replacement)
        .await
        .expect("a lapsed waiver must not block a replacement change set");
}

/// The sweep and the apply gate must agree on the exact second.
///
/// `waiver_expiry_error` treats `now == expires_at` as expired
/// (`apply.rs`, asserted by `waiver_expiry_boundary_is_exact`). A sweep that
/// used `>` where the gate uses `>=` would leave a one-second window in which
/// apply refuses a record that still reports `Approved` — the same disagreement
/// in a narrower form.
#[tokio::test]
async fn lapse_boundary_matches_the_apply_gate() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = load_coordinator(&dir);

    let expires_now = now();
    let record = waived_record("e", OWNER, Some(expires_now), expires_now - 600);
    let id = record.id.clone();
    coordinator.seed_change_set_for_test(record).await.unwrap();

    let status = coordinator
        .change_set_status(id, DEVICE.to_owned())
        .await
        .unwrap();

    assert_eq!(
        status.state,
        ChangeSetState::Expired,
        "a waiver is expired at the exact instant it expires, as the apply gate has it"
    );
}
