//! The approval digest binds the preview the approver read (rustproxmoxmcp#56).
//!
//! Before v5, approval was evidenced against `(change_set_id, plan_digest,
//! owner, approver, approved_at)`. The plan digest covers the *actions*; the
//! preview is rendered from those actions and stored beside them, and nothing
//! joined the two. An approver's consent therefore attested to the actions,
//! while what they actually read was the preview.
//!
//! v5 adds the preview digest to that tuple. These tests pin the two properties
//! that makes true — the text is bound, and a v4 record is never promoted to
//! claim it was.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetState as StateFile,
    digest::{change_set_digest, compute_approval_digest_v4, compute_approval_digest_v5},
    persistence::{read_state, write_state_for_test},
    records::{ApprovalRecord, ChangeSetRecord, PreviewRecord},
};
use serde_json::json;

const LIMIT: u64 = 1024 * 1024;

fn record_with_preview(preview: Option<&str>) -> ChangeSetRecord {
    let owner = "alice";
    let device = "pve3";
    let fingerprint = format!("sha256:{}", "a".repeat(64));
    let actions = vec![json!({"op": "destroy_guest", "vmid": 617})];
    let digest = change_set_digest(owner, device, &fingerprint, &actions).unwrap();
    ChangeSetRecord {
        id: "b".repeat(64),
        owner: owner.to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: ChangeSetState::Approved,
        approver: Some("bob".to_owned()),
        approval: None,
        expires_at_unix: 4_102_444_800,
        operation_id: None,
        policy_signature: "test".to_owned(),
        targets: Vec::new(),
        preview: preview.map(|text| PreviewRecord {
            digest: mecmcp_changeset::digest::preview_digest(text),
            artifact: text.to_owned(),
            job_id: None,
        }),
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

fn round_trip(record: ChangeSetRecord) -> Result<StateFile, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut change_sets = std::collections::BTreeMap::new();
    change_sets.insert(record.id.clone(), record);
    let state = StateFile {
        operations: std::collections::BTreeMap::new(),
        change_sets,
    };
    write_state_for_test(&path, &state, LIMIT).map_err(|e| e.to_string())?;
    read_state(&path, LIMIT).map_err(|e| e.to_string())
}

/// A v5 approval survives a write/read cycle with its preview intact.
#[test]
fn a_v5_approval_round_trips() {
    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    let state = round_trip(record).expect("a v5 approval must load");
    let loaded = state.change_sets.values().next().unwrap();
    assert_eq!(loaded.approval.as_ref().unwrap().digest_version, 5);
}

/// **The property this whole change exists for.** Editing the preview after
/// approval must invalidate the approval, not merely the preview's own digest.
#[test]
fn editing_the_preview_invalidates_the_approval() {
    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });

    // Swap the preview for different text, keeping its own digest self-consistent
    // so `validate_preview` is satisfied. Before v5 this passed every check.
    let replacement = "RESIZE lxc/617 disk on pve3";
    record.preview = Some(PreviewRecord {
        digest: mecmcp_changeset::digest::preview_digest(replacement),
        artifact: replacement.to_owned(),
        job_id: None,
    });

    let error = round_trip(record).expect_err("a swapped preview must break the approval");
    assert!(
        error.contains("approval digest mismatch"),
        "expected an approval mismatch, got: {error}"
    );
}

/// A v4 approval keeps verifying under v4 forever. It must not be promoted:
/// its approver never saw a preview binding, and re-signing it as v5 would
/// assert consent that was never given.
#[test]
fn a_v4_approval_is_never_promoted() {
    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v4(
            &record.id,
            &record.digest,
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    let state = round_trip(record).expect("a v4 approval must still load");
    let loaded = state.change_sets.values().next().unwrap();
    assert_eq!(
        loaded.approval.as_ref().unwrap().digest_version,
        4,
        "a v4 approval was promoted, which would claim consent that was not given"
    );
}

/// The corollary: a v4 approval is *not* protected against a preview swap, and
/// that is correct rather than a gap. It never bound the preview, and pretending
/// otherwise is exactly what promoting it would do.
#[test]
fn a_v4_approval_still_tolerates_a_preview_swap() {
    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v4(
            &record.id,
            &record.digest,
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    let replacement = "RESIZE lxc/617 disk on pve3";
    record.preview = Some(PreviewRecord {
        digest: mecmcp_changeset::digest::preview_digest(replacement),
        artifact: replacement.to_owned(),
        job_id: None,
    });
    round_trip(record).expect("a v4 approval does not bind the preview, by construction");
}

/// A v5 approval on a record with no preview is legal, and the absence is signed.
#[test]
fn a_previewless_v5_approval_binds_the_absence() {
    let mut record = record_with_preview(None);
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            None,
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    round_trip(record.clone()).expect("a previewless v5 approval must load");

    // Attaching a preview to a record approved without one must not verify.
    let mut with_preview = record;
    with_preview.preview = Some(PreviewRecord {
        digest: mecmcp_changeset::digest::preview_digest("injected"),
        artifact: "injected".to_owned(),
        job_id: None,
    });
    let error = round_trip(with_preview)
        .expect_err("adding a preview after a previewless approval must break it");
    assert!(error.contains("approval digest mismatch"), "{error}");
}

/// An unknown digest version is refused rather than silently treated as one of
/// the known rules.
#[test]
fn an_unknown_digest_version_is_refused() {
    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v4(
            &record.id,
            &record.digest,
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 99,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    let error = round_trip(record).expect_err("an unknown version must be refused");
    assert!(
        error.contains("unsupported digest version"),
        "expected an explicit refusal, got: {error}"
    );
}

/// The digest check in `read_state` only runs on a *reload*. Between an
/// in-process preview swap and the next restart, the record still applies and
/// carries an approval for text that is no longer there. The write is refused
/// so the window never opens.
#[tokio::test]
async fn a_bound_preview_cannot_be_changed_in_process() {
    let dir = tempfile::tempdir().unwrap();
    let coord = mecmcp_changeset::ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(3600),
        true,
    )
    .unwrap();

    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.state = ChangeSetState::Planned;
    record.approver = None;
    record.approval = None;
    coord.insert_change_set(record.clone()).await.unwrap();

    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    let mut approved = record.clone();
    approved.state = ChangeSetState::Approved;
    approved.approver = Some("bob".to_owned());
    approved.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    coord.update_change_set(approved.clone()).await.unwrap();

    // Swap the text, keeping the preview record self-consistent.
    let mut swapped = approved.clone();
    let replacement = "RESIZE lxc/617 disk on pve3";
    swapped.preview = Some(PreviewRecord {
        digest: mecmcp_changeset::digest::preview_digest(replacement),
        artifact: replacement.to_owned(),
        job_id: None,
    });
    let error = coord
        .update_change_set(swapped)
        .await
        .expect_err("rewriting a bound preview must be refused");
    assert!(
        error.to_string().contains("bound by an approval"),
        "expected the immutability refusal, got: {error}"
    );

    // A write that leaves the preview alone is still fine.
    coord
        .update_change_set(approved)
        .await
        .expect("an unrelated update must still be allowed");
}

/// The digest is a field of the record being written, so an update that
/// rewrites the text and leaves the digest alone passes a digest-only
/// comparison. That put altered text in front of the next reader under an
/// approval given for different text.
#[tokio::test]
async fn a_bound_preview_cannot_have_its_text_rewritten_under_its_own_digest() {
    let dir = tempfile::tempdir().unwrap();
    let coord = mecmcp_changeset::ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(3600),
        true,
    )
    .unwrap();

    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.state = ChangeSetState::Planned;
    record.approver = None;
    record.approval = None;
    coord.insert_change_set(record.clone()).await.unwrap();

    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    let mut approved = record.clone();
    approved.state = ChangeSetState::Approved;
    approved.approver = Some("bob".to_owned());
    approved.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    coord.update_change_set(approved.clone()).await.unwrap();

    // Rewrite only the text. The digest still says what it said, so a
    // digest-to-digest comparison sees no change at all.
    let mut tampered = approved;
    tampered.preview = Some(PreviewRecord {
        digest: preview_digest.clone().unwrap(),
        artifact: "RESIZE lxc/617 disk on pve3".to_owned(),
        job_id: None,
    });
    let error = coord
        .update_change_set(tampered)
        .await
        .expect_err("rewriting the text under its own digest must be refused");
    assert!(
        error.to_string().contains("preview is invalid"),
        "expected the content check to fire, got: {error}"
    );
}

/// Invariant 2. Without it invariant 3 falls in two steps: swap the v5 approval
/// for a valid v4 one, at which point the record no longer reports v5, then
/// change the preview freely on the next write.
#[tokio::test]
async fn a_granted_approval_cannot_be_downgraded_to_free_the_preview() {
    let dir = tempfile::tempdir().unwrap();
    let coord = mecmcp_changeset::ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(3600),
        true,
    )
    .unwrap();

    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.state = ChangeSetState::Planned;
    record.approver = None;
    record.approval = None;
    coord.insert_change_set(record.clone()).await.unwrap();

    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    let mut approved = record.clone();
    approved.state = ChangeSetState::Approved;
    approved.approver = Some("bob".to_owned());
    approved.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    coord.update_change_set(approved.clone()).await.unwrap();

    // Step one of the bypass: a perfectly valid v4 approval over the same plan.
    let mut downgraded = approved;
    downgraded.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v4(
            &record.id,
            &record.digest,
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 4,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    let error = coord
        .update_change_set(downgraded)
        .await
        .expect_err("downgrading a granted approval must be refused");
    assert!(
        error
            .to_string()
            .contains("rewritten or removed once granted"),
        "expected the approval-immutability refusal, got: {error}"
    );
}

/// Invariant 1. An inconsistent preview must never reach a signature — the
/// resulting approval is valid, and the state file it produces is not.
#[tokio::test]
async fn an_inconsistent_preview_cannot_be_written_or_signed() {
    let dir = tempfile::tempdir().unwrap();
    let coord = mecmcp_changeset::ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(3600),
        true,
    )
    .unwrap();

    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.state = ChangeSetState::Planned;
    record.approver = None;
    record.approval = None;
    coord.insert_change_set(record.clone()).await.unwrap();

    // A planned record whose artifact and digest disagree.
    let mut inconsistent = record;
    inconsistent.preview = Some(PreviewRecord {
        digest: mecmcp_changeset::digest::preview_digest("what the approver is shown"),
        artifact: "what would actually run".to_owned(),
        job_id: None,
    });
    let error = coord
        .update_change_set(inconsistent)
        .await
        .expect_err("an inconsistent preview must not be written at all");
    assert!(
        error.to_string().contains("preview is invalid"),
        "expected the consistency refusal, got: {error}"
    );
}

/// Removal is a rewrite. Dropping the nested approval leaves the top-level
/// `approver` populated, so `apply_change_set` still accepts the record through
/// its legacy-approval path — while the preview, bound by nothing now, is free
/// to be replaced on the next write.
#[tokio::test]
async fn a_granted_approval_cannot_be_removed_to_free_the_preview() {
    let dir = tempfile::tempdir().unwrap();
    let coord = mecmcp_changeset::ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        mecmcp_changeset::OperationLimits::default(),
        std::time::Duration::from_secs(3600),
        true,
    )
    .unwrap();

    let mut record = record_with_preview(Some("DESTROY lxc/617 on pve3"));
    record.state = ChangeSetState::Planned;
    record.approver = None;
    record.approval = None;
    coord.insert_change_set(record.clone()).await.unwrap();

    let preview_digest = record.preview.as_ref().map(|p| p.digest.clone());
    let mut approved = record.clone();
    approved.state = ChangeSetState::Approved;
    approved.approver = Some("bob".to_owned());
    approved.approval = Some(ApprovalRecord {
        approver: Some("bob".to_owned()),
        approved_at_unix: 1_700_000_000,
        digest: compute_approval_digest_v5(
            &record.id,
            &record.digest,
            preview_digest.as_deref(),
            &record.owner,
            "bob",
            1_700_000_000,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });
    coord.update_change_set(approved.clone()).await.unwrap();

    // Step one: drop the nested approval, keeping the top-level approver.
    let mut stripped = approved.clone();
    stripped.approval = None;
    let error = coord
        .update_change_set(stripped)
        .await
        .expect_err("removing a granted approval must be refused");
    assert!(
        error
            .to_string()
            .contains("rewritten or removed once granted"),
        "expected the removal refusal, got: {error}"
    );

    // Any other field of the approval is frozen too, not just the digest.
    let mut retimed = approved;
    if let Some(approval) = retimed.approval.as_mut() {
        approval.approved_at_unix = 1_700_000_999;
    }
    let error = coord
        .update_change_set(retimed)
        .await
        .expect_err("retiming a granted approval must be refused");
    assert!(
        error
            .to_string()
            .contains("rewritten or removed once granted"),
        "expected the rewrite refusal, got: {error}"
    );
}
