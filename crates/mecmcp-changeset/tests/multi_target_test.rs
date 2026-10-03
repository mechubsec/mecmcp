//! Multi-target change sets (#195, #90 phase 5).
//!
//! The compatibility tests here matter more than the feature tests. This crate
//! is pinned by both shipping servers, `ChangeSetRecord` is
//! `deny_unknown_fields`, and LXC 608 is running it right now against a live
//! version-1 state file holding ten change sets.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetRecord, ChangesetState, OperationLimits, PreviewRecord, TargetError,
    change_set_digest, change_set_digest_with_targets, preview_digest, read_state,
    validate_targets, write_state_for_test,
};

fn record(device: &str, targets: Vec<String>) -> ChangeSetRecord {
    // A real digest, because `read_state` recomputes and checks it. That check
    // is also why the digest-stability test above matters: a changed encoding
    // does not merely produce different digests, it stops the deployed state
    // file loading at all.
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = if targets.is_empty() {
        change_set_digest("alice", device, &fingerprint, &actions).unwrap()
    } else {
        change_set_digest_with_targets("alice", device, &fingerprint, &actions, &targets).unwrap()
    };

    ChangeSetRecord {
        id: "a".repeat(64),
        owner: "alice".to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: mecmcp_changeset::ChangeSetState::Planned,
        approver: None,
        approval: None,
        expires_at_unix: 0,
        operation_id: None,
        policy_signature: String::new(),
        targets,
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    }
}

#[test]
fn a_single_target_record_reports_its_device() {
    let record = record("fw-01", Vec::new());
    assert_eq!(record.targets(), vec!["fw-01".to_string()]);
}

#[test]
fn a_multi_target_record_reports_its_set() {
    let record = record("fw-01", vec!["fw-01".into(), "fw-02".into()]);
    assert_eq!(
        record.targets(),
        vec!["fw-01".to_string(), "fw-02".to_string()]
    );
}

/// The single-target digest must be byte-identical to what shipped.
///
/// 608 holds ten change sets whose digests were computed by the original
/// function. Any change to the single-target encoding invalidates every one of
/// them at the next approval, so this asserts against a fixed value rather than
/// against a freshly computed one — a recomputed expectation would move with the
/// bug.
#[test]
fn the_single_target_digest_is_unchanged() {
    let actions = vec![serde_json::json!({"op": "set", "path": "/a"})];
    let original = change_set_digest("alice", "fw-01", "sha256:abc", &actions).unwrap();

    // Hard-coded, and taken from `main` before this change rather than from this
    // branch: recomputing it here would move with the bug. Verified by building
    // `main` in a scratch worktree and printing the value.
    assert_eq!(
        original, "sha256:0a434734755db876c1df689b02ce31177641135f54b48fca2a650f07820a9014",
        "the single-target digest encoding changed; every digest on LXC 608 is now stale"
    );

    // And the targets-aware function must agree when there are no extra targets.
    let via_targets =
        change_set_digest_with_targets("alice", "fw-01", "sha256:abc", &actions, &[]).unwrap();
    assert_eq!(
        via_targets, original,
        "an empty target set changed the digest"
    );
}

#[test]
fn targets_are_bound_into_the_digest() {
    let actions = vec![serde_json::json!({"op": "set"})];
    let one = change_set_digest_with_targets(
        "alice",
        "fw-01",
        "sha256:abc",
        &actions,
        &["fw-01".into(), "fw-02".into()],
    )
    .unwrap();
    let other = change_set_digest_with_targets(
        "alice",
        "fw-01",
        "sha256:abc",
        &actions,
        &["fw-01".into(), "fw-03".into()],
    )
    .unwrap();

    assert_ne!(one, other, "editing the target list left the digest intact");
}

#[test]
fn a_target_set_must_be_sorted_unique_and_bounded() {
    let cases: Vec<(Vec<String>, TargetError)> = vec![
        (vec![], TargetError::Empty),
        (
            vec!["b".into(), "a".into()],
            TargetError::Unsorted("a".into()),
        ),
        (
            vec!["a".into(), "a".into()],
            TargetError::Duplicate("a".into()),
        ),
        (vec![String::new()], TargetError::EmptyName),
    ];

    for (targets, expected) in cases {
        assert_eq!(
            validate_targets(&targets, 64),
            Err(expected),
            "target set {targets:?} was not refused correctly"
        );
    }

    let too_many: Vec<String> = (0..65).map(|n| format!("fw-{n:03}")).collect();
    assert_eq!(
        validate_targets(&too_many, 64),
        Err(TargetError::TooMany {
            count: 65,
            maximum: 64
        })
    );

    // The legal shape passes.
    assert!(validate_targets(&["a".into(), "b".into()], 64).is_ok());
}

/// A record using no new field must still be written as version 1.
///
/// 608's live file is version 1. A version-2 file that a rolled-back binary
/// cannot parse is not a degraded experience, it is a server that will not
/// start — and rolling back is a documented deploy step.
#[test]
fn a_single_target_deployment_still_writes_version_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert("a".repeat(64), record("fw-01", Vec::new()));

    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 1, "a single-target record forced v2");

    // The absent fields must genuinely be absent, not null or empty.
    let stored = &on_disk["state"]["change_sets"][&"a".repeat(64)];
    assert!(stored.get("targets").is_none(), "targets was serialised");
    assert!(stored.get("preview").is_none(), "preview was serialised");
}

/// Using a new field moves the file to version 2, as the gate intends.
#[test]
fn a_multi_target_record_forces_version_two() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut state = ChangesetState::default();
    state.change_sets.insert(
        "a".repeat(64),
        record("fw-01", vec!["fw-01".into(), "fw-02".into()]),
    );

    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 2, "multi-target must gate to v2");
}

#[test]
fn a_preview_record_forces_version_two_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut changeset = record("fw-01", Vec::new());
    let artifact = "+ set address x".to_owned();
    changeset.preview = Some(PreviewRecord {
        // Built with `preview_digest`, not by hand. A fabricated value used to
        // reload cleanly, which is what made the preview decoration rather than
        // evidence.
        digest: preview_digest(&artifact),
        artifact,
        job_id: Some("job-7".to_owned()),
    });

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 2);

    let reloaded = read_state(&path, OperationLimits::default().max_state_bytes).unwrap();
    let preview = reloaded.change_sets[&"a".repeat(64)]
        .preview
        .as_ref()
        .unwrap();
    assert_eq!(preview.job_id.as_deref(), Some("job-7"));
    assert_eq!(preview.artifact, "+ set address x");
}

/// A version-1 file with none of the new fields must load unchanged.
///
/// The shape here is copied from LXC 608's real `mutation-state.json`: version
/// 1, change sets carrying no `policy_signature`, no `approval`, no `targets`.
#[test]
fn a_deployed_version_one_file_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let id = "a".repeat(64);
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let digest = change_set_digest("alice", "panosvm-writer", &fingerprint, &actions).unwrap();
    let body = serde_json::json!({
        "version": 1,
        "state": {
            "change_sets": {
                &id: {
                    "id": &id,
                    "owner": "alice",
                    "device": "panosvm-writer",
                    "expected_candidate_fingerprint": fingerprint,
                    "actions": actions,
                    "digest": digest,
                    "state": "planned",
                    "approver": serde_json::Value::Null,
                    "expires_at_unix": 0,
                    "operation_id": serde_json::Value::Null
                }
            },
            "operations": {}
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let state = read_state(&path, OperationLimits::default().max_state_bytes).unwrap();
    let loaded = &state.change_sets[&id];
    assert_eq!(loaded.device, "panosvm-writer");
    assert!(loaded.targets.is_empty(), "targets must default to absent");
    assert!(loaded.preview.is_none());
    // And the accessor still answers.
    assert_eq!(loaded.targets(), vec!["panosvm-writer".to_string()]);
}

/// The defect that made multi-target unusable across restarts.
///
/// A multi-target record is written with the five-tuple digest, but load-time
/// validation recomputed the four-tuple. Every such record was therefore
/// rejected on the next `read_state` or coordinator restart with a digest
/// mismatch — the feature worked exactly until the process stopped.
#[test]
fn a_multi_target_record_survives_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let targets = vec!["fw-01".to_owned(), "fw-02".to_owned()];
    let mut changeset = record("fw-01", targets.clone());
    changeset.digest = change_set_digest_with_targets(
        &changeset.owner,
        &changeset.device,
        &changeset.expected_candidate_fingerprint,
        &changeset.actions,
        &targets,
    )
    .unwrap();

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let reloaded = read_state(&path, OperationLimits::default().max_state_bytes)
        .expect("a multi-target record must reload");
    assert_eq!(reloaded.change_sets[&"a".repeat(64)].targets, targets);
}

/// A single-target record still validates against the four-tuple, byte for
/// byte. LXC 608 holds change sets whose digests were computed by the old
/// function; the target-aware recompute must not invalidate them.
#[test]
fn a_single_target_record_still_validates_against_the_old_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut changeset = record("fw-01", Vec::new());
    changeset.digest = change_set_digest(
        &changeset.owner,
        &changeset.device,
        &changeset.expected_candidate_fingerprint,
        &changeset.actions,
    )
    .unwrap();

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    read_state(&path, OperationLimits::default().max_state_bytes)
        .expect("a record written by the old digest function must still load");
}

/// The digest is what makes a preview evidence. An artifact edited in the state
/// file used to reload cleanly and be served as valid.
#[test]
fn an_edited_preview_artifact_is_rejected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let artifact = "+ set address x".to_owned();
    let mut changeset = record("fw-01", Vec::new());
    changeset.preview = Some(PreviewRecord {
        digest: preview_digest(&artifact),
        artifact,
        job_id: None,
    });

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    // Edit the artifact on disk, leaving the digest alone — the tamper this
    // digest exists to catch.
    let mut on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    on_disk["state"]["change_sets"][&"a".repeat(64)]["preview"]["artifact"] =
        serde_json::json!("+ set address evil");
    std::fs::write(&path, serde_json::to_vec(&on_disk).unwrap()).unwrap();

    let error = read_state(&path, OperationLimits::default().max_state_bytes)
        .expect_err("an edited artifact must not reload");
    assert!(error.to_string().contains("preview"), "got {error}");
}

/// A structurally invalid target set is rejected on load, not just at insert.
///
/// The digest check cannot catch this on its own: a record written with an
/// unsorted list and a digest computed over that same unsorted list verifies
/// perfectly. That is the point of the ordering rule — without it the digest is
/// a function of how the caller built the list rather than of what the change
/// set does, so two identical change sets can hold different digests.
#[test]
fn an_unsorted_target_set_is_rejected_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let targets = vec!["fw-02".to_owned(), "fw-01".to_owned()];
    let mut changeset = record("fw-01", targets.clone());
    changeset.digest = change_set_digest_with_targets(
        &changeset.owner,
        &changeset.device,
        &changeset.expected_candidate_fingerprint,
        &changeset.actions,
        &targets,
    )
    .unwrap();

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let error = read_state(&path, OperationLimits::default().max_state_bytes)
        .expect_err("an unsorted target set must not reload");
    assert!(error.to_string().contains("sorted"), "got {error}");
}

/// A target set that omits the record's own device makes the record name
/// different devices depending on which API is asked: `targets()` reports the
/// list, while approval and apply still look it up under `device`.
#[test]
fn a_target_set_must_contain_the_records_own_device() {
    let changeset = record("fw-01", vec!["fw-02".to_owned(), "fw-03".to_owned()]);
    assert_eq!(
        changeset.validate_target_set(64),
        Err(TargetError::MissingPrimary("fw-01".to_owned()))
    );

    let good = record("fw-01", vec!["fw-01".to_owned(), "fw-02".to_owned()]);
    assert_eq!(good.validate_target_set(64), Ok(()));
}

/// An empty target set is the single-target shape, which is always valid.
#[test]
fn an_empty_target_set_is_the_single_target_shape() {
    let changeset = record("fw-01", Vec::new());
    assert_eq!(changeset.validate_target_set(64), Ok(()));
    assert_eq!(changeset.targets(), vec!["fw-01".to_owned()]);
}

/// The configured ceilings, which nothing read.
///
/// `max_targets_per_set` and `max_preview_bytes` were both dead: a target list
/// of any length and a preview of any size were accepted so long as the whole
/// file stayed under `max_state_bytes`. The preview is the part a vendor API
/// controls the size of, which is why it has a ceiling of its own.
mod insert_boundary {
    use super::record;
    use mecmcp_changeset::{
        ChangesetCoordinator, OperationLimits, PreviewRecord, change_set_digest_with_targets,
        preview_digest,
    };

    fn coordinator(dir: &tempfile::TempDir, limits: OperationLimits) -> ChangesetCoordinator {
        ChangesetCoordinator::load(
            Some(&dir.path().join("state.json")),
            limits,
            std::time::Duration::from_secs(900),
            false,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn too_many_targets_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let limits = OperationLimits {
            max_targets_per_set: 2,
            ..OperationLimits::default()
        };
        let targets = vec!["fw-01".to_owned(), "fw-02".to_owned(), "fw-03".to_owned()];
        let mut changeset = record("fw-01", targets.clone());
        changeset.digest = change_set_digest_with_targets(
            &changeset.owner,
            &changeset.device,
            &changeset.expected_candidate_fingerprint,
            &changeset.actions,
            &targets,
        )
        .unwrap();

        let error = coordinator(&dir, limits)
            .insert_change_set(changeset)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds the maximum"),
            "got {error}"
        );
    }

    #[tokio::test]
    async fn an_oversized_preview_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let limits = OperationLimits {
            max_preview_bytes: 16,
            ..OperationLimits::default()
        };
        let artifact = "x".repeat(17);
        let mut changeset = record("fw-01", Vec::new());
        changeset.preview = Some(PreviewRecord {
            digest: preview_digest(&artifact),
            artifact,
            job_id: None,
        });

        let error = coordinator(&dir, limits)
            .insert_change_set(changeset)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds the maximum"),
            "got {error}"
        );
    }

    /// A ceiling lowered after the fact must not make an existing file
    /// unloadable — which is why `validate_state` checks structure only.
    #[tokio::test]
    async fn a_preview_within_the_ceiling_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = "+ set address x".to_owned();
        let mut changeset = record("fw-01", Vec::new());
        changeset.preview = Some(PreviewRecord {
            digest: preview_digest(&artifact),
            artifact,
            job_id: None,
        });

        coordinator(&dir, OperationLimits::default())
            .insert_change_set(changeset)
            .await
            .expect("a preview inside the ceiling must be accepted");
    }
}

/// A `task_id` forces version 2, for the same reason as `targets` and
/// `preview` — and this is the sharpest case of the three.
///
/// `task_id` is written while an apply is in flight, so a rollback performed
/// *during* an apply is exactly when the file carries one. That is the moment
/// an unreadable state file hurts most: the operator is already recovering.
#[test]
fn a_task_id_forces_version_two_and_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut changeset = record("fw-01", Vec::new());
    changeset.task_id = Some("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:".into());

    let mut state = ChangesetState::default();
    state.change_sets.insert("a".repeat(64), changeset);
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        on_disk["version"], 2,
        "an in-flight task handle must gate to v2"
    );

    let reloaded = read_state(&path, OperationLimits::default().max_state_bytes).unwrap();
    let stored = reloaded.change_sets.get(&"a".repeat(64)).unwrap();
    assert_eq!(
        stored.task_id.as_deref(),
        Some("UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:"),
        "the handle must survive a round trip, or recovery has nothing to ask about"
    );
}

/// Absent when unused, so a deployment that never applies keeps writing
/// version-1 files an older binary can read.
#[test]
fn no_task_id_is_serialised_when_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert("a".repeat(64), record("fw-01", Vec::new()));
    write_state_for_test(&path, &state, OperationLimits::default().max_state_bytes).unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 1);
    let stored = &on_disk["state"]["change_sets"][&"a".repeat(64)];
    assert!(
        stored.get("task_id").is_none(),
        "task_id was serialised as null, which a v1 reader rejects"
    );
}
