//! MEC-457: the approval digest is keyed (HMAC) rather than a plain hash, so it
//! cannot be forged by anyone who can merely read or edit the state file —
//! only by someone who holds the deployment's key.
//!
//! Covers:
//! 1. Approving through a coordinator configured with a key produces a v6,
//!    HMAC-keyed digest — not the unkeyed v5 one.
//! 2. Reloading that state file with the correct key succeeds.
//! 3. Reloading it with no key, or the wrong key, is rejected: a v6 digest is
//!    unverifiable without the key that produced it.
//! 4. Editing the approval's plaintext fields (e.g. re-pointing `approver`)
//!    without also holding the key is detected as tampering on reload, exactly
//!    like the existing v4/v5 tamper-evidence tests.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, OperationLimits,
    persistence::{read_state_with_key, write_state_for_test},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

/// A fresh HMAC key for a single test, generated at runtime rather than a
/// committed literal — nothing here is a credential, so there is nothing
/// for a secret scanner to flag.
fn random_key() -> Vec<u8> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).expect("system randomness for a test key");
    key.to_vec()
}

fn limits() -> OperationLimits {
    OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    }
}

async fn setup_keyed_coordinator(
    key: Arc<[u8]>,
) -> (tempfile::TempDir, PathBuf, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load_with_key(
        Some(&state_path),
        limits(),
        Duration::from_secs(15 * 60),
        false,
        Some(Arc::clone(&key).into()),
    )
    .expect("coordinator")
    .with_approval_digest_key(key);

    (dir, state_path, coordinator)
}

async fn create_and_approve(
    coordinator: &ChangesetCoordinator,
) -> mecmcp_changeset::ChangeSetOutput {
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

    coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await
        .expect("approve")
}

/// Approving through a keyed coordinator produces a v7 digest, not v5.
#[tokio::test]
async fn approving_with_a_key_produces_a_v7_digest() {
    let key = random_key();
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::from(key.as_slice())).await;

    let approved = create_and_approve(&coordinator).await;
    assert_eq!(approved.state, ChangeSetState::Approved);

    let state = read_state_with_key(&state_path, limits().max_state_bytes, Some(&key))
        .expect("read with the correct key");
    let record = state
        .change_sets
        .get(&approved.change_set_id)
        .expect("change set");
    let approval = record.approval.as_ref().expect("approval");
    assert_eq!(
        approval.digest_version, 7,
        "a configured key must produce a v7 (keyed) digest"
    );
}

/// A coordinator with no key configured keeps signing the unkeyed v5 digest —
/// this is an additive capability, not a breaking change for deployments that
/// have not provisioned a key yet.
#[tokio::test]
async fn approving_without_a_key_still_produces_a_v5_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits(), Duration::from_secs(900), false)
            .expect("coordinator");

    let approved = create_and_approve(&coordinator).await;

    let state = mecmcp_changeset::persistence::read_state(&state_path, limits().max_state_bytes)
        .expect("read with no key");
    let approval = state.change_sets[&approved.change_set_id]
        .approval
        .as_ref()
        .expect("approval");
    assert_eq!(approval.digest_version, 5);
}

/// The whole point: a v6-signed state file cannot be loaded without the key
/// that signed it, even though every plaintext field is exactly as written.
#[tokio::test]
async fn reloading_a_v6_file_without_the_key_is_rejected() {
    let real_key = random_key();
    let guessed_key = random_key();
    let (_dir, state_path, coordinator) =
        setup_keyed_coordinator(Arc::from(real_key.as_slice())).await;
    create_and_approve(&coordinator).await;
    drop(coordinator);

    let no_key = read_state_with_key(&state_path, limits().max_state_bytes, None);
    assert!(
        no_key.is_err(),
        "a v6 digest must not be accepted without a key at all"
    );
    assert!(
        no_key
            .unwrap_err()
            .to_string()
            .contains("no approval digest key was supplied")
    );

    let wrong_key = read_state_with_key(&state_path, limits().max_state_bytes, Some(&guessed_key));
    assert!(
        wrong_key.is_err(),
        "a v6 digest must not verify under the wrong key"
    );
    assert!(
        wrong_key
            .unwrap_err()
            .to_string()
            .contains("approval digest mismatch")
    );

    // `ChangesetCoordinator::load` goes through the same path and must refuse
    // the same way -- an operator who forgets to configure the key at startup
    // gets a load failure, not a coordinator that silently trusts an
    // unverifiable file.
    let reload =
        ChangesetCoordinator::load(Some(&state_path), limits(), Duration::from_secs(900), false);
    assert!(reload.is_err(), "load without the key must fail closed");
}

/// Reloading with the correct key succeeds and the approval is intact.
#[tokio::test]
async fn reloading_a_v6_file_with_the_correct_key_succeeds() {
    let key: Arc<[u8]> = Arc::from(random_key().as_slice());
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::clone(&key)).await;
    let approved = create_and_approve(&coordinator).await;
    drop(coordinator);

    let reloaded = ChangesetCoordinator::load_with_key(
        Some(&state_path),
        limits(),
        Duration::from_secs(900),
        false,
        Some(key.into()),
    )
    .expect("load with the correct key must succeed");

    let status = reloaded
        .change_set_status(approved.change_set_id, "device-a".to_string())
        .await
        .expect("status");
    assert_eq!(status.state, ChangeSetState::Approved);
}

/// Percy's review (MEC-457, finding 1): a keyed deployment must not accept an
/// approval that was forged by downgrading `digest_version` to 5 (or 4, or the
/// legacy encoding). Those digests are unkeyed — anyone who can write the
/// state file can recompute them without ever holding the key. Only a v6/v7
/// digest is bound to the key, so once a key is configured, any approver-
/// bearing approval that isn't v6/v7 must be rejected outright, not verified
/// under its own claimed rule.
#[tokio::test]
async fn downgrade_to_v5_is_rejected_when_a_key_is_configured() {
    let key: Arc<[u8]> = Arc::from(random_key().as_slice());
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::clone(&key)).await;
    let approved = create_and_approve(&coordinator).await;
    drop(coordinator);

    let mut state = read_state_with_key(&state_path, limits().max_state_bytes, Some(&key))
        .expect("read with the correct key");
    let id = approved.change_set_id.clone();
    let (plan, owner) = {
        let record = state.change_sets.get(&id).expect("change set");
        (record.digest.clone(), record.owner.clone())
    };
    let preview = state
        .change_sets
        .get(&id)
        .and_then(|record| record.preview.as_ref())
        .map(|preview| preview.digest.clone());
    {
        let record = state.change_sets.get_mut(&id).expect("change set");
        let approval = record.approval.as_mut().expect("approval");
        approval.approver = Some("mallory".to_string());
        approval.digest_version = 5;
        // A genuine v5 approval never carries these — they are v7-only
        // (MEC-994). Cleared here so this forgery is caught by the
        // keyed-version gate this test means to exercise, not by the
        // separate "v7 fields on a non-v7 record" check.
        approval.mechanism = None;
        approval.issuer = None;
        approval.subject = None;
        approval.digest = mecmcp_changeset::digest::compute_approval_digest_v5(
            &id,
            &plan,
            preview.as_deref(),
            &owner,
            "mallory",
            approval.approved_at_unix,
        );
    }
    write_state_for_test(&state_path, &state, limits().max_state_bytes)
        .expect("write forged v5 approval");

    let reloaded = read_state_with_key(&state_path, limits().max_state_bytes, Some(&key));
    assert!(
        reloaded.is_err(),
        "a keyless v5 forgery must not be accepted by a keyed coordinator"
    );
    assert!(
        reloaded
            .unwrap_err()
            .to_string()
            .contains("requires keyed (v6/v7) approvals")
    );

    assert!(
        ChangesetCoordinator::load_with_key(
            Some(&state_path),
            limits(),
            Duration::from_secs(900),
            false,
            Some(key.into()),
        )
        .is_err(),
        "load_with_key must refuse the same downgraded file"
    );
}

/// Percy's review (MEC-457, finding 3): the coordinator derives `Debug`, and a
/// bare `Arc<[u8]>` key would print its raw bytes through any `{:?}` of the
/// coordinator — a tracing field, a panic message, or (as here) a test
/// assertion failure. `ApprovalDigestKey` must redact instead.
#[tokio::test]
async fn debug_output_never_contains_the_approval_digest_key() {
    let key: Arc<[u8]> = Arc::from(random_key().as_slice());
    // `Arc<[u8]>`'s own (undesired) `Debug` prints the bytes as a numeric
    // array, not ASCII text -- so the leak-detecting assertion has to look
    // for that shape, not the plaintext key.
    let leaked_form = format!("{:?}", key.as_ref());
    let (_dir, _state_path, coordinator) = setup_keyed_coordinator(key).await;

    let rendered = format!("{coordinator:?}");
    assert!(
        !rendered.contains(&leaked_form),
        "coordinator Debug output must not contain the approval digest key bytes: {rendered}"
    );
    assert!(rendered.contains("ApprovalDigestKey(<redacted>)"));
}

/// Tamper-evidence: editing the approver in a v6-signed record — without
/// holding the key — must be caught on reload, exactly as it is for v4/v5.
#[tokio::test]
async fn a_tampered_approver_is_rejected_even_with_the_correct_key() {
    let key: Arc<[u8]> = Arc::from(random_key().as_slice());
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::clone(&key)).await;
    let approved = create_and_approve(&coordinator).await;
    drop(coordinator);

    let mut state =
        read_state_with_key(&state_path, limits().max_state_bytes, Some(&key)).expect("read");
    {
        let record = state
            .change_sets
            .get_mut(&approved.change_set_id)
            .expect("change set");
        let approval = record.approval.as_mut().expect("approval");
        approval.approver = Some("eve".to_string());
    }
    write_state_for_test(&state_path, &state, limits().max_state_bytes).expect("write tampered");

    let result = read_state_with_key(&state_path, limits().max_state_bytes, Some(&key));
    assert!(result.is_err(), "a tampered approver must be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("approval digest mismatch")
    );
}
