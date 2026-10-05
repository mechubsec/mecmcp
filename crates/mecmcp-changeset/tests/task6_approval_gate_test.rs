//! Tests for Task 6 — change-set approval gate.
//!
//! Covers:
//! 1. Create change set as alice
//! 2. Approve as alice must fail
//! 3. Approve as bob must succeed
//! 4. Second approval must fail
//! 5. Expired change sets transition to Expired on status poll
//!
//! Plus Issue #50 (approval digest tamper-evidence) and #54 (lab mode)

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ApprovalRecord, ApproverIdentity, ChangeSetRecord, ChangeSetState, ChangesetCoordinator,
    OperationLimits, OwnerSubject, WaiverKind, change_set_digest,
    persistence::{read_state, read_state_with_key, write_state_for_test},
};
use std::path::PathBuf;
use std::time::Duration;

/// Action type for test change sets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

/// Build an `OidcVerified` approver identity the way a real server would:
/// through `ApproverIdentity::from_attribution`, never by naming the
/// variant's (crate-private) payload directly. `ApproverIdentity` is opaque
/// to this test crate on purpose (MEC-994 F1) — this is the only door.
fn oidc_verified_approver(principal: &str, issuer: &str, subject: &str) -> ApproverIdentity {
    let attribution = mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::Token(principal.to_owned()),
        actor_type: mecmcp_audit::ActorType::Human,
        agent: None,
        on_behalf_of: None,
        change_ref: None,
        request_id: uuid::Uuid::nil(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::default(),
        verified_approver: Some(mecmcp_auth::VerifiedApprover::for_test(issuer, subject)),
        approver: None,
        change_set_id: None,
    };
    ApproverIdentity::from_attribution(&attribution)
}

/// Sets up a temporary coordinator with a clean state file.
fn setup_coordinator() -> (tempfile::TempDir, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    (dir, coordinator)
}

/// A fresh HMAC key for a single test, generated at runtime rather than a
/// committed literal — nothing here is a credential, so there is nothing
/// for a secret scanner to flag.
fn random_key() -> std::sync::Arc<[u8]> {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).expect("system randomness for a test key");
    std::sync::Arc::from(key.as_slice())
}

/// Sets up a coordinator in MEC-994 strict (verified-approver) mode, keyed so
/// genuine approvals sign under v7. Returns the key too, for tests that need
/// to reload the state file themselves.
fn setup_strict_coordinator() -> (
    tempfile::TempDir,
    ChangesetCoordinator,
    std::sync::Arc<[u8]>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let key = random_key();

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator")
        .with_approval_digest_key(std::sync::Arc::clone(&key))
        .with_require_verified_approver(true);

    (dir, coordinator, key)
}

/// Generates a test fingerprint.
fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[tokio::test]
async fn test_create_then_approve_as_owner_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    assert_eq!(created.state, ChangeSetState::Planned);
    assert!(created.approver.is_none());

    // Attempt to approve as alice (the owner)
    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "alice".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(
        err.message()
            .contains("owner cannot approve their own plan")
    );
}

#[tokio::test]
async fn test_create_then_approve_as_distinct_principal_succeeds() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    assert_eq!(created.state, ChangeSetState::Planned);

    // Approve as bob
    let approved = coordinator
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
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));
    assert_eq!(approved.owner, "alice");
}

/// House rule: a human approves. An agent acting as the second principal must
/// not be able to move a change set to `Approved`, even though it is a distinct
/// principal from the owner.
#[tokio::test]
async fn test_approve_by_agent_actor_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

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

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Agent,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "approver_actor_type");
    assert!(err.message().contains("must be a human principal"));

    // Denied, so the change set is still Planned and a genuine human approval
    // can still land.
    let status = coordinator
        .change_set_status(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status");
    assert_eq!(status.state, ChangeSetState::Planned);
}

/// The stdio path and any unattributed caller carry `ActorType::Unknown`, not
/// `Human` — the same denial applies, so a caller context that never
/// established who is acting cannot approve either.
#[tokio::test]
async fn test_approve_by_unknown_actor_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

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

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Unknown,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "approver_actor_type");
}

/// The self-approval check must still win when both denials apply: a
/// non-human owner attempting to approve their own plan gets the
/// self-approval message, not the actor-type one, so an operator reading the
/// error is told the more specific and more actionable fact.
#[tokio::test]
async fn test_owner_approving_own_plan_as_agent_gets_self_approval_error() {
    let (_dir, coordinator) = setup_coordinator();

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

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "alice".to_string(),
                actor_type: mecmcp_audit::ActorType::Agent,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(
        err.message()
            .contains("owner cannot approve their own plan")
    );
}

#[tokio::test]
async fn test_second_approval_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    // First approval as bob
    let approved = coordinator
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
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);

    // Second approval as charlie must fail
    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: "charlie".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("not awaiting approval"));
}

#[tokio::test]
async fn test_expired_change_set_transitions_on_status_poll() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };

    // Use a 1-second approval TTL so it expires immediately
    let approval_ttl = Duration::from_secs(1);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    assert_eq!(created.state, ChangeSetState::Planned);

    // Wait for expiry
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Poll status
    let status = coordinator
        .change_set_status(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status");

    assert_eq!(status.state, ChangeSetState::Expired);
}

// Issue #50 tests: approval digest tamper-evidence

/// Helper to stage the production fixture as a private temp file.
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

#[tokio::test]
async fn test_production_fixture_loads_without_approval_digest() {
    // The production fixture has no approval digest (legacy records).
    // validate_state must accept it because `approval` is Option<ApprovalRecord>.
    let (_dir, path) = staged_production_fixture();

    let state = read_state(&path, 8 * 1024 * 1024).expect("load production fixture");

    assert_eq!(state.change_sets.len(), 6);

    // All six change sets have an approver but no approval digest
    for (id, record) in &state.change_sets {
        assert!(
            record.approver.is_some(),
            "change set {id} has an approver (legacy field)"
        );
        assert!(
            record.approval.is_none(),
            "change set {id} has no approval digest (legacy record)"
        );
    }
}

#[tokio::test]
async fn test_approval_digest_tamper_detection_swap_approver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    // Approve as bob
    let approved = coordinator
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
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));

    // Read the state file
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    // Tamper: swap approver to alice (masking a self-approval)
    let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
    if let Some(approval) = &mut record.approval {
        approval.approver = Some("alice".to_string()); // tamper
    }

    // Write the tampered state back
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write tampered state");

    // Attempt to reload — must be refused. The self-approval invariant now
    // rejects this shape outright, before the digest is even recomputed: a
    // record with owner == approver is illegal regardless of whether its
    // digest happens to verify.
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("same principal as owner and approver"),
        "Expected a self-approval rejection, got: {error_message}"
    );
}

/// Swapping the approver alone (as above) is caught by the stale digest, which
/// happens to still name "bob". A tampering party who also re-signs the
/// digest for the new (owner, owner) pair produces a record that is
/// internally self-consistent — the digest genuinely verifies what it claims
/// — and previously reached `apply` unchallenged. `read_state` must refuse it
/// on the self-approval invariant, not on digest mismatch, because there is
/// none.
#[tokio::test]
async fn test_self_consistent_forged_self_approval_digest_is_still_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

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

    let approved = coordinator
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
        .expect("approve");

    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
    if let Some(approval) = &mut record.approval {
        // Re-sign the digest for a self-approval so it is internally
        // consistent — this is exactly what `compute_approval_digest_v5`
        // being a public function lets any caller do.
        approval.approver = Some("alice".to_string());
        approval.digest = mecmcp_changeset::digest::compute_approval_digest_v5(
            &created.change_set_id,
            &record.digest,
            record.preview.as_ref().map(|p| p.digest.as_str()),
            "alice",
            "alice",
            approval.approved_at_unix,
        );
    }
    assert_eq!(approved.approver, Some("bob".to_string()));

    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write forged state");

    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(
        result.is_err(),
        "a self-consistent self-approval digest must still be rejected"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("same principal as owner and approver"),
        "Expected a self-approval rejection, got: {error_message}"
    );
}

/// `approve_change_set` refuses self-approval, but it is not the only public
/// way to move a change set to `Approved`: `update_change_set_from` writes
/// any record a caller hands it, gated only by `check_change_set_write`. A
/// caller that builds an "approved" record directly — never going through
/// `approve_change_set` at all — must be refused there too, or the owner
/// check is a property of one call path rather than of the change-set type.
#[tokio::test]
async fn test_self_approval_via_direct_update_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

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

    let mut record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(record.state, ChangeSetState::Planned);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    record.state = ChangeSetState::Approved;
    record.approver = Some("alice".to_string());
    record.approval = Some(ApprovalRecord {
        approver: Some("alice".to_string()),
        approved_at_unix: now,
        digest: mecmcp_changeset::digest::compute_approval_digest_v5(
            &created.change_set_id,
            &record.digest,
            record.preview.as_ref().map(|p| p.digest.as_str()),
            "alice",
            "alice",
            now,
        ),
        digest_version: 5,
        waived: None,
        mechanism: None,
        issuer: None,
        subject: None,
    });

    let result = coordinator
        .update_change_set_from(ChangeSetState::Planned, record)
        .await;
    assert!(
        result.is_err(),
        "a self-approved record must not be writable by bypassing approve_change_set"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("cannot approve their own plan"),
        "Expected a self-approval rejection, got: {error_message}"
    );

    // And the change set is still exactly where it was left: Planned.
    let record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(record.state, ChangeSetState::Planned);
}

/// A rewritten owner would otherwise let two writes each individually satisfy
/// "approver != owner" while the same principal both created and approved the
/// plan: rewrite `owner` to a co-conspirator on one write, then approve as the
/// original owner on the next. Freezing `owner`, `device` and `digest` at
/// creation (in `check_change_set_write`) closes this at the write that
/// attempts the rewrite, before any approval is granted.
#[tokio::test]
async fn test_owner_rewrite_is_refused_even_though_neither_write_self_approves() {
    let (_dir, coordinator) = setup_coordinator();

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

    let mut rewritten = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(rewritten.owner, "alice");
    rewritten.owner = "mallory".to_string();

    let result = coordinator
        .update_change_set_from(ChangeSetState::Planned, rewritten)
        .await;
    assert!(
        result.is_err(),
        "a change set's owner must be fixed at creation, not rewritable through \
         an ordinary update"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("fixed at creation"),
        "Expected an owner-frozen rejection, got: {error_message}"
    );

    // The record is untouched: still owned by alice, still Planned, and she
    // can still legitimately be refused if she tries to approve her own plan.
    let record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(record.owner, "alice");
    assert_eq!(record.state, ChangeSetState::Planned);
}

/// `insert_change_set` doesn't go through `check_change_set_write`, so a
/// caller handing it a `Planned` record that already carries a
/// self-consistent approval (forged, but internally consistent, the way
/// `test_self_consistent_forged_self_approval_digest_is_still_rejected` shows
/// is possible) would otherwise be stored unchecked. Invariant 4 blocks it
/// from ever reaching `Approved`, but a stored record like this fails
/// `validate_state_with_key` on the next reload — taking every change set in
/// the file down with it. Creation must refuse it outright.
#[tokio::test]
async fn test_insert_refuses_a_record_that_already_carries_approval() {
    let (_dir, coordinator) = setup_coordinator();

    let owner = "alice";
    let device = "device-a";
    let fingerprint = test_fingerprint();
    let actions = vec![serde_json::json!({"action": "set", "target": "/test/path"})];
    let digest = change_set_digest(owner, device, &fingerprint, &actions).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = ChangeSetRecord {
        id: "1".repeat(64),
        device: device.to_owned(),
        owner: owner.to_owned(),
        digest: digest.clone(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        state: ChangeSetState::Planned,
        expires_at_unix: u64::MAX,
        operation_id: None,
        approver: Some(owner.to_owned()),
        approval: Some(ApprovalRecord {
            approver: Some(owner.to_owned()),
            approved_at_unix: now,
            digest: mecmcp_changeset::digest::compute_approval_digest_v5(
                &"1".repeat(64),
                &digest,
                None,
                owner,
                owner,
                now,
            ),
            digest_version: 5,
            waived: None,
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        policy_signature: "policy-sig".to_owned(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };

    let result = coordinator.insert_change_set(record).await;
    assert!(
        result.is_err(),
        "a change set must be created unapproved, not with approval attached"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("created unapproved"),
        "Expected an unapproved-at-creation rejection, got: {error_message}"
    );
}

#[tokio::test]
async fn test_new_approval_has_approval_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
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

    // Approve as bob
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
        .expect("approve");

    // Read the state file and verify approval digest exists
    let state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get(&created.change_set_id).unwrap();

    assert!(record.approval.is_some(), "approval record must be present");
    let approval = record.approval.as_ref().unwrap();
    assert_eq!(approval.approver, Some("bob".to_string()));
    assert!(approval.digest.starts_with("sha256:"));
    assert_eq!(approval.digest.len(), "sha256:".len() + 64);
}

/// MEC-994 W4: in strict mode, a `TokenAsserted` approver — even a genuinely
/// distinct, human principal — is refused. Only a verified IdP assertion
/// satisfies the two-person rule once strict mode is on.
#[tokio::test]
async fn strict_mode_refuses_a_token_asserted_approver() {
    let (_dir, coordinator, _key) = setup_strict_coordinator();

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("strict verified-approver mode")
    );
}

/// MEC-994 W4: strict mode accepts an `OidcVerified` approver distinct from
/// the owner, and the stored record carries the mechanism and digest version
/// that prove it.
#[tokio::test]
async fn strict_mode_accepts_an_oidc_verified_approver() {
    let (dir, coordinator, key) = setup_strict_coordinator();
    let state_path = dir.path().join("state.json");

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &oidc_verified_approver("bob", "https://idp.example", "bob-sub"),
            created.digest.clone(),
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);

    let state = read_state_with_key(&state_path, 8 * 1024 * 1024, Some(&key)).expect("read state");
    let record = state.change_sets.get(&created.change_set_id).unwrap();
    let approval = record.approval.as_ref().expect("approval");
    assert_eq!(approval.digest_version, 7);
    assert_eq!(approval.mechanism.as_deref(), Some("oidc"));
    assert_eq!(approval.issuer.as_deref(), Some("https://idp.example"));
    assert_eq!(approval.subject.as_deref(), Some("bob-sub"));
}

/// MEC-994 W4: the owner cannot satisfy the two-person rule by approving
/// through a second token bound to the same verified IdP subject.
#[tokio::test]
async fn an_approver_sharing_the_owners_verified_subject_is_refused() {
    let (_dir, coordinator, _key) = setup_strict_coordinator();

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    // "alice-second-token" is a distinct principal name, but its verified
    // subject is the owner's own — the same human holding two tokens.
    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &oidc_verified_approver("alice-second-token", "https://idp.example", "alice-sub"),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("same IdP identity as the change-set owner")
    );
}

/// MEC-994 W4: strict mode refuses to propose a change set for an owner whose
/// token carries no `oidc_subject` binding.
#[tokio::test]
async fn strict_mode_refuses_to_propose_without_an_owner_subject() {
    let (_dir, coordinator, _key) = setup_strict_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let result = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("oidc_subject binding")
    );
}

/// MEC-994 W4: editing `mechanism`/`issuer`/`subject` onto a non-v7 approval
/// record invalidates it on load, even though those fields are not what a
/// v4/v5/v6 digest binds.
#[tokio::test]
async fn v7_only_fields_on_a_non_v7_record_are_rejected_on_load() {
    let (dir, coordinator) = setup_coordinator();
    let state_path = dir.path().join("state.json");

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
            &ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: mecmcp_audit::ActorType::Human,
            },
            created.digest.clone(),
        )
        .await
        .expect("approve");

    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    {
        let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
        let approval = record.approval.as_mut().unwrap();
        assert_eq!(approval.digest_version, 5, "no key configured, so v5");
        approval.mechanism = Some("oidc".to_string());
        approval.issuer = Some("https://evil.example".to_string());
        approval.subject = Some("forged".to_string());
    }
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write forged state");

    let reloaded = read_state(&state_path, 8 * 1024 * 1024);
    assert!(reloaded.is_err());
    assert!(
        reloaded
            .unwrap_err()
            .to_string()
            .contains("only a v7 digest binds")
    );
}

/// MEC-994 Percy review F2: strict mode must refuse a lab-mode waiver
/// outright, not just reject a non-`OidcVerified` approval. Before this fix,
/// `waive_approval` checked only `lab_mode()`, so a coordinator built with
/// both `with_require_verified_approver(true)` and lab mode on let the owner
/// waive their own approval — bypassing strict mode entirely rather than
/// being gated by it.
#[tokio::test]
async fn strict_mode_refuses_a_lab_mode_waiver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    // lab_mode = true alongside strict mode — the combination
    // `VerifiedApproverArgs::validate` refuses at CLI startup, but this
    // coordinator is built directly, bypassing that courtesy pre-check, to
    // prove the library itself still refuses.
    let coordinator = ChangesetCoordinator::load(
        Some(&state_path),
        limits,
        Duration::from_secs(15 * 60),
        true,
    )
    .expect("coordinator")
    .with_approval_digest_key(random_key())
    .with_require_verified_approver(true);

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    let result = coordinator
        .waive_approval(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("refused under strict verified-approver mode")
    );
}

/// MEC-994 Percy review F3: strict mode without a keyed approval digest must
/// refuse to approve, not silently fall back to an unkeyed v5 approval that
/// drops the mechanism/issuer/subject fields strict mode exists to make
/// tamper-evident.
#[tokio::test]
async fn strict_mode_without_a_digest_key_refuses_to_approve() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    // Strict mode, deliberately with no `with_approval_digest_key` call.
    let coordinator = ChangesetCoordinator::load(
        Some(&state_path),
        limits,
        Duration::from_secs(15 * 60),
        false,
    )
    .expect("coordinator")
    .with_require_verified_approver(true);

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &oidc_verified_approver("bob", "https://idp.example", "bob-sub"),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires a keyed approval digest")
    );
}

/// MEC-994 Percy review F4: strict mode must refuse to approve a change set
/// whose `owner_subject` is absent, even though that field is not itself
/// covered by any digest on a `Planned` record and so could have been
/// stripped from the state file after proposal rather than genuinely never
/// set. Without this check, stripping `owner_subject` from a pending change
/// set would silently disable the self-approval check for it.
#[tokio::test]
async fn strict_mode_refuses_to_approve_when_owner_subject_is_missing() {
    let (dir, coordinator, key) = setup_strict_coordinator();
    let state_path = dir.path().join("state.json");

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    // Simulate `owner_subject` having been stripped from the state file
    // after proposal — not reachable through the public API, which is the
    // point: this field is not itself tamper-evident on a `Planned` record.
    drop(coordinator);
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    state
        .change_sets
        .get_mut(&created.change_set_id)
        .unwrap()
        .owner_subject = None;
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    let coordinator = ChangesetCoordinator::load(
        Some(&state_path),
        OperationLimits {
            max_operations: 1024,
            max_change_sets: 1024,
            max_actions_per_set: 64,
            max_state_bytes: 8 * 1024 * 1024,
            max_change_set_bytes: 256 * 1024,
            ..OperationLimits::default()
        },
        Duration::from_secs(15 * 60),
        false,
    )
    .expect("coordinator")
    .with_approval_digest_key(std::sync::Arc::clone(&key))
    .with_require_verified_approver(true);

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &oidc_verified_approver("bob", "https://idp.example", "bob-sub"),
            created.digest.clone(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires the change set to carry an owner_subject")
    );
}

/// MEC-994 Percy review F10: an operator waiver (`waive_approval_operator`)
/// has no verified-identity check of its own, so without this guard an
/// owner could grant themselves an operator waiver under strict mode and
/// reach `Approved` with no verified second human at all — exactly the
/// property strict mode exists to prevent.
#[tokio::test]
async fn strict_mode_refuses_an_operator_waiver() {
    let (dir, coordinator, _key) = setup_strict_coordinator();
    let _ = &dir;

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
            Some(OwnerSubject {
                issuer: "https://idp.example".to_string(),
                subject: "alice-sub".to_string(),
            }),
        )
        .await
        .expect("create");

    let result = coordinator
        .waive_approval_operator(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
            WaiverKind::OperatorTool,
            "authorised exception".to_string(),
            None,
            None,
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("refused under strict verified-approver mode")
    );
}
