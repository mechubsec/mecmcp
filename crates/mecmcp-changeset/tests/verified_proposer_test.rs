//! Strict verified-proposer mode (mecmcp#400): the owner of a change set is IdP-verified, so
//! the two-person rule compares two verified subjects instead of an operator-typed one.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::approver::{ApproverIdentity, ProposerIdentity};
use mecmcp_changeset::records::OwnerSubject;
use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use std::time::Duration;

const FINGERPRINT: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ISSUER: &str = "https://idp.example";

fn coordinator(dir: &tempfile::TempDir, strict_proposer: bool) -> ChangesetCoordinator {
    ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap()
    .with_require_verified_proposer(strict_proposer)
}

fn attribution(
    principal: mecmcp_audit::Principal,
    verified: Option<&str>,
) -> mecmcp_audit::Attribution {
    mecmcp_audit::Attribution {
        principal,
        actor_type: mecmcp_audit::ActorType::Human,
        verified_proposer: verified
            .map(|subject| mecmcp_auth::VerifiedProposer::for_test(ISSUER, subject)),
        ..mecmcp_audit::Attribution::stdio()
    }
}

fn token_subject(subject: &str) -> Option<OwnerSubject> {
    Some(OwnerSubject {
        issuer: ISSUER.to_owned(),
        subject: subject.to_owned(),
    })
}

async fn propose(
    coordinator: &ChangesetCoordinator,
    owner: &str,
    proposer: &ProposerIdentity,
) -> Result<(String, String), String> {
    coordinator
        .create_change_set_as(
            "device-a".to_owned(),
            vec!["set x".to_owned()],
            owner.to_owned(),
            FINGERPRINT.to_owned(),
            "policy-sig".to_owned(),
            proposer,
        )
        .await
        .map(|created| (created.change_set_id, created.digest))
        .map_err(|error| error.message().to_owned())
}

fn token_proposer(subject: &str) -> ProposerIdentity {
    let attribution = attribution(mecmcp_audit::Principal::Token("agent".to_owned()), None);
    ProposerIdentity::from_attribution(&attribution, token_subject(subject))
}

fn verified_proposer(subject: &str) -> ProposerIdentity {
    let attribution = attribution(
        mecmcp_audit::Principal::Token("agent".to_owned()),
        Some(subject),
    );
    ProposerIdentity::from_attribution(&attribution, token_subject(subject))
}

fn state_version(dir: &tempfile::TempDir) -> u64 {
    let text = std::fs::read_to_string(dir.path().join("state.json")).unwrap();
    serde_json::from_str::<serde_json::Value>(&text).unwrap()["version"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn strict_mode_refuses_a_token_asserted_proposer_however_it_arrives() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = coordinator(&dir, true);
    let refused = propose(&coordinator, "agent", &token_proposer("alice")).await;
    assert!(refused.unwrap_err().contains("IdP-verified proposer"));
    // The older entry point can only ever carry a token-asserted subject.
    let legacy = coordinator
        .create_change_set(
            "device-a".to_owned(),
            vec!["set x".to_owned()],
            "agent".to_owned(),
            FINGERPRINT.to_owned(),
            "policy-sig".to_owned(),
            token_subject("alice"),
        )
        .await;
    assert!(
        legacy
            .unwrap_err()
            .message()
            .contains("IdP-verified proposer")
    );
    assert!(coordinator.change_sets().await.is_empty());
}

#[tokio::test]
async fn a_verified_proposer_is_recorded_as_verified() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = coordinator(&dir, true);
    let (id, _) = propose(&coordinator, "agent", &verified_proposer("alice"))
        .await
        .unwrap();
    let record = coordinator.change_set(&id, "device-a").await.unwrap();
    assert!(record.owner_verified);
    assert_eq!(record.owner_subject, token_subject("alice"));
    assert_eq!(state_version(&dir), 9);
}

#[tokio::test]
async fn an_oauth_principal_is_already_verified() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = coordinator(&dir, true);
    let oauth = attribution(
        mecmcp_audit::Principal::OAuth {
            issuer: ISSUER.to_owned(),
            subject: "carol".to_owned(),
            client_id: None,
        },
        None,
    );
    let proposer = ProposerIdentity::from_attribution(&oauth, None);
    let (id, _) = propose(&coordinator, &oauth.principal.to_string(), &proposer)
        .await
        .unwrap();
    let record = coordinator.change_set(&id, "device-a").await.unwrap();
    assert!(record.owner_verified);
    assert_eq!(record.owner_subject, token_subject("carol"));
}

#[tokio::test]
async fn off_by_default_a_token_asserted_proposal_is_unchanged_and_writes_no_new_version() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = coordinator(&dir, false);
    let (id, _) = propose(&coordinator, "agent", &token_proposer("alice"))
        .await
        .unwrap();
    let record = coordinator.change_set(&id, "device-a").await.unwrap();
    assert!(!record.owner_verified);
    assert_eq!(
        state_version(&dir),
        8,
        "owner_subject alone is still version 8"
    );
    let state = std::fs::read_to_string(dir.path().join("state.json")).unwrap();
    assert!(!state.contains("owner_verified"));
}

#[tokio::test]
async fn the_verified_marker_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let id = {
        let coordinator = coordinator(&dir, true);
        propose(&coordinator, "agent", &verified_proposer("alice"))
            .await
            .unwrap()
            .0
    };
    let reloaded = coordinator(&dir, true);
    assert!(
        reloaded
            .change_set(&id, "device-a")
            .await
            .unwrap()
            .owner_verified
    );
}

fn human_approver(principal: &str) -> ApproverIdentity {
    ApproverIdentity::TokenAsserted {
        principal: principal.to_owned(),
        actor_type: mecmcp_audit::ActorType::Human,
    }
}

#[tokio::test]
async fn approval_refuses_a_change_set_whose_owner_was_never_verified() {
    let dir = tempfile::tempdir().unwrap();
    // Proposed before the mode was on, then the mode is turned on.
    let before = coordinator(&dir, false);
    let (id, digest) = propose(&before, "agent", &token_proposer("alice"))
        .await
        .unwrap();
    drop(before);
    let strict = coordinator(&dir, true);
    let refused = strict
        .approve_change_set(
            id.clone(),
            "device-a".to_owned(),
            &human_approver("bob"),
            digest,
        )
        .await;
    assert!(
        refused
            .unwrap_err()
            .message()
            .contains("IdP-verified when it was proposed")
    );
}

#[tokio::test]
async fn approval_of_a_verified_owner_proceeds_and_the_same_verified_subject_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = coordinator(&dir, true);
    let (id, digest) = propose(&coordinator, "agent", &verified_proposer("alice"))
        .await
        .unwrap();

    // The same IdP identity behind a second token is the same person.
    let same_person = ApproverIdentity::from_attribution(&mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::Token("alice-2".to_owned()),
        actor_type: mecmcp_audit::ActorType::Human,
        verified_approver: Some(mecmcp_auth::VerifiedApprover::for_test(ISSUER, "alice")),
        ..mecmcp_audit::Attribution::stdio()
    });
    let refused = coordinator
        .approve_change_set(
            id.clone(),
            "device-a".to_owned(),
            &same_person,
            digest.clone(),
        )
        .await;
    assert!(refused.unwrap_err().message().contains("same IdP identity"));

    coordinator
        .approve_change_set(id, "device-a".to_owned(), &human_approver("bob"), digest)
        .await
        .expect("a different person approves");
}
