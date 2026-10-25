//! `Principal::OAuth` persistence and self-approval identity (mecmcp#498).

use mecmcp_changeset::approver::ApproverIdentity;
use mecmcp_changeset::records::{PersistedAttribution, PersistedPrincipal};
use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use std::time::Duration;

#[test]
fn an_oauth_principal_survives_a_json_round_trip_as_a_tagged_variant() {
    let principal = PersistedPrincipal::OAuth {
        issuer: "https://idp.example".into(),
        subject: "alice".into(),
        client_id: Some("odysseus".into()),
    };
    let json = serde_json::to_value(&principal).expect("serialise");
    assert_eq!(
        json,
        serde_json::json!({
            "type": "oauth",
            "value": {"issuer": "https://idp.example", "subject": "alice", "client_id": "odysseus"}
        })
    );
    let back: PersistedPrincipal = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, principal);
}

fn oauth_attribution(issuer: &str, subject: &str) -> mecmcp_audit::Attribution {
    mecmcp_audit::Attribution {
        principal: mecmcp_audit::Principal::OAuth {
            issuer: issuer.into(),
            subject: subject.into(),
            client_id: None,
        },
        ..mecmcp_audit::Attribution::stdio()
    }
}

#[test]
fn an_oauth_attribution_persists_as_oauth_not_as_a_token() {
    let persisted = PersistedAttribution::from(&oauth_attribution("https://idp.example", "alice"));
    assert!(matches!(
        persisted.principal,
        PersistedPrincipal::OAuth { .. }
    ));
}

fn approver_for(attribution: &mecmcp_audit::Attribution) -> ApproverIdentity {
    ApproverIdentity::from_attribution(&mecmcp_audit::Attribution {
        actor_type: mecmcp_audit::ActorType::Human,
        ..attribution.clone()
    })
}

async fn coordinator_with_change_set(
    owner: &mecmcp_audit::Attribution,
) -> (tempfile::TempDir, ChangesetCoordinator, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let coordinator = ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("coordinator");
    // Downstream servers record `attribution.principal.to_string()` as owner.
    let created = coordinator
        .create_change_set(
            "device-a".to_owned(),
            vec!["set x".to_owned()],
            owner.principal.to_string(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            "policy-sig".to_owned(),
            None,
        )
        .await
        .expect("create");
    (dir, coordinator, created.change_set_id, created.digest)
}

#[tokio::test]
async fn an_oauth_owner_cannot_approve_their_own_change_set() {
    let alice = oauth_attribution("https://a", "alice");
    let (_dir, coordinator, id, digest) = coordinator_with_change_set(&alice).await;
    let error = coordinator
        .approve_change_set(id, "device-a".to_owned(), &approver_for(&alice), digest)
        .await
        .expect_err("self-approval must be refused");
    assert!(
        error.message().contains("owner cannot approve"),
        "{}",
        error.message()
    );
}

#[tokio::test]
async fn the_same_subject_from_another_issuer_is_a_different_owner() {
    let alice = oauth_attribution("https://a", "alice");
    let impostor = oauth_attribution("https://b", "alice");
    assert_ne!(alice.principal.to_string(), impostor.principal.to_string());
    let (_dir, coordinator, id, digest) = coordinator_with_change_set(&alice).await;
    // Not the owner, so it may not cancel the other issuer's change set...
    let cancel = coordinator
        .cancel_change_set(
            id.clone(),
            "device-a".to_owned(),
            impostor.principal.to_string(),
        )
        .await;
    assert!(cancel.is_err(), "{cancel:?}");
    // ...and approving is not refused as self-approval.
    let outcome = coordinator
        .approve_change_set(id, "device-a".to_owned(), &approver_for(&impostor), digest)
        .await;
    assert!(outcome.is_ok(), "{outcome:?}");
}
