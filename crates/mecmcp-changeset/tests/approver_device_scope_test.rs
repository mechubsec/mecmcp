#![allow(clippy::unwrap_used)]
//! An approver may approve only a change set on a device inside their device scope, and a
//! selector-scoped token's scope is narrowed by inventory attributes (mecmcp#400).
//!
//! A change set targets exactly one device, so "every device the change set targets is in the
//! approver's scope" is one `authorize_target` on that device. The coordinator takes no caller
//! scope; the server handler enforces it, as `approve_*_change_set` does in the vendor
//! servers. This test composes the same two calls those handlers make.

use mecmcp_auth::{
    ActorType, CallerCtx, DeviceAttributeSource, DeviceAttrs, NoGrant, ScopeSet, TokenEntry,
    TokenSecret,
};
use mecmcp_changeset::approver::ApproverIdentity;
use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use mecmcp_server::authorize::authorize_target;
use std::time::Duration;

struct Fleet;

impl DeviceAttributeSource for Fleet {
    fn device_attributes(&self) -> Vec<(String, DeviceAttrs)> {
        [("lab-fw-1", "lab-a"), ("prod-fw-1", "prod-a")]
            .iter()
            .map(|(name, site)| {
                let attrs = serde_json::from_str(&format!(r#"{{"site":"{site}"}}"#)).unwrap();
                ((*name).to_owned(), attrs)
            })
            .collect()
    }
}

fn approver_token(selectors: Option<Vec<String>>) -> CallerCtx<NoGrant> {
    let (_secret, digest) = TokenSecret::mint().unwrap();
    let entry = TokenEntry::<NoGrant> {
        name: "approver".to_owned(),
        digest,
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        created_at: chrono::Utc::now(),
        expires_at: None,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
        oidc_subject: None,
        device_selectors: selectors,
    };
    CallerCtx::from_entry_with_attributes(&entry, Some(&Fleet))
}

/// What a vendor server's approve handler does: scope check, then the coordinator.
async fn approve(
    coordinator: &ChangesetCoordinator,
    caller: &CallerCtx<NoGrant>,
    device: &str,
    change_set_id: &str,
    digest: &str,
) -> Result<(), String> {
    authorize_target(Some(caller), "approve_change_set", device).map_err(|e| e.to_string())?;
    let approver = ApproverIdentity::TokenAsserted {
        principal: caller.token_name.clone(),
        actor_type: mecmcp_audit::ActorType::Human,
    };
    coordinator
        .approve_change_set(
            change_set_id.to_owned(),
            device.to_owned(),
            &approver,
            digest.to_owned(),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.message().to_owned())
}

async fn propose(coordinator: &ChangesetCoordinator, device: &str) -> (String, String) {
    let created = coordinator
        .create_change_set(
            device.to_owned(),
            vec!["set x".to_owned()],
            "owner".to_owned(),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            "policy-sig".to_owned(),
            None,
        )
        .await
        .unwrap();
    (created.change_set_id, created.digest)
}

#[tokio::test]
async fn a_lab_scoped_approver_cannot_approve_a_prod_change_set() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();
    let (lab_id, lab_digest) = propose(&coordinator, "lab-fw-1").await;
    let (prod_id, prod_digest) = propose(&coordinator, "prod-fw-1").await;
    let lab_approver = approver_token(Some(vec!["site=lab-*".to_owned()]));

    let refused = approve(
        &coordinator,
        &lab_approver,
        "prod-fw-1",
        &prod_id,
        &prod_digest,
    )
    .await;
    assert!(refused.unwrap_err().contains("not authorized"));
    // The refusal happened before the coordinator: the prod change set is still Planned.
    let prod = coordinator.change_set(&prod_id, "prod-fw-1").await.unwrap();
    assert_eq!(prod.state, mecmcp_changeset::ChangeSetState::Planned);

    approve(
        &coordinator,
        &lab_approver,
        "lab-fw-1",
        &lab_id,
        &lab_digest,
    )
    .await
    .expect("the same approver may approve inside their scope");

    // Control: an approver with no selectors keeps working everywhere.
    approve(
        &coordinator,
        &approver_token(None),
        "prod-fw-1",
        &prod_id,
        &prod_digest,
    )
    .await
    .expect("a wildcard approver is unchanged");
}

/// A multi-target change set is judged on every target, not just its primary device.
#[tokio::test]
async fn a_lab_scoped_approver_cannot_approve_a_set_that_also_targets_prod() {
    use mecmcp_changeset::records::ChangeSetRecord;
    use mecmcp_changeset::{ChangeSetState, change_set_digest_with_targets};

    let dir = tempfile::tempdir().unwrap();
    let coordinator = ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "set"})];
    let targets = vec!["lab-fw-1".to_owned(), "prod-fw-1".to_owned()];
    let digest =
        change_set_digest_with_targets("owner", "lab-fw-1", &fingerprint, &actions, &targets)
            .unwrap();
    let record = ChangeSetRecord {
        id: "a".repeat(64),
        owner: "owner".to_owned(),
        device: "lab-fw-1".to_owned(),
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest: digest.clone(),
        state: ChangeSetState::Planned,
        approver: None,
        approval: None,
        expires_at_unix: u64::MAX / 2,
        operation_id: None,
        policy_signature: String::new(),
        targets,
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
        owner_verified: false,
    };
    let id = record.id.clone();
    coordinator.insert_change_set(record).await.unwrap();

    let lab_approver = approver_token(Some(vec!["site=lab-*".to_owned()]));
    let approver = ApproverIdentity::TokenAsserted {
        principal: lab_approver.token_name.clone(),
        actor_type: mecmcp_audit::ActorType::Human,
    };
    let in_lab = |name: &str| lab_approver.devices.allows(name);
    let refused = coordinator
        .approve_change_set_within(
            id.clone(),
            "lab-fw-1".to_owned(),
            &approver,
            digest.clone(),
            &in_lab,
        )
        .await;
    assert!(refused.unwrap_err().message().contains("every device"));
    let still = coordinator.change_set(&id, "lab-fw-1").await.unwrap();
    assert_eq!(still.state, ChangeSetState::Planned);

    // Control: an approver whose scope covers both targets approves it.
    let wide = approver_token(None);
    let in_wide = |name: &str| wide.devices.allows(name);
    coordinator
        .approve_change_set_within(id, "lab-fw-1".to_owned(), &approver, digest, &in_wide)
        .await
        .expect("a wildcard approver covers every target");
}

fn assert_send<T: Send>(_: &T) {}

/// rmcp handlers are `Send` futures: holding the scope closure across the `.await` must not
/// take that away. Fails to compile if the future stops being `Send`.
#[tokio::test]
async fn the_scoped_approve_future_is_send() {
    let dir = tempfile::tempdir().unwrap();
    let coordinator = ChangesetCoordinator::load(
        Some(&dir.path().join("state.json")),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();
    let approver = ApproverIdentity::TokenAsserted {
        principal: "a".to_owned(),
        actor_type: mecmcp_audit::ActorType::Human,
    };
    let allow = |_: &str| true;
    let future = coordinator.approve_change_set_within(
        "x".to_owned(),
        "d".to_owned(),
        &approver,
        String::new(),
        &allow,
    );
    assert_send(&future);
}
