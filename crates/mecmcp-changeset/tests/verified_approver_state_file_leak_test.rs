//! MEC-1511 (deferred from MEC-994 Percy review F5): the acceptance
//! criteria name four sinks a presented approver assertion's raw JWT must
//! never reach — tool result, logs, audit events, and the state file.
//! `mecmcp-transport`'s `approver_assertion.rs` tests cover the first three;
//! this covers the fourth, the one sink this crate itself owns.
//!
//! `ApproverIdentity::OidcVerified` can only ever carry an issuer and a
//! subject (`mecmcp_auth::VerifiedApprover`, deliberately minimal — "no raw
//! claims, the spec requires the JWT itself never be retained past
//! verification"). This test drives a real approval through to disk and
//! greps the persisted state file for a stand-in "raw assertion" value that
//! was never passed to any `mecmcp-changeset` API, proving the on-disk
//! record carries only the derived issuer/subject, not the token a real
//! caller would have presented over HTTP.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::{ActorType, Attribution, Principal, TokenVerifiedFields};
use mecmcp_changeset::{ApproverIdentity, ChangesetCoordinator, OperationLimits};
use std::time::Duration;

/// A JWT-shaped value standing in for the raw assertion a real caller would
/// present in the `Mecmcp-Approver-Assertion` header. Synthetic, not a real
/// signed token — only its shape (three dot-separated base64url segments)
/// and the fact that it must never appear on disk matter here.
const RAW_ASSERTION_JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIn0.\
     fake-signature-never-should-reach-the-state-file";

const APPROVER_ISSUER: &str = "https://idp.example.com";
const APPROVER_SUBJECT: &str = "alice";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

/// A keyed digest is what actually persists `mechanism`/`issuer`/`subject`
/// onto the approval record (the unkeyed v5 digest drops all three): the
/// state-file leak this test guards against only has anything to find once
/// the coordinator is configured the way a deployment recording verified
/// approvals for real would be.
fn setup_coordinator() -> (tempfile::TempDir, std::path::PathBuf, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let coordinator = ChangesetCoordinator::load(
        Some(&state_path),
        OperationLimits::default(),
        Duration::from_secs(15 * 60),
        false,
    )
    .expect("coordinator")
    .with_approval_digest_key(
        std::sync::Arc::from(vec![0x42u8; 32].into_boxed_slice()) as std::sync::Arc<[u8]>
    );
    (dir, state_path, coordinator)
}

/// Builds the `Attribution` a real approval request would carry once
/// `mecmcp-transport`'s bearer preflight has bound a verified assertion to
/// the caller — i.e. with `verified_approver` populated, never with the raw
/// JWT itself (that type has nowhere to put it).
fn verified_approver_attribution(principal: &str) -> Attribution {
    Attribution {
        principal: Principal::Token(principal.to_owned()),
        actor_type: ActorType::Human,
        agent: None,
        on_behalf_of: None,
        change_ref: None,
        request_id: uuid::Uuid::new_v4(),
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: Some(mecmcp_auth::VerifiedApprover::for_test(
            APPROVER_ISSUER,
            APPROVER_SUBJECT,
        )),
        approver: None,
        change_set_id: None,
    }
}

#[tokio::test]
async fn an_approved_change_sets_state_file_never_carries_the_raw_assertion() {
    let (_dir, state_path, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "owner".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    let approver_attribution = verified_approver_attribution("bob");
    let approver = ApproverIdentity::from_attribution(&approver_attribution);
    assert!(
        matches!(approver, ApproverIdentity::OidcVerified { .. }),
        "the test fixture must exercise the OIDC-verified path, not token-asserted"
    );

    coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            &approver,
            created.digest.clone(),
        )
        .await
        .expect("approve");

    let on_disk = std::fs::read_to_string(&state_path).expect("read state file");

    assert!(
        !on_disk.contains(RAW_ASSERTION_JWT),
        "the raw approver assertion must never reach the state file: {on_disk}"
    );
    assert!(
        on_disk.contains(APPROVER_ISSUER),
        "the verified issuer is expected to be persisted: {on_disk}"
    );
    assert!(
        on_disk.contains(APPROVER_SUBJECT),
        "the verified subject is expected to be persisted: {on_disk}"
    );
}
