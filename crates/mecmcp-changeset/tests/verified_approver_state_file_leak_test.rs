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
//! checks two things about the persisted state file: that it does not
//! contain a stand-in "raw assertion" value never passed to any
//! `mecmcp-changeset` API, and — since a plain substring search cannot fail
//! if a *new* field were added later to carry claims — that the persisted
//! approval object's key set is exactly the allowlist of fields
//! `ApprovalRecord` is documented to carry. A field added to that struct
//! without updating this allowlist makes this test fail.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::{ActorType, Attribution, Principal, TokenVerifiedFields};
use mecmcp_changeset::{ApproverIdentity, ChangesetCoordinator, OperationLimits};
use std::collections::BTreeSet;
use std::time::Duration;

/// A JWT-shaped value standing in for the raw assertion a real caller would
/// present in the `Mecmcp-Approver-Assertion` header. Synthetic, not a real
/// signed token — only its shape (three dot-separated base64url segments)
/// and the fact that it must never appear on disk matter here.
const RAW_ASSERTION_JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIn0.\
     fake-signature-never-should-reach-the-state-file";

/// The complete set of keys `ApprovalRecord` (`records.rs`) is allowed to
/// serialize for an OIDC-verified approval. `#[serde(deny_unknown_fields)]`
/// on `ApprovalRecord` already stops an *unrecognized* on-disk key from
/// loading; this allowlist instead stops a *recognized* field — one added to
/// the struct to carry more of the verified claims than issuer/subject —
/// from silently starting to persist here.
const EXPECTED_APPROVAL_KEYS: &[&str] = &[
    "approver",
    "approved_at_unix",
    "digest",
    "digest_version",
    "mechanism",
    "issuer",
    "subject",
];

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

    let on_disk_json: serde_json::Value =
        serde_json::from_str(&on_disk).expect("state file is valid JSON");
    let approval = on_disk_json["state"]["change_sets"][&created.change_set_id]["approval"]
        .as_object()
        .expect("approved change set has an approval object");
    let actual_keys: BTreeSet<&str> = approval.keys().map(String::as_str).collect();
    let expected_keys: BTreeSet<&str> = EXPECTED_APPROVAL_KEYS.iter().copied().collect();
    assert_eq!(
        actual_keys, expected_keys,
        "the persisted approval record carries a field outside the allowlist \
         (or is missing one); if this is a deliberate new verified-approver \
         claim, update EXPECTED_APPROVAL_KEYS and confirm the new field is \
         safe to persist: {on_disk}"
    );
}
