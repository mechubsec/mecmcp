//! Operator waivers (mecmcp#275): the kind, expiry and ticket are bound into
//! the digest, so a record cannot be relabelled or its time box extended.

// `WaiverKind` and `WaiverRecord` are re-exported at the crate root (lib.rs:32);
// the digest functions are NOT — they live behind `pub mod digest`. Importing
// them from the root does not compile.
use async_trait::async_trait;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal};
use mecmcp_changeset::digest::{
    change_set_digest, compute_approval_digest_v4 as compute_approval_digest,
    compute_waiver_digest, compute_waiver_digest_v3,
};
use mecmcp_changeset::persistence::{read_state, write_state_for_test};
use mecmcp_changeset::{
    ApprovalRecord, ApproverIdentity, ChangeSetRecord, ChangeSetState, ChangesetCoordinator,
    ChangesetState, CommitOptions, CommitOutcome, DeviceTransaction, OperationLimits,
    RollbackOutcome, RollbackRef, WaiverKind, WaiverRecord, validate_state,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn waiver(kind: WaiverKind, expires: Option<u64>, ticket: Option<&str>) -> WaiverRecord {
    WaiverRecord {
        kind,
        reason: "authorised exception".to_owned(),
        expires_at_unix: expires,
        ticket: ticket.map(str::to_owned),
    }
}

const ID: &str = "cs-1";
const PLAN: &str = "sha256:plan";
const OWNER: &str = "operator";
const AT: u64 = 1_000;

/// Every bound field must change the digest. This is the whole point: without
/// it the distinction is advisory and a record can be edited after the fact.
#[test]
fn each_bound_field_changes_the_digest() {
    let base = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );

    let other_kind = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorFile, None, None),
    );
    assert_ne!(
        base, other_kind,
        "kind is not bound: a waiver could be relabelled"
    );

    let with_expiry = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, Some(9_999), None),
    );
    assert_ne!(
        base, with_expiry,
        "expires_at is not bound: a time box could be extended"
    );

    let with_ticket = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, Some("CHG-1")),
    );
    assert_ne!(
        base, with_ticket,
        "ticket is not bound: an audit pointer could be rewritten"
    );

    let other_channel = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorTool, None, None),
    );
    assert_ne!(
        other_kind, other_channel,
        "the two operator channels must not collide"
    );
}

/// A value containing the old separator must not be able to impersonate a
/// different field arrangement. The legacy encoding joined fields with `|`;
/// this one serializes a tuple, so lengths are encoded.
#[test]
fn separator_bearing_values_cannot_shift_field_boundaries() {
    let a = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a|b".to_owned(),
            expires_at_unix: None,
            ticket: Some("c".to_owned()),
        },
    );
    let b = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a".to_owned(),
            expires_at_unix: None,
            ticket: Some("b|c".to_owned()),
        },
    );
    assert_ne!(a, b, "a `|` in a value shifted a field boundary");
}

/// A waiver digest must never equal an approval digest. The legacy waiver
/// digest achieved this with a literal marker; v3 uses a domain prefix.
#[test]
fn a_waiver_digest_is_never_an_approval_digest() {
    let waived = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );
    let approved = compute_approval_digest(ID, PLAN, OWNER, "someone-else", AT);
    assert_ne!(waived, approved);

    let legacy = compute_waiver_digest(ID, PLAN, OWNER, AT);
    assert_ne!(waived, legacy, "v3 must not reproduce the legacy digest");
}

/// v1 and v2 files must keep loading. On the evidence of a 2026-08-14 fleet
/// survey no waiver record exists anywhere, so this path is unreachable today —
/// but that is a statement about five hosts on one afternoon, not a property of
/// the format.
#[test]
fn legacy_schema_versions_still_validate() {
    use mecmcp_changeset::WaiverKind;

    for (fixture, version) in [
        (include_str!("fixtures/waiver-v1.json"), 1_u32),
        (include_str!("fixtures/waiver-v2.json"), 2_u32),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(fixture).expect("fixture parses");
        let state: ChangesetState =
            serde_json::from_value(parsed["state"].clone()).expect("fixture state decodes");
        validate_state(&state, version)
            .unwrap_or_else(|error| panic!("version {version} must still validate: {error:?}"));

        // Verify the waiver actually loaded and has the expected legacy structure
        let change_sets: Vec<_> = state.change_sets.values().collect();
        assert_eq!(
            change_sets.len(),
            1,
            "fixture must contain exactly one change set"
        );

        let cs = change_sets[0];
        let approval = cs.approval.as_ref().expect("change set must have approval");
        let waiver = approval.waived.as_ref().expect("approval must be waived");

        assert_eq!(
            waiver.kind,
            WaiverKind::LabMode,
            "legacy waiver must be LabMode"
        );
        assert_eq!(
            waiver.expires_at_unix, None,
            "legacy waiver must not have expiry"
        );
        assert_eq!(waiver.ticket, None, "legacy waiver must not have ticket");
        assert_eq!(
            waiver.reason, "lab-mode",
            "fixture must use exact legacy reason"
        );
    }
}

/// A waiver with non-LabMode kind, expiry, or ticket triggers v3 write and v3
/// verification. The v3 digest binds those fields; a forged legacy digest must
/// fail.
#[test]
fn v3_waiver_round_trip_and_version_dependence() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");

    let change_set_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let owner = "operator";
    let device = "firewall-1";
    let fingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let actions = vec![serde_json::json!({"set": "foo"})];
    let approved_at = 1_723_000_000_u64;

    // Compute the change-set digest
    let plan_digest =
        change_set_digest(owner, device, fingerprint, &actions).expect("compute digest");

    // Build a waiver with all v3-triggering fields: non-LabMode kind, expiry, ticket
    let waiver_record = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "documented exception".to_owned(),
        expires_at_unix: Some(1_723_999_999),
        ticket: Some("CHG-12345".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        change_set_id,
        &plan_digest,
        owner,
        approved_at,
        &waiver_record,
    );

    let change_set = ChangeSetRecord {
        id: change_set_id.to_owned(),
        owner: owner.to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint.to_owned(),
        actions,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        approver: None,
        approval: Some(ApprovalRecord {
            approver: None,
            approved_at_unix: approved_at,
            digest: waiver_digest.clone(),
            digest_version: 4,
            waived: Some(waiver_record.clone()),
            mechanism: None,
            issuer: None,
            subject: None,
        }),
        expires_at_unix: approved_at + 900,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
        task_id: None,
        apply_without_handle: false,
        owner_subject: None,
    };

    let mut state = ChangesetState {
        operations: BTreeMap::new(),
        change_sets: BTreeMap::new(),
    };
    state
        .change_sets
        .insert(change_set_id.to_owned(), change_set);

    // Write the state
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state with v3 waiver");

    // Assert the written file has version 3
    let raw_json = std::fs::read_to_string(&state_path).expect("read written state");
    let parsed: serde_json::Value = serde_json::from_str(&raw_json).expect("parse written state");
    assert_eq!(
        parsed["version"], 3,
        "a waiver with non-LabMode kind, expiry, and ticket must trigger version 3"
    );

    // Verify it reads back successfully
    let loaded_state =
        read_state(&state_path, 8 * 1024 * 1024).expect("v3 waiver record must load");
    assert_eq!(
        loaded_state.change_sets.len(),
        1,
        "change set must survive round trip"
    );

    // CRITICAL: prove version-dependence. A legacy digest must NOT satisfy a v3 record.
    let legacy_digest = compute_waiver_digest(change_set_id, &plan_digest, owner, approved_at);
    let mut tampered_state = loaded_state;
    tampered_state
        .change_sets
        .get_mut(change_set_id)
        .expect("change set present")
        .approval
        .as_mut()
        .expect("approval present")
        .digest = legacy_digest;

    let result = validate_state(&tampered_state, 3);
    assert!(
        result.is_err(),
        "a legacy digest must NOT verify a v3 record — the version determines the rule"
    );
    let error_message = result.expect_err("already checked is_err").to_string();
    assert!(
        error_message.contains("approval digest mismatch"),
        "expected digest mismatch, got: {error_message}"
    );
}

// ============================================================================
// Mock transaction for apply tests
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MockActionType {
    Set,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MockAction {
    action: MockActionType,
    path: String,
    value: Option<String>,
}

#[derive(Debug)]
struct MockStaged {
    actions: Vec<MockAction>,
    #[allow(dead_code)]
    before_fp: String,
    #[allow(dead_code)]
    after_fp: String,
}

#[derive(Debug, Clone, Serialize)]
struct MockDiff {
    changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MockValidation {
    succeeded: bool,
}

#[derive(Debug, Clone)]
struct MockDeviceState {
    config: std::collections::HashMap<String, String>,
}

impl Default for MockDeviceState {
    fn default() -> Self {
        let mut config = std::collections::HashMap::new();
        config.insert("/initial".to_string(), "value".to_string());
        Self { config }
    }
}

#[derive(Clone)]
struct MockTransaction {
    state: Arc<Mutex<MockDeviceState>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDeviceState::default())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum MockError {
    #[error("mock error: {0}")]
    Generic(String),
}

#[async_trait]
impl DeviceTransaction for MockTransaction {
    type Action = MockAction;
    type Staged = MockStaged;
    type Diff = MockDiff;
    type Validation = MockValidation;
    type Error = MockError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().expect("lock");
        let mut keys: Vec<_> = state.config.keys().cloned().collect();
        keys.sort();
        let concatenated = keys.join(":");
        let hash = sha2::Sha256::digest(concatenated.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let before_fp = self.fingerprint().await?;

        {
            let mut state = self.state.lock().expect("lock");
            for action in actions {
                match action.action {
                    MockActionType::Set => {
                        if let Some(ref value) = action.value {
                            state.config.insert(action.path.clone(), value.clone());
                        }
                    }
                    MockActionType::Delete => {
                        state.config.remove(&action.path);
                    }
                }
            }
        }

        let after_fp = self.fingerprint().await?;

        Ok(MockStaged {
            actions: actions.to_vec(),
            before_fp,
            after_fp,
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        let changes = staged
            .actions
            .iter()
            .map(|a| format!("{:?} {}", a.action, a.path))
            .collect();
        Ok(MockDiff { changes })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(MockValidation { succeeded: true })
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: Some("mock-commit".to_string()),
            details: None,
        })
    }

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Ok(RollbackOutcome {
            succeeded: true,
            details: None,
        })
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError::Generic(
            "confirmed commit not supported in mock".to_string(),
        ))
    }
}

fn test_attribution(principal: &str) -> Attribution {
    Attribution {
        principal: Principal::Token(principal.into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-test".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: mecmcp_audit::Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: Some("dev@example.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        approver: None,
        verified_approver: None,
        change_set_id: None,
    }
}

/// Test harness providing a change set in Planned state with all necessary context.
struct PlannedChangeSetHarness {
    #[allow(dead_code)]
    coordinator: ChangesetCoordinator,
    change_set_id: String,
    device: String,
    owner: String,
    digest: String,
    transaction: MockTransaction,
    _temp_dir: tempfile::TempDir,
}

async fn planned_change_set_harness() -> PlannedChangeSetHarness {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator");

    let device = "test-device".to_string();
    let owner = "alice".to_string();

    // Use transaction to get the actual fingerprint
    let transaction = MockTransaction::new();
    let fingerprint = transaction.fingerprint().await.expect("fingerprint");

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/test/path".to_string(),
        value: Some("test-value".to_string()),
    }];

    let created = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.clone(),
            fingerprint.clone(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    PlannedChangeSetHarness {
        coordinator,
        change_set_id: created.change_set_id,
        device,
        owner,
        digest: created.digest,
        transaction,
        _temp_dir: temp_dir,
    }
}

/// A waiver whose expiry has passed must not authorize an apply.
///
/// Sabotage-verify this one: remove the expiry check in `apply.rs` and confirm
/// this test fails. A time box that does not block anything is decoration.
#[tokio::test]
async fn an_expired_waiver_does_not_authorize_apply() {
    let harness = planned_change_set_harness().await;

    // Manually create an expired waiver and transition to Approved
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let expired_at = now - 3600; // 1 hour ago

    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test expired waiver".to_owned(),
        expires_at_unix: Some(expired_at),
        ticket: Some("TEST-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Directly manipulate the state to set the expired waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");

    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        digest_version: 4,
        waived: Some(waiver),
        mechanism: None,
        issuer: None,
        subject: None,
    });

    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator to pick up the modified state. Drop the harness's
    // coordinator first: it holds the state file's single-writer lock for
    // its whole lifetime (MEC-540), which this reload would otherwise be
    // refused against.
    drop(harness.coordinator);
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    // Attempt apply with the expired waiver
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");
    let error = coordinator
        .apply_change_set(
            harness.change_set_id.clone(),
            harness.device.clone(),
            "https://test-device.example.com".to_string(),
            harness.owner.clone(),
            harness.digest.clone(),
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &CancellationToken::new(),
        )
        .await
        .expect_err("an expired waiver must not authorize apply");

    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "the refusal must name expiry, not report a generic missing approval — \
         an operator sent looking for the wrong problem loses the time the \
         message was supposed to save: {message}"
    );
}

/// `compute_waiver_digest_v3` needs no key -- it is a plain hash, not a MAC --
/// so it verifies on its own bytes regardless of whether this deployment
/// currently runs in lab mode. A valid, unexpired waiver record must still be
/// refused at apply time once lab mode is off, or write access to the state
/// file (without ever running with lab mode enabled) would be enough to forge
/// an approval (MEC-457 review, finding 1, "also check").
///
/// Sabotage-verify: remove the `!self.lab_mode()` check added alongside this
/// test in `apply.rs` and confirm this test fails.
#[tokio::test]
async fn lab_mode_disabled_after_waiver_does_not_authorize_apply() {
    let harness = planned_change_set_harness().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();

    let waiver = WaiverRecord {
        kind: WaiverKind::LabMode,
        reason: "lab-mode".to_owned(),
        expires_at_unix: None,
        ticket: None,
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");

    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        digest_version: 4,
        waived: Some(waiver),
        mechanism: None,
        issuer: None,
        subject: None,
    });

    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload with lab_mode=false, as if the waiver were forged directly into
    // the state file on a deployment that never ran with lab mode enabled.
    // Drop the harness's coordinator first: it holds the state file's
    // single-writer lock for its whole lifetime (MEC-540), which this reload
    // would otherwise be refused against.
    drop(harness.coordinator);
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
        .expect("reload coordinator with lab mode disabled");

    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");
    let error = coordinator
        .apply_change_set(
            harness.change_set_id.clone(),
            harness.device.clone(),
            "https://test-device.example.com".to_string(),
            harness.owner.clone(),
            harness.digest.clone(),
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &CancellationToken::new(),
        )
        .await
        .expect_err("a lab-mode waiver must not authorize apply when lab mode is disabled");

    let message = format!("{error:?}");
    assert!(
        message.contains("lab mode"),
        "the refusal must name lab mode, not report a generic missing approval: {message}"
    );
}

/// The pre-guard waiver expiry check must fail fast without waiting for the
/// device guard. Isolate it by pre-holding the guard: a dead check would block.
#[tokio::test]
async fn pre_guard_waiver_expiry_check_fails_without_blocking() {
    let harness = planned_change_set_harness().await;

    // Create an expired waiver
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let expired_at = now - 3600; // 1 hour ago

    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test pre-guard expired waiver".to_owned(),
        expires_at_unix: Some(expired_at),
        ticket: Some("PRE-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the expired waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        digest_version: 4,
        waived: Some(waiver),
        mechanism: None,
        issuer: None,
        subject: None,
    });
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator. Drop the harness's coordinator first: it holds
    // the state file's single-writer lock for its whole lifetime (MEC-540),
    // which this reload would otherwise be refused against.
    drop(harness.coordinator);
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    // Pre-hold the device guard
    let cancellation = CancellationToken::new();
    let _guard = coordinator
        .device_guard(&harness.device, &cancellation)
        .await
        .expect("acquire device guard");

    // Attempt apply with a 2-second timeout. If the pre-guard check is working,
    // it returns the expiry error immediately without waiting for the guard.
    // If the check is dead, apply blocks waiting for the held guard and times out.
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");
    let apply_result = tokio::time::timeout(
        Duration::from_secs(2),
        coordinator.apply_change_set(
            harness.change_set_id.clone(),
            harness.device.clone(),
            "https://test-device.example.com".to_string(),
            harness.owner.clone(),
            harness.digest.clone(),
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &cancellation,
        ),
    )
    .await
    .expect("pre-guard check must return immediately, not block on the held guard");

    let error = apply_result.expect_err("expired waiver must not authorize apply");
    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired") && message.contains("before device guard"),
        "pre-guard check must detect the expired waiver with the pre-guard message: {message}"
    );
}

/// The post-guard waiver expiry check must detect a TOCTOU attack: a waiver
/// rewritten to an expired value while apply is blocked on the device guard.
#[tokio::test]
async fn post_guard_waiver_expiry_check_detects_toctou_rewrite() {
    let harness = planned_change_set_harness().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let future_expiry = now + 3600; // 1 hour from now

    // Start with a valid future expiry so the pre-guard check passes
    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test post-guard TOCTOU".to_owned(),
        expires_at_unix: Some(future_expiry),
        ticket: Some("POST-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the change set with a future-expiring waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        digest_version: 4,
        waived: Some(waiver.clone()),
        mechanism: None,
        issuer: None,
        subject: None,
    });
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator and wrap in Arc for sharing between tasks. Drop
    // the harness's coordinator first: it holds the state file's
    // single-writer lock for its whole lifetime (MEC-540), which this
    // reload would otherwise be refused against.
    drop(harness.coordinator);
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = Arc::new(
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
            .expect("reload coordinator"),
    );

    // Pre-hold the device guard so apply will block
    let cancellation = CancellationToken::new();
    let guard = coordinator
        .device_guard(&harness.device, &cancellation)
        .await
        .expect("acquire device guard");

    // Spawn apply_change_set in the background; it will block on the held guard
    let coordinator_clone = Arc::clone(&coordinator);
    let change_set_id_clone = harness.change_set_id.clone();
    let device_clone = harness.device.clone();
    let owner_clone = harness.owner.clone();
    let digest_clone = harness.digest.clone();
    let transaction_clone = harness.transaction.clone();
    let cancellation_clone = cancellation.clone();
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");

    let apply_handle = tokio::spawn(async move {
        coordinator_clone
            .apply_change_set(
                change_set_id_clone,
                device_clone,
                "https://test-device.example.com".to_string(),
                owner_clone,
                digest_clone,
                fingerprint,
                &transaction_clone,
                "set",
                None,
                None,
                &test_attribution("alice"),
                &cancellation_clone,
            )
            .await
    });

    // Give the scheduler chances to run the background apply task so it passes
    // the pre-guard check and blocks on the held guard. `yield_now` drives the
    // cooperative scheduler forward without wall-clock delay. The `#[tokio::test]`
    // macro uses a current-thread runtime so the ordering is deterministic:
    // after ten yields, the spawned task has passed the pre-guard check and
    // reached the device guard. The assertion on the post-guard message below
    // proves which gate fired regardless of scheduler implementation.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    // While apply is blocked, rewrite the waiver to have a PAST expiry
    let past_expiry = now - 3600; // 1 hour ago
    let expired_waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test post-guard TOCTOU".to_owned(),
        expires_at_unix: Some(past_expiry),
        ticket: Some("POST-123".to_owned()),
    };

    // Recompute the digest with the expired waiver
    let expired_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &expired_waiver,
    );

    // Update the coordinator's in-memory state with the expired waiver
    let mut updated_change_set = coordinator
        .change_set(&harness.change_set_id, &harness.device)
        .await
        .expect("retrieve change set");
    updated_change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: expired_digest,
        digest_version: 4,
        waived: Some(expired_waiver),
        mechanism: None,
        issuer: None,
        subject: None,
    });
    coordinator
        .update_change_set(updated_change_set)
        .await
        .expect("update change set with expired waiver");

    // Release the guard so apply can proceed
    drop(guard);

    // Wait for apply to complete; it should fail with the post-guard expiry error
    let result = apply_handle
        .await
        .expect("apply task must complete without panic");

    let error = result.expect_err("post-guard check must detect the expired waiver");
    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired") && message.contains("after acquiring device guard"),
        "post-guard check must detect the TOCTOU rewrite with the post-guard message: {message}"
    );
}

/// Waiver expiry boundary: a waiver whose `expires_at_unix` equals the current
/// time is treated as expired (consistent with change-set expiry everywhere else).
#[tokio::test]
async fn waiver_at_exact_expiry_instant_is_expired() {
    let harness = planned_change_set_harness().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();

    // Waiver expires at exactly now (not in the past, not in the future)
    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test boundary: expires at exactly now".to_owned(),
        expires_at_unix: Some(now),
        ticket: Some("BOUNDARY-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the change set with the waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        digest_version: 4,
        waived: Some(waiver),
        mechanism: None,
        issuer: None,
        subject: None,
    });
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator. Drop the harness's coordinator first: it holds
    // the state file's single-writer lock for its whole lifetime (MEC-540),
    // which this reload would otherwise be refused against.
    drop(harness.coordinator);
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    let cancellation = CancellationToken::new();
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");

    // Apply must fail because the waiver's expiry is at exactly now, which is
    // treated as expired (consistent with `now >= expires_at` everywhere else).
    let error = coordinator
        .apply_change_set(
            harness.change_set_id,
            harness.device,
            "https://test-device.example.com".to_string(),
            harness.owner,
            harness.digest,
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &cancellation,
        )
        .await
        .expect_err("waiver with expires_at_unix == now must be treated as expired");

    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "boundary check: expires_at_unix == now must be expired, got: {message}"
    );
}

/// Lab mode keeps working untouched — no consumer changes to keep it.
#[tokio::test]
async fn lab_mode_waiver_still_records_lab_mode() {
    let harness = planned_change_set_harness().await;
    harness
        .coordinator
        .waive_approval(
            harness.change_set_id.clone(),
            harness.device.clone(),
            harness.owner.clone(),
            harness.digest.clone(),
        )
        .await
        .expect("lab-mode waiver");

    let record = harness
        .coordinator
        .change_set(&harness.change_set_id, &harness.device)
        .await
        .expect("retrieve change set");

    let waiver = record
        .approval
        .as_ref()
        .and_then(|approval| approval.waived.as_ref())
        .expect("a waived approval");
    assert_eq!(waiver.kind, WaiverKind::LabMode);
    assert_eq!(waiver.expires_at_unix, None);
}

/// An operator waiver refuses an expiry already in the past. That is a
/// configuration error, not a waiver that is instantly dead.
#[tokio::test]
async fn an_operator_waiver_refuses_an_expiry_in_the_past() {
    let harness = planned_change_set_harness().await;
    let error = harness
        .coordinator
        .waive_approval_operator(
            harness.change_set_id.clone(),
            harness.device.clone(),
            harness.owner.clone(),
            harness.digest.clone(),
            WaiverKind::OperatorFile,
            "authorised exception".to_owned(),
            Some(1), // unix epoch + 1s, comfortably past
            Some("CHG-1".to_owned()),
        )
        .await
        .expect_err("an expiry in the past must be refused");
    assert!(format!("{error:?}").contains("expires_at_unix"));
}

/// The operator waiver path must reject `WaiverKind::LabMode` — that kind
/// belongs exclusively to `waive_approval`.
#[tokio::test]
async fn waive_approval_operator_refuses_lab_mode_kind() {
    let harness = planned_change_set_harness().await;
    let error = harness
        .coordinator
        .waive_approval_operator(
            harness.change_set_id.clone(),
            harness.device.clone(),
            harness.owner.clone(),
            harness.digest.clone(),
            WaiverKind::LabMode,
            "lab mode test".to_owned(),
            None,
            None,
        )
        .await
        .expect_err("LabMode kind must be refused");
    assert!(format!("{error:?}").contains("waive_approval"));
}

/// Sabotage test for Defect 2: v1/v2 waivers with v3-only metadata must be rejected.
#[test]
fn sabotage_defect_2_forged_v3_metadata_in_legacy_file() {
    use std::fs;

    // Each field is forged ON ITS OWN. Forging all three at once only proves the
    // first guard fires: `kind` is checked first, so it masks the other two and
    // either could be deleted with the suite green.
    for (field, forged, expected) in [
        (
            "kind",
            serde_json::json!("operator_file"),
            "v1 waiver cannot carry kind",
        ),
        (
            "expires_at_unix",
            serde_json::json!(1_800_000_000_u64),
            "v1 waiver cannot carry expires_at_unix",
        ),
        (
            "ticket",
            serde_json::json!("FORGED-123"),
            "v1 waiver cannot carry ticket",
        ),
    ] {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let state_path = temp_dir.path().join("forged.json");

        let mut fixture: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/waiver-v1.json")).expect("parse fixture");

        let waiver = fixture["state"]["change_sets"]["0000000000000000000000000000000000000000000000000000000000000001"]["approval"]["waived"]
            .as_object_mut()
            .expect("waiver object");
        waiver.insert(field.to_owned(), forged);

        fs::write(
            &state_path,
            serde_json::to_vec_pretty(&fixture).expect("serialize"),
        )
        .expect("write forged file");
        fs::set_permissions(
            &state_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("chmod");

        let error = match read_state(&state_path, 128 * 1024) {
            Ok(_) => panic!("forging {field} alone in a v1 file must be rejected, but it loaded"),
            Err(error) => error,
        };
        let error_msg = format!("{error:?}");
        assert!(
            error_msg.contains(expected),
            "forging {field} alone must be refused with {expected:?}, got: {error_msg}"
        );
    }
}

/// Sabotage test for Defect 1: load/save cycle without migration bricks a legacy file.
#[test]
fn sabotage_defect_1_load_save_cycle_without_migration() {
    use std::fs;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("legacy.json");

    // Write a v1 waiver fixture
    fs::write(&state_path, include_str!("fixtures/waiver-v1.json")).expect("write fixture");
    fs::set_permissions(
        &state_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("chmod");

    // Load it (with migration)
    let state = read_state(&state_path, 128 * 1024).expect("load v1 file");

    // Write it back (triggers v3 due to waivers_need_v3)
    write_state_for_test(&state_path, &state, 128 * 1024).expect("write state");

    // Load again — must succeed because migration happened
    read_state(&state_path, 128 * 1024).expect("second load must succeed after migration");
}

/// MEC-994 Percy review F10: a token-asserted approval recorded before
/// strict verified-approver mode was turned on must not still authorize an
/// apply once strict mode is in effect. The approval digest's `mechanism`
/// field is HMAC-covered (v7), so this check cannot be forged post hoc
/// without the digest key.
#[tokio::test]
async fn strict_mode_refuses_apply_of_a_pre_strict_token_asserted_approval() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let key: Arc<[u8]> = Arc::from(vec![7u8; 32]);

    // Pre-strict: a keyed v7 approval, but by a `TokenAsserted` (not
    // `OidcVerified`) approver — the shape strict mode exists to refuse.
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator")
        .with_approval_digest_key(Arc::clone(&key));

    let device = "test-device".to_string();
    let owner = "alice".to_string();
    let transaction = MockTransaction::new();
    let fingerprint = transaction.fingerprint().await.expect("fingerprint");
    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/test/path".to_string(),
        value: Some("test-value".to_string()),
    }];

    let created = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.clone(),
            fingerprint.clone(),
            "policy-sig".to_string(),
            None,
        )
        .await
        .expect("create");

    coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            device.clone(),
            &ApproverIdentity::TokenAsserted {
                principal: "bob".to_string(),
                actor_type: ActorType::Human,
            },
            created.digest.clone(),
        )
        .await
        .expect("approve");

    // Strict mode turned on after the fact, same key. The on-disk record
    // already carries a v7 (keyed) digest, so the key must be supplied to
    // `load_with_key` itself, not only via the builder afterward.
    drop(coordinator);
    let coordinator = ChangesetCoordinator::load_with_key(
        Some(&state_path),
        limits,
        approval_ttl,
        true,
        Some(Arc::clone(&key).into()),
    )
    .expect("reload coordinator")
    .with_require_verified_approver(true);

    let error = coordinator
        .apply_change_set(
            created.change_set_id.clone(),
            device.clone(),
            "https://test-device.example.com".to_string(),
            owner.clone(),
            created.digest.clone(),
            fingerprint,
            &transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &CancellationToken::new(),
        )
        .await
        .expect_err(
            "a pre-strict token-asserted approval must not authorize apply under strict mode",
        );

    let message = format!("{error:?}");
    assert!(
        message.contains("strict verified-approver mode"),
        "the refusal must name strict mode, not report a generic missing approval: {message}"
    );
}
