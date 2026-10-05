//! Mock implementations of DeviceTransaction proving the trait fits both
//! PAN-OS and Junos without awkward adapters.

#![allow(clippy::unwrap_used, dead_code)]

use async_trait::async_trait;
use mecmcp_audit::{ActorType, Attribution, Principal, TokenVerifiedFields};
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ============================================================================
// PAN-OS-shaped mock
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PanosActionType {
    Set,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PanosAction {
    action: PanosActionType,
    xpath: String,
    element: Option<String>,
}

#[derive(Debug)]
struct PanosStagedHandle {
    operation_id: String,
    config_lock_held: bool,
    before_fingerprint: String,
    after_fingerprint: String,
    actions: Vec<PanosAction>,
}

#[derive(Debug, Clone, Serialize)]
struct PanosDiff {
    changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PanosValidation {
    succeeded: bool,
    job_id: Option<String>,
    details: String,
}

#[derive(Debug, Clone)]
struct PanosDeviceState {
    candidate: HashMap<String, String>,
    running: HashMap<String, String>,
    config_lock_holder: Option<String>,
}

impl Default for PanosDeviceState {
    fn default() -> Self {
        let mut running = HashMap::new();
        running.insert(
            "/config/devices/entry[@name='localhost.localdomain']/network".into(),
            "<network/>".into(),
        );
        Self {
            candidate: running.clone(),
            running,
            config_lock_holder: None,
        }
    }
}

struct PanosMockTransaction {
    state: Arc<Mutex<PanosDeviceState>>,
    admin: String,
}

impl PanosMockTransaction {
    fn new(admin: String) -> Self {
        Self {
            state: Arc::new(Mutex::new(PanosDeviceState::default())),
            admin,
        }
    }

    fn with_state(state: Arc<Mutex<PanosDeviceState>>, admin: String) -> Self {
        Self { state, admin }
    }
}

#[derive(Debug, thiserror::Error)]
enum PanosError {
    #[error("config lock held by {0}")]
    LockHeld(String),
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("commit failed: {0}")]
    CommitFailed(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("confirmed commit not supported on PAN-OS")]
    ConfirmedCommitUnsupported,
}

#[async_trait]
impl DeviceTransaction for PanosMockTransaction {
    type Action = PanosAction;
    type Staged = PanosStagedHandle;
    type Diff = PanosDiff;
    type Validation = PanosValidation;
    type Error = PanosError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().unwrap();
        let mut xpaths: Vec<_> = state.candidate.keys().cloned().collect();
        xpaths.sort();
        let concatenated = xpaths.join(":");
        let hash = sha2::Sha256::digest(concatenated.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        // Acquire config lock
        {
            let mut state = self.state.lock().unwrap();
            if let Some(holder) = &state.config_lock_holder {
                return Err(PanosError::LockHeld(holder.clone()));
            }
            state.config_lock_holder = Some(self.admin.clone());
        }

        let before_fp = self.fingerprint().await?;

        // Apply actions atomically
        {
            let mut state = self.state.lock().unwrap();
            for action in actions {
                match action.action {
                    PanosActionType::Set => {
                        if let Some(ref element) = action.element {
                            state
                                .candidate
                                .insert(action.xpath.clone(), element.clone());
                        }
                    }
                    PanosActionType::Delete => {
                        state.candidate.remove(&action.xpath);
                    }
                }
            }
        }

        let after_fp = self.fingerprint().await?;

        Ok(PanosStagedHandle {
            operation_id: hex::encode(sha2::Sha256::digest(Uuid::new_v4().as_bytes())),
            config_lock_held: true,
            before_fingerprint: before_fp,
            after_fingerprint: after_fp,
            actions: actions.to_vec(),
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        let changes = staged
            .actions
            .iter()
            .map(|a| format!("{:?} {}", a.action, a.xpath))
            .collect();
        Ok(PanosDiff { changes })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(PanosValidation {
            succeeded: true,
            job_id: Some("123".into()),
            details: "validation passed".into(),
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // PAN-OS does not support confirmed commit; return error if requested
        if options.confirm_timeout.is_some() {
            return Err(PanosError::ConfirmedCommitUnsupported);
        }

        let mut state = self.state.lock().unwrap();

        // PAN-OS commits are async but we simulate success
        state.running = state.candidate.clone();

        // Release lock
        if staged.config_lock_held {
            state.config_lock_holder = None;
        }

        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: Some("commit-456".into()),
            details: Some("commit completed".into()),
        })
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(PanosError::Unsupported(
            "PAN-OS does not support confirmed commit".into(),
        ))
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::Archive(_) => Err(PanosError::Unsupported(
                "PAN-OS does not support archive-based rollback".into(),
            )),
            RollbackRef::CandidateRevert => {
                let mut state = self.state.lock().unwrap();
                // Admin-scoped revert: clear candidate changes attributed to this admin
                state.candidate = state.running.clone();
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("reverted candidate to running".into()),
                })
            }
            RollbackRef::Custom(_) => Err(PanosError::Unsupported(
                "custom rollback not implemented in mock".into(),
            )),
        }
    }
}

// ============================================================================
// Junos-shaped mock
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ConfigPayload {
    Set(String),
    Xml(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct JunosAction {
    payload: ConfigPayload,
    rollback_source: Option<u32>,
}

#[derive(Debug)]
struct JunosStagedHandle {
    candidate_locked: bool,
    diff: String,
    actions: Vec<JunosAction>,
}

#[derive(Debug, Clone, Serialize)]
struct JunosDiff {
    text: String,
}

#[derive(Debug, Clone, Serialize)]
struct JunosValidation {
    succeeded: bool,
    details: String,
}

#[derive(Debug, Clone)]
struct JunosDeviceState {
    candidate: String,
    committed: String,
    rollback_archives: HashMap<u32, String>,
    candidate_locked: bool,
}

impl Default for JunosDeviceState {
    fn default() -> Self {
        let config = "system { host-name test; }".to_string();
        Self {
            candidate: config.clone(),
            committed: config.clone(),
            rollback_archives: HashMap::from([
                (0, config.clone()),
                (1, "system { host-name old; }".into()),
            ]),
            candidate_locked: false,
        }
    }
}

struct JunosMockTransaction {
    state: Arc<Mutex<JunosDeviceState>>,
}

impl JunosMockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(JunosDeviceState::default())),
        }
    }

    fn with_state(state: Arc<Mutex<JunosDeviceState>>) -> Self {
        Self { state }
    }

    fn build_commit_comment(
        &self,
        attribution: &Attribution,
        confirming_operation_id: Option<&str>,
    ) -> String {
        let change_ref = attribution.change_ref.as_deref().unwrap_or("N/A");
        let principal = &attribution.principal;

        let provenance = if let Some(agent) = &attribution.agent {
            agent.provenance_string(attribution.on_behalf_of.as_deref())
        } else {
            format!("human-initiated by {}", principal)
        };

        if let Some(op_id) = confirming_operation_id {
            format!(
                "Confirming commit {}: {} via {}",
                op_id, change_ref, provenance
            )
        } else {
            format!("{} via {}", change_ref, provenance)
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum JunosError {
    #[error("candidate database locked")]
    CandidateLocked,
    #[error("commit check failed: {0}")]
    CommitCheckFailed(String),
    #[error("commit failed: {0}")]
    CommitFailed(String),
    #[error("rollback archive {0} not found")]
    ArchiveNotFound(u32),
}

#[async_trait]
impl DeviceTransaction for JunosMockTransaction {
    type Action = JunosAction;
    type Staged = JunosStagedHandle;
    type Diff = JunosDiff;
    type Validation = JunosValidation;
    type Error = JunosError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().unwrap();
        let hash = sha2::Sha256::digest(state.candidate.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let mut state = self.state.lock().unwrap();

        // Lock candidate
        if state.candidate_locked {
            return Err(JunosError::CandidateLocked);
        }
        state.candidate_locked = true;

        // Load actions (simplified: just append)
        for action in actions {
            if let Some(version) = action.rollback_source {
                if let Some(archive) = state.rollback_archives.get(&version) {
                    state.candidate = archive.clone();
                } else {
                    state.candidate_locked = false;
                    return Err(JunosError::ArchiveNotFound(version));
                }
            } else {
                match &action.payload {
                    ConfigPayload::Set(cmd) => {
                        state.candidate.push('\n');
                        state.candidate.push_str(cmd);
                    }
                    ConfigPayload::Xml(xml) => {
                        state.candidate = xml.clone();
                    }
                }
            }
        }

        let diff = format!("[edit]\n+ {}", state.candidate);

        Ok(JunosStagedHandle {
            candidate_locked: true,
            diff,
            actions: actions.to_vec(),
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(JunosDiff {
            text: staged.diff.clone(),
        })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        // Junos commit-check is synchronous
        Ok(JunosValidation {
            succeeded: true,
            details: "configuration check succeeds".into(),
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        let mut state = self.state.lock().unwrap();

        // Junos commits are synchronous
        state.committed = state.candidate.clone();

        // Unlock candidate
        if staged.candidate_locked {
            state.candidate_locked = false;
        }

        // Handle confirmed commit
        if let Some(timeout) = options.confirm_timeout {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            let deadline = now.as_secs() + timeout.as_secs();

            // Junos: comment is NOT applied during confirmed commit
            // We return AwaitingConfirmation to signal this
            Ok(CommitOutcome::AwaitingConfirmation {
                job_id: None,
                rollback_deadline_unix: deadline,
                details: Some(format!(
                    "confirmed commit active, auto-rollback in {}s (comment not applied per Junos behavior)",
                    timeout.as_secs()
                )),
            })
        } else {
            // Normal commit with comment (attribution provenance)
            let comment = self.build_commit_comment(attribution, None);
            // In real impl: ConfigManager::commit_with_comment(&comment)
            let _ = comment; // silence unused warning in mock

            Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some("commit complete".into()),
            })
        }
    }

    async fn confirm_commit(
        &self,
        operation_id: &str,
        attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        // Issue confirming commit with attribution comment
        let comment = self.build_commit_comment(attribution, Some(operation_id));
        // In real impl: ConfigManager::commit_with_comment(&comment)
        let _ = comment; // silence unused warning in mock

        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: None,
            details: Some(format!(
                "confirming commit for operation {} complete",
                operation_id
            )),
        })
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        let mut state = self.state.lock().unwrap();

        match to {
            RollbackRef::Archive(version) => {
                if let Some(archive) = state.rollback_archives.get(&version).cloned() {
                    state.candidate = archive.clone();
                    state.committed = archive;
                    Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some(format!("rolled back to archive {}", version)),
                    })
                } else {
                    Err(JunosError::ArchiveNotFound(version))
                }
            }
            RollbackRef::CandidateRevert => {
                // Load rollback 0 (clear candidate changes)
                if let Some(archive) = state.rollback_archives.get(&0) {
                    state.candidate = archive.clone();
                    Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some("reverted candidate to rollback 0".into()),
                    })
                } else {
                    Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some("candidate cleared".into()),
                    })
                }
            }
            RollbackRef::Custom(_) => Ok(RollbackOutcome {
                succeeded: false,
                details: Some("custom rollback not implemented in mock".into()),
            }),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

fn test_attribution() -> Attribution {
    use mecmcp_audit::{AgentIdentity, Tier};
    Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-test".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: Some("dev@example.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
        // Hand-built rather than derived from a token entry, so the model,
        // provider and delegated user here are claims, not verified facts.
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

fn test_human_attribution() -> Attribution {
    Attribution {
        principal: Principal::Token("human-token".into()),
        actor_type: ActorType::Human,
        agent: None,
        on_behalf_of: None,
        change_ref: Some("CHG0099999".into()),
        request_id: Uuid::new_v4(),
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    }
}

#[tokio::test]
async fn panos_mock_full_lifecycle() {
    let panos = PanosMockTransaction::new("admin".into());

    // Fingerprint
    let fp1 = panos.fingerprint().await.unwrap();
    assert!(fp1.starts_with("sha256:"));

    // Stage
    let actions = vec![PanosAction {
        action: PanosActionType::Set,
        xpath: "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
            .into(),
        element: Some("<vsys><entry name='vsys1'/></vsys>".into()),
    }];
    let staged = panos.stage(&actions).await.unwrap();
    assert!(staged.config_lock_held);
    assert_ne!(staged.before_fingerprint, staged.after_fingerprint);

    // Diff
    let diff = panos.diff(&staged).await.unwrap();
    assert_eq!(diff.changes.len(), 1);

    // Validate
    let validation = panos.validate(&staged).await.unwrap();
    assert!(validation.succeeded);

    // Commit
    let outcome = panos
        .commit(&staged, &test_attribution(), &CommitOptions::default())
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        CommitOutcome::Reconciled {
            succeeded: true,
            ..
        }
    ));

    // Verify lock released
    let state = panos.state.lock().unwrap();
    assert!(state.config_lock_holder.is_none());
}

#[tokio::test]
async fn panos_mock_candidate_revert() {
    let state = Arc::new(Mutex::new(PanosDeviceState::default()));
    let panos = PanosMockTransaction::with_state(state.clone(), "admin".into());

    // Stage a change
    let actions = vec![PanosAction {
        action: PanosActionType::Set,
        xpath: "/test".into(),
        element: Some("<test/>".into()),
    }];
    let _staged = panos.stage(&actions).await.unwrap();

    // Verify candidate changed
    {
        let s = state.lock().unwrap();
        assert!(s.candidate.contains_key("/test"));
        assert!(!s.running.contains_key("/test"));
    }

    // Rollback candidate
    let outcome = panos.rollback(RollbackRef::CandidateRevert).await.unwrap();
    assert!(outcome.succeeded);

    // Verify candidate reverted
    let s = state.lock().unwrap();
    assert!(!s.candidate.contains_key("/test"));
}

#[tokio::test]
async fn panos_mock_archive_rollback_unsupported() {
    let panos = PanosMockTransaction::new("admin".into());
    let result = panos.rollback(RollbackRef::Archive(5)).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("does not support archive-based rollback")
    );
}

#[tokio::test]
async fn junos_mock_full_lifecycle() {
    let junos = JunosMockTransaction::new();

    // Fingerprint
    let fp1 = junos.fingerprint().await.unwrap();
    assert!(fp1.starts_with("sha256:"));

    // Stage
    let actions = vec![JunosAction {
        payload: ConfigPayload::Set(
            "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24".into(),
        ),
        rollback_source: None,
    }];
    let staged = junos.stage(&actions).await.unwrap();
    assert!(staged.candidate_locked);

    // Diff
    let diff = junos.diff(&staged).await.unwrap();
    assert!(diff.text.contains("[edit]"));

    // Validate
    let validation = junos.validate(&staged).await.unwrap();
    assert!(validation.succeeded);

    // Commit
    let outcome = junos
        .commit(&staged, &test_attribution(), &CommitOptions::default())
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        CommitOutcome::Reconciled {
            succeeded: true,
            ..
        }
    ));

    // Verify lock released
    let state = junos.state.lock().unwrap();
    assert!(!state.candidate_locked);
}

#[tokio::test]
async fn junos_mock_confirmed_commit() {
    let junos = JunosMockTransaction::new();

    let actions = vec![JunosAction {
        payload: ConfigPayload::Set("set system host-name test-confirmed".into()),
        rollback_source: None,
    }];
    let staged = junos.stage(&actions).await.unwrap();

    // Commit with confirm timeout
    let options = CommitOptions {
        confirm_timeout: Some(Duration::from_secs(300)),
    };
    let outcome = junos
        .commit(&staged, &test_attribution(), &options)
        .await
        .unwrap();

    // Should return AwaitingConfirmation
    match outcome {
        CommitOutcome::AwaitingConfirmation {
            rollback_deadline_unix,
            details,
            ..
        } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert!(rollback_deadline_unix > now);
            assert!(
                details
                    .unwrap()
                    .contains("comment not applied per Junos behavior")
            );
        }
        other => panic!("expected AwaitingConfirmation, got {:?}", other),
    }
}

#[tokio::test]
async fn junos_mock_archive_rollback() {
    let junos = JunosMockTransaction::new();

    // Rollback to archive 1
    let outcome = junos.rollback(RollbackRef::Archive(1)).await.unwrap();
    assert!(outcome.succeeded);
    assert!(
        outcome
            .details
            .unwrap()
            .contains("rolled back to archive 1")
    );

    // Verify committed config changed
    let state = junos.state.lock().unwrap();
    assert_eq!(state.committed, "system { host-name old; }");
}

#[tokio::test]
async fn junos_mock_candidate_revert() {
    let state = Arc::new(Mutex::new(JunosDeviceState::default()));
    let junos = JunosMockTransaction::with_state(state.clone());

    // Stage a change
    let actions = vec![JunosAction {
        payload: ConfigPayload::Set("set system domain-name example.com".into()),
        rollback_source: None,
    }];
    let _staged = junos.stage(&actions).await.unwrap();

    // Verify candidate changed
    {
        let s = state.lock().unwrap();
        assert!(s.candidate.contains("domain-name"));
    }

    // Rollback candidate
    let outcome = junos.rollback(RollbackRef::CandidateRevert).await.unwrap();
    assert!(outcome.succeeded);

    // Verify candidate reverted
    let s = state.lock().unwrap();
    assert!(!s.candidate.contains("domain-name"));
}

#[tokio::test]
async fn junos_mock_archive_not_found() {
    let junos = JunosMockTransaction::new();
    let result = junos.rollback(RollbackRef::Archive(99)).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("rollback archive 99 not found")
    );
}

#[tokio::test]
async fn panos_rejects_unsupported_confirm_timeout() {
    let panos = PanosMockTransaction::new("admin".into());
    let actions = vec![PanosAction {
        action: PanosActionType::Set,
        xpath: "/test".into(),
        element: Some("<test/>".into()),
    }];
    let staged = panos.stage(&actions).await.unwrap();

    // PAN-OS must return an error if confirm_timeout is requested
    let options = CommitOptions {
        confirm_timeout: Some(Duration::from_secs(300)),
    };
    let result = panos.commit(&staged, &test_attribution(), &options).await;

    // Must error, not silently ignore
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("confirmed commit not supported")
    );
}

#[tokio::test]
async fn panos_confirm_commit_unsupported() {
    let panos = PanosMockTransaction::new("admin".into());
    let result = panos
        .confirm_commit("some-op-id", &test_attribution())
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not support"));
}

#[tokio::test]
async fn junos_confirming_commit_applies_attribution() {
    let junos = JunosMockTransaction::new();

    // First: confirmed commit returns AwaitingConfirmation
    let actions = vec![JunosAction {
        payload: ConfigPayload::Set("set system host-name confirm-test".into()),
        rollback_source: None,
    }];
    let staged = junos.stage(&actions).await.unwrap();
    let options = CommitOptions {
        confirm_timeout: Some(Duration::from_secs(300)),
    };
    let outcome = junos
        .commit(&staged, &test_attribution(), &options)
        .await
        .unwrap();

    let operation_id = match outcome {
        CommitOutcome::AwaitingConfirmation { .. } => "test-op-123",
        _ => panic!("expected AwaitingConfirmation"),
    };

    // Second: confirming commit applies attribution
    let confirm_outcome = junos
        .confirm_commit(operation_id, &test_attribution())
        .await
        .unwrap();

    match confirm_outcome {
        CommitOutcome::Reconciled {
            succeeded, details, ..
        } => {
            assert!(succeeded);
            assert!(
                details
                    .unwrap()
                    .contains(&format!("confirming commit for operation {}", operation_id))
            );
        }
        _ => panic!("expected Reconciled after confirm_commit"),
    }
}

#[tokio::test]
async fn provenance_string_matches_owner_example() {
    use mecmcp_audit::{AgentIdentity, Tier};

    let agent = AgentIdentity {
        model_id: "claude-opus-5".into(),
        session_id: "sess-test".into(),
        client_name: None,
        provider: "anthropic".into(),
        provider_tier: Tier::Public,
        skills_used: vec![],
    };

    let provenance = agent.provenance_string(Some("dev@example.com"));
    assert_eq!(
        provenance,
        "anthropic-public, claude-opus-5, none, dev@example.com"
    );
}

#[tokio::test]
async fn human_initiated_commit_renders_sensibly() {
    let junos = JunosMockTransaction::new();
    let human_attr = test_human_attribution();

    let comment = junos.build_commit_comment(&human_attr, None);
    assert!(comment.contains("CHG0099999"));
    assert!(comment.contains("human-initiated"));
}
