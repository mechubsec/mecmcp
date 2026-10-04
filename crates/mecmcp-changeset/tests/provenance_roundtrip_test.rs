//! Round-trip integration test for provenance flow.
//!
//! This test verifies that request IDs composed by apply_commit_metadata can be
//! successfully parsed by mecmcp-verify's device-log parser, closing the final
//! gate for the evidence-first audit system.
//!
//! The test:
//! 1. Builds an Attribution with a known request_id
//! 2. Composes a commit comment through the REAL hook path (apply_commit_metadata)
//! 3. Wraps the composed comment in a realistic device-log text block
//! 4. Parses using the REAL library parser (mecmcp_audit::device_log::parse_device_log)
//! 5. Asserts the parser extracts exactly the known request_id
//! 6. Tests negative cases: mangled provenance, missing request.id field

use mecmcp_audit::device_log::parse_device_log;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal, Tier, TokenVerifiedFields};
use mecmcp_changeset::commit_metadata::{
    CommitMetaError, CommitMetadataSink, apply_commit_metadata,
};
use std::io::Cursor;
use uuid::Uuid;

/// Mock sink that records the composed commit comment.
struct RecordingSink {
    recorded_line: Option<String>,
}

impl RecordingSink {
    fn new() -> Self {
        Self {
            recorded_line: None,
        }
    }

    fn take_recorded(&mut self) -> Option<String> {
        self.recorded_line.take()
    }
}

impl CommitMetadataSink for RecordingSink {
    fn attach(&mut self, line: &str) -> Result<(), CommitMetaError> {
        self.recorded_line = Some(line.to_string());
        Ok(())
    }
}

#[test]
fn roundtrip_request_id_composition_and_parsing() {
    let known_request_id =
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").expect("valid UUID");

    // 1. Build an Attribution with a known request_id
    let attribution = Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-roundtrip-test".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: Some("dev@example.com".into()),
        change_ref: None,
        request_id: known_request_id,
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    };

    // 2. Compose a commit comment through the REAL hook path
    let mut sink = RecordingSink::new();
    let outcome = apply_commit_metadata(&mut sink, Some("Fix BGP peering"), &attribution);

    // Verify attachment succeeded
    assert_eq!(
        outcome,
        mecmcp_changeset::commit_metadata::AttachOutcome::Attached
    );

    let composed_line = sink
        .take_recorded()
        .expect("sink should have recorded the composed line");

    // Verify the composed line contains the operator comment and request.id
    assert!(
        composed_line.contains("Fix BGP peering"),
        "composed line must preserve operator comment"
    );
    assert!(
        composed_line.contains(&format!("request.id={}", known_request_id)),
        "composed line must contain request.id: {}",
        composed_line
    );

    // 3. Wrap the composed comment in a realistic device-log text block
    let device_log = format!(
        r#"commit abc123def456789012345678901234567890ab
Author: Alice <alice@mechub.org>
Date:   Fri Aug 9 14:01:00 2026 +0000

Device: vsrx-prod
    {}
"#,
        composed_line
    );

    // 4. Parse using the REAL library parser
    let parsed_commits = parse_device_log(Cursor::new(&device_log));

    assert_eq!(
        parsed_commits.len(),
        1,
        "parser should extract exactly one commit"
    );

    let commit_ref = &parsed_commits[0];
    assert_eq!(commit_ref.device_id, "vsrx-prod");
    assert_eq!(
        commit_ref.commit_sha,
        "abc123def456789012345678901234567890ab"
    );
    assert_eq!(
        commit_ref.request_id,
        known_request_id.to_string(),
        "parser must extract the exact request_id that was composed"
    );
}

#[test]
fn roundtrip_provenance_only_no_operator_comment() {
    let known_request_id =
        Uuid::parse_str("deadbeef-dead-beef-dead-beefdeadbeef").expect("valid UUID");

    let attribution = Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-test-2".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: None,
        change_ref: None,
        request_id: known_request_id,
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    };

    // Compose with no operator comment
    let mut sink = RecordingSink::new();
    let outcome = apply_commit_metadata(&mut sink, None, &attribution);

    assert_eq!(
        outcome,
        mecmcp_changeset::commit_metadata::AttachOutcome::Attached
    );

    let composed_line = sink
        .take_recorded()
        .expect("sink should have recorded the line");

    // Should NOT contain a pipe delimiter when there's no operator comment
    assert!(
        !composed_line.contains(" | "),
        "provenance-only line must not have delimiter: {}",
        composed_line
    );

    // Wrap in device log
    let device_log = format!(
        r#"commit fedcba9876543210fedcba9876543210fedcba98
Device: vsrx-lab
    {}
"#,
        composed_line
    );

    let parsed_commits = parse_device_log(Cursor::new(&device_log));

    assert_eq!(parsed_commits.len(), 1);

    let commit_ref = &parsed_commits[0];
    assert_eq!(
        commit_ref.request_id,
        known_request_id.to_string(),
        "parser must extract request_id from provenance-only line"
    );
}

#[test]
fn mangled_request_id_yields_no_join() {
    // A provenance-looking line with a mangled request.id should yield no join
    let device_log = r#"commit abc123def456
Device: vsrx-prod
    Fix NAT policy | anthropic-public, claude-opus-5 request.id=NOT-A-VALID-UUID, ...
"#;

    let parsed_commits = parse_device_log(Cursor::new(device_log));

    // The parser should still extract the mangled ID (it's not a UUID validator)
    assert_eq!(parsed_commits.len(), 1);
    let commit_ref = &parsed_commits[0];
    assert_eq!(commit_ref.request_id, "NOT-A-VALID-UUID");

    // The real verification would fail when this mangled ID is not found in audit
    // records — that's tested in mecmcp-verify's integration tests. This test
    // just proves the parser extracts what's there, even if invalid.
}

#[test]
fn missing_request_id_field_yields_no_join() {
    // A commit with provenance but no request.id field should yield no join
    let device_log = r#"commit abc123def456
Device: vsrx-prod
    Fix NAT policy | anthropic-public, claude-opus-5
"#;

    let parsed_commits = parse_device_log(Cursor::new(device_log));

    assert_eq!(
        parsed_commits.len(),
        0,
        "parser should extract nothing when request.id is absent"
    );
}

#[test]
fn multiple_commits_in_log() {
    let request_id_1 = Uuid::parse_str("11111111-1111-1111-1111-111111111111").expect("valid UUID");
    let request_id_2 = Uuid::parse_str("22222222-2222-2222-2222-222222222222").expect("valid UUID");

    // Compose two provenance lines
    let attribution_1 = Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-1".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: None,
        change_ref: None,
        request_id: request_id_1,
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    };

    let attribution_2 = Attribution {
        principal: Principal::Token("test-token".into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-2".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: None,
        change_ref: None,
        request_id: request_id_2,
        token_verified_fields: TokenVerifiedFields::none(),
        verified_approver: None,
        approver: None,
        change_set_id: None,
    };

    let mut sink_1 = RecordingSink::new();
    apply_commit_metadata(&mut sink_1, Some("Change 1"), &attribution_1);
    let line_1 = sink_1.take_recorded().expect("line 1");

    let mut sink_2 = RecordingSink::new();
    apply_commit_metadata(&mut sink_2, Some("Change 2"), &attribution_2);
    let line_2 = sink_2.take_recorded().expect("line 2");

    let device_log = format!(
        r#"commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Device: vsrx-prod
    {}

commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Device: vsrx-lab
    {}
"#,
        line_1, line_2
    );

    let parsed_commits = parse_device_log(Cursor::new(&device_log));

    assert_eq!(parsed_commits.len(), 2);

    let commit_ref_1 = &parsed_commits[0];
    assert_eq!(commit_ref_1.device_id, "vsrx-prod");
    assert_eq!(
        commit_ref_1.commit_sha,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(commit_ref_1.request_id, request_id_1.to_string());

    let commit_ref_2 = &parsed_commits[1];
    assert_eq!(commit_ref_2.device_id, "vsrx-lab");
    assert_eq!(
        commit_ref_2.commit_sha,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(commit_ref_2.request_id, request_id_2.to_string());
}
