//! Regression coverage for a review finding on MEC-512 (mecmcp#441): an
//! installed `devices` redaction policy must not be able to erase which token
//! a `token set-scopes` / `token set-provenance` audit record is about.
//!
//! Before the fix, both commands passed the token name as the scope's
//! `devices` vector — a field an operator can map to `drop` or `hmac` via
//! `mecmcp_audit::redact::install`, even though neither command touches a
//! device. The name now travels in a `token` metadata field instead, which is
//! not in `mecmcp_audit::REDACTABLE_FIELDS`.
//!
//! `redact::install` sets a process-global `OnceLock` (idempotent: only the
//! first call in a process takes effect), so this policy install must not
//! share a test binary with any test asserting on *unredacted* audit output —
//! hence its own file, separate from `token_cmd_integration.rs` and
//! `token_set_provenance.rs`.
#![allow(clippy::unwrap_used)]

use mecmcp_audit::{AuditRedaction, install};
use mecmcp_runtime::{cli::TokenAction, token_cmd::run};
use std::path::PathBuf;
use tempfile::TempDir;

const KNOWN_TOOLS: &[&str] = &["get_config"];

fn temp_tokens_file() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    (dir, path)
}

#[test]
fn token_identity_survives_a_devices_drop_policy() {
    install(AuditRedaction::parse("devices=drop", None).unwrap());

    let (_dir, tokens_file) = temp_tokens_file();
    run(
        TokenAction::Add {
            tokens_file: tokens_file.clone(),
            name: "reader".to_owned(),
            devices: vec!["device1".to_owned()],
            tools: vec!["get_config".to_owned()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            oidc_issuer: None,
            oidc_subject: None,
            server_pid: None,
        },
        &["device1".to_owned(), "device2".to_owned()],
        KNOWN_TOOLS,
    )
    .unwrap();

    let scopes_captured = mecmcp_audit::testutil::run_with_capture(|| {
        run(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                devices: Some(vec!["device1".to_owned(), "device2".to_owned()]),
                tools: None,
                yes: true,
                server_pid: None,
            },
            &["device1".to_owned(), "device2".to_owned()],
            KNOWN_TOOLS,
        )
        .unwrap();
    });
    assert!(
        scopes_captured.contains("token=reader"),
        "the token identity must survive an installed devices=drop policy: {scopes_captured}"
    );

    let provenance_captured = mecmcp_audit::testutil::run_with_capture(|| {
        run(
            TokenAction::SetProvenance {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                provider: Some("anthropic".to_owned()),
                provider_tier: Some("public".to_owned()),
                on_behalf_of: Some("mharman".to_owned()),
                actor_type: Some("agent".to_owned()),
                yes: false,
                server_pid: None,
            },
            &["device1".to_owned(), "device2".to_owned()],
            KNOWN_TOOLS,
        )
        .unwrap();
    });
    assert!(
        provenance_captured.contains("token=reader"),
        "the token identity must survive an installed devices=drop policy: {provenance_captured}"
    );
}
