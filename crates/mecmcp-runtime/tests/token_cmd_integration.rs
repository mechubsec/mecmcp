//! Integration tests for token command implementation.
//!
//! `unwrap()` is idiomatic in a test — a panic *is* the failure, and the
//! workspace sets `unwrap_used = "warn"` for shipping code, not for tests.
//! The sibling crates apply the same allow at their test-module boundaries.
#![allow(clippy::unwrap_used)]

use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::{
    cli::TokenAction,
    token_cmd::{TokenCommandError, run},
};
use std::path::PathBuf;
use tempfile::TempDir;

const KNOWN_TOOLS: &[&str] = &["get_config", "execute_command", "load_config"];

fn temp_tokens_file() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    (dir, path)
}

#[test]
fn add_creates_token_and_returns_secret() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "alice".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };

    // Capture stdout to verify secret is printed
    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_ok(), "add failed: {result:?}");

    // Verify the token was stored
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store = store_file.store();
    assert_eq!(store.entries().len(), 1);
    assert_eq!(store.entries()[0].name, "alice");
}

#[test]
fn list_shows_token_metadata_not_secret() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "bob".to_string(),
        devices: vec!["device1".to_string()],
        tools: vec!["get_config".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // List tokens
    let list_action = TokenAction::List {
        tokens_file: tokens_file.clone(),
    };
    let result = run(list_action, &[], KNOWN_TOOLS);
    assert!(result.is_ok());

    // Verify file contains metadata, not plaintext secret
    let content = std::fs::read_to_string(&tokens_file).unwrap();
    assert!(content.contains("bob"));
    assert!(content.contains("device1"));
    assert!(content.contains("get_config"));
    assert!(!content.contains("Bearer "), "secret leaked into file");
}

#[test]
fn revoke_removes_token() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "charlie".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // Revoke it
    let revoke_action = TokenAction::Revoke {
        tokens_file: tokens_file.clone(),
        name: "charlie".to_string(),
        server_pid: None,
    };
    run(revoke_action, &[], KNOWN_TOOLS).unwrap();

    // Verify it's gone
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store = store_file.store();
    assert!(store.is_empty());
}

#[test]
fn rotate_changes_secret_preserves_scopes() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Add a token
    let add_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "diana".to_string(),
        devices: vec!["dev1".to_string(), "dev2".to_string()],
        tools: vec!["get_config".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };
    run(add_action, &[], KNOWN_TOOLS).unwrap();

    // Capture initial digest
    let store_before = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let digest_before = store_before.store().entries()[0].digest.clone();
    let created_at_before = store_before.store().entries()[0].created_at;

    // Rotate
    let rotate_action = TokenAction::Rotate {
        tokens_file: tokens_file.clone(),
        name: "diana".to_string(),
        server_pid: None,
    };
    run(rotate_action, &[], KNOWN_TOOLS).unwrap();

    // Verify digest changed but scopes and created_at are preserved
    let store_after = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store_after_ref = store_after.store();
    let entry_after = &store_after_ref.entries()[0];

    assert_ne!(entry_after.digest, digest_before, "digest unchanged");
    assert_eq!(entry_after.name, "diana");
    assert!(matches!(
        &entry_after.devices,
        mecmcp_auth::ScopeSet::Allowlist(d) if d == &["dev1", "dev2"]
    ));
    assert!(matches!(
        &entry_after.tools,
        mecmcp_auth::ScopeSet::Allowlist(t) if t == &["get_config"]
    ));
    // Exactly equal, not "close enough".
    //
    // This assertion previously allowed a 1ms tolerance, described as
    // serialization precision. It was not: rotate regenerated created_at with
    // Utc::now(), and the test only passed because add and rotate completed
    // within a millisecond of each other on a fast machine. CI was slower and
    // caught it.
    //
    // A tolerance on a value that should round-trip unchanged hides exactly
    // this. Rotation replaces the secret; the credential's creation time is not
    // a thing that can legitimately drift by any amount.
    assert_eq!(
        entry_after.created_at, created_at_before,
        "rotate must preserve created_at exactly; regenerating it erases when \
         the credential was first issued"
    );
}

#[test]
fn wildcard_mixed_with_names_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "evil".to_string(),
        devices: vec!["*".to_string(), "device1".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, message } => {
            assert_eq!(field, "devices");
            assert!(message.contains("'*'"));
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
fn unknown_tool_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "eve".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["no_such_tool".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
}

#[test]
fn device_validation_when_known_devices_provided() {
    let (_dir, tokens_file) = temp_tokens_file();
    let known_devices = vec!["dev1".to_string(), "dev2".to_string()];

    // Valid device name
    let valid_action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "frank".to_string(),
        devices: vec!["dev1".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };
    assert!(run(valid_action, &known_devices, KNOWN_TOOLS).is_ok());

    // Invalid device name should fail
    let invalid_action = TokenAction::Add {
        tokens_file,
        name: "george".to_string(),
        devices: vec!["unknown_dev".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };
    assert!(run(invalid_action, &known_devices, KNOWN_TOOLS).is_err());
}

#[test]
fn empty_device_scope_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "hannah".to_string(),
        devices: vec![],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, .. } => {
            assert_eq!(field, "devices");
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
fn empty_tool_scope_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "ivan".to_string(),
        devices: vec!["*".to_string()],
        tools: vec![],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: None,
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Scope { field, .. } => {
            assert_eq!(field, "tools");
        }
        other => panic!("expected Scope error, got {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn signal_reload_with_valid_pid_succeeds() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Use PID 1 (init/systemd) - it will ignore SIGHUP from non-root
    // We don't care if the signal succeeds, just that the token command
    // doesn't fail when given a valid PID.
    let init_pid = 1;

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "judy".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: Some(init_pid),
    };

    // We expect this to potentially fail with EPERM (permission denied) when
    // trying to signal init, but NOT fail due to invalid PID format.
    // Either success or EPERM is acceptable for this test.
    let result = run(action, &[], KNOWN_TOOLS);
    // The token should be added regardless of signal success
    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    assert_eq!(store_file.store().entries().len(), 1);
    // If we got an error, it should be I/O (EPERM), not parsing
    if let Err(e) = result {
        assert!(
            matches!(e, TokenCommandError::Io(_)),
            "unexpected error: {e:?}"
        );
    }
}

#[test]
#[cfg(unix)]
fn signal_reload_with_invalid_pid_fails() {
    let (_dir, tokens_file) = temp_tokens_file();

    // Zero PID is invalid for kill_process
    let action = TokenAction::Add {
        tokens_file,
        name: "kate".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: Some(0),
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err(), "expected error for invalid PID 0");
}

#[test]
#[cfg(not(unix))]
fn signal_reload_on_non_unix_with_pid_fails() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file,
        name: "leo".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: None,
        server_pid: Some(1234),
    };

    let result = run(action, &[], KNOWN_TOOLS);
    assert!(result.is_err());
    match result.unwrap_err() {
        TokenCommandError::Io(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
        }
        other => panic!("expected Io(Unsupported) error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// mecmcp#160: the shared command path must preserve consumer grant types.
//
// `run` is pinned to `NoGrant`, so a store holding real grants was unmanageable
// through it — `list`, `revoke`, and `rotate` all failed while deserializing the
// grant. `run_with_grant` is the seam; these tests hold it to the acceptance
// criteria on the issue.
// ---------------------------------------------------------------------------
mod grant_lifecycle {
    use super::{KNOWN_TOOLS, temp_tokens_file};
    use mecmcp_auth::{Grant, GrantError, TokenStoreFile};
    use mecmcp_runtime::{
        cli::TokenAction,
        token_cmd::{TokenCommandError, run, run_with_grant},
    };
    use serde::{Deserialize, Serialize};
    use std::path::Path;

    /// A non-unit grant, shaped like the real PAN-OS one so the test exercises a
    /// struct-with-fields rather than something that happens to deserialize from
    /// anything.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestGrant {
        allowed_roots: Vec<String>,
        actions: Vec<TestAction>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TestAction {
        Set,
        Delete,
    }

    impl Grant for TestGrant {
        type Action = TestAction;

        fn allows_action(&self, action: Self::Action) -> bool {
            self.actions.contains(&action)
        }

        fn allows_subject(&self, subject: &str) -> bool {
            self.allowed_roots.iter().any(|root| subject == root)
        }

        fn validate(&self) -> Result<(), GrantError> {
            if self.allowed_roots.is_empty() {
                return Err(GrantError::Invalid("grant needs at least one root".into()));
            }
            Ok(())
        }
    }

    fn grant() -> TestGrant {
        TestGrant {
            allowed_roots: vec!["/config/devices".to_owned()],
            actions: vec![TestAction::Set, TestAction::Delete],
        }
    }

    fn add(tokens_file: &Path, name: &str, new_grant: Option<TestGrant>) {
        run_with_grant::<TestGrant>(
            TokenAction::Add {
                tokens_file: tokens_file.to_path_buf(),
                name: name.to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["get_config".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            new_grant,
        )
        .unwrap();
    }

    fn grant_of(tokens_file: &Path, name: &str) -> Option<TestGrant> {
        let store_file = TokenStoreFile::<TestGrant>::load(tokens_file).unwrap();
        store_file
            .store()
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .unwrap()
            .grant
            .clone()
    }

    #[test]
    fn add_attaches_the_supplied_grant() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));
        assert_eq!(grant_of(&tokens_file, "writer"), Some(grant()));
    }

    #[test]
    fn add_without_a_grant_mints_a_grantless_entry() {
        // The default must be "can mutate nothing", never an ambient grant.
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "reader", None);
        assert_eq!(grant_of(&tokens_file, "reader"), None);
    }

    #[test]
    fn list_reads_a_grant_bearing_store() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));

        run_with_grant::<TestGrant>(
            TokenAction::List {
                tokens_file: tokens_file.clone(),
            },
            &[],
            KNOWN_TOOLS,
            None,
        )
        .expect("list must not fail on a grant-bearing store");
    }

    #[test]
    fn rotate_preserves_the_grant_and_changes_the_secret() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));
        let before = std::fs::read_to_string(&tokens_file).unwrap();

        run_with_grant::<TestGrant>(
            TokenAction::Rotate {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            None,
        )
        .expect("rotate must not fail on a grant-bearing store");

        // The grant survives; the digest does not.
        assert_eq!(grant_of(&tokens_file, "writer"), Some(grant()));
        assert_ne!(
            before,
            std::fs::read_to_string(&tokens_file).unwrap(),
            "rotate must change the stored digest"
        );
    }

    #[test]
    fn revoke_works_on_a_grant_bearing_store() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));
        add(&tokens_file, "other", Some(grant()));

        run_with_grant::<TestGrant>(
            TokenAction::Revoke {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            None,
        )
        .expect("revoke must not fail on a grant-bearing store");

        let store_file = TokenStoreFile::<TestGrant>::load(&tokens_file).unwrap();
        assert!(
            !store_file
                .store()
                .entries()
                .iter()
                .any(|e| e.name == "writer")
        );
        // The survivor keeps its grant — revoke must not rewrite its neighbours.
        assert_eq!(grant_of(&tokens_file, "other"), Some(grant()));
    }

    #[test]
    fn adding_to_a_grant_bearing_store_leaves_existing_grants_untouched() {
        // The acceptance criterion that actually bites: a second `add` rewrites
        // the whole file, so an existing entry's grant must come through byte for
        // byte rather than being dropped or re-serialized from a default.
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "first", Some(grant()));

        let first_before = grant_of(&tokens_file, "first");
        add(&tokens_file, "second", None);

        assert_eq!(
            grant_of(&tokens_file, "first"),
            first_before,
            "adding a token must not disturb an existing grant"
        );
        assert_eq!(grant_of(&tokens_file, "second"), None);
    }

    #[test]
    fn a_structurally_invalid_grant_is_rejected_before_it_reaches_disk() {
        let (_dir, tokens_file) = temp_tokens_file();
        let empty = TestGrant {
            allowed_roots: vec![],
            actions: vec![TestAction::Set],
        };

        let result = run_with_grant::<TestGrant>(
            TokenAction::Add {
                tokens_file: tokens_file.clone(),
                name: "bad".to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["get_config".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(empty),
        );

        match result {
            Err(TokenCommandError::InvalidArgument(message)) => {
                assert!(message.contains("invalid grant"), "got: {message}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
        assert!(
            !tokens_file.exists(),
            "a rejected grant must not create a store"
        );
    }

    #[test]
    fn run_pinned_to_nograant_still_cannot_read_a_grant_store() {
        // This is the reproduction from mecmcp#160, kept as a test so the
        // behaviour is documented rather than rediscovered. `run` is not broken —
        // it is simply the wrong entry point for a store with grants, and it fails
        // loudly instead of silently discarding them.
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));

        let result = run(
            TokenAction::List {
                tokens_file: tokens_file.clone(),
            },
            &[],
            KNOWN_TOOLS,
        );
        assert!(
            result.is_err(),
            "NoGrant must not silently succeed against a grant-bearing store"
        );

        // Critically, the failed read left the grant intact on disk.
        assert_eq!(grant_of(&tokens_file, "writer"), Some(grant()));
    }

    #[test]
    fn a_grant_field_this_binary_does_not_know_is_refused_not_dropped() {
        // Codex review of mecmcp#160 raised this: every mutation deserializes the
        // whole document into `G` and reserializes it, so a field unknown to this
        // binary would be dropped on the next add/rotate/revoke. If such a field
        // encoded a restriction whose absence reads as permissive, that rewrite
        // widens authority — silently.
        //
        // `#[serde(deny_unknown_fields)]` on the grant turns that into a load
        // error, which is why StoredGrant requires it. This test pins the
        // fail-closed behaviour so a future grant that omits the attribute is
        // caught here rather than in production.
        let (_dir, tokens_file) = temp_tokens_file();
        add(&tokens_file, "writer", Some(grant()));

        // Simulate a store written by a newer binary that understands one more
        // restriction field than this one does.
        // The store is written pretty-printed, so match on the grant object's
        // opening brace rather than a compact field pattern.
        let raw = std::fs::read_to_string(&tokens_file).unwrap();
        let doctored = raw.replace(
            "\"grant\": {\n",
            "\"grant\": {\n        \"max_targets\": 1,\n",
        );
        assert_ne!(raw, doctored, "fixture must actually inject the field");
        std::fs::write(&tokens_file, &doctored).unwrap();

        let result = TokenStoreFile::<TestGrant>::load(&tokens_file);
        assert!(
            result.is_err(),
            "an unknown grant field must fail the load, not be silently dropped"
        );

        // And the file is untouched by the failed read — nothing was rewritten.
        assert_eq!(std::fs::read_to_string(&tokens_file).unwrap(), doctored);
    }

    /// A grant that deliberately omits `#[serde(deny_unknown_fields)]`.
    ///
    /// This is the shape `StoredGrant`'s docs tell consumers not to write. Codex
    /// review of mecmcp#160 made the point that documentation is not enforcement
    /// and a trait bound cannot express the attribute, so the store enforces the
    /// guarantee instead. This type exists to prove that — it is the
    /// non-compliant consumer, and it must still fail closed.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct LaxGrant {
        allowed_roots: Vec<String>,
    }

    impl Grant for LaxGrant {
        type Action = TestAction;

        fn allows_action(&self, _action: Self::Action) -> bool {
            true
        }

        fn allows_subject(&self, subject: &str) -> bool {
            self.allowed_roots.iter().any(|root| subject == root)
        }

        fn validate(&self) -> Result<(), GrantError> {
            Ok(())
        }
    }

    #[test]
    fn a_grant_without_deny_unknown_fields_still_fails_closed() {
        let (_dir, tokens_file) = temp_tokens_file();

        run_with_grant::<LaxGrant>(
            TokenAction::Add {
                tokens_file: tokens_file.clone(),
                name: "lax".to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["get_config".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(LaxGrant {
                allowed_roots: vec!["/config/devices".to_owned()],
            }),
        )
        .unwrap();

        // A newer binary added a restriction this build has never heard of.
        let raw = std::fs::read_to_string(&tokens_file).unwrap();
        let doctored = raw.replace(
            "\"grant\": {\n",
            "\"grant\": {\n        \"max_targets\": 1,\n",
        );
        assert_ne!(raw, doctored, "fixture must actually inject the field");
        std::fs::write(&tokens_file, &doctored).unwrap();

        // `LaxGrant` would happily deserialize this and drop `max_targets` on the
        // next write. The store must refuse rather than silently narrow-then-widen.
        let load = TokenStoreFile::<LaxGrant>::load(&tokens_file);
        let error = load.expect_err("a droppable grant field must fail the load");
        let rendered = format!("{error}");
        assert!(
            rendered.contains("max_targets"),
            "the error must name the field at risk, got: {rendered}"
        );

        // And every mutating path is closed too, not just load.
        let rotate = run_with_grant::<LaxGrant>(
            TokenAction::Rotate {
                tokens_file: tokens_file.clone(),
                name: "lax".to_owned(),
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            None,
        );
        assert!(
            rotate.is_err(),
            "rotate must not rewrite a file whose grant it would truncate"
        );
        assert_eq!(
            std::fs::read_to_string(&tokens_file).unwrap(),
            doctored,
            "the file must be left exactly as found"
        );
    }
}

/// `token set-scopes` (#163): change scopes without minting a new secret.
///
/// The gap this closes is specific. `rotate` preserves scopes and changes the
/// secret — the exact inverse of what an operator adjusting a scope needs — and
/// `revoke`+`add` costs the same. Hand-editing `tokens.json` keeps the secret
/// only because scopes sit in plaintext beside the digest, which is an
/// implementation detail that also skips every validation here.
#[allow(clippy::unwrap_used)]
mod set_scopes {
    use super::{KNOWN_TOOLS, temp_tokens_file};
    use mecmcp_auth::{Grant, GrantError, TokenStoreFile};
    use mecmcp_runtime::{cli::TokenAction, token_cmd::run_with_grant};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct XpathGrant {
        allowed_roots: Vec<String>,
    }

    impl Grant for XpathGrant {
        type Action = ();
        fn allows_action(&self, _action: Self::Action) -> bool {
            true
        }
        fn allows_subject(&self, subject: &str) -> bool {
            self.allowed_roots.iter().any(|r| subject.starts_with(r))
        }
        fn validate(&self) -> Result<(), GrantError> {
            if self.allowed_roots.iter().any(String::is_empty) {
                return Err(GrantError::Invalid("root must not be empty".into()));
            }
            Ok(())
        }
    }

    fn add(tokens_file: &std::path::Path, grant: XpathGrant) {
        run_with_grant(
            TokenAction::Add {
                tokens_file: tokens_file.to_path_buf(),
                name: "writer".to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["*".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(grant),
        )
        .unwrap();
    }

    fn digest_of(tokens_file: &std::path::Path) -> mecmcp_auth::TokenDigest {
        let file: TokenStoreFile<XpathGrant> = TokenStoreFile::load(tokens_file).unwrap();
        let store = file.store();
        store
            .entries()
            .iter()
            .find(|e| e.name == "writer")
            .unwrap()
            .digest
            .clone()
    }

    /// The scenario from the issue: widening a PAN-OS mutation root, which
    /// `set_scopes` could not express at all before because the grant was not a
    /// parameter.
    #[test]
    fn a_grant_can_be_widened_without_changing_the_secret() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config/devices/address".to_owned()],
            },
        );
        let digest_before = digest_of(&tokens_file);

        run_with_grant(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: None,
                tools: None,
                yes: true,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(XpathGrant {
                allowed_roots: vec![
                    "/config/devices/address".to_owned(),
                    "/config/devices/network/interface/ethernet".to_owned(),
                ],
            }),
        )
        .unwrap();

        let file: TokenStoreFile<XpathGrant> = TokenStoreFile::load(&tokens_file).unwrap();
        let store = file.store();
        let entry = store.entries().iter().find(|e| e.name == "writer").unwrap();
        assert_eq!(
            entry.grant.as_ref().unwrap().allowed_roots.len(),
            2,
            "the grant must be the widened one"
        );
        assert_eq!(
            entry.digest, digest_before,
            "the secret must be untouched — that is the entire point"
        );
    }

    /// An invalid grant is refused as bad input, not written and not surfaced
    /// as a storage fault.
    #[test]
    fn an_invalid_grant_is_refused() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            },
        );

        let error = run_with_grant(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: None,
                tools: None,
                yes: true,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(XpathGrant {
                allowed_roots: vec![String::new()],
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid grant"), "got {error}");

        // And nothing was written.
        let file: TokenStoreFile<XpathGrant> = TokenStoreFile::load(&tokens_file).unwrap();
        let store = file.store();
        let entry = store.entries().iter().find(|e| e.name == "writer").unwrap();
        assert_eq!(entry.grant.as_ref().unwrap().allowed_roots, vec!["/config"]);
    }

    /// A widening without `--yes` is refused, so it cannot be a silent side
    /// effect of a typo.
    #[test]
    fn widening_requires_confirmation() {
        let (_dir, tokens_file) = temp_tokens_file();
        run_with_grant::<mecmcp_auth::NoGrant>(
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
            None,
        )
        .unwrap();

        let error = run_with_grant::<mecmcp_auth::NoGrant>(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                devices: Some(vec!["device1".to_owned(), "device2".to_owned()]),
                tools: None,
                yes: false,
                server_pid: None,
            },
            &["device1".to_owned(), "device2".to_owned()],
            KNOWN_TOOLS,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--yes"), "got {error}");
    }

    /// Regression test: a refused widening used to leave no trace at all — the
    /// hand-rolled `tracing::info!` sat after the confirmation gate, so a
    /// refusal returned early and emitted nothing. Routing this call site
    /// through `AuditScope` means the refusal itself is now on the audit
    /// trail as a `denied` outcome, same as a served handler's authorization
    /// denial (mecmcp#415).
    #[test]
    fn a_refused_widening_is_now_audited_as_denied() {
        let (_dir, tokens_file) = temp_tokens_file();
        run_with_grant::<mecmcp_auth::NoGrant>(
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
            None,
        )
        .unwrap();

        let captured = mecmcp_audit::testutil::run_with_capture(|| {
            let _ = run_with_grant::<mecmcp_auth::NoGrant>(
                TokenAction::SetScopes {
                    tokens_file: tokens_file.clone(),
                    name: "reader".to_owned(),
                    devices: Some(vec!["device1".to_owned(), "device2".to_owned()]),
                    tools: None,
                    yes: false,
                    server_pid: None,
                },
                &["device1".to_owned(), "device2".to_owned()],
                KNOWN_TOOLS,
                None,
            );
        });

        assert!(captured.contains("tool=token_set_scopes"), "got {captured}");
        assert!(
            captured.contains("token=reader"),
            "the token name is the audited target: {captured}"
        );
        assert!(
            captured.contains("device_count=0"),
            "this call touches no device: {captured}"
        );
        assert!(captured.contains("authorization=denied"), "{captured}");
        assert!(captured.contains("result=denied"), "{captured}");
        assert!(
            captured.contains("reason=scope_widening_requires_yes"),
            "{captured}"
        );
    }

    /// A successful scope change is audited with the same canonical shape a
    /// served handler's tool call gets — `AuditScope`'s single `Drop` impl,
    /// not a bespoke `metadata="token=... widening=..."` string.
    #[test]
    fn a_successful_scope_change_emits_the_canonical_audit_shape() {
        let (_dir, tokens_file) = temp_tokens_file();
        run_with_grant::<mecmcp_auth::NoGrant>(
            TokenAction::Add {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["get_config".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &["device1".to_owned()],
            KNOWN_TOOLS,
            None,
        )
        .unwrap();

        let captured = mecmcp_audit::testutil::run_with_capture(|| {
            run_with_grant::<mecmcp_auth::NoGrant>(
                TokenAction::SetScopes {
                    tokens_file: tokens_file.clone(),
                    name: "reader".to_owned(),
                    devices: Some(vec!["device1".to_owned()]),
                    tools: None,
                    yes: false,
                    server_pid: None,
                },
                &["device1".to_owned()],
                KNOWN_TOOLS,
                None,
            )
            .unwrap();
        });

        assert!(captured.contains("tool=token_set_scopes"), "got {captured}");
        assert!(captured.contains("token=reader"), "{captured}");
        assert!(
            captured.contains("device_count=0"),
            "this call touches no device: {captured}"
        );
        assert!(captured.contains("authorization=no_auth"), "{captured}");
        assert!(captured.contains("result=ok"), "{captured}");
        assert!(captured.contains("widening=false"), "{captured}");
    }

    /// A store failure past the `--yes` gate is audited as `result=error`, not
    /// silently swallowed. The refusal path and the success path were already
    /// covered; this is the third outcome the issue's acceptance criteria name
    /// (success, failure, refused) and the one still missing at review time.
    #[test]
    fn a_store_failure_past_the_yes_gate_is_audited_as_error() {
        let (_dir, tokens_file) = temp_tokens_file();
        run_with_grant::<mecmcp_auth::NoGrant>(
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
            &["device1".to_owned()],
            KNOWN_TOOLS,
            None,
        )
        .unwrap();

        // `ghost` is not in the known-devices list passed below, so the store's
        // `validate_references` rejects it after the `--yes` gate has already
        // passed and the `AuditScope` already exists.
        let captured = mecmcp_audit::testutil::run_with_capture(|| {
            let error = run_with_grant::<mecmcp_auth::NoGrant>(
                TokenAction::SetScopes {
                    tokens_file: tokens_file.clone(),
                    name: "reader".to_owned(),
                    devices: Some(vec!["device1".to_owned(), "ghost".to_owned()]),
                    tools: None,
                    yes: true,
                    server_pid: None,
                },
                &["device1".to_owned()],
                KNOWN_TOOLS,
                None,
            )
            .unwrap_err();
            assert!(error.to_string().contains("unknown device"), "got {error}");
        });

        assert!(captured.contains("tool=token_set_scopes"), "got {captured}");
        assert!(captured.contains("token=reader"), "{captured}");
        assert!(captured.contains("result=error"), "{captured}");
        assert!(captured.contains("error_kind=error"), "{captured}");
    }

    /// Narrowing does not need confirmation — it cannot grant anything.
    #[test]
    fn narrowing_needs_no_confirmation() {
        let (_dir, tokens_file) = temp_tokens_file();
        run_with_grant::<mecmcp_auth::NoGrant>(
            TokenAction::Add {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                devices: vec!["*".to_owned()],
                tools: vec!["get_config".to_owned()],
                provider: None,
                provider_tier: None,
                on_behalf_of: None,
                actor_type: None,
                oidc_issuer: None,
                oidc_subject: None,
                server_pid: None,
            },
            &["device1".to_owned()],
            KNOWN_TOOLS,
            None,
        )
        .unwrap();

        run_with_grant::<mecmcp_auth::NoGrant>(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "reader".to_owned(),
                devices: Some(vec!["device1".to_owned()]),
                tools: None,
                yes: false,
                server_pid: None,
            },
            &["device1".to_owned()],
            KNOWN_TOOLS,
            None,
        )
        .expect("narrowing must not require --yes");
    }

    /// A grant replacement is the mutation-authority change #163 exists for, so
    /// it must reach the confirmation. Before the fix, changing only the grant
    /// left both scope comparisons unchanged, `widening` stayed false, and the
    /// escalation went through unconfirmed and was audited as a non-widening.
    #[test]
    fn replacing_a_grant_requires_confirmation() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config/devices/address".to_owned()],
            },
        );

        let error = run_with_grant(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: None,
                tools: None,
                yes: false,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            // A far broader mutation root, and nothing else changes.
            Some(XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--yes"), "got {error}");

        // Refused before the write: the old grant is still on disk.
        let file: TokenStoreFile<XpathGrant> = TokenStoreFile::load(&tokens_file).unwrap();
        let store = file.store();
        let entry = store.entries().iter().find(|e| e.name == "writer").unwrap();
        assert_eq!(
            entry.grant.as_ref().unwrap().allowed_roots,
            vec!["/config/devices/address".to_owned()],
            "a refused confirmation must not have written the new grant"
        );
    }

    /// Narrowing the *tool* wildcard to an allowlist is not a narrowing.
    ///
    /// The tool wildcard deliberately withholds the server's write tools, so an
    /// allowlist naming one grants authority the wildcard withheld. The
    /// field-blind predicate read this as the same shape as the device case and
    /// waved it through.
    #[test]
    fn wildcard_to_allowlist_on_tools_requires_confirmation() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            },
        );

        let error = run_with_grant::<XpathGrant>(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: None,
                tools: Some(vec!["get_config".to_owned()]),
                yes: false,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("--yes"), "got {error}");
    }

    #[test]
    fn an_unknown_token_is_reported_clearly() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            },
        );

        let error = run_with_grant(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "nobody".to_owned(),
                devices: None,
                tools: None,
                yes: true,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            Some(XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            }),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not exist"), "got {error}");
    }

    /// Changing nothing is a usage error, not a silent no-op write.
    #[test]
    fn no_change_requested_is_an_error() {
        let (_dir, tokens_file) = temp_tokens_file();
        add(
            &tokens_file,
            XpathGrant {
                allowed_roots: vec!["/config".to_owned()],
            },
        );

        let error = run_with_grant::<XpathGrant>(
            TokenAction::SetScopes {
                tokens_file: tokens_file.clone(),
                name: "writer".to_owned(),
                devices: None,
                tools: None,
                yes: true,
                server_pid: None,
            },
            &[],
            KNOWN_TOOLS,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("at least one"), "got {error}");
    }
}

#[test]
fn add_with_both_oidc_flags_stores_the_binding() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "alice".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: Some("human".to_owned()),
        oidc_issuer: Some("https://idp.example.com".to_owned()),
        oidc_subject: Some("alice".to_owned()),
        server_pid: None,
    };
    if let Err(e) = &run(action, &[], KNOWN_TOOLS) {
        panic!("add failed: {e}");
    }

    let store_file = TokenStoreFile::<mecmcp_auth::NoGrant>::load(&tokens_file).unwrap();
    let store = store_file.store();
    let entry = store
        .entries()
        .iter()
        .find(|e| e.name == "alice")
        .expect("token exists");
    let oidc_subject = entry.oidc_subject.as_ref().expect("oidc_subject stored");
    assert_eq!(oidc_subject.issuer, "https://idp.example.com");
    assert_eq!(oidc_subject.subject, "alice");
}

#[test]
fn add_with_only_oidc_issuer_is_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "alice".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: Some("https://idp.example.com".to_owned()),
        oidc_subject: None,
        server_pid: None,
    };
    let error = run(action, &[], KNOWN_TOOLS).unwrap_err();
    assert!(error.to_string().contains("--oidc-subject"), "got {error}");
}

#[test]
fn add_with_only_oidc_subject_is_rejected() {
    let (_dir, tokens_file) = temp_tokens_file();

    let action = TokenAction::Add {
        tokens_file: tokens_file.clone(),
        name: "alice".to_string(),
        devices: vec!["*".to_string()],
        tools: vec!["*".to_string()],
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: None,
        oidc_issuer: None,
        oidc_subject: Some("alice".to_owned()),
        server_pid: None,
    };
    let error = run(action, &[], KNOWN_TOOLS).unwrap_err();
    assert!(error.to_string().contains("--oidc-issuer"), "got {error}");
}
