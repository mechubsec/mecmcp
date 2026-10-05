//! `token set-provenance`: retag a token without minting a new secret (#289).
//!
//! The four provenance fields could only be set at `add` time. `set-scopes`
//! takes devices and tools only, `rotate` reissues the secret, and `revoke`+`add`
//! does the same — so the only way to tag an existing token was to hand-edit
//! `tokens.json`, which skips the two rules the loader enforces (`provider`
//! requires an actor type that is not `human`; a present-but-empty field is
//! refused). Getting either wrong by hand means the service refuses to start, on
//! a credential file, at restart.
//!
//! Semantics are **full replacement**: every call rewrites all four fields from
//! the flags, so an omitted flag clears. Because that is destructive, a call
//! that would clear a field which currently holds a value requires `--yes` —
//! the same shape `set-scopes` uses to confirm a widening. Adding or changing a
//! value is unprompted; only destruction asks.

#![allow(clippy::unwrap_used)]

use mecmcp_auth::{ActorType, NoGrant, Tier, TokenEntry, TokenStoreFile};
use mecmcp_runtime::{
    cli::TokenAction,
    token_cmd::{TokenCommandError, run},
};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const KNOWN_TOOLS: &[&str] = &["get_config", "execute_command"];

fn temp_tokens_file() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tokens.json");
    (dir, path)
}

/// Mint `name` with the given provenance, returning nothing but the file state.
fn add_token(
    tokens_file: &Path,
    name: &str,
    provider: Option<&str>,
    provider_tier: Option<&str>,
    on_behalf_of: Option<&str>,
    actor_type: Option<&str>,
) {
    run(
        TokenAction::Add {
            tokens_file: tokens_file.to_path_buf(),
            name: name.to_owned(),
            devices: vec!["device1".to_owned()],
            tools: vec!["get_config".to_owned()],
            provider: provider.map(str::to_owned),
            provider_tier: provider_tier.map(str::to_owned),
            on_behalf_of: on_behalf_of.map(str::to_owned),
            actor_type: actor_type.map(str::to_owned),
            oidc_issuer: None,
            oidc_subject: None,
            server_pid: None,
        },
        &[],
        KNOWN_TOOLS,
    )
    .unwrap();
}

fn set_provenance(
    tokens_file: &Path,
    name: &str,
    provider: Option<&str>,
    provider_tier: Option<&str>,
    on_behalf_of: Option<&str>,
    actor_type: Option<&str>,
    yes: bool,
) -> Result<(), TokenCommandError> {
    run(
        TokenAction::SetProvenance {
            tokens_file: tokens_file.to_path_buf(),
            name: name.to_owned(),
            provider: provider.map(str::to_owned),
            provider_tier: provider_tier.map(str::to_owned),
            on_behalf_of: on_behalf_of.map(str::to_owned),
            actor_type: actor_type.map(str::to_owned),
            yes,
            server_pid: None,
        },
        &[],
        KNOWN_TOOLS,
    )
}

fn entry(tokens_file: &Path, name: &str) -> TokenEntry<NoGrant> {
    let store_file = TokenStoreFile::<NoGrant>::load(tokens_file).unwrap();
    let store = store_file.store();
    store
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .expect("token exists")
        .clone()
}

/// The whole point: tag a token minted before the fields existed.
#[test]
fn set_provenance_tags_an_untagged_token() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    assert_eq!(
        entry(&tokens_file, "fleet").actor_type,
        ActorType::Unknown,
        "precondition: an untagged token audits as unknown"
    );

    set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        Some("mharman"),
        Some("agent"),
        false,
    )
    .unwrap();

    let tagged = entry(&tokens_file, "fleet");
    assert_eq!(tagged.provider.as_deref(), Some("anthropic"));
    assert_eq!(tagged.provider_tier, Some(Tier::Public));
    assert_eq!(tagged.on_behalf_of.as_deref(), Some("mharman"));
    assert_eq!(tagged.actor_type, ActorType::Agent);
}

/// The secret must survive, or the command is no better than `rotate`.
///
/// Every registered client would have to be reconfigured, which is precisely
/// what makes `rotate` and `revoke`+`add` the wrong tools for this job.
#[test]
fn set_provenance_preserves_the_secret_and_the_scopes() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    let before = entry(&tokens_file, "fleet");

    set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        Some("agent"),
        false,
    )
    .unwrap();

    let after = entry(&tokens_file, "fleet");
    assert_eq!(after.digest, before.digest, "the secret must not change");
    assert_eq!(
        after.devices, before.devices,
        "device scope must not change"
    );
    assert_eq!(after.tools, before.tools, "tool scope must not change");
    assert_eq!(
        after.created_at, before.created_at,
        "created_at must not change"
    );
}

/// Full replacement: an omitted flag clears the field it names.
///
/// Confirmed with `--yes`, because clearing a populated field is destructive.
#[test]
fn omitting_a_flag_clears_that_field() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        Some("mharman"),
        Some("agent"),
    );

    // Restate everything except on_behalf_of.
    set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        Some("agent"),
        true,
    )
    .unwrap();

    assert_eq!(
        entry(&tokens_file, "fleet").on_behalf_of,
        None,
        "an omitted flag clears the field under replacement semantics"
    );
}

/// Destruction is confirmed. Without `--yes`, a clearing call is refused whole.
#[test]
fn clearing_a_populated_field_requires_yes() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        Some("mharman"),
        Some("agent"),
    );

    let error = set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        Some("agent"),
        false,
    )
    .expect_err("dropping on_behalf_of must be confirmed");

    assert!(
        matches!(error, TokenCommandError::InvalidArgument(ref message) if message.contains("--yes")),
        "the refusal must name the flag that proceeds: {error:?}"
    );
    assert_eq!(
        entry(&tokens_file, "fleet").on_behalf_of.as_deref(),
        Some("mharman"),
        "a refused call must not have written anything"
    );
}

/// Regression test: a refused clear used to leave no audit trace at all — the
/// hand-rolled `tracing::info!` sat after the confirmation gate, so refusing
/// returned early and emitted nothing. Routing this call site through
/// `AuditScope` means the refusal is now a `denied` outcome on the audit
/// trail, same shape a served handler's authorization denial gets (mecmcp#415).
#[test]
fn a_refused_clear_is_now_audited_as_denied() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        Some("mharman"),
        Some("agent"),
    );

    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        let _ = set_provenance(
            &tokens_file,
            "fleet",
            Some("anthropic"),
            Some("public"),
            None,
            Some("agent"),
            false,
        );
    });

    assert!(
        captured.contains("tool=token_set_provenance"),
        "got {captured}"
    );
    assert!(
        captured.contains("token=fleet"),
        "the token name is the audited target: {captured}"
    );
    assert!(
        captured.contains("device_count=0"),
        "this call touches no device: {captured}"
    );
    assert!(captured.contains("authorization=denied"), "{captured}");
    assert!(captured.contains("result=denied"), "{captured}");
    assert!(
        captured.contains("reason=provenance_clear_requires_yes"),
        "{captured}"
    );
}

/// A successful provenance change is audited with the same canonical shape a
/// served handler's tool call gets — `AuditScope`'s single `Drop` impl, not a
/// bespoke `metadata="token=... cleared=..."` string.
#[test]
fn a_successful_provenance_change_emits_the_canonical_audit_shape() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    let captured = mecmcp_audit::testutil::run_with_capture(|| {
        set_provenance(
            &tokens_file,
            "fleet",
            Some("anthropic"),
            Some("public"),
            Some("mharman"),
            Some("agent"),
            false,
        )
        .unwrap();
    });

    assert!(
        captured.contains("tool=token_set_provenance"),
        "got {captured}"
    );
    assert!(captured.contains("token=fleet"), "{captured}");
    assert!(
        captured.contains("device_count=0"),
        "this call touches no device: {captured}"
    );
    assert!(captured.contains("authorization=no_auth"), "{captured}");
    assert!(captured.contains("result=ok"), "{captured}");
}

/// Adding a value is not destruction, so it is not confirmed.
#[test]
fn setting_a_field_that_was_empty_needs_no_confirmation() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, Some("human"));

    set_provenance(
        &tokens_file,
        "fleet",
        None,
        None,
        Some("mharman"),
        Some("human"),
        false,
    )
    .expect("populating an empty field is not destructive");

    assert_eq!(
        entry(&tokens_file, "fleet").on_behalf_of.as_deref(),
        Some("mharman")
    );
}

/// The rule the loader enforces must be enforced here, at write time.
///
/// Hand-editing gets this wrong and the service refuses to start at next
/// restart. Routing through the validating path is the entire justification for
/// the command existing.
#[test]
fn provider_with_a_human_actor_type_is_refused_at_write_time() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    let error = set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        Some("human"),
        true,
    )
    .expect_err("a provider contradicts actor_type human");

    assert!(
        format!("{error:?}").contains("human"),
        "the error must name the contradiction: {error:?}"
    );
    assert_eq!(
        entry(&tokens_file, "fleet").provider,
        None,
        "a refused call must not have written anything"
    );
}

/// `--actor-type unknown` with a provider is refused, as it is at `add`.
///
/// On disk an omitted actor type and an explicit `unknown` both deserialize to
/// `Unknown`; the flag is the only place the two are distinguishable, so the
/// reconciliation must happen here rather than being guessed later.
#[test]
fn explicit_unknown_actor_type_with_a_provider_is_refused() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    let error = set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        Some("unknown"),
        true,
    )
    .expect_err("unknown cannot be combined with a provider");

    assert!(
        matches!(error, TokenCommandError::InvalidArgument(_)),
        "expected an argument error: {error:?}"
    );
}

/// An omitted actor type alongside a provider is derived, not demanded.
#[test]
fn actor_type_is_derived_from_a_provider_when_omitted() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        None,
        false,
    )
    .unwrap();

    assert_eq!(
        entry(&tokens_file, "fleet").actor_type,
        ActorType::Agent,
        "nothing but an agent has an LLM provider"
    );
}

/// A name that is not in the store is an argument error, not a silent no-op.
#[test]
fn unknown_token_name_is_refused() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);

    let error = set_provenance(
        &tokens_file,
        "nonexistent",
        Some("anthropic"),
        Some("public"),
        None,
        None,
        false,
    )
    .expect_err("an unknown token must be refused");

    assert!(
        format!("{error:?}").contains("nonexistent"),
        "the error must name the token: {error:?}"
    );
}

/// One token's provenance change must not disturb its neighbours.
#[test]
fn other_tokens_are_left_untouched() {
    let (_dir, tokens_file) = temp_tokens_file();
    add_token(&tokens_file, "fleet", None, None, None, None);
    add_token(
        &tokens_file,
        "neighbour",
        Some("ollama"),
        Some("private"),
        Some("someone"),
        Some("agent"),
    );

    let before = entry(&tokens_file, "neighbour");

    set_provenance(
        &tokens_file,
        "fleet",
        Some("anthropic"),
        Some("public"),
        None,
        None,
        false,
    )
    .unwrap();

    let after = entry(&tokens_file, "neighbour");
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.provider, before.provider);
    assert_eq!(after.provider_tier, before.provider_tier);
    assert_eq!(after.on_behalf_of, before.on_behalf_of);
    assert_eq!(after.actor_type, before.actor_type);
}
