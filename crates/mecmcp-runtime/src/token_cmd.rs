//! Bearer-token management commands.
//!
//! Provides add, list, revoke, and rotate actions for token stores, with safe
//! SIGHUP hot-reload signalling via rustix.

use crate::cli::TokenAction;
use mecmcp_audit::AuditScope;
use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, StoredGrant, TokenStoreFile};
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// Which scope field is being compared.
///
/// The comparison is not the same for both. For devices, `Wildcard` permits
/// every device, so narrowing to an allowlist can only reduce authority. For
/// tools, `Wildcard` deliberately **denies** the server's write tools, so naming
/// one explicitly grants something the wildcard did not — the same transition is
/// a narrowing in one field and an escalation in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeField {
    /// Device scope. `Wildcard` is the broadest value.
    Devices,
    /// Tool scope. `Wildcard` excludes write tools, so it is not the broadest.
    Tools,
}

/// Whether replacing `current` with `next` grants anything it did not before.
///
/// Only a widening needs confirmation. Narrowing cannot grant access, so
/// requiring `--yes` to *reduce* a scope would train operators to pass it
/// reflexively — which is how the confirmation stops being one.
///
/// Conservative by construction: anything not provably a narrowing counts as a
/// widening.
fn is_widening(field: ScopeField, current: &ScopeSet, next: Option<&ScopeSet>) -> bool {
    let Some(next) = next else {
        return false; // unchanged
    };
    match (current, next) {
        (ScopeSet::Wildcard, ScopeSet::Wildcard) => false,
        // Devices: the wildcard already permits everything, so an allowlist is
        // strictly smaller. Tools: the wildcard withholds write tools, so an
        // allowlist can name one and gain authority. Treated as a widening
        // because this function cannot see the server's write-tool registry.
        (ScopeSet::Wildcard, ScopeSet::Allowlist(_)) => field == ScopeField::Tools,
        (ScopeSet::Allowlist(_), ScopeSet::Wildcard) => true,
        (ScopeSet::Allowlist(have), ScopeSet::Allowlist(want)) => {
            want.iter().any(|name| !have.contains(name))
        }
    }
}

/// Token command execution error.
#[derive(Debug, Error)]
pub enum TokenCommandError {
    /// Token store operation failed.
    #[error(transparent)]
    Store(#[from] mecmcp_auth::FileError),

    /// Scope validation failed.
    #[error("invalid {field} scope: {message}")]
    Scope {
        /// Scope field name.
        field: &'static str,
        /// Diagnostic message.
        message: String,
    },

    /// Invalid command argument.
    #[error("{0}")]
    InvalidArgument(String),

    /// I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The four `token add` provenance flags, parsed and reconciled.
///
/// Ready to hand straight to `TokenStoreFile::add_with_options`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Provider name, passed through unchanged.
    pub provider: Option<String>,
    /// Parsed provider tier.
    pub provider_tier: Option<mecmcp_auth::Tier>,
    /// The human on whose behalf the credential acts, passed through unchanged.
    pub on_behalf_of: Option<String>,
    /// Actor type, derived from `provider` when the caller omitted it.
    pub actor_type: Option<mecmcp_auth::ActorType>,
}

/// Parse and reconcile the provenance flags accepted by `token add`.
///
/// Consumers that cannot route through [`run`] — because they carry extra
/// fields such as mutation grants or expiry — call this directly so the
/// reconciliation rules live in exactly one place. Duplicating them per server
/// is how the two servers drift apart on what a token means.
///
/// # Errors
///
/// Returns [`TokenCommandError::InvalidArgument`] if a tier or actor type is
/// unrecognised, or if `--actor-type unknown` is combined with `--provider`.
pub fn parse_provenance(
    provider: Option<String>,
    provider_tier: Option<String>,
    on_behalf_of: Option<String>,
    actor_type: Option<String>,
) -> Result<Provenance, TokenCommandError> {
    let parsed_tier = provider_tier
        .as_ref()
        .map(|s| match s.as_str() {
            "public" => Ok(mecmcp_auth::Tier::Public),
            "private" => Ok(mecmcp_auth::Tier::Private),
            other => Err(TokenCommandError::InvalidArgument(format!(
                "provider_tier must be 'public' or 'private', got '{other}'"
            ))),
        })
        .transpose()?;

    let parsed_actor = actor_type
        .as_ref()
        .map(|s| match s.as_str() {
            "human" => Ok(mecmcp_auth::ActorType::Human),
            "agent" => Ok(mecmcp_auth::ActorType::Agent),
            "unknown" => Ok(mecmcp_auth::ActorType::Unknown),
            other => Err(TokenCommandError::InvalidArgument(format!(
                "actor_type must be 'human', 'agent', or 'unknown', got '{other}'"
            ))),
        })
        .transpose()?;

    // Declaring an LLM provider is only meaningful for an agent, and a token
    // entry carrying provider metadata with any other actor type is rejected at
    // validation. Derive it rather than making the operator pass --actor-type
    // agent to satisfy a rule they cannot see, but never override an actor type
    // they stated explicitly.
    let parsed_actor = match (parsed_actor, provider.as_ref()) {
        (None, Some(_)) => Some(mecmcp_auth::ActorType::Agent),
        // Here — and only here — an omitted flag is distinguishable from an
        // explicit `unknown`. On disk both deserialize to `Unknown`, so silently
        // deriving `Agent` would override a choice the operator actually made.
        // Refuse instead of guessing.
        (Some(mecmcp_auth::ActorType::Unknown), Some(_)) => {
            return Err(TokenCommandError::InvalidArgument(
                "--actor-type unknown cannot be combined with --provider: a provider \
                 belongs to an agent. Pass --actor-type agent, or omit the flag to have \
                 it derived."
                    .to_owned(),
            ));
        }
        (existing, _) => existing,
    };

    Ok(Provenance {
        provider,
        provider_tier: parsed_tier,
        on_behalf_of,
        actor_type: parsed_actor,
    })
}

/// Parse the `--oidc-issuer`/`--oidc-subject` pair accepted by `token add`.
///
/// Both or neither: a token bound to only one of the two would either bind to
/// "any issuer" (dangerous) or fail validation downstream with a less
/// specific error than this can give the operator directly.
///
/// # Errors
///
/// Returns [`TokenCommandError::InvalidArgument`] if exactly one of the two
/// flags was given.
pub fn parse_oidc_subject(
    oidc_issuer: Option<String>,
    oidc_subject: Option<String>,
) -> Result<Option<mecmcp_auth::OidcSubject>, TokenCommandError> {
    match (oidc_issuer, oidc_subject) {
        (None, None) => Ok(None),
        (Some(issuer), Some(subject)) => Ok(Some(mecmcp_auth::OidcSubject { issuer, subject })),
        (Some(_), None) => Err(TokenCommandError::InvalidArgument(
            "--oidc-issuer requires --oidc-subject".to_owned(),
        )),
        (None, Some(_)) => Err(TokenCommandError::InvalidArgument(
            "--oidc-subject requires --oidc-issuer".to_owned(),
        )),
    }
}

/// Execute a token management command.
///
/// # Arguments
///
/// * `action` - The token action to perform
/// * `known_devices` - Device names to validate against (empty slice = no validation)
/// * `known_tools` - Tool names to validate against
///
/// # Errors
///
/// Returns error if the token operation fails, scope validation fails, or I/O fails.
pub fn run(
    action: TokenAction,
    known_devices: &[String],
    known_tools: &[&str],
) -> Result<(), TokenCommandError> {
    run_with_grant::<NoGrant>(action, known_devices, known_tools, None)
}

/// Execute a token management command against a store carrying vendor grants.
///
/// [`run`] is this function pinned to [`NoGrant`]. A consumer whose store holds
/// real grants must call this instead: the store is deserialized as `G`, so
/// `list`, `revoke`, and `rotate` round-trip existing grants untouched. Calling
/// [`run`] against such a store fails to deserialize (`invalid type: map,
/// expected unit struct NoGrant`) — the grant is not lost, but it is unreadable
/// through the shared command path, which is the whole reason this seam exists
/// (mecmcp#160).
///
/// `new_grant` applies to `add` only, and only to the token being created. It is
/// deliberately explicit rather than defaulted: a server that forgets to pass a
/// grant should mint a token that can mutate nothing, not one that inherits some
/// ambient default. Existing entries are never rewritten from it.
///
/// # Arguments
///
/// * `action` - The token action to perform
/// * `known_devices` - Device names to validate against (empty slice = no validation)
/// * `known_tools` - Tool names to validate against
/// * `new_grant` - Grant to attach to a newly added token; `None` mints a
///   grantless entry. Ignored by `list`, `revoke`, and `rotate`.
///
/// # Errors
///
/// Returns error if the token operation fails, scope validation fails,
/// `new_grant` is structurally invalid, or I/O fails.
pub fn run_with_grant<G>(
    action: TokenAction,
    known_devices: &[String],
    known_tools: &[&str],
    new_grant: Option<G>,
) -> Result<(), TokenCommandError>
where
    G: StoredGrant,
{
    let known = KnownNames {
        devices: if known_devices.is_empty() {
            None
        } else {
            Some(known_devices)
        },
        tools: known_tools,
    };

    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            oidc_issuer,
            oidc_subject,
            server_pid,
        } => {
            let devices_scope = parse_scope(devices, "devices")?;
            let tools_scope = parse_scope(tools, "tools")?;

            let provenance = parse_provenance(provider, provider_tier, on_behalf_of, actor_type)?;
            let oidc_subject = parse_oidc_subject(oidc_issuer, oidc_subject)?;

            // Not a safety check — the store already refuses an invalid grant
            // before writing: `add_with_options` builds a `TokenStore` (which
            // validates each entry, and so each grant) ahead of `write_atomic`,
            // so a malformed grant never reaches disk either way.
            //
            // This exists for the error the operator sees. Reaching it through
            // the store surfaces a nested `FileError::Store { Entry { Grant } }`
            // about a file; raising it here says "the grant you passed on the
            // command line is invalid" and classifies it as bad input rather
            // than a storage fault. The cost is validating twice, which is
            // cheap, and taking precedence over scope/reference errors.
            if let Some(grant) = new_grant.as_ref() {
                grant.validate().map_err(|error| {
                    TokenCommandError::InvalidArgument(format!("invalid grant: {error}"))
                })?;
            }

            let secret = TokenStoreFile::<G>::add_with_options(
                &tokens_file,
                &name,
                devices_scope,
                tools_scope,
                None, // expires_at
                new_grant,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
                oidc_subject,
                &known,
            )?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::SetScopes {
            tokens_file,
            name,
            devices,
            tools,
            yes,
            server_pid,
        } => {
            let devices_scope = devices.map(|v| parse_scope(v, "devices")).transpose()?;
            let tools_scope = tools.map(|v| parse_scope(v, "tools")).transpose()?;

            if devices_scope.is_none() && tools_scope.is_none() && new_grant.is_none() {
                return Err(TokenCommandError::InvalidArgument(
                    "set-scopes needs at least one of --devices, --tools, or a grant".to_owned(),
                ));
            }

            // Read the current scopes so the operator sees what is changing.
            // A scope change is a security event and previously left no trace
            // at all; showing before and after is the minimum that makes a
            // widening deliberate rather than a side effect of a typo.
            // Same reasoning as the Add arm: validate here so the operator is
            // told their grant is bad, not handed a nested storage error.
            if let Some(grant) = new_grant.as_ref() {
                grant.validate().map_err(|error| {
                    TokenCommandError::InvalidArgument(format!("invalid grant: {error}"))
                })?;
            }

            // Cloned out of the store: `store()` returns a guard, and holding
            // a borrow into it across the write below would not compile.
            let store_file = TokenStoreFile::<G>::load(&tokens_file)?;
            let (before_devices, before_tools, before_grant) = {
                let store = store_file.store();
                let existing = store
                    .entries()
                    .iter()
                    .find(|entry| entry.name == name)
                    .ok_or_else(|| {
                        TokenCommandError::InvalidArgument(format!("token '{name}' does not exist"))
                    })?;
                (
                    existing.devices.clone(),
                    existing.tools.clone(),
                    existing.grant.clone(),
                )
            };

            // A grant replacement is always treated as a widening. `Grant`
            // exposes no subset relation, so this code cannot prove a new grant
            // is narrower — and the case #163 exists for is widening a mutation
            // root, which would otherwise have skipped the confirmation entirely
            // and audited `widening=false`. Confirming a narrowing costs an
            // operator one flag; missing a widening costs authority nobody
            // approved.
            let widening =
                is_widening(ScopeField::Devices, &before_devices, devices_scope.as_ref())
                    || is_widening(ScopeField::Tools, &before_tools, tools_scope.as_ref())
                    || new_grant.is_some();

            // A scope change is a security event. Auditing here — through the
            // same `AuditScope` a served handler would use — means the record
            // exists in the same shape and stream even though the change is
            // made by a CLI rather than through the served API, and means a
            // refusal below is recorded rather than silent.
            //
            // The token name goes in `meta`, not `devices`: `devices` is a
            // redactable field (an operator can install a `devices=drop` or
            // `devices=hmac` policy), and this call touches no device, so
            // redacting it would erase the identity of the token whose
            // privileges just changed. `token` is not a redactable key, so
            // the name survives any installed policy.
            let mut scope = AuditScope::stdio("token_set_scopes", "set_scopes", Vec::new());
            scope.meta("token", name.clone());
            scope.meta("widening", widening);

            println!("token: {name}");
            println!("  devices: {before_devices:?}");
            if let Some(next) = devices_scope.as_ref() {
                println!("        -> {next:?}");
            }
            println!("  tools:   {before_tools:?}");
            if let Some(next) = tools_scope.as_ref() {
                println!("        -> {next:?}");
            }
            if let Some(next) = new_grant.as_ref() {
                // `Debug`, not a bespoke summary: a grant is vendor-defined and
                // this crate cannot know its shape. Printing only "replaced" —
                // as the first version did — left an operator unable to spot a
                // mistyped or unexpectedly broad grant in the very output the
                // confirmation exists to make them read.
                //
                // `Grant: Debug` is a trait bound, and a grant carries authority
                // rather than secrets: `TokenEntry`'s secret is the digest, which
                // is not part of this.
                match before_grant.as_ref() {
                    Some(current) => println!("  grant:   {current:?}\n        -> {next:?}"),
                    None => println!("  grant:   (none)\n        -> {next:?}"),
                }
            }

            if widening && !yes {
                scope.deny("scope_widening_requires_yes");
                return Err(TokenCommandError::InvalidArgument(
                    "this widens a scope, which is a privilege escalation; re-run with --yes"
                        .to_owned(),
                ));
            }

            if let Err(error) = TokenStoreFile::<G>::set_scopes(
                &tokens_file,
                &name,
                devices_scope,
                tools_scope,
                new_grant,
                &known,
            ) {
                scope.fail(&error);
                return Err(error.into());
            }
            scope.succeed();

            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::SetProvenance {
            tokens_file,
            name,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            yes,
            server_pid,
        } => {
            // The same reconciliation `add` performs, from the one place that
            // owns it. Restating the derive rule here is how two paths end up
            // disagreeing about what a token means.
            let provenance = parse_provenance(provider, provider_tier, on_behalf_of, actor_type)?;

            // Cloned out of the store for the same reason as the SetScopes arm:
            // `store()` returns a guard, and holding a borrow across the write
            // would not compile.
            let store_file = TokenStoreFile::<G>::load(&tokens_file)?;
            let before = {
                let store = store_file.store();
                store
                    .entries()
                    .iter()
                    .find(|entry| entry.name == name)
                    .ok_or_else(|| {
                        TokenCommandError::InvalidArgument(format!("token '{name}' does not exist"))
                    })?
                    .clone()
            };

            // Replacement semantics make an omitted flag destructive, and the
            // fields exist to attribute actions to a principal — losing one
            // silently is not discovered until an auditor reads an event months
            // later. So the clears are named, and confirmed.
            let mut cleared: Vec<&str> = Vec::new();
            if before.provider.is_some() && provenance.provider.is_none() {
                cleared.push("provider");
            }
            if before.provider_tier.is_some() && provenance.provider_tier.is_none() {
                cleared.push("provider_tier");
            }
            if before.on_behalf_of.is_some() && provenance.on_behalf_of.is_none() {
                cleared.push("on_behalf_of");
            }
            if before.actor_type != mecmcp_auth::ActorType::Unknown
                && provenance.actor_type.is_none()
            {
                cleared.push("actor_type");
            }

            // Provenance decides how every subsequent action by this token is
            // attributed, so a change to it is an audit event in its own
            // right — recorded here, through the same `AuditScope` a served
            // handler would use, because the change is made by a CLI rather
            // than through the served API.
            //
            // As in `set_scopes`, the token name goes in `meta`, not
            // `devices`: this call touches no device, and `devices` can be
            // redacted by operator policy, which would erase which token's
            // provenance just changed. `token` is not a redactable key.
            let mut scope = AuditScope::stdio("token_set_provenance", "set_provenance", Vec::new());
            scope.meta("token", name.clone());
            scope.meta("cleared", cleared.join("|"));

            println!("token: {name}");
            println!(
                "  provider:      {:?} -> {:?}",
                before.provider, provenance.provider
            );
            println!(
                "  provider_tier: {:?} -> {:?}",
                before.provider_tier, provenance.provider_tier
            );
            println!(
                "  on_behalf_of:  {:?} -> {:?}",
                before.on_behalf_of, provenance.on_behalf_of
            );
            println!(
                "  actor_type:    {:?} -> {:?}",
                before.actor_type,
                provenance.actor_type.unwrap_or_default()
            );

            if !cleared.is_empty() && !yes {
                scope.deny("provenance_clear_requires_yes");
                return Err(TokenCommandError::InvalidArgument(format!(
                    "this clears {} — every field is replaced on each call, so an omitted \
                     flag drops the value it names; restate it, or re-run with --yes",
                    cleared.join(", ")
                )));
            }

            if let Err(error) = TokenStoreFile::<G>::set_provenance(
                &tokens_file,
                &name,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
            ) {
                scope.fail(&error);
                return Err(error.into());
            }
            scope.succeed();

            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::List { tokens_file } => list::<G>(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::<G>::revoke(&tokens_file, &name, &known)?;
            if removed {
                eprintln!("revoked '{name}'");
                // Only when something was actually removed. A no-op revoke has
                // no stale credential to warn about (mecmcp#266).
                if let Some(warning) = reload_warning(server_pid, "token removed", &tokens_file) {
                    eprintln!("{warning}");
                }
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let secret = TokenStoreFile::<G>::rotate(&tokens_file, &name, &known)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            // Rotate needs this more than revoke: without the reload the server
            // still accepts the OLD secret, so an operator who believes they
            // have retired it is wrong in the more dangerous direction
            // (mecmcp#266).
            if let Some(warning) = reload_warning(server_pid, "secret rotated", &tokens_file) {
                eprintln!("{warning}");
            }
            signal_reload(server_pid)?;
            Ok(())
        }
    }
}

fn parse_scope(values: Vec<String>, field: &'static str) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|v| v == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

fn list<G>(path: &Path) -> Result<(), TokenCommandError>
where
    G: StoredGrant,
{
    let store_file = TokenStoreFile::<G>::load(path)?;
    let store = store_file.store();
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<32} {:<24} {:<24} CREATED_AT",
        "NAME", "DEVICES", "TOOLS"
    )?;
    for entry in store.entries() {
        let devices = match &entry.devices {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        let tools = match &entry.tools {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        writeln!(
            out,
            "{:<32} {:<24} {:<24} {}",
            entry.name,
            devices,
            tools,
            entry.created_at.to_rfc3339()
        )?;
    }
    Ok(())
}

/// Send SIGHUP to the specified process for hot-reload.
///
/// # Errors
///
/// Returns error if the PID is invalid or the signal fails.
#[cfg(unix)]
/// Warning text for a credential change that has not reached the running server.
///
/// Returns `None` when a PID was supplied, because [`signal_reload`] delivers
/// SIGHUP and the change is live before the command exits.
///
/// # Why this exists (mecmcp#266)
///
/// `token revoke` removes the entry, prints `revoked '<name>'` and exits 0 —
/// while a running server keeps its store in memory and goes on accepting the
/// credential until it is signalled. An operator revoking a compromised token
/// has every reason to read that output as "the credential is dead". Measured
/// on a live server: immediately after `revoke` without `--server-pid` the
/// token still returned 200; after SIGHUP it returned 401.
///
/// The reload design is deliberate — a failed reload must not take
/// authentication offline — so the gap is the missing signal to the operator,
/// not the caching. This supplies that signal.
///
/// The command still exits 0: the revoke genuinely succeeded, and failing it
/// would misreport that and break scripts that check the exit status.
fn reload_warning(server_pid: Option<i32>, effect: &str, tokens_file: &Path) -> Option<String> {
    if server_pid.is_some() {
        return None;
    }
    Some(format!(
        "warning: {effect} in {}, but a running server holds its token store in \
         memory and will keep accepting the old credential until it receives \
         SIGHUP. The credential is NOT dead yet. Re-run with --server-pid <pid>, \
         or signal the service directly (systemctl kill -s HUP <unit>).",
        tokens_file.display()
    ))
}

fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

/// No-op on non-Unix platforms.
///
/// # Errors
///
/// Returns error if a PID was provided on a non-Unix platform.
#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn oidc_subject_absent_when_neither_flag_given() {
        assert!(parse_oidc_subject(None, None).unwrap().is_none());
    }

    #[test]
    fn oidc_subject_present_when_both_flags_given() {
        let subject = parse_oidc_subject(
            Some("https://idp.example.com".to_owned()),
            Some("alice".to_owned()),
        )
        .unwrap()
        .expect("both flags given must produce a subject");
        assert_eq!(subject.issuer, "https://idp.example.com");
        assert_eq!(subject.subject, "alice");
    }

    #[test]
    fn oidc_issuer_without_subject_is_rejected() {
        let err = parse_oidc_subject(Some("https://idp.example.com".to_owned()), None)
            .expect_err("issuer alone must be refused");
        assert!(matches!(err, TokenCommandError::InvalidArgument(_)));
    }

    #[test]
    fn oidc_subject_without_issuer_is_rejected() {
        let err = parse_oidc_subject(None, Some("alice".to_owned()))
            .expect_err("subject alone must be refused");
        assert!(matches!(err, TokenCommandError::InvalidArgument(_)));
    }

    /// A supplied PID means SIGHUP was delivered, so there is nothing to warn about.
    #[test]
    fn no_warning_when_the_server_was_signalled() {
        assert!(
            reload_warning(
                Some(1234),
                "token removed",
                Path::new("/etc/jmcp/tokens.json")
            )
            .is_none()
        );
    }

    /// Without a PID the operator must be told the credential is still live.
    ///
    /// Regression test for mecmcp#266: `revoke` printed success and exited 0
    /// while the running server kept accepting the token, and nothing said so.
    #[test]
    fn warns_that_the_credential_is_not_dead_yet() {
        let warning = reload_warning(None, "token removed", Path::new("/etc/jmcp/tokens.json"))
            .expect("a revoke with no --server-pid must warn");

        assert!(
            warning.contains("NOT dead"),
            "the warning must contradict the success message directly: {warning}"
        );
        assert!(
            warning.contains("--server-pid"),
            "the warning must name the flag that fixes it: {warning}"
        );
        assert!(
            warning.contains("SIGHUP"),
            "the warning must name the mechanism: {warning}"
        );
        assert!(
            warning.contains("/etc/jmcp/tokens.json"),
            "the warning must name the store that changed: {warning}"
        );
    }

    /// Rotate carries its own wording; the old secret is what stays live.
    #[test]
    fn rotate_warning_names_its_own_effect() {
        let warning = reload_warning(None, "secret rotated", Path::new("/tmp/t.json"))
            .expect("a rotate with no --server-pid must warn");
        assert!(warning.contains("secret rotated"), "{warning}");
        assert!(warning.contains("old credential"), "{warning}");
    }

    #[test]
    fn provenance_derives_agent_from_a_provider() {
        let parsed = parse_provenance(
            Some("anthropic".to_owned()),
            Some("private".to_owned()),
            Some("mharman".to_owned()),
            None,
        )
        .expect("valid provenance");

        assert_eq!(parsed.provider_tier, Some(mecmcp_auth::Tier::Private));
        assert_eq!(
            parsed.actor_type,
            Some(mecmcp_auth::ActorType::Agent),
            "a provider implies an agent, so the operator should not have to say so"
        );
    }

    #[test]
    fn provenance_preserves_an_explicit_actor_type() {
        let parsed = parse_provenance(
            None,
            None,
            Some("reviewer".to_owned()),
            Some("human".to_owned()),
        )
        .expect("valid provenance");

        assert_eq!(parsed.actor_type, Some(mecmcp_auth::ActorType::Human));
        assert_eq!(parsed.provider, None);
    }

    #[test]
    fn provenance_refuses_unknown_actor_type_with_a_provider() {
        // `unknown` and an omitted flag both deserialize to `Unknown` on disk,
        // so deriving `Agent` here would silently overwrite a stated choice.
        let err = parse_provenance(
            Some("anthropic".to_owned()),
            Some("private".to_owned()),
            None,
            Some("unknown".to_owned()),
        )
        .expect_err("unknown + provider must be refused");

        assert!(
            matches!(err, TokenCommandError::InvalidArgument(ref m) if m.contains("--actor-type agent")),
            "the error should name the fix, got: {err}"
        );
    }

    #[test]
    fn provenance_rejects_an_unrecognised_tier() {
        let err = parse_provenance(
            Some("anthropic".to_owned()),
            Some("secret".to_owned()),
            None,
            None,
        )
        .expect_err("an unrecognised tier must be refused");

        assert!(matches!(err, TokenCommandError::InvalidArgument(ref m) if m.contains("public")));
    }

    #[test]
    fn wildcard_is_exclusive() {
        assert!(matches!(
            parse_scope(vec!["*".to_owned()], "tools"),
            Ok(ScopeSet::Wildcard)
        ));
        assert!(parse_scope(vec!["*".to_owned(), "get_config".to_owned()], "tools").is_err());
        assert!(parse_scope(Vec::new(), "tools").is_err());
    }

    #[test]
    fn empty_scope_rejected() {
        let err = parse_scope(Vec::new(), "devices").unwrap_err();
        assert!(matches!(err, TokenCommandError::Scope { .. }));
    }

    #[test]
    fn mixed_wildcard_rejected() {
        let err = parse_scope(vec!["*".to_owned(), "device1".to_owned()], "devices").unwrap_err();
        if let TokenCommandError::Scope { field, message } = err {
            assert_eq!(field, "devices");
            assert!(message.contains("'*'"));
        } else {
            panic!("expected Scope error");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod widening_tests {
    use super::*;

    fn allow(names: &[&str]) -> ScopeSet {
        ScopeSet::Allowlist(names.iter().map(|n| (*n).to_owned()).collect())
    }

    /// Only a widening is confirmed. Requiring `--yes` to *narrow* would train
    /// operators to pass it reflexively, which is how a confirmation stops
    /// being one.
    #[test]
    fn narrowing_and_no_change_are_not_widenings() {
        assert!(
            !is_widening(ScopeField::Devices, &ScopeSet::Wildcard, None),
            "unchanged"
        );
        assert!(
            !is_widening(
                ScopeField::Devices,
                &ScopeSet::Wildcard,
                Some(&allow(&["a"]))
            ),
            "wildcard -> allowlist is the clearest narrowing there is"
        );
        assert!(
            !is_widening(
                ScopeField::Devices,
                &allow(&["a", "b"]),
                Some(&allow(&["a"]))
            ),
            "dropping a name is a narrowing"
        );
        assert!(
            !is_widening(ScopeField::Devices, &allow(&["a"]), Some(&allow(&["a"]))),
            "the same allowlist is not a widening"
        );
        assert!(!is_widening(
            ScopeField::Devices,
            &ScopeSet::Wildcard,
            Some(&ScopeSet::Wildcard)
        ));
    }

    #[test]
    fn adding_a_name_or_going_wildcard_is_a_widening() {
        assert!(
            is_widening(
                ScopeField::Devices,
                &allow(&["a"]),
                Some(&allow(&["a", "b"]))
            ),
            "gaining a name grants something new"
        );
        assert!(
            is_widening(
                ScopeField::Devices,
                &allow(&["a"]),
                Some(&ScopeSet::Wildcard)
            ),
            "allowlist -> wildcard grants everything"
        );
        assert!(
            is_widening(ScopeField::Devices, &allow(&[]), Some(&allow(&["a"]))),
            "empty -> one name is a widening"
        );
    }

    /// Reordering is not a widening — the set is what matters, not the order.
    #[test]
    fn reordering_an_allowlist_is_not_a_widening() {
        assert!(!is_widening(
            ScopeField::Devices,
            &allow(&["a", "b"]),
            Some(&allow(&["b", "a"]))
        ));
    }

    /// A swap that both adds and removes still counts, because it grants
    /// something that was not permitted before.
    #[test]
    fn a_swap_that_adds_anything_is_a_widening() {
        assert!(is_widening(
            ScopeField::Devices,
            &allow(&["a"]),
            Some(&allow(&["b"]))
        ));
    }

    /// The field asymmetry, which a field-blind predicate got wrong.
    ///
    /// `Wildcard` -> `Allowlist` reduces device authority but can *increase*
    /// tool authority, because the tool wildcard deliberately withholds the
    /// server's write tools. Naming one explicitly grants it.
    #[test]
    fn wildcard_to_allowlist_differs_by_field() {
        assert!(
            !is_widening(
                ScopeField::Devices,
                &ScopeSet::Wildcard,
                Some(&allow(&["fw-01"]))
            ),
            "for devices the wildcard is the broadest value, so this is a narrowing"
        );
        assert!(
            is_widening(
                ScopeField::Tools,
                &ScopeSet::Wildcard,
                Some(&allow(&["load_and_commit_config"]))
            ),
            "for tools the wildcard withholds write tools, so naming one is an escalation"
        );
    }
}
