//! Command-line arguments for MCP servers.
//!
//! Defines the common CLI surface shared by all vendor servers, with an
//! extensible command enum for vendor-specific subcommands.

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// MCP transport mode.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    /// Local child-process transport with no listening socket.
    Stdio,
    /// MCP Streamable HTTP transport.
    StreamableHttp,
}

/// Parse the shared CLI, reporting the consumer's own identity.
///
/// The shared `Cli` carries no version of its own, so a consumer parsing it
/// directly gets clap exit status 2 for `--version` — which breaks the
/// package-identity smoke test every deployment wants to run (#159). Pass the
/// consumer's `CARGO_PKG_NAME`/`CARGO_PKG_VERSION` and both `--version` and
/// `--help` report the binary rather than this crate.
///
/// For a server that adds flags of its own, parse the server's own type with
/// [`parse_with_provenance`] instead — this function understands only the
/// shared arguments and rejects anything else as unknown.
///
/// # Examples
/// ```no_run
/// let cli = mecmcp_runtime::cli::parse_for(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
/// # let _ = cli;
/// ```
#[must_use]
pub fn parse_for(binary_name: &'static str, version: &'static str) -> Cli {
    parse_with_provenance::<Cli>(binary_name, version).cli
}

/// Parse the consumer's CLI, and record which arguments the operator supplied.
///
/// The provenance is the point. A consumer that also reads these values from
/// product configuration cannot otherwise tell an explicitly supplied
/// `--approval-timeout-secs 900` from clap's default of the same number, so it
/// cannot implement any precedence rule at all without guessing (#162).
///
/// `C` is the *consumer's* parser, not the shared [`Cli`]. That is the whole
/// point: `approval_timeout_secs` and the rest of the flags this precedence
/// rule exists for are defined by each server, so a parser hard-wired to the
/// shared type would reject them as unknown and could never report their
/// provenance. A server flattens [`Cli`] into its own struct and passes that.
///
/// # Examples
/// ```no_run
/// use clap::Parser;
/// use mecmcp_runtime::cli::{Cli, parse_with_provenance};
///
/// #[derive(Debug, Parser)]
/// struct ServerCli {
///     #[command(flatten)]
///     shared: Cli,
///     /// A vendor flag the shared type knows nothing about.
///     #[arg(long, default_value_t = 900)]
///     approval_timeout_secs: u64,
/// }
///
/// let parsed = parse_with_provenance::<ServerCli>(
///     env!("CARGO_PKG_NAME"),
///     env!("CARGO_PKG_VERSION"),
/// );
/// // CLI wins only when it was actually given.
/// let approval_timeout_secs = if parsed.was_supplied("approval_timeout_secs") {
///     parsed.cli.approval_timeout_secs
/// } else {
///     600 // from product configuration
/// };
/// # let _ = approval_timeout_secs;
/// ```
#[must_use]
pub fn parse_with_provenance<C>(binary_name: &'static str, version: &'static str) -> ParsedCli<C>
where
    C: clap::CommandFactory + clap::FromArgMatches,
{
    match try_parse_from::<C, _, _>(binary_name, version, std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(error) => error.exit(),
    }
}

/// The real parse, over an explicit argument list.
///
/// Split out so tests drive the same code the binaries do. Building an
/// equivalent `Command` in a test was not enough: a mutation that corrupted the
/// version passed here went undetected, because the test exercised its own copy
/// of the composition rather than this function.
///
/// # Errors
/// Returns the clap error, including the `DisplayVersion` and `DisplayHelp`
/// cases, which are not failures.
pub fn try_parse_from<C, I, T>(
    binary_name: &'static str,
    version: &'static str,
    args: I,
) -> Result<ParsedCli<C>, clap::Error>
where
    C: clap::CommandFactory + clap::FromArgMatches,
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut command = C::command().name(binary_name).version(version);
    // Built explicitly, then read, then parsed. `try_get_matches_from` builds
    // too, but only after this function has already captured the tree — and an
    // unbuilt tree has not yet had global arguments propagated into its
    // subcommands, so what gets captured would depend on that ordering rather
    // than on a stated rule. Building first makes the tree the real one and puts
    // the global handling in `argument_ids_of`, where it is visible.
    command.build();
    let argument_ids = argument_ids_of(&command);
    let matches = command.try_get_matches_from(args)?;

    let supplied = supplied_arguments_from(&argument_ids, &matches);
    let cli = C::from_arg_matches(&matches)?;

    Ok(ParsedCli { cli, supplied })
}

/// An argument the operator typed, and where in the command tree it sits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuppliedArgument {
    /// Subcommand path, outermost first. Empty for a top-level argument.
    ///
    /// `token add --tokens-file x` yields `["token", "add"]`.
    pub command_path: Vec<String>,
    /// The clap argument id — the field name, not the flag spelling.
    pub id: String,
}

/// Every real argument id in a command tree, keyed by subcommand path.
///
/// Global arguments are recorded only at the level that declares them. Clap
/// propagates a global into every descendant's matches, so counting it again
/// deeper would report `--device-mapping` as supplied to `token add` when the
/// operator typed it once, before the subcommand.
fn argument_ids_of(command: &clap::Command) -> BTreeMap<Vec<String>, HashSet<String>> {
    fn walk(
        command: &clap::Command,
        path: Vec<String>,
        into: &mut BTreeMap<Vec<String>, HashSet<String>>,
    ) {
        let ids: HashSet<String> = command
            .get_arguments()
            .filter(|arg| path.is_empty() || !arg.is_global_set())
            .map(|arg| arg.get_id().as_str().to_owned())
            .collect();
        for subcommand in command.get_subcommands() {
            let mut child = path.clone();
            child.push(subcommand.get_name().to_owned());
            walk(subcommand, child, into);
        }
        into.insert(path, ids);
    }

    let mut ids = BTreeMap::new();
    walk(command, Vec::new(), &mut ids);
    ids
}

/// Collect the arguments that came from the command line, at every depth.
///
/// Clap keeps a subcommand's own arguments in a child `ArgMatches`, so a walk
/// of the root alone reported nothing for `token add --tokens-file x` and
/// `supplied_ids()` quietly contradicted its every-argument contract.
///
/// `ArgMatches::ids()` also yields the `ArgGroup` clap's derive creates for the
/// struct itself — an id named `Cli` that is not an argument at all and would
/// otherwise be reported as something the operator supplied. Groups are
/// excluded by intersecting against the command's real arguments; `try_get_raw`
/// does not distinguish them, which a test caught.
fn supplied_arguments_from(
    argument_ids: &BTreeMap<Vec<String>, HashSet<String>>,
    matches: &clap::ArgMatches,
) -> Vec<SuppliedArgument> {
    fn walk(
        argument_ids: &BTreeMap<Vec<String>, HashSet<String>>,
        matches: &clap::ArgMatches,
        path: Vec<String>,
        into: &mut Vec<SuppliedArgument>,
    ) {
        if let Some(known) = argument_ids.get(&path) {
            for id in matches.ids() {
                let id = id.as_str();
                if known.contains(id)
                    && matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine)
                {
                    into.push(SuppliedArgument {
                        command_path: path.clone(),
                        id: id.to_owned(),
                    });
                }
            }
        }

        if let Some((name, child_matches)) = matches.subcommand() {
            let mut child = path;
            child.push(name.to_owned());
            walk(argument_ids, child_matches, child, into);
        }
    }

    let mut supplied = Vec::new();
    walk(argument_ids, matches, Vec::new(), &mut supplied);
    supplied.sort_unstable();
    supplied
}

/// A parsed CLI plus which of its arguments the operator actually typed.
///
/// `C` defaults to the shared [`Cli`] so a server with no flags of its own can
/// name the type without a parameter.
#[derive(Debug)]
pub struct ParsedCli<C = Cli> {
    /// The parsed arguments.
    pub cli: C,
    /// Arguments that came from the command line rather than a default.
    supplied: Vec<SuppliedArgument>,
}

impl<C> ParsedCli<C> {
    /// Whether a top-level `id` was supplied on the command line.
    ///
    /// `id` is the field name as clap sees it — `approval_timeout_secs`, not
    /// `--approval-timeout-secs`.
    ///
    /// Top-level only, deliberately. `tokens_file` names both a server flag and
    /// an argument of `token add`; answering `true` for the second would tell a
    /// server the operator had chosen a value for the first. Use
    /// [`was_supplied_in`](Self::was_supplied_in) for a subcommand.
    ///
    /// This is the mechanism behind the precedence rule in `docs/PACKAGING.md`:
    /// an explicit CLI value wins over product configuration, and a defaulted
    /// one does not. Without it a consumer cannot distinguish the two, and
    /// would either ignore a flag the operator typed or override a config value
    /// with a default the operator never chose.
    #[must_use]
    pub fn was_supplied(&self, id: &str) -> bool {
        self.was_supplied_in(&[], id)
    }

    /// Whether `id` was supplied to the subcommand at `command_path`.
    ///
    /// `was_supplied_in(&["token", "add"], "tokens_file")` answers for
    /// `token add --tokens-file x`. An empty path is the top level.
    #[must_use]
    pub fn was_supplied_in(&self, command_path: &[&str], id: &str) -> bool {
        self.supplied
            .iter()
            .any(|argument| argument.id == id && argument.command_path == command_path)
    }

    /// Every top-level argument id the operator supplied, sorted.
    ///
    /// Subcommand arguments are in [`supplied_arguments`](Self::supplied_arguments),
    /// which carries the path that tells them apart.
    #[must_use]
    pub fn supplied_ids(&self) -> Vec<&str> {
        self.supplied
            .iter()
            .filter(|argument| argument.command_path.is_empty())
            .map(|argument| argument.id.as_str())
            .collect()
    }

    /// Every argument the operator supplied anywhere in the command tree.
    #[must_use]
    pub fn supplied_arguments(&self) -> &[SuppliedArgument] {
        &self.supplied
    }
}

/// Server-common approver-tooling switches. Flatten into a server's CLI with
/// `#[command(flatten)]` so every mecmcp-based server exposes the same flag.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct WebApproverArgs {
    /// Include staged actions in change-set status responses (approver
    /// tooling, e.g. the mechub approval webapp). Off by default: exposes
    /// staged config content to any caller with status scope.
    #[arg(long)]
    pub web_enabled_approver: bool,
}

/// Step-up approver-identity verification switches (MEC-994 W5).
///
/// Standalone, like [`WebApproverArgs`] — **not** flattened into [`Cli`].
/// Flattening it into the shared `Cli` would put `--require-verified-approver`
/// on every mecmcp-based server on upgrade, whether or not that server
/// actually wires a `ChangesetCoordinator` with `with_require_verified_approver`
/// and an `ApproverIdentity::from_attribution`-derived approver. An operator
/// who set the flag on a server that does not wire it would get a clean
/// startup and the old behavior, while `THREAT-MODEL.md` told them otherwise
/// (MEC-994 Percy review, finding F1). A server opts in explicitly with
/// `#[command(flatten)]` the same way it opts into `WebApproverArgs`, and
/// must call [`VerifiedApproverArgs::validate`] itself, since the fields it
/// cross-checks (`--approval-digest-key-file`, the server's own lab-mode
/// flag) are not uniform across servers either.
///
/// Absent `--oidc-issuer`, a server behaves identically to one with no OIDC
/// support at all: no verifier is configured, so a presented
/// `Mecmcp-Approver-Assertion` header is refused with 400 rather than
/// silently accepted (see
/// `mecmcp_transport::auth::BearerBoundary::with_approver_assertion`).
///
/// This crate depends on neither `mecmcp-oidc`, `mecmcp-transport`, nor
/// `mecmcp-changeset`, so it cannot itself build a `TokenVerifier`, an
/// `ApproverAssertionVerifier`, or configure a `ChangesetCoordinator`. It can
/// build `mecmcp-auth`'s [`ApproverPolicy`](mecmcp_auth::ApproverPolicy),
/// via [`VerifiedApproverArgs::approver_policy`]; the raw issuer/audience
/// strings are exposed for a server to build the rest.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct VerifiedApproverArgs {
    /// IdP issuer URL to verify approver assertions against. Required for any
    /// of the other approver flags to take effect.
    #[arg(long)]
    pub oidc_issuer: Option<String>,

    /// Expected `aud` claim on approver assertions. Used, alongside
    /// `--oidc-issuer`, to build an `mecmcp_oidc::OidcConfig`.
    #[arg(long)]
    pub oidc_audience: Option<String>,

    /// Claim name carrying the approver's roles or groups, e.g. `roles` or
    /// `groups`. Compared against `--approver-role`.
    #[arg(long, default_value = "roles")]
    pub oidc_role_claim: String,

    /// The role or group value a verified assertion must carry to approve.
    #[arg(long, default_value = "approver")]
    pub approver_role: String,

    /// Maximum age, in seconds, of an approver assertion's `iat` claim,
    /// per RFC 9470's `max_age` step-up pattern.
    #[arg(long, default_value_t = 300)]
    pub approver_max_age_secs: u64,

    /// Require a fresh interactive login (an `auth_time` claim no older than
    /// `--approver-max-age-secs`) rather than merely a fresh token. Off by
    /// default: not every IdP or grant type emits `auth_time`.
    #[arg(long)]
    pub approver_require_auth_time: bool,

    /// Require every change-set approval to carry a verified approver
    /// identity, and every proposal to come from an owner with a bound
    /// `oidc_subject`. Off by default, so a deployment that has not
    /// configured step-up authentication keeps behaving exactly as it did
    /// before this flag existed.
    #[arg(long)]
    pub require_verified_approver: bool,
}

impl VerifiedApproverArgs {
    /// Build the server-side binding policy, or `None` when no issuer was
    /// configured — "no issuer" and "no OIDC support at all" are the same
    /// state here.
    #[must_use]
    pub fn approver_policy(&self) -> Option<mecmcp_auth::ApproverPolicy> {
        self.oidc_issuer.as_ref()?;
        Some(mecmcp_auth::ApproverPolicy {
            approver_role: self.approver_role.clone(),
            max_age: std::time::Duration::from_secs(self.approver_max_age_secs),
            require_auth_time: self.approver_require_auth_time,
        })
    }

    /// Cross-check these flags against the two pieces of server-specific
    /// context this crate cannot see on its own: whether a
    /// `--approval-digest-key-file` was configured, and whether the
    /// server's own lab-mode waiver is on.
    ///
    /// A server that flattens `VerifiedApproverArgs` must call this (and
    /// refuse to start on an `Err`) wherever it already validates its own
    /// CLI, alongside `mecmcp_runtime::cli_validate::validate`.
    ///
    /// # Errors
    /// Returns the specific combination that has no safe interpretation.
    pub fn validate(
        &self,
        digest_key_configured: bool,
        lab_mode: bool,
    ) -> Result<(), VerifiedApproverArgsError> {
        if self.oidc_issuer.is_some() && self.oidc_audience.is_none() {
            return Err(VerifiedApproverArgsError::IssuerWithoutAudience);
        }
        if self.require_verified_approver {
            if self.oidc_issuer.is_none() {
                return Err(VerifiedApproverArgsError::RequiresIssuer);
            }
            if !digest_key_configured {
                return Err(VerifiedApproverArgsError::RequiresDigestKey);
            }
            if lab_mode {
                return Err(VerifiedApproverArgsError::IncompatibleWithLabMode);
            }
        }
        Ok(())
    }
}

/// A `VerifiedApproverArgs` combination with no safe unambiguous
/// interpretation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifiedApproverArgsError {
    /// `--oidc-issuer` was given with no `--oidc-audience`. `OidcConfig`
    /// requires an audience, so a server building one without this check
    /// would otherwise have to invent one or silently skip building the
    /// verifier — either of which is a worse failure than refusing here.
    #[error("--oidc-issuer requires --oidc-audience")]
    IssuerWithoutAudience,
    /// Strict verified-approver mode needs an IdP to verify assertions
    /// against.
    #[error("--require-verified-approver requires --oidc-issuer")]
    RequiresIssuer,
    /// Strict mode without a keyed approval digest lets the verified-approver
    /// fields (mechanism/issuer/subject/owner_subject) in a change-set record
    /// be edited with no detection, which defeats the point of requiring them.
    #[error(
        "--require-verified-approver requires --approval-digest-key-file: without a keyed \
         digest, the verified-approver fields recorded in a change-set are not tamper-evident"
    )]
    RequiresDigestKey,
    /// Lab mode lets an owner waive their own approval outright, which
    /// bypasses the two-person rule strict mode exists to enforce — the two
    /// are mutually exclusive, not layered.
    #[error(
        "--require-verified-approver is incompatible with lab mode: lab mode lets an owner \
         waive approval outright, which bypasses the verified-approver gate entirely"
    )]
    IncompatibleWithLabMode,
}

/// SSDF evidence-pipeline switches, defined once and flattened into every
/// server's CLI.
///
/// Absent `--ssdf-audit-endpoint` means no pipeline: evidence is a deployment
/// choice, and a server without it behaves exactly as before.
///
/// **Passwords come from files, never from flags.** A password in `argv` is
/// readable by any process that can run `ps`, which would hand the audit
/// writer's credential to every account on the host — the opposite of what a
/// tamper-evident trail is for. The files go through
/// [`mecmcp_secret::read_hardened_file`], the workspace's single implementation
/// of the symlink / regular-file / mode / owner checks, so a 0644 credential is
/// refused here exactly as it is for a token store.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct EvidenceArgs {
    /// ClickHouse endpoint for the SSDF evidence sink. Enables the pipeline.
    #[arg(long)]
    pub ssdf_audit_endpoint: Option<String>,

    /// This writer's chain identity. Required whenever the endpoint is set.
    ///
    /// Deliberately not defaulted to the hostname. The chain is keyed by this
    /// value, so if it ever changes the writer starts a second root -- and a
    /// fork verifies as two valid chains, so nothing downstream reports it.
    /// This fleet has already renamed its hosts once; a value that follows the
    /// hostname would have forked every chain silently when it did.
    #[arg(long)]
    pub ssdf_audit_server_id: Option<String>,

    /// ClickHouse database holding the audit table.
    #[arg(long, default_value = "ssdf")]
    pub ssdf_audit_database: String,

    /// INSERT-only write identity.
    #[arg(long, default_value = "ssdf_audit")]
    pub ssdf_audit_user: String,

    /// File holding the write identity's password. Must be 0600.
    #[arg(long)]
    pub ssdf_audit_password_file: Option<PathBuf>,

    /// SELECT-only read identity, used for the high-water and tail reads.
    #[arg(long, default_value = "ssdf_audit_verify")]
    pub ssdf_audit_verify_user: String,

    /// File holding the read identity's password. Must be 0600.
    #[arg(long)]
    pub ssdf_audit_verify_password_file: Option<PathBuf>,

    /// PEM trust anchor for the ClickHouse certificate. Required for `https://`.
    ///
    /// SSDF issues that certificate from its own CA, so the public root set
    /// cannot validate it and trusting the public set as well would only widen
    /// what can impersonate the audit destination. Lives with the other
    /// evidence flags rather than in each server's CLI so all five configure it
    /// the same way.
    #[arg(long)]
    pub ssdf_audit_ca_file: Option<PathBuf>,

    /// Durable outbox for closed segments. Required when the endpoint is set.
    ///
    /// Deliberately undefaulted. Every packaged unit runs `ProtectSystem=strict`
    /// with only its own state directory writable -- `/var/lib/jmcp`,
    /// `/var/lib/rust-panosmcp`, and so on -- so a shared default like
    /// `/var/lib/mecmcp` is writable on none of them, and the service would
    /// fail to start. There is no value that is right for every consumer, so
    /// there is no default.
    #[arg(long)]
    pub ssdf_audit_outbox: Option<PathBuf>,

    /// Delivery ledger. Required when the endpoint is set.
    #[arg(long)]
    pub ssdf_audit_ledger: Option<PathBuf>,

    /// Seconds between delivery attempts. Must be positive.
    ///
    /// Zero would make the drain's `wait_timeout` return immediately on every
    /// iteration, reloading the outbox in a tight loop -- a busy spin on CPU
    /// and disk that looks like a wedged server.
    #[arg(long, default_value_t = 30, value_parser = positive_seconds)]
    pub ssdf_audit_interval_secs: u64,

    /// Records per segment before one is closed and spooled.
    #[arg(long, default_value_t = 64)]
    pub ssdf_audit_records_per_segment: usize,

    /// Ed25519 signing key for evidence segments. Must be 0600.
    ///
    /// Optional: a deployment that has not provisioned a key produces
    /// unsigned segments rather than failing to start. When given, every
    /// segment is signed as it closes with no further operator step
    /// (MEC-457) -- there is no separate "sign" step to remember or forget.
    #[arg(long)]
    pub ssdf_audit_signing_key: Option<PathBuf>,

    /// HTTPS (or loopback HTTP) endpoint for a second, best-effort audit
    /// destination beyond SSDF -- a SIEM, a log collector, an object-lock
    /// bucket's HTTP front end. Enables the forward sink.
    ///
    /// This ships the same hash-chained [`ClosedSegment`] the SSDF sink
    /// ships, `prev_hash`/`head_hash` intact -- it is not the unchained
    /// syslog path `docs/AUDIT-FORWARDING-STANDARD.md` rejected. See
    /// [`mecmcp_audit::sinks::forward`] for why that distinction holds.
    /// Independent of `--ssdf-audit-endpoint`: SSDF's own delivery is
    /// unaffected whether or not this is set.
    ///
    /// [`ClosedSegment`]: mecmcp_audit::ClosedSegment
    #[arg(long)]
    pub audit_forward_endpoint: Option<String>,

    /// File holding a bearer token for the forward endpoint's `Authorization`
    /// header. Optional: some collectors authenticate at the network layer
    /// instead. Must be 0600, like every other credential file here.
    #[arg(long)]
    pub audit_forward_token_file: Option<PathBuf>,

    /// PEM trust anchor for the forward endpoint's certificate, if it is not
    /// signed by a publicly trusted CA.
    #[arg(long)]
    pub audit_forward_ca_file: Option<PathBuf>,

    /// Durable outbox for the forward sink. Required when
    /// `--audit-forward-endpoint` is set. Undefaulted for the same
    /// `ProtectSystem=strict` reason as `--ssdf-audit-outbox`.
    #[arg(long)]
    pub audit_forward_outbox: Option<PathBuf>,

    /// Delivery ledger for the forward sink. Required when
    /// `--audit-forward-endpoint` is set.
    #[arg(long)]
    pub audit_forward_ledger: Option<PathBuf>,
}

impl EvidenceArgs {
    /// The trust anchor to give the transport, if one was configured.
    #[must_use]
    pub fn ca_file(&self) -> Option<&Path> {
        self.ssdf_audit_ca_file.as_deref()
    }

    /// Build a pipeline config, or `None` when no endpoint was given.
    ///
    /// `--ssdf-audit-server-id` names this writer's chain. **One process per
    /// `server_id`**: two servers sharing one fork the chain, and a fork
    /// verifies as two valid chains rather than as an error, so nothing
    /// downstream reports it.
    ///
    /// # Errors
    ///
    /// Returns an error when an endpoint is configured without credentials, or
    /// when a credential file fails its permission checks. Both are refusals
    /// rather than warnings: a server that starts with a half-configured
    /// pipeline spools evidence it can never deliver.
    pub fn into_config(&self) -> Result<Option<mecmcp_audit::EvidenceConfig>, EvidenceArgsError> {
        let Some(endpoint) = self.ssdf_audit_endpoint.clone() else {
            // The forward sink rides alongside the SSDF pipeline -- the
            // recorder, chain identity and resume logic all anchor on SSDF --
            // so an operator who set `--audit-forward-endpoint` alone asked
            // for something this cannot build. Returning `Ok(None)` here
            // would silently drop a destination they explicitly configured,
            // which is exactly what issue #158's fix to the audit-file sink
            // exists to avoid elsewhere in this crate.
            if self.audit_forward_endpoint.is_some() {
                return Err(EvidenceArgsError::ForwardWithoutSsdf);
            }
            return Ok(None);
        };
        let server_id = self
            .ssdf_audit_server_id
            .clone()
            .ok_or(EvidenceArgsError::MissingServerId)?;
        // An empty expansion -- `--ssdf-audit-server-id ""` from a unit file
        // whose variable is unset -- reaches here as `Some("")`, and every
        // writer that does it would share the empty chain key and fork the
        // chain. The rule lives in mecmcp-audit so the write side and
        // `mecmcp-verify` cannot disagree about it.
        mecmcp_audit::evidence::validate_server_id(&server_id)
            .map_err(EvidenceArgsError::InvalidServerId)?;
        // Refuses http:// to a non-loopback host, exactly as the transport does
        // on every send. Checking it here too, rather than leaving it to the
        // first delivery attempt, is the difference between a server that
        // refuses to start and one that starts, spools every segment to the
        // outbox, and fails every delivery forever: a server that starts with a
        // half-configured pipeline spools evidence it can never deliver.
        mecmcp_audit::sinks::ssdf::split_endpoint(&endpoint)
            .map_err(|error| EvidenceArgsError::InvalidEndpoint(error.to_string()))?;
        if endpoint.starts_with("https://") && self.ssdf_audit_ca_file.is_none() {
            return Err(EvidenceArgsError::MissingTrustAnchor);
        }
        let outbox_path = self
            .ssdf_audit_outbox
            .clone()
            .ok_or(EvidenceArgsError::MissingPath {
                flag: "--ssdf-audit-outbox",
            })?;
        let ledger_path = self
            .ssdf_audit_ledger
            .clone()
            .ok_or(EvidenceArgsError::MissingPath {
                flag: "--ssdf-audit-ledger",
            })?;

        let password = read_password(
            self.ssdf_audit_password_file.as_deref(),
            "--ssdf-audit-password-file",
        )?;
        let verify_password = read_password(
            self.ssdf_audit_verify_password_file.as_deref(),
            "--ssdf-audit-verify-password-file",
        )?;
        let forward_sink = self.forward_config()?;

        Ok(Some(mecmcp_audit::EvidenceConfig {
            server_id,
            run_id: new_run_id(),
            records_per_segment: self.ssdf_audit_records_per_segment,
            delivery_interval: std::time::Duration::from_secs(self.ssdf_audit_interval_secs),
            sink: mecmcp_audit::SsdfSinkConfig {
                endpoint,
                database: self.ssdf_audit_database.clone(),
                username: self.ssdf_audit_user.clone(),
                password,
                verify_username: self.ssdf_audit_verify_user.clone(),
                verify_password,
                outbox_path,
                ledger_path,
                initial_backoff: std::time::Duration::from_secs(1),
                max_backoff: std::time::Duration::from_secs(60),
            },
            signing_key_path: self.ssdf_audit_signing_key.clone(),
            forward_sink,
        }))
    }

    /// The trust anchor to give the forward sink's transport, if one was
    /// configured. Separate from [`ca_file`](Self::ca_file): the forward
    /// endpoint is a different host with its own certificate, typically not
    /// issued by SSDF's private CA.
    #[must_use]
    pub fn forward_ca_file(&self) -> Option<&Path> {
        self.audit_forward_ca_file.as_deref()
    }

    /// Build the forward-sink config, or `None` when no endpoint was given.
    fn forward_config(&self) -> Result<Option<mecmcp_audit::ForwardSinkConfig>, EvidenceArgsError> {
        let Some(endpoint) = self.audit_forward_endpoint.clone() else {
            return Ok(None);
        };
        mecmcp_audit::sinks::ssdf::split_endpoint(&endpoint)
            .map_err(|error| EvidenceArgsError::InvalidEndpoint(error.to_string()))?;
        let outbox_path =
            self.audit_forward_outbox
                .clone()
                .ok_or(EvidenceArgsError::MissingPath {
                    flag: "--audit-forward-outbox",
                })?;
        let ledger_path =
            self.audit_forward_ledger
                .clone()
                .ok_or(EvidenceArgsError::MissingPath {
                    flag: "--audit-forward-ledger",
                })?;
        // Unlike the SSDF password files, a bearer token is optional here:
        // some collectors authenticate at the network layer instead of at
        // the application layer.
        let bearer_token = self
            .audit_forward_token_file
            .as_deref()
            .map(|path| mecmcp_secret::load_from_file(path, mecmcp_secret::SecretLimits::default()))
            .transpose()?;

        Ok(Some(mecmcp_audit::ForwardSinkConfig {
            endpoint,
            bearer_token,
            outbox_path,
            ledger_path,
            initial_backoff: std::time::Duration::from_secs(1),
            max_backoff: std::time::Duration::from_secs(60),
        }))
    }
}

/// Why an evidence configuration was refused.
///
/// `#[non_exhaustive]`: the list of ways a pipeline can be misconfigured is
/// exactly the kind that grows, and adding a variant to a public enum breaks
/// any consumer matching it exhaustively -- inside a patch release, where
/// Cargo would apply the update automatically. Marked now, while a check across
/// all five servers shows zero matches on this type, because doing it later is
/// the breaking change it exists to avoid.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvidenceArgsError {
    /// An endpoint was configured without the credential to use it.
    #[error("--ssdf-audit-endpoint requires a password: {flag} was not given")]
    MissingPassword {
        /// The flag that was omitted.
        flag: &'static str,
    },
    /// An endpoint was configured without a spool path.
    #[error(
        "--ssdf-audit-endpoint requires {flag}; every unit runs ProtectSystem=strict \
         with only its own state directory writable, so there is no default that \
         works anywhere"
    )]
    MissingPath {
        /// The flag that was omitted.
        flag: &'static str,
    },
    /// An `https://` endpoint was configured with no trust anchor.
    #[error(
        "--ssdf-audit-endpoint is https, so --ssdf-audit-ca-file is required: SSDF \
         issues the ClickHouse certificate from its own CA, which the public root \
         set cannot validate"
    )]
    MissingTrustAnchor,
    /// An endpoint was configured without a chain identity.
    #[error(
        "--ssdf-audit-endpoint requires --ssdf-audit-server-id; it keys the hash \
         chain, and a value that drifts starts a second root that verifies as a \
         valid chain"
    )]
    MissingServerId,
    /// The chain identity is empty or holds characters that cannot key a chain.
    #[error("--ssdf-audit-server-id is not usable: {0}")]
    InvalidServerId(String),
    /// The endpoint is malformed, or uses `http://` to a non-loopback host.
    #[error("--ssdf-audit-endpoint is not usable: {0}")]
    InvalidEndpoint(String),
    /// A credential file failed its checks — wrong mode, wrong owner, symlink.
    #[error("credential file rejected (must be a regular file, 0600, owned by this user): {0}")]
    Credential(#[from] mecmcp_secret::SecretError),
    /// `--audit-forward-endpoint` was set without `--ssdf-audit-endpoint`.
    #[error(
        "--audit-forward-endpoint requires --ssdf-audit-endpoint: the forward sink ships \
         alongside the SSDF evidence pipeline, not instead of it"
    )]
    ForwardWithoutSsdf,
}

/// Read a password file through the workspace's canonical secret loader.
///
/// Its semantics are the ones that matter here and are easy to get wrong by
/// hand: strip **at most one** trailing newline, reject invalid UTF-8, reject
/// an empty or whitespace-only file. A `trim_end` instead would eat real
/// password bytes when a password legitimately ends in a space, and a lossy
/// UTF-8 conversion would silently substitute replacement characters -- both
/// surfacing later as an authentication failure that looks like a wrong
/// password rather than a mangled one.
fn read_password(
    path: Option<&Path>,
    flag: &'static str,
) -> Result<mecmcp_secret::OutboundSecret, EvidenceArgsError> {
    let path = path.ok_or(EvidenceArgsError::MissingPassword { flag })?;
    let secret = mecmcp_secret::load_from_file(path, mecmcp_secret::SecretLimits::default())?;
    Ok(secret)
}

/// A fresh run identifier for this process lifetime.
///
/// Time-ordered **and** random, because two different invariants apply.
///
/// Delivery identity is `(server_id, run_id, segment_seq)`, so a *repeated* run
/// id makes a new run's segment 0 collide with one already delivered and be
/// skipped as landed -- losing the head of the chain. Clock-plus-pid repeats
/// after a snapshot restore, where the clock rolls back and pid 1 is taken
/// again; the random half rules that out.
///
/// But `SegmentArchive::archive` also requires run ids to be non-decreasing and
/// rejects anything else as `RunIdNotMonotonic` -- so a purely random id fails
/// archival on roughly half of all ordinary restarts. The millisecond prefix,
/// zero-padded so lexicographic order matches chronological order, satisfies
/// that. A clock that rolls backwards still breaks ordering, but it breaks it
/// loudly, as a named error rather than as a silently skipped segment.
fn new_run_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the OS RNG is required for a run id");
    let random: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    // Nanoseconds, zero-padded to 19 digits so lexicographic order is
    // chronological order. Milliseconds were not enough: two ids inside one
    // millisecond share a prefix, and the random suffix then decides their
    // order -- sorting the later one first about half the time. There is no
    // coordination-free way to make this exact across processes, so the
    // resolution is pushed below the time it takes to start one.
    format!("run-{nanos:019}-{random}")
}

/// Reject a non-positive interval at parse time.
fn positive_seconds(raw: &str) -> Result<u64, String> {
    let seconds: u64 = raw.parse().map_err(|_| format!("not a number: {raw}"))?;
    if seconds == 0 {
        return Err("must be at least 1 second; 0 spins the delivery thread".to_owned());
    }
    Ok(seconds)
}

/// Common CLI arguments for MCP servers.
///
/// This struct holds only the flags every vendor needs. Vendor servers
/// should wrap this in their own struct and add vendor-specific fields.
#[derive(Debug, Parser)]
#[command(name = "mecmcp-server")]
pub struct Cli {
    /// Optional management command.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with device mapping.
    #[arg(short = 'f', long, default_value = "devices.json", global = true)]
    pub device_mapping: PathBuf,

    /// MCP transport.
    #[arg(short = 't', long, value_enum, default_value = "stdio")]
    pub transport: Transport,

    /// Bind host (streamable-http only).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (streamable-http only).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,

    /// Bearer-token file. Required for streamable-http unless --allow-no-auth.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// PEM-encoded TLS cert (streamable-http only). Pair with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS key (streamable-http only). Pair with --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer-token auth. Refuses to bind off-loopback.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Additional accepted HTTP Host authority. Repeat for multiple values.
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Accepted browser Origin URL. Repeat for multiple values.
    #[arg(long)]
    pub allowed_origin: Vec<String>,

    /// Audit/log output format: text or json.
    #[arg(long, default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long)]
    pub audit_log_file: Option<PathBuf>,

    /// Also send structured audit events directly to journald.
    #[arg(long)]
    pub audit_journald: bool,

    /// Base OTLP/HTTP endpoint for optional trace export, e.g.
    /// `http://127.0.0.1:4318`. Inert unless set -- off by default, like
    /// every other sink here. `http://` to a loopback IP literal only: this
    /// build does not carry its own TLS stack (decision D4), so a remote
    /// collector is reached through a loopback TLS-terminating proxy, not by
    /// pointing this at `https://` or a non-loopback host directly -- both
    /// are refused at startup, since plaintext OTLP off-loopback puts span
    /// attributes and event bodies on the wire in the clear. Requires
    /// `mecmcp-audit`'s `otel` Cargo feature at build time; set with no
    /// feature enabled, startup fails rather than silently dropping the
    /// export. See `mecmcp_audit::otel`.
    #[arg(long)]
    pub otel_endpoint: Option<String>,

    /// The `service.name` resource attribute for OTel export. Ignored unless
    /// `--otel-endpoint` is set.
    #[arg(long, default_value = "mecmcp")]
    pub otel_service_name: String,

    /// SSDF evidence pipeline. Inert unless `--ssdf-audit-endpoint` is given.
    #[command(flatten)]
    pub evidence: EvidenceArgs,

    /// Per-field audit redaction, e.g. `devices=hmac,host=drop`.
    /// Fields: devices, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long)]
    pub audit_hmac_key_file: Option<PathBuf>,

    /// File containing the HMAC key for the change-set approval digest.
    ///
    /// Path only, like `--audit-hmac-key-file`: this crate does not depend on
    /// `mecmcp-changeset`, so it does not load the key itself. A server that
    /// uses change-set approvals should load this path with
    /// `mecmcp_changeset::ApprovalDigestKey::load_from_file` and pass the
    /// result to `ChangesetCoordinator::load_with_key` (not also to
    /// `with_approval_digest_key` -- `load_with_key` already stores it on the
    /// returned coordinator; passing it to both just risks the two drifting).
    /// Omitted, a deployment keeps signing and accepting the unkeyed v5
    /// approval digest (MEC-457).
    #[arg(long)]
    pub approval_digest_key_file: Option<PathBuf>,
}

/// Top-level management commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the bearer-token store.
    Token {
        /// Token action.
        #[command(subcommand)]
        action: TokenAction,
    },
}

/// Token-store action.
#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// IdP issuer URL this token is bound to, for verified-approver
        /// identity (MEC-994). Required if `--oidc-subject` is set.
        #[arg(long)]
        oidc_issuer: Option<String>,
        /// The IdP's `sub` claim identifying the human this token is bound
        /// to. Required if `--oidc-issuer` is set.
        #[arg(long)]
        oidc_subject: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without touching its secret.
    ///
    /// The alternatives all mint a new secret: `rotate` preserves scopes and
    /// changes the secret — the exact inverse of what is wanted — and
    /// `revoke`+`add` does the same. Hand-editing `tokens.json` keeps the secret
    /// but skips every validation this path performs (#163).
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        ///
        /// Widening is a privilege escalation, so it is confirmed by default.
        /// Narrowing is not: reducing a scope cannot grant anything.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Replace an existing token's provenance without touching its secret.
    ///
    /// A sibling of `set-scopes` rather than four more flags on it: that
    /// command's name would stop being true, and the two changes confirm
    /// different things. `set-scopes` confirms a widening, which is a privilege
    /// escalation; this confirms a clear, which destroys attribution.
    ///
    /// All four fields are replaced on every call, so an omitted flag clears the
    /// field it names. Because that is destructive, a call that would clear a
    /// field currently holding a value is refused unless `--yes` is passed.
    /// Setting or changing a value is never prompted.
    SetProvenance {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Provider name (e.g., "anthropic", "ollama"). Omit to clear.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Omit to clear.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Omit to clear.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Omit to clear.
        ///
        /// Derived as "agent" when a provider is given and this is omitted:
        /// nothing else has an LLM provider.
        #[arg(long)]
        actor_type: Option<String>,
        /// Apply a change that clears a populated field without confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults() {
        let cli = Cli::parse_from(["test-server"]);
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30030);
        assert!(cli.command.is_none());
        assert!(cli.tokens_file.is_none());
        assert!(!cli.allow_no_auth);
        assert!(!cli.allow_insecure_bind);
        assert!(!cli.audit_journald);
        assert_eq!(cli.audit_format, "text");
        assert_eq!(cli.audit_redact, "");
    }

    #[test]
    fn parses_streamable_http() {
        let cli = Cli::parse_from(["test-server", "-t", "streamable-http"]);
        assert_eq!(cli.transport, Transport::StreamableHttp);
    }

    #[test]
    fn parses_short_flags() {
        let cli = Cli::parse_from(["test-server", "-f", "/etc/mcp/devices.json"]);
        assert_eq!(cli.device_mapping, PathBuf::from("/etc/mcp/devices.json"));
    }

    #[test]
    fn parses_token_add_subcommand() {
        let cli = Cli::parse_from([
            "test-server",
            "token",
            "add",
            "--tokens-file",
            "/tmp/t.json",
            "--name",
            "alice",
            "--devices",
            "*",
            "--tools",
            "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }

    #[test]
    fn audit_journald_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["test-server"]);
        assert!(!default_cli.audit_journald);

        let enabled = Cli::parse_from(["test-server", "--audit-journald"]);
        assert!(enabled.audit_journald);
    }

    #[test]
    fn otel_endpoint_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["test-server"]);
        assert!(default_cli.otel_endpoint.is_none());
        assert_eq!(default_cli.otel_service_name, "mecmcp");

        let enabled = Cli::parse_from([
            "test-server",
            "--otel-endpoint",
            "http://127.0.0.1:4318",
            "--otel-service-name",
            "rustjunosmcp",
        ]);
        assert_eq!(
            enabled.otel_endpoint.as_deref(),
            Some("http://127.0.0.1:4318")
        );
        assert_eq!(enabled.otel_service_name, "rustjunosmcp");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod composition_tests {
    use super::*;

    /// Every test here goes through `try_parse_from`, the same code the
    /// binaries run. An earlier version built an equivalent `Command` instead
    /// and a mutation to the real function slipped past it.
    fn parse(args: &[&str]) -> Result<ParsedCli, clap::Error> {
        try_parse_from::<Cli, _, _>("consumer-mcp", "9.9.9", args)
    }

    #[test]
    fn version_reports_the_consumers_identity_not_this_crate() {
        let error = parse(&["consumer-mcp", "--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);

        let rendered = error.to_string();
        assert!(rendered.contains("consumer-mcp"), "got {rendered}");
        assert!(rendered.contains("9.9.9"), "got {rendered}");
        assert!(
            !rendered.contains("mecmcp-server"),
            "the shared default name leaked into the consumer's version: {rendered}"
        );
    }

    /// Before #159 this was clap exit status 2, which breaks the
    /// package-identity smoke test a deployment wants to run.
    #[test]
    fn version_is_not_an_unknown_argument() {
        let error = parse(&["consumer-mcp", "--version"]).unwrap_err();
        assert_ne!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "--version must be understood, not rejected"
        );
    }

    #[test]
    fn help_also_names_the_consumer() {
        let error = parse(&["consumer-mcp", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("consumer-mcp"));
    }

    /// The distinction #162 needs: supplied and defaulted are otherwise
    /// indistinguishable.
    #[test]
    fn supplied_and_defaulted_values_are_distinguishable() {
        let parsed = parse(&["consumer-mcp", "--host", "10.0.0.1"]).unwrap();

        assert!(
            parsed.was_supplied("host"),
            "an explicit --host must read as supplied"
        );
        assert!(
            !parsed.was_supplied("transport"),
            "a defaulted value must not read as supplied"
        );
        assert_eq!(parsed.cli.host, "10.0.0.1");
    }

    /// The case a `value == default` check gets wrong: typing the default.
    #[test]
    fn a_value_equal_to_the_default_still_counts_as_supplied() {
        let parsed = parse(&["consumer-mcp", "--host", "127.0.0.1"]).unwrap();
        assert!(
            parsed.was_supplied("host"),
            "127.0.0.1 is also the default; provenance must not be inferred from the value"
        );
    }

    /// The `ArgGroup` clap's derive creates for the struct must not be reported
    /// as something the operator supplied.
    #[test]
    fn supplied_ids_are_sorted_and_exclude_the_struct_group() {
        let parsed = parse(&["consumer-mcp", "--host", "0.0.0.0", "--port", "9999"]).unwrap();
        assert_eq!(parsed.supplied_ids(), vec!["host", "port"]);
    }

    #[test]
    fn nothing_supplied_means_nothing_reported() {
        let parsed = parse(&["consumer-mcp"]).unwrap();
        assert!(
            parsed.supplied_ids().is_empty(),
            "got {:?}",
            parsed.supplied_ids()
        );
    }

    /// The API's reason for existing, which it could not actually do.
    ///
    /// `approval_timeout_secs` is the flag the doc example names and the one
    /// #162 was raised for, and it is defined by the *server*, not by the shared
    /// type. A parser hard-wired to `Cli` rejected it as unknown, so no consumer
    /// could have implemented the precedence rule this API documents.
    #[test]
    fn a_consumers_own_flag_parses_and_reports_provenance() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[arg(long, default_value_t = 900)]
            approval_timeout_secs: u64,
        }

        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            ["consumer-mcp", "--approval-timeout-secs", "60"],
        )
        .expect("a consumer's own flag must parse");

        assert_eq!(parsed.cli.approval_timeout_secs, 60);
        assert!(
            parsed.was_supplied("approval_timeout_secs"),
            "the vendor flag must report as supplied"
        );
        // The shared arguments still work through the flattened struct.
        assert_eq!(parsed.cli.shared.host, "127.0.0.1");
        assert!(!parsed.was_supplied("host"));
    }

    /// Clap stores a subcommand's own arguments in a child `ArgMatches`, so a
    /// walk of the root alone reported nothing for them.
    #[test]
    fn subcommand_arguments_are_collected_with_their_path() {
        let parsed = parse(&[
            "consumer-mcp",
            "token",
            "add",
            "--tokens-file",
            "/etc/t.json",
            "--name",
            "writer",
            "--devices",
            "*",
            "--tools",
            "*",
        ])
        .unwrap();

        assert!(
            parsed.was_supplied_in(&["token", "add"], "tokens_file"),
            "supplied {:?}",
            parsed.supplied_arguments()
        );
        assert!(parsed.was_supplied_in(&["token", "add"], "name"));
    }

    /// The reason subcommand provenance carries a path rather than joining one
    /// flat set: `tokens_file` names both a server flag and an argument of
    /// `token add`, and a server asking about its own flag must not be told
    /// "yes" because the operator typed the other one.
    #[test]
    fn a_subcommand_argument_does_not_answer_for_the_top_level_flag_of_the_same_name() {
        let parsed = parse(&[
            "consumer-mcp",
            "token",
            "add",
            "--tokens-file",
            "/etc/t.json",
            "--name",
            "writer",
            "--devices",
            "*",
            "--tools",
            "*",
        ])
        .unwrap();

        assert!(parsed.was_supplied_in(&["token", "add"], "tokens_file"));
        assert!(
            !parsed.was_supplied("tokens_file"),
            "the server's own --tokens-file was never typed"
        );
        assert!(
            !parsed.supplied_ids().contains(&"tokens_file"),
            "top-level ids must stay top-level: {:?}",
            parsed.supplied_ids()
        );
    }

    /// A global typed once, before the subcommand, is supplied once. Clap
    /// propagates globals into every descendant's matches, so counting them at
    /// each level would invent supplies the operator never made.
    #[test]
    fn a_global_is_reported_once_at_the_level_it_was_typed() {
        let parsed = parse(&[
            "consumer-mcp",
            "--device-mapping",
            "/etc/devices.json",
            "token",
            "list",
            "--tokens-file",
            "/etc/t.json",
        ])
        .unwrap();

        assert!(parsed.was_supplied("device_mapping"));
        let mappings: Vec<_> = parsed
            .supplied_arguments()
            .iter()
            .filter(|argument| argument.id == "device_mapping")
            .collect();
        assert_eq!(
            mappings.len(),
            1,
            "a global typed once must be reported once: {mappings:?}"
        );
    }

    #[test]
    fn web_approver_args_defaults_to_false() {
        let args = WebApproverArgs::default();
        assert!(!args.web_enabled_approver);
    }

    #[test]
    fn web_approver_args_parses_flag() {
        #[derive(Debug, Parser)]
        struct TestCli {
            #[command(flatten)]
            approver: WebApproverArgs,
        }

        let cli = TestCli::parse_from(["test", "--web-enabled-approver"]);
        assert!(cli.approver.web_enabled_approver);
    }

    #[test]
    fn web_approver_args_flattens_without_conflict() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[command(flatten)]
            approver: WebApproverArgs,
            #[arg(long, default_value_t = 900)]
            approval_timeout_secs: u64,
        }

        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            [
                "consumer-mcp",
                "--web-enabled-approver",
                "--approval-timeout-secs",
                "60",
            ],
        )
        .expect("WebApproverArgs must flatten without conflict");

        assert!(parsed.cli.approver.web_enabled_approver);
        assert_eq!(parsed.cli.approval_timeout_secs, 60);
        assert!(parsed.was_supplied("web_enabled_approver"));
        assert!(parsed.was_supplied("approval_timeout_secs"));
    }

    #[test]
    fn verified_approver_args_default_to_off() {
        let args = VerifiedApproverArgs::default();
        assert!(args.oidc_issuer.is_none());
        assert!(!args.require_verified_approver);
        assert!(args.approver_policy().is_none());
    }

    /// A server opts into `VerifiedApproverArgs` by flattening it alongside
    /// `Cli`, exactly like `WebApproverArgs` — it is not part of `Cli` itself
    /// (MEC-994 Percy review F1).
    #[derive(Debug, Parser)]
    struct VerifiedApproverTestCli {
        #[command(flatten)]
        shared: Cli,
        #[command(flatten)]
        verified_approver: VerifiedApproverArgs,
    }

    #[test]
    fn verified_approver_args_no_issuer_means_no_policy_regardless_of_other_flags() {
        let cli = VerifiedApproverTestCli::parse_from([
            "test",
            "--approver-role",
            "security-approver",
            "--approver-max-age-secs",
            "60",
            "--approver-require-auth-time",
        ]);
        assert!(
            cli.verified_approver.approver_policy().is_none(),
            "absent --oidc-issuer, a server has no OIDC support at all"
        );
    }

    #[test]
    fn verified_approver_args_build_policy_when_issuer_is_set() {
        let cli = VerifiedApproverTestCli::parse_from([
            "test",
            "--oidc-issuer",
            "https://idp.example",
            "--oidc-audience",
            "mecmcp",
            "--approver-role",
            "security-approver",
            "--approver-max-age-secs",
            "60",
            "--approver-require-auth-time",
        ]);
        let policy = cli
            .verified_approver
            .approver_policy()
            .expect("issuer configured");
        assert_eq!(policy.approver_role, "security-approver");
        assert_eq!(policy.max_age, std::time::Duration::from_secs(60));
        assert!(policy.require_auth_time);
        assert_eq!(
            cli.verified_approver.oidc_audience.as_deref(),
            Some("mecmcp")
        );
    }

    #[test]
    fn verified_approver_args_defaults() {
        let cli = VerifiedApproverTestCli::parse_from(["test"]);
        assert_eq!(cli.verified_approver.oidc_role_claim, "roles");
        assert_eq!(cli.verified_approver.approver_role, "approver");
        assert_eq!(cli.verified_approver.approver_max_age_secs, 300);
        assert!(!cli.verified_approver.approver_require_auth_time);
        assert!(!cli.verified_approver.require_verified_approver);
    }

    #[test]
    fn verified_approver_args_flattens_without_conflict() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[command(flatten)]
            verified_approver: VerifiedApproverArgs,
            #[arg(long, default_value_t = 900)]
            approval_timeout_secs: u64,
        }

        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            [
                "consumer-mcp",
                "--oidc-issuer",
                "https://idp.example",
                "--oidc-audience",
                "mecmcp",
                "--require-verified-approver",
            ],
        )
        .expect("VerifiedApproverArgs must flatten without conflict");

        assert_eq!(
            parsed.cli.verified_approver.oidc_issuer.as_deref(),
            Some("https://idp.example")
        );
        assert!(parsed.cli.verified_approver.require_verified_approver);
    }

    #[test]
    fn verified_approver_args_validate_requires_issuer_for_strict_mode() {
        let args = VerifiedApproverArgs {
            require_verified_approver: true,
            ..Default::default()
        };
        assert_eq!(
            args.validate(true, false),
            Err(VerifiedApproverArgsError::RequiresIssuer)
        );
    }

    #[test]
    fn verified_approver_args_validate_requires_digest_key_for_strict_mode() {
        let args = VerifiedApproverArgs {
            oidc_issuer: Some("https://idp.example".to_owned()),
            oidc_audience: Some("mecmcp".to_owned()),
            require_verified_approver: true,
            ..Default::default()
        };
        assert_eq!(
            args.validate(false, false),
            Err(VerifiedApproverArgsError::RequiresDigestKey)
        );
    }

    #[test]
    fn verified_approver_args_validate_refuses_lab_mode_in_strict_mode() {
        let args = VerifiedApproverArgs {
            oidc_issuer: Some("https://idp.example".to_owned()),
            oidc_audience: Some("mecmcp".to_owned()),
            require_verified_approver: true,
            ..Default::default()
        };
        assert_eq!(
            args.validate(true, true),
            Err(VerifiedApproverArgsError::IncompatibleWithLabMode)
        );
    }

    #[test]
    fn verified_approver_args_validate_requires_audience_with_issuer() {
        let args = VerifiedApproverArgs {
            oidc_issuer: Some("https://idp.example".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            args.validate(true, false),
            Err(VerifiedApproverArgsError::IssuerWithoutAudience)
        );
    }

    #[test]
    fn verified_approver_args_validate_ok_with_issuer_audience_and_digest_key() {
        let args = VerifiedApproverArgs {
            oidc_issuer: Some("https://idp.example".to_owned()),
            oidc_audience: Some("mecmcp".to_owned()),
            require_verified_approver: true,
            ..Default::default()
        };
        assert!(args.validate(true, false).is_ok());
    }

    #[test]
    fn verified_approver_args_validate_ok_with_no_flags_at_all() {
        assert!(
            VerifiedApproverArgs::default()
                .validate(false, false)
                .is_ok()
        );
    }
}
