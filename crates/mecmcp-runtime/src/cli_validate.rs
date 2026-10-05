//! Validates the parsed CLI args against the design's refusal matrix.
//!
//! # This is a courtesy pre-check, not the control
//!
//! Since mecmcp#273 the listener admission checks live in
//! `mecmcp_transport::serve_router`, which every consumer must call to obtain a
//! socket. Calling `validate` first is still worth doing — it fails a bad CLI
//! before anything is constructed, and its messages name the flags rather than
//! the transport concepts — but skipping it now costs a startup refusal instead
//! of an open port. Do not reintroduce the assumption that calling this is what
//! makes a deployment safe.
//!
//! # Rule coverage
//!
//! This module validates every rule that can be expressed purely in terms of
//! fields already on the shared [`Cli`]: `AuthConflict`, `NonNumericHost`, and
//! `InvalidAllowedHost`/`InvalidAllowedOrigin` (see each variant's doc comment
//! for the specific case each one closes). Extending coverage further is a
//! separate, larger scope decision tracked outside this module.

use crate::cli::{Cli, Transport};
use std::net::IpAddr;

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum CliRefusal {
    /// Remote transport needs authentication.
    #[error("--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)")]
    AuthRequired,
    /// Auth may not be both configured and disabled.
    #[error("--tokens-file and --allow-no-auth are mutually exclusive")]
    AuthConflict,
    /// No-auth listeners are loopback-only.
    #[error("--allow-no-auth refuses to bind off-loopback (host '{host}' is not 127.0.0.1 or ::1)")]
    NoAuthOffLoopback {
        /// Refused bind value.
        host: String,
    },
    /// Off-loopback plaintext is an explicit proxy-only exception.
    #[error(
        "non-loopback bind '{host}' over plain HTTP requires --allow-insecure-bind (or supply --tls-cert/--tls-key)"
    )]
    InsecureBindRequired {
        /// Refused bind value.
        host: String,
    },
    /// An off-loopback listener was given no accepted Host authority.
    ///
    /// Fail-closed on purpose. An empty allowlist is not "allow everything the
    /// operator forgot to name" — on a remote listener it is a DNS-rebinding
    /// and Host-confusion surface that nobody chose.
    #[error(
        "non-loopback bind '{host}' requires at least one --allowed-host (the accepted HTTP Host authority, e.g. server.example.org:8443)"
    )]
    AllowedHostRequired {
        /// Refused bind value.
        host: String,
    },
    /// An off-loopback listener was given no accepted browser Origin.
    ///
    /// An empty Origin list disables browser-origin policy entirely, which is
    /// the check that stops a page the operator has never heard of driving this
    /// server through a victim's browser.
    #[error(
        "non-loopback bind '{host}' requires at least one --allowed-origin (the accepted browser Origin, e.g. https://server.example.org:8443)"
    )]
    AllowedOriginRequired {
        /// Refused bind value.
        host: String,
    },
    /// Certificate and key form one atomic setting.
    #[error("--tls-cert and --tls-key must be set together (got cert={cert}, key={key})")]
    TlsPairIncomplete {
        /// Whether cert was set.
        cert: bool,
        /// Whether key was set.
        key: bool,
    },
    /// Bind address must not involve DNS resolution.
    ///
    /// `--host` ultimately feeds a `SocketAddr`, which a hostname never
    /// parses into — the bind fails downstream with an opaque error instead.
    /// This gives the same outcome a clear, named cause before anything else
    /// is constructed.
    #[error("--host must be a numeric IPv4 or IPv6 address, got '{host}'")]
    NonNumericHost {
        /// Refused bind value.
        host: String,
    },
    /// One Host allowlist entry is not a usable authority.
    ///
    /// An entry that does not parse as an authority never matches the Host
    /// header comparison in `mecmcp_transport::server`, so it is not a
    /// weaker policy than a well-formed one — it is silently inert. Refusing
    /// it at startup turns a policy the operator believes exists but does
    /// not into a startup error instead of a runtime no-op.
    #[error("invalid --allowed-host authority '{value}'")]
    InvalidAllowedHost {
        /// Refused value.
        value: String,
    },
    /// One Origin allowlist entry is not a usable HTTP(S) origin.
    ///
    /// Same reasoning as `InvalidAllowedHost`: an entry that does not parse
    /// never matches in `origin_is_allowed_exact`, so it is a silently inert
    /// policy entry rather than a weaker one.
    #[error("invalid --allowed-origin URL '{value}'")]
    InvalidAllowedOrigin {
        /// Refused value.
        value: String,
    },
}

/// Validate `cli` and, on refusal, print the operator-facing message and
/// exit the process with status 1.
///
/// Call this instead of handling [`validate`]'s `Result` yourself. Two of six
/// consumers drifted from the shared refusal text (mecmcp#358): one forked
/// this module and propagated the error with `?`, which surfaced the bare
/// enum variant name instead of its message; the other never called shared
/// validation at all, so its refusal came from a downstream bind failure
/// with the real cause swallowed. Routing every consumer through this single
/// function makes both mistakes structurally unreachable — there is no
/// `Result` left for a consumer's own formatting (or lack of a call) to get
/// wrong.
///
/// Must run before inventory, secrets, sockets, or TLS load, same as
/// [`validate`] — see that function's doc for why.
pub fn validate_or_exit(cli: &Cli) {
    if let Err(refusal) = validate(cli) {
        eprintln!("Error: {refusal}");
        std::process::exit(1);
    }
}

/// Validate all serve arguments before inventory, secrets, sockets, or TLS load.
///
/// This function validates the common CLI arguments that apply to all vendors.
/// Vendor-specific validation should be performed separately.
///
/// An off-loopback listener must supply both `--allowed-host` and
/// `--allowed-origin`. Since 0.7.0 the shared transport applies Origin policy
/// for every consumer, so the weaker check that accepted a listener with no
/// Origin allowlist is itself an instance of the defect class in mecmcp#273.
pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    // Stdio needs no transport validation.
    if cli.transport == Transport::Stdio {
        return Ok(());
    }

    // TLS pair must be complete or absent.
    let tls_configured = match (cli.tls_cert.is_some(), cli.tls_key.is_some()) {
        (true, true) => true,
        (false, false) => false,
        (cert, key) => return Err(CliRefusal::TlsPairIncomplete { cert, key }),
    };

    // The bind address must be a literal IP: it feeds a `SocketAddr` with no
    // DNS resolution step, so a hostname never reaches a socket either way.
    // Refusing it here names the cause instead of letting it surface as an
    // opaque parse error after everything else has already loaded.
    let host_ip: IpAddr = cli.host.parse().map_err(|_| CliRefusal::NonNumericHost {
        host: cli.host.clone(),
    })?;
    let host_is_loopback = host_ip.is_loopback();

    // Auth requirement. `--tokens-file` and `--allow-no-auth` are mutually
    // exclusive, not a precedence rule — every consumer currently builds its
    // token store with `tokens_file` taking priority and `allow_no_auth`
    // silently dropped, which lets an operator believe no-auth is in effect
    // when auth is actually enforced (or vice versa, depending on which flag
    // they meant). Refusing the combination surfaces the mistake instead of
    // guessing which flag the operator meant.
    if cli.tokens_file.is_some() && cli.allow_no_auth {
        return Err(CliRefusal::AuthConflict);
    }
    if cli.tokens_file.is_none() && !cli.allow_no_auth {
        return Err(CliRefusal::AuthRequired);
    }
    if cli.tokens_file.is_none() && cli.allow_no_auth && !host_is_loopback {
        return Err(CliRefusal::NoAuthOffLoopback {
            host: cli.host.clone(),
        });
    }

    // Insecure-bind requirement.
    if !host_is_loopback && !tls_configured && !cli.allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired {
            host: cli.host.clone(),
        });
    }

    // Off-loopback listeners must name what they accept.
    //
    // This path previously ignored both allowlists entirely, so an
    // authenticated TLS listener — or an explicitly insecure remote one —
    // passed shared validation with neither set (#157). That is fail-open: the
    // absence of a policy read as permission, in the one place where the
    // listener is reachable by something other than the machine it runs on.
    //
    // Loopback is deliberately exempt. A listener on 127.0.0.1 is already
    // bounded by the host, and requiring the flags there would break every
    // stdio and local-HTTP deployment for no gain.
    if !host_is_loopback && !has_usable_entry(&cli.allowed_host) {
        return Err(CliRefusal::AllowedHostRequired {
            host: cli.host.clone(),
        });
    }

    if !host_is_loopback && !has_usable_entry(&cli.allowed_origin) {
        return Err(CliRefusal::AllowedOriginRequired {
            host: cli.host.clone(),
        });
    }

    // Every entry must actually be able to match something. An entry that
    // fails to parse here also fails to parse in the runtime comparison
    // (`mecmcp_transport::server::normalize_host_authority` /
    // `parse_and_normalize_origin`), so it was never a weaker policy — it was
    // a policy entry that silently matched nothing.
    for value in &cli.allowed_host {
        validate_allowed_host(value)?;
    }
    for value in &cli.allowed_origin {
        validate_allowed_origin(value)?;
    }

    Ok(())
}

/// Whether one `--allowed-host` entry could ever match a Host header.
///
/// Is at least as strict as the parse
/// `mecmcp_transport::server::normalize_host_authority` performs at request
/// time, so a value this rejects is a value that server would also silently
/// never match.
fn validate_allowed_host(value: &str) -> Result<(), CliRefusal> {
    let usable =
        value.len() <= 255 && !value.contains('@') && http::uri::Authority::try_from(value).is_ok();
    if usable {
        Ok(())
    } else {
        Err(CliRefusal::InvalidAllowedHost {
            value: value.to_owned(),
        })
    }
}

/// Whether one `--allowed-origin` entry could ever match a browser Origin.
///
/// Is at least as strict as the parse
/// `mecmcp_transport::server::parse_and_normalize_origin` performs at request
/// time: requires a scheme of `http`/`https`, an authority with no userinfo,
/// and no query or non-root path (an Origin header carries neither), and also
/// refuses the opaque `null` origin outright (the transport never treats any
/// allowlist entry as matching it — see `mecmcp-transport/src/server.rs`).
fn validate_allowed_origin(value: &str) -> Result<(), CliRefusal> {
    let valid = value.len() <= 2048
        && value
            .parse::<http::Uri>()
            .ok()
            .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")))
            .filter(|uri| {
                uri.authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
            })
            .is_some_and(|uri| {
                uri.query().is_none() && (uri.path().is_empty() || uri.path() == "/")
            });
    if valid {
        Ok(())
    } else {
        Err(CliRefusal::InvalidAllowedOrigin {
            value: value.to_owned(),
        })
    }
}

/// Whether an allowlist carries at least one value that could match anything.
///
/// A vector holding only empty strings is not a policy. `--allowed-host ""`
/// parses into a non-empty `Vec`, so a bare `is_empty()` check would accept it
/// and reintroduce exactly the gap this closes.
fn has_usable_entry(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

/// Shared fixtures for pinning a consumer's *actual process* stderr against
/// the refusal messages this module promises, instead of each repo hand-
/// copying the expected text into its own integration test — hand copies
/// are exactly how rustpanosmcp's fork and the five other consumers ended up
/// disagreeing in the first place (mecmcp#358).
///
/// A consumer's own integration test should spawn its real binary once per
/// fixture and assert its stderr equals [`expected_stderr`] of the paired
/// [`CliRefusal`]:
///
/// ```ignore
/// # use std::process::Command;
/// for (args, refusal) in mecmcp_runtime::cli_validate::testing::refusal_fixtures() {
///     let output = Command::new(env!("CARGO_BIN_EXE_my-server"))
///         .args(&args)
///         .output()
///         .expect("spawn");
///     assert_eq!(
///         String::from_utf8_lossy(&output.stderr).trim_end(),
///         mecmcp_runtime::cli_validate::testing::expected_stderr(&refusal),
///     );
/// }
/// ```
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use super::CliRefusal;

    /// The exact stderr line a conformant consumer must print for `refusal`.
    ///
    /// This is what [`super::validate_or_exit`] prints. A consumer that does
    /// not call `validate_or_exit` directly (for example because it needs to
    /// run vendor-specific validation first) must still reproduce this
    /// exactly — `format!("Error: {refusal}")`, nothing added or reformatted.
    #[must_use]
    pub fn expected_stderr(refusal: &CliRefusal) -> String {
        format!("Error: {refusal}")
    }

    /// One minimal CLI argument set per [`CliRefusal`] variant, paired with
    /// the refusal it produces under [`super::validate`].
    ///
    /// Covers every variant that exists today; extend this alongside the
    /// enum so a new refusal is pinned from the start rather than left to
    /// drift the way the original ten did.
    #[must_use]
    pub fn refusal_fixtures() -> Vec<(Vec<&'static str>, CliRefusal)> {
        vec![
            (vec!["-t", "streamable-http"], CliRefusal::AuthRequired),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "--allow-no-auth",
                ],
                CliRefusal::AuthConflict,
            ),
            (
                vec!["-t", "streamable-http", "--allow-no-auth", "-H", "0.0.0.0"],
                CliRefusal::NoAuthOffLoopback {
                    host: "0.0.0.0".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "0.0.0.0",
                ],
                CliRefusal::InsecureBindRequired {
                    host: "0.0.0.0".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                ],
                CliRefusal::AllowedHostRequired {
                    host: "0.0.0.0".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                    "--allowed-host",
                    "server.example.org:8443",
                ],
                CliRefusal::AllowedOriginRequired {
                    host: "0.0.0.0".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "--tls-cert",
                    "/tmp/c.pem",
                ],
                CliRefusal::TlsPairIncomplete {
                    cert: true,
                    key: false,
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "server.example.org",
                    "--allow-insecure-bind",
                ],
                CliRefusal::NonNumericHost {
                    host: "server.example.org".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                    "--allowed-host",
                    "not a host!",
                    "--allowed-origin",
                    "https://server.example.org:8443",
                ],
                CliRefusal::InvalidAllowedHost {
                    value: "not a host!".to_owned(),
                },
            ),
            (
                vec![
                    "-t",
                    "streamable-http",
                    "--tokens-file",
                    "/tmp/t.json",
                    "-H",
                    "0.0.0.0",
                    "--allow-insecure-bind",
                    "--allowed-host",
                    "server.example.org:8443",
                    "--allowed-origin",
                    "not a url",
                ],
                CliRefusal::InvalidAllowedOrigin {
                    value: "not a url".to_owned(),
                },
            ),
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::super::validate;
        use super::*;
        use crate::cli::Cli;
        use clap::Parser;

        fn parse(args: &[&str]) -> Cli {
            Cli::parse_from(std::iter::once("test-server").chain(args.iter().copied()))
        }

        /// Every fixture must actually reproduce the refusal it claims to,
        /// against the real `validate`. If this drifts, the fixture is
        /// wrong, not the rule it was meant to pin.
        #[test]
        fn every_fixture_reproduces_its_claimed_refusal() {
            for (args, refusal) in refusal_fixtures() {
                let got = validate(&parse(&args));
                assert_eq!(
                    got,
                    Err(refusal.clone()),
                    "fixture {args:?} did not reproduce its claimed refusal"
                );
            }
        }

        /// One variant per enum member, exact byte match. This is the test
        /// that would have caught rustpanosmcp's fork: a bare `?`
        /// propagation of a type without this exact `Display` text prints
        /// something other than what is asserted here.
        #[test]
        fn expected_stderr_is_exactly_error_colon_space_display() {
            assert_eq!(
                expected_stderr(&CliRefusal::AuthRequired),
                "Error: --transport streamable-http requires --tokens-file \
                 (or --allow-no-auth on loopback)"
            );
            assert_eq!(
                expected_stderr(&CliRefusal::AllowedOriginRequired {
                    host: "0.0.0.0".to_owned()
                }),
                "Error: non-loopback bind '0.0.0.0' requires at least one \
                 --allowed-origin (the accepted browser Origin, e.g. \
                 https://server.example.org:8443)"
            );
        }

        /// All ten variants that exist today are covered. A new variant
        /// added without a matching fixture is a silent gap in the shared
        /// contract this module exists to pin (mecmcp#358 point 3).
        #[test]
        fn fixtures_cover_every_known_variant() {
            use std::collections::BTreeSet;
            let covered: BTreeSet<&'static str> = refusal_fixtures()
                .iter()
                .map(|(_, r)| variant_name(r))
                .collect();
            let all = [
                "AuthRequired",
                "AuthConflict",
                "NoAuthOffLoopback",
                "InsecureBindRequired",
                "AllowedHostRequired",
                "AllowedOriginRequired",
                "TlsPairIncomplete",
                "NonNumericHost",
                "InvalidAllowedHost",
                "InvalidAllowedOrigin",
            ];
            for variant in all {
                assert!(
                    covered.contains(variant),
                    "fixtures missing a case for {variant}"
                );
            }
            assert_eq!(
                covered.len(),
                all.len(),
                "fixtures cover an unlisted variant too"
            );
        }

        fn variant_name(r: &CliRefusal) -> &'static str {
            match r {
                CliRefusal::AuthRequired => "AuthRequired",
                CliRefusal::AuthConflict => "AuthConflict",
                CliRefusal::NoAuthOffLoopback { .. } => "NoAuthOffLoopback",
                CliRefusal::InsecureBindRequired { .. } => "InsecureBindRequired",
                CliRefusal::AllowedHostRequired { .. } => "AllowedHostRequired",
                CliRefusal::AllowedOriginRequired { .. } => "AllowedOriginRequired",
                CliRefusal::TlsPairIncomplete { .. } => "TlsPairIncomplete",
                CliRefusal::NonNumericHost { .. } => "NonNumericHost",
                CliRefusal::InvalidAllowedHost { .. } => "InvalidAllowedHost",
                CliRefusal::InvalidAllowedOrigin { .. } => "InvalidAllowedOrigin",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("test-server").chain(args.iter().copied()))
    }

    #[test]
    fn stdio_always_ok() {
        assert!(validate(&parse(&[])).is_ok());
        assert!(validate(&parse(&["-t", "stdio", "-H", "10.0.0.1"])).is_ok());
    }

    #[test]
    fn http_requires_tokens_file() {
        let r = validate(&parse(&["-t", "streamable-http"]));
        assert_eq!(r, Err(CliRefusal::AuthRequired));
    }

    #[test]
    fn http_no_auth_loopback_ok() {
        let r = validate(&parse(&["-t", "streamable-http", "--allow-no-auth"]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_no_auth_off_loopback_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--allow-no-auth",
            "-H",
            "0.0.0.0",
        ]));
        assert!(matches!(r, Err(CliRefusal::NoAuthOffLoopback { .. })));
    }

    #[test]
    fn http_with_tokens_loopback_ok() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_off_loopback_plain_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
        ]));
        assert!(matches!(r, Err(CliRefusal::InsecureBindRequired { .. })));
    }

    /// Both of these used to assert that an off-loopback listener with **no**
    /// allowlists is fine. That was the fail-open gap in #157, encoded as a
    /// passing test, so they now carry the flags a remote listener must have.
    #[test]
    fn http_off_loopback_insecure_bind_ok_with_allowlists() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "server.example.org:8443",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(r.is_ok(), "got {r:?}");
    }

    #[test]
    fn http_off_loopback_tls_ok_with_allowlists() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--tls-cert",
            "/tmp/c.pem",
            "--tls-key",
            "/tmp/k.pem",
            "--allowed-host",
            "server.example.org:8443",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(r.is_ok(), "got {r:?}");
    }

    /// The refusals themselves, for both remote shapes named in #157.
    #[test]
    fn off_loopback_without_allowed_host_is_refused() {
        for extra in [
            vec!["--allow-insecure-bind"],
            vec!["--tls-cert", "/tmp/c.pem", "--tls-key", "/tmp/k.pem"],
        ] {
            let mut args = vec![
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                "0.0.0.0",
            ];
            args.extend(extra.iter());
            args.extend(["--allowed-origin", "https://server.example.org:8443"]);

            let r = validate(&parse(&args));
            assert!(
                matches!(r, Err(CliRefusal::AllowedHostRequired { .. })),
                "expected a Host refusal for {extra:?}, got {r:?}"
            );
        }
    }

    /// The Origin requirement is now unconditional.
    ///
    /// Before mecmcp#273 `validate` did NOT refuse a missing Origin: LXC 609 ran
    /// off-loopback with `--allowed-host` and no `--allowed-origin`, and its
    /// transport did not apply Origin policy. Since 0.7.0 the shared transport
    /// applies Origin policy for every consumer, so the weaker check is itself
    /// an instance of the defect class in mecmcp#273.
    #[test]
    fn plain_validate_now_requires_an_origin() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "192.0.2.10",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::AllowedOriginRequired { .. })),
            "got {r:?}"
        );
    }

    /// The Host requirement is unconditional — every transport applies it.
    #[test]
    fn plain_validate_still_requires_a_host() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::AllowedHostRequired { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn origin_policy_path_still_requires_a_host() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::AllowedHostRequired { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn origin_policy_path_is_satisfied_when_both_are_supplied() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "server.example.org:8443",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn origin_policy_path_exempts_loopback_and_stdio() {
        assert!(validate(&parse(&["-t", "stdio"])).is_ok());
        for host in ["127.0.0.1", "::1"] {
            let r = validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                host,
            ]));
            assert!(r.is_ok(), "loopback {host} refused: {r:?}");
        }
    }

    #[test]
    fn off_loopback_without_allowed_origin_is_refused() {
        for extra in [
            vec!["--allow-insecure-bind"],
            vec!["--tls-cert", "/tmp/c.pem", "--tls-key", "/tmp/k.pem"],
        ] {
            let mut args = vec![
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                "0.0.0.0",
            ];
            args.extend(extra.iter());
            args.extend(["--allowed-host", "server.example.org:8443"]);

            let r = validate(&parse(&args));
            assert!(
                matches!(r, Err(CliRefusal::AllowedOriginRequired { .. })),
                "expected an Origin refusal for {extra:?}, got {r:?}"
            );
        }
    }

    /// An allowlist of empty strings is not a policy.
    ///
    /// `--allowed-host ""` parses into a non-empty `Vec`, so an `is_empty()`
    /// check would accept it and leave the gap open.
    #[test]
    fn an_allowlist_of_blanks_is_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "   ",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::AllowedHostRequired { .. })),
            "got {r:?}"
        );
    }

    /// A hostname bind is treated as remote, so it needs the flags too.
    #[test]
    fn a_hostname_bind_is_refused_as_non_numeric() {
        // `--host` feeds a `SocketAddr` with no DNS step, so a hostname never
        // reaches a bind either way. It is refused here, before the
        // allowlist checks, with a cause the opaque downstream parse error
        // would not have named.
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "server.example.org",
            "--allow-insecure-bind",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::NonNumericHost { .. })),
            "got {r:?}"
        );
    }

    /// Loopback stays exempt — requiring the flags there would break every
    /// local deployment for no gain.
    #[test]
    fn loopback_needs_no_allowlists() {
        for host in ["127.0.0.1", "::1"] {
            let r = validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                host,
            ]));
            assert!(r.is_ok(), "loopback {host} was refused: {r:?}");
        }
    }

    /// Stdio is unaffected regardless of allowlists.
    #[test]
    fn stdio_needs_no_allowlists() {
        assert!(validate(&parse(&["-t", "stdio"])).is_ok());
    }

    #[test]
    fn tls_pair_incomplete_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "--tls-cert",
            "/tmp/c.pem",
        ]));
        assert!(matches!(r, Err(CliRefusal::TlsPairIncomplete { .. })));
    }

    #[test]
    fn ipv6_loopback_recognized() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "::1",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn validate_requires_an_origin_allowlist_off_loopback() {
        let cli = Cli::try_parse_from([
            "test",
            "--transport",
            "streamable-http",
            "--host",
            "192.168.1.5",
            "--tokens-file",
            "/tmp/tokens.json",
            "--allow-insecure-bind",
            "--allowed-host",
            "192.168.1.5",
        ])
        .expect("parse");

        assert!(
            matches!(
                validate(&cli),
                Err(CliRefusal::AllowedOriginRequired { .. })
            ),
            "since 0.7.0 the shared transport applies Origin policy for every \
             consumer, so the weaker check is itself the defect class in mecmcp#273"
        );
    }

    // `--require-verified-approver` and friends (MEC-994 W5) are no longer
    // flags on the shared `Cli` at all (see `VerifiedApproverArgs`'s doc
    // comment for why), so their cross-checks live and are tested on
    // `VerifiedApproverArgs::validate` in `cli.rs`, not here.

    /// `--tokens-file` and `--allow-no-auth` together used to pass shared
    /// validation, with every consumer's own main.rs silently preferring
    /// `tokens_file` and dropping `allow_no_auth` (mecmcp#358). Promoted from
    /// rustpanosmcp's fork, which refused this from the start.
    #[test]
    fn tokens_file_and_allow_no_auth_together_is_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "--allow-no-auth",
        ]));
        assert_eq!(r, Err(CliRefusal::AuthConflict));
    }

    /// A numeric loopback address is unaffected by the new `--host` check.
    #[test]
    fn numeric_loopback_host_is_not_a_non_numeric_refusal() {
        assert!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                "127.0.0.1",
            ]))
            .is_ok()
        );
    }

    /// Promoted from rustpanosmcp's fork (mecmcp#358): an allowlist entry
    /// that cannot parse never matches anything at the Host/Origin
    /// comparison in `mecmcp_transport::server`, so accepting it here was a
    /// policy that silently did nothing.
    #[test]
    fn a_malformed_allowed_host_entry_is_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "not a host!",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::InvalidAllowedHost { .. })),
            "got {r:?}"
        );
    }

    #[test]
    fn a_malformed_allowed_origin_entry_is_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "server.example.org:8443",
            "--allowed-origin",
            "not a url",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::InvalidAllowedOrigin { .. })),
            "got {r:?}"
        );
    }

    #[test]
    fn an_allowed_origin_with_a_path_or_query_is_refused() {
        for bad in [
            "https://server.example.org/some/path",
            "https://server.example.org?x=1",
        ] {
            let r = validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                "0.0.0.0",
                "--allow-insecure-bind",
                "--allowed-host",
                "server.example.org",
                "--allowed-origin",
                bad,
            ]));
            assert!(
                matches!(r, Err(CliRefusal::InvalidAllowedOrigin { .. })),
                "expected a refusal for {bad}, got {r:?}"
            );
        }
    }

    #[test]
    fn the_opaque_null_origin_is_refused() {
        // The transport never matches "null" against any allowlist entry (see
        // mecmcp-transport/src/server.rs), so the allowlist must not accept it either.
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "server.example.org",
            "--allowed-origin",
            "null",
        ]));
        assert!(
            matches!(r, Err(CliRefusal::InvalidAllowedOrigin { .. })),
            "got {r:?}"
        );
    }

    #[test]
    fn well_formed_allowlists_still_pass() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
            "--allowed-host",
            "server.example.org:8443",
            "--allowed-origin",
            "https://server.example.org:8443",
        ]));
        assert!(r.is_ok(), "got {r:?}");
    }
}
