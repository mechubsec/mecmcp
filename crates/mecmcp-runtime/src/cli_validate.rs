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
//! # Convergence with rustpanosmcp's fork (mecmcp#358)
//!
//! rustpanosmcp carries its own copy of this module with six extra rules this
//! one lacked: `AuthConflict`, `NonNumericHost`, `InvalidAllowedHost`/
//! `InvalidAllowedOrigin`, `AbsolutePathRequired`, and bounded `BodyLimit`/
//! `RateLimit` settings. This revision promotes the first four — they read
//! only fields already on the shared [`Cli`] and tighten behaviour that was
//! already inert or already a silent footgun on every consumer, not just
//! panos (see each variant's doc comment for the specific case).
//!
//! `AbsolutePathRequired` and the rate/body-limit rules are deliberately
//! **not** promoted here:
//! - `AbsolutePathRequired` would refuse a relative `--tokens-file`/
//!   `--tls-cert`/`--tls-key` that currently starts successfully on the other
//!   five consumers, which is a compatibility break, not a tightening.
//! - `BodyLimit`/`RateLimit` validate CLI fields (`request_body_limit`,
//!   `*_rate_per_minute`) that only exist on rustpanosmcp's own `Cli` — there
//!   is nothing to validate upstream without first adding those flags to the
//!   shared surface, which is a CLI-surface change for every consumer, not a
//!   validation fix.
//!
//! Both are a separate, larger scope decision than this change makes.

use crate::cli::{Cli, Transport};
use std::net::IpAddr;

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, thiserror::Error, PartialEq)]
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
/// Mirrors the parse `mecmcp_transport::server::normalize_host_authority`
/// performs at request time, so a value this rejects is a value that server
/// would also silently never match.
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
/// Mirrors the parse `mecmcp_transport::server::parse_and_normalize_origin`
/// performs at request time: a scheme of `http`/`https`, an authority with no
/// userinfo, and no query or non-root path (an Origin header carries neither).
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
