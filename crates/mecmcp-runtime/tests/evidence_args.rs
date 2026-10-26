//! The evidence pipeline's CLI surface, defined once for all five servers.
//!
//! Without these flags the sink is unreachable from a deployment: `mecmcp-audit`
//! can build a pipeline but nothing tells it an endpoint, an identity or a
//! spool path, so credentials on a host would be read by no code at all
//! (mecmcp#292).

#![allow(clippy::unwrap_used)]

use clap::Parser;
use mecmcp_runtime::cli::EvidenceArgs;
use std::io::Write;

#[derive(Debug, Parser)]
struct Harness {
    #[command(flatten)]
    evidence: EvidenceArgs,
}

fn parse(args: &[&str]) -> EvidenceArgs {
    let mut argv = vec!["test"];
    argv.extend_from_slice(args);
    Harness::parse_from(argv).evidence
}

/// A stand-in trust anchor. Never parsed here — `into_config` only checks that
/// a path was given; the transport is what reads it.
fn anchor(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("ca.pem");
    std::fs::write(&path, "-----BEGIN CERTIFICATE-----\n").unwrap();
    path
}

fn secret(dir: &std::path::Path, name: &str, value: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(value.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// Absent flags mean absent pipeline. Evidence is a deployment choice.
#[test]
fn no_endpoint_means_no_evidence() {
    assert!(parse(&[]).into_config().unwrap().is_none());
}

/// The full flag set produces a usable config.
#[test]
fn a_configured_endpoint_produces_a_pipeline_config() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret\n");
    let verify = secret(dir.path(), "v", "verify-secret");

    let config = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .unwrap()
    .expect("an endpoint was given");

    assert_eq!(config.server_id, "junos-950");
    assert_eq!(config.sink.endpoint, "https://ch.example:8443");
    assert_eq!(config.sink.username, "ssdf_audit");
    assert_eq!(config.sink.verify_username, "ssdf_audit_verify");
    // Trailing newline stripped: a password file written with an editor ends
    // in one, and sending it would fail auth in a way that reads like a wrong
    // password rather than a stray byte.
    assert_eq!(config.sink.password.expose(), "write-secret");
    assert_eq!(config.sink.verify_password.expose(), "verify-secret");
    assert!(
        !config.run_id.is_empty() && config.run_id != config.server_id,
        "each process lifetime needs its own run id"
    );
}

/// An endpoint with no credentials is a misconfiguration, not a default.
#[test]
fn an_endpoint_without_credentials_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no password file was given");
    assert!(
        format!("{error}").contains("password"),
        "the error must name what is missing: {error}"
    );
}

/// A world-readable password file is refused, matching the token-file rule.
#[cfg(unix)]
#[test]
fn a_loose_password_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    std::fs::set_permissions(&write, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("0644 on a credential must be refused");
    assert!(
        format!("{error}").contains("0600") || format!("{error}").contains("permissions"),
        "the error must say what is wrong with the file: {error}"
    );
}

/// An endpoint without a chain identity is refused.
///
/// The chain is keyed by `server_id`. Defaulting it to something incidental —
/// the hostname, say — means a rename starts a second root, and a fork
/// verifies as two valid chains, so nothing downstream would report it. This
/// fleet has already renamed its hosts once.
#[test]
fn an_endpoint_without_a_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no chain identity was given");

    assert!(
        format!("{error}").contains("--ssdf-audit-server-id"),
        "the error must name the flag to set: {error}"
    );
}

/// A zero delivery interval is refused at parse time.
///
/// `Duration::ZERO` makes the drain's `wait_timeout` return immediately every
/// iteration, reloading the outbox in a tight loop — a busy spin on CPU and
/// disk that presents as a wedged server rather than as a misconfiguration.
#[test]
fn a_zero_delivery_interval_is_refused() {
    let parsed = Harness::try_parse_from(["test", "--ssdf-audit-interval-secs", "0"]);
    let error = parsed.expect_err("zero must not parse").to_string();
    assert!(
        error.contains("at least 1 second"),
        "the error must say what to use instead: {error}"
    );
}

/// Run ids must not be derived from clock and pid.
///
/// Delivery identity is `(server_id, run_id, segment_seq)`, so a repeated run
/// id makes a new run's segment 0 collide with one already delivered and be
/// skipped as landed — losing the head of the chain. A snapshot restore brings
/// back both the clock and pid 1.
#[test]
fn run_ids_do_not_repeat() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let args = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ]);

    let seen: std::collections::HashSet<String> = (0..64)
        .map(|_| args.into_config().unwrap().unwrap().run_id)
        .collect();

    assert_eq!(
        seen.len(),
        64,
        "run ids repeated within one process, so they cannot be distinguishing \
         two runs of one server either"
    );
}

/// A password ending in real whitespace keeps it; only one line ending goes.
///
/// `trim_end` would eat the trailing space, and the resulting auth failure
/// reads as a wrong password rather than a mangled one.
#[test]
fn only_one_line_ending_is_stripped_from_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "trailing space \n");
    let verify = secret(dir.path(), "v", "verify-secret");

    let config = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .unwrap()
    .expect("configured");

    assert_eq!(config.sink.password.expose(), "trailing space ");
}

/// An empty credential file is a configuration error, not an empty password.
#[test]
fn an_empty_password_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "\n");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("an empty credential must be refused");
    assert!(!format!("{error}").is_empty());
}

/// Spool paths have no default, because no default is writable anywhere.
#[test]
fn an_endpoint_without_spool_paths_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let ca = anchor(dir.path());

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no spool path was given");
    assert!(
        format!("{error}").contains("--ssdf-audit-outbox"),
        "the error must name the flag: {error}"
    );
}

/// A blank chain identity is refused.
///
/// `--ssdf-audit-server-id ""` is what a unit file produces when the variable
/// behind it is unset, and clap hands it over as `Some("")`. Every writer that
/// did it would share the empty chain key, which is a fork — and a fork
/// verifies as two valid chains, so nothing downstream would say so.
#[test]
fn a_blank_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    for blank in ["", "   "] {
        let error = parse(&[
            "--ssdf-audit-endpoint",
            "https://ch.example:8443",
            "--ssdf-audit-server-id",
            blank,
            "--ssdf-audit-password-file",
            write.to_str().unwrap(),
            "--ssdf-audit-verify-password-file",
            verify.to_str().unwrap(),
            "--ssdf-audit-outbox",
            dir.path().join("outbox").to_str().unwrap(),
            "--ssdf-audit-ledger",
            dir.path().join("ledger").to_str().unwrap(),
        ])
        .into_config()
        .expect_err("a blank chain identity must be refused");
        assert!(
            format!("{error}").contains("empty"),
            "the error must name the problem for {blank:?}: {error}"
        );
    }
}

/// Run ids must sort in the order they were created.
///
/// `SegmentArchive::archive` requires run ids to be non-decreasing and rejects
/// anything else as `RunIdNotMonotonic`, so a purely random id fails archival
/// on roughly half of all ordinary restarts — unique but unusable.
#[test]
fn run_ids_sort_in_creation_order() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let args = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ]);

    // No sleep. An earlier version of this test paused 2ms between ids, which
    // hid the case that actually breaks: two ids inside one clock tick share
    // their prefix, and the random half then decides the order. Generating them
    // back to back is what exercises it.
    let mut previous = args.into_config().unwrap().unwrap().run_id;
    for _ in 0..256 {
        let next = args.into_config().unwrap().unwrap().run_id;
        assert!(
            next > previous,
            "run ids must not sort below their predecessor"
        );
        previous = next;
    }
}

/// An https endpoint without a trust anchor is refused at configuration time.
///
/// The transport refuses it too, but there it surfaces as a failed delivery
/// once per interval, which reads as an outage. Catching it here fails the
/// server at startup, where a missing flag looks like a missing flag.
#[test]
fn an_https_endpoint_without_a_ca_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("https without a CA must be refused");

    let text = format!("{error}");
    assert!(
        text.contains("--ssdf-audit-ca-file"),
        "must name the flag: {text}"
    );
    assert!(
        !text.contains("ProtectSystem"),
        "the CA refusal must not carry the spool-path rationale, which is about \
         a different flag entirely: {text}"
    );
}

/// A plaintext endpoint to a non-loopback host is refused at configuration
/// time, matching the refusal `split_endpoint` already applies on every send.
///
/// Catching it here fails the server at startup. Leaving it to the transport
/// alone means the server starts, spools every segment to the outbox, and
/// fails every delivery attempt forever — which reads as an outage, not as
/// the misconfiguration it is.
#[test]
fn a_plaintext_endpoint_to_a_non_loopback_host_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "http://192.0.2.40:8123",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("http:// to a non-loopback host must be refused");
    assert!(
        format!("{error}").contains("loopback"),
        "the error must say why: {error}"
    );
}

/// A plaintext endpoint to loopback is accepted: the traffic never leaves the
/// host, so there is nothing for the loopback-only rule to refuse.
#[test]
fn a_plaintext_endpoint_to_loopback_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let config = parse(&[
        "--ssdf-audit-endpoint",
        "http://127.0.0.1:8123",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .unwrap();

    assert!(
        config.is_some(),
        "a loopback http:// endpoint must be accepted"
    );
}

/// The base SSDF flag set an assortment of these tests reuse for the forward
/// sink's own tests, so each one only has to add the `--audit-forward-*` bits
/// under test.
fn base_ssdf_args(dir: &std::path::Path) -> Vec<String> {
    let write = secret(dir, "w", "write-secret");
    let verify = secret(dir, "v", "verify-secret");
    vec![
        "--ssdf-audit-endpoint".to_string(),
        "http://127.0.0.1:8123".to_string(),
        "--ssdf-audit-server-id".to_string(),
        "junos-950".to_string(),
        "--ssdf-audit-password-file".to_string(),
        write.to_str().unwrap().to_string(),
        "--ssdf-audit-verify-password-file".to_string(),
        verify.to_str().unwrap().to_string(),
        "--ssdf-audit-outbox".to_string(),
        dir.join("outbox").to_str().unwrap().to_string(),
        "--ssdf-audit-ledger".to_string(),
        dir.join("ledger").to_str().unwrap().to_string(),
    ]
}

/// Absent `--audit-forward-endpoint` means no forward sink, same as the
/// pipeline behaved before this flag existed.
#[test]
fn no_forward_endpoint_means_no_forward_sink() {
    let dir = tempfile::tempdir().unwrap();
    let args = base_ssdf_args(dir.path());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let config = parse(&args).into_config().unwrap().unwrap();
    assert!(config.forward_sink.is_none());
}

/// `--audit-forward-endpoint` alone, without `--ssdf-audit-endpoint`, must be
/// refused rather than silently produce no pipeline at all -- the forward
/// sink rides on the SSDF pipeline's recorder and chain identity, and an
/// operator who asked for it and got nothing has no signal anything is wrong.
#[test]
fn forward_endpoint_without_ssdf_endpoint_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let error = parse(&[
        "--audit-forward-endpoint",
        "https://collector.example/audit",
        "--audit-forward-outbox",
        dir.path().join("fwd-outbox").to_str().unwrap(),
        "--audit-forward-ledger",
        dir.path().join("fwd-ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("a forward endpoint with no SSDF endpoint must be refused");
    assert!(
        format!("{error}").contains("--ssdf-audit-endpoint"),
        "the error must say why: {error}"
    );
}

/// The full forward flag set, alongside SSDF, produces a usable forward-sink
/// config with the bearer token loaded from its file.
#[test]
fn a_configured_forward_endpoint_produces_a_forward_sink_config() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = base_ssdf_args(dir.path());
    let token = secret(dir.path(), "token", "s3cret-token");
    args.extend([
        "--audit-forward-endpoint".to_string(),
        "https://collector.example/audit".to_string(),
        "--audit-forward-token-file".to_string(),
        token.to_str().unwrap().to_string(),
        "--audit-forward-outbox".to_string(),
        dir.path().join("fwd-outbox").to_str().unwrap().to_string(),
        "--audit-forward-ledger".to_string(),
        dir.path().join("fwd-ledger").to_str().unwrap().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let config = parse(&args).into_config().unwrap().unwrap();
    let forward = config
        .forward_sink
        .expect("a forward endpoint was configured");
    assert_eq!(forward.endpoint, "https://collector.example/audit");
    assert_eq!(
        forward.bearer_token.map(|t| t.expose().to_string()),
        Some("s3cret-token".to_string())
    );
}

/// A forward endpoint with no bearer token is accepted: some collectors
/// authenticate at the network layer instead.
#[test]
fn a_forward_endpoint_with_no_token_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = base_ssdf_args(dir.path());
    args.extend([
        "--audit-forward-endpoint".to_string(),
        "http://127.0.0.1:9090/audit".to_string(),
        "--audit-forward-outbox".to_string(),
        dir.path().join("fwd-outbox").to_str().unwrap().to_string(),
        "--audit-forward-ledger".to_string(),
        dir.path().join("fwd-ledger").to_str().unwrap().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let config = parse(&args).into_config().unwrap().unwrap();
    let forward = config
        .forward_sink
        .expect("a forward endpoint was configured");
    assert!(forward.bearer_token.is_none());
}

/// A forward endpoint without its outbox path is refused, same as SSDF's own
/// `--ssdf-audit-outbox` requirement.
#[test]
fn a_forward_endpoint_without_an_outbox_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = base_ssdf_args(dir.path());
    args.extend([
        "--audit-forward-endpoint".to_string(),
        "https://collector.example/audit".to_string(),
        "--audit-forward-ledger".to_string(),
        dir.path().join("fwd-ledger").to_str().unwrap().to_string(),
    ]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let error = parse(&args)
        .into_config()
        .expect_err("a forward endpoint with no outbox path must be refused");
    assert!(
        format!("{error}").contains("--audit-forward-outbox"),
        "the error must name the missing flag: {error}"
    );
}

/// Forward flags, no SSDF endpoint (mecmcp#378, option 2).
fn forward_only_args(dir: &std::path::Path) -> Vec<String> {
    vec![
        "--audit-forward-endpoint".to_string(),
        "https://collector.example/audit".to_string(),
        "--audit-forward-outbox".to_string(),
        dir.join("fwd-outbox").to_str().unwrap().to_string(),
        "--audit-forward-ledger".to_string(),
        dir.join("fwd-ledger").to_str().unwrap().to_string(),
        "--ssdf-audit-server-id".to_string(),
        "junos-950".to_string(),
        "--ssdf-audit-records-per-segment".to_string(),
        "7".to_string(),
    ]
}

fn parse_owned(args: &[String]) -> EvidenceArgs {
    parse(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Forward flags alone build a forward-only pipeline, reusing the shared
/// chain identity and segment size.
#[test]
fn forward_only_args_produce_a_forward_only_config() {
    use mecmcp_audit::EvidencePipelineConfig;
    let dir = tempfile::tempdir().unwrap();
    let config = parse_owned(&forward_only_args(dir.path()))
        .into_pipeline_config()
        .unwrap()
        .unwrap();
    let EvidencePipelineConfig::ForwardOnly(config) = config else {
        panic!("expected a forward-only pipeline: {config:?}");
    };
    assert_eq!(config.server_id, "junos-950");
    assert_eq!(config.records_per_segment, 7);
    assert_eq!(config.forward.endpoint, "https://collector.example/audit");
}

/// With an SSDF endpoint, `into_pipeline_config` is the SSDF pipeline, and
/// with neither it is nothing.
#[test]
fn pipeline_config_is_ssdf_with_an_ssdf_endpoint_and_none_without_any() {
    use mecmcp_audit::EvidencePipelineConfig;
    assert!(parse(&[]).into_pipeline_config().unwrap().is_none());

    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "w");
    let verify = secret(dir.path(), "v", "v");
    let config = parse(&[
        "--ssdf-audit-endpoint",
        "http://127.0.0.1:8123",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("o").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("l").to_str().unwrap(),
    ])
    .into_pipeline_config()
    .unwrap()
    .unwrap();
    assert!(matches!(config, EvidencePipelineConfig::Ssdf(_)));
}

/// The chain identity is required: without it the forward-only chain would
/// have no key.
#[test]
fn forward_only_without_a_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = forward_only_args(dir.path());
    args.drain(6..8);
    let error = parse_owned(&args)
        .into_pipeline_config()
        .expect_err("no server id");
    assert!(
        format!("{error}").contains("--ssdf-audit-server-id"),
        "{error}"
    );
}

/// An unusable server id is refused exactly as on the SSDF path.
#[test]
fn forward_only_with_an_empty_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut args = forward_only_args(dir.path());
    args[7] = String::new();
    parse_owned(&args)
        .into_pipeline_config()
        .expect_err("an empty server id forks the chain");
}

/// The forward spool is the record, so its outbox and ledger are required.
#[test]
fn forward_only_without_outbox_or_ledger_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (flag_index, flag) in [(2, "--audit-forward-outbox"), (4, "--audit-forward-ledger")] {
        let mut args = forward_only_args(dir.path());
        args.drain(flag_index..flag_index + 2);
        let error = parse_owned(&args)
            .into_pipeline_config()
            .expect_err("missing spool path");
        assert!(format!("{error}").contains(flag), "{error}");
    }
}
