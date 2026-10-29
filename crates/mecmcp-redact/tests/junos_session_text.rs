//! Junos text/JSON redaction keeps non-secret `session` counters and
//! keywords (rustjunosmcp#579) while every session secret stays masked.

use mecmcp_redact::junos::{redact_json_value, redact_text};
use serde_json::json;

const SECRET: &str = "abcdef0123456789";

const PRESERVED: &[&str] = &[
    "SESSION_OPEN       1234        0",
    "SESSION_CLOSE      1233        0",
    "Valid sessions: 12",
    "Active sessions: 3",
    "Total processed sessions:      42",
    "Unicast-sessions: 12",
    "Multicast-sessions: 0",
    "Services-offload-sessions: 0",
    "Sessions-in-use: 3",
    "Pending sessions: 0",
    "Invalidated sessions: 0",
    "Sessions in other states: 0",
    "Maximum-sessions: 524288",
    "Failed sessions: 0",
    "Total sessions: 5",
    "show security flow session destination-prefix 10.9.0.2",
    "show security flow session destination-prefix 2001:db8::/32",
    "show security flow session summary",
    "then log session-init",
    "then log session-close",
    "limit-session source-ip-based 100",
    "set security policies from-zone a to-zone b policy p then log session-init",
    "set security policies from-zone a to-zone b policy p then log session-close",
    "set security screen ids-option s1 limit-session source-ip-based 100",
    "Then Log SESSION-INIT;",
    "log {\n    session-init;\n    session-close;\n}",
];

const MASKED: &[&str] = &[
    "session-id abcdef0123456789",
    "session abcdef0123456789",
    "Session-Key: abcdef0123456789", // gitleaks:allow -- fabricated must-mask fixture, not a real key
    "SESSION_TOKEN abcdef0123456789",
    "Valid sessions: abcdef0123456789",
    "Sessions-in-use: abcdef0123456789",
    "Total sessions: 12 token=abcdef0123456789", // gitleaks:allow -- fabricated must-mask fixture, not a real key
    "show security flow session destination-prefix abcdef0123456789",
    "session summary token 0123456789abcdef",
    "session-token: s3cr3tvalue",
    "set system login session-key supersecretvalue",
    "set security ike policy p pre-shared-key ascii-text \"hunter2hunter2\"",
    "set snmp community s3cr3tcomm authorization read-only",
    "set system root-authentication encrypted-password \"$6$abc$defghijklmnop\"",
    "Authorization: Bearer abcdef0123456789",
    "ftp://svc:hunter2hunter2@archive.example.net/cfg",
    "session init 0123456789abcdef0123456789abcdef01234567",
    "session close id=0123456789abcdef0123456789abcdef01234567",
    "limit-session notanumber9f8e7d6c5b4a",
    "  password:\n    Valid sessions: 12\n    hunter2hunter2\n",
    "secret: |\n  Total sessions: 5\n  hunter2hunter2",
    "community:\n  Valid sessions: 12\n  hunter2hunter2",
    "Total sessions:\n    hunter2hunter2",
    "then log session-init; hunter2hunter2",
    "show security flow session summary; hunter2hunter2",
    "then log session-init; hunter2hunter2 password x",
    "limit-session 10.1.2.3 192.168.1.1",
    "show security flow session summary dead:beef:cafe:babe:dead:beef:cafe:babe",
    "then log session-init; pass.word hunter2hunter2",
    "then log session-init; bind.pw hunter2hunter2",
    "then log session-init hunter2pwd tail",
    "then log session-init; mysecret99xyz tail",
    "show security flow session summary; hunter2psk tail",
    "then log session-init; foo=hunter2psk tail",
    "show security flow session summary 4111111111",
    "IP address  Session Id  Hardware address abcdef0123456789",
];

const SECRETS: &[&str] = &[
    SECRET,
    "0123456789abcdef",
    "s3cr3tvalue",
    "supersecretvalue",
    "hunter2hunter2",
    "s3cr3tcomm",
    "$6$abc",
    "notanumber",
    "mysecret99xyz",
    "hunter2psk",
    "hunter2pwd",
    "4111111111",
    "dead:beef:cafe:babe",
    "192.168.1.1",
];

#[test]
fn counters_and_keywords_survive_as_text() {
    for line in PRESERVED {
        assert_eq!(redact_text(line), *line, "over-masked");
    }
}

#[test]
fn counters_and_keywords_survive_in_json_strings() {
    for line in PRESERVED {
        for field in ["output", "command"] {
            let mut value = json!({ field: line });
            redact_json_value(&mut value);
            assert_eq!(value[field], *line, "over-masked in {field}");
        }
    }
}

#[test]
fn secrets_stay_masked_as_text_and_json() {
    for line in MASKED {
        let out = redact_text(line);
        let mut value = json!({ "output": line });
        redact_json_value(&mut value);
        let json_out = value["output"].to_string();
        for secret in SECRETS {
            assert!(!out.contains(secret), "text leaked in: {line} -> {out}");
            assert!(
                !json_out.contains(secret),
                "json leaked in: {line} -> {json_out}"
            );
        }
    }
}

#[test]
fn secret_after_session_init_is_masked_and_keyword_survives() {
    let out = redact_text("then log session-init; pre-shared-key ascii-text \"hunter2hunter2\"");
    assert!(out.contains("session-init"), "{out}");
    assert!(!out.contains("hunter2hunter2"), "{out}");
}

#[test]
fn multi_line_mix_masks_only_the_secret_line() {
    let out = redact_text("Valid sessions: 12\nsession-id abcdef0123456789\nActive sessions: 3\n");
    assert!(out.contains("Valid sessions: 12\n"), "{out}");
    assert!(out.contains("Active sessions: 3\n"), "{out}");
    assert!(!out.contains(SECRET), "{out}");
}

#[test]
fn generic_redact_text_is_unchanged() {
    for line in ["Valid sessions: 12", "show security flow session summary"] {
        assert_ne!(mecmcp_redact::redact_text(line), line);
    }
}

#[test]
fn many_keywords_restore_in_linear_time() {
    let line = "set security policies from-zone a to-zone b policy p then log session-init\n\
                set security policies from-zone a to-zone b policy p then log session-close\n\
                Valid sessions: 12\n";
    let big = line.repeat(20_000);
    assert_eq!(redact_text(&big), big);
}

#[test]
fn overlong_statement_is_not_shielded() {
    let long = format!("session-init {}", "session-init ".repeat(100));
    assert!(!redact_text(&long).starts_with("session-init session-init"));
    let short = "limit-session { source-ip-based 100; destination-ip-based 50; }";
    assert_eq!(redact_text(short), short);
}

/// Input carrying the marker stem is scanned unshielded: identical to the
/// plain Junos scan, never forged or colliding, and fast.
#[test]
fn marker_stem_in_input_is_scanned_unshielded() {
    let start = std::time::Instant::now();
    let crafted = format!("JMCPKEEP{} then log session-init", "X".repeat(200_000));
    let expected = mecmcp_redact::junos::redact_log_text(&mecmcp_redact::redact_text(&crafted));
    assert_eq!(redact_text(&crafted), expected);
    let mixed = "JMCPKEEP0 Valid sessions: abcdef0123456789 then log session-init";
    assert!(!redact_text(mixed).contains(SECRET));
    assert!(!redact_text("JMCPKEEP0Z session-id abcdef0123456789").contains(SECRET));
    assert!(start.elapsed().as_secs() < 5);
}

/// Many shield hits next to a large crafted run stay linear.
#[test]
fn many_markers_with_large_crafted_input_stay_fast() {
    let start = std::time::Instant::now();
    let line = "then log session-init\nValid sessions: 12\n";
    let big = format!("{}{}", line.repeat(20_000), "X".repeat(200_000));
    assert_eq!(redact_text(&big), big);
    let with_stem = format!("JMCPKEEP{}\n{}", "X".repeat(200_000), line.repeat(5_000));
    let _ = redact_text(&with_stem);
    assert!(start.elapsed().as_secs() < 20);
}
