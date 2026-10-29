//! `junos::redact_log_text` runs over device-supplied text, so every line
//! shape that used to rescan its prefix or token per position stays linear
//! (mecmcp#584). Each input is at least 200k bytes; the bounds are generous.

use std::time::{Duration, Instant};

use mecmcp_redact::junos::redact_log_text;

/// Redact `input`, then check it finished in time and produced `expected`.
fn assert_fast(input: &str, expected: &str) {
    assert!(input.len() >= 200_000, "input too small: {}", input.len());
    let start = Instant::now();
    let got = redact_log_text(input);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "{} bytes took {elapsed:?}",
        input.len()
    );
    assert!(got == expected, "output changed for {} bytes", input.len());
}

/// Every boundary in a whitespace run asked whether a `set` statement
/// precedes it by rescanning the prefix.
#[test]
fn long_whitespace_run_stays_fast() {
    let line = format!("foo{}x", " ".repeat(200_000));
    assert_fast(&line, &line);
    let set_line = format!("set foo{}x", " ".repeat(200_000));
    assert_fast(&set_line, &set_line);
}

/// Every key hit asked whether a `set` statement precedes it by rescanning
/// the prefix.
#[test]
fn many_keys_on_one_line_stay_fast() {
    let prose = "secret ".repeat(30_000);
    assert_fast(&prose, &prose);
    let set_line = format!("set {}", "key v ".repeat(35_000));
    let expected = format!("set {}", "key [REDACTED] ".repeat(35_000));
    assert_fast(&set_line, &expected);
}

/// Every token boundary inside one long undelimited (or escaped-quote)
/// token re-walked and re-shape-checked the rest of the token.
#[test]
fn long_token_with_many_internal_boundaries_stays_fast() {
    for unit in ["a.", "x=", "/a", "\\\"", "\\'", "\u{a0}"] {
        let line = unit.repeat(200_000 / unit.len() + 1);
        assert_fast(&line, &line);
    }
    // A secret shape at the far end of such a token is still found.
    let prefix = "a.".repeat(100_000);
    let tails = ["$9$abc", "ENC(x"]; // gitleaks:allow -- fabricated $9$ fixture, not a real secret
    for tail in tails {
        assert_fast(&format!("{prefix}{tail}"), &format!("{prefix}[REDACTED]"));
    }
}
