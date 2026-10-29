//! Junos-only preservation of non-secret `session` text around a redaction
//! scan (rustjunosmcp#579). The generic denylist matches `session` as a
//! substring and blanks the rest of the line, which masks counters
//! (`Valid sessions: 12`), config keywords (`then log session-init`) and CLI
//! echoes (`show security flow session summary`). A narrow closed set of
//! those is swapped for opaque markers before the scan and restored after;
//! everything else (`session-id`, `session <value>`, ...) is left to the
//! scan and stays masked (fail closed). All passes are linear in the input:
//! the marker prefix is fixed, and input containing it is not shielded.

#![deny(clippy::indexing_slicing, clippy::string_slice)]

use crate::denylist::{is_inert_session_value, is_session_config_name};
use std::net::IpAddr;

/// Bare `session`/`sessions` is CLI vocabulary only when the next token is one
/// of these `show security flow session` keywords; `session <value>` stays
/// masked. The prefix and port filters take one address or integer.
const KEYWORD_FOLLOWERS: &[&str] = &[
    "summary",
    "table",
    "extensive",
    "brief",
    "terse",
    "count",
    "destination-prefix",
    "source-prefix",
    "destination-port",
    "source-port",
];

/// Filters whose single argument may be an IPv4/IPv6 address or prefix; it is
/// accepted only as the token directly after one of these.
const ADDRESS_FILTERS: &[&str] = &["destination-prefix", "source-prefix"];

/// Keywords whose single argument may be a bare integer; accepted only as the
/// token directly after one of these.
const NUMERIC_FILTERS: &[&str] = &[
    "source-ip-based",
    "destination-ip-based",
    "destination-port",
    "source-port",
];

/// Words other than numbers and addresses that may follow a shielded keyword
/// within the same statement; anything else may be introducing a value.
const STATEMENT_WORDS: &[&str] = &[
    "session-init",
    "session-close",
    "limit-session",
    "session",
    "sessions",
    "source-ip-based",
    "destination-ip-based",
];

/// Longest digit run accepted as a numeric argument (a limit or count).
/// Opaque stand-in prefix for a preserved span.
const MARKER: &str = "JMCPKEEP";

/// Counter-label words specific to Junos `show security flow session summary`
/// output; kept here rather than in the shared `SESSION_NAME_WORDS` so other
/// vendors' session-name handling is unchanged.
const JUNOS_LABEL_WORDS: &[&str] = &[
    "processed",
    "unicast",
    "multicast",
    "services",
    "offload",
    "use",
    "pending",
    "invalidated",
    "other",
    "states",
];

const MAX_DIGITS: usize = 10;

/// Longest statement tail (in chars) inspected after a shielded keyword;
/// longer tails are not shielded, which keeps the scan linear.
const MAX_STATEMENT_CHARS: usize = 256;

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Run `scan` over `input` with the closed non-secret `session` text hidden
/// from it.
pub(crate) fn scan_preserving_sessions(input: &str, scan: impl Fn(&str) -> String) -> String {
    // Fail closed: input that already carries the marker stem is scanned
    // as-is, so a marker can never be forged or collide.
    if input.contains(MARKER) {
        return scan(input);
    }
    let prefix = MARKER;
    let mut kept: Vec<String> = Vec::new();
    let mut shielded = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        let content = line.trim_end_matches(['\n', '\r']);
        let (content, ending) = line.split_at(content.len());
        if is_counter_row(content) {
            // Leading whitespace stays visible so the generic scan's
            // indentation-based carry (YAML blocks) still sees this line.
            let (indent, row) = content.split_at(content.len() - content.trim_start().len());
            shielded.push_str(indent);
            shielded.push_str(&mark(prefix, &mut kept, row));
        } else {
            shield_keywords(content, prefix, &mut kept, &mut shielded);
        }
        shielded.push_str(ending);
    }
    if kept.is_empty() {
        return scan(input);
    }
    restore(&scan(&shielded), prefix, &kept)
}

fn mark(prefix: &str, kept: &mut Vec<String>, text: &str) -> String {
    kept.push(text.to_string());
    format!("{prefix}{}Z", kept.len() - 1)
}

/// Replace every surviving `{prefix}{i}Z` marker with `kept[i]` in one pass.
fn restore(out: &str, prefix: &str, kept: &[String]) -> String {
    let mut res = String::with_capacity(out.len());
    let mut rest = out;
    while let Some(pos) = rest.find(prefix) {
        let (before, from_marker) = rest.split_at(pos);
        res.push_str(before);
        let after = from_marker.get(prefix.len()..).unwrap_or_default();
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        let (number, tail) = after.split_at(digits);
        match (
            number.parse::<usize>().ok().and_then(|i| kept.get(i)),
            tail.strip_prefix('Z'),
        ) {
            (Some(original), Some(remaining)) => {
                res.push_str(original);
                rest = remaining;
            }
            _ => {
                res.push_str(prefix);
                rest = after;
            }
        }
    }
    res.push_str(rest);
    res
}

/// A counter row: a label (words joined by whitespace, optional trailing `:`)
/// that is a [`is_session_config_name`] once lowercased and `-`-joined,
/// followed only by inert values (`Valid sessions: 12`, `SESSION_OPEN 1234 0`).
fn is_counter_row(line: &str) -> bool {
    let mut words = line.split_whitespace().peekable();
    let mut label = String::new();
    while let Some(word) = words.next_if(|w| !is_inert_session_value(w.trim_end_matches(':'))) {
        let word = word.strip_suffix(':').unwrap_or(word);
        if !word.chars().all(is_token_char) {
            return false;
        }
        if !label.is_empty() {
            label.push('-');
        }
        label.push_str(&word.to_ascii_lowercase());
    }
    // At least one value: a bare `Total sessions:` is a key that may open a
    // block carrying a secret on the next lines.
    // Junos-local words stand in as `flow`, a shared counter word.
    let label = label
        .split('-')
        .map(|w| {
            if JUNOS_LABEL_WORDS.contains(&w) {
                "flow"
            } else {
                w
            }
        })
        .collect::<Vec<_>>()
        .join("-");
    words.peek().is_some() && is_session_config_name(&label) && words.all(is_inert_session_value)
}

/// True when the rest of the line holds only `{}|`, known non-secret keywords,
/// one address after an address filter and one integer after a numeric
/// filter, in every `;` statement. Anything else fails closed (not shielded).
fn statement_is_keywords_only(after: &str) -> bool {
    if after.chars().nth(MAX_STATEMENT_CHARS).is_some() {
        return false;
    }
    after.split(';').all(|statement| {
        let mut previous = "";
        statement
            .split(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '|'))
            .filter(|w| !w.is_empty())
            .map(str::to_ascii_lowercase)
            .all(|w| {
                let is_number = w.len() <= MAX_DIGITS && w.bytes().all(|b| b.is_ascii_digit());
                let ok = STATEMENT_WORDS.contains(&w.as_str())
                    || KEYWORD_FOLLOWERS.contains(&w.as_str())
                    || (NUMERIC_FILTERS.contains(&previous) && is_number)
                    || (ADDRESS_FILTERS.contains(&previous) && is_address_or_prefix(&w));
                previous = [ADDRESS_FILTERS, NUMERIC_FILTERS, KEYWORD_FOLLOWERS]
                    .iter()
                    .flat_map(|set| set.iter())
                    .find(|k| **k == w)
                    .copied()
                    .unwrap_or("");
                ok
            })
    })
}

fn is_address_or_prefix(word: &str) -> bool {
    let (address, length) = word.split_once('/').unwrap_or((word, "0"));
    address.parse::<IpAddr>().is_ok()
        && length.len() <= 3
        && length.bytes().all(|b| b.is_ascii_digit())
}

/// Append `line` to `out`, replacing each shielded keyword token by a marker.
fn shield_keywords(line: &str, prefix: &str, kept: &mut Vec<String>, out: &mut String) {
    let mut rest = line;
    while !rest.is_empty() {
        let start = rest.find(is_token_char).unwrap_or(rest.len());
        let (gap, from_token) = rest.split_at(start);
        out.push_str(gap);
        let end = from_token
            .find(|c: char| !is_token_char(c))
            .unwrap_or(from_token.len());
        let (token, after) = from_token.split_at(end);
        if token.is_empty() {
            return;
        }
        let shield_it = match token.to_ascii_lowercase().as_str() {
            "session-init" | "session-close" | "limit-session" => statement_is_keywords_only(after),
            "session" | "sessions" => {
                let next = after.trim_start_matches([' ', '\t']);
                let next_end = next.find(|c: char| !is_token_char(c)).unwrap_or(next.len());
                KEYWORD_FOLLOWERS.contains(&next.split_at(next_end).0.to_ascii_lowercase().as_str())
                    && statement_is_keywords_only(after)
            }
            _ => false,
        };
        if shield_it {
            out.push_str(&mark(prefix, kept, token));
        } else {
            out.push_str(token);
        }
        rest = after;
    }
}
