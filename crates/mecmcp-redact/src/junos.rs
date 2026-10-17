//! Junos profile (MEC-1245): two pieces of redaction coverage rustjunosmcp's
//! `collect_jtac_support_bundle` (`redact=true`, the default) needs that this
//! crate's vendor-agnostic `crate::xml`/`crate::text` passes do not provide
//! on their own.
//!
//! - [`redact_xml`] — the generic XML pass (denylisted element/attribute
//!   names plus the [`crate::shape`] value-shape catch-all) already covers
//!   most of rustjunosmcp's locked `REDACT_ELEMENT_NAMES` list. What is left
//!   over is a handful of element names (e.g. a bare `<value>` element, as in
//!   the NTP `authentication-key` secret,
//!   `<key><name>1</name><type>md5</type><value>$9$...</value></key>`) that
//!   are deliberately not on [`crate::denylist`] — as a substring or exact
//!   match they are far too generic to redact unconditionally across every
//!   vendor this crate serves — but within Junos's own closed NETCONF element
//!   vocabulary, treating them as unconditionally secret-bearing is the same
//!   judgement call rustjunosmcp already made and has shipped on for years.
//!   `is_extra_secret_element` derives this set from
//!   [`redact_log_text`]'s own `REDACT_LOG_KEYS` vocabulary rather than
//!   hand-maintaining a second list, so the XML and text passes cannot drift
//!   apart on which Junos-specific names are secret-bearing. [`redact_xml`]
//!   is the generic pass plus that derived set, not a second XML scanner
//!   (parser differentials are exactly the risk a second hand-rolled XML walk
//!   would invite).
//! - [`redact_log_text`] — a conservative, `set`-statement-aware line
//!   redactor for the non-XML support-bundle artefacts (`/var/log/*` files,
//!   `request support information` tech-support output). This is *not* a
//!   thin wrapper over `crate::text::redact`: that pass is substring-keyed
//!   and intentionally over-redacts (documented, accepted cost for the
//!   generic multi-vendor case) — it matches `secret` inside `secretary` and
//!   flags a bare prose mention of a denylisted word with no config-syntax
//!   signal at all. A support bundle's `/var/log/*` files are full of prose
//!   (syslog messages, command echoes), so that cost is not acceptable here.
//!   This pass instead whole-word-matches a closed, Junos-specific key list
//!   and only redacts the following value when a config-syntax signal is
//!   present: quotes, a `=`, a trailing `;`/`{`, a Junos crypt hash, or a
//!   preceding `set` statement (including one echoed mid-line in a
//!   `UI_CMDLINE_READ_LINE` syslog entry).
//!
//! Ported from `rust-junosmcp-srx-core/src/workflows/support_bundle/redact.rs`
//! (Phase 3 design doc § "Redact rules"; `docs/superpowers/plans/`
//! `2026-07-13-audit-field-redaction.md`), which becomes a thin call-through
//! to this module.

#![deny(clippy::indexing_slicing, clippy::string_slice)]

use crate::RedactError;
use crate::denylist::is_denylisted_key;
use crate::policy::{RedactionPolicy, active};
use crate::shape::looks_like_secret_value;
use crate::xml;

/// Junos element names whose value is always a secret, independent of its
/// `crate::denylist`-covered ancestor and of whether the text itself looks
/// like a crypt hash — see the module docs for why a name like `value` needs
/// to be named here at all (`key` is already denylisted under exact match).
///
/// Derived from [`REDACT_LOG_KEYS`] — the text pass's own closed vocabulary —
/// rather than kept as a second hand-maintained list: any entry already
/// covered by [`crate::denylist::is_denylisted_key`] is skipped (it is
/// already secret-bearing everywhere, not just in Junos XML), and anything
/// left over is exactly the set of Junos-specific element names the generic
/// XML pass would otherwise miss. Adding a name to `REDACT_LOG_KEYS` gives it
/// XML coverage for free; the two lists cannot drift apart.
fn is_extra_secret_element(local_name: &str) -> bool {
    REDACT_LOG_KEYS.contains(&local_name) && !is_denylisted_key(local_name)
}

/// Junos configuration keywords that contain `session` but are not secrets
/// (`then log session-init`, `limit-session`, ...). Exact local-name match
/// against a closed vocabulary; the shared denylist's `session` substring
/// entry would otherwise redact the element's own text and its whole
/// subtree. The waiver is value-aware (see `xml::any_ancestor_secret`): it
/// only applies to empty or numeric values, and every descendant element and
/// every non-numeric value is still judged on its own.
fn is_session_keyword_element(local_name: &str) -> bool {
    matches!(
        local_name,
        "session-init" | "session-close" | "limit-session"
    )
}

/// Redact a Junos NETCONF/XML support-bundle artefact.
///
/// Identical to [`crate::redact_xml_str`] except that the Junos-specific
/// extra element set is always treated as secret-bearing (see the module
/// docs).
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] when `input` does not parse as
/// well-formed XML — callers on a fail-closed path (anything shipped in a
/// JTAC support bundle) must refuse the artefact rather than fall back to
/// the unredacted input.
pub fn redact_xml(input: &str) -> Result<String, RedactError> {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        xml::validate(input)?;
        return Ok(input.to_string());
    }
    xml::redact_with(input, &is_extra_secret_element, &is_session_keyword_element)
}

/// Redact a JSON value in place with the Junos-specific keyword waiver: the
/// closed `session` vocabulary of [`redact_xml`] is kept when its value is
/// benign (null, bool, number, empty or digits-only string); every other
/// value, nested secret and real `session*` key is still redacted.
pub fn redact_json_value(value: &mut serde_json::Value) {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return;
    }
    crate::json::redact_with_waiver(value, &is_session_keyword_element);
}

/// Redact a Junos non-XML support-bundle artefact (`/var/log/*` files,
/// `request support information` tech-support text). Always succeeds — there
/// is no parse step to fail on free-form text.
#[must_use]
pub fn redact_log_text(input: &str) -> String {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    // `split_inclusive` keeps the line terminator attached, preserving the
    // exact newline structure (including any final newline) on rejoin.
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_log_line(line));
    }
    out
}

/// True when `input` is shaped like XML: trimmed of leading whitespace, it
/// starts with `<` followed by an XML name-start character (ASCII letter,
/// `_`, or `:`), a `?` (`<?xml ...?>` declaration), or a `!` (`<!--`
/// comment, `<!DOCTYPE`). This is a shape test only, not a parse — it exists
/// so the dispatcher in [`redact_log_artefact`] can pick the XML-vs-text path
/// from what the input *looks like* rather than from whether parsing happens
/// to succeed (see that function's doc comment for why the distinction
/// matters). A `<` followed by a digit (a syslog PRI prefix, e.g. `<134>`)
/// or by punctuation deliberately does not count: those are text artefacts
/// that merely contain an angle bracket, not XML.
fn looks_like_xml_shaped(input: &str) -> bool {
    let mut chars = input.trim_start().chars();
    chars.next() == Some('<')
        && matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || matches!(c, '_' | ':' | '?' | '!'))
}

/// Route a captured support-bundle artefact through the appropriate pass.
///
/// The choice of path is made from the artefact's *shape*
/// (`looks_like_xml_shaped`), decided before any parsing is attempted —
/// never from whether parsing happens to succeed. Picking the path by parse
/// outcome is a parser differential: two artefacts of the same kind could
/// take different redaction paths depending on incidental byte content
/// elsewhere in the file, and an artefact's secret coverage must not be
/// allowed to depend on that.
///
/// XML-shaped input is run through [`redact_xml`] and then *always* through
/// [`redact_log_text`] as well — a CLI-syntax secret can end up sitting in
/// plain text under an element name not on the XML pass's locked list (e.g.
/// directly under `<rpc-reply>` when the expected wrapper element is
/// absent), so the line-oriented pass is the floor every XML artefact goes
/// through regardless of its inner shape.
///
/// Non-XML-shaped input never goes through the XML pass (so it is never
/// XML-escaped or whitespace-normalised — see [`redact_xml`]'s doc comment).
/// It instead gets `crate::text::redact`'s denylisted-key/PEM-block/shape
/// scan as a floor under [`redact_log_text`]: that generic pass is
/// substring-keyed and case-insensitive where this module's own closed,
/// whole-word `REDACT_LOG_KEYS` scan is not, and it also handles a `key:
/// value` / JSON `"key": "value"` shape and PEM blocks that
/// [`redact_log_text`] alone does not recognise. Running both passes
/// over-redacts prose relative to [`redact_log_text`] alone — an accepted
/// cost the generic pass already takes everywhere else it is the floor —
/// but an artefact leaving the user's infrastructure for JTAC must not leak
/// a secret shape that pass would have caught.
///
/// # Errors
/// Fail-closed: when `input` is XML-shaped but [`redact_xml`] cannot parse
/// it, this returns [`RedactError::InvalidXml`] instead of falling back to
/// the line-oriented pass alone — that pass knows nothing about element
/// structure, so it is not a safe stand-in for a structural redactor that
/// failed. Callers on a fail-closed path must leave the artefact out of the
/// bundle and record that it did.
pub fn redact_log_artefact(input: &str) -> Result<String, RedactError> {
    if looks_like_xml_shaped(input) {
        let redacted = redact_xml(input)?;
        Ok(redact_log_text(&redacted))
    } else {
        Ok(redact_log_text(&crate::text::redact(input)))
    }
}

/// Element/key names whose value in Junos CLI/log syntax is a secret. Whole-
/// word matched (see [`is_word_char`]) against a closed, Junos-specific
/// vocabulary — unlike [`crate::denylist::is_denylisted_key`]'s deliberate
/// substring matching, which would turn `secret` into a false-positive match
/// inside `secretary`.
const REDACT_LOG_KEYS: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
    "authentication-key",
    "authentication-password",
    "privacy-password",
    "privacy-key",
    "password",
    "chap-secret",
    "default-chap-secret",
    "local-password",
    "hello-authentication-key",
    "plain-text-password-value",
    "key",
    "value",
];

/// Characters that form part of a Junos identifier token. Used for whole-word
/// matching of key names (so `community` does not match inside
/// `community-name` and `secret` does not match inside `secretary`).
#[allow(clippy::indexing_slicing)] // called with bounds-checked byte offsets
fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Byte offset of the end of the identifier word starting at `start` (a run
/// of [`is_word_char`] bytes). Returns `start` when there is no word there.
fn word_end(line: &str, start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut end = start;
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while end < bytes.len() && is_word_char(bytes[end]) {
        end += 1;
    }
    end
}

/// Fallback for a compound key not on the closed [`REDACT_LOG_KEYS`] list: a
/// Junos field whose last hyphen-separated segment is `password`, `secret`,
/// or `key` (e.g. a future `foo-bar-secret`), or one that ends in the
/// `-password-value` shape, is treated as sensitive. Kept narrower than
/// substring matching (which would catch `password` inside `passwordless`)
/// by anchoring on the final segment, and only consulted in `set` context
/// (see the caller) so it does not add new prose false positives.
fn matches_sensitive_key_suffix(word: &str) -> bool {
    word.ends_with("-password-value")
        || matches!(
            word.rsplit('-').next().unwrap_or(word),
            "password" | "secret" | "key"
        )
}

/// Redact a single log line (which may include a trailing `\n`).
fn redact_log_line(line: &str) -> String {
    // `set:` is the Junos audit marker (`UI_CFG_AUDIT_SET`); when present the
    // whole line is config context. Otherwise set-context is decided per-key
    // by `set_statement_precedes`, which also catches a `set` statement
    // echoed mid-line (e.g. a `UI_CMDLINE_READ_LINE` syslog entry).
    let audit_context = line.contains("set:");

    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut idx = 0;
    while idx < bytes.len() {
        // SOUND: `idx > 0` guard ensures `idx - 1` is valid.
        #[allow(clippy::indexing_slicing)]
        let at_boundary = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut matched = false;
        if at_boundary {
            for key in REDACT_LOG_KEYS {
                let klen = key.len();
                let end = idx + klen;
                // SOUND: `idx` is always a char boundary, `klen` is the byte
                // length of an ASCII key, so `end` is also a char boundary.
                // The `end <= bytes.len()` guard prevents out-of-bounds.
                #[allow(clippy::indexing_slicing)]
                if end <= bytes.len()
                    && &bytes[idx..end] == key.as_bytes()
                    && (end == bytes.len() || !is_word_char(bytes[end]))
                {
                    let set_context = audit_context || set_statement_precedes(line, idx);
                    if let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                    {
                        // SOUND: `idx` is a char boundary, `value_start` comes
                        // from `value_token`, which guarantees char
                        // boundaries (scans for ASCII delimiters or
                        // `line.len()`).
                        #[allow(clippy::string_slice)]
                        out.push_str(&line[idx..value_start]);
                        out.push_str("[REDACTED]");
                        idx = value_end;
                        matched = true;
                    }
                    break;
                }
            }
            if !matched {
                let end = word_end(line, idx);
                let set_context = audit_context || set_statement_precedes(line, idx);
                // SOUND: `idx`/`end` are char boundaries (`word_end` scans
                // ASCII `is_word_char` bytes only).
                #[allow(clippy::string_slice)]
                if end > idx
                    && set_context
                    && matches_sensitive_key_suffix(&line[idx..end])
                    && let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                {
                    #[allow(clippy::string_slice)]
                    out.push_str(&line[idx..value_start]);
                    out.push_str("[REDACTED]");
                    idx = value_end;
                    matched = true;
                }
            }
        }
        // Crypt-hash floor: whatever key (if any) precedes it, a token that
        // looks like a reversible Junos secret (`$9$...` etc. — see
        // `crate::shape::looks_like_secret_value`) never occurs in prose, so
        // it is safe to redact unconditionally at any token boundary. This
        // catches values sitting after a key not on `REDACT_LOG_KEYS` and
        // bare hash tokens with no preceding key at all. The boundary is
        // "previous byte is not ASCII alphanumeric" rather than a fixed
        // delimiter set, so structured forms (`k=v`, `k:v`, `(v)`, `,v,`,
        // `[v]`, or a non-ASCII byte such as U+00A0) still find the start of
        // the token — a hash value never has an alphanumeric glued directly
        // in front of it.
        if !matched {
            // SOUND: `idx > 0` guard ensures `idx - 1` is valid.
            #[allow(clippy::indexing_slicing)]
            let at_token_boundary = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
            if at_token_boundary
                && let Some((value_start, value_end)) = floor_value_token(line, idx)
            {
                let inner = token_inner_for_shape_check(line, value_start, value_end);
                if !inner.is_empty() && looks_like_secret_value(inner) {
                    out.push_str("[REDACTED]");
                    idx = value_end;
                    matched = true;
                }
            }
        }
        if !matched {
            // Push the current char (respecting UTF-8 boundaries).
            // SOUND: `idx` is always a char boundary (loop invariant).
            #[allow(clippy::string_slice)]
            let ch = line[idx..]
                .chars()
                .next()
                .expect("chars().next() cannot fail: loop invariant idx < line.len()");
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    out
}

/// English determiners/possessives that, when sitting between a `set` token
/// and a sensitive key, indicate prose ("we set the secret aside") rather
/// than a Junos `set` config statement. Used to suppress false positives.
const SET_CONTEXT_STOPWORDS: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "your", "our", "his", "her", "its",
    "their",
];

/// True when `token` looks like a Junos config path element: non-empty and
/// made up solely of identifier characters (alphanumerics plus `-_/.:`).
/// Tokens with spaces, quotes, or punctuation are not config identifiers.
fn is_config_identifier(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'/'
                || byte == b'.'
                || byte == b':'
        })
}

/// Byte offset just past the rightmost whole-word `set` token in `prefix`,
/// using the same word-boundary rule as [`is_word_char`]. Returns `None`
/// when `set` does not occur as a whole word.
fn rightmost_set_word_end(prefix: &str) -> Option<usize> {
    let bytes = prefix.as_bytes();
    let mut found = None;
    let mut i = 0;
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"set" {
            let before_ok = i == 0 || !is_word_char(bytes[i - 1]);
            let after_ok = i + 3 == bytes.len() || !is_word_char(bytes[i + 3]);
            if before_ok && after_ok {
                found = Some(i + 3);
            }
        }
        i += 1;
    }
    found
}

/// Decide whether a Junos `set` config statement precedes the key at byte
/// offset `key_start` on this line. Returns true when a whole-word `set`
/// (see [`rightmost_set_word_end`] — this also matches a `set` with a quote
/// or other punctuation glued directly against it, as when a shell or
/// syslog line quotes or structurally encodes the echoed command) appears
/// earlier on the line and every whitespace-separated token between that
/// `set` and the key is a config identifier (not a stopword) once its own
/// leading/trailing quote characters are stripped. This catches both a line
/// that starts with `set ...` and a `set ...` statement echoed mid-line
/// (e.g. a `UI_CMDLINE_READ_LINE` syslog: `... load-configuration set snmp
/// community VALUE ...`), while leaving prose like "we set the secret
/// aside" untouched because the intervening "the" is a stopword.
fn set_statement_precedes(line: &str, key_start: usize) -> bool {
    // SOUND: `key_start` is `idx` from the caller, which is always a char
    // boundary.
    #[allow(clippy::string_slice)]
    let prefix = &line[..key_start];
    let Some(set_end) = rightmost_set_word_end(prefix) else {
        return false;
    };
    // SOUND: `set_end` comes from `rightmost_set_word_end`, which only
    // returns offsets at or past a `set` match found within `prefix`'s
    // bounds, so it is a valid char boundary (ASCII word match).
    #[allow(clippy::string_slice)]
    let tail = &prefix[set_end..];
    tail.split_whitespace().all(|token| {
        let trimmed = token.trim_matches(['\'', '"']);
        is_config_identifier(trimmed) && !SET_CONTEXT_STOPWORDS.contains(&trimmed)
    })
}

/// Format qualifiers that may sit between a sensitive key and its value in
/// Junos config/log syntax (e.g. `pre-shared-key ascii-text "$9$..."`). When
/// present they are preserved and the *following* token is redacted.
const VALUE_QUALIFIERS: &[&str] = &["ascii-text", "hexadecimal", "plain-text", "encrypted"];

/// XML entity form of a double quote (`&quot;`). CLI text redacted after
/// [`redact_xml`]'s element pass (see [`redact_log_artefact`]) may still have
/// its literal `"` characters XML-escaped; [`value_token`] and
/// [`redactable_value`] must recognise this form too, or a quoted value with
/// an internal space is only partially matched up to the first space —
/// leaking the remainder.
const QUOT_ENTITY: &[u8] = b"&quot;";

/// True when `bytes[pos..]` starts with `needle`, without slicing (this
/// module denies `clippy::indexing_slicing`/`clippy::string_slice`).
fn bytes_start_with(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    needle
        .iter()
        .enumerate()
        .all(|(i, &b)| bytes.get(pos + i) == Some(&b))
}

/// Given the byte offset just past a matched key, decide whether the
/// following value should be redacted and return its `[start, end)` byte
/// range (the slice to replace with the marker, excluding any trailing `;`).
/// Returns `None` when there is no config signal, leaving prose mentions
/// untouched.
fn redactable_value(line: &str, after_key: usize, set_context: bool) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let pos = after_key;

    // Equals form: optional spaces, `=`, optional spaces, then the value.
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let mut scan = pos;
    #[allow(clippy::indexing_slicing)]
    while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
        scan += 1;
    }
    #[allow(clippy::indexing_slicing)]
    if scan < bytes.len() && bytes[scan] == b'=' {
        scan += 1;
        #[allow(clippy::indexing_slicing)]
        while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
            scan += 1;
        }
        return value_token(line, scan);
    }

    // Space form: require at least one space after the key.
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    if pos >= bytes.len() || (bytes[pos] != b' ' && bytes[pos] != b'\t') {
        return None;
    }
    let mut pos = pos;
    #[allow(clippy::indexing_slicing)]
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    // Optional format qualifier (e.g. `ascii-text`): preserved, value
    // follows.
    let mut qualifier_present = false;
    let (tok_start, tok_end) = token_bounds(line, pos);
    // SOUND: `token_bounds` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    if VALUE_QUALIFIERS.contains(&&line[tok_start..tok_end]) {
        qualifier_present = true;
        pos = tok_end;
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
    }

    let (value_start, value_end) = value_token(line, pos)?;
    // SOUND: bounds checks prevent out-of-bounds indexing.
    #[allow(clippy::indexing_slicing)]
    let quoted = bytes[value_start] == b'"'
        || bytes[value_start] == b'\''
        || bytes_start_with(bytes, value_start, QUOT_ENTITY);
    #[allow(clippy::indexing_slicing)]
    let terminated = value_end < bytes.len() && bytes[value_end] == b';';
    // A `{` (optionally preceded by whitespace) opens a config block — treat
    // it as a terminator like `;` (legacy curly-brace SNMP syntax, e.g.
    // `community NAME {`).
    let mut block_scan = value_end;
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while block_scan < bytes.len() && (bytes[block_scan] == b' ' || bytes[block_scan] == b'\t') {
        block_scan += 1;
    }
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let opens_block = block_scan < bytes.len() && bytes[block_scan] == b'{';
    // SOUND: `value_token` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    let hash = looks_like_secret_value(&line[value_start..value_end]);

    if quoted || qualifier_present || terminated || opens_block || hash || set_context {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Locate the value token starting at `pos`, returning its `[start, end)`
/// byte range. A quoted token — delimited by `"`, `'`, or the XML entity
/// `&quot;` — spans to its matching closing quote; a bare token runs until
/// whitespace or a `;` terminator. Returns `None` at end-of-line.
fn value_token(line: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if pos >= bytes.len() {
        return None;
    }
    // SOUND: bounds-checked above.
    #[allow(clippy::indexing_slicing)]
    let first = bytes[pos];
    if first == b'"' || first == b'\'' {
        let mut end = pos + 1;
        // Stop at `\n`: an unterminated quote must not consume the line
        // terminator and merge with the next line. Skip `\"`/`\'` (escaped
        // quote) rather than treating it as the closing delimiter, so a
        // value containing an escaped quote is not truncated mid-value.
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while end < bytes.len() && bytes[end] != first && bytes[end] != b'\n' {
            if bytes[end] == b'\\' && end + 1 < bytes.len() && bytes[end + 1] == first {
                end += 2;
            } else {
                end += 1;
            }
        }
        // SOUND: bounds-checked.
        #[allow(clippy::indexing_slicing)]
        if end < bytes.len() && bytes[end] == first {
            end += 1; // include the closing quote
        }
        // `end` is always a char boundary: either `bytes.len()`, a `\n`, or
        // one byte past an ASCII quote (`"` or `'`), all of which are char
        // boundaries.
        return Some((pos, end));
    }
    if bytes_start_with(bytes, pos, QUOT_ENTITY) {
        let mut end = pos + QUOT_ENTITY.len();
        while end < bytes.len() && !bytes_start_with(bytes, end, QUOT_ENTITY) {
            end += 1;
        }
        if end < bytes.len() {
            end += QUOT_ENTITY.len(); // include the closing entity
        }
        // `end` only ever lands where the ASCII byte sequence `&quot;`
        // starts or matches `bytes.len()`, both of which are char
        // boundaries — the scan advances one byte at a time but a partial
        // match can never stop mid-multi-byte-char, since `&` (0x26) never
        // occurs as a UTF-8 continuation byte (0x80-0xBF).
        return Some((pos, end));
    }
    let (start, end) = token_bounds(line, pos);
    if start == end {
        None
    } else {
        Some((start, end))
    }
}

/// Whether `byte` delimits a token for the crypt-hash floor scan: whitespace,
/// the angle brackets a captured artefact's embedded XML-ish text can carry,
/// and the punctuation that wraps a value in structured log forms (`k=v;`,
/// `(v)`, `,v,`, `[v]`, `{v}`) (see [`redact_log_line`]'s floor pass).
fn is_token_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b';'
            | b'<'
            | b'>'
            | b'"'
            | b'\''
            | b','
            | b')'
            | b']'
            | b'}'
    )
}

/// Like [`value_token`], but a bare (unquoted) token also stops at `<`/`>` —
/// the floor pass runs over artefacts that may embed XML-ish text, where a
/// hash token can sit directly against a tag delimiter with no whitespace.
fn floor_value_token(line: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if pos >= bytes.len() {
        return None;
    }
    // SOUND: bounds-checked above.
    #[allow(clippy::indexing_slicing)]
    let first = bytes[pos];
    if first == b'"' || first == b'\'' || bytes_start_with(bytes, pos, QUOT_ENTITY) {
        return value_token(line, pos);
    }
    let mut end = pos;
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while end < bytes.len() && !is_token_delimiter(bytes[end]) {
        end += 1;
    }
    if end == pos { None } else { Some((pos, end)) }
}

/// Strip the surrounding quote (or `&quot;` entity) delimiters from a
/// `[start, end)` span returned by [`value_token`]/[`floor_value_token`], so
/// [`looks_like_secret_value`] (which anchors on the value's own leading
/// byte, e.g. a crypt hash's `$`) sees the value and not its delimiters.
fn token_inner_for_shape_check(line: &str, start: usize, end: usize) -> &str {
    let bytes = line.as_bytes();
    // SOUND: `start`/`end` come from `value_token`/`floor_value_token`, which
    // guarantee char boundaries.
    #[allow(clippy::string_slice, clippy::indexing_slicing)]
    if end > start && (bytes[start] == b'"' || bytes[start] == b'\'') {
        let close = bytes[start];
        if end - start >= 2 && bytes[end - 1] == close {
            &line[start + 1..end - 1]
        } else {
            &line[start + 1..end]
        }
    } else if bytes_start_with(bytes, start, QUOT_ENTITY) {
        let qlen = QUOT_ENTITY.len();
        if end >= start + 2 * qlen && bytes_start_with(bytes, end - qlen, QUOT_ENTITY) {
            &line[start + qlen..end - qlen]
        } else {
            &line[start + qlen..end]
        }
    } else {
        &line[start..end]
    }
}

/// Bare-token bounds starting at `pos`: a run until whitespace, `;`, or EOL.
fn token_bounds(line: &str, pos: usize) -> (usize, usize) {
    let bytes = line.as_bytes();
    let mut end = pos;
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while end < bytes.len()
        && bytes[end] != b' '
        && bytes[end] != b'\t'
        && bytes[end] != b'\n'
        && bytes[end] != b'\r'
        && bytes[end] != b';'
    {
        end += 1;
    }
    // `end` is always a char boundary: either `bytes.len()` or pointing to an
    // ASCII delimiter (space, tab, newline, carriage return, or semicolon).
    (pos, end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn bare_value_element_is_redacted_even_without_a_denylisted_ancestor() {
        let xml = "<root><value>leak-value</value></root>";
        let got = redact_xml(xml).unwrap();
        assert!(!got.contains("leak-value"), "got: {got}");
    }

    #[test]
    fn xml_pass_covers_every_text_pass_key_not_already_in_the_shared_denylist() {
        for key in REDACT_LOG_KEYS {
            if is_denylisted_key(key) {
                // Already covered by the shared denylist regardless of
                // vendor; only the Junos-specific leftovers are this
                // module's job to cover.
                continue;
            }
            let xml = format!("<rpc-reply><{key}>FAKEleak{key}</{key}></rpc-reply>");
            let got = redact_xml(&xml).unwrap();
            let leak = format!("FAKEleak{key}");
            assert!(!got.contains(&leak), "key {key:?} leaked: {got}");
        }
    }

    #[test]
    fn unrelated_elements_are_untouched() {
        let xml = "<host><name>r1.example.net</name></host>";
        let got = redact_xml(xml).unwrap();
        assert_eq!(got, xml);
    }

    #[test]
    fn malformed_xml_is_refused_not_shipped_unredacted() {
        assert!(redact_xml("<unclosed><secret>oops").is_err());
    }

    #[test]
    fn prose_mention_of_a_denylisted_word_is_untouched() {
        let line = "Note: the secret to success is consistent testing.";
        assert_eq!(redact_log_text(line), line);
    }

    #[test]
    fn substring_of_a_denylisted_word_is_untouched() {
        let line = "The secretary updated the community-board listing today";
        assert_eq!(redact_log_text(line), line);
    }

    #[test]
    fn qualified_quoted_pre_shared_key_is_redacted() {
        let line = r#"set security ike policy p pre-shared-key ascii-text "$9$abcDEF123""#; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$abcDEF123"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        assert!(got.contains("pre-shared-key"), "got: {got}");
        assert!(got.contains("ascii-text"), "got: {got}");
    }

    #[test]
    fn bare_value_on_set_statement_is_redacted() {
        let got = redact_log_text("set snmp community privateRO");
        assert!(!got.contains("privateRO"), "got: {got}");
    }

    #[test]
    fn semicolon_terminated_community_is_redacted() {
        let got = redact_log_text("    community s3cr3tCommunity;");
        assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
        assert!(got.trim_end().ends_with(';'), "got: {got}");
    }

    #[test]
    fn bare_junos_hash_is_redacted() {
        let got = redact_log_text("encrypted-password $6$saltsalt$hashhashhash");
        assert!(!got.contains("$6$saltsalt$hashhashhash"), "got: {got}");
    }

    #[test]
    fn hmac_key_equals_form_is_redacted() {
        let got = redact_log_text("hmac-key=deadbeefcafe1234");
        assert!(!got.contains("deadbeefcafe1234"), "got: {got}");
        assert!(got.contains("hmac-key="), "got: {got}");
    }

    #[test]
    fn newline_structure_is_preserved_across_lines() {
        let input = "ts=1 user=admin action=login\nset security ike policy p pre-shared-key ascii-text \"$9$leakme\"\nts=2 user=admin action=logout\n"; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(input);
        assert!(!got.contains("$9$leakme"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        assert!(got.contains("action=login"), "got: {got}");
        assert!(got.contains("action=logout"), "got: {got}");
        assert_eq!(got.lines().count(), 3, "got: {got}");
    }

    #[test]
    fn tech_support_output_text_is_redacted() {
        let tech_support = "Hostname: srx1\nset security ike policy p1 pre-shared-key ascii-text \"$9$leakedPSK\";\nset snmp community privateRO;\n"; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(tech_support);
        assert!(!got.contains("leakedPSK"), "got: {got}");
        assert!(!got.contains("privateRO"), "got: {got}");
    }

    #[test]
    fn midline_set_statement_in_a_cmdline_echo_is_redacted() {
        let line = "Jun  5 12:00:00 host mgd[123]: UI_CMDLINE_READ_LINE: User 'admin', \
                    command 'load-configuration rpc rpc ... set snmp community SMOKE89LEAK \
                    authorization read-only'";
        let got = redact_log_text(line);
        assert!(!got.contains("SMOKE89LEAK"), "got: {got}");
    }

    #[test]
    fn curly_brace_config_block_value_is_redacted() {
        let got = redact_log_text("    community s3cr3tCommunity {\n");
        assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
        assert!(got.trim_end().ends_with('{'), "got: {got}");
    }

    #[test]
    fn cli_text_embedded_in_xml_without_an_output_wrapper_is_scrubbed() {
        let xml = "<rpc-reply>set snmp community leakedXML;\n</rpc-reply>";
        let got = redact_log_artefact(xml).unwrap();
        assert!(!got.contains("leakedXML"), "got: {got}");
    }

    #[test]
    fn non_xml_text_still_goes_through_the_log_text_floor() {
        let text = "Hostname: srx1\nset snmp community leakedBad;\n";
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("leakedBad"), "got: {got}");
    }

    // ── whether a non-XML-shaped artefact gets the full redaction floor
    // must not depend on incidental byte content elsewhere in the file;
    // these cases exercise secret shapes that this module's own closed,
    // whole-word key list does not cover on its own. ────────────────────

    #[test]
    fn colon_form_password_with_a_stray_ampersand_elsewhere_is_redacted() {
        let text = "httpd: login password: FAKEcolonPass && ok";
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEcolonPass"), "got: {got}");
    }

    #[test]
    fn json_form_password_with_a_stray_ampersand_elsewhere_is_redacted() {
        let text = r#"jweb: a & b {"password":"FAKEjsonPass"}"#;
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEjsonPass"), "got: {got}");
    }

    #[test]
    fn uppercase_set_statement_with_a_stray_ampersand_elsewhere_is_redacted() {
        let text = "a & b\nSET SNMP COMMUNITY FAKEUpperCase";
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEUpperCase"), "got: {got}");
    }

    #[test]
    fn unqualified_bare_pre_shared_key_with_a_stray_ampersand_elsewhere_is_redacted() {
        let text = "a & b\npre-shared-key FAKEUnqualifiedPsk";
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEUnqualifiedPsk"), "got: {got}");
    }

    #[test]
    fn pem_private_key_block_with_a_stray_ampersand_elsewhere_is_redacted() {
        let text = "a & b\n-----BEGIN RSA PRIVATE KEY-----\nFAKEbase64PemBody\n-----END RSA PRIVATE KEY-----\n"; // gitleaks:allow -- fabricated PEM fixture, not a real key
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEbase64PemBody"), "got: {got}");
    }

    // ── non-XML-shaped text must not be routed through the XML pass at
    // all, since that pass XML-escapes and normalises the output —
    // corrupting a support-bundle log file that happens to parse as
    // all-text XML. ───────────────────────────────────────────────────

    #[test]
    fn non_xml_shaped_text_is_not_xml_escaped_even_when_it_would_parse_as_xml() {
        let text = r#"user said "hi" it's fine"#;
        let got = redact_log_artefact(text).unwrap();
        assert_eq!(got, text, "got: {got}");
    }

    // ── a raw syslog line with a PRI prefix (`<NNN>`) is not XML-shaped
    // and must not be refused by the fail-closed XML path. ─────────────

    #[test]
    fn syslog_pri_prefixed_line_is_not_refused() {
        let text = "<134>Oct 2 mgd: set snmp community FAKEsyslogPri";
        let got = redact_log_artefact(text).unwrap();
        assert!(!got.contains("FAKEsyslogPri"), "got: {got}");
    }

    // ── crypt-hash floor in `redact_log_text`: a `$9$...`-shaped value is
    // redacted whatever key precedes it, or with no preceding key at all. ──

    #[test]
    fn hash_after_a_key_not_on_the_closed_list_is_redacted() {
        let line = r#"set snmp v3 usm local-engine user u1 privacy-aes128 privacy-key "$9$FAKEaes128priv""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$FAKEaes128priv"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_after_a_compound_key_hyphen_joined_to_an_unlisted_word_is_redacted() {
        let line = r#"set protocols isis interface ge-0/0/0.0 level 2 hello-authentication-key "$9$FAKEisisHello""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$FAKEisisHello"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_after_firewall_user_password_is_redacted() {
        let line = r#"set access profile p1 client c1 firewall-user password "$9$FAKEfwUserPw""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$FAKEfwUserPw"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_after_ppp_chap_and_pap_secret_keys_is_redacted() {
        let chap = r#"set interfaces ge-0/0/0 unit 0 ppp-options chap default-chap-secret "$9$FAKEchapSecret""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got_chap = redact_log_text(chap);
        assert!(!got_chap.contains("$9$FAKEchapSecret"), "got: {got_chap}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key

        let pap =
            r#"set interfaces ge-0/0/1 unit 0 ppp-options pap local-password "$9$FAKEpapSecret""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got_pap = redact_log_text(pap);
        assert!(!got_pap.contains("$9$FAKEpapSecret"), "got: {got_pap}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn bare_hash_token_with_no_preceding_key_is_redacted() {
        let line = "unexpected diagnostic dump: $9$FAKEbareToken follows no known key"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$FAKEbareToken"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    // ── when `redact_xml` cannot parse XML-shaped input, the caller refuses
    // the artefact instead of falling back to a weaker pass. ───────────────

    #[test]
    fn truncated_xml_missing_closing_tags_is_refused() {
        let bad = "<configuration><snmp><community><name>FAKEcommunity</name>"; // gitleaks:allow -- fabricated fixture, not a real community string
        assert!(redact_log_artefact(bad).is_err());
    }

    #[test]
    fn truncated_xml_around_an_encrypted_password_is_refused() {
        let bad = "<system><root-authentication><encrypted-password>$6$FAKEsalt$FAKEhash</encrypted-password>"; // gitleaks:allow -- fabricated Junos $6$ fixture, not a real hash
        assert!(redact_log_artefact(bad).is_err());
    }

    #[test]
    fn truncated_xml_around_a_pre_shared_key_is_refused() {
        let bad = "<pre-shared-key><ascii-text>FAKEplainpsk</ascii-text>"; // gitleaks:allow -- fabricated fixture, not a real key
        assert!(redact_log_artefact(bad).is_err());
    }

    #[test]
    fn well_formed_xml_with_an_unresolvable_entity_is_refused() {
        let bad = "<configuration>&nbsp;<snmp><community><name>FAKEcommunity</name></community></snmp></configuration>"; // gitleaks:allow -- fabricated fixture, not a real community string
        assert!(redact_log_artefact(bad).is_err());
    }

    #[test]
    fn a_bare_unescaped_angle_bracket_in_text_is_refused() {
        let bad = "<community><name>FAKEcommunity</name></community> < more text"; // gitleaks:allow -- fabricated fixture, not a real community string
        assert!(redact_log_artefact(bad).is_err());
    }

    // ── a quoted value with an escaped quote is redacted in full, and an
    // unterminated quote does not consume the line terminator. ─────────────

    #[test]
    fn quoted_value_with_an_escaped_quote_is_fully_redacted() {
        let line = r#"set security ike policy p pre-shared-key ascii-text "ab\"FAKEtail""#; // gitleaks:allow -- fabricated fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEtail"), "got: {got}");
        assert!(!got.contains("ab\\\""), "got: {got}");
    }

    #[test]
    fn unterminated_quote_does_not_merge_with_the_next_line() {
        let input = "set security ike policy p pre-shared-key ascii-text \"FAKEunterminated\nnext line user=admin action=login\n";
        let got = redact_log_text(input);
        assert_eq!(got.lines().count(), 2, "got: {got}");
        assert!(got.contains("action=login"), "got: {got}");
    }

    // ── the crypt-hash floor fires at a structured (non-whitespace)
    // delimiter, not only at whitespace/quote/angle-bracket boundaries. ────

    #[test]
    fn hash_after_equals_sign_with_no_space_is_redacted() {
        let got = redact_log_text("foo=$9$FAKEequalsForm"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        assert!(!got.contains("$9$FAKEequalsForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_after_colon_with_no_space_is_redacted() {
        let got = redact_log_text("key:$9$FAKEcolonForm"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        assert!(!got.contains("$9$FAKEcolonForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_inside_parentheses_is_redacted() {
        let got = redact_log_text("rollback diff (hash:$9$FAKEparenForm)"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        assert!(!got.contains("$9$FAKEparenForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_between_commas_in_a_csv_line_is_redacted() {
        let got = redact_log_text("field1,$9$FAKEcsvForm,field3"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        assert!(!got.contains("$9$FAKEcsvForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_inside_square_brackets_is_redacted() {
        let got = redact_log_text("tags=[$9$FAKEbracketForm]"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        assert!(!got.contains("$9$FAKEbracketForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    #[test]
    fn hash_preceded_by_a_non_breaking_space_is_redacted() {
        let line = "diagnostic:\u{a0}$9$FAKEnbspForm"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$FAKEnbspForm"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    }

    // ── compound keys not on the closed `REDACT_LOG_KEYS` list are still
    // redacted in `set` context when their final segment is sensitive. ─────

    #[test]
    fn plain_text_password_value_key_is_redacted() {
        let got = redact_log_text(
            "set system root-authentication plain-text-password-value FAKEplaintextRoot",
        );
        assert!(!got.contains("FAKEplaintextRoot"), "got: {got}");
    }

    #[test]
    fn unlisted_compound_key_ending_in_secret_is_redacted_in_set_context() {
        let got = redact_log_text("set system services oauth client-app-secret FAKEoauthSecret");
        assert!(!got.contains("FAKEoauthSecret"), "got: {got}");
    }

    #[test]
    fn unlisted_compound_key_ending_in_password_value_is_redacted_in_set_context() {
        let got = redact_log_text("set system login user u1 vault-password-value FAKEvaultValue");
        assert!(!got.contains("FAKEvaultValue"), "got: {got}");
    }

    #[test]
    fn prose_mention_of_a_compound_secret_looking_word_without_set_context_is_untouched() {
        let line = "Note: the database-password field was rotated by the admin team today";
        assert_eq!(redact_log_text(line), line);
    }

    // ── a `set` statement echoed with a quote glued to the token still
    // establishes set context. ───────────────────────────────────────────

    #[test]
    fn quoted_set_token_in_a_cmdline_echo_establishes_set_context_for_a_closed_list_key() {
        let line = "UI_CMDLINE_READ_LINE: User 'u', command 'set snmp community FAKEcomm authorization read-only'";
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEcomm"), "got: {got}");
    }

    #[test]
    fn quoted_set_token_in_a_cmdline_echo_establishes_set_context_for_a_hyphenated_key() {
        let line = "… command 'set protocols bgp group g authentication-key FAKEbgp'"; // gitleaks:allow -- fabricated fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEbgp"), "got: {got}");
    }

    #[test]
    fn quoted_set_token_in_a_cmdline_echo_establishes_set_context_for_a_compound_suffix_key() {
        let line = "… command 'set system root-authentication plain-text-password-value FAKEa'";
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEa"), "got: {got}");
    }

    #[test]
    fn quoted_set_token_in_a_cmdline_echo_establishes_set_context_for_privacy_key() {
        let line =
            "… command 'set snmp v3 usm local-engine user u1 privacy-aes128 privacy-key FAKEc'"; // gitleaks:allow -- fabricated fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEc"), "got: {got}");
    }

    #[test]
    fn quoted_set_token_in_a_cmdline_echo_establishes_set_context_for_an_unlisted_compound_key() {
        let line = "… command 'set system foo-auth-password FAKEb'";
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEb"), "got: {got}");
    }

    #[test]
    fn set_token_with_a_quote_glued_directly_to_it_in_a_structured_audit_line_establishes_set_context()
     {
        let line = r#"audit: cmd="set snmp community FAKEstructured""#;
        let got = redact_log_text(line);
        assert!(!got.contains("FAKEstructured"), "got: {got}");
    }

    #[test]
    fn session_keyword_elements_pass_through_without_truncating_the_document() {
        let xml = "<configuration><security><screen><ids-option><name>s1</name>\
<limit-session><source-ip-based>100</source-ip-based>\
<destination-ip-based>200</destination-ip-based></limit-session></ids-option></screen>\
<policies><policy><name>p</name><then><log><session-init/><session-close/></log>\
<permit/></then></policy></policies></security></configuration>";
        let got = redact_xml(xml).unwrap();
        assert_eq!(got, xml);
    }

    #[test]
    fn session_keyword_element_with_pretty_printed_whitespace_is_kept() {
        let xml = "<limit-session>\n  <source-ip-based>100</source-ip-based>\n</limit-session>";
        assert_eq!(redact_xml(xml).unwrap(), xml);
    }

    #[test]
    fn non_numeric_text_under_a_session_keyword_element_is_still_redacted() {
        let got = redact_xml("<session-init>FAKEtoken123</session-init>").unwrap();
        assert!(!got.contains("FAKEtoken123"), "got: {got}");
        let got = redact_xml("<limit-session>FAKEtoken123</limit-session>").unwrap();
        assert!(!got.contains("FAKEtoken123"), "got: {got}");
    }

    #[test]
    fn secrets_nested_in_a_session_keyword_element_are_still_redacted() {
        let got = redact_xml(
            "<limit-session><password>FAKEpw</password><secret>FAKEs</secret></limit-session>",
        )
        .unwrap();
        assert!(
            !got.contains("FAKEpw") && !got.contains("FAKEs"),
            "got: {got}"
        );
    }

    #[test]
    fn real_session_elements_are_still_redacted() {
        for xml in [
            "<session>FAKEsess1</session>",
            "<session-id>FAKEsess1</session-id>",
            "<session-token>FAKEsess1</session-token>",
            "<session-key>FAKEsess1</session-key>",
            "<session-count>FAKEsess1</session-count>",
            "<session><token>FAKEsess1</token></session>",
        ] {
            let got = redact_xml(xml).unwrap();
            assert!(!got.contains("FAKEsess1"), "{xml} -> {got}");
        }
    }

    #[test]
    fn json_session_keywords_pass_through_with_benign_values() {
        let mut v = serde_json::json!({
            "limit-session": {"source-ip-based": 100, "destination-ip-based": "200"},
            "then": {"log": {"session-init": [null], "session-close": [null]}},
            "after": "kept"
        });
        let want = v.clone();
        redact_json_value(&mut v);
        assert_eq!(v, want);
    }

    #[test]
    #[allow(clippy::indexing_slicing)]
    fn json_session_keyword_with_secret_content_is_still_redacted() {
        let mut v = serde_json::json!({"limit-session": "FAKEabc"});
        redact_json_value(&mut v);
        assert_eq!(v["limit-session"], "[REDACTED]");
        let mut v = serde_json::json!({"limit-session": {"password": "FAKEpw"}});
        redact_json_value(&mut v);
        assert_eq!(v["limit-session"]["password"], "[REDACTED]");
        let mut v = serde_json::json!({"limit-session": {"note": "FAKEabc"}});
        redact_json_value(&mut v);
        assert_eq!(v["limit-session"]["note"], "[REDACTED]");
    }

    #[test]
    #[allow(clippy::indexing_slicing)]
    fn json_real_session_keys_are_still_redacted() {
        for key in [
            "session",
            "session-id",
            "session-token",
            "session-key",
            "session-count",
        ] {
            let mut v = serde_json::json!({ key: "FAKEsess1" });
            redact_json_value(&mut v);
            assert_eq!(v[key], "[REDACTED]", "{key}");
        }
        let mut v = serde_json::json!({"limit-session": {"session-id": 4242}});
        redact_json_value(&mut v);
        assert_eq!(v["limit-session"]["session-id"], "[REDACTED]");
    }
}
