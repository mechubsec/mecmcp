//! Acceptance criterion: "A property test shows that no fixture secret
//! survives redaction."
//!
//! This enumerates the whole finite state space it claims to cover — every
//! entry in [`mecmcp_redact::denylist::DENYLISTED_KEYS`] crossed with every
//! wire format, plus every value shape crossed with every format under a
//! field name that is on no list at all — rather than sampling it, the way a
//! `proptest`-style generator would. For a state space this small and this
//! enumerable, exhaustive coverage is a strictly stronger guarantee than
//! random sampling, and it does not add a new dependency to a crate whose own
//! job is minimizing what a supply-chain audit has to look at.
//!
//! Every fixture secret is a unique token so a failure names exactly which
//! `(key_or_shape, format)` pair leaked, instead of a generic "some secret
//! somewhere" failure.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::denylist::{DENYLISTED_EXACT_KEYS, DENYLISTED_KEYS};
use mecmcp_redact::{redact_json_str, redact_text, redact_xml_str};

#[derive(Clone, Copy)]
enum Format {
    Json,
    Xml,
    Text,
}

const FORMATS: &[Format] = &[Format::Json, Format::Xml, Format::Text];

/// Value-shape fixtures under a field name (`zz_unlisted_field`) that is not,
/// and normalizes to nothing that is, on [`DENYLISTED_KEYS`].
const SHAPE_FIXTURES: &[&str] = &[
    "$9$fakesaltfakehashvalueA",
    "AKKgtu07M3XlnBEEmH0OZ1YkKl9-AQ==",
    "ENC(fakeciphertextB==)",
];

fn render(field: &str, secret: &str, format: Format) -> String {
    match format {
        Format::Json => format!(r#"{{"{field}": "{secret}"}}"#),
        Format::Xml => format!("<{field}>{secret}</{field}>"),
        Format::Text => format!("{field}: {secret}"),
    }
}

fn redact(input: &str, format: Format) -> String {
    match format {
        Format::Json => redact_json_str(input).unwrap(),
        Format::Xml => redact_xml_str(input).unwrap(),
        Format::Text => redact_text(input),
    }
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Json => "json",
        Format::Xml => "xml",
        Format::Text => "text",
    }
}

#[test]
fn no_denylisted_key_fixture_secret_survives_any_format() {
    for (i, key) in DENYLISTED_KEYS.iter().enumerate() {
        // `DENYLISTED_KEYS` entries are already normalized (lowercase,
        // alphanumeric only), so using one directly as the field name means
        // it normalizes right back to itself.
        let field = *key;
        for &format in FORMATS {
            let secret = format!("QQZZ{i:04}{}", format_name(format));
            let input = render(field, &secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(&secret),
                "denylisted key '{key}' (field '{field}') leaked in {}",
                format_name(format)
            );
        }
    }
}

/// F5 (MEC-537 review): the exact-match entries get no coverage from the
/// substring sweep above, since a key that merely contains one (`keyword`,
/// `monkey`) must *not* match it. Render each exact entry as the literal,
/// bare field name instead.
#[test]
fn no_denylisted_exact_key_fixture_secret_survives_any_format() {
    for (i, key) in DENYLISTED_EXACT_KEYS.iter().enumerate() {
        let field = *key;
        for &format in FORMATS {
            let secret = format!("QQZZEXACT{i:04}{}", format_name(format));
            let input = render(field, &secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(&secret),
                "exact-match key '{key}' (field '{field}') leaked in {}",
                format_name(format)
            );
        }
    }
}

/// Real, hyphenated multi-word vendor spellings of denylist terms.
///
/// N6 / MEC-121 F1: the previous version of this test rendered
/// `hyphenate(DENYLISTED_KEYS[i])`, but every entry in
/// [`DENYLISTED_KEYS`] is already normalized down to a single run of
/// alphanumerics with no `_` for `hyphenate` to swap — so it rendered the
/// exact same already-normalized field name as the first property test above
/// (`presharedkey`, not `pre-shared-key`), making it redundant rather than a
/// distinct hyphenated-spelling check. It also always suffixed a digit index
/// onto the fake secret, which coincidentally never exercised the N1 "digit
/// free value" tokenizer bug even where that bug did apply. This table names
/// the actual hyphenated forms a vendor CLI uses, and the accompanying test
/// renders the TEXT case in bare `key value` form with a digit-free secret,
/// which is exactly the shape that triggers N1.
const VENDOR_SPELLINGS: &[&str] = &[
    "pre-shared-key",
    "private-key",
    "api-key",
    "authentication-key",
    "shared-secret",
    "bind-pw",
    "encryption-key",
    "x-passphrase",
];

fn alpha_letter(i: usize) -> char {
    (b'a' + u8::try_from(i).expect("VENDOR_SPELLINGS is well under 26 entries")) as char
}

#[test]
fn no_denylisted_key_fixture_secret_survives_any_format_in_its_hyphenated_vendor_spelling() {
    for (i, hyphenated) in VENDOR_SPELLINGS.iter().enumerate() {
        for &format in FORMATS {
            // Deliberately all-alphabetic, no digits: the exhaustive test
            // above always suffixes a digit index onto its fake secret,
            // which happens to mask the N1 "type keyword" heuristic bug in
            // the text tokenizer — a digit-free secret is exactly the shape
            // a real SNMP community string or weak PSK takes.
            let secret = format!("QQvendorspell{}{}", alpha_letter(i), format_name(format));
            let input = match format {
                // Bare `key value trailing` form, the shape N1's bug
                // actually reaches (the `key=`/`key:` forms tested by
                // `render` don't go through the same "value or type
                // keyword?" branch).
                Format::Text => format!("{hyphenated} {secret} trailing"),
                Format::Json | Format::Xml => render(hyphenated, &secret, format),
            };
            let got = redact(&input, format);
            assert!(
                !got.contains(&secret),
                "vendor-spelled key '{hyphenated}' leaked in {}",
                format_name(format)
            );
        }
    }
}

#[test]
fn no_value_shape_fixture_secret_survives_any_format_under_an_unlisted_key() {
    for (i, secret) in SHAPE_FIXTURES.iter().enumerate() {
        for &format in FORMATS {
            let field = "zz_unlisted_field";
            let input = render(field, secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(secret),
                "shape fixture #{i} leaked in {}",
                format_name(format)
            );
        }
    }
}
