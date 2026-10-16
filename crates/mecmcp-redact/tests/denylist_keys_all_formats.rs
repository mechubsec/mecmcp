//! Acceptance criterion: "unit tests for each denylist key ... in XML, JSON
//! and text form." One fixture generator per format, run against every key
//! named in the MEC-11 spec plus the aliases it explicitly calls out
//! (`private-key`/`private_key`, `x_passphrase`, `x_secret`).
//!
//! These do not touch `mecmcp_redact::policy` — every call here relies on the
//! crate's own default (`RedactionPolicy::Enabled`), so, unlike the
//! `policy_*` integration tests, there is nothing process-global at stake and
//! ordinary multi-threaded `cargo test` execution is fine.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{redact_json_str, redact_text, redact_xml_str};

/// `(spec key, a realistic spelling of it, a synthetic fake secret value)`.
///
/// The fake values are deliberately generic (`FAKEQWZX...`) rather than
/// echoing the key name (`FAKEsecretVALUE`): a value that happens to spell
/// out "secret" would still get redacted by the value-shape/text scan even if
/// the *key*-matching path being tested here were broken, silently masking
/// exactly that regression.
const SPEC_KEYS: &[(&str, &str, &str)] = &[
    ("secret", "secret", "QWZX7714900001"),
    ("private-key", "private_key", "QWZX7714900002"),
    ("pre-shared-key", "pre_shared_key", "QWZX7714900003"),
    ("psk", "psk", "QWZX7714900004"),
    ("passphrase", "passphrase", "QWZX7714900005"),
    ("x_passphrase", "x_passphrase", "QWZX7714900006"),
    ("x_secret", "x_secret", "QWZX7714900007"),
    ("phash", "phash", "QWZX7714900008"),
    ("community", "community", "QWZX7714900009"),
    ("api_key", "api_key", "QWZX7714900010"),
    ("token", "token", "QWZX7714900011"),
    ("authentication-key", "authentication_key", "QWZX7714900012"),
    ("password", "password", "QWZX7714900013"),
    // MEC-711: Mist OpenAPI secret fields missed by the denylist at the
    // rustmistmcp#137 pinned rev.
    ("auth_key", "auth_key", "QWZX7714900014"),
    ("auth_keys", "auth_keys", "QWZX7714900015"),
    ("keywrap_kek", "keywrap_kek", "QWZX7714900016"),
    ("keywrap_mack", "keywrap_mack", "QWZX7714900017"),
    ("partner_key", "partner_key", "QWZX7714900018"),
    ("account_key", "account_key", "QWZX7714900019"),
    ("ldap_client_key", "ldap_client_key", "QWZX7714900020"),
    (
        "openroaming_wba_client_key",
        "openroaming_wba_client_key",
        "QWZX7714900021",
    ),
];

#[test]
fn every_spec_key_is_redacted_in_json() {
    for (spec_key, field, secret) in SPEC_KEYS {
        let input = format!(r#"{{"{field}": "{secret}", "hostname": "r1.example.net"}}"#);
        let got = redact_json_str(&input).unwrap();
        assert!(
            !got.contains(secret),
            "spec key '{spec_key}' (field '{field}') leaked in JSON"
        );
        assert!(
            got.contains("r1.example.net"),
            "unrelated field must survive"
        );
    }
}

#[test]
fn every_spec_key_is_redacted_in_xml() {
    for (spec_key, field, secret) in SPEC_KEYS {
        let input = format!(
            "<config><{field}>{secret}</{field}><hostname>r1.example.net</hostname></config>"
        );
        let got = redact_xml_str(&input).unwrap();
        assert!(
            !got.contains(secret),
            "spec key '{spec_key}' (field '{field}') leaked in XML"
        );
        assert!(
            got.contains("r1.example.net"),
            "unrelated element must survive"
        );
    }
}

#[test]
fn every_spec_key_is_redacted_in_text() {
    for (spec_key, field, secret) in SPEC_KEYS {
        let input = format!("{field}: {secret}\nhostname: r1.example.net");
        let got = redact_text(&input);
        assert!(
            !got.contains(secret),
            "spec key '{spec_key}' (field '{field}') leaked in text"
        );
        assert!(
            got.contains("r1.example.net"),
            "unrelated line must survive"
        );
    }
}
