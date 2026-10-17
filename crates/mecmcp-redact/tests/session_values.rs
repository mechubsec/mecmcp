//! Value-aware handling of `session`-named configuration fields on the
//! structured (XML/JSON) paths, opt-in through a vendor `Profile`.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{Profile, redact_json_value_with_profile, redact_xml_str_with_profile};
use serde_json::json;

const ON: Profile = Profile::new(&[], &[]).with_session_config_values();
const OFF: Profile = Profile::new(&[], &[]);

const XML_CONFIG: &str = "<security><policies><policy><then><log>\
<session-init/><session-close/></log></then></policy></policies>\
<screen><ids-option><limit-session>\n  <source-ip-based>128</source-ip-based>\n\
<destination-ip-based>64</destination-ip-based></limit-session></ids-option></screen></security>";

#[test]
fn xml_config_samples_pass_through_when_opted_in() {
    let out = redact_xml_str_with_profile(XML_CONFIG, &ON).unwrap();
    assert_eq!(out, XML_CONFIG);
}

#[test]
fn xml_samples_stay_masked_without_the_profile_flag() {
    let out = redact_xml_str_with_profile(XML_CONFIG, &OFF).unwrap();
    assert!(out.contains("[REDACTED]"), "{out}");
}

#[test]
fn xml_counters_pass_but_non_integer_values_are_masked() {
    let out = redact_xml_str_with_profile(
        "<r><sessions-active>12</sessions-active><flow-session-count>7</flow-session-count></r>",
        &ON,
    )
    .unwrap();
    assert!(out.contains(">12<") && out.contains(">7<"), "{out}");
    let out = redact_xml_str_with_profile(
        "<r><sessions-active>tok3nValueABC</sessions-active></r>",
        &ON,
    )
    .unwrap();
    assert!(!out.contains("tok3nValueABC"), "{out}");
}

#[test]
fn xml_real_session_secrets_are_still_masked() {
    for doc in [
        "<r><session-id>123456</session-id></r>",
        "<r><session>123456</session></r>",
        "<r><session-token>abc</session-token></r>",
        "<r><session-key>99</session-key></r>",
        "<r><limit-session><password>hunter2xyz</password></limit-session></r>",
        "<r><limit-session><note>abcSecretValue</note></limit-session></r>",
        "<r><session-init>abcSecretValue</session-init></r>",
        "<r><session-init token=\"abcSecretValue\"/></r>",
    ] {
        let out = redact_xml_str_with_profile(doc, &ON).unwrap();
        for leak in ["123456", "abc", "hunter2xyz", "99"] {
            assert!(
                !out.contains(leak) || out.contains("[REDACTED]"),
                "{doc} -> {out}"
            );
        }
        assert!(out.contains("[REDACTED]"), "{doc} -> {out}");
    }
}

#[test]
fn json_config_samples_pass_through_when_opted_in() {
    let orig = json!({
        "then": {"log": {"session-init": null, "session-close": null}},
        "limit-session": {"source-ip-based": 128, "destination-ip-based": "64"},
        "sessions-active": 12
    });
    let mut v = orig.clone();
    redact_json_value_with_profile(&mut v, &ON);
    assert_eq!(v, orig);
    let mut v = orig.clone();
    redact_json_value_with_profile(&mut v, &OFF);
    assert_ne!(v, orig);
}

#[test]
fn json_real_session_secrets_are_still_masked() {
    let mut v = json!({
        "session-id": "123456", "session": 12345, "session_token": "abc",
        "sessions-active": "abcSecretValue",
        "limit-session": {"password": "hunter2xyz"}
    });
    redact_json_value_with_profile(&mut v, &ON);
    let s = v.to_string();
    for leak in ["123456", "12345", "abc\"", "abcSecretValue", "hunter2xyz"] {
        assert!(!s.contains(leak), "{leak} leaked: {s}");
    }
}
