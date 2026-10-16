//! Acceptance criterion: "unit tests for each ... value shape, in XML, JSON
//! and text form." Every fixture here uses a field name
//! (`totally_new_vendor_field`) that is deliberately *not* on the denylist,
//! so a pass here can only be explained by the value-shape catch-all in
//! [`mecmcp_redact::shape`] — not by [`mecmcp_redact::denylist`].

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{redact_json_str, redact_text, redact_xml_str};

const UNKNOWN_FIELD: &str = "totally_new_vendor_field";

/// `(shape name, a fixture value carrying that shape)`.
const SHAPES: &[(&str, &str)] = &[
    ("crypt-hash", "$9$fakesaltfakehashvalue"),
    ("pan-os-aq-suffix", "AKKgtu07M3XlnBEEmH0OZ1YkKl9-AQ=="),
    ("enc-marker", "ENC(fakeciphertext==)"),
];

#[test]
fn every_value_shape_is_redacted_in_json_under_an_unlisted_key() {
    for (shape, value) in SHAPES {
        let input = format!(r#"{{"{UNKNOWN_FIELD}": "{value}"}}"#);
        let got = redact_json_str(&input).unwrap();
        assert!(
            !got.contains(value),
            "shape '{shape}' leaked in JSON: {got}"
        );
    }
}

#[test]
fn every_value_shape_is_redacted_in_xml_under_an_unlisted_element() {
    for (shape, value) in SHAPES {
        let input = format!("<{UNKNOWN_FIELD}>{value}</{UNKNOWN_FIELD}>");
        let got = redact_xml_str(&input).unwrap();
        assert!(!got.contains(value), "shape '{shape}' leaked in XML: {got}");
    }
}

#[test]
fn every_value_shape_is_redacted_in_text_under_an_unlisted_key() {
    for (shape, value) in SHAPES {
        let input = format!("{UNKNOWN_FIELD}: {value}");
        let got = redact_text(&input);
        assert!(
            !got.contains(value),
            "shape '{shape}' leaked in text: {got}"
        );
    }
}

#[test]
fn pem_block_is_redacted_in_text_under_an_unlisted_key() {
    let input = format!(
        "{UNKNOWN_FIELD}:\n-----BEGIN CERTIFICATE-----\nFAKEBASE64CERTBODY==\n-----END CERTIFICATE-----"
    );
    let got = redact_text(&input);
    assert!(!got.contains("FAKEBASE64CERTBODY=="), "got: {got}");
    assert!(got.contains("-----BEGIN CERTIFICATE-----"));
    assert!(got.contains("-----END CERTIFICATE-----"));
}

#[test]
fn f7_pem_marker_anywhere_in_value_is_redacted_under_an_unlisted_key() {
    let secret = "MIIFAKEBASE64==";
    // Fabricated base64 body ("FAKE"), not a real key.
    let json_pem = format!("-----BEGIN PRIVATE KEY-----\\n{secret}\\n-----END PRIVATE KEY-----"); // gitleaks:allow
    let json_input = format!(r#"{{"{UNKNOWN_FIELD}": "{json_pem}"}}"#);
    let got = redact_json_str(&json_input).unwrap();
    assert!(!got.contains(secret), "PEM leaked in JSON");

    let xml_pem = format!("-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----");
    let xml_input = format!("<{UNKNOWN_FIELD}>{xml_pem}</{UNKNOWN_FIELD}>");
    let got = redact_xml_str(&xml_input).unwrap();
    assert!(!got.contains(secret), "PEM leaked in XML");
}

#[test]
fn secret_data_marker_is_redacted_in_text_under_an_unlisted_key() {
    let input = format!(r#"{UNKNOWN_FIELD} "$9$fakehashvalue"; ## SECRET-DATA"#);
    let got = redact_text(&input);
    assert!(!got.contains("fakehashvalue"), "got: {got}");
    assert!(got.contains("## SECRET-DATA"));
}
