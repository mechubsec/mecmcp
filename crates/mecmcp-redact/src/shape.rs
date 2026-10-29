//! Value-shape catch-all: secrets that reach a tool result under a field name
//! nobody put on [`crate::denylist`] yet.
//!
//! Every vendor eventually ships a field the denylist has never heard of. The
//! shapes below are how a handful of encodings — crypt hashes, PAN-OS's
//! `-AQ==` suffixed blobs, `ENC`-prefixed ciphertext, PEM material, and
//! Junos's `## SECRET-DATA` marker — get caught anyway, independent of what
//! the surrounding key is called.

/// Whether `value` matches a known secret-value shape.
#[must_use]
pub fn looks_like_secret_value(value: &str) -> bool {
    is_crypt_hash(value)
        || contains_pan_aq_suffix(value)
        || is_enc_marker(value)
        || contains_pem_marker(value)
}

/// A PEM block header appearing anywhere in `value`: `-----BEGIN <TYPE>-----`.
/// Unlike [`is_pem_begin`], this matches mid-string (a PEM embedded in a JSON
/// string value or an XML text node carries the header inline, not as its own
/// trimmed line), so a PEM under any key — denylisted or not — is caught.
fn contains_pem_marker(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

/// Juniper/glibc crypt-style hash: `$<id>$<content>`, e.g. `$9$abC1EyKM8`.
///
/// `id` must be short and alphanumeric (real ids are one to a handful of
/// characters — `1`, `5`, `6`, `9`) and there must be content after the
/// second `$`. This over-matches things like `$100$` in ordinary prose; that
/// is the direction it is safe to be wrong in.
pub(crate) fn is_crypt_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'$') {
        return false;
    }
    let rest = &value[1..];
    let Some(second_dollar) = rest.find('$') else {
        return false;
    };
    let id = &rest[..second_dollar];
    if id.is_empty() || id.len() > 8 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let content = &rest[second_dollar + 1..];
    !content.is_empty()
}

/// PAN-OS encrypted-value convention: a base64-ish blob ending `-AQ==`.
fn contains_pan_aq_suffix(value: &str) -> bool {
    value.contains("-AQ==")
}

/// `ENC` marker prefix (e.g. `ENC(...)`, `ENC abcdef==`), followed by a
/// non-alphanumeric so ordinary words like `Encoding` never match — the
/// marker is upper-case `ENC` immediately followed by a delimiter.
pub(crate) fn is_enc_marker(value: &str) -> bool {
    let trimmed = value.trim_start();
    let Some(rest) = trimmed.strip_prefix("ENC") else {
        return false;
    };
    match rest.chars().next() {
        None => false,
        Some(c) => !c.is_ascii_alphanumeric(),
    }
}

/// Whether `value` looks like it carries an embedded secret-bearing blob (a
/// whole Junos `configuration-text` body, a command `<output>`, or a JSON
/// `"output"` string) rather than being a single secret-shaped scalar itself.
/// [`looks_like_secret_value`] only matches when the *entire* value has one
/// of the known shapes, so a multi-line blob with a `$9$` hash or a
/// `## SECRET-DATA` line buried inside otherwise-ordinary text needs this
/// separate check to be routed through `crate::text::redact` instead of
/// being passed through whole.
#[must_use]
pub fn looks_like_embedded_blob(value: &str) -> bool {
    value.contains('\n')
        || value.contains('$')
        || value.contains("-----BEGIN")
        || value.contains("SECRET-DATA")
}

/// Junos flat-config secret marker: a line carrying `## SECRET-DATA`.
#[must_use]
pub fn line_has_secret_data_marker(line: &str) -> bool {
    line.contains("## SECRET-DATA")
}

/// Whether `trimmed` opens a PEM block: `-----BEGIN <TYPE>-----`.
#[must_use]
pub fn is_pem_begin(trimmed: &str) -> bool {
    trimmed.starts_with("-----BEGIN ") && trimmed.ends_with("-----")
}

/// Whether `trimmed` closes a PEM block: `-----END <TYPE>-----`.
#[must_use]
pub fn is_pem_end(trimmed: &str) -> bool {
    trimmed.starts_with("-----END ") && trimmed.ends_with("-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypt_hash_shapes_match() {
        for v in ["$9$abC1EyKM8x", "$1$saltsalt$hashhash", "$6$rounds$xyz"] {
            assert!(looks_like_secret_value(v), "expected match: {v}");
        }
    }

    #[test]
    fn crypt_hash_requires_content_after_second_dollar() {
        assert!(!looks_like_secret_value("$9$"));
    }

    #[test]
    fn ordinary_text_is_not_a_crypt_hash() {
        assert!(!looks_like_secret_value("hello world"));
        assert!(!looks_like_secret_value("just a description"));
    }

    #[test]
    fn pan_os_aq_suffix_matches() {
        assert!(looks_like_secret_value("AKKgtu07M3XlnBEEmH0OZ1YkKl9-AQ=="));
    }

    #[test]
    fn enc_marker_matches_common_forms() {
        assert!(looks_like_secret_value("ENC(AES256-abcdef==)"));
        assert!(looks_like_secret_value("ENC abcdef1234=="));
        assert!(!looks_like_secret_value("Encoding is UTF-8"));
        assert!(!looks_like_secret_value("Encyclopedia"));
    }

    #[test]
    fn secret_data_marker_detected() {
        assert!(line_has_secret_data_marker(
            "pre-shared-key ascii-text \"$9$abc123\"; ## SECRET-DATA"
        ));
        assert!(!line_has_secret_data_marker("set interfaces ge-0/0/0"));
    }

    #[test]
    fn pem_marker_anywhere_in_value_is_a_secret_shape() {
        assert!(looks_like_secret_value(
            "-----BEGIN PRIVATE KEY-----\nMIIFAKE==\n-----END PRIVATE KEY-----"
        )); // gitleaks:allow -- fabricated PEM body, not a real key
        assert!(!looks_like_secret_value("hello world"));
    }

    #[test]
    fn pem_begin_and_end_detected() {
        assert!(is_pem_begin("-----BEGIN RSA PRIVATE KEY-----")); // gitleaks:allow -- bare PEM header, no key material
        assert!(is_pem_begin("-----BEGIN CERTIFICATE-----"));
        assert!(is_pem_end("-----END RSA PRIVATE KEY-----"));
        assert!(!is_pem_begin("not a pem line"));
        assert!(!is_pem_end("-----BEGIN CERTIFICATE-----"));
    }
}
