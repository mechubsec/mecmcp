//! Tool-output redaction for mechub MCP servers.
//!
//! Every vendor MCP server eventually hands a device's raw config, a REST
//! response body, or a CLI dump back to the model as a tool result. That
//! output routinely carries the device's own secrets — PSKs, API tokens,
//! password hashes, private keys — because the vendor's own read APIs do not
//! distinguish "safe to show an operator" from "safe to show a model with no
//! duty of confidentiality." This crate is the boundary that makes that
//! distinction, applied once, the same way, by every server.
//!
//! # Two strategies, not one
//!
//! - [`projection`] — **allowlist-shaped**, for the handful of resource
//!   shapes a server fully controls (UniFi `list`/`get_resource`, SDC
//!   certificates). A [`projection::FieldAllowlist`] states which fields
//!   survive; everything else is dropped, known or not. This is the strong
//!   guarantee, and it only exists where a server bothers to declare one.
//! - `json`, `xml`, `text` — **denylist-and-shape**, for everything
//!   else: raw vendor JSON/XML/text passed through mostly as-is. A fixed key
//!   denylist (see [`denylist`]) catches known-sensitive field names under
//!   any of their common spellings; a value-shape catch-all (see [`shape`])
//!   catches secrets under field names nobody has denylisted yet. This is a
//!   best-effort net, not a guarantee — see the residual-risk section of the
//!   crate README.
//!
//! A server with vendor-specific exceptions to the denylist-and-shape scan —
//! a field that must be withheld as a whole rather than key/value scanned,
//! or a field name that collides with the denylist by substring but is not a
//! secret in that vendor's schema — declares a [`Profile`] and calls
//! [`redact_json_value_with_profile`] instead of [`redact_json_value`]. See
//! the [`profile`] module docs.
//!
//! # On by default, and not through a tool argument
//!
//! [`policy::active`] defaults to [`policy::RedactionPolicy::Enabled`]. The
//! only way to change that is [`policy::install`], which a server binary
//! calls at most once at startup from an operator CLI flag — never from a
//! tool call. None of [`redact_text`], [`redact_json_str`], or
//! [`redact_xml_str`] takes a "skip redaction" parameter; there is nothing in
//! their signatures a tool argument could thread through even if a handler
//! tried.
//!
//! # Redaction removes bytes; `Untrusted` marks the rest
//!
//! Everything above is about *what* a model may see. [`Untrusted`] is about
//! *how it's told apart* once it does: it wraps a device/controller-sourced
//! value so it cannot reach [`Untrusted::render_tagged`]'s delimited
//! rendering — the sanctioned way to fold device text into a tool result —
//! without first being marked as untrusted at the point it left the vendor
//! response. See the [`trust`] module docs for what that wrapping does and
//! does not guarantee.
//!
//! # Fingerprints are computed before redaction, and keyed
//!
//! [`redact_and_digest`] computes an HMAC-SHA256 fingerprint over the
//! original bytes, under a per-install key the caller supplies and the model
//! never sees. See the [`digest`] module for why change detection breaks if
//! the digest runs on redacted text, why it must be keyed rather than a
//! plain content hash, and why [`redact_and_digest`] is the only place that
//! order and that key ever meet.

pub mod denylist;
pub mod digest;
mod json;
pub mod junos;
mod junos_session;
pub mod policy;
pub mod profile;
pub mod projection;
pub mod shape;
pub mod testing;
mod text;
pub mod trust;
mod xml;

pub use policy::{RedactionPolicy, active, install};
pub use profile::Profile;
pub use trust::Untrusted;

/// A tool-output body's wire format, so [`redact_and_digest`] knows which
/// unstructured redactor to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Line-oriented plain text (CLI output, flat config dumps).
    Text,
    /// A JSON document.
    Json,
    /// An XML document (NETCONF replies, XML REST responses).
    Xml,
}

/// A tool output could not be redacted.
#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    /// `redact_json_str` was given input that does not parse as JSON.
    #[error("input is not valid JSON, refusing to guess: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// `redact_xml_str` (or [`redact_and_digest`] with [`Format::Xml`]) was
    /// given input that does not parse as XML.
    #[error("input is not well-formed XML, refusing to guess: {0}")]
    InvalidXml(String),
    /// [`redact_and_digest`] was given a `digest_key` shorter than
    /// [`MIN_DIGEST_KEY_LEN`] bytes. An empty or low-entropy key makes the
    /// HMAC fingerprint effectively public, restoring the guessing oracle
    /// keying the digest exists to close — see the [`digest`] module docs.
    #[error(
        "digest key is {0} bytes, at least {MIN_DIGEST_KEY_LEN} are required to keep the HMAC \
         fingerprint from being a guessing oracle for low-entropy secrets"
    )]
    WeakDigestKey(usize),
}

/// The minimum acceptable length, in bytes, for the `digest_key` passed to
/// [`redact_and_digest`]. Below this, the key no longer supplies enough
/// entropy to keep the paired digest from being replayable offline against
/// candidate low-entropy secrets (an SNMP community string, a short PSK).
pub const MIN_DIGEST_KEY_LEN: usize = 32;

/// Redact unstructured plain text. Always succeeds — there is no parse step
/// to fail on free-form text — and passes input through unchanged when
/// [`policy::active`] is [`RedactionPolicy::DisabledByOperator`].
#[must_use]
pub fn redact_text(input: &str) -> String {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return input.to_string();
    }
    text::redact(input)
}

/// Parse `input` as JSON, redact it, and re-serialize.
///
/// # Errors
/// Returns [`RedactError::InvalidJson`] when `input` does not parse. This
/// crate never falls back to returning unparseable input verbatim — an
/// unparseable body might still contain a secret this function was never
/// asked to find a way around finding.
pub fn redact_json_str(input: &str) -> Result<String, RedactError> {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        // Still validated: a disabled-redaction passthrough must not become a
        // way to skip the "this is valid JSON" check callers rely on.
        let _: serde_json::Value = serde_json::from_str(input)?;
        return Ok(input.to_string());
    }
    let mut value: serde_json::Value = serde_json::from_str(input)?;
    json::redact(&mut value);
    Ok(serde_json::to_string(&value).expect("a redacted Value always re-serializes"))
}

/// Redact a JSON value in place. Unlike [`redact_json_str`] this cannot fail
/// — the caller already has a parsed value — so it is the better entry point
/// for a server that parses the vendor response itself.
pub fn redact_json_value(value: &mut serde_json::Value) {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return;
    }
    json::redact(value);
}

/// Redact a JSON value in place under [`redact_json_value`]'s generic
/// denylist-and-shape scan, extended by `profile`'s vendor-specific
/// wholesale-field and key-exemption rules. See the [`profile`] module docs
/// for why those two rules need a declared profile rather than living in the
/// generic scan.
pub fn redact_json_value_with_profile(value: &mut serde_json::Value, profile: &Profile) {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return;
    }
    profile::redact_json_value_with_profile(value, profile);
}

/// Redact an XML document.
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] when `input` does not parse as XML.
pub fn redact_xml_str(input: &str) -> Result<String, RedactError> {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        // Same validate-without-redact contract as `redact_json_str`, and
        // the same well-formedness check `xml::redact` itself enforces
        // (N7) — a disabled policy must not become a way to skip the "this
        // is valid XML" check callers rely on.
        xml::validate(input)?;
        return Ok(input.to_string());
    }
    xml::redact(input)
}

/// Redact an XML document under [`redact_xml_str`]'s generic scan, extended
/// by `profile`'s BGP route-community exemption when it opts in via
/// [`Profile::with_bgp_route_communities`]. `profile`'s
/// `wholesale_redact_keys` and `key_exemptions` are JSON-only fields and are
/// not consulted here — see the [`profile`] module docs.
///
/// # Errors
/// Same as [`redact_xml_str`].
pub fn redact_xml_str_with_profile(input: &str, profile: &Profile) -> Result<String, RedactError> {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        xml::validate(input)?;
        return Ok(input.to_string());
    }
    xml::redact_with_profile(input, profile)
}

/// The result of [`redact_and_digest`]: the redacted body, and a fingerprint
/// of the *original* body it was computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedOutput {
    /// `hmac-sha256:<hex>` over the unredacted input, keyed by the
    /// `digest_key` passed to [`redact_and_digest`].
    pub digest: String,
    /// The redacted body, in the same format it was given in.
    pub redacted: String,
}

/// Digest the original bytes under `digest_key`, then redact them, and hand
/// back both.
///
/// This is the recommended entry point for a server wiring redaction into a
/// tool-output path that also needs a fingerprint: it makes "digest the
/// unredacted data, keyed" the only order and shape reachable through the
/// API, rather than two separate calls a future edit could accidentally
/// reorder or a plain unkeyed hash a future edit could accidentally swap in.
///
/// `digest_key` must be a per-install secret the model never sees — see the
/// [`digest`] module docs for why an unkeyed digest paired with the redacted
/// body is a guessing oracle for low-entropy secrets. This function has no
/// opinion on where the key comes from; a typical caller loads it once at
/// startup the same way `mecmcp_audit::redact`'s own `--audit-hmac-key-file`
/// does, and passes the same bytes on every call so change detection keeps
/// working across polls.
///
/// # Errors
/// Returns [`RedactError::InvalidJson`] or [`RedactError::InvalidXml`] per
/// `format`, for the same reasons [`redact_json_str`] and [`redact_xml_str`]
/// do. [`Format::Text`] never fails for those reasons.
///
/// Returns [`RedactError::WeakDigestKey`] when `digest_key` is shorter than
/// [`MIN_DIGEST_KEY_LEN`] bytes, regardless of `format` — an empty or
/// constant key is rejected rather than silently accepted (N8).
pub fn redact_and_digest(
    raw: &str,
    format: Format,
    digest_key: &[u8],
) -> Result<RedactedOutput, RedactError> {
    if digest_key.len() < MIN_DIGEST_KEY_LEN {
        return Err(RedactError::WeakDigestKey(digest_key.len()));
    }
    let digest = digest::digest_hex(digest_key, raw.as_bytes());
    let redacted = match format {
        Format::Text => redact_text(raw),
        Format::Json => redact_json_str(raw)?,
        Format::Xml => redact_xml_str(raw)?,
    };
    Ok(RedactedOutput { digest, redacted })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    /// Deterministic 32-byte test key derived from `seed`, so no key material
    /// is embedded as a literal.
    fn test_key(seed: u8) -> Vec<u8> {
        (0..32u8)
            .map(|index| index.wrapping_mul(seed).wrapping_add(seed))
            .collect()
    }

    fn digest_key() -> Vec<u8> {
        test_key(7)
    }

    #[test]
    fn redact_and_digest_digest_matches_direct_digest_of_raw_input() {
        let raw = r#"{"password": "FAKEsupersecret123", "hostname": "r1.example.net"}"#;
        let out = redact_and_digest(raw, Format::Json, &digest_key()).unwrap();
        assert_eq!(
            out.digest,
            digest::digest_hex(&digest_key(), raw.as_bytes())
        );
        assert!(!out.redacted.contains("FAKEsupersecret123"));
    }

    /// F8: pairing the redacted body with an *unkeyed* digest of the
    /// original is a guessing oracle for low-entropy secrets. Different
    /// install keys over the same raw input must disagree.
    #[test]
    fn redact_and_digest_digest_depends_on_the_key() {
        let raw = r#"{"community": "FAKEcommunity123"}"#;
        let a = redact_and_digest(raw, Format::Json, &test_key(1)).unwrap();
        let b = redact_and_digest(raw, Format::Json, &test_key(2)).unwrap();
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn redact_and_digest_rejects_malformed_json_rather_than_guessing() {
        let err = redact_and_digest("{not json", Format::Json, &digest_key()).unwrap_err();
        assert!(matches!(err, RedactError::InvalidJson(_)));
    }

    #[test]
    fn redact_and_digest_rejects_malformed_xml_rather_than_guessing() {
        let err = redact_and_digest("<unclosed>", Format::Xml, &digest_key()).unwrap_err();
        assert!(matches!(err, RedactError::InvalidXml(_)));
    }

    /// N8: an empty (or otherwise too-short) digest key must be rejected —
    /// accepting it would restore the F8 unkeyed-digest guessing oracle for
    /// low-entropy secrets in all but name.
    #[test]
    fn redact_and_digest_rejects_an_empty_digest_key() {
        let err = redact_and_digest("hello", Format::Text, &Vec::new()).unwrap_err();
        assert!(matches!(err, RedactError::WeakDigestKey(0)));
    }

    #[test]
    fn redact_and_digest_rejects_a_digest_key_shorter_than_the_minimum() {
        let err = redact_and_digest("hello", Format::Text, &test_key(9)[..9]).unwrap_err();
        assert!(matches!(err, RedactError::WeakDigestKey(9)));
    }

    #[test]
    fn redact_json_value_redacts_in_place() {
        let mut v = serde_json::json!({"api_key": "FAKEabc123"});
        redact_json_value(&mut v);
        assert_eq!(v["api_key"], "[REDACTED]");
    }
}
