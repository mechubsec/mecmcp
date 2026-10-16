//! Fingerprints computed over unredacted data.
//!
//! Change detection (`mecmcp-changeset`'s fingerprint-bound apply, and any
//! server that diffs a device's config across two polls) has to keep working
//! after redaction is switched on. If the digest were computed on the
//! *redacted* text, two configs that differ only in a secret's value would
//! hash identically once that secret's field is denylisted — a rotated PSK
//! would look like no change at all.
//!
//! # Why HMAC, not plain SHA-256
//!
//! [`crate::redact_and_digest`] hands the model both the redacted body and
//! this digest. A plain content hash of the *unredacted* bytes turns that
//! pairing into a guessing oracle: every byte outside the redacted spans is
//! already known to the model verbatim, so for a low-entropy secret (an SNMP
//! community string, a short PSK) an attacker with tool access can replay
//! candidate values through the same digest function offline and check for a
//! match — the redacted body leaks nothing extra, but the *digest* does.
//! Keying the hash with a per-install secret the model never sees closes
//! that: matching a candidate now requires the key, not just the algorithm.
//!
//! The key is supplied by the caller — typically a server binary loading it
//! from an operator-provided key file at startup, the same convention
//! `mecmcp_audit::redact` already uses for its own `hmac` field transform —
//! rather than managed as process-global state here. This crate has no
//! opinion on *where* the key comes from; it only refuses to hash without
//! one.
//!
//! `digest_hex` is `pub(crate)`, not exported: the only public entry point
//! is [`crate::redact_and_digest`], which calls it on the original bytes
//! before redacting a copy. That makes "digest first, from the unredacted
//! input" the only order reachable through the public API, rather than a
//! recommendation a future edit could accidentally invert (a caller could
//! otherwise write `digest_hex(key, redact_text(x).as_bytes())` and get a
//! digest of already-redacted data with no compiler or test to catch it).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// `hmac-sha256:<64 lowercase hex>` over `data`, keyed by `key`.
///
/// `key` should be a per-install secret an operator provisions and the model
/// never sees — see the module docs. HMAC accepts a key of any length, so
/// this never fails.
#[must_use]
pub(crate) fn digest_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2);
    for byte in tag {
        use std::fmt::Write as _;
        // A `write!` to a `String` is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    format!("hmac-sha256:{hex}")
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

    fn key_a() -> Vec<u8> {
        test_key(1)
    }

    fn key_b() -> Vec<u8> {
        test_key(2)
    }

    #[test]
    fn digest_is_stable_for_the_same_key_and_content_addressed() {
        let a = digest_hex(&key_a(), b"hello");
        let b = digest_hex(&key_a(), b"hello");
        let c = digest_hex(&key_a(), b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("hmac-sha256:"));
        assert_eq!(a.strip_prefix("hmac-sha256:").unwrap().len(), 64);
    }

    /// F8: the digest must depend on the key, not just the bytes — otherwise
    /// it degenerates back into the plain-SHA-256 guessing oracle the HMAC
    /// switch exists to close.
    #[test]
    fn digest_differs_across_keys_for_the_same_bytes() {
        let with_a = digest_hex(&key_a(), b"same message");
        let with_b = digest_hex(&key_b(), b"same message");
        assert_ne!(
            with_a, with_b,
            "digest must depend on the install key, not just the message"
        );
    }

    /// N9: the load-bearing property is that the digest changes when the
    /// *secret* changes, even though the *redacted* body it is paired with
    /// does not — that is the whole point of digesting the unredacted bytes
    /// (see the module docs). Two inputs differing only inside a redacted
    /// span must produce identical `redact_and_digest` output but different
    /// digests; if the digest were computed on the redacted copy instead, a
    /// rotated PSK would look like no change at all. (The prior version of
    /// this test hashed the same bytes twice and asserted the two hashes
    /// were equal, which holds for any pure function and proves nothing.)
    #[test]
    fn digest_changes_when_a_secret_changes_even_though_the_redacted_output_does_not() {
        let raw_before = r#"{"password": "FAKEsupersecretAAA"}"#;
        let raw_after = r#"{"password": "FAKEsupersecretBBB"}"#;

        let out_before =
            crate::redact_and_digest(raw_before, crate::Format::Json, &key_a()).unwrap();
        let out_after = crate::redact_and_digest(raw_after, crate::Format::Json, &key_a()).unwrap();

        assert_eq!(
            out_before.redacted, out_after.redacted,
            "sanity: both secrets are under the same denylisted key, so the \
             redacted body must not reveal which one changed"
        );
        assert_ne!(
            out_before.digest, out_after.digest,
            "the digest must still distinguish the two inputs even though \
             the redacted body cannot"
        );
    }
}
