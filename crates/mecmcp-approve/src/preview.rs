//! Printing what is about to be sent, and requiring the human to say so
//! before it goes out.
//!
//! Two digests matter here, and they are not interchangeable:
//! - the *request digest*, computed locally over exactly the tool name and
//!   arguments this process is about to send -- this is always printed, and
//!   needs nothing from the server;
//! - the *server-reported digest*, read out of a preview tool's
//!   `structured_content.digest` when `--preview-tool` is used -- this is
//!   the authoritative change-set digest `mecmcp-changeset` computed, and is
//!   compared against `--expect-digest` (fail closed on mismatch) rather
//!   than trusted blindly.

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::ApproveError;

/// A SHA-256 digest, in the same `sha256:<hex>` shape
/// `mecmcp_changeset::digest` uses, over the canonical
/// `{"tool":<name>,"arguments":<arguments>}` JSON this request is about to
/// send. `arguments` is re-sorted into a `BTreeMap` before hashing, rather
/// than hashed in `--arg`-flag order: this workspace's feature unification
/// turns on `serde_json/preserve_order` (pulled in transitively through
/// `mecmcp-changeset`), which would otherwise make this digest depend on
/// whether this crate happens to be built standalone or inside the
/// workspace. Sorting here makes it reproducible either way.
#[must_use]
pub fn request_digest(tool: &str, arguments: &Map<String, Value>) -> String {
    let sorted: BTreeMap<&String, &Value> = arguments.iter().collect();
    let canonical = serde_json::json!({ "tool": tool, "arguments": sorted });
    // `to_string` on a `Value` never fails -- it is already valid JSON data,
    // not something that can contain a non-representable type.
    let bytes = canonical.to_string().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("sha256:{}", bytes_hex(&hasher.finalize()))
}

/// Refuse `--expect-digest` when there is nothing to check it against:
/// either no `--preview-tool` was given, or the preview tool's reply had
/// no usable `structured_content.digest`. Returns the mismatch error when
/// both are present but disagree.
pub fn check_expect_digest(
    expect_digest: Option<&str>,
    server_digest: Option<&str>,
) -> Result<(), ApproveError> {
    match (expect_digest, server_digest) {
        (Some(expected), Some(actual)) if expected != actual => Err(ApproveError::DigestMismatch {
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        }),
        (Some(_), None) => Err(ApproveError::DigestUnverifiable),
        _ => Ok(()),
    }
}

/// Bind the preview the human just saw to the approve call about to be
/// made: if the approve arguments carry their own `expected_digest` key
/// (the server-side check `mecmcp-changeset` performs), it must agree with
/// the digest the preview tool actually reported. Without this, a preview
/// of change set A could be followed by an approve call naming change set
/// B -- the server's own digest check still catches that, but the human
/// would have confirmed the wrong preview without this cross-check saying
/// so.
pub fn check_expected_digest_arg(
    approve_args: &Map<String, Value>,
    server_digest: Option<&str>,
) -> Result<(), ApproveError> {
    let (Some(server_digest), Some(claimed)) = (
        server_digest,
        approve_args.get("expected_digest").and_then(Value::as_str),
    ) else {
        return Ok(());
    };
    if claimed == server_digest {
        Ok(())
    } else {
        Err(ApproveError::DigestMismatch {
            expected: claimed.to_owned(),
            actual: server_digest.to_owned(),
        })
    }
}

/// Lowercase hex encoding, matching the shape `mecmcp_changeset::digest`
/// uses for its own digests (see its `bytes_hex`); duplicated rather than
/// depended on, since that crate is the server-side digest authority and
/// this crate only ever needs the encoding, not the digest computation.
fn bytes_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// Print the tool name, arguments, and request digest the approve call is
/// about to send. Always called before the approve call, regardless of
/// `--yes` -- the acceptance criterion is that this is *visible*, not that
/// a human necessarily has to type a confirmation every time (e.g. in a
/// scripted dry run that already confirmed out of band).
pub fn print_preview(tool: &str, arguments: &Map<String, Value>, digest: &str) {
    println!("About to approve:");
    println!("  tool:      {tool}");
    println!(
        "  arguments: {}",
        serde_json::to_string_pretty(arguments).unwrap_or_else(|_| "<unprintable>".to_owned())
    );
    println!("  digest:    {digest}");
}

/// Require the operator to type `approve` (not just press Enter) before
/// continuing. Skipped only when `skip` is true (`--yes`) -- but the
/// preview above is still printed either way, which is what the acceptance
/// criterion actually requires.
pub fn confirm(skip: bool) -> Result<(), ApproveError> {
    if skip {
        return Ok(());
    }
    print!("\nType \"approve\" to send this approval, anything else to abort: ");
    std::io::stdout()
        .flush()
        .map_err(ApproveError::ConfirmationRead)?;

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(ApproveError::ConfirmationRead)?;

    if line.trim() == "approve" {
        Ok(())
    } else {
        Err(ApproveError::NotConfirmed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn request_digest_is_deterministic() {
        let mut args = Map::new();
        args.insert("change_set_id".to_owned(), Value::String("cs-1".to_owned()));
        let a = request_digest("approve_change_set", &args);
        let b = request_digest("approve_change_set", &args);
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn request_digest_changes_with_arguments() {
        let mut args_a = Map::new();
        args_a.insert("change_set_id".to_owned(), Value::String("cs-1".to_owned()));
        let mut args_b = Map::new();
        args_b.insert("change_set_id".to_owned(), Value::String("cs-2".to_owned()));

        let digest_a = request_digest("approve_change_set", &args_a);
        let digest_b = request_digest("approve_change_set", &args_b);
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn request_digest_changes_with_tool_name() {
        let args = Map::new();
        let digest_a = request_digest("approve_change_set", &args);
        let digest_b = request_digest("preview_change_set", &args);
        assert_ne!(digest_a, digest_b);
    }

    #[test]
    fn request_digest_is_insensitive_to_insertion_order() {
        let mut a = Map::new();
        a.insert("b".to_owned(), Value::String("2".to_owned()));
        a.insert("a".to_owned(), Value::String("1".to_owned()));

        let mut b = Map::new();
        b.insert("a".to_owned(), Value::String("1".to_owned()));
        b.insert("b".to_owned(), Value::String("2".to_owned()));

        assert_eq!(
            request_digest("approve_change_set", &a),
            request_digest("approve_change_set", &b)
        );
    }

    #[test]
    fn expect_digest_with_no_preview_tool_is_unverifiable() {
        assert!(matches!(
            check_expect_digest(Some("sha256:abc"), None),
            Err(ApproveError::DigestUnverifiable)
        ));
    }

    #[test]
    fn expect_digest_matching_server_digest_is_ok() {
        assert!(check_expect_digest(Some("sha256:abc"), Some("sha256:abc")).is_ok());
    }

    #[test]
    fn expect_digest_mismatching_server_digest_is_rejected() {
        assert!(matches!(
            check_expect_digest(Some("sha256:abc"), Some("sha256:def")),
            Err(ApproveError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn no_expect_digest_is_always_ok() {
        assert!(check_expect_digest(None, None).is_ok());
        assert!(check_expect_digest(None, Some("sha256:abc")).is_ok());
    }

    #[test]
    fn expected_digest_arg_matching_server_digest_is_ok() {
        let mut approve_args = Map::new();
        approve_args.insert(
            "expected_digest".to_owned(),
            Value::String("sha256:abc".to_owned()),
        );
        assert!(check_expected_digest_arg(&approve_args, Some("sha256:abc")).is_ok());
    }

    #[test]
    fn expected_digest_arg_mismatching_server_digest_is_rejected() {
        let mut approve_args = Map::new();
        approve_args.insert(
            "expected_digest".to_owned(),
            Value::String("sha256:abc".to_owned()),
        );
        assert!(matches!(
            check_expected_digest_arg(&approve_args, Some("sha256:def")),
            Err(ApproveError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn expected_digest_arg_absent_is_ok_regardless_of_server_digest() {
        let approve_args = Map::new();
        assert!(check_expected_digest_arg(&approve_args, Some("sha256:abc")).is_ok());
        assert!(check_expected_digest_arg(&approve_args, None).is_ok());
    }
}
