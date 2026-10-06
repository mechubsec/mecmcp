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

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::error::ApproveError;

/// A SHA-256 digest, in the same `sha256:<hex>` shape
/// `mecmcp_changeset::digest` uses, over the canonical
/// `{"tool":<name>,"arguments":<arguments>}` JSON this request is about to
/// send. `serde_json::Map` serializes object keys in insertion order, and
/// callers build `arguments` from a stable, sorted `--arg` order (see
/// `cli.rs`), so this digest is reproducible across runs given the same
/// input.
#[must_use]
pub fn request_digest(tool: &str, arguments: &Map<String, Value>) -> String {
    let canonical = serde_json::json!({ "tool": tool, "arguments": arguments });
    // `to_string` on a `Value` never fails -- it is already valid JSON data,
    // not something that can contain a non-representable type.
    let bytes = canonical.to_string().into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("sha256:{}", bytes_hex(&hasher.finalize()))
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
}
