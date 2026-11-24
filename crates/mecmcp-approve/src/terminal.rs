//! Escaping untrusted strings before they reach the approver's terminal.
//!
//! An IdP, an MCP server, or the change-set author can all put arbitrary
//! text in front of this CLI (a discovery document's `issuer`, a tool
//! result's rendered content, a JSON-RPC error message). Printed raw, an
//! ANSI/OSC escape sequence in that text -- a cursor move, a line erase, a
//! forged `OSC 8` hyperlink -- can rewrite what the human sees on screen in
//! the moment just before they type "approve". That defeats the one thing
//! this CLI promises: that the preview the human confirms is the preview
//! they actually saw.

use mecmcp_client::UntrustedText;

/// Escape `input` for the terminal (see [`UntrustedText`] for the exact rules).
#[must_use]
pub(crate) fn terminal_safe(input: &str) -> String {
    UntrustedText::new(input).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_ansi_cursor_and_erase_sequences() {
        let input = "\u{1b}[2K\u{1b}[1Aclobbered";
        let escaped = terminal_safe(input);
        assert!(!escaped.contains('\u{1b}'));
        assert!(escaped.contains("clobbered"));
    }

    #[test]
    fn leaves_newlines_and_tabs_alone() {
        assert_eq!(terminal_safe("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn leaves_plain_unicode_alone() {
        assert_eq!(terminal_safe("héllo 世界"), "héllo 世界");
    }

    #[test]
    fn escapes_del_and_c1_controls() {
        let input = "\u{7f}\u{9b}";
        let escaped = terminal_safe(input);
        assert!(!escaped.contains('\u{7f}'));
        assert!(!escaped.contains('\u{9b}'));
    }
}
