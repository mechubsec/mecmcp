//! Escaping untrusted strings before they reach a human's terminal.
//!
//! A server's JSON-RPC error or tool output printed raw can carry ANSI/OSC
//! sequences (cursor moves, line erase, forged `OSC 8` hyperlinks) that
//! rewrite what the human sees just before they confirm something.

use std::fmt::{self, Write as _};

/// Text from a remote peer. `Display` and `Debug` escape every C0 control
/// except `\n`/`\t`, DEL and the C1 range as `\u{xx}`; [`raw`](Self::raw)
/// gives the unmodified bytes for programmatic use.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedText(String);

impl UntrustedText {
    /// Wrap raw peer-supplied text.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The unescaped text. Never print this to a terminal.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UntrustedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            let code = u32::from(ch);
            let is_c0 = code < 0x20 && ch != '\n' && ch != '\t';
            if is_c0 || ch == '\u{7f}' || (0x80..=0x9f).contains(&code) {
                write!(f, "\\u{{{code:02x}}}")?;
            } else {
                f.write_char(ch)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for UntrustedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UntrustedText({self})")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests
mod tests {
    use super::*;

    fn shown(raw: &str) -> String {
        UntrustedText::new(raw).to_string()
    }

    #[test]
    fn escapes_ansi_cursor_and_erase_sequences() {
        let escaped = shown("\u{1b}[2K\u{1b}[1Aclobbered");
        assert!(!escaped.contains('\u{1b}'));
        assert!(escaped.contains("clobbered"));
    }

    #[test]
    fn leaves_newlines_and_tabs_alone() {
        assert_eq!(shown("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn leaves_plain_unicode_alone() {
        assert_eq!(shown("héllo 世界"), "héllo 世界");
    }

    #[test]
    fn escapes_del_and_c1_controls() {
        let escaped = shown("\u{7f}\u{9b}");
        assert!(!escaped.contains('\u{7f}') && !escaped.contains('\u{9b}'));
    }

    #[test]
    fn display_escapes_osc8_hyperlink() {
        let text = UntrustedText::new("\u{1b}]8;;https://evil.example\u{7}click\u{1b}]8;;\u{7}");
        assert!(!text.to_string().contains('\u{1b}'));
        assert!(!format!("{text:?}").contains('\u{7}'));
        assert!(text.raw().contains('\u{1b}'));
    }
}
