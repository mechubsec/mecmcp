//! Wildcard-or-allowlist authorization scopes over opaque names.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum names in one explicit scope, keeping linear lookup bounded.
pub const MAX_SCOPE_NAMES: usize = 256;

/// Rejection reason for a malformed scope.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// The scope failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// Wildcard or literal allowlist for device and tool names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSet {
    /// Permit every name known to the server.
    Wildcard,
    /// Permit only the exact listed names. May be empty, which permits nothing.
    Allowlist(Vec<String>),
}

/// The built-in tool every authenticated caller may call regardless of its tool scope
/// (mecmcp#580). It returns only the caller's own token metadata, so no scope can make it
/// disclose more than the holder already learns from a denial message (which names the token).
pub const WHOAMI_TOOL: &str = "whoami";

impl ScopeSet {
    /// Whether an exact name is allowed.
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether a tool is allowed, with write tools excluded from the wildcard.
    ///
    /// A wildcard tool scope is a convenience for read-only automation; granting
    /// write authority must always be an explicit, named decision. The caller
    /// supplies its own write-tool registry so this crate stays vendor-neutral.
    /// An empty allowlist permits nothing — the set is simply empty, so no name
    /// can match. [`WHOAMI_TOOL`] is the exception: every scope permits it, even an
    /// empty allowlist.
    #[must_use]
    pub fn allows_tool(&self, name: &str, write_tools: &[&str]) -> bool {
        if name == WHOAMI_TOOL {
            return true;
        }
        match self {
            Self::Wildcard => !write_tools.contains(&name),
            Self::Allowlist(names) => names.iter().any(|allowed| allowed == name),
        }
    }

    /// Whether this scope permits nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Allowlist(names) if names.is_empty())
    }

    /// Stable comma-separated representation for audit metadata.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Wildcard => "*".to_owned(),
            Self::Allowlist(names) => names.join(","),
        }
    }

    /// Validate count, duplicates, and wildcard spelling.
    pub fn validate(&self, field: &'static str) -> Result<(), ScopeError> {
        let Self::Allowlist(names) = self else {
            return Ok(());
        };
        if names.len() > MAX_SCOPE_NAMES {
            return Err(ScopeError::Invalid(format!(
                "{field} scope contains more than {MAX_SCOPE_NAMES} names"
            )));
        }
        let mut seen = BTreeSet::new();
        for name in names {
            if name == "*" {
                return Err(ScopeError::Invalid(format!(
                    "{field} scope may use '*' only as the sole list entry"
                )));
            }
            if name.is_empty() || name.len() > 128 || name.contains('\0') {
                return Err(ScopeError::Invalid(format!(
                    "{field} scope contains an out-of-range name"
                )));
            }
            if !seen.insert(name) {
                return Err(ScopeError::Invalid(format!(
                    "duplicate name '{name}' in {field} scope"
                )));
            }
        }
        Ok(())
    }
}

impl Serialize for ScopeSet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let names: Vec<&str> = match self {
            Self::Wildcard => vec!["*"],
            Self::Allowlist(names) => names.iter().map(String::as_str).collect(),
        };
        names.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        if names.len() == 1 && names[0] == "*" {
            Ok(Self::Wildcard)
        } else {
            Ok(Self::Allowlist(names))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITE_TOOLS: &[&str] = &["load_and_commit_config", "commit_panos_candidate"];

    #[test]
    fn wildcard_allows_any_device_name() {
        assert!(ScopeSet::Wildcard.allows("edge-fw"));
    }

    #[test]
    fn allowlist_allows_only_exact_names() {
        let scope = ScopeSet::Allowlist(vec!["edge-fw".to_owned()]);
        assert!(scope.allows("edge-fw"));
        assert!(!scope.allows("edge-fw-2"));
        assert!(!scope.allows("edge"));
    }

    #[test]
    fn wildcard_tool_scope_excludes_write_tools() {
        let scope = ScopeSet::Wildcard;
        assert!(scope.allows_tool("get_junos_config", WRITE_TOOLS));
        assert!(!scope.allows_tool("load_and_commit_config", WRITE_TOOLS));
    }

    #[test]
    fn explicit_allowlist_may_name_a_write_tool() {
        let scope = ScopeSet::Allowlist(vec!["load_and_commit_config".to_owned()]);
        assert!(scope.allows_tool("load_and_commit_config", WRITE_TOOLS));
    }

    #[test]
    fn empty_allowlist_permits_nothing() {
        let scope = ScopeSet::Allowlist(vec![]);
        assert!(scope.is_empty());
        assert!(!scope.allows("anything"));
    }

    #[test]
    fn wildcard_round_trips_as_a_single_star_entry() {
        let json = serde_json::to_string(&ScopeSet::Wildcard).expect("serialize");
        assert_eq!(json, "[\"*\"]");
        let back: ScopeSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ScopeSet::Wildcard);
    }

    #[test]
    fn star_inside_a_longer_list_fails_validation() {
        let scope = ScopeSet::Allowlist(vec!["a".to_owned(), "*".to_owned()]);
        assert!(scope.validate("devices").is_err());
    }

    #[test]
    fn duplicate_names_fail_validation() {
        let scope = ScopeSet::Allowlist(vec!["a".to_owned(), "a".to_owned()]);
        assert!(scope.validate("devices").is_err());
    }

    #[test]
    fn oversized_allowlist_fails_validation() {
        let names = (0..=MAX_SCOPE_NAMES).map(|i| format!("d{i}")).collect();
        assert!(ScopeSet::Allowlist(names).validate("devices").is_err());
    }

    #[test]
    fn summary_is_stable_for_audit_metadata() {
        assert_eq!(ScopeSet::Wildcard.summary(), "*");
        assert_eq!(
            ScopeSet::Allowlist(vec!["a".to_owned(), "b".to_owned()]).summary(),
            "a,b"
        );
    }

    #[test]
    fn wildcard_excludes_a_write_tool_named_by_a_heap_string() {
        // Guards the contents-vs-pointer comparison in `allows_tool`: the tool
        // name arrives from JSON at runtime, never as the same &'static str as
        // the registry entry.
        let from_the_wire = String::from("load_and_commit_") + "config";
        assert!(!ScopeSet::Wildcard.allows_tool(&from_the_wire, WRITE_TOOLS));
    }

    #[test]
    fn empty_allowlist_permits_no_tools() {
        let scope = ScopeSet::Allowlist(vec![]);
        assert!(!scope.allows_tool("get_junos_config", WRITE_TOOLS));
        assert!(!scope.allows_tool("load_and_commit_config", WRITE_TOOLS));
    }

    #[test]
    fn whoami_is_allowed_by_every_tool_scope() {
        let other = ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]);
        for scope in [ScopeSet::Allowlist(vec![]), other] {
            assert!(scope.allows_tool(WHOAMI_TOOL, WRITE_TOOLS));
            assert!(!scope.allows_tool("commit_panos_candidate", WRITE_TOOLS));
        }
    }

    #[test]
    fn an_allowlist_of_exactly_max_scope_names_is_accepted() {
        // The existing oversize test proves rejection at MAX+1; this proves the
        // boundary itself is not off by one.
        let names = (0..MAX_SCOPE_NAMES).map(|i| format!("d{i}")).collect();
        assert!(ScopeSet::Allowlist(names).validate("devices").is_ok());
    }
}
