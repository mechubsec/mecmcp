//! The typed, minimal claim set produced by a successful verification.

/// What a verified token is permitted to leave behind.
///
/// Deliberately narrow: `sub`, the configured role/group claim, and `exp`.
/// Everything else in the token — arbitrary IdP-specific claims, the raw
/// token string itself — is dropped once verification completes and must
/// not be retained past the request, per the offline-first / minimal-retention
/// requirement this crate was built against.
///
/// The optional `display_name` is a browser-login-relying-party addition,
/// only populated when [`crate::OidcConfig::include_display_name`] is `true`.
/// Resource servers that never show a human's name in a UI leave it `false`
/// and this field stays `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    /// The `sub` claim: the IdP's stable identifier for the human.
    pub subject: String,
    /// The configured group/role claim, normalized to a list of strings.
    ///
    /// Empty if the claim was absent, a string is treated as a single-element
    /// list, and a JSON array is filtered to its string elements (a non-string
    /// entry is dropped rather than making the whole claim unusable).
    pub roles: Vec<String>,
    /// The `exp` claim, as Unix seconds. Carried through so a caller can
    /// bound how long to trust a claim set it may cache in memory, without
    /// retaining the token itself.
    pub expires_at: i64,
    /// A human-readable display name from `preferred_username` or `name`,
    /// only when opted in via config. Capped at 128 Unicode scalar values and
    /// trimmed. `None` if the config leaves `include_display_name` as `false`
    /// (the default), or if both claims are absent or empty after trimming.
    pub display_name: Option<String>,
}

/// Pull the configured role/group claim out of a token's extra claims.
pub(crate) fn extract_roles(
    extra: &serde_json::Map<String, serde_json::Value>,
    role_claim: &str,
) -> Vec<String> {
    match extra.get(role_claim) {
        Some(serde_json::Value::String(single)) => vec![single.clone()],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract a display name from `preferred_username` or `name`, when opted in.
///
/// Falls back to `name` if `preferred_username` is absent or empty after
/// trimming. Caps at 128 Unicode scalar values (not bytes, not graphemes —
/// scalar values, which is what `char_indices` counts) to bound what this
/// crate retains. Returns `None` if both claims are absent or empty.
pub(crate) fn extract_display_name(
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let preferred = extra
        .get("preferred_username")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let fallback = extra
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    preferred.or(fallback).map(|s| {
        // Cap at 128 Unicode scalar values
        s.char_indices()
            .nth(128)
            .map_or_else(|| s.to_owned(), |(idx, _)| s[..idx].to_owned())
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        match value {
            serde_json::Value::Object(map) => map,
            _ => panic!("expected object"),
        }
    }

    #[test]
    fn extracts_single_string_role() {
        let extra = map(json!({"role": "approver"}));
        assert_eq!(extract_roles(&extra, "role"), vec!["approver".to_string()]);
    }

    #[test]
    fn extracts_array_of_roles() {
        let extra = map(json!({"groups": ["ops", "pci-approvers"]}));
        assert_eq!(
            extract_roles(&extra, "groups"),
            vec!["ops".to_string(), "pci-approvers".to_string()]
        );
    }

    #[test]
    fn missing_claim_yields_empty() {
        let extra = map(json!({"other": "value"}));
        assert!(extract_roles(&extra, "groups").is_empty());
    }

    #[test]
    fn non_string_array_entries_are_dropped_not_fatal() {
        let extra = map(json!({"groups": ["ops", 42, null, "pci"]}));
        assert_eq!(
            extract_roles(&extra, "groups"),
            vec!["ops".to_string(), "pci".to_string()]
        );
    }

    #[test]
    fn display_name_prefers_preferred_username() {
        let extra = map(json!({
            "preferred_username": "alice",
            "name": "Alice Anderson"
        }));
        assert_eq!(extract_display_name(&extra), Some("alice".to_string()));
    }

    #[test]
    fn display_name_falls_back_to_name() {
        let extra = map(json!({"name": "Alice Anderson"}));
        assert_eq!(
            extract_display_name(&extra),
            Some("Alice Anderson".to_string())
        );
    }

    #[test]
    fn display_name_returns_none_when_both_absent() {
        let extra = map(json!({"other": "value"}));
        assert_eq!(extract_display_name(&extra), None);
    }

    #[test]
    fn display_name_trims_whitespace() {
        let extra = map(json!({"name": "  Alice  "}));
        assert_eq!(extract_display_name(&extra), Some("Alice".to_string()));
    }

    #[test]
    fn display_name_returns_none_for_empty_after_trim() {
        let extra = map(json!({"preferred_username": "  ", "name": ""}));
        assert_eq!(extract_display_name(&extra), None);
    }

    #[test]
    fn display_name_caps_at_128_unicode_scalar_values() {
        let long_name = "a".repeat(200);
        let extra = map(json!({"name": long_name}));
        let result = extract_display_name(&extra).unwrap();
        assert_eq!(result.chars().count(), 128);
        assert_eq!(result, "a".repeat(128));
    }

    #[test]
    fn display_name_prefers_non_empty_preferred_username_over_name() {
        let extra = map(json!({
            "preferred_username": "",
            "name": "Alice"
        }));
        // Empty preferred_username is filtered out, so fallback to name
        assert_eq!(extract_display_name(&extra), Some("Alice".to_string()));
    }
}
