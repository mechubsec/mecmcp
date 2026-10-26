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
    /// The `iat` claim, as Unix seconds. Required: a step-up freshness check
    /// (RFC 9470's `max_age` pattern) cannot be enforced against a claim that
    /// might be absent, and a verifier that made it optional would let every
    /// freshness check silently pass vacuously on a token with no `iat`.
    pub issued_at: i64,
    /// The `auth_time` claim, as Unix seconds, when the IdP included it
    /// (OpenID Connect Core 1.0 §2). Optional because not every IdP or grant
    /// emits it; a caller that requires proof of a fresh interactive login
    /// must treat its absence as a rejection, not as "no opinion".
    pub auth_time: Option<i64>,
    /// The `jti` claim, when present. Optional because not every IdP issues
    /// one; a caller enforcing single-use assertions must treat its absence
    /// as a rejection rather than silently skip the replay check.
    pub jwt_id: Option<String>,
    /// A human-readable display name from `preferred_username` or `name`,
    /// only when opted in via config. Capped at 128 Unicode scalar values and
    /// trimmed. `None` if the config leaves `include_display_name` as `false`
    /// (the default), or if both claims are absent or empty after trimming.
    pub display_name: Option<String>,
    /// OAuth scopes from the `scope` claim (RFC 9068 s2.2.3: a space-delimited
    /// string) or, when `scope` is absent, the `scp` claim (a string or an array).
    ///
    /// Each entry is a valid RFC 6749 s3.3 scope-token; anything else (an empty
    /// string, an array element containing a space, a control character) is dropped
    /// rather than split or repaired, so a crafted claim can only ever *reduce*
    /// what a caller maps to. Deduplicated, at most 64 entries of at most 128 bytes.
    /// A claim of any other JSON type (including an array in `scope`) yields an
    /// empty list.
    pub scopes: Vec<String>,
    /// The OAuth client the token was issued to: `client_id` (RFC 9068), else
    /// `azp`. `None` when neither is a clean string (<= 128 bytes, no control
    /// characters). Required (non-`None`) under [`crate::TokenProfile::AccessToken`].
    pub client_id: Option<String>,
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

/// Maximum scopes retained from one token.
const MAX_SCOPES: usize = 64;
/// Maximum bytes in one scope-token or client id.
const MAX_TOKEN_LEN: usize = 128;

/// Whether `candidate` is a legal OAuth scope-token (RFC 6749 s3.3):
/// `1*( %x21 / %x23-5B / %x5D-7E )`, so no space, no `"`, no `\`, no control
/// character, no non-ASCII. Also bounded to 128 bytes.
#[must_use]
pub fn is_scope_token(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= MAX_TOKEN_LEN
        && candidate
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Pull the token's scopes out of its extra claims (see [`VerifiedClaims::scopes`]).
pub(crate) fn extract_scopes(extra: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    // RFC 9068 s2.2.3 allows only a string for `scope`; arrays come only from `scp`.
    let raw: Vec<&str> = match (extra.get("scope"), extra.get("scp")) {
        (Some(serde_json::Value::String(joined)), _)
        | (None, Some(serde_json::Value::String(joined))) => joined.split(' ').collect(),
        (None, Some(serde_json::Value::Array(items))) => {
            items.iter().filter_map(serde_json::Value::as_str).collect()
        }
        _ => Vec::new(),
    };
    let mut scopes: Vec<String> = Vec::new();
    for candidate in raw {
        if !is_scope_token(candidate) || scopes.iter().any(|seen| seen == candidate) {
            continue;
        }
        if scopes.len() == MAX_SCOPES {
            break;
        }
        scopes.push(candidate.to_owned());
    }
    scopes
}

/// `client_id` (RFC 9068), else `azp`; `None` unless a clean, bounded string.
pub(crate) fn extract_client_id(
    extra: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let raw = extra
        .get("client_id")
        .or_else(|| extra.get("azp"))?
        .as_str()?;
    let clean = !raw.is_empty() && raw.len() <= MAX_TOKEN_LEN && !raw.chars().any(char::is_control);
    clean.then(|| raw.to_owned())
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
