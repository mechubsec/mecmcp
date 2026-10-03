//! The typed, minimal claim set produced by a successful verification.

/// What a verified token is permitted to leave behind.
///
/// Deliberately narrow: `sub`, the configured role/group claim, and `exp`.
/// Everything else in the token — arbitrary IdP-specific claims, the raw
/// token string itself — is dropped once verification completes and must
/// not be retained past the request, per the offline-first / minimal-retention
/// requirement this crate was built against.
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
}
