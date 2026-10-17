//! The element/key denylist for unstructured redaction.
//!
//! Matching is substring-on-normalized-key, not exact-match, on purpose: vendor
//! field names vary in case and separator (`pre-shared-key`, `pre_shared_key`,
//! `preSharedKey`) and are sometimes compounded (`wifiPassword`,
//! `adminApiKey`). A denylist that only matched the literal spelling would miss
//! every variant a vendor happens to use. The cost is the occasional field that
//! merely *contains* a denylisted word — an over-redaction, which is the safe
//! direction to be wrong in. See the crate README for what this still misses.

/// Canonical secret-bearing field names. Each is normalized (lowercased,
/// separators stripped) before comparison, so this list only needs one form
/// of each word.
pub const DENYLISTED_KEYS: &[&str] = &[
    "secret",
    "privatekey",
    "presharedkey",
    "psk",
    "passphrase",
    "xpassphrase",
    "xsecret",
    "phash",
    "community",
    "communities",
    "communitystring",
    "apikey",
    "token",
    "authenticationkey",
    "password",
    "sharedkey",
    "sharedsecret",
    "credential",
    "bindpw",
    "encryptionkey",
    "privkey",
    "authorization",
    "bearer",
    "cookie",
    "passwd",
    "pwd",
    "session",
    "sessionid",
    "sessiontoken",
    "sessionkey",
    "sessioncookie",
    "sessionsecret",
    "keystring",
    "messagedigestkey",
    "authkey",
    "keywrap",
    "partnerkey",
    "accountkey",
    "clientkey",
    // MEC-1245: extends Junos field coverage in the shared denylist.
    "hmackey",
];

/// Field names that must match the *whole* normalized key, not a substring.
///
/// `"key"` is deliberately not in [`DENYLISTED_KEYS`]: as a substring it would
/// match half of every config (`keys`, `keyword`, `keychain`, an interface
/// named `key0`, ...). But the bare field name `key` alone is exactly the
/// PAN-OS keygen response shape (`<result><key>` is the API key itself), so it
/// still needs to be denylisted — just under exact match instead.
///
/// `pub` (not `pub(crate)`) for two independent consumers:
/// [`crate::profile::Profile::check_exemptions`] refuses a vendor exemption
/// that exactly matches one of these, the same way it refuses one matching
/// [`DENYLISTED_KEYS`]; the crate's property test also enumerates this list
/// directly to assert every exact-match secret field is covered.
pub const DENYLISTED_EXACT_KEYS: &[&str] = &["key"];

/// Exact-match field name that is a secret only given additional sibling or
/// parent context (see [`is_wep_keys_field`]), not by name alone — so it
/// cannot live in [`DENYLISTED_EXACT_KEYS`] without over-matching every
/// unrelated `keys` field. A vendor exemption must still not be allowed to
/// claim this exact name, since in the right context it is secret-bearing.
pub(crate) const CONTEXTUALLY_DENYLISTED_EXACT_KEYS: &[&str] = &["keys"];

/// Whether `key` is a WEP key-material field, identifiable only by the shape
/// of its enclosing object rather than its own name.
///
/// A bare `keys` field is too generic to add to [`DENYLISTED_KEYS`] as a
/// substring: it would over-match every unrelated `keys` array or map in a
/// vendor payload (interface lists, route tables, ...). But Mist's
/// `wlan_auth` schema (MEC-711) uses exactly `keys` for its WEP key table,
/// always either alongside a sibling `type: "wep"` field on the same object,
/// or nested directly under a parent field named `auth`. Both are narrow
/// enough that a caller walking the JSON tree can check them without
/// widening the denylist's blast radius.
#[must_use]
pub fn is_wep_keys_field(key: &str, parent_key: Option<&str>, sibling_type: Option<&str>) -> bool {
    if normalize(key) != "keys" {
        return false;
    }
    if sibling_type.is_some_and(|t| normalize(t) == "wep") {
        return true;
    }
    parent_key.is_some_and(|p| normalize(p) == "auth")
}

/// Words a `session` counter/limit field name may be built from, besides
/// `session`/`sessions` itself. Closed on purpose: a name with any other word
/// (`id`, `token`, `data`, `value`, ...) stays denylisted.
const SESSION_NAME_WORDS: &[&str] = &[
    "flow",
    "active",
    "count",
    "counter",
    "counters",
    "current",
    "max",
    "maximum",
    "total",
    "failed",
    "invalid",
    "valid",
    "created",
    "closed",
    "allocated",
    "peak",
    "limit",
    "per",
    "ip",
    "source",
    "destination",
    "tcp",
    "udp",
    "icmp",
    "in",
    "out",
    "half",
    "open",
    "idle",
    "rate",
    "ager",
    "aged",
    "burst",
    "drop",
    "dropped",
    "rejected",
    "denied",
    "allowed",
];

/// Whether `name` is an operational `session` configuration or counter field
/// name rather than possible session secret material: `limit-session`,
/// `session-init`, `session-close`, or a lowercase `-`/`_`-separated name of
/// `session`/`sessions` plus only [`SESSION_NAME_WORDS`] (`sessions-active`,
/// `flow-session-count`). A bare `session`/`sessions` is not eligible.
///
/// Only a *name* test; callers must also check the value with
/// [`is_inert_session_value`], and must gate it behind a vendor profile.
#[must_use]
pub(crate) fn is_session_config_name(name: &str) -> bool {
    if matches!(
        normalize(name).as_str(),
        "limitsession" | "sessioninit" | "sessionclose"
    ) {
        return true;
    }
    let mut has_session = false;
    let mut words = 0;
    for w in name.split(['-', '_']) {
        words += 1;
        match w {
            "session" | "sessions" => has_session = true,
            w if SESSION_NAME_WORDS.contains(&w) => {}
            _ => return false,
        }
    }
    has_session && words > 1
}

/// A value too plain to be session secret material: empty/whitespace
/// (container or flag element) or a bare integer of at most 12 digits.
#[must_use]
pub(crate) fn is_inert_session_value(value: &str) -> bool {
    let v = value.trim();
    v.is_empty() || (v.len() <= 12 && v.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `key` is the BGP configuration scope that [`is_bgp_community_field`]
/// looks for among a value's ancestors.
#[must_use]
pub fn is_bgp_scope_key(key: &str) -> bool {
    normalize(key) == "bgp"
}

/// Whether `key` is a BGP route-community field that may survive despite
/// normalizing to the `community` substring entry.
///
/// PAN-OS and Junos both spell a BGP route community (a routing-policy tag
/// like `65000:100`, public on the wire) with the exact same bare `community`
/// field an SNMP community *string* (a shared secret) uses — the two are
/// indistinguishable by field name alone. PAN-OS nests its BGP route
/// community under a `bgp` element, which SNMP configuration never is, so a
/// caller walking the tree can tell them apart by checking whether a `bgp`
/// scope is among the value's ancestors. Junos instead nests its route
/// communities under `policy-options`, not `bgp`, so this exemption does not
/// fire for them and they stay redacted — over-redaction, the safe direction
/// to be wrong in, not a leak.
///
/// This is necessary but not sufficient: it only tells the caller the *key*
/// matches the shape. A `bgp` ancestor can itself be a vendor's own
/// user-chosen map key (a profile, VR, or template literally named `bgp`),
/// so the key-only check does not prove the field underneath is actually
/// BGP routing data. Callers must additionally confirm the value with
/// [`is_bgp_community_tag`] before skipping redaction — a secret does not
/// parse as community-tag syntax even when it happens to sit under
/// something named `bgp`.
#[must_use]
pub fn is_bgp_community_field(key: &str, under_bgp_scope: bool) -> bool {
    under_bgp_scope && normalize(key) == "community"
}

/// Whether `s` looks like BGP community-tag syntax (`65000:100`, a routing
/// tag; or `65000:100:5`, an extended/large community) or one of BGP's
/// well-known community names, rather than an arbitrary secret value.
///
/// Required alongside [`is_bgp_community_field`] before exempting a
/// `community` field from redaction: the key-only check cannot tell a real
/// BGP routing policy apart from an unrelated value that merely sits under a
/// `bgp`-named ancestor, so the value itself has to back up the "this is
/// public routing data" claim. A secret string does not parse as this
/// shape.
#[must_use]
pub fn is_bgp_community_tag(s: &str) -> bool {
    const WELL_KNOWN: &[&str] = &[
        "no-export",
        "no-advertise",
        "no-peer",
        "no-export-subconfed",
        "local-as",
        "internet",
    ];
    if WELL_KNOWN.iter().any(|w| s.eq_ignore_ascii_case(w)) {
        return true;
    }
    let parts: Vec<&str> = s.split(':').collect();
    (parts.len() == 2 || parts.len() == 3)
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Lowercase `s` and drop every non-alphanumeric byte, so `pre-shared-key`,
/// `pre_shared_key`, and `preSharedKey` all normalize to `presharedkey`.
///
/// `pub(crate)` so [`crate::profile`] can match a vendor-declared field name
/// under the exact same normalization the denylist itself uses, rather than
/// maintaining a second normalize function that could drift out of sync with
/// this one.
pub(crate) fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Whether `key` matches a denylisted field name, under normalization.
///
/// Substring, not equality: a normalized denylist term appearing anywhere in
/// the normalized key is enough. `is_denylisted_key("x_shared_key")` and
/// `is_denylisted_key("wifi_password")` both match even though neither is a
/// literal entry in [`DENYLISTED_KEYS`].
#[must_use]
pub fn is_denylisted_key(key: &str) -> bool {
    let normalized = normalize(key);
    if normalized.is_empty() {
        return false;
    }
    if DENYLISTED_EXACT_KEYS.iter().any(|term| normalized == *term) {
        return true;
    }
    DENYLISTED_KEYS.iter().any(|term| normalized.contains(term))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spec_key_matches_its_own_variants() {
        let cases: &[(&str, &[&str])] = &[
            ("secret", &["secret", "Secret", "SECRET"]),
            ("private-key", &["private-key", "private_key", "privateKey"]),
            (
                "pre-shared-key",
                &["pre-shared-key", "pre_shared_key", "preSharedKey"],
            ),
            ("psk", &["psk", "PSK"]),
            ("passphrase", &["passphrase", "passPhrase"]),
            ("x_passphrase", &["x_passphrase", "x-passphrase"]),
            ("x_secret", &["x_secret", "x-secret"]),
            ("phash", &["phash", "x_phash"]),
            ("community", &["community", "community-string"]),
            ("api_key", &["api_key", "apiKey", "api-key"]),
            ("token", &["token", "auth_token", "bearerToken"]),
            (
                "authentication-key",
                &["authentication-key", "authentication_key"],
            ),
            ("password", &["password", "adminPassword", "wifi_password"]),
        ];
        for (spec_key, variants) in cases {
            for variant in *variants {
                assert!(
                    is_denylisted_key(variant),
                    "expected '{variant}' (variant of spec key '{spec_key}') to be denylisted"
                );
            }
        }
    }

    #[test]
    fn unrelated_keys_are_not_denylisted() {
        for key in ["description", "hostname", "interface", "vlan_id", "name"] {
            assert!(!is_denylisted_key(key), "'{key}' must not be denylisted");
        }
    }

    #[test]
    fn f7_new_field_names_are_denylisted() {
        for key in [
            "authorization",
            "Authorization",
            "bearer",
            "bearer_token",
            "cookie",
            "passwd",
            "pwd",
            "session",
            "session_id",
        ] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    #[test]
    fn bare_key_matches_exactly_but_not_as_a_substring() {
        assert!(is_denylisted_key("key"));
        assert!(is_denylisted_key("Key"));
        for key in ["keys", "keyword", "keychain", "monkey", "key0", "hotkey"] {
            assert!(
                !is_denylisted_key(key),
                "'{key}' must not match the exact-only 'key' entry"
            );
        }
    }

    #[test]
    fn empty_key_is_not_denylisted() {
        assert!(!is_denylisted_key(""));
    }

    /// MEC-711: Mist OpenAPI secret fields Percy's sweep found missing from
    /// the denylist at the mecmcp rev rustmistmcp#137 pinned
    /// (`auth_key`/`auth_keys`, `keywrap_kek`/`keywrap_mack`, and the
    /// lower-confidence `partner_key`/`account_key`/`*client_key` set).
    #[test]
    fn mec_711_mist_secret_fields_are_denylisted() {
        let cases: &[(&str, &[&str])] = &[
            ("auth_key", &["auth_key", "authKey", "bgpAuthKey"]),
            ("auth_keys", &["auth_keys", "authKeys"]),
            ("keywrap_kek", &["keywrap_kek", "keywrapKek"]),
            ("keywrap_mack", &["keywrap_mack", "keywrapMack"]),
            ("partner_key", &["partner_key", "partnerKey"]),
            ("account_key", &["account_key", "accountKey"]),
            ("ldap_client_key", &["ldap_client_key", "ldapClientKey"]),
            (
                "openroaming_wba_client_key",
                &["openroaming_wba_client_key", "openroamingWbaClientKey"],
            ),
        ];
        for (spec_key, variants) in cases {
            for variant in *variants {
                assert!(
                    is_denylisted_key(variant),
                    "expected '{variant}' (variant of spec key '{spec_key}') to be denylisted"
                );
            }
        }
    }

    /// MEC-1245: extends Junos field coverage in the shared denylist.
    #[test]
    fn mec_1245_junos_routing_auth_keys_denylisted() {
        for key in ["hmac-key", "hmac_key", "hmacKey", "HMAC-KEY"] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    /// `session` and `community` match as a substring (a session
    /// cookie/token, or PAN-OS/Junos's SNMP community string), and so do
    /// operational/routing-policy field names that merely contain those
    /// words (`idle-timeout-tcp-session`, `community-list`, ...). There is
    /// no global key-name exemption for them: a vendor server that needs one
    /// declares a [`crate::profile::Profile`] with those exact names as
    /// `key_exemptions`, scoped to that vendor's own tool-output path,
    /// rather than loosening this crate's default for every caller.
    #[test]
    fn mec_537_session_and_community_match_as_substrings() {
        for key in [
            "session",
            "Session",
            "community",
            "Community",
            "idle-timeout-tcp-session",
            "sessions-active",
            "max-sessions",
            "session-timeout",
            "sessions",
            "community-list",
            "match-community",
            "add-community",
            "remove-community",
        ] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    /// Compound spellings not on the exceptions list still match as a
    /// substring.
    #[test]
    fn mec_537_secret_shaped_session_and_community_compounds_still_match() {
        for key in [
            "session_id",
            "sessionId",
            "session-token",
            "session_key",
            "session_cookie",
            "jsessionid",
            "auth_session",
            "user_session",
            "x-session",
            "session_data",
            "session_ticket",
            "session-hash",
            "session_value",
            "community_string",
            "communityString",
            "snmp-community-string",
            "community_name",
            "communityName",
            "community-name",
            "ro_community",
            "rw-community",
            "read-community",
            "trap-community",
            "snmp_community",
            "snmpCommunity",
            "community-key",
        ] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    /// These community-related keys have no vendor evidence to justify an
    /// exemption and must be denylisted.
    #[test]
    fn mec_1342_unjustified_community_exceptions_are_denylisted() {
        for key in ["communities", "communitymembers", "overwritecommunity"] {
            assert!(is_denylisted_key(key), "'{key}' must be denylisted");
        }
    }

    #[test]
    fn mec_537_bgp_community_field_only_matches_under_bgp_scope() {
        assert!(is_bgp_community_field("community", true));
        assert!(!is_bgp_community_field("community", false));
        assert!(!is_bgp_community_field("community-list", true));
        assert!(is_bgp_scope_key("bgp"));
        assert!(!is_bgp_scope_key("bgp-peer-group"));
    }

    /// The key-only `bgp`-ancestor check is not enough on its own — the
    /// value itself must look like BGP community-tag syntax before the
    /// exemption applies.
    #[test]
    fn mec_537_bgp_community_tag_requires_community_shaped_value() {
        for tag in [
            "65000:100",
            "4294967295:100",
            "1:2:3",
            "no-export",
            "NO-EXPORT",
        ] {
            assert!(is_bgp_community_tag(tag), "'{tag}' should look BGP-shaped");
        }
        for not_tag in ["QQSecretValue", "", "65000", "65000:", ":100", "a:b"] {
            assert!(
                !is_bgp_community_tag(not_tag),
                "'{not_tag}' should not look BGP-shaped"
            );
        }
    }

    #[test]
    fn session_config_names_are_a_closed_set() {
        for ok in [
            "limit-session",
            "session-init",
            "session-close",
            "sessions-active",
            "flow-session-count",
            "max_sessions",
        ] {
            assert!(is_session_config_name(ok), "{ok}");
        }
        for bad in [
            "session",
            "sessions",
            "session-id",
            "session_token",
            "sessionId",
            "session-hash",
            "session-data",
            "session-key",
            "auth-session",
            "x-session",
        ] {
            assert!(!is_session_config_name(bad), "{bad}");
        }
    }

    #[test]
    fn inert_session_values_are_empty_or_small_integers() {
        for ok in ["", "  ", "0", "65535", "\n    "] {
            assert!(is_inert_session_value(ok), "{ok:?}");
        }
        for bad in ["abc", "1234567890123", "12a", "session-init", "-1", "1.5"] {
            assert!(!is_inert_session_value(bad), "{bad:?}");
        }
    }

    #[test]
    fn mec_711_wep_keys_field_needs_context() {
        // Bare "keys" with no context (no sibling type, no "auth" parent)
        // must not be denylisted — that would over-match every unrelated
        // `keys` field in a vendor payload.
        assert!(!is_wep_keys_field("keys", None, None));
        assert!(!is_wep_keys_field("keys", Some("wlan"), Some("psk")));

        // Sibling `type: "wep"` on the same object is enough regardless of
        // the parent key name.
        assert!(is_wep_keys_field("keys", None, Some("wep")));
        assert!(is_wep_keys_field("keys", Some("wlan"), Some("WEP")));

        // Parent key "auth" is enough even without a sibling type.
        assert!(is_wep_keys_field("keys", Some("auth"), None));
        assert!(is_wep_keys_field("keys", Some("auth"), Some("open")));

        // Only the "keys" field name itself is eligible.
        assert!(!is_wep_keys_field("key_ids", Some("auth"), Some("wep")));
    }
}
