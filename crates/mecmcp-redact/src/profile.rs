//! Vendor-declared extensions to the denylist-and-shape JSON scan.
//!
//! `crate::json::redact` already covers the secret shapes common to every
//! vendor. Two kinds of policy are not generic, and the shared crate cannot
//! infer either from a vendor's schema on its own — it has no dependency on
//! any vendor's schema, the same reason [`crate::projection::FieldAllowlist`]
//! takes its field list from the caller:
//!
//! - **Wholesale fields**: a field whose value is a vendor-rendered body that
//!   can embed a secret in a shape the generic line/key scan is not
//!   guaranteed to recognize. The whole value is withheld as a unit rather
//!   than trusted to a best-effort scan.
//! - **Key exemptions**: a field name that collides with a denylist entry by
//!   substring in this vendor's schema, but is not a secret (an opaque paging
//!   cursor, a logging flag). Redacting it is a functional regression (MEC-440
//!   B1: redacting `continuation_token` breaks paging) or a security
//!   regression in the *other* direction (MEC-973 F1: hiding a policy rule's
//!   real logging state from the model reviewing a write).
//!
//! A vendor server declares a [`Profile`] once, as a `const`, the same way
//! [`crate::projection::FieldAllowlist`] is declared, and calls
//! [`crate::redact_json_value_with_profile`] instead of
//! [`crate::redact_json_value`]. Everything [`crate::redact_json_value`]
//! already catches is still caught — a `Profile` only adds exceptions and
//! extra withholding, it never narrows the generic scan.
//!
//! # What a key exemption does and does not suppress
//!
//! An exemption only suppresses the key-*name* denylist match for that exact
//! key. It does not exempt the value: the generic scan still recurses into
//! it, so a denylisted key nested under an exempted container is still
//! redacted, and a value that is itself secret-shaped (a PEM block, a
//! password hash) is still caught by the value-shape scan even though its
//! key name was exempted.

use serde_json::Value;

use crate::denylist::normalize;
use crate::json::PLACEHOLDER;

/// A vendor's extensions to the generic denylist-and-shape scan: fields
/// withheld as a whole, and field names exempted from the denylist despite a
/// substring collision.
///
/// Construct with [`Profile::new`] as a `const`, so a server declares its
/// vendor-specific exceptions once, at compile time, rather than building the
/// lists per call.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    wholesale_redact_keys: &'static [&'static str],
    key_exemptions: &'static [&'static str],
    bgp_route_communities: bool,
    session_config_values: bool,
}

impl Profile {
    /// Build a profile from fixed field-name lists. Each entry must already
    /// be normalized — lowercase ASCII letters and digits only, the same
    /// alphabet a JSON key is normalized into before matching — so
    /// `"site_config"` is written as `"siteconfig"`, not `"site_config"` or
    /// `"siteConfig"`. At match time the JSON key is normalized the same
    /// way, so `"site_config"`, `"siteConfig"`, and `"site-config"` in the
    /// input all match the one entry `"siteconfig"`.
    ///
    /// Because every profile is declared as a `const`, an entry that is
    /// empty or carries any other byte (an underscore, a hyphen, an
    /// uppercase letter) is a build-time panic rather than a silently
    /// unmatchable entry — a field spelled wrong here would otherwise lose
    /// wholesale withholding or an exemption with no test failure.
    ///
    /// # Panics
    ///
    /// Panics (at compile time, from `const` evaluation) if any entry in
    /// either list is empty or contains a byte other than an ASCII lowercase
    /// letter or digit.
    #[must_use]
    pub const fn new(
        wholesale_redact_keys: &'static [&'static str],
        key_exemptions: &'static [&'static str],
    ) -> Self {
        check_all_normalized(wholesale_redact_keys);
        check_all_normalized(key_exemptions);
        Self {
            wholesale_redact_keys,
            key_exemptions,
            bgp_route_communities: false,
            session_config_values: false,
        }
    }

    /// Opt this profile into the BGP route-community exemption: a
    /// `community` field (JSON) or element (XML) directly under a `bgp`
    /// scope, whose value looks like BGP community-tag syntax rather than an
    /// arbitrary secret, survives redaction. Off by default, so linking this
    /// crate never loosens the denylist for a vendor that has not declared
    /// it needs this exemption. [`crate::redact_json_value_with_profile`]
    /// reads this flag from the profile it is called with;
    /// [`crate::redact_xml_str_with_profile`] does the same for the XML
    /// path. The plain [`crate::redact_json_value`] and
    /// [`crate::redact_xml_str`] entry points never apply it.
    #[must_use]
    pub const fn with_bgp_route_communities(mut self) -> Self {
        self.bgp_route_communities = true;
        self
    }

    /// Opt this profile into value-aware handling of `session`-named
    /// configuration fields: a small closed set of operational names
    /// (`limit-session`, `session-init`, `session-close`, and `*-session-*`
    /// counters built only from a fixed vocabulary) survives redaction when
    /// its value is empty or a bare integer. Any other `session`-named field
    /// (`session-id`, `session-token`, bare `session`, ...) and any
    /// non-integer value under one of these names is still redacted. Off by
    /// default; applies to both the JSON and XML paths.
    #[must_use]
    pub const fn with_session_config_values(mut self) -> Self {
        self.session_config_values = true;
        self
    }

    /// Reject a key exemption that normalizes to exactly a denylisted term —
    /// one of [`crate::denylist::DENYLISTED_KEYS`] (substring-matched
    /// elsewhere, but refused here as a whole name: `"token"` or
    /// `"password"` is refused, `"continuationtoken"` is fine), or one of the
    /// exact-match-only denylist terms that [`crate::denylist::is_denylisted_key`]
    /// also checks (`"key"`, and `"keys"` given the right sibling/parent
    /// context — see [`crate::denylist::is_wep_keys_field`]). Nothing in
    /// [`Profile::new`] can check this at compile time (the denylist is
    /// matched at runtime), so a vendor profile's own test suite should call
    /// this once and assert `Ok(())`, the same way it asserts
    /// denylist-completeness over its own schema.
    ///
    /// # Errors
    ///
    /// Returns the offending exemption entry if one exactly matches a
    /// denylist term.
    pub fn check_exemptions(&self) -> Result<(), &'static str> {
        for &exemption in self.key_exemptions {
            if crate::denylist::DENYLISTED_KEYS.contains(&exemption)
                || crate::denylist::DENYLISTED_EXACT_KEYS.contains(&exemption)
                || crate::denylist::CONTEXTUALLY_DENYLISTED_EXACT_KEYS.contains(&exemption)
            {
                return Err(exemption);
            }
        }
        Ok(())
    }
}

/// `const fn` panic, so [`Profile::new`] rejects a bad entry at compile time
/// for every profile, which is always declared as a `const`.
const fn check_all_normalized(entries: &[&str]) {
    let mut i = 0;
    while i < entries.len() {
        check_normalized(entries[i]);
        i += 1;
    }
}

const fn check_normalized(entry: &str) {
    let bytes = entry.as_bytes();
    if bytes.is_empty() {
        panic!("mecmcp_redact::Profile entry must not be empty");
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
            panic!(
                "mecmcp_redact::Profile entry must be pre-normalized: lowercase ASCII letters and digits only"
            );
        }
        i += 1;
    }
}

/// Redact `value` in place under the generic denylist-and-shape scan, then
/// apply `profile`'s vendor-specific extensions.
///
/// Order matters and is fixed, not a caller choice: wholesale fields are
/// withheld *before* the generic scan ever sees them (so the scan cannot
/// partially rewrite a body this profile says should be withheld as a unit),
/// and key exemptions suppress only the key-name denylist match for that
/// exact key — the generic scan still recurses into an exempted key's value,
/// so a denylisted descendant or a secret-shaped leaf is still caught.
pub fn redact_json_value_with_profile(value: &mut Value, profile: &Profile) {
    redact_wholesale_fields(value, profile.wholesale_redact_keys);
    crate::json::redact_with_exemptions(value, profile.key_exemptions, opts(profile));
}

/// Per-profile exemption flags, read by [`crate::xml::redact_with_profile`]
/// and [`crate::json::redact_with_exemptions`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Opts {
    pub(crate) bgp_route_communities: bool,
    pub(crate) session_config_values: bool,
}

impl Opts {
    /// No exemptions: the generic scan.
    pub(crate) const NONE: Self = Self {
        bgp_route_communities: false,
        session_config_values: false,
    };
}

pub(crate) fn opts(profile: &Profile) -> Opts {
    Opts {
        bgp_route_communities: profile.bgp_route_communities,
        session_config_values: profile.session_config_values,
    }
}

/// Replace every value under a [`Profile::wholesale_redact_keys`] key with
/// the redaction placeholder, at any depth, before the generic scan runs.
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
fn redact_wholesale_fields(value: &mut Value, wholesale_redact_keys: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if wholesale_redact_keys.contains(&normalize(key).as_str()) {
                    if !child.is_null() {
                        *child = Value::String(PLACEHOLDER.to_owned());
                    }
                } else {
                    redact_wholesale_fields(child, wholesale_redact_keys);
                }
            }
        }
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| redact_wholesale_fields(item, wholesale_redact_keys)),
        _ => {}
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_PROFILE: Profile = Profile::new(
        &["siteconfig", "cpeconfig"],
        &["continuationtoken", "nextpagetoken", "maxsessions"],
    );

    #[test]
    fn wholesale_key_is_withheld_as_a_unit_regardless_of_case_or_separator() {
        for key in ["site_config", "siteConfig", "site-config"] {
            let mut v = json!({ key: {"body": "set security ike ... pre-shared-key leak"} });
            redact_json_value_with_profile(&mut v, &TEST_PROFILE);
            assert_eq!(v[key], PLACEHOLDER, "{key} must be withheld wholesale");
        }
    }

    #[test]
    fn wholesale_key_null_value_stays_null() {
        let mut v = json!({"site_config": null});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert!(v["site_config"].is_null());
    }

    #[test]
    fn exempted_key_survives_despite_denylist_substring_collision() {
        let mut v = json!({"continuation_token": "page-cursor-abc", "accessToken": "QQsecret"});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["continuation_token"], "page-cursor-abc");
        assert_eq!(v["accessToken"], PLACEHOLDER);
    }

    #[test]
    fn unexempted_key_with_the_same_denylist_substring_is_still_redacted() {
        // Only the exact exempted names survive; an unlisted `session*`
        // field must still be caught by the generic scan — an exemption
        // list is not a way to carve out a whole denylist term.
        let mut v = json!({"session_id": "s1", "max_session_number": 5});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["session_id"], PLACEHOLDER);
        assert_eq!(v["max_session_number"], PLACEHOLDER);
    }

    #[test]
    fn exempted_key_matching_full_name_survives_while_sibling_is_redacted() {
        let mut v = json!({"max_sessions": 5, "session_id": "s1"});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["max_sessions"], 5);
        assert_eq!(v["session_id"], PLACEHOLDER);
    }

    #[test]
    fn exemption_and_wholesale_withholding_both_apply_in_one_pass() {
        let mut v = json!({
            "nextPageToken": "abc",
            "cpe_config": {"body": "pre-shared-key leak"},
            "password": "hunter2",
        });
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["nextPageToken"], "abc");
        assert_eq!(v["cpe_config"], PLACEHOLDER);
        assert_eq!(v["password"], PLACEHOLDER);
    }

    #[test]
    fn nested_exempted_and_wholesale_keys_are_handled_at_any_depth() {
        let mut v = json!({"site": {"cpe_devices": [{
            "cpe_config": {"body": "..."},
            "continuation_token": "cursor",
            "psk": "shared"
        }]}});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        let device = &v["site"]["cpe_devices"][0];
        assert_eq!(device["cpe_config"], PLACEHOLDER);
        assert_eq!(device["continuation_token"], "cursor");
        assert_eq!(device["psk"], PLACEHOLDER);
    }

    #[test]
    fn an_empty_profile_behaves_exactly_like_the_generic_scan() {
        const EMPTY: Profile = Profile::new(&[], &[]);
        let mut a = json!({"password": "hunter2", "name": "a"});
        let mut b = a.clone();
        redact_json_value_with_profile(&mut a, &EMPTY);
        crate::redact_json_value(&mut b);
        assert_eq!(a, b);
    }

    /// F3: exemption only suppresses the key-*name* match. A value that is
    /// itself secret-shaped under an exempted key must still be caught by
    /// the value-shape scan.
    #[test]
    fn exempted_key_with_a_secret_shaped_value_is_still_redacted() {
        let mut v = json!({"continuation_token": "$6$fakesaltfakehash"});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["continuation_token"], PLACEHOLDER);
    }

    /// F3: a denylisted key nested under an exempted container key must
    /// still be redacted — exemption does not withhold the whole subtree
    /// from the scan, only the exempted key's own name match.
    #[test]
    fn denylisted_child_under_an_exempted_key_is_still_redacted() {
        let mut v = json!({"continuation_token": {"password": "hunter2"}});
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert_eq!(v["continuation_token"]["password"], PLACEHOLDER);
    }

    /// F2 regression: pins that keys from the input are never renamed into
    /// an exempted field name, no matter what shape they take. This probes
    /// specifically with a key shape that an earlier, since-removed
    /// implementation briefly used internally for its own bookkeeping, to
    /// make sure a future reimplementation of that kind of mechanism can't
    /// reopen the same hole: untrusted input must never be able to collide
    /// with an internal marker and get renamed, or overwritten, as a result.
    #[test]
    fn untrusted_input_cannot_forge_an_exempted_key_via_a_marker_shaped_key() {
        const MARKER_SHAPED_KEY: &str = "\u{0}mecmcp-redact-profile-guard\u{0}0";
        let mut v = json!({
            "nested": {
                "continuation_token": "real-cursor",
                MARKER_SHAPED_KEY: "sibling-of-the-real-key",
            },
            MARKER_SHAPED_KEY: "top-level-attacker-value",
        });
        redact_json_value_with_profile(&mut v, &TEST_PROFILE);
        assert!(
            v.get("continuation_token").is_none(),
            "a marker-shaped input key must never be renamed into an exempted field name that didn't exist in the input"
        );
        assert_eq!(
            v[MARKER_SHAPED_KEY], "top-level-attacker-value",
            "a marker-shaped input key must keep its own value, not be consumed by internal bookkeeping"
        );
        assert_eq!(
            v["nested"]["continuation_token"], "real-cursor",
            "the real exempted key must keep its own value"
        );
        assert_eq!(
            v["nested"][MARKER_SHAPED_KEY], "sibling-of-the-real-key",
            "a marker-shaped input key sitting beside the real exempted key must not be silently overwritten"
        );
    }

    /// F4: an exemption list must not be able to carve out a whole denylist
    /// term — only a name that merely contains one, like
    /// `continuationtoken`, is a legitimate exemption.
    #[test]
    fn check_exemptions_rejects_an_exact_denylist_term() {
        const BAD: Profile = Profile::new(&[], &["token"]);
        assert_eq!(BAD.check_exemptions(), Err("token"));
    }

    /// R1: `DENYLISTED_KEYS` is not the only source of denylisted field
    /// names — `"key"` is denylisted under exact match
    /// ([`crate::denylist::DENYLISTED_EXACT_KEYS`]), and `"keys"` is
    /// denylisted given sibling/parent context
    /// ([`crate::denylist::is_wep_keys_field`]). An exemption list must not
    /// be able to carve either of those out either.
    #[test]
    fn check_exemptions_rejects_the_exact_match_only_denylist_terms() {
        const BAD_KEY: Profile = Profile::new(&[], &["key"]);
        assert_eq!(BAD_KEY.check_exemptions(), Err("key"));

        const BAD_KEYS: Profile = Profile::new(&[], &["keys"]);
        assert_eq!(BAD_KEYS.check_exemptions(), Err("keys"));
    }

    #[test]
    fn check_exemptions_accepts_a_substring_collision() {
        assert_eq!(TEST_PROFILE.check_exemptions(), Ok(()));
    }

    /// F1: an entry that is not already normalized must fail to build
    /// rather than silently losing wholesale withholding for every spelling
    /// variant except the one written.
    #[test]
    #[should_panic(expected = "pre-normalized")]
    fn new_panics_on_an_unnormalized_wholesale_entry() {
        let _ = Profile::new(&["site_config"], &[]);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn new_panics_on_an_empty_entry() {
        let _ = Profile::new(&[""], &[]);
    }
}
