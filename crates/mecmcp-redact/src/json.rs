//! Recursive denylist-and-shape redaction over a parsed [`serde_json::Value`].
//!
//! Structure is preserved — this walks every object and array, so a secret
//! nested ten levels deep under an array of objects is redacted in place
//! rather than requiring a caller to know the shape in advance. That is the
//! point of the denylist approach versus [`crate::projection`]: it costs
//! nothing to add a new nested shape, at the cost of never being a positive
//! guarantee the way an allowlist projection is.

use crate::denylist::{
    is_bgp_community_field, is_bgp_community_tag, is_bgp_scope_key, is_denylisted_key,
    is_inert_session_value, is_session_config_name, is_wep_keys_field, normalize,
};
use crate::profile::Opts;
use crate::shape::looks_like_secret_value;
use serde_json::Value;

pub(crate) const PLACEHOLDER: &str = "[REDACTED]";

/// Redact `value` in place.
pub fn redact(value: &mut Value) {
    redact_inner(
        value,
        None,
        false,
        &[],
        Opts::NONE,
        &|_| false,
        &|_| false,
        &crate::text::redact,
    );
}

/// Redact `value` in place, except that a key whose normalized form appears
/// in `exempt` is never treated as denylisted — its value is still walked
/// (so a denylisted descendant, or a secret-shaped leaf value, is still
/// caught), only the key-name match is suppressed. `exempt` entries must
/// already be normalized (see [`crate::profile::Profile::new`]).
///
/// `opts.bgp_route_communities` is [`crate::profile::Profile::with_bgp_route_communities`]'s
/// flag: only when set does a `community` field under a `bgp` scope get the
/// routing-policy exemption below.
pub(crate) fn redact_with_exemptions(value: &mut Value, exempt: &[&str], opts: Opts) {
    redact_inner(
        value,
        None,
        false,
        exempt,
        opts,
        &|_| false,
        &|_| false,
        &crate::text::redact,
    );
}

/// Redact `value` in place like [`redact`], except that a key for which
/// `waive` returns true is not treated as denylisted when its value is benign
/// (null, bool, number, or empty/digits-only string); a container value under
/// such a key is walked with each child judged on its own key, and any
/// non-benign scalar left inside it is masked. This is the value-aware
/// counterpart of the XML path's keyword waiver.
///
/// Independent of [`crate::profile::Profile::with_session_config_values`]:
/// that flag fails closed (a non-inert value under a session-config name is
/// redacted wholesale) and is off unless a profile opts in. This waiver is
/// the Junos path's closed keyword set and keeps benign siblings.
pub(crate) fn redact_with_waiver(
    value: &mut Value,
    waive: &dyn Fn(&str) -> bool,
    extra_secret: &dyn Fn(&str) -> bool,
    scan: &dyn Fn(&str) -> String,
) {
    redact_inner(
        value,
        None,
        false,
        &[],
        Opts::NONE,
        waive,
        extra_secret,
        scan,
    );
}

/// Scalar with no secret-bearing content of its own: a counter or limit.
fn is_benign_scalar(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(s) => {
            let v = s.trim();
            v.is_empty() || v.bytes().all(|b| b.is_ascii_digit())
        }
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// Mask every scalar leaf under `value` that is not benign.
fn mask_non_benign(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(mask_non_benign),
        Value::Array(items) => items.iter_mut().for_each(mask_non_benign),
        leaf if is_benign_scalar(leaf) => {}
        leaf => *leaf = Value::String(PLACEHOLDER.to_string()),
    }
}

/// Whether every string leaf under `value` looks like BGP community-tag
/// syntax (see [`is_bgp_community_tag`]), so the [`is_bgp_community_field`]
/// exemption only fires when the value itself backs up the "this is routing
/// data, not a secret" claim. An empty container counts as not BGP-shaped —
/// no leaves means no evidence either way.
///
/// For an object, the keys matter too, not just the values: the exemption
/// only applies to the expected member-key shape, exactly one level deep —
/// a bare string or array of strings, or an object whose only keys are
/// `member`/`members` holding a string or array of strings. Nesting any
/// deeper, or any other key layout, is treated as not BGP-shaped even if
/// every leaf would otherwise parse as a tag — this caps the match to the
/// same depth the XML path allows, so the two formats agree on the same
/// scope.
fn looks_like_bgp_community_value(value: &Value) -> bool {
    fn is_tag_or_tags(value: &Value) -> bool {
        match value {
            Value::String(s) => is_bgp_community_tag(s),
            Value::Array(items) => {
                !items.is_empty()
                    && items
                        .iter()
                        .all(|item| matches!(item, Value::String(s) if is_bgp_community_tag(s)))
            }
            _ => false,
        }
    }
    match value {
        Value::String(_) | Value::Array(_) => is_tag_or_tags(value),
        Value::Object(map) => {
            !map.is_empty()
                && map.iter().all(|(k, v)| {
                    matches!(normalize(k).as_str(), "member" | "members") && is_tag_or_tags(v)
                })
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => false,
    }
}

/// `parent_key` is the JSON object key `value` was found under, if any — the
/// only context [`is_wep_keys_field`] needs to tell a WEP `keys` table apart
/// from an unrelated `keys` field without widening the denylist itself.
///
/// `under_bgp` is whether a `bgp` key sits somewhere above `value` in the
/// tree — the context [`is_bgp_community_field`] needs to tell a BGP route
/// community apart from an SNMP community string sharing the same bare
/// `community` field name.
///
/// `exempt` is the same key-name exemption list [`redact_with_exemptions`]
/// takes — a key whose normalized form appears in it is never treated as
/// denylisted, but its value is still walked.
///
/// `opts` gates the BGP and session-value exemptions themselves — see
/// [`redact_with_exemptions`].
///
/// `waive` is the Junos keyword waiver from [`redact_with_waiver`]. It is
/// consulted only when the profile session flag did not already decide the
/// key: a non-inert value under an opted-in session-config name is redacted
/// wholesale (fail closed), and a waived key otherwise keeps benign scalars
/// while masking the rest. `scan` is the text scan applied to string values
/// (the generic one, or a vendor-aware wrapper around it).
#[allow(clippy::too_many_arguments)]
fn redact_inner(
    value: &mut Value,
    parent_key: Option<&str>,
    under_bgp: bool,
    exempt: &[&str],
    opts: Opts,
    waive: &dyn Fn(&str) -> bool,
    extra_secret: &dyn Fn(&str) -> bool,
    scan: &dyn Fn(&str) -> String,
) {
    match value {
        Value::Object(map) => {
            let sibling_type = map.get("type").and_then(Value::as_str).map(str::to_owned);
            for (key, v) in map.iter_mut() {
                let child_under_bgp = under_bgp || is_bgp_scope_key(key);
                if exempt.contains(&normalize(key).as_str()) {
                    redact_inner(
                        v,
                        Some(key),
                        child_under_bgp,
                        exempt,
                        opts,
                        waive,
                        extra_secret,
                        scan,
                    );
                } else {
                    let is_bgp_field = opts.bgp_route_communities
                        && is_bgp_community_field(key, under_bgp)
                        && looks_like_bgp_community_value(v);
                    let session_named = opts.session_config_values && is_session_config_name(key);
                    let session_inert = session_named && is_inert_session_json_value(v);
                    let is_secret = (is_denylisted_key(key)
                        || extra_secret(key)
                        || is_wep_keys_field(key, parent_key, sibling_type.as_deref()))
                        && !is_bgp_field
                        && !session_inert;
                    // Profile session flag fails closed: a non-inert value
                    // under a session-config name is redacted wholesale, even
                    // when a keyword waiver would keep benign siblings.
                    let session_fail_closed = session_named && !session_inert;
                    if session_fail_closed {
                        *v = redact_leaf(v);
                    } else if is_secret
                        && waive(key)
                        && !is_wep_keys_field(key, parent_key, sibling_type.as_deref())
                    {
                        redact_inner(
                            v,
                            Some(key),
                            child_under_bgp,
                            exempt,
                            opts,
                            waive,
                            extra_secret,
                            scan,
                        );
                        mask_non_benign(v);
                    } else if is_secret {
                        *v = redact_leaf(v);
                    } else {
                        redact_inner(
                            v,
                            Some(key),
                            child_under_bgp,
                            exempt,
                            opts,
                            waive,
                            extra_secret,
                            scan,
                        );
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_inner(
                    item,
                    parent_key,
                    under_bgp,
                    exempt,
                    opts,
                    waive,
                    extra_secret,
                    scan,
                );
            }
        }
        Value::String(s) => {
            if looks_like_secret_value(s) {
                *s = PLACEHOLDER.to_string();
            } else {
                // Run the text-path scan over every non-denylisted string,
                // not just ones that already look like a multi-line/PEM
                // blob — a single-line `{"msg": "... password=X ..."}`
                // payload (a Mist event, syslog-as-JSON) needs the same
                // `k=v` scan (N5). `text::redact`'s non-forced path only
                // touches known value shapes, so this is a no-op on
                // ordinary strings.
                *s = scan(s);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Whether `v` carries no secret-shaped content for a session-named key:
/// containers are inert only if every descendant is inert (fail closed),
/// and scalars must be empty or a bare
/// small integer (see [`is_inert_session_value`]).
fn is_inert_session_json_value(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(_) => true,
        Value::Array(a) => a.iter().all(is_inert_session_json_value),
        Value::Object(m) => m.values().all(is_inert_session_json_value),
        Value::Number(n) => n.is_u64() || n.is_i64(),
        Value::String(s) => is_inert_session_value(s),
    }
}

/// A denylisted key's value: strings and numbers become the placeholder
/// string outright (a denylisted key is redacted regardless of shape).
/// Objects and arrays are walked recursively rather than nuked wholesale, so
/// a denylisted container key (unlikely, but not impossible for a vendor to
/// name e.g. `secrets: { ... }`) still preserves the structure — but every
/// scalar leaf inside that subtree is force-redacted regardless of its own
/// key or shape: once a caller has said "this container is secret", a value
/// two levels down (`secrets.wifi`, `pre_shared_keys[0]`) must not survive
/// just because its own immediate key or shape is not independently
/// suspicious.
fn redact_leaf(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_leaf(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_leaf).collect()),
        Value::Null => Value::Null,
        _ => Value::String(PLACEHOLDER.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn top_level_denylisted_key_is_redacted() {
        let mut v = json!({"password": "FAKEsecret123", "hostname": "r1.example.net"});
        redact(&mut v);
        assert_eq!(v["password"], "[REDACTED]");
        assert_eq!(v["hostname"], "r1.example.net");
    }

    #[test]
    fn nested_denylisted_key_under_array_of_objects_is_redacted() {
        let mut v = json!({
            "peers": [
                {"name": "peer1", "pre_shared_key": "FAKEpsk1"},
                {"name": "peer2", "pre_shared_key": "FAKEpsk2"}
            ]
        });
        redact(&mut v);
        assert_eq!(v["peers"][0]["pre_shared_key"], "[REDACTED]");
        assert_eq!(v["peers"][1]["pre_shared_key"], "[REDACTED]");
        assert_eq!(v["peers"][0]["name"], "peer1");
    }

    #[test]
    fn value_shape_catch_all_applies_to_unknown_keys() {
        let mut v = json!({"totally_new_vendor_field": "$6$fakesaltfakehash"});
        redact(&mut v);
        assert_eq!(v["totally_new_vendor_field"], "[REDACTED]");
    }

    #[test]
    fn numbers_and_booleans_under_denylisted_keys_become_placeholder_strings() {
        let mut v = json!({"api_key": 12345, "enabled": true});
        redact(&mut v);
        assert_eq!(v["api_key"], "[REDACTED]");
        // `enabled` is not denylisted and not a secret-shaped string, so a
        // non-string, non-denylisted value is left completely alone.
        assert_eq!(v["enabled"], true);
    }

    #[test]
    fn null_under_denylisted_key_stays_null() {
        let mut v = json!({"password": null});
        redact(&mut v);
        assert_eq!(v["password"], Value::Null);
    }

    #[test]
    fn f3_array_under_denylisted_key_has_every_element_redacted() {
        let mut v = json!({"pre_shared_keys": ["QQ1", "QQ2"]});
        redact(&mut v);
        assert_eq!(v["pre_shared_keys"][0], "[REDACTED]");
        assert_eq!(v["pre_shared_keys"][1], "[REDACTED]");
    }

    #[test]
    fn f3_nested_object_under_denylisted_key_has_every_leaf_redacted() {
        let mut v = json!({"secrets": {"wifi": "QQ3", "count": 2}});
        redact(&mut v);
        assert_eq!(v["secrets"]["wifi"], "[REDACTED]");
        // A non-string leaf still becomes a placeholder string, matching the
        // existing top-level `numbers_and_booleans_...` contract.
        assert_eq!(v["secrets"]["count"], "[REDACTED]");
    }

    #[test]
    fn f3_combined_repro_from_review_leaks_nothing() {
        let mut v = json!({
            "pre_shared_keys": ["QQ1", "QQ2"],
            "secrets": {"wifi": "QQ3"}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("QQ1") && !s.contains("QQ2") && !s.contains("QQ3"),
            "got: {s}"
        );
    }

    #[test]
    fn f4b_embedded_blob_in_an_unlisted_string_field_is_scrubbed() {
        let mut v = json!({
            "output": "set interfaces ge-0/0/0 unit 0\nset security ike policy p1 pre-shared-key ascii-text \"$9$fakehashvalue\"; ## SECRET-DATA\n"
        });
        redact(&mut v);
        let s = v["output"].as_str().expect("output is a string");
        assert!(!s.contains("fakehashvalue"), "got: {s}");
        assert!(
            s.contains("set interfaces ge-0/0/0 unit 0"),
            "unrelated config lines must survive: {s}"
        );
    }

    #[test]
    fn unrelated_structure_is_untouched() {
        let mut v = json!({"hostname": "r1.example.net", "vlan": 100, "up": true});
        let original = v.clone();
        redact(&mut v);
        assert_eq!(v, original);
    }

    /// MEC-711: `bgp_config`/`switch_bgp_config`/`vrrp_group` shaped BGP MD5
    /// auth keys, reachable via get/list_mist_wan_config and
    /// plan_mist_change, must be redacted under any common spelling.
    #[test]
    fn mec_711_bgp_auth_key_is_redacted() {
        let mut v = json!({
            "bgp_config": {"neighbors": [{"neighbor": "192.0.2.1", "auth_key": "QWZXbgpmd5001"}]}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(!s.contains("QWZXbgpmd5001"), "got: {s}");
    }

    /// MEC-711: `ospf_areas_network.auth_keys` is a map of key-id to key
    /// material, reachable via invoke_mist_read on site_setting,
    /// network_template, and switch profiles.
    #[test]
    fn mec_711_ospf_auth_keys_map_is_redacted() {
        let mut v = json!({
            "ospf_areas_network": {"auth_keys": {"1": "QWZXospfmd5002", "2": "QWZXospfmd5003"}}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("QWZXospfmd5002") && !s.contains("QWZXospfmd5003"),
            "got: {s}"
        );
    }

    /// MEC-711: RADIUS `keywrap_kek`/`keywrap_mack` on
    /// `radius_auth_server`/`radius_acct_server`/`mxcluster_radsec_auth_server`,
    /// reachable via list_mist_wlans (`wlan.auth_servers[]`) and
    /// invoke_mist_read.
    #[test]
    fn mec_711_radius_keywrap_kek_and_mack_are_redacted() {
        let mut v = json!({
            "wlan": {"auth_servers": [{"host": "10.0.0.1", "keywrap_kek": "QWZXkek004", "keywrap_mack": "QWZXmack005"}]}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("QWZXkek004") && !s.contains("QWZXmack005"),
            "got: {s}"
        );
    }

    /// MEC-711: `wlan_auth.keys` (WEP key table), reachable via
    /// list_mist_wlans. A bare "keys" field is not in the substring
    /// denylist (it would over-match everywhere), so this relies on the
    /// context rule: sibling `type: "wep"` on the same `auth` object.
    #[test]
    fn mec_711_wep_keys_under_sibling_type_wep_are_redacted() {
        let mut v = json!({
            "wlan": {"auth": {"type": "wep", "keys": {"0": "QWZXwep006", "1": "QWZXwep007"}}}
        });
        redact(&mut v);
        let s = v.to_string();
        assert!(
            !s.contains("QWZXwep006") && !s.contains("QWZXwep007"),
            "got: {s}"
        );
    }

    /// MEC-711: the same WEP `keys` table also matches under the "parent key
    /// is auth" half of the context rule, independent of a sibling `type`.
    #[test]
    fn mec_711_keys_nested_directly_under_auth_are_redacted() {
        let mut v = json!({"auth": {"keys": ["QWZXwep008"]}});
        redact(&mut v);
        let s = v.to_string();
        assert!(!s.contains("QWZXwep008"), "got: {s}");
    }

    /// MEC-711 (over-redaction guard): a "keys" field with neither a
    /// sibling `type: "wep"` nor an "auth" parent must survive untouched —
    /// the context rule must not degrade into a bare substring match.
    #[test]
    fn mec_711_unrelated_keys_field_is_not_redacted() {
        let mut v = json!({"ssh": {"keys": ["k1", "k2"]}});
        redact(&mut v);
        assert_eq!(v["ssh"]["keys"][0], "k1");
        assert_eq!(v["ssh"]["keys"][1], "k2");
    }

    /// MEC-711: low-confidence secret fields (`partner_key`, `account_key`,
    /// `ldap_client_key`, `openroaming_wba_client_key`) from
    /// account_zscaler_config/map_micello/sso schemas.
    #[test]
    fn mec_711_low_confidence_secret_fields_are_redacted() {
        let mut v = json!({
            "partner_key": "QWZX009",
            "account_key": "QWZX010",
            "ldap_client_key": "QWZX011",
            "openroaming_wba_client_key": "QWZX012"
        });
        redact(&mut v);
        let s = v.to_string();
        for secret in ["QWZX009", "QWZX010", "QWZX011", "QWZX012"] {
            assert!(!s.contains(secret), "got: {s}");
        }
    }

    /// N5: a single-line `k=v` secret embedded in an ordinary log/event
    /// string must be caught, not just multi-line blobs or PEM/`SECRET-DATA`
    /// markers — this is exactly the shape of a Mist event or a
    /// syslog-as-JSON payload.
    #[test]
    fn n5_single_line_kv_secret_in_an_unlisted_string_field_is_redacted() {
        // X1 (mecmcp#386 re-review): the value locator now redacts to the
        // end of the line/string once a denylisted key is found, rather than
        // guessing where the value ends — so `src=192.0.2.1`, which trails
        // `password=`, is swept too. That is the accepted over-redaction
        // cost; only the field *before* the key is unaffected.
        let mut v = json!({"msg": "login ok user=admin password=QQvalue8 src=192.0.2.1"});
        redact(&mut v);
        let s = v["msg"].as_str().expect("msg is a string");
        assert!(!s.contains("QQvalue8"), "got: {s}");
        assert!(s.contains("user=admin"), "got: {s}");
    }
}
