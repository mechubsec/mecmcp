//! The server-side table turning verified OAuth claims into tool and device scopes.
//!
//! The table lives on the resource server (like `tokens.json`); a token cannot name its own
//! authority. Everything here fails closed: no default entry, no implicit wildcard,
//! no partial matching.

use mecmcp_auth::{ActorType, ScopeSet};
use mecmcp_oidc::is_scope_token;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 256;

/// Why a scope-map file was refused.
#[derive(Debug, thiserror::Error)]
pub enum ScopeMapError {
    /// Could not read the file.
    #[error("cannot read scope map: {0}")]
    Io(String),
    /// Larger than 64 KiB.
    #[error("scope map is larger than 64 KiB")]
    TooLarge,
    /// Not valid JSON of the expected shape (includes unknown and missing fields).
    #[error("scope map is not valid JSON of the expected shape: {0}")]
    Json(String),
    /// A structural rule was violated.
    #[error("scope map invalid: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantSpec {
    tools: ScopeSet,
    devices: ScopeSet,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapFile {
    version: u32,
    #[serde(default)]
    actor_type: ActorType,
    #[serde(default, deserialize_with = "unique_keys")]
    scopes: BTreeMap<String, GrantSpec>,
    #[serde(default, deserialize_with = "unique_keys")]
    roles: BTreeMap<String, GrantSpec>,
}

/// Deserialize a table, refusing a repeated key: serde's map impl lets the last copy win,
/// so a pasted-then-edited block would silently be governed by the unedited copy.
fn unique_keys<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, GrantSpec>, D::Error> {
    struct UniqueKeys;
    impl<'de> serde::de::Visitor<'de> for UniqueKeys {
        type Value = BTreeMap<String, GrantSpec>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map of names to grants")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut table = BTreeMap::new();
            while let Some((name, spec)) = access.next_entry::<String, GrantSpec>()? {
                if table.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!("duplicate key {name:?}")));
                }
                table.insert(name, spec);
            }
            Ok(table)
        }
    }
    deserializer.deserialize_map(UniqueKeys)
}

/// What a verified token is allowed to do on this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedAuthority {
    /// Tools the caller may call.
    pub tools: ScopeSet,
    /// Devices the caller may address.
    pub devices: ScopeSet,
    /// Server-asserted actor type (from the file, not the token).
    pub actor_type: ActorType,
}

/// A validated scope map. See the module docs for the semantics.
#[derive(Debug, Clone)]
pub struct OAuthScopeMap {
    actor_type: ActorType,
    scopes: BTreeMap<String, GrantSpec>,
    roles: BTreeMap<String, GrantSpec>,
}

impl OAuthScopeMap {
    /// Parse and validate a scope-map document.
    ///
    /// # Errors
    /// Returns a [`ScopeMapError`] naming the first violated rule.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ScopeMapError> {
        let file: MapFile = serde_json::from_slice(bytes)
            .map_err(|error| ScopeMapError::Json(error.to_string()))?;
        if file.version != 1 {
            return Err(ScopeMapError::Invalid(format!(
                "unsupported version {}",
                file.version
            )));
        }
        // OAuth cannot prove a human (no verified-approver binding), and the one value would
        // also cover client-credentials accounts, making them token-asserted human approvers.
        if file.actor_type == ActorType::Human {
            return Err(ScopeMapError::Invalid(
                "actor_type \"human\" is not allowed: OAuth cannot prove a human approver; \
                 use \"agent\" or \"unknown\""
                    .to_owned(),
            ));
        }
        if file.scopes.len() > MAX_ENTRIES || file.roles.len() > MAX_ENTRIES {
            return Err(ScopeMapError::Invalid(format!(
                "more than {MAX_ENTRIES} entries in a table"
            )));
        }
        if file.scopes.is_empty() && file.roles.is_empty() {
            return Err(ScopeMapError::Invalid(
                "the map grants nothing: define at least one scope or role".to_owned(),
            ));
        }
        for (name, spec) in &file.scopes {
            // `*` would read as a default entry; it is only ever an exact-match literal.
            if !is_scope_token(name) || name == "*" {
                return Err(ScopeMapError::Invalid(format!(
                    "scope key {name:?} is not a valid scope-token (and may not be \"*\")"
                )));
            }
            validate_spec(name, spec)?;
        }
        for (name, spec) in &file.roles {
            // Printable ASCII only (space allowed: IdP group names use it), so no control,
            // zero-width or bidi character can make two role names look alike.
            let printable = name.bytes().all(|byte| matches!(byte, 0x20..=0x7E));
            if name.is_empty() || name.len() > 128 || !printable || name == "*" {
                return Err(ScopeMapError::Invalid(format!(
                    "role key {name:?} must be 1-128 bytes of printable ASCII and not \"*\""
                )));
            }
            validate_spec(name, spec)?;
        }
        Ok(Self {
            actor_type: file.actor_type,
            scopes: file.scopes,
            roles: file.roles,
        })
    }

    /// Read and validate a scope-map file (at most 64 KiB).
    ///
    /// # Errors
    /// Returns a [`ScopeMapError`] if the file is unreadable, oversized, or invalid.
    pub fn load(path: &Path) -> Result<Self, ScopeMapError> {
        // Bounded read, not a metadata length: FIFOs and /dev or /proc files report 0.
        let file =
            std::fs::File::open(path).map_err(|error| ScopeMapError::Io(error.to_string()))?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ScopeMapError::Io(error.to_string()))?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(ScopeMapError::TooLarge);
        }
        Self::from_json(&bytes)
    }

    /// The scope names this server understands, sorted, for `scopes_supported`.
    #[must_use]
    pub fn scopes_supported(&self) -> Vec<&str> {
        self.scopes.keys().map(String::as_str).collect()
    }

    /// The authority for a token carrying these scopes and roles, or `None` if it maps to
    /// nothing (no entry matched, or the union grants no tools).
    ///
    /// Tools are the **union** of the matched entries; devices are their **intersection**
    /// (`["*"]` is the identity). Unioning devices too would let one entry's tools reach
    /// another entry's devices: read-on-`*` plus write-on-`lab` must not become
    /// write-on-`*`. Disjoint device sets leave an empty device set: the token keeps its
    /// tools but no device-addressed call is allowed (fail closed; not a refusal).
    #[must_use]
    pub fn map(&self, scopes: &[String], roles: &[String]) -> Option<MappedAuthority> {
        let matched: Vec<&GrantSpec> = scopes
            .iter()
            .filter_map(|scope| self.scopes.get(scope))
            .chain(roles.iter().filter_map(|role| self.roles.get(role)))
            .collect();
        if matched.is_empty() {
            return None;
        }
        let mut tools = ScopeSet::Allowlist(Vec::new());
        let mut devices = ScopeSet::Wildcard;
        for spec in matched {
            tools = union(tools, &spec.tools);
            devices = intersect(devices, &spec.devices);
        }
        // The union can exceed MAX_SCOPE_NAMES; refuse rather than truncate.
        if tools.is_empty()
            || tools.validate("tools").is_err()
            || devices.validate("devices").is_err()
        {
            return None;
        }
        Some(MappedAuthority {
            tools,
            devices,
            actor_type: self.actor_type,
        })
    }
}

fn validate_spec(name: &str, spec: &GrantSpec) -> Result<(), ScopeMapError> {
    spec.tools
        .validate("tools")
        .and_then(|()| spec.devices.validate("devices"))
        .map_err(|error| ScopeMapError::Invalid(format!("{name}: {error}")))
}

/// Union of two grants. A tools `Wildcard` absorbs any allowlist, and a tools wildcard
/// excludes write tools at enforcement (`ScopeSet::allows_tool`). So a token holding both
/// a `["*"]` mapping and a mapping that names a write tool ends up *without* that write
/// tool. Deliberate and fail-safe: `ScopeSet` cannot express "wildcard plus these write
/// tools", and narrowing is the safe direction. Grant write tools from a non-wildcard entry.
fn union(accumulated: ScopeSet, next: &ScopeSet) -> ScopeSet {
    match (accumulated, next) {
        (ScopeSet::Wildcard, _) | (_, ScopeSet::Wildcard) => ScopeSet::Wildcard,
        (ScopeSet::Allowlist(mut names), ScopeSet::Allowlist(more)) => {
            for name in more {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
            ScopeSet::Allowlist(names)
        }
    }
}

/// Intersection of two device grants; `Wildcard` is the identity.
fn intersect(accumulated: ScopeSet, next: &ScopeSet) -> ScopeSet {
    match (accumulated, next) {
        (accumulated, ScopeSet::Wildcard) => accumulated,
        (ScopeSet::Wildcard, next) => next.clone(),
        (ScopeSet::Allowlist(mut names), ScopeSet::Allowlist(more)) => {
            names.retain(|name| more.contains(name));
            ScopeSet::Allowlist(names)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MAP: &str = r#"{
        "version": 1,
        "actor_type": "agent",
        "scopes": {
            "junos:read": {"tools": ["get_junos_config"], "devices": ["srx-1"]},
            "junos:ops":  {"tools": ["gather_device_facts"], "devices": ["srx-2"]},
            "junos:none": {"tools": [], "devices": []}
        },
        "roles": {"netops": {"tools": ["get_device_list"], "devices": ["srx-1"]}}
    }"#;

    fn map() -> OAuthScopeMap {
        OAuthScopeMap::from_json(MAP.as_bytes()).unwrap()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_mapped_scope_grants_exactly_what_the_file_says() {
        let authority = map().map(&strings(&["junos:read"]), &[]).unwrap();
        assert_eq!(
            authority.tools,
            ScopeSet::Allowlist(strings(&["get_junos_config"]))
        );
        assert_eq!(authority.devices, ScopeSet::Allowlist(strings(&["srx-1"])));
        assert_eq!(authority.actor_type, mecmcp_auth::ActorType::Agent);
    }

    #[test]
    fn scopes_and_roles_union_tools_and_intersect_devices() {
        let authority = map()
            .map(&strings(&["junos:read"]), &strings(&["netops"]))
            .unwrap();
        assert_eq!(
            authority.tools,
            ScopeSet::Allowlist(strings(&["get_junos_config", "get_device_list"]))
        );
        assert_eq!(authority.devices, ScopeSet::Allowlist(strings(&["srx-1"])));
    }

    /// (c) Disjoint explicit device sets intersect to no devices: the tools stay, but no
    /// device-addressed call is allowed.
    #[test]
    fn disjoint_device_sets_leave_no_devices() {
        let authority = map()
            .map(&strings(&["junos:read", "junos:ops"]), &[])
            .unwrap();
        assert_eq!(authority.devices, ScopeSet::Allowlist(Vec::new()));
        assert!(!authority.devices.allows("srx-1"));
        assert!(!authority.devices.allows("srx-2"));
    }

    /// (a) read-on-every-device plus write-on-lab must not become write-on-every-device.
    #[test]
    fn a_write_entry_does_not_inherit_another_entrys_device_wildcard() {
        let json = r#"{"version":1,"scopes":{
            "junos:read":{"tools":["get_junos_config"],"devices":["*"]},
            "junos:lab":{"tools":["load_and_commit_config"],"devices":["lab-srx1"]}}}"#;
        let map = OAuthScopeMap::from_json(json.as_bytes()).unwrap();
        let both = map
            .map(&strings(&["junos:read", "junos:lab"]), &[])
            .unwrap();
        assert!(
            both.tools
                .allows_tool("load_and_commit_config", &["load_and_commit_config"])
        );
        assert!(both.devices.allows("lab-srx1"));
        assert!(!both.devices.allows("core-srx1"));
    }

    /// (b) Two all-device entries still reach every device.
    #[test]
    fn two_device_wildcards_stay_a_wildcard() {
        let json = r#"{"version":1,"scopes":{
            "a":{"tools":["get_junos_config"],"devices":["*"]},
            "b":{"tools":["get_device_list"],"devices":["*"]}}}"#;
        let map = OAuthScopeMap::from_json(json.as_bytes()).unwrap();
        let both = map.map(&strings(&["a", "b"]), &[]).unwrap();
        assert_eq!(both.devices, ScopeSet::Wildcard);
    }

    #[test]
    fn an_unmapped_scope_grants_nothing() {
        assert!(map().map(&strings(&["junos:admin"]), &[]).is_none());
        assert!(map().map(&strings(&["openid", "profile"]), &[]).is_none());
        assert!(map().map(&[], &[]).is_none());
    }

    #[test]
    fn matching_is_exact_and_case_sensitive() {
        for near_miss in [
            "JUNOS:READ",
            "junos:read ",
            "junos:rea",
            "junos:read2",
            "junos:*",
            "*",
        ] {
            assert!(
                map().map(&strings(&[near_miss]), &[]).is_none(),
                "{near_miss:?} must not match"
            );
        }
    }

    #[test]
    fn an_entry_that_grants_no_tools_maps_to_nothing() {
        assert!(map().map(&strings(&["junos:none"]), &[]).is_none());
    }

    #[test]
    fn unknown_scopes_alongside_a_mapped_one_add_nothing() {
        let with_noise = map()
            .map(&strings(&["openid", "junos:read", "evil"]), &[])
            .unwrap();
        let alone = map().map(&strings(&["junos:read"]), &[]).unwrap();
        assert_eq!(with_noise, alone);
    }

    #[test]
    fn an_explicit_wildcard_is_honoured_only_when_written() {
        let json = r#"{"version":1,"scopes":{"all":{"tools":["*"],"devices":["*"]}}}"#;
        let authority = OAuthScopeMap::from_json(json.as_bytes())
            .unwrap()
            .map(&strings(&["all"]), &[])
            .unwrap();
        assert_eq!(authority.tools, ScopeSet::Wildcard);
        assert_eq!(authority.devices, ScopeSet::Wildcard);
        assert_eq!(authority.actor_type, mecmcp_auth::ActorType::Unknown);
    }

    #[test]
    fn load_time_refusals() {
        let cases: &[(&str, &str)] = &[
            (
                r#"{"version":2,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#,
                "version",
            ),
            (r#"{"version":1,"scopes":{"a":{"tools":["t"]}}}"#, "devices"),
            (
                r#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["d"],"extra":1}}}"#,
                "extra",
            ),
            (
                r#"{"version":1,"extra":1,"scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#,
                "extra",
            ),
            (
                r#"{"version":1,"scopes":{"two words":{"tools":["t"],"devices":["d"]}}}"#,
                "scope-token",
            ),
            (
                r#"{"version":1,"scopes":{"":{"tools":["t"],"devices":["d"]}}}"#,
                "scope-token",
            ),
            (
                r#"{"version":1,"scopes":{"a":{"tools":["t","t"],"devices":["d"]}}}"#,
                "duplicate",
            ),
            (
                r#"{"version":1,"scopes":{"a":{"tools":["*","t"],"devices":["d"]}}}"#,
                "'*'",
            ),
            (r#"{"version":1,"scopes":{},"roles":{}}"#, "grants nothing"),
            (
                r#"{"version":1,"actor_type":"human","scopes":{"a":{"tools":["t"],"devices":["d"]}}}"#,
                "actor_type \"human\"",
            ),
            ("not json", "JSON"),
        ];
        for (json, needle) in cases {
            let error = OAuthScopeMap::from_json(json.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{json} -> {error}");
        }
    }

    #[test]
    fn scopes_supported_lists_scope_keys_sorted_and_not_roles() {
        assert_eq!(
            map().scopes_supported(),
            vec!["junos:none", "junos:ops", "junos:read"]
        );
    }

    fn refusal(json: &str) -> String {
        OAuthScopeMap::from_json(json.as_bytes())
            .unwrap_err()
            .to_string()
    }

    fn table(count: usize) -> String {
        (0..count)
            .map(|index| format!(r#""k{index}":{{"tools":["t"],"devices":["d"]}}"#))
            .collect::<Vec<_>>()
            .join(",")
    }

    #[test]
    fn duplicate_keys_are_refused() {
        let scopes = r#"{"version":1,"scopes":{
            "junos:read":{"tools":["get_junos_config"],"devices":["srx-1"]},
            "junos:read":{"tools":["*"],"devices":["*"]}}}"#;
        let roles = r#"{"version":1,"roles":{
            "netops":{"tools":["t"],"devices":["d"]},
            "netops":{"tools":["*"],"devices":["*"]}}}"#;
        for json in [scopes, roles] {
            assert!(refusal(json).contains("duplicate key"), "{json}");
        }
    }

    #[test]
    fn a_star_key_is_refused() {
        assert!(
            refusal(r#"{"version":1,"scopes":{"*":{"tools":["t"],"devices":["d"]}}}"#)
                .contains("scope key")
        );
        assert!(
            refusal(r#"{"version":1,"roles":{"*":{"tools":["t"],"devices":["d"]}}}"#)
                .contains("role key")
        );
    }

    #[test]
    fn role_keys_must_be_printable_ascii() {
        let long = "r".repeat(129);
        for bad in [
            "",
            long.as_str(),
            r"net\u200bops",
            r"net\u202eops",
            r"net\nops",
            r"net\u00f6ps",
        ] {
            let json =
                format!(r#"{{"version":1,"roles":{{"{bad}":{{"tools":["t"],"devices":["d"]}}}}}}"#);
            assert!(refusal(&json).contains("role key"), "{bad:?}");
        }
        let json = r#"{"version":1,"roles":{"Domain Admins":{"tools":["t"],"devices":["d"]}}}"#;
        let map = OAuthScopeMap::from_json(json.as_bytes()).unwrap();
        assert!(map.map(&[], &strings(&["Domain Admins"])).is_some());
    }

    #[test]
    fn each_table_is_capped_at_256_entries() {
        for name in ["scopes", "roles"] {
            let at_cap = format!(r#"{{"version":1,"{name}":{{{}}}}}"#, table(256));
            assert!(
                OAuthScopeMap::from_json(at_cap.as_bytes()).is_ok(),
                "{name}"
            );
            let over = format!(r#"{{"version":1,"{name}":{{{}}}}}"#, table(257));
            assert!(refusal(&over).contains("more than 256"), "{name}");
        }
    }

    #[test]
    fn a_tools_wildcard_absorbs_an_explicit_write_tool_grant() {
        let json = r#"{"version":1,"scopes":{
            "junos:admin":{"tools":["*"],"devices":["*"]},
            "junos:write":{"tools":["load_and_commit_config"],"devices":["srx-1"]}}}"#;
        let map = OAuthScopeMap::from_json(json.as_bytes()).unwrap();
        let write_tools = ["load_and_commit_config"];
        let alone = map.map(&strings(&["junos:write"]), &[]).unwrap();
        assert!(
            alone
                .tools
                .allows_tool("load_and_commit_config", &write_tools)
        );
        let both = map
            .map(&strings(&["junos:admin", "junos:write"]), &[])
            .unwrap();
        assert_eq!(both.tools, ScopeSet::Wildcard);
        assert!(
            !both
                .tools
                .allows_tool("load_and_commit_config", &write_tools)
        );
    }

    #[test]
    fn load_bounds_a_file_that_reports_no_length() {
        let error = OAuthScopeMap::load(Path::new("/dev/zero")).unwrap_err();
        assert!(matches!(error, ScopeMapError::TooLarge), "{error}");
    }

    #[test]
    fn load_refuses_an_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("map.json");
        std::fs::write(&path, vec![b' '; 70_000]).unwrap();
        assert!(
            OAuthScopeMap::load(&path)
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
    }

    #[test]
    fn the_scope_map_example_in_the_operator_guide_loads() {
        // Read at run time: a packaged crate has no workspace `docs/`, so skip there.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/OAUTH.md");
        let Ok(guide) = std::fs::read_to_string(path) else {
            return;
        };
        let start = guide.find("```json\n").unwrap() + "```json\n".len();
        let end = start + guide[start..].find("\n```").unwrap();
        let map = OAuthScopeMap::from_json(&guide.as_bytes()[start..end]).unwrap();
        assert_eq!(map.scopes_supported(), ["junos:lab", "junos:read"]);
    }
}
