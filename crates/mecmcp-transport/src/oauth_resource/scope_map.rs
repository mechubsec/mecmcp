//! The server-side table turning verified OAuth claims into tool and device scopes.
//!
//! The table lives on the resource server (like `tokens.json`); a token cannot name its own
//! authority. Everything here fails closed: no default entry, no implicit wildcard,
//! no partial matching.

use mecmcp_auth::{ActorType, DeviceAttributeSource, DeviceAttrs, ScopeSet, SelectorSet};
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
    /// Optional attribute selectors (AND) that narrow `devices` to matching inventory devices.
    #[serde(default, deserialize_with = "selectors_not_null")]
    device_selectors: Option<Vec<String>>,
    /// `device_selectors`, compiled at load; never read from the file.
    #[serde(skip)]
    compiled: Option<SelectorSet>,
}

/// Absent means "no selectors"; an explicit `null` must not silently mean the same, or an
/// operator's broken edit would widen the entry to every device its `devices` names.
fn selectors_not_null<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}

impl GrantSpec {
    /// Devices this entry grants right now. Selectors are resolved against the live
    /// inventory attributes, so a SIGHUP reload takes effect on the next request; an absent
    /// source or an attribute-less device matches nothing (fail closed).
    fn effective_devices(&self, snapshot: &[(String, DeviceAttrs)]) -> ScopeSet {
        let Some(selectors) = &self.compiled else {
            return self.devices.clone();
        };
        selectors.narrow(&self.devices, snapshot)
    }
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
        let mut file: MapFile = serde_json::from_slice(bytes)
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
        // Compile selectors first: an expression that cannot compile fails startup.
        for (name, spec) in file.scopes.iter_mut().chain(file.roles.iter_mut()) {
            let Some(expressions) = &spec.device_selectors else {
                continue;
            };
            spec.compiled = Some(
                SelectorSet::compile(expressions)
                    .map_err(|error| ScopeMapError::Invalid(format!("{name}: {error}")))?,
            );
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
    /// The file defines every OAuth caller's authority, so on Unix it is held to the
    /// workspace's no-secret config rules (`CredentialFileRole::ConfigNoSecret`): opened with
    /// `O_NOFOLLOW` (no symlink), a regular file, mode within `0640`, owned by the process
    /// euid or root (a root process accepts any owner). All checks run on the one fd that is
    /// then read, so the path cannot be swapped between check and use.
    ///
    /// # Errors
    /// Returns a [`ScopeMapError`] if the file is unreadable, unsafe, oversized, or invalid.
    pub fn load(path: &Path) -> Result<Self, ScopeMapError> {
        let file = open_hardened(path)?;
        Self::from_json(&read_bounded(file)?)
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
        self.map_with(scopes, roles, None)
    }

    /// [`map`](Self::map) with a live view of device attributes for entries that carry
    /// `device_selectors`. Each such entry's devices are its `devices` names that also match
    /// every selector, then intersected with the other entries exactly as before.
    #[must_use]
    pub fn map_with(
        &self,
        scopes: &[String],
        roles: &[String],
        attributes: Option<&dyn DeviceAttributeSource>,
    ) -> Option<MappedAuthority> {
        let matched: Vec<&GrantSpec> = scopes
            .iter()
            .filter_map(|scope| self.scopes.get(scope))
            .chain(roles.iter().filter_map(|role| self.roles.get(role)))
            .collect();
        if matched.is_empty() {
            return None;
        }
        // One snapshot per authentication: every entry is judged against the same inventory
        // generation, so a concurrent reload cannot let two entries disagree about a device.
        let snapshot = if matched.iter().any(|spec| spec.compiled.is_some()) {
            attributes
                .map(DeviceAttributeSource::device_attributes)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut tools = ScopeSet::Allowlist(Vec::new());
        let mut devices = ScopeSet::Wildcard;
        for spec in matched {
            tools = union(tools, &spec.tools);
            devices = intersect(devices, &spec.effective_devices(&snapshot));
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

/// Open `path` and refuse anything but a regular, non-symlink, tightly-moded, trusted-owner
/// file, judged by `fstat` on the returned descriptor.
#[cfg(unix)]
fn open_hardened(path: &Path) -> Result<std::fs::File, ScopeMapError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    use rustix::io::Errno;

    // NONBLOCK: a FIFO with no writer would otherwise hang the open before the type check.
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == Errno::LOOP {
            return ScopeMapError::Io(
                "refusing a symlink; point --oauth-scope-map at the file itself".to_owned(),
            );
        }
        ScopeMapError::Io(std::io::Error::from(error).to_string())
    })?;
    let stat = fstat(&descriptor)
        .map_err(|error| ScopeMapError::Io(std::io::Error::from(error).to_string()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(ScopeMapError::Io(
            "refusing a file that is not a regular file".to_owned(),
        ));
    }
    let mode = stat.st_mode & 0o777;
    if mode & !0o640 != 0 {
        return Err(ScopeMapError::Io(format!(
            "refusing mode {mode:04o}, looser than 0640; run chmod 0640 on it"
        )));
    }
    let effective = rustix::process::geteuid().as_raw();
    if effective != 0 && stat.st_uid != effective && stat.st_uid != 0 {
        return Err(ScopeMapError::Io(format!(
            "refusing owner uid {}, neither the service user (uid {effective}) nor root",
            stat.st_uid
        )));
    }
    Ok(std::fs::File::from(descriptor))
}

#[cfg(not(unix))]
fn open_hardened(path: &Path) -> Result<std::fs::File, ScopeMapError> {
    std::fs::File::open(path).map_err(|error| ScopeMapError::Io(error.to_string()))
}

/// Bounded read, not a metadata length: procfs and similar files report 0.
fn read_bounded(file: impl Read) -> Result<Vec<u8>, ScopeMapError> {
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ScopeMapError::Io(error.to_string()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(ScopeMapError::TooLarge);
    }
    Ok(bytes)
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
    fn read_bounded_caps_a_source_that_reports_no_length() {
        let error = read_bounded(std::fs::File::open("/dev/zero").unwrap()).unwrap_err();
        assert!(matches!(error, ScopeMapError::TooLarge), "{error}");
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    fn set_mode(_: &Path, _: u32) {}

    #[cfg(unix)]
    fn written_map(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("map.json");
        std::fs::write(&path, MAP).unwrap();
        set_mode(&path, mode);
        (directory, path)
    }

    #[cfg(unix)]
    #[test]
    fn load_accepts_a_0640_file_owned_by_the_process() {
        let (_directory, path) = written_map(0o640);
        assert!(OAuthScopeMap::load(&path).is_ok());
        set_mode(&path, 0o600);
        assert!(OAuthScopeMap::load(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_group_or_world_writable_file() {
        for mode in [0o646, 0o660, 0o666, 0o644] {
            let (_directory, path) = written_map(mode);
            let error = OAuthScopeMap::load(&path).unwrap_err();
            assert!(matches!(error, ScopeMapError::Io(_)), "{mode:o}: {error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_symlink() {
        let (directory, path) = written_map(0o640);
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let error = OAuthScopeMap::load(&link).unwrap_err();
        assert!(error.to_string().contains("refusing"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_non_regular_file() {
        let error = OAuthScopeMap::load(Path::new("/dev/null")).unwrap_err();
        assert!(error.to_string().contains("refusing"), "{error}");
    }

    #[test]
    fn load_refuses_an_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("map.json");
        std::fs::write(&path, vec![b' '; 70_000]).unwrap();
        set_mode(&path, 0o640);
        assert!(
            OAuthScopeMap::load(&path)
                .unwrap_err()
                .to_string()
                .contains("64 KiB")
        );
    }

    struct Fleet(Vec<(String, mecmcp_auth::DeviceAttrs)>);

    impl DeviceAttributeSource for Fleet {
        fn device_attributes(&self) -> Vec<(String, mecmcp_auth::DeviceAttrs)> {
            self.0.clone()
        }
    }

    fn fleet() -> Fleet {
        let site = |name: &str, site: &str| {
            let attrs = serde_json::from_str(&format!(r#"{{"site":"{site}","vendor":"junos"}}"#));
            (name.to_owned(), attrs.unwrap())
        };
        Fleet(vec![
            site("lab-a", "lab-1"),
            site("emea-a", "emea-lon"),
            site("apac-a", "apac-1"),
            ("bare".to_owned(), mecmcp_auth::DeviceAttrs::default()),
        ])
    }

    const SELECTOR_MAP: &str = r#"{"version":1,
        "scopes":{
            "junos:read":{"tools":["get_junos_config"],"devices":["*"]},
            "junos:lab":{"tools":["load_and_commit_config"],"devices":["*"],
                         "device_selectors":["site=lab-*"]}},
        "roles":{"site=*":{"tools":["get_device_list"],"devices":["*"],
                           "device_selectors":["site=emea-*","vendor=junos"]}}}"#;

    fn allowed(authority: &MappedAuthority) -> Vec<&'static str> {
        ["lab-a", "emea-a", "apac-a", "bare", "ghost"]
            .into_iter()
            .filter(|name| authority.devices.allows(name))
            .collect()
    }

    #[test]
    fn selectors_resolve_against_the_live_inventory() {
        let map = OAuthScopeMap::from_json(SELECTOR_MAP.as_bytes()).unwrap();
        let fleet = fleet();
        let lab = map
            .map_with(&strings(&["junos:lab"]), &[], Some(&fleet))
            .unwrap();
        assert_eq!(
            allowed(&lab),
            ["lab-a"],
            "attribute-less and unknown devices match nothing"
        );
    }

    #[test]
    fn selectors_never_widen_the_intersection() {
        let map = OAuthScopeMap::from_json(SELECTOR_MAP.as_bytes()).unwrap();
        let fleet = fleet();
        let both = map
            .map_with(&strings(&["junos:read", "junos:lab"]), &[], Some(&fleet))
            .unwrap();
        assert_eq!(allowed(&both), ["lab-a"]);
        // Two selector entries with disjoint sites leave nothing.
        let disjoint = map
            .map_with(
                &strings(&["junos:lab"]),
                &strings(&["site=*"]),
                Some(&fleet),
            )
            .unwrap();
        assert!(allowed(&disjoint).is_empty());
    }

    #[test]
    fn selector_entries_grant_nothing_without_an_attribute_source() {
        let map = OAuthScopeMap::from_json(SELECTOR_MAP.as_bytes()).unwrap();
        let lab = map.map(&strings(&["junos:lab"]), &[]).unwrap();
        assert_eq!(lab.devices, ScopeSet::Allowlist(Vec::new()));
    }

    #[test]
    fn an_inventory_reload_changes_the_next_mapping() {
        let map = OAuthScopeMap::from_json(SELECTOR_MAP.as_bytes()).unwrap();
        let mut moved = fleet();
        moved.0[2].1 = serde_json::from_str(r#"{"site":"lab-9"}"#).unwrap();
        let lab = map
            .map_with(&strings(&["junos:lab"]), &[], Some(&moved))
            .unwrap();
        assert_eq!(allowed(&lab), ["lab-a", "apac-a"]);
    }

    /// A claim value that looks like a selector is only ever a lookup key.
    #[test]
    fn a_claim_cannot_inject_a_selector() {
        let map = OAuthScopeMap::from_json(SELECTOR_MAP.as_bytes()).unwrap();
        let fleet = fleet();
        for claim in [
            "site=*",
            "vendor=junos",
            "junos:read site=*",
            "site=lab-* ",
            "junos:lab,site=*",
        ] {
            // `site=*` is a role *key* in SELECTOR_MAP, so only that exact string maps, and it
            // grants its own configured selectors, not what the claim text says.
            let by_scope = map.map_with(&strings(&[claim]), &[], Some(&fleet));
            assert!(by_scope.is_none(), "{claim:?} must not map as a scope");
        }
        let by_role = map
            .map_with(&[], &strings(&["site=*"]), Some(&fleet))
            .unwrap();
        assert_eq!(
            allowed(&by_role),
            ["emea-a"],
            "the key is opaque; its selectors come from config"
        );
        assert!(
            map.map_with(&[], &strings(&["site=emea-*"]), Some(&fleet))
                .is_none()
        );
    }

    #[test]
    fn selector_load_errors() {
        for bad in [
            r#""device_selectors":[]"#,
            r#""device_selectors":["region=emea"]"#,
            r#""device_selectors":["site="]"#,
            r#""device_selectors":["site=emea-?"]"#,
            r#""device_selectors":["site=emea\u0000"]"#,
            r#""device_selectors":"site=emea-*""#,
        ] {
            let json = format!(
                r#"{{"version":1,"scopes":{{"a":{{"tools":["t"],"devices":["*"],{bad}}}}}}}"#
            );
            assert!(OAuthScopeMap::from_json(json.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_file_without_selectors_maps_identically_with_or_without_a_source() {
        let fleet = fleet();
        let plain = map();
        let with = plain.map_with(
            &strings(&["junos:read"]),
            &strings(&["netops"]),
            Some(&fleet),
        );
        assert_eq!(
            with,
            plain.map(&strings(&["junos:read"]), &strings(&["netops"]))
        );
    }

    #[test]
    fn a_null_device_selectors_is_refused_not_read_as_absent() {
        let json = r#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["*"],"device_selectors":null}}}"#;
        assert!(OAuthScopeMap::from_json(json.as_bytes()).is_err());
        let absent = r#"{"version":1,"scopes":{"a":{"tools":["t"],"devices":["*"]}}}"#;
        assert!(OAuthScopeMap::from_json(absent.as_bytes()).is_ok());
    }

    /// Each call returns the next inventory generation. A device that is lab/panos in
    /// generation 0 and emea/junos in generation 1 satisfies neither conjunction at any
    /// instant, so per-entry reads would grant it via lab-* (gen 0) and junos (gen 1).
    struct Flapping(std::sync::atomic::AtomicUsize);

    impl DeviceAttributeSource for Flapping {
        fn device_attributes(&self) -> Vec<(String, mecmcp_auth::DeviceAttrs)> {
            let generation = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let json = if generation == 0 {
                r#"{"site":"lab-1","vendor":"panos"}"#
            } else {
                r#"{"site":"emea-1","vendor":"junos"}"#
            };
            vec![("x".to_owned(), serde_json::from_str(json).unwrap())]
        }
    }

    #[test]
    fn every_entry_is_judged_against_one_attribute_snapshot() {
        let json = r#"{"version":1,"scopes":{
            "a":{"tools":["t"],"devices":["*"],"device_selectors":["site=lab-*"]},
            "b":{"tools":["t"],"devices":["*"],"device_selectors":["vendor=junos"]}}}"#;
        let map = OAuthScopeMap::from_json(json.as_bytes()).unwrap();
        let source = Flapping(std::sync::atomic::AtomicUsize::new(0));
        let granted = map
            .map_with(&strings(&["a", "b"]), &[], Some(&source))
            .unwrap();
        assert!(!granted.devices.allows("x"));
        assert_eq!(
            source.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "read once"
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
