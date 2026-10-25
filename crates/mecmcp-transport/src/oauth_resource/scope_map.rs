//! The server-side table turning verified OAuth claims into tool and device scopes.
//!
//! The table lives on the resource server (like `tokens.json`); a token cannot name its own
//! authority. Everything here fails closed: no default entry, no implicit wildcard,
//! no partial matching.

use mecmcp_auth::{ActorType, ScopeSet};
use mecmcp_oidc::is_scope_token;
use serde::Deserialize;
use std::collections::BTreeMap;
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
    #[serde(default)]
    scopes: BTreeMap<String, GrantSpec>,
    #[serde(default)]
    roles: BTreeMap<String, GrantSpec>,
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
            if !is_scope_token(name) {
                return Err(ScopeMapError::Invalid(format!(
                    "scope key {name:?} is not a valid scope-token"
                )));
            }
            validate_spec(name, spec)?;
        }
        for (name, spec) in &file.roles {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                return Err(ScopeMapError::Invalid(format!(
                    "role key {name:?} is out of range"
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
        let metadata =
            std::fs::metadata(path).map_err(|error| ScopeMapError::Io(error.to_string()))?;
        if metadata.len() > MAX_FILE_BYTES {
            return Err(ScopeMapError::TooLarge);
        }
        let bytes = std::fs::read(path).map_err(|error| ScopeMapError::Io(error.to_string()))?;
        Self::from_json(&bytes)
    }

    /// The scope names this server understands, sorted, for `scopes_supported`.
    #[must_use]
    pub fn scopes_supported(&self) -> Vec<&str> {
        self.scopes.keys().map(String::as_str).collect()
    }

    /// The authority for a token carrying these scopes and roles, or `None` if it maps to
    /// nothing (no entry matched, or the union grants no tools).
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
        let mut devices = ScopeSet::Allowlist(Vec::new());
        for spec in matched {
            tools = union(tools, &spec.tools);
            devices = union(devices, &spec.devices);
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
    fn scopes_and_roles_union() {
        let authority = map()
            .map(
                &strings(&["junos:read", "junos:ops"]),
                &strings(&["netops"]),
            )
            .unwrap();
        assert_eq!(
            authority.tools,
            ScopeSet::Allowlist(strings(&[
                "get_junos_config",
                "gather_device_facts",
                "get_device_list"
            ]))
        );
        assert_eq!(
            authority.devices,
            ScopeSet::Allowlist(strings(&["srx-1", "srx-2"]))
        );
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
}
