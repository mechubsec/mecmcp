//! Canonical config/state/service-user layout, derived once per server.
//!
//! Each mechub MCP server used to pick its own directory and service-user
//! names independently. `rustjunosmcp` (`jmcp`), `rustproxmoxmcp`
//! (`proxmoxmcp`) and `rustunifimcp` (`unifimcp`) already used a short,
//! derived name. The other three -- `rustpanosmcp`, `rustsdcmcp` and
//! `rustmistmcp` -- carry their full crate/repo name into `/etc`,
//! `/var/lib` and the service user in production today. Renaming a live
//! service's config dir, state dir *and* system user (systemd unit edits,
//! sysusers edits, re-chowning directories that hold secrets, coordinated
//! across every deployed LXC) is a bigger, messier operation than the
//! tokens.json config/state split this module's sibling ([`crate::validate`])
//! exists to fix, for a cosmetic naming-consistency win with no
//! operator-facing benefit. Kay's decision (MEC-987, 2026-09-30): **do not
//! rename production.** Those three keep their currently-deployed names.
//! [`known`] therefore encodes `PANOS`, `SDC` and `MIST` as explicit,
//! hand-verified exceptions matching deployed reality, not derivations --
//! the same pattern already used for `JUNOS`'s `jmcp` contraction, just
//! three entries instead of one. No path migration, fallback-path logic, or
//! deploy coordination is needed for these three: nothing on disk changes.
//!
//! [`ServerNaming::derive`] is the single place this triple is computed from
//! now on. It takes a `short_name`, not a crate name: the short name is not a
//! mechanical strip of the crate name (`rust-junosmcp` folds to `jmcp`, not
//! `junosmcp`), so this module does not attempt to derive it automatically.
//! [`known`] is the fixed table for the seven servers this module covers
//! today. `rustfortimcp` also exists in the workspace but is not yet in this
//! table; adding it is the same one-constant step as any other new server,
//! not a separate mechanism. A server not yet in `known` takes its full
//! binary name as its short name, adds a constant to that table, and calls
//! `ServerNaming::derive` with it -- nothing else in this module changes.

use std::path::PathBuf;

/// The canonical filesystem and service-account layout for one mechub MCP
/// server, derived from a single short name.
///
/// - `config_dir` (`/etc/<short_name>`): operator-authored input the server
///   does not rewrite -- device inventories, cluster lists, controller
///   configs, SSH keys, tenant aliases.
/// - `state_dir` (`/var/lib/<short_name>`): anything the server itself
///   writes, foremost `tokens.json`, which is rewritten on `token
///   add`/`rotate`/`revoke` and therefore is not config.
/// - `service_user`: the system account the packaged unit runs as, and the
///   owner every hardened file check in [`crate`] validates against. Same
///   string as `short_name` -- one fewer name to keep in sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerNaming {
    /// The short name this layout was derived from, e.g. `"jmcp"`.
    pub short_name: &'static str,
    /// `/etc/<short_name>` -- operator-authored config, never rewritten by
    /// the server.
    pub config_dir: PathBuf,
    /// `/var/lib/<short_name>` -- state the server rewrites itself.
    pub state_dir: PathBuf,
    /// The service account name. Identical to `short_name`.
    pub service_user: &'static str,
}

impl ServerNaming {
    /// Derive the canonical layout for `short_name`.
    ///
    /// This is the *only* place `/etc/<name>`, `/var/lib/<name>`, and the
    /// service-user string get assembled. A server should call this once
    /// with its entry from [`known`] and pass the resulting paths down,
    /// rather than formatting `/etc/{name}` itself anywhere else.
    ///
    /// # Examples
    /// ```
    /// use mecmcp_secret::naming::{ServerNaming, known};
    ///
    /// let naming = ServerNaming::derive(known::JUNOS);
    /// assert_eq!(naming.config_dir.to_str().unwrap(), "/etc/jmcp");
    /// assert_eq!(naming.state_dir.to_str().unwrap(), "/var/lib/jmcp");
    /// assert_eq!(naming.service_user, "jmcp");
    /// ```
    #[must_use]
    pub fn derive(short_name: &'static str) -> Self {
        Self {
            short_name,
            config_dir: PathBuf::from(format!("/etc/{short_name}")),
            state_dir: PathBuf::from(format!("/var/lib/{short_name}")),
            service_user: short_name,
        }
    }
}

/// The short name for each of the seven mechub MCP servers this table covers
/// today. `rustfortimcp` also exists in the workspace but has not yet been
/// assigned a short name here.
///
/// Each short name is either a server's full binary name, or an explicit,
/// documented exception matching the server's production deployment:
///
/// | Repo               | Crate            | Short name (`known`) | Source                              |
/// |--------------------|------------------|----------------------|--------------------------------------|
/// | `rustjunosmcp`      | `rust-junosmcp`  | `jmcp`               | exception -- deployed short name     |
/// | `rustpanosmcp`      | `rust-panosmcp`  | `rust-panosmcp`      | full binary name, as deployed        |
/// | `rustsdcmcp`        | `rustsdcmcp`     | `rustsdcmcp`         | full binary name, as deployed        |
/// | `rustproxmoxmcp`    | `rust-proxmoxmcp`| `proxmoxmcp`         | exception -- deployed short name     |
/// | `rustmistmcp`       | `rustmistmcp`    | `rustmistmcp`        | full binary name, as deployed        |
/// | `rustunifimcp`      | `rustunifimcp`   | `unifimcp`           | exception -- deployed short name     |
/// | `rustopnsmcp`       | `rustopnsmcp`    | `rustopnsmcp`        | full binary name (new server)        |
///
/// A new server adds one constant here, set to its full binary name
/// (FILESYSTEM-LAYOUT.md, "Decision: directory base and devices.json mode").
/// The three short names above are deployed exceptions, and Kay's MEC-987
/// decision (2026-09-30) stands: production is not renamed in either
/// direction. They are not a pattern for a new server to follow.
pub mod known {
    /// `rustjunosmcp` / `rust-junosmcp`. Hand-verified exception: deployed
    /// everywhere as `jmcp`, not the full binary name. Do not change this
    /// without a coordinated on-disk migration.
    pub const JUNOS: &str = "jmcp";
    /// `rustpanosmcp` / `rust-panosmcp`. Full binary name, as deployed.
    pub const PANOS: &str = "rust-panosmcp";
    /// `rustsdcmcp`. Full binary name, as deployed.
    pub const SDC: &str = "rustsdcmcp";
    /// `rustproxmoxmcp` / `rust-proxmoxmcp`. Hand-verified exception:
    /// deployed everywhere as `proxmoxmcp`, not the full binary name. Do not
    /// change this without a coordinated on-disk migration.
    pub const PROXMOX: &str = "proxmoxmcp";
    /// `rustmistmcp`. Full binary name, as deployed.
    pub const MIST: &str = "rustmistmcp";
    /// `rustunifimcp`. Hand-verified exception: deployed everywhere as
    /// `unifimcp`, not the full binary name. Do not change this without a
    /// coordinated on-disk migration.
    pub const UNIFI: &str = "unifimcp";
    /// `rustopnsmcp`. The full binary name, which is the rule for a server
    /// with no earlier deployment (FILESYSTEM-LAYOUT.md, "Decision: directory
    /// base and devices.json mode").
    pub const OPNSENSE: &str = "rustopnsmcp";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_builds_etc_and_var_lib_from_the_short_name() {
        let naming = ServerNaming::derive("examplemcp");
        assert_eq!(naming.config_dir, PathBuf::from("/etc/examplemcp"));
        assert_eq!(naming.state_dir, PathBuf::from("/var/lib/examplemcp"));
        assert_eq!(naming.service_user, "examplemcp");
        assert_eq!(naming.short_name, "examplemcp");
    }

    #[test]
    fn service_user_matches_short_name_exactly() {
        for short_name in [
            known::JUNOS,
            known::PANOS,
            known::SDC,
            known::PROXMOX,
            known::MIST,
            known::UNIFI,
            known::OPNSENSE,
        ] {
            let naming = ServerNaming::derive(short_name);
            assert_eq!(naming.service_user, short_name);
        }
    }

    #[test]
    fn known_short_names_are_distinct() {
        let names = [
            known::JUNOS,
            known::PANOS,
            known::SDC,
            known::PROXMOX,
            known::MIST,
            known::UNIFI,
            known::OPNSENSE,
        ];
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                assert!(i == j || a != b, "duplicate short name: {a}");
            }
        }
    }

    #[test]
    fn known_table_matches_documented_values() {
        assert_eq!(known::JUNOS, "jmcp");
        assert_eq!(known::PANOS, "rust-panosmcp");
        assert_eq!(known::SDC, "rustsdcmcp");
        assert_eq!(known::PROXMOX, "proxmoxmcp");
        assert_eq!(known::MIST, "rustmistmcp");
        assert_eq!(known::UNIFI, "unifimcp");
        assert_eq!(known::OPNSENSE, "rustopnsmcp");
    }

    #[test]
    fn panos_sdc_mist_derive_to_their_deployed_paths() {
        // Regression guard for MEC-987: Kay's decision was not to rename
        // production, so these three must resolve to the paths and service
        // user actually deployed today, not a shortened derivation.
        let panos = ServerNaming::derive(known::PANOS);
        assert_eq!(panos.config_dir, PathBuf::from("/etc/rust-panosmcp"));
        assert_eq!(panos.state_dir, PathBuf::from("/var/lib/rust-panosmcp"));
        assert_eq!(panos.service_user, "rust-panosmcp");

        let sdc = ServerNaming::derive(known::SDC);
        assert_eq!(sdc.config_dir, PathBuf::from("/etc/rustsdcmcp"));
        assert_eq!(sdc.state_dir, PathBuf::from("/var/lib/rustsdcmcp"));
        assert_eq!(sdc.service_user, "rustsdcmcp");

        let mist = ServerNaming::derive(known::MIST);
        assert_eq!(mist.config_dir, PathBuf::from("/etc/rustmistmcp"));
        assert_eq!(mist.state_dir, PathBuf::from("/var/lib/rustmistmcp"));
        assert_eq!(mist.service_user, "rustmistmcp");
    }

    #[test]
    fn opnsense_derives_to_its_full_binary_name() {
        // New servers use the full binary name as the directory base
        // (FILESYSTEM-LAYOUT.md, "Decision: directory base and devices.json
        // mode"), not a shortened vendor token such as `opnsmcp`.
        let opnsense = ServerNaming::derive(known::OPNSENSE);
        assert_eq!(opnsense.config_dir, PathBuf::from("/etc/rustopnsmcp"));
        assert_eq!(opnsense.state_dir, PathBuf::from("/var/lib/rustopnsmcp"));
        assert_eq!(opnsense.service_user, "rustopnsmcp");
    }

    #[test]
    fn the_layout_doc_lists_opnsense_at_its_known_paths() {
        let doc = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/FILESYSTEM-LAYOUT.md"
        ))
        .expect("FILESYSTEM-LAYOUT.md is readable from the workspace");
        let naming = ServerNaming::derive(known::OPNSENSE);
        let row = format!(
            "| `rustopnsmcp` | `rustopnsmcp` | `{user}` | `{config}` | `{state}` |",
            user = naming.service_user,
            config = naming.config_dir.display(),
            state = naming.state_dir.display(),
        );
        assert!(
            doc.contains(&row),
            "FILESYSTEM-LAYOUT.md is missing the row {row}"
        );
    }
}
