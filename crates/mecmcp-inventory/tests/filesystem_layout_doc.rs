#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! The layout document must state the devices.json mode the loader enforces.
//!
//! FILESYSTEM-LAYOUT.md once said `0640 root:<svc>` while
//! `read_hardened_file` refuses any group-readable inventory. An installer
//! written from the doc produced a service that would not start. These tests
//! tie the doc and the loader together so they cannot drift again.

use mecmcp_inventory::FileInventory;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ExampleDevice {
    endpoint: String,
}

fn layout_doc() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/FILESYSTEM-LAYOUT.md"
    ))
    .unwrap()
}

#[test]
fn the_layout_doc_states_the_devices_json_mode_the_loader_enforces() {
    let doc = layout_doc();
    assert!(
        doc.contains("| `/etc/<svc>/devices.json` | 0600 | `<svc>` | `<svc>` |"),
        "FILESYSTEM-LAYOUT.md must document devices.json as 0600 <svc>:<svc>"
    );
    assert!(
        !doc.contains("| `/etc/<svc>/devices.json` | 0640"),
        "FILESYSTEM-LAYOUT.md still documents a devices.json mode the loader refuses"
    );
}

#[test]
fn the_layout_doc_records_the_directory_base_decision() {
    let doc = layout_doc();
    assert!(
        doc.contains("## Decision: directory base and devices.json mode"),
        "FILESYSTEM-LAYOUT.md must carry the decision section"
    );
}

#[cfg(unix)]
#[test]
fn a_0640_inventory_is_refused_as_the_doc_now_says() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("devices.json");
    std::fs::write(
        &path,
        r#"{"version":1,"devices":{"fw-1":{"endpoint":"https://fw-1.example.org"}}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

    let Err(error) = FileInventory::<ExampleDevice, ()>::load(&path) else {
        panic!("a 0640 inventory must be refused")
    };
    assert!(
        error.to_string().contains("group- or world-accessible"),
        "{error}"
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(FileInventory::<ExampleDevice, ()>::load(&path).is_ok());
}
