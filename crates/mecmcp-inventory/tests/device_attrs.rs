//! `DeviceAttrs` embedded in a consumer's device record loads through `FileInventory`.
#![allow(clippy::unwrap_used)]

use mecmcp_auth::DeviceAttrs;
use mecmcp_inventory::FileInventory;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Device {
    ip: String,
    #[serde(default)]
    attributes: Option<DeviceAttrs>,
}

#[derive(Debug, Clone, Deserialize)]
struct Policy {}

fn write(json: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), json).unwrap();
    file
}

#[test]
fn attributes_load_through_file_inventory_and_round_trip() {
    let file = write(
        r#"{"r1":{"ip":"1.2.3.4","attributes":{"site":"emea-lon","vendor":"junos","tags":["pci"]}},
            "r2":{"ip":"1.2.3.5"}}"#,
    );
    let inventory = FileInventory::<Device, Policy>::load(file.path()).unwrap();
    let r1 = inventory.get_device("r1").unwrap();
    assert_eq!(
        r1.attributes
            .as_ref()
            .unwrap()
            .site
            .as_ref()
            .unwrap()
            .as_str(),
        "emea-lon"
    );
    assert!(inventory.get_device("r2").unwrap().attributes.is_none());

    let back: Device = serde_json::from_str(&serde_json::to_string(&r1).unwrap()).unwrap();
    assert_eq!(back, r1);
}

#[test]
fn an_invalid_attribute_fails_the_inventory_load() {
    let file = write(r#"{"r1":{"ip":"1.2.3.4","attributes":{"site":"emea‐lon"}}}"#);
    assert!(FileInventory::<Device, Policy>::load(file.path()).is_err());
}
