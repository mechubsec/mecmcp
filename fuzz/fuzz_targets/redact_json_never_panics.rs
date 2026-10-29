#![no_main]
//! `redact_json_str` is the denylist-and-shape path every vendor JSON
//! response walks before a model sees it, for every server that has not
//! declared a `FieldAllowlist` projection for that shape. The input is raw
//! device/controller output -- untrusted by definition -- so a panic while
//! walking or rewriting it is reachable by anything the server talks to.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = mecmcp_redact::redact_json_str(data);
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) {
        mecmcp_redact::junos::redact_json_value(&mut value);
    }
});
