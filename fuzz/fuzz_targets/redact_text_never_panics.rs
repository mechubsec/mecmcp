#![no_main]
//! `redact_text` runs, unconditionally by default, on every unstructured
//! text tool result a device or controller hands back before it reaches a
//! model (MEC-511 marks that same output untrusted for the same reason). It
//! always succeeds -- there is no parse step to fail on free-form text -- so
//! the only property to hold is that it never panics on arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = mecmcp_redact::redact_text(data);
    let _ = mecmcp_redact::junos::redact_text(data);
});
