//! The one and only place the redaction policy is allowed to change: an
//! operator's CLI flag calling `mecmcp_redact::install` at startup.
//!
//! `RedactionPolicy` lives behind a process-global `OnceLock`, so — same
//! reasoning as `tests/policy_default_enabled.rs` — this needs its own
//! process, and everything that touches `install`/`active` has to live in a
//! single `#[test]` function here: `cargo test` runs tests in one binary on
//! multiple threads by default, and two tests racing to be "the first
//! `install` call" would be exactly the kind of flake a process-global
//! deserves to produce.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{RedactionPolicy, install, redact_json_str, redact_text, redact_xml_str};
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;

/// A `MakeWriter` that appends every write to a shared buffer, so the test
/// can inspect exactly what a real `mecmcp_audit::init_tracing` console layer
/// would have printed.
#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn disabling_redaction_only_happens_through_install_and_is_logged_and_audited() {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(CapturedLog(buffer.clone())),
    );

    tracing::subscriber::with_default(subscriber, || {
        install(RedactionPolicy::DisabledByOperator {
            flag: "--no-redact",
        });
    });

    // 1. The state actually changed.
    assert_eq!(
        mecmcp_redact::active(),
        RedactionPolicy::DisabledByOperator {
            flag: "--no-redact"
        }
    );

    // 2. It logged loudly: a WARN-level, `target: "audit"` event naming the
    // flag. This is the exact convention `mecmcp_audit::init_tracing`'s audit
    // file/journald layers filter on (`target == "audit"`), and its console
    // layer prints anything at WARN or above — so this one line is both "logs
    // loudly at startup" and "recorded in the audit trail" simultaneously.
    let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(log.contains("\"target\":\"audit\""), "log: {log}");
    assert!(log.contains("WARN"), "log: {log}");
    assert!(log.contains("--no-redact"), "log: {log}");
    assert!(log.contains("tool_output_redaction_disabled"), "log: {log}");

    // 3. No tool-facing API can turn it back on or off: the only lever is the
    // `install` call above, which every mecmcp server gates behind a CLI
    // flag, never a tool argument. None of the redact_* entry points below
    // accept a parameter that could re-enable redaction per call — with the
    // policy disabled, a secret really does survive every one of them.
    assert_eq!(
        redact_text("password: FAKEhunter2"),
        "password: FAKEhunter2"
    );
    assert_eq!(
        redact_json_str(r#"{"password":"FAKEhunter2"}"#).unwrap(),
        r#"{"password":"FAKEhunter2"}"#
    );
    assert_eq!(
        mecmcp_redact::junos::redact_text("password: FAKEhunter2"),
        "password: FAKEhunter2"
    );
    let xml = "<password>FAKEhunter2</password>";
    assert_eq!(redact_xml_str(xml).unwrap(), xml);

    // N7: the disabled-policy passthrough must still validate well-formedness
    // — it must not become a way to skip the "this is valid XML" check every
    // other entry point enforces just because redaction itself is off.
    let err = redact_xml_str("<unclosed>").unwrap_err();
    assert!(matches!(err, mecmcp_redact::RedactError::InvalidXml(_)));

    // 4. `install` is idempotent: a later call (e.g. a second, mistaken
    // startup invocation) cannot flip the policy back.
    install(RedactionPolicy::Enabled);
    assert_eq!(
        mecmcp_redact::active(),
        RedactionPolicy::DisabledByOperator {
            flag: "--no-redact"
        },
        "a second install() call must not change the already-installed policy"
    );
}
