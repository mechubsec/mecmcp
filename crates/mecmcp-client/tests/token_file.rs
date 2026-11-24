//! `BearerToken::from_file` must inherit `mecmcp-secret`'s file hardening.
#![allow(clippy::unwrap_used)] // tests

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;

use mecmcp_client::{BearerToken, ClientConfig, ClientError};

// gitleaks:allow (obviously fake)
const FAKE: &str = "fake-token-for-tests-only";

fn write_token(dir: &tempfile::TempDir, contents: &str, mode: u32) -> PathBuf {
    let path = dir.path().join("token");
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn rejects_group_readable_token_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, FAKE, 0o640);
    assert!(matches!(
        BearerToken::from_file(&path),
        Err(ClientError::Token(_))
    ));
}

#[test]
fn rejects_symlink_token_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_token(&dir, FAKE, 0o600);
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(matches!(
        BearerToken::from_file(&link),
        Err(ClientError::Token(_))
    ));
}

#[test]
fn strips_one_trailing_newline() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "abc\n", 0o600);
    assert_eq!(BearerToken::from_file(&path).unwrap().expose(), "abc");
}

#[test]
fn rejects_empty_token_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, "", 0o600);
    assert!(matches!(
        BearerToken::from_file(&path),
        Err(ClientError::Token(_))
    ));
}

#[test]
// "Bearer " (header form): the mandated Debug text "BearerToken(<redacted>)" itself starts with "Bearer".
fn debug_never_contains_token() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_token(&dir, FAKE, 0o600);
    let token = BearerToken::from_file(&path).unwrap();
    let config = ClientConfig::new("https://mcp.example/mcp", token).unwrap();
    let rendered = format!("{config:?}");
    assert!(!rendered.contains(FAKE) && !rendered.contains("Bearer "));

    let bad = write_token(&dir, FAKE, 0o644);
    let err = format!("{:?}", BearerToken::from_file(&bad).unwrap_err());
    assert!(!err.contains(FAKE) && !err.contains("Bearer "));
}
