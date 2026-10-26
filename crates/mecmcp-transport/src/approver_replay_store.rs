//! Durable `jti` replay store for the verified-approver step-up (mecmcp#400).
//!
//! Append log (periodically compacted, not an audit record), one record per line: `<hex sha256(jti)> <retain_until unix secs>\n`.
//! The raw `jti` is never written. A record is appended and fsynced before the approval it
//! guards is returned, so a restart inside the assertion's lifetime cannot forget it.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags, fstat, open};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

/// Upper bound on a store file we are willing to load; compaction keeps real files far smaller.
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
/// Never compact a file with fewer expired records than this.
const COMPACT_FLOOR: usize = 1024;

/// Why a replay store could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    /// An I/O step failed.
    #[error("replay store {op}: {source}")]
    Io {
        /// The step that failed.
        op: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file exists but is not safe to trust (symlink, not regular, wrong mode or owner).
    #[error("replay store refused: {0}")]
    Refused(String),
    /// A record is malformed. Never carries the content of the line.
    #[error(
        "replay store is corrupt at line {line}; refusing to start rather than drop replay \
         protection (inspect it, or remove it deliberately)"
    )]
    Corrupt {
        /// 1-based line number of the first bad record.
        line: usize,
    },
}

fn io_error(op: &'static str) -> impl FnOnce(std::io::Error) -> ReplayStoreError {
    move |source| ReplayStoreError::Io { op, source }
}

/// The fixed-length key stored (and held in memory) for a `jti`.
pub(crate) fn jti_key(jti: &str) -> String {
    let digest = Sha256::digest(jti.as_bytes());
    let mut key = String::with_capacity(64);
    for byte in digest {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// An open, validated replay store.
#[derive(Debug)]
pub(crate) struct ReplayStore {
    file: File,
    path: PathBuf,
    /// Records currently in the file, live or expired.
    lines: usize,
}

impl ReplayStore {
    /// Open (creating at 0600) and load `path`; returns the store and its unexpired records.
    pub(crate) fn open(
        path: &Path,
        now: i64,
    ) -> Result<(Self, HashMap<String, i64>), ReplayStoreError> {
        let file = open_hardened(path)?;
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            // Make a freshly created file's directory entry durable.
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(io_error("fsync dir"))?;
        }
        let mut bytes = Vec::new();
        (&file)
            .take(MAX_STORE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error("read"))?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(ReplayStoreError::Refused(
                "file is larger than the 64 MiB limit".to_owned(),
            ));
        }
        let mut live = HashMap::new();
        let mut lines = 0;
        for (index, raw) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
            let record = raw
                .strip_suffix(b"\n")
                .and_then(parse_record)
                .ok_or(ReplayStoreError::Corrupt { line: index + 1 })?;
            lines += 1;
            if record.1 >= now {
                live.insert(record.0, record.1);
            }
        }
        let mut store = Self {
            file,
            path: path.to_owned(),
            lines,
        };
        if let Err(error) = store.compact_if_needed(&live) {
            // The records are intact; compaction is retried on the next trigger.
            tracing::warn!(%error, "replay store compaction failed");
        }
        Ok((store, live))
    }

    /// A store over an arbitrary already-open file (tests: `/dev/full`).
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn from_file(file: File) -> Self {
        Self {
            file,
            path: PathBuf::new(),
            lines: 0,
        }
    }

    /// Append and fsync one record; on failure the file is rolled back to its prior length.
    pub(crate) fn record(&mut self, key: &str, retain_until: i64) -> std::io::Result<()> {
        let before = self.file.metadata()?.len();
        let line = format!("{key} {retain_until}\n");
        let written = self
            .file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all());
        if let Err(error) = written {
            // Best effort: a torn tail would make the next startup refuse.
            let _ = self.file.set_len(before);
            return Err(error);
        }
        self.lines += 1;
        Ok(())
    }

    /// Rewrite the file from `live` when expired records dominate.
    pub(crate) fn compact_if_needed(&mut self, live: &HashMap<String, i64>) -> std::io::Result<()> {
        let expired = self.lines.saturating_sub(live.len());
        if expired <= COMPACT_FLOOR.max(live.len().saturating_mul(2)) {
            return Ok(());
        }
        let mut temp_name = self.path.as_os_str().to_owned();
        temp_name.push(".compact.tmp");
        let temp = PathBuf::from(temp_name);
        match std::fs::remove_file(&temp) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let rewritten = (|| {
            let mut fresh = OpenOptions::new()
                .append(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            let mut body = String::new();
            for (key, until) in live {
                let _ = writeln!(body, "{key} {until}");
            }
            fresh.write_all(body.as_bytes())?;
            fresh.sync_all()?;
            std::fs::rename(&temp, &self.path)?;
            if let Some(parent) = self.path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                File::open(parent)?.sync_all()?;
            }
            Ok(fresh)
        })();
        match rewritten {
            Ok(fresh) => {
                self.file = fresh;
                self.lines = live.len();
                Ok(())
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                Err(error)
            }
        }
    }
}

/// `<64 lowercase hex> <i64>` with no other bytes.
fn parse_record(line: &[u8]) -> Option<(String, i64)> {
    let (key, rest) = line.split_at_checked(64)?;
    if !key
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let until = std::str::from_utf8(rest.strip_prefix(b" ")?).ok()?;
    if until.starts_with('+') {
        return None;
    }
    Some((String::from_utf8(key.to_vec()).ok()?, until.parse().ok()?))
}

/// Open read-write/append, creating at 0600, and refuse anything but a regular, non-symlink,
/// owner-only file owned by the service user (root may read anything), judged by `fstat` on
/// the descriptor. Mirrors the `Secret` role in `mecmcp-secret`'s validate.rs.
fn open_hardened(path: &Path) -> Result<File, ReplayStoreError> {
    // NONBLOCK: a FIFO with no writer would otherwise hang the open before the type check.
    let descriptor = open(
        path,
        OFlags::RDWR
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|errno| {
        if errno == Errno::LOOP {
            return ReplayStoreError::Refused(
                "refusing a symlink; point --approver-replay-store at the file itself".to_owned(),
            );
        }
        ReplayStoreError::Io {
            op: "open",
            source: errno.into(),
        }
    })?;
    let stat = fstat(&descriptor).map_err(|errno| ReplayStoreError::Io {
        op: "fstat",
        source: errno.into(),
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(ReplayStoreError::Refused("not a regular file".to_owned()));
    }
    let mode = stat.st_mode & 0o777;
    if mode & 0o077 != 0 {
        return Err(ReplayStoreError::Refused(format!(
            "mode {mode:04o} is group/world-accessible; run chmod 0600 on it"
        )));
    }
    let effective = rustix::process::geteuid().as_raw();
    if effective != 0 && stat.st_uid != effective {
        return Err(ReplayStoreError::Refused(format!(
            "owner uid {} is not the service user (uid {effective})",
            stat.st_uid
        )));
    }
    Ok(File::from(descriptor))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key(n: u32) -> String {
        jti_key(&format!("jti-{n}"))
    }

    #[test]
    fn records_survive_reopen_and_expired_are_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jti.log");
        let (mut store, live) = ReplayStore::open(&path, 100).unwrap();
        assert!(live.is_empty());
        store.record(&key(1), 500).unwrap();
        store.record(&key(2), 50).unwrap();
        drop(store);
        let (_, live) = ReplayStore::open(&path, 100).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live.get(&key(1)), Some(&500));
    }

    #[test]
    fn the_raw_jti_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jti.log");
        let (mut store, _) = ReplayStore::open(&path, 0).unwrap();
        store.record(&jti_key("super-secret-jti"), 10).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("super-secret-jti"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn a_malformed_line_refuses_startup_naming_only_the_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jti.log");
        let good = format!("{} 500\n", key(1));
        for tail in ["GARBAGE-SECRET\n", &format!("{} 5x\n", key(2)), &key(3)] {
            std::fs::write(&path, format!("{good}{tail}")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = ReplayStore::open(&path, 0).unwrap_err();
            assert!(
                matches!(error, ReplayStoreError::Corrupt { line: 2 }),
                "{error}"
            );
            assert!(!error.to_string().contains("GARBAGE"));
        }
    }

    #[test]
    fn symlink_loose_mode_and_non_regular_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.log");
        std::fs::write(&real, "").unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            ReplayStore::open(&link, 0).unwrap_err(),
            ReplayStoreError::Refused(_)
        ));
        for mode in [0o644, 0o640, 0o602] {
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    ReplayStore::open(&real, 0).unwrap_err(),
                    ReplayStoreError::Refused(_)
                ),
                "{mode:o}"
            );
        }
        assert!(matches!(
            ReplayStore::open(dir.path(), 0).unwrap_err(),
            ReplayStoreError::Io { .. } | ReplayStoreError::Refused(_)
        ));
    }

    #[test]
    fn compaction_keeps_live_and_drops_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jti.log");
        let (mut store, _) = ReplayStore::open(&path, 0).unwrap();
        for n in 0..2000 {
            store
                .record(&key(n), if n < 3 { 10_000 } else { 50 })
                .unwrap();
        }
        drop(store);
        // Reopening at now=100 loads 3 live of 2000 lines and compacts.
        let (mut store, live) = ReplayStore::open(&path, 100).unwrap();
        assert_eq!(live.len(), 3);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        // The post-compaction handle still appends to the new file.
        store.record(&key(9999), 10_000).unwrap();
        drop(store);
        let (_, live) = ReplayStore::open(&path, 100).unwrap();
        assert_eq!(live.len(), 4);
        assert!(live.contains_key(&key(0)) && live.contains_key(&key(9999)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_failed_write_is_an_error_and_leaves_the_file_unchanged() {
        // /dev/full accepts open and fails every write with ENOSPC.
        let file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let mut store = ReplayStore::from_file(file);
        assert!(store.record(&key(1), 10).is_err());
        assert_eq!(store.lines, 0);
    }
}
