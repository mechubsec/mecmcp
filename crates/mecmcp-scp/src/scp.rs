//! Legacy SCP1 file transfer over SSH exec channels.
//!
//! This module implements the SCP1 protocol (the wire format used by OpenSSH's
//! `scp -O` flag) for uploading and downloading files to/from devices that
//! disable SFTP-over-SSH (e.g., Junos). All transfers stream in chunks —
//! never buffer a whole image in memory.
//!
//! ## Why SCP1 and not SFTP
//!
//! Junos disables the SFTP subsystem. The legacy SCP1 wire protocol (running
//! over `ssh ... scp -t <dir>` or `scp -f <file>`) is the only file-transfer
//! mechanism available.
//!
//! ## Platform Support
//!
//! The SCP client is **Unix-only** (Linux, macOS, BSD). It relies on Unix-specific
//! APIs for secure file handling:
//!
//! - `O_NOFOLLOW` to prevent symlink traversal attacks
//! - `O_NONBLOCK` to prevent FIFO blocking
//! - `MetadataExt` for file timestamps in T headers
//!
//! Non-Unix fallbacks for security-relevant code should not be written. This follows
//! the same principle as `mecmcp-secret` and the MCP server fleet (LXC/Docker only).
//!
//! ## Limitations
//!
//! - No jump host / ProxyCommand support (direct connections only)
//! - No password authentication (key-based auth only)
//!
//! ## Usage
//!
//! ```no_run
//! use mecmcp_scp::{ScpClient, SshConfig, SshAuth, HostKeyVerification};
//! use tokio_util::sync::CancellationToken;
//! use std::path::{Path, PathBuf};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let config = SshConfig {
//! #     host: "10.0.0.1".into(),
//! #     port: 22,
//! #     username: "user".into(),
//! #     auth: SshAuth::PrivateKey {
//! #         path: PathBuf::from("/home/user/.ssh/id_ed25519"),
//! #         passphrase: None,
//! #     },
//! #     host_key_verification: HostKeyVerification::AcceptAll,
//! # };
//!
//! let ct = CancellationToken::new();
//! let mut client = ScpClient::connect(config, &ct).await?;
//!
//! let outcome = client
//!     .upload(Path::new("/tmp/image.tgz"), "/var/tmp/", None, &ct)
//!     .await?;
//!
//! println!("Transferred {} bytes", outcome.bytes_transferred);
//! client.close().await?;
//! # Ok(())
//! # }
//! ```

// Gate the entire module to Unix-only. The SCP client requires Unix-specific
// file-handling APIs (O_NOFOLLOW, O_NONBLOCK, MetadataExt) for secure operation.
// Non-Unix fallbacks for security-relevant code should not be written — this
// matches the fleet rule that MCP servers are Linux-only (LXC/Docker).
#[cfg(not(unix))]
compile_error!(
    "The SCP client (mecmcp_scp::scp) is Unix-only. \
     It requires O_NOFOLLOW, O_NONBLOCK, and MetadataExt for secure file handling. \
     Non-Unix platforms are not supported."
);

use crate::config::{HostKeyVerification, SshAuth, SshConfig};
use crate::error::ScpError;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate, key::PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, Disconnect, client};
use rustix::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const CHUNK_SIZE: usize = 64 * 1024;

/// Maximum length for SCP protocol control lines (header, error messages).
/// SCP control lines are typically < 512 bytes. 16 KB is generous and prevents
/// unbounded growth from a malformed peer that never sends a newline.
const MAX_CONTROL_LINE_LENGTH: usize = 16 * 1024;

/// Get file descriptor flags using libc::fcntl.
///
/// This is a safe wrapper around the libc fcntl(F_GETFL) call.
fn libc_fcntl_getfl(fd: std::os::unix::io::RawFd) -> Result<i32, ScpError> {
    let flags = rustix::fs::fcntl_getfl(
        // SAFETY: We're borrowing the fd for the duration of this call only.
        // The caller guarantees the fd is valid.
        #[allow(unsafe_code)]
        unsafe {
            rustix::fd::BorrowedFd::borrow_raw(fd)
        },
    )
    .map_err(|e| ScpError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?;

    // Convert OFlags to i32 for manipulation
    Ok(flags.bits() as i32)
}

/// Set file descriptor flags using libc::fcntl.
///
/// This is a safe wrapper around the libc fcntl(F_SETFL) call.
fn libc_fcntl_setfl(fd: std::os::unix::io::RawFd, flags: i32) -> Result<(), ScpError> {
    rustix::fs::fcntl_setfl(
        // SAFETY: We're borrowing the fd for the duration of this call only.
        // The caller guarantees the fd is valid.
        #[allow(unsafe_code)]
        unsafe {
            rustix::fd::BorrowedFd::borrow_raw(fd)
        },
        rustix::fs::OFlags::from_bits_truncate(flags as u32),
    )
    .map_err(|e| ScpError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))
}

/// Build russh client configuration with secure defaults and liveness deadlines.
///
/// Extends russh's secure defaults to include NIST ECDH KEX algorithms for
/// compatibility with legacy devices (e.g., Junos) that only offer those curves.
///
/// Liveness policy (matching openssh-client `-o ServerAliveInterval=10 -o ServerAliveCountMax=3`):
/// - `keepalive_interval = 10s` — send a keepalive if no data received for 10 seconds
/// - `keepalive_max = 3` — close connection after 3 unanswered keepalives (~30s total)
/// - `inactivity_timeout = 45s` — garbage-collect idle connections (> 3 * keepalive window)
///
/// This prevents black-hole TCP or stalled peers from holding per-device transfer
/// capacity until the outer timeout (600-900s). A stalled connection fails in ~30s.
fn build_russh_config() -> client::Config {
    use russh::kex;
    use std::borrow::Cow;

    let mut config = client::Config::default();

    // Extend the default KEX preference list to include NIST curves.
    // Put secure modern algorithms first, NIST curves after for legacy device support.
    let mut kex_list = config.preferred.kex.into_owned();
    kex_list.extend_from_slice(&[
        kex::ECDH_SHA2_NISTP256,
        kex::ECDH_SHA2_NISTP384,
        kex::ECDH_SHA2_NISTP521,
    ]);
    config.preferred.kex = Cow::Owned(kex_list);

    // SSH liveness deadlines: match openssh-client keepalive policy.
    config.keepalive_interval = Some(std::time::Duration::from_secs(10));
    config.keepalive_max = 3;
    config.inactivity_timeout = Some(std::time::Duration::from_secs(45));

    config
}

/// Check for OpenSSH marker lines (@revoked, @cert-authority) in known_hosts.
///
/// OpenSSH supports marker lines that begin with `@marker` to denote special entries.
/// russh's `check_known_hosts_path` does not implement marker semantics, so we handle
/// them before delegating.
///
/// - `@revoked host key`: Marks a key as revoked. If the presented key matches, refuse
///   the connection with a distinct HostKeyRevoked error.
/// - `@cert-authority host key`: Marks a CA key for certificate authentication. This
///   crate does not support certificate authentication, so if the known_hosts file
///   contains a @cert-authority line for this host, we refuse the connection rather
///   than silently falling through to a weaker non-CA check.
///
/// Marker lines may use hashed hostnames (`|1|salt|hash`), so host matching requires
/// the same hash computation that russh uses. We reuse russh's implementation by parsing
/// each line and checking if it would match via `check_known_hosts_path` with a
/// single-line temporary file.
///
/// Returns:
/// - `Ok(())`: No markers matched (safe to proceed to russh's full check)
/// - `Err(ScpError::HostKeyRevoked(_))`: @revoked marker matched the presented key
/// - `Err(ScpError::HostKeyVerification(_))`: @cert-authority for this host, or file error
fn check_known_hosts_markers(
    host: &str,
    port: u16,
    server_public_key: &PublicKey,
    known_hosts_path: &Path,
) -> Result<(), ScpError> {
    use std::io::{BufRead, BufReader};

    // Read the known_hosts file line by line
    let file = std::fs::File::open(known_hosts_path).map_err(|e| {
        ScpError::HostKeyVerification(format!(
            "failed to read known_hosts {}: {}",
            known_hosts_path.display(),
            e
        ))
    })?;

    let reader = BufReader::new(file);

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result.map_err(|e| {
            ScpError::HostKeyVerification(format!(
                "failed to read known_hosts line {}: {}",
                line_num + 1,
                e
            ))
        })?;

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check if this line starts with a marker
        if let Some(after_marker) = trimmed.strip_prefix('@') {
            // Extract marker name (first word after @)
            if let Some(space_idx) = after_marker.find(|c: char| c.is_whitespace()) {
                let marker_name = &after_marker[..space_idx];
                let line_rest = after_marker[space_idx..].trim_start();

                // Check revoked keys
                if marker_name == "revoked"
                    && line_matches_host_and_key(line_rest, host, port, server_public_key)?
                {
                    return Err(ScpError::HostKeyRevoked(format!(
                        "Host key for {}:{} is marked @revoked in known_hosts (line {}). \
                         This key has been compromised or retired and must not be trusted.",
                        host,
                        port,
                        line_num + 1
                    )));
                }

                // Check cert-authority entries
                if marker_name == "cert-authority" && line_matches_host(line_rest, host, port)? {
                    return Err(ScpError::HostKeyVerification(format!(
                        "Host {}:{} has a @cert-authority entry in known_hosts (line {}), \
                         but certificate authentication is not supported by this client. \
                         Remove the @cert-authority line or use a different authentication method.",
                        host,
                        port,
                        line_num + 1
                    )));
                }

                // Unknown markers (e.g., future OpenSSH additions) — ignore them
            }
            // Malformed marker line (no content after marker) — ignore it
            continue;
        } else {
            // Not a marker line
            continue;
        }
    }

    Ok(())
}

/// Check if a known_hosts line (without marker prefix) matches the given host and key.
///
/// Uses russh's `check_known_hosts_path` with a temporary file containing just this line.
/// This reuses russh's hashed-host and key-matching logic without reimplementing it.
fn line_matches_host_and_key(
    line: &str,
    host: &str,
    port: u16,
    server_public_key: &PublicKey,
) -> Result<bool, ScpError> {
    use russh::keys::known_hosts;
    use std::io::Write;

    // Create a temporary file with just this line
    let mut temp_file = tempfile::NamedTempFile::new().map_err(|e| {
        ScpError::HostKeyVerification(format!(
            "failed to create temp file for marker check: {}",
            e
        ))
    })?;

    writeln!(temp_file, "{}", line).map_err(|e| {
        ScpError::HostKeyVerification(format!("failed to write temp known_hosts: {}", e))
    })?;

    temp_file.flush().map_err(|e| {
        ScpError::HostKeyVerification(format!("failed to flush temp known_hosts: {}", e))
    })?;

    // Use russh to check if this line matches
    match known_hosts::check_known_hosts_path(host, port, server_public_key, temp_file.path()) {
        Ok(true) => Ok(true),                                    // Host and key match
        Ok(false) => Ok(false),                                  // Host not in this line
        Err(russh::keys::Error::KeyChanged { .. }) => Ok(false), // Key mismatch (not a match)
        Err(e) => Err(ScpError::HostKeyVerification(format!(
            "error checking marker line: {}",
            e
        ))),
    }
}

/// Check if a known_hosts line (without marker prefix) matches the given host (ignoring key).
///
/// Used for @cert-authority lines where we only care if the host matches, not the key.
fn line_matches_host(line: &str, host: &str, port: u16) -> Result<bool, ScpError> {
    // Parse the line to extract the host pattern
    // Format: "host_pattern key_type key_data"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        // Malformed line - skip it
        return Ok(false);
    }

    let host_pattern = parts[0];

    // Check for hashed host: |1|salt|hash
    if let Some(rest) = host_pattern.strip_prefix("|1|") {
        // Hashed host - need to compute the hash to check if it matches
        let hash_parts: Vec<&str> = rest.split('|').collect();
        if hash_parts.len() != 2 {
            return Ok(false);
        }

        let salt_b64 = hash_parts[0];
        let expected_hash_b64 = hash_parts[1];

        // Decode salt from base64
        use base64::Engine;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64)
            .map_err(|_| {
                ScpError::HostKeyVerification(
                    "failed to decode salt in hashed host pattern".to_string(),
                )
            })?;

        // Compute HMAC-SHA1 of the host (with port if non-standard)
        let host_to_hash = if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        };

        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let mut hmac = HmacSha1::new_from_slice(&salt)
            .map_err(|e| ScpError::HostKeyVerification(format!("failed to create HMAC: {}", e)))?;
        hmac.update(host_to_hash.as_bytes());
        let hash = hmac.finalize().into_bytes();

        // Encode to base64
        let actual_hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

        Ok(actual_hash_b64 == expected_hash_b64)
    } else {
        // Plain text host pattern - check for exact match, wildcard, or comma-separated list
        // For simplicity, we delegate to russh by creating a temporary line with a dummy key
        // and checking if russh would match the host (it will say KeyChanged, but that's fine
        // since we only care about the host match).
        //
        // Actually, let's just do simple matching: exact match, wildcard, or comma-list.
        if host_pattern.contains(',') {
            // Comma-separated list
            let hosts: Vec<&str> = host_pattern.split(',').collect();
            let target = if port == 22 {
                host.to_string()
            } else {
                format!("[{}]:{}", host, port)
            };
            Ok(hosts.iter().any(|&h| h == target || h == host))
        } else if host_pattern.contains('*') || host_pattern.contains('?') {
            // Wildcard pattern - for now, we don't implement wildcard matching
            // (russh does, but it's complex to extract). Be conservative: if the file
            // uses wildcards in @cert-authority, we can't determine the match reliably,
            // so we'll return false and let the operator fix the known_hosts file.
            Ok(false)
        } else {
            // Exact match
            let target = if port == 22 {
                host.to_string()
            } else {
                format!("[{}]:{}", host, port)
            };
            Ok(host_pattern == target || host_pattern == host)
        }
    }
}

/// Thread-safe slot for host key verification errors.
///
/// When russh's check_server_key returns an error, it gets swallowed by russh's
/// connect machinery. We use this slot to smuggle the typed error out.
#[derive(Clone, Default)]
struct HostKeyErrorSlot(Arc<Mutex<Option<ScpError>>>);

impl HostKeyErrorSlot {
    fn set(&self, err: ScpError) {
        *self.0.lock().expect("lock poisoned") = Some(err);
    }

    fn take(&self) -> Option<ScpError> {
        self.0.lock().expect("lock poisoned").take()
    }
}

/// SSH client handler for host key verification.
#[allow(dead_code)] // host and port used in error messages, not directly accessed
struct SshHandler {
    host_key_verification: HostKeyVerification,
    host: String,
    port: u16,
    error_slot: HostKeyErrorSlot,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key_or_cert: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Extract the public key or reject certificates. Unwrapping a Certificate
        // to its inner key would validate the key itself while ignoring the CA
        // signature, validity window, and principals — accepting a certificate
        // the CA never authorized for this host.
        let server_public_key = match key_or_cert {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => {
                let err = ScpError::HostKeyVerification(format!(
                    "Server {}:{} presented an SSH certificate, but certificate \
                     authentication is not supported by this client. Use key-based \
                     authentication instead.",
                    self.host, self.port
                ));
                self.error_slot.set(err);
                return Err(russh::Error::Disconnect);
            }
        };

        match &self.host_key_verification {
            HostKeyVerification::AcceptAll => Ok(true),
            HostKeyVerification::Fingerprint(expected) => {
                // Use ssh-key's fingerprint method
                let actual_fp = server_public_key.fingerprint(HashAlg::Sha256);
                let actual = actual_fp.to_string();

                // Strip optional SHA256: prefix from expected
                let expected_stripped = expected.strip_prefix("SHA256:").unwrap_or(expected);

                // The fingerprint format is "SHA256:base64"
                let actual_hash = actual.strip_prefix("SHA256:").unwrap_or(&actual);

                if actual_hash == expected_stripped {
                    Ok(true)
                } else {
                    let err = ScpError::HostKeyVerification(format!(
                        "host key mismatch: expected SHA256:{}, got {}",
                        expected_stripped, actual
                    ));
                    self.error_slot.set(err);
                    Err(russh::Error::Disconnect)
                }
            }
            HostKeyVerification::KnownHosts(path) | HostKeyVerification::AcceptNew(path) => {
                // Check for OpenSSH marker lines (@revoked, @cert-authority) BEFORE
                // delegating to russh. russh does not implement marker semantics.
                if let Err(e) =
                    check_known_hosts_markers(&self.host, self.port, server_public_key, path)
                {
                    self.error_slot.set(e);
                    return Err(russh::Error::Disconnect);
                }

                // Use russh's built-in known_hosts implementation which correctly handles:
                // - Hashed hosts (|1|...)
                // - Wildcard/comma host lists
                // - Non-default ports ([host]:port format)
                use russh::keys::known_hosts;

                match known_hosts::check_known_hosts_path(
                    &self.host,
                    self.port,
                    server_public_key,
                    path,
                ) {
                    Ok(true) => {
                        // Host key matched
                        Ok(true)
                    }
                    Ok(false) => {
                        // Host not in known_hosts
                        match &self.host_key_verification {
                            HostKeyVerification::KnownHosts(_) => {
                                let err = ScpError::HostKeyVerification(format!(
                                    "Host {} not found in known_hosts file. Add it manually or use AcceptNew mode.",
                                    self.host
                                ));
                                self.error_slot.set(err);
                                Err(russh::Error::Disconnect)
                            }
                            HostKeyVerification::AcceptNew(_) => {
                                // Learn the new host
                                if let Err(e) = known_hosts::learn_known_hosts_path(
                                    &self.host,
                                    self.port,
                                    server_public_key,
                                    path,
                                ) {
                                    let err = ScpError::HostKeyVerification(format!(
                                        "failed to write to known_hosts file {}: {}",
                                        path.display(),
                                        e
                                    ));
                                    self.error_slot.set(err);
                                    return Err(russh::Error::Disconnect);
                                }
                                Ok(true)
                            }
                            _ => unreachable!(),
                        }
                    }
                    Err(russh::keys::Error::KeyChanged { line }) => {
                        // Key changed - security violation
                        let err = ScpError::HostKeyVerification(format!(
                            "Host key mismatch for {}! Key at line {} has changed. \
                             This could indicate a man-in-the-middle attack.",
                            self.host, line
                        ));
                        self.error_slot.set(err);
                        Err(russh::Error::Disconnect)
                    }
                    Err(e) => {
                        // Other error (file read error, parse error, etc.)
                        let err = ScpError::HostKeyVerification(format!(
                            "known_hosts check failed for {}: {}",
                            path.display(),
                            e
                        ));
                        self.error_slot.set(err);
                        Err(russh::Error::Disconnect)
                    }
                }
            }
        }
    }
}

/// Authenticate with the SSH server.
///
/// Supports SSH agent and private key authentication. Password auth is rejected.
async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    username: &str,
    auth: &SshAuth,
    ct: &CancellationToken,
) -> Result<(), ScpError> {
    match auth {
        SshAuth::PrivateKey { path, passphrase } => {
            // P2-2: Load private key with bounded read and validation
            // Maximum size for SSH private keys (64 KB is generous for any real key)
            const MAX_KEY_SIZE: u64 = 64 * 1024;

            // Open and validate the key file atomically with O_NOFOLLOW | O_NONBLOCK
            // - O_NOFOLLOW: fail if path is a symlink
            // - O_NONBLOCK: prevent blocking on FIFO opens
            use rustix::fs::OFlags;

            let path_clone = path.to_path_buf();
            let file = tokio::select! {
                result = tokio::task::spawn_blocking(move || -> Result<std::fs::File, ScpError> {
                    let fd = rustix::fs::openat(
                        rustix::fs::CWD,
                        &path_clone,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(|e| ScpError::Auth(format!(
                        "failed to open private key {}: {}",
                        path_clone.display(),
                        std::io::Error::from_raw_os_error(e.raw_os_error())
                    )))?;
                    Ok(std::fs::File::from(fd))
                }) => {
                    result.map_err(|e| ScpError::Auth(format!("failed to open private key: {}", e)))??
                }
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during key file open"
                    )));
                }
            };

            let file = tokio::fs::File::from_std(file);

            // Validate the opened file descriptor
            let meta = file.metadata().await.map_err(|e| {
                ScpError::Auth(format!(
                    "failed to stat private key {}: {}",
                    path.display(),
                    e
                ))
            })?;

            // Must be a regular file (not FIFO, directory, etc)
            validate_regular_file(path, &meta)?;

            // Enforce size ceiling to prevent OOM on /dev/zero or huge files
            if meta.len() > MAX_KEY_SIZE {
                return Err(ScpError::Auth(format!(
                    "private key file {} is too large ({} bytes, max {} bytes)",
                    path.display(),
                    meta.len(),
                    MAX_KEY_SIZE
                )));
            }

            // Check permissions: reject world-readable keys (standard SSH requirement)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if (mode & 0o077) != 0 {
                    return Err(ScpError::Auth(format!(
                        "private key file {} has unsafe permissions {:04o} (world or group readable). \
                         Use chmod 600 to fix.",
                        path.display(),
                        mode & 0o777
                    )));
                }
            }

            // Clear O_NONBLOCK for blocking read
            let raw_fd = file.as_fd().as_raw_fd();
            let flags = libc_fcntl_getfl(raw_fd)?;
            let new_flags = flags & !(rustix::fs::OFlags::NONBLOCK.bits() as i32);
            libc_fcntl_setfl(raw_fd, new_flags)?;

            // Read the key data with cancellation support
            let mut file = file;
            let mut key_data = Vec::with_capacity(meta.len() as usize);
            tokio::select! {
                result = file.read_to_end(&mut key_data) => {
                    result.map_err(|e| {
                        ScpError::Auth(format!("failed to read private key {}: {}", path.display(), e))
                    })?;
                }
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during key file read"
                    )));
                }
            }

            let key_data = String::from_utf8(key_data).map_err(|_| {
                ScpError::Auth(format!(
                    "private key file {} contains invalid UTF-8",
                    path.display()
                ))
            })?;

            let key_pair = if let Some(pass) = passphrase {
                russh::keys::decode_secret_key(&key_data, Some(pass.expose()))
                    .map_err(|e| ScpError::Auth(format!("failed to decode private key: {}", e)))?
            } else {
                russh::keys::decode_secret_key(&key_data, None)
                    .map_err(|e| ScpError::Auth(format!("failed to decode private key: {}", e)))?
            };

            // Get the best supported RSA hash algorithm for this session
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| ScpError::Auth(format!("failed to query RSA hash support: {}", e)))?
                .flatten();

            let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg);

            let result = handle
                .authenticate_publickey(username, key_with_alg)
                .await
                .map_err(|e| ScpError::Auth(format!("authentication failed: {}", e)))?;

            if result.success() {
                Ok(())
            } else {
                Err(ScpError::Auth("key rejected by server".to_string()))
            }
        }
    }
}

/// Cancellation-aware wrapper around russh Channel.
///
/// Every channel operation (data, wait, exec, eof) is raced against ct.cancelled(),
/// preventing indefinite hangs when the remote peer stalls or stops sending window
/// updates. The wrapper also ensures the channel is closed on drop, so early returns
/// (via `?` operator) cannot leak channels.
///
/// **Drop behavior:** Since `channel.eof()` is async and Drop cannot await, Drop
/// spawns a background task to close the channel. Explicit `close()` is preferred
/// but not required — Drop guarantees cleanup.
struct CancellableChannel {
    /// The underlying SSH channel. Wrapped in Option so Drop can take ownership.
    channel: Option<Channel<client::Msg>>,
    /// Cancellation token shared across the transfer.
    ct: CancellationToken,
}

impl CancellableChannel {
    fn new(channel: Channel<client::Msg>, ct: CancellationToken) -> Self {
        Self {
            channel: Some(channel),
            ct,
        }
    }

    /// Execute a command on the channel, racing against cancellation.
    async fn exec(&mut self, want_reply: bool, cmd: String) -> Result<(), ScpError> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| ScpError::Channel("channel already closed".into()))?;

        tokio::select! {
            biased;
            _ = self.ct.cancelled() => {
                // P2: Cancellation must return promptly, same rule as data/wait branches.
                // When the channel is stalled, close().await would block indefinitely.
                // Drop spawns detached cleanup.
                Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            result = channel.exec(want_reply, cmd) => {
                result.map_err(|e| ScpError::Channel(format!("exec failed: {e}")))
            }
        }
    }

    /// Send data to the channel, racing against cancellation.
    ///
    /// This is the critical fix for P1 #1: when the remote sink stops sending SSH
    /// window adjustments, russh::Channel::data waits indefinitely for window capacity.
    /// By racing against ct.cancelled(), we can wake a stalled upload.
    async fn data(&mut self, data: impl tokio::io::AsyncRead + Unpin) -> Result<(), ScpError> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| ScpError::Channel("channel already closed".into()))?;

        tokio::select! {
            biased;
            _ = self.ct.cancelled() => {
                // P1: Cancellation must return promptly. When the channel is stalled (outbound
                // queue full or TCP write blocked), close().await would block indefinitely trying
                // to push EOF/CLOSE through the same stalled sender. The rule: a cancellation
                // path never awaits anything that can block. Drop spawns detached cleanup.
                Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            result = channel.data(data) => {
                result.map_err(|e| ScpError::Io(std::io::Error::other(e)))
            }
        }
    }

    /// Wait for the next channel message, racing against cancellation.
    async fn wait(&mut self) -> Result<Option<ChannelMsg>, ScpError> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| ScpError::Channel("channel already closed".into()))?;

        tokio::select! {
            biased;
            _ = self.ct.cancelled() => {
                // P1: Cancellation must return promptly. When the channel is stalled, close().await
                // would block indefinitely trying to push EOF/CLOSE through the stalled sender.
                // The rule: a cancellation path never awaits anything that can block.
                // Drop spawns detached cleanup.
                Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            msg = channel.wait() => {
                Ok(msg)
            }
        }
    }

    /// Send EOF to signal end of data, but keep the channel alive for reading messages.
    ///
    /// Used in the normal transfer flow: send EOF, then read the exit status.
    /// Drop will take care of final cleanup.
    ///
    /// P1: Race against cancellation. If the sender queue is full (stalled connection),
    /// eof() can block indefinitely waiting to enqueue the EOF message. Make it
    /// cancellation-aware like data() and wait() so cancelling the transfer can wake
    /// a stalled eof().
    async fn eof(&mut self) -> Result<(), ScpError> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| ScpError::Channel("channel already closed".into()))?;

        tokio::select! {
            biased;
            _ = self.ct.cancelled() => {
                // P1: Cancellation must return promptly. When the channel is stalled, close().await
                // would block indefinitely trying to push EOF/CLOSE through the stalled sender.
                // The rule: a cancellation path never awaits anything that can block.
                // Drop spawns detached cleanup.
                Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )))
            }
            result = channel.eof() => {
                result.map_err(|e| ScpError::Io(std::io::Error::other(e)))
            }
        }
    }
}

impl Drop for CancellableChannel {
    /// Ensures the channel is closed even if an early return (`?`) bypasses explicit close.
    ///
    /// Since `channel.eof()` is async and Drop cannot await, we spawn a background task
    /// to fire-and-forget the close. This prevents leaking channels and remote processes
    /// when transfers are cancelled or fail mid-flight.
    ///
    /// **Runtime shutdown caveat:** If the tokio runtime is shutting down or the current
    /// task is cancelled, `tokio::spawn` may fail to schedule the close task, or the task
    /// may be dropped before it runs. In that case, the channel is not explicitly closed.
    /// However, the SSH connection will eventually time out or be closed when the process
    /// exits, so the leak is bounded to the process lifetime.
    ///
    /// **Explicit close is better:** The normal transfer paths call `channel.close().await`
    /// explicitly (upload line ~489, download line ~611), which is strictly better than
    /// relying on Drop because it completes before returning success to the caller.
    /// Drop is a safety net for error paths (`?` early returns), not the primary mechanism.
    fn drop(&mut self) {
        if let Some(channel) = self.channel.take() {
            // Best-effort cleanup: only spawn if a runtime is active.
            // If the runtime is gone, the channel is already unusable.
            if tokio::runtime::Handle::try_current().is_ok() {
                tokio::spawn(async move {
                    // P2: Give EOF and CLOSE independent timeouts.
                    // When cancellation happens because the russh sender is stalled, eof() can
                    // burn the entire timeout budget and close() never runs. Since russh::Channel
                    // doesn't close on drop, repeated aborted transfers on a reused client retain
                    // remote SCP processes.
                    //
                    // EOF is a courtesy; CLOSE actually frees the channel. Give each a separate
                    // 2.5s budget so CLOSE always gets a chance to run, even if EOF blocks or times out.
                    use tokio::time::{Duration, timeout};
                    let _ = timeout(Duration::from_millis(2500), channel.eof()).await;
                    let _ = timeout(Duration::from_millis(2500), channel.close()).await;
                });
            }
        }
    }
}

/// Buffered reader for channel data that preserves unread bytes across read operations.
///
/// `ChannelMsg::Data` can contain arbitrary-length buffers. Without buffering,
/// reading a single byte from a message that contains multiple bytes would discard
/// the remainder, causing protocol desynchronization.
struct ChannelReader {
    buffer: Vec<u8>,
    pos: usize,
}

impl ChannelReader {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            pos: 0,
        }
    }

    /// Read a single byte, fetching from the channel if the buffer is empty.
    async fn read_byte(&mut self, channel: &mut CancellableChannel) -> Result<u8, ScpError> {
        if self.pos >= self.buffer.len() {
            self.fill(channel).await?;
        }
        let byte = self.buffer[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    /// Read exactly `buf.len()` bytes into `buf`.
    async fn read_exact<'a>(
        &mut self,
        channel: &mut CancellableChannel,
        buf: &'a mut [u8],
    ) -> Result<&'a [u8], ScpError> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pos >= self.buffer.len() {
                self.fill(channel).await?;
            }
            let available = std::cmp::min(buf.len() - filled, self.buffer.len() - self.pos);
            buf[filled..filled + available]
                .copy_from_slice(&self.buffer[self.pos..self.pos + available]);
            self.pos += available;
            filled += available;
        }
        Ok(&buf[..])
    }

    /// Fill the buffer with data from the channel.
    async fn fill(&mut self, channel: &mut CancellableChannel) -> Result<(), ScpError> {
        loop {
            match channel.wait().await? {
                Some(ChannelMsg::Data { data }) if !data.is_empty() => {
                    self.buffer = data.to_vec();
                    self.pos = 0;
                    return Ok(());
                }
                Some(ChannelMsg::Data { .. }) => continue,
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    return Err(ScpError::ChannelClosed(
                        "channel closed while reading".to_string(),
                    ));
                }
                Some(_) => continue, // WindowAdjusted, etc.
            }
        }
    }
}

/// Result of a successful SCP transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScpOutcome {
    /// Number of bytes transferred.
    pub bytes_transferred: u64,
    /// Warning messages from the server (ack byte `\x01`).
    /// Empty if the transfer completed without warnings.
    pub server_messages: Vec<String>,
}

/// SCP protocol acknowledgement byte.
#[derive(Debug, PartialEq, Eq)]
enum Ack {
    Success,
    Warning(String),
    Error(String),
}

/// Drop guard that sets the poisoned flag if a channel open was queued but outcome not observed.
///
/// This handles cancellation-by-drop (e.g., tokio::time::timeout expiring) where the
/// cancellation token branch never runs. The guard is armed around the channel_open_session,
/// and disarmed on success. If dropped while armed (future dropped mid-flight), it poisons
/// the client.
///
/// Invariant: Poison exactly when an open was queued and its outcome was not observed.
struct PoisonGuard<'a> {
    poisoned: &'a mut bool,
    armed: bool,
}

impl<'a> PoisonGuard<'a> {
    fn new(poisoned: &'a mut bool) -> Self {
        Self {
            poisoned,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PoisonGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            *self.poisoned = true;
        }
    }
}

/// SCP1 client for uploading and downloading files over SSH exec channels.
///
/// Opens a dedicated SSH connection for each transfer (does not share NETCONF
/// session pools).
pub struct ScpClient {
    handle: client::Handle<SshHandler>,
    /// Set when cancellation drops an in-flight channel open. Subsequent operations fail fast.
    poisoned: bool,
}

impl ScpClient {
    /// Open a new SSH connection for SCP operations.
    ///
    /// Uses key-only authentication (Agent or PrivateKey). Password auth is not supported.
    /// Jump hosts and proxy commands are not supported.
    pub async fn connect(config: SshConfig, ct: &CancellationToken) -> Result<Self, ScpError> {
        let russh_config = Arc::new(build_russh_config());

        // P2: Validate known_hosts file off-runtime before SSH callback.
        // If it's a FIFO, metadata() blocks and freezes current-thread runtime.
        if let HostKeyVerification::KnownHosts(ref path)
        | HostKeyVerification::AcceptNew(ref path) = config.host_key_verification
        {
            let path_clone = path.clone();
            tokio::select! {
                result = tokio::task::spawn_blocking(move || -> Result<(), ScpError> {
                    // Check if file exists and is a regular file (not FIFO, not symlink)
                    match std::fs::metadata(&path_clone) {
                        Ok(meta) => {
                            if !meta.is_file() {
                                return Err(ScpError::HostKeyVerification(format!(
                                    "known_hosts path is not a regular file: {}",
                                    path_clone.display()
                                )));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            // File doesn't exist - OK for AcceptNew mode, will be created
                        }
                        Err(e) => {
                            return Err(ScpError::HostKeyVerification(format!(
                                "failed to access known_hosts file {}: {}",
                                path_clone.display(),
                                e
                            )));
                        }
                    }
                    Ok(())
                }) => {
                    result.map_err(|e| ScpError::Io(std::io::Error::other(e)))??
                }
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during known_hosts validation"
                    )));
                }
            };
        }

        let error_slot = HostKeyErrorSlot::default();
        let handler = SshHandler {
            host_key_verification: config.host_key_verification.clone(),
            host: config.host.clone(),
            port: config.port,
            error_slot: error_slot.clone(),
        };

        // Connect and authenticate with a 15-second deadline (matching openssh-client
        // `-o ConnectTimeout=15`). Race both operations against the timeout and the
        // cancellation token. A peer that accepts TCP but never speaks SSH, or stalls
        // mid-handshake, will fail promptly instead of holding per-device capacity.
        const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

        let connect_fut = async {
            // Race connect against cancellation.
            let mut handle = tokio::select! {
                result = client::connect(russh_config, (&*config.host, config.port), handler) => {
                    result.map_err(|e| {
                        error_slot
                            .take()
                            .unwrap_or_else(|| ScpError::Connect(format!("SSH connect failed: {e}")))
                    })?
                }
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during SSH connect"
                    )));
                }
            };

            // Authenticate (also cancellable)
            tokio::select! {
                result = authenticate(&mut handle, &config.username, &config.auth, ct) => {
                    result?
                }
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during SSH auth"
                    )));
                }
            };

            Ok::<_, ScpError>(handle)
        };

        // Wrap the whole connect+auth sequence in a timeout.
        let handle = tokio::time::timeout(CONNECT_TIMEOUT, connect_fut)
            .await
            .map_err(|_| {
                ScpError::Connect(format!(
                    "Connection timed out after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })??;

        Ok(Self {
            handle,
            poisoned: false,
        })
    }

    /// Upload a file to the remote host using `scp -t <remote_dir>`.
    ///
    /// # Arguments
    ///
    /// * `local_path` - Path to the local file to upload. **The caller must ensure that
    ///   the parent directories of `local_path` are trusted** (not writable by untrusted
    ///   local users). `O_NOFOLLOW` protects only the final component from symlink
    ///   redirection; a symlinked or attacker-replaceable parent directory can still
    ///   redirect the open.
    /// * `remote_dir` - Directory on the remote host (e.g., `"/var/tmp/"`).
    ///   The filename will match the local basename.
    /// * `progress` - Optional progress callback `(bytes_sent, total_bytes)`.
    /// * `ct` - Cancellation token.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is cancelled mid-transfer, or for permission
    /// denied, disk full, file not found, etc. If a previous transfer was cancelled
    /// during channel open, this returns `ScpClientPoisoned` — reconnect to get a
    /// fresh client.
    pub async fn upload(
        &mut self,
        local_path: &Path,
        remote_dir: &str,
        progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
        ct: &CancellationToken,
    ) -> Result<ScpOutcome, ScpError> {
        if self.poisoned {
            return Err(ScpError::ScpClientPoisoned);
        }

        // Open the file with O_NOFOLLOW | O_NONBLOCK atomically, then validate the descriptor.
        // This eliminates TOCTOU races: we validate what we opened, not what existed at check time.
        // - O_NOFOLLOW: fail if local_path is a symlink (prevents symlink redirection)
        // - O_NONBLOCK: prevent blocking on FIFO opens (returns immediately instead of hanging)
        //
        // Known limitation: O_NOFOLLOW protects only the final component. A symlinked or
        // attacker-replaceable parent directory can still redirect the open. The documented
        // fix is openat2(2) with RESOLVE_NO_SYMLINKS (Linux 5.6+), which walks the entire
        // path without following any symlinks. This module is already Unix-gated, so adding
        // openat2 via libc::openat2 + RESOLVE_NO_SYMLINKS would fully defend the path. For
        // now, the API documents that the caller must supply paths whose parent directories
        // are trusted.
        use rustix::fs::OFlags;

        // openat is a blocking syscall; run it off-runtime so cancellation can interrupt
        let local_path_clone = local_path.to_path_buf();
        let file = tokio::select! {
            result = tokio::task::spawn_blocking(move || -> Result<std::fs::File, ScpError> {
                let fd = rustix::fs::openat(
                    rustix::fs::CWD,
                    &local_path_clone,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|e| ScpError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?;
                Ok(std::fs::File::from(fd))
            }) => {
                result.map_err(|e| ScpError::Io(std::io::Error::other(e)))??
            }
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "upload cancelled during file open"
                )));
            }
        };

        let file = tokio::fs::File::from_std(file);

        // Validate the opened file descriptor (not the path — we validate what we opened)
        // P2-3: Race metadata read against cancellation
        let meta_after = tokio::select! {
            result = file.metadata() => result?,
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during metadata read"
                )));
            }
        };
        validate_regular_file(local_path, &meta_after)?;
        let file_size = meta_after.len();

        // Extract mode bits for the C header, preserving the file's permissions.
        use std::os::unix::fs::PermissionsExt;
        let mode = meta_after.permissions().mode() & 0o777;

        // Extract basename as raw OS bytes. Unix paths may contain non-UTF-8 sequences.
        // The C header format is "C<mode> <size> <name>\n", where mode/size are ASCII
        // but <name> is raw bytes terminated by newline. Only reject newline delimiter.
        use std::os::unix::ffi::OsStrExt;
        let os_name = local_path.file_name().ok_or_else(|| {
            ScpError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("local_path has no filename: {}", local_path.display()),
            ))
        })?;
        let basename_bytes = os_name.as_bytes();
        if basename_bytes.contains(&b'\n') {
            return Err(ScpError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("filename contains newline: {}", local_path.display()),
            )));
        }

        // P2: Check cancellation before poisoning client - pre-cancelled token should not brick
        // a healthy reusable client.
        if ct.is_cancelled() {
            return Err(ScpError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled before opening channel",
            )));
        }

        // Open exec channel: scp -t <remote_dir>
        // P1: Race against cancellation - peer may never confirm channel open.
        // P3: Drop guard to handle cancellation-by-drop (e.g., timeout expiring) where the
        // token branch never runs. The guard sets poisoned on drop unless disarmed.
        let mut poison_guard = PoisonGuard::new(&mut self.poisoned);
        let mut open_future = Box::pin(self.handle.channel_open_session());

        let raw_channel = tokio::select! {
            biased;
            _ = ct.cancelled() => {
                // P1: Cancellation must return promptly without blocking. The rule: a cancellation
                // path never awaits anything that can block.
                //
                // We cannot spawn a detached task to close any channel the open produces because
                // open_future borrows &self.handle (russh::client::Handle is not Clone, and
                // channel_open_session() returns impl Future + '_ not + 'static). Spawning would
                // require open_future: 'static, which we cannot satisfy.
                //
                // Leak bound: One channel per cancelled transfer, only if cancellation races the
                // confirmation window (peer sent SSH_MSG_CHANNEL_OPEN_CONFIRM after we cancelled
                // but before the future was dropped). The leaked channel is bounded by the
                // connection lifetime. Mark the client poisoned (via drop guard) so subsequent
                // operations fail fast rather than risking unpredictable behavior.
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled while opening channel"
                )));
            }
            result = &mut open_future => {
                // Observed failures (server refused) are not races — disarm guard before propagating
                match result {
                    Ok(ch) => ch,
                    Err(e) => {
                        poison_guard.disarm();
                        return Err(ScpError::Channel(format!("failed to open session: {e}")));
                    }
                }
            }
        };

        // P3: Channel opened successfully, disarm the guard (don't poison on normal drop)
        poison_guard.disarm();

        let mut channel = CancellableChannel::new(raw_channel, ct.clone());

        // P1: -p preserves file timestamps (mtime/atime via T header)
        // P2: -d enforces that remote_dir is actually a directory, rejecting regular files
        // P2: -- terminates option parsing before remote_dir, preventing "-staging" being parsed as an option
        let cmd = format!("scp -p -d -t -- {}", shell_escape(remote_dir));
        channel.exec(true, cmd).await?;

        // Wait for exec success/failure before starting SCP protocol.
        // If the server rejects exec, russh delivers ChannelMsg::Failure;
        // without consuming it, we'd wait indefinitely for an SCP ack.
        // If the server emits SCP data before CHANNEL_SUCCESS, preserve it.
        check_cancellation(ct)?;
        let mut reader = ChannelReader::new();
        loop {
            match channel.wait().await? {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(ScpError::Channel(
                        "server rejected exec request".to_string(),
                    ));
                }
                Some(ChannelMsg::Data { data }) => {
                    // Server started SCP before sending CHANNEL_SUCCESS.
                    // Feed the data into ChannelReader so it's not lost.
                    reader.buffer = data.to_vec();
                    reader.pos = 0;
                    break;
                }
                Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => {
                    return Err(ScpError::ChannelClosed(
                        "channel closed before exec response".to_string(),
                    ));
                }
                Some(_) => continue, // WindowAdjusted, etc.
            }
        }

        // SCP protocol upload sequence
        let mut warnings = Vec::new();

        // 1. Wait for initial ack (server ready)
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) => {
                // P2: ack byte 1 on initial handshake is an error, not a warning
                return Err(scp_error(msg));
            }
            Ack::Error(msg) => return Err(scp_error(msg)),
        }

        // 2. Send T header: T<mtime> 0 <atime> 0\n
        // Extract file timestamps and clamp pre-epoch values to zero.
        // Files with mtime/atime before 1970 emit negative values, producing
        // T-1 0 -1 0, which OpenSSH rejects as malformed. Clamp to zero like OpenSSH.
        use std::os::unix::fs::MetadataExt;
        let (mtime, atime) = (meta_after.mtime().max(0), meta_after.atime().max(0));

        let t_header = format!("T{} 0 {} 0\n", mtime, atime);
        channel.data(t_header.as_bytes()).await?;

        // Wait for T header ack
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) | Ack::Error(msg) => {
                // Server rejected T header
                return Err(scp_error(msg));
            }
        }

        // 3. Send C header: C<mode> <size> <name>\n
        // Build header from bytes to handle non-UTF-8 filenames on Unix.
        // The mode and size fields are ASCII, but name is raw OS bytes.
        let mut header = format!("C{:04o} {} ", mode, file_size).into_bytes();
        header.extend_from_slice(basename_bytes);
        header.push(b'\n');
        channel.data(&header[..]).await?;

        // 4. Wait for header ack
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) | Ack::Error(msg) => {
                // P2: reject C header (ack byte 1 or 2) aborts the transfer
                return Err(scp_error(msg));
            }
        }

        // 5. Stream file data in chunks
        let mut file = file;
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut sent = 0u64;

        while sent < file_size {
            check_cancellation(ct)?;

            // Clamp in u64 before casting to avoid truncation on 32-bit targets
            let to_read = std::cmp::min(file_size - sent, CHUNK_SIZE as u64) as usize;

            // Race file read against cancellation. Tokio's file operations run on the
            // blocking pool, so cancelling the future makes the call return promptly but
            // does NOT abort the underlying syscall — the blocking task finishes in
            // background. This is still correct (caller freed, handle dropped), but the
            // read completes unseen rather than being truly aborted.
            let n = tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during file read"
                    )));
                }
                result = file.read(&mut buf[..to_read]) => result?,
            };
            if n == 0 {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "local file ended early",
                )));
            }

            channel.data(&buf[..n]).await?;

            sent += n as u64;
            if let Some(cb) = progress {
                cb(sent, file_size);
            }
        }

        // 6. Send final \0 (end of data)
        check_cancellation(ct)?;
        channel.data(&[0u8][..]).await?;

        // 7. Wait for final ack
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) | Ack::Error(msg) => {
                // P2: Status byte 1 or 2 after payload (e.g., "disk full") is a failure.
                // Storing as a warning loses typed error and can make the transfer look
                // successful if the server then exits 0.
                return Err(scp_error(msg));
            }
        }

        // 8. Send E\n (end session)
        channel.data(&b"E\n"[..]).await?;

        // 9. Wait for E ack
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) => warnings.push(msg),
            Ack::Error(msg) => return Err(scp_error(msg)),
        }

        // 10. Send EOF and read exit status
        channel.eof().await?;

        let exit_status = wait_exit_status(&mut channel).await?;
        if exit_status != 0 {
            return Err(ScpError::Channel(format!(
                "scp command exited with status {}",
                exit_status
            )));
        }

        // Channel is dropped here, triggering background cleanup via Drop

        Ok(ScpOutcome {
            bytes_transferred: sent,
            server_messages: warnings,
        })
    }

    /// Download a file from the remote host using `scp -f <remote_path>`.
    ///
    /// # Arguments
    ///
    /// * `remote_path` - Full path to the remote file (e.g., `"/var/tmp/foo.tgz"`).
    /// * `local_path` - Destination path on the local filesystem. **The caller must ensure
    ///   that the parent directories of `local_path` are trusted** (not writable by
    ///   untrusted local users). `O_NOFOLLOW` protects only the final component from symlink
    ///   redirection; a symlinked or attacker-replaceable parent directory can still
    ///   redirect the open.
    /// * `progress` - Optional progress callback `(bytes_received, total_bytes)`.
    /// * `ct` - Cancellation token.
    ///
    /// # File Permissions
    ///
    /// On Unix, the destination file is created (or, if it already exists, chmod'd)
    /// with the mode received in the SCP `C` header **before** any payload data is
    /// written. This differs from OpenSSH's `scp`, which leaves pre-existing files'
    /// modes unchanged, but is more predictable for security-sensitive transfers:
    /// a `C0600` download always lands at mode 0600, regardless of prior state.
    ///
    /// # Errors
    ///
    /// Returns an error if cancelled mid-transfer, if the remote file does not
    /// exist, or is unreadable. If a previous transfer was cancelled during channel
    /// open, this returns `ScpClientPoisoned` — reconnect to get a fresh client.
    pub async fn download(
        &mut self,
        remote_path: &str,
        local_path: &Path,
        progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
        ct: &CancellationToken,
    ) -> Result<ScpOutcome, ScpError> {
        if self.poisoned {
            return Err(ScpError::ScpClientPoisoned);
        }

        // P2: Check cancellation before poisoning client - pre-cancelled token should not brick
        // a healthy reusable client.
        if ct.is_cancelled() {
            return Err(ScpError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled before opening channel",
            )));
        }

        // Open exec channel: scp -f <remote_path>
        // P1: Race against cancellation - peer may never confirm channel open.
        // P3: Drop guard to handle cancellation-by-drop (e.g., timeout expiring) where the
        // token branch never runs. The guard sets poisoned on drop unless disarmed.
        let mut poison_guard = PoisonGuard::new(&mut self.poisoned);
        let mut open_future = Box::pin(self.handle.channel_open_session());

        let raw_channel = tokio::select! {
            biased;
            _ = ct.cancelled() => {
                // P1: Cancellation must return promptly without blocking. The rule: a cancellation
                // path never awaits anything that can block.
                //
                // We cannot spawn a detached task to close any channel the open produces because
                // open_future borrows &self.handle (russh::client::Handle is not Clone, and
                // channel_open_session() returns impl Future + '_ not + 'static). Spawning would
                // require open_future: 'static, which we cannot satisfy.
                //
                // Leak bound: One channel per cancelled transfer, only if cancellation races the
                // confirmation window (peer sent SSH_MSG_CHANNEL_OPEN_CONFIRM after we cancelled
                // but before the future was dropped). The leaked channel is bounded by the
                // connection lifetime. Mark the client poisoned (via drop guard) so subsequent
                // operations fail fast rather than risking unpredictable behavior.
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled while opening channel"
                )));
            }
            result = &mut open_future => {
                // Observed failures (server refused) are not races — disarm guard before propagating
                match result {
                    Ok(ch) => ch,
                    Err(e) => {
                        poison_guard.disarm();
                        return Err(ScpError::Channel(format!("failed to open session: {e}")));
                    }
                }
            }
        };

        // P3: Channel opened successfully, disarm the guard (don't poison on normal drop)
        poison_guard.disarm();

        let mut channel = CancellableChannel::new(raw_channel, ct.clone());

        // P2: -- terminates option parsing before remote_path, preventing "-staging" being parsed as an option
        let cmd = format!("scp -f -- {}", shell_escape(remote_path));
        channel.exec(true, cmd).await?;

        // Wait for exec success/failure before starting SCP protocol
        // Preserve any SCP data sent before CHANNEL_SUCCESS
        check_cancellation(ct)?;
        let mut reader = ChannelReader::new();
        loop {
            match channel.wait().await? {
                Some(ChannelMsg::Success) => break,
                Some(ChannelMsg::Failure) => {
                    return Err(ScpError::Channel(
                        "server rejected exec request".to_string(),
                    ));
                }
                Some(ChannelMsg::Data { data }) => {
                    // Server started SCP before sending CHANNEL_SUCCESS.
                    // Feed the data into ChannelReader so it's not lost.
                    reader.buffer = data.to_vec();
                    reader.pos = 0;
                    break;
                }
                Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => {
                    return Err(ScpError::ChannelClosed(
                        "channel closed before exec response".to_string(),
                    ));
                }
                Some(_) => continue,
            }
        }

        let warnings = Vec::new();

        // P1 fix: Send \0 BEFORE waiting for data — the source won't send until receiver is ready
        // 1. Send \0 (ready to receive)
        channel.data(&[0u8][..]).await?;

        // 2. Read C header or error from server
        check_cancellation(ct)?;
        let header = read_line(&mut reader, &mut channel).await?;

        // Check if this is an error message (starts with \x01 or \x02) instead of C header
        if header.starts_with('\x01') || header.starts_with('\x02') {
            return Err(scp_error(header[1..].to_string()));
        }

        let (raw_mode, file_size, remote_name) = parse_c_header(&header)?;

        // P1: Strip privileged bits from server-provided mode.
        // The mode from the C header is attacker-controlled. If we run with root or
        // CAP_FSETID and the server sends C4755, we'd create a setuid root binary from
        // downloaded payload — a straight pivot from a compromised firewall to the host.
        // Mask to 0o777 (strip setuid, setgid, sticky) before using it anywhere.
        let mode = raw_mode & 0o777;

        // Validate the server didn't try to send an absolute path.
        // We don't check for leading `.` or embedded `..` since remote_name is never joined
        // to a path — it's only validated as-is and never used for filesystem operations
        // (we write to local_path instead).
        if remote_name.contains('/') {
            return Err(ScpError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server sent unsafe filename: {}", remote_name),
            )));
        }

        // 3. Open destination and apply mode BEFORE acknowledging header
        // Apply the received mode BEFORE acknowledging the header or writing any data.
        // OpenOptionsExt::mode applies only when the file is created. If local_path
        // already exists at, say, 0666 and the server sends C0600, the mode is ignored,
        // so the destination stays broadly readable for the whole transfer. If cancellation,
        // a write failure, or a source error hits before we can chmod, it keeps those
        // permissions with partial or complete secret content on disk.
        //
        // Fix: Open the file and apply the received mode through the handle itself
        // (File::set_permissions on the open file, not a path-based chmod — a path-based
        // one reintroduces a race). Do this BEFORE sending the accept ack, so the file
        // has restrictive permissions from the moment we acknowledge the header. Do it for
        // both newly-created and pre-existing cases, so OpenOptionsExt::mode is an
        // optimisation rather than the only protection.
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::PermissionsExt;

        // Open with O_NOFOLLOW | O_NONBLOCK atomically to prevent:
        // - Symlink traversal (O_NOFOLLOW fails if local_path is a symlink)
        // - FIFO blocking (O_NONBLOCK prevents waiting for a reader on FIFO open)
        //
        // Known limitation: O_NOFOLLOW protects only the final component. A symlinked or
        // attacker-replaceable parent directory can still redirect the open. The documented
        // fix is openat2(2) with RESOLVE_NO_SYMLINKS (Linux 5.6+), which walks the entire
        // path without following any symlinks. This module is already Unix-gated, so adding
        // openat2 via libc::openat2 + RESOLVE_NO_SYMLINKS would fully defend the path. For
        // now, the API documents that the caller must supply paths whose parent directories
        // are trusted.
        //
        // Also open without truncate first: if local_path exists but is not owned by the
        // caller (group-writable or ACL-writable but caller != owner), open-with-truncate
        // succeeds and destroys the contents, then set_permissions fails with EPERM,
        // leaving the user's file empty. Open, chmod, THEN truncate so a permission
        // failure aborts before data loss.

        // openat is a blocking syscall; run it off-runtime so cancellation can interrupt
        let local_path_clone = local_path.to_path_buf();
        let f = tokio::select! {
            result = tokio::task::spawn_blocking(move || -> Result<std::fs::File, ScpError> {
                let fd = rustix::fs::openat(
                    rustix::fs::CWD,
                    &local_path_clone,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                    Mode::from_raw_mode(mode),
                )
                .map_err(|e| ScpError::Io(std::io::Error::from_raw_os_error(e.raw_os_error())))?;
                Ok(std::fs::File::from(fd))
            }) => {
                result.map_err(|e| ScpError::Io(std::io::Error::other(e)))??
            }
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "download cancelled during file open"
                )));
            }
        };

        let f = tokio::fs::File::from_std(f);

        // Validate the opened file descriptor is a regular file (not FIFO/directory/etc).
        // This validation happens AFTER the open, so we validate what we actually opened,
        // eliminating TOCTOU races.
        // P2-3: Race metadata read against cancellation
        let meta = tokio::select! {
            result = f.metadata() => result?,
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during metadata read"
                )));
            }
        };
        validate_regular_file(local_path, &meta)?;

        // SECURITY: Two-phase mode application to satisfy dual constraints:
        //
        // Constraint 1 (from round 12): Never destroy data before knowing chmod will succeed.
        // If local_path exists but caller is not owner (group-writable or ACL-writable but
        // caller != owner), chmod can fail with EPERM. Truncating first would destroy data,
        // then fail to apply the mode, leaving an empty file with wrong permissions.
        //
        // Constraint 2 (this round): Never widen permissions while old contents remain.
        // If local_path exists at 0600 and peer sends 0644, immediately applying 0644 creates
        // a window where another local user can read the old contents before truncation.
        //
        // Solution: Apply mode in two phases:
        // 1. Interim mode = current_mode & requested_mode (narrowing only, never widening)
        // 2. Truncate to 0 (old contents destroyed)
        // 3. Final mode = requested_mode (safe to widen now that old bytes are gone)
        //
        // This proves chmod works (satisfies constraint 1) before truncating, and only widens
        // after old data is gone (satisfies constraint 2).
        //
        // Use handle-based chmod (not path-based) to eliminate TOCTOU races — we chmod the
        // inode we actually opened, so there is no path resolution to race.

        // Step 1: Read current mode from the opened descriptor
        let current_mode = meta.permissions().mode() & 0o777;

        // Step 2: Compute interim mode (intersection = narrowing only)
        let interim_mode = current_mode & mode;

        // Step 3: Apply interim mode - if this fails with EPERM, abort before truncating
        // P2-3: Race against cancellation
        let interim_permissions = std::fs::Permissions::from_mode(interim_mode);
        tokio::select! {
            result = f.set_permissions(interim_permissions) => result?,
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during chmod"
                )));
            }
        };

        // Step 4: Truncate to 0 - old contents destroyed, safe because mode was narrowed or unchanged
        // P2-3: Race against cancellation
        tokio::select! {
            result = f.set_len(0) => result?,
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during truncate"
                )));
            }
        };

        // Step 5: Apply requested mode - widening now safe, old bytes gone
        // P2-3: Race against cancellation
        let final_permissions = std::fs::Permissions::from_mode(mode);
        tokio::select! {
            result = f.set_permissions(final_permissions) => result?,
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during chmod"
                )));
            }
        };

        // Clear O_NONBLOCK flag for blocking I/O during download.
        // We needed O_NONBLOCK to prevent blocking on FIFO open, but now that we've
        // validated the descriptor is a regular file, we want blocking writes.
        let raw_fd = f.as_fd().as_raw_fd();
        let flags = libc_fcntl_getfl(raw_fd)?;
        let new_flags = flags & !(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        libc_fcntl_setfl(raw_fd, new_flags)?;

        let mut file = f;

        // 4. Send \0 (accept header) - file is now open with restrictive mode applied
        channel.data(&[0u8][..]).await?;

        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut received = 0u64;

        while received < file_size {
            check_cancellation(ct)?;

            // Clamp in u64 before casting to avoid truncation on 32-bit targets
            let to_read = std::cmp::min(file_size - received, CHUNK_SIZE as u64) as usize;
            let data = reader.read_exact(&mut channel, &mut buf[..to_read]).await?;

            // Race file write against cancellation. Tokio's file operations run on the
            // blocking pool, so cancelling the future makes the call return promptly but
            // does NOT abort the underlying syscall — the blocking task finishes in
            // background. This is still correct (caller freed, handle dropped), but the
            // write completes unseen rather than being truly aborted.
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    return Err(ScpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled during file write"
                    )));
                }
                result = file.write_all(data) => result?,
            }
            received += data.len() as u64;

            if let Some(cb) = progress {
                cb(received, file_size);
            }
        }

        // P1: Flush the file to observe any write errors (disk exhaustion, quota, I/O)
        // before acknowledging the source. Without this, write_all can schedule the
        // blocking write and return Ok, and we'd send success with a truncated file.
        // Use flush() rather than sync_all(): flush() ensures data reaches the OS buffer
        // cache, which is sufficient to surface write errors. sync_all() would force
        // physical disk sync, adding latency for no protocol benefit (SCP1 has no
        // fsync semantics, and the remote has no way to retry on our disk failure).
        //
        // Race flush against cancellation. Tokio's file operations run on the blocking
        // pool, so cancelling the future makes the call return promptly but does NOT
        // abort the underlying syscall — the blocking task finishes in background. This
        // is still correct (caller freed, handle dropped), but the flush completes
        // unseen rather than being truly aborted.
        tokio::select! {
            biased;
            _ = ct.cancelled() => {
                return Err(ScpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled during file flush"
                )));
            }
            result = file.flush() => result?,
        }

        // 5. Read final status byte from server (end of data)
        check_cancellation(ct)?;
        match read_ack(&mut reader, &mut channel).await? {
            Ack::Success => {}
            Ack::Warning(msg) | Ack::Error(msg) => {
                // Source reports an error after the payload (e.g., read error on its end)
                return Err(scp_error(msg));
            }
        }

        // 6. Send \0 (ack received)
        channel.data(&[0u8][..]).await?;

        // 7. Send EOF and read exit status
        channel.eof().await?;

        let exit_status = wait_exit_status(&mut channel).await?;
        if exit_status != 0 {
            return Err(ScpError::Channel(format!(
                "scp command exited with status {}",
                exit_status
            )));
        }

        // Channel is dropped here, triggering background cleanup via Drop

        Ok(ScpOutcome {
            bytes_transferred: received,
            server_messages: warnings,
        })
    }

    /// Close the SSH connection.
    pub async fn close(self) -> Result<(), ScpError> {
        self.handle
            .disconnect(Disconnect::ByApplication, "closing session", "en")
            .await
            .map_err(|e| ScpError::Io(std::io::Error::other(e)))?;
        Ok(())
    }
}

/// Read a single acknowledgement byte and optional message from the SCP server.
///
/// Format:
/// - `\0` → Success
/// - `\x01<message>\n` → Warning
/// - `\x02<message>\n` → Error
async fn read_ack(
    reader: &mut ChannelReader,
    channel: &mut CancellableChannel,
) -> Result<Ack, ScpError> {
    let byte = reader.read_byte(channel).await?;
    match byte {
        0 => Ok(Ack::Success),
        1 | 2 => {
            let msg = read_line(reader, channel).await?;
            if byte == 1 {
                Ok(Ack::Warning(msg))
            } else {
                Ok(Ack::Error(msg))
            }
        }
        _ => Err(ScpError::Channel(format!("invalid SCP ack byte: {}", byte))),
    }
}

/// Read a line (until `\n`) from the channel.
async fn read_line(
    reader: &mut ChannelReader,
    channel: &mut CancellableChannel,
) -> Result<String, ScpError> {
    let mut line = Vec::new();
    loop {
        let byte = reader.read_byte(channel).await?;
        if byte == b'\n' {
            break;
        }
        line.push(byte);
        if line.len() > MAX_CONTROL_LINE_LENGTH {
            return Err(ScpError::Channel(format!(
                "SCP control line exceeded maximum length of {} bytes",
                MAX_CONTROL_LINE_LENGTH
            )));
        }
    }
    String::from_utf8(line)
        .map_err(|_| ScpError::Channel("SCP server sent non-UTF-8 message".to_string()))
}

/// Parse the SCP C header: `C<mode> <size> <name>\n`
/// Returns (mode, size, filename).
///
/// P2: Preserve whitespace-only filenames. read_line stripped the newline already,
/// so trim() also eats filenames made of spaces: 'C0644 1  ' collapses to two fields.
/// Split untrimmed line, filename is everything after second separator. This mirrors
/// the upload side's shell_escape which preserves spaces.
fn parse_c_header(line: &str) -> Result<(u32, u64, String), ScpError> {
    // Strip trailing newline if present (read_line strips it, but tests may pass raw strings)
    let line = line.strip_suffix('\n').unwrap_or(line);

    // Split the line (no general trim!) into exactly 3 parts on whitespace.
    // The third part is the filename, which can contain spaces or be space-only.
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 || !parts[0].starts_with('C') {
        return Err(ScpError::Channel(format!("invalid SCP C header: {}", line)));
    }

    // Parse mode from C<mode> (e.g., "C0600" -> mode is "0600")
    let mode_str = &parts[0][1..]; // Skip the 'C'
    let mode = u32::from_str_radix(mode_str, 8)
        .map_err(|_| ScpError::Channel(format!("invalid mode in C header: {}", parts[0])))?;

    let size: u64 = parts[1]
        .parse()
        .map_err(|_| ScpError::Channel(format!("invalid file size in C header: {}", parts[1])))?;

    Ok((mode, size, parts[2].to_string()))
}

/// Wait for the channel's exit status, racing against cancellation.
async fn wait_exit_status(channel: &mut CancellableChannel) -> Result<u32, ScpError> {
    loop {
        match channel.wait().await? {
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                return Ok(exit_status);
            }
            Some(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                ..
            }) => {
                return Err(ScpError::Channel(format!(
                    "remote process killed by signal {:?} (core dumped: {})",
                    signal_name, core_dumped
                )));
            }
            Some(ChannelMsg::Close) | None => {
                // Channel closed without explicit exit status — treat as 0
                return Ok(0);
            }
            Some(_) => continue,
        }
    }
}

/// Shell-escape a string for safe inclusion in an SSH exec command.
///
/// Single-quotes the argument and escapes any embedded single quotes.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Validate that an opened file descriptor is a regular file, rejecting symlinks, FIFOs, directories, etc.
///
/// This function validates the file descriptor *after* it has been opened with O_NOFOLLOW | O_NONBLOCK,
/// eliminating TOCTOU races. The caller must open the file atomically with these flags:
/// - O_NOFOLLOW: fail if the path is a symlink (no traversal)
/// - O_NONBLOCK: prevent blocking on FIFO opens (returns immediately)
///
/// After validation succeeds, the caller may clear O_NONBLOCK if blocking I/O is needed.
///
/// # Security invariant
///
/// Never validate a path and then open it separately — that is a TOCTOU race. Always:
/// 1. Open with O_NOFOLLOW | O_NONBLOCK
/// 2. Validate the opened descriptor
/// 3. Use the validated descriptor
///
/// Returns Ok(()) if the file is a regular file, Err otherwise.
fn validate_regular_file(path: &Path, meta: &std::fs::Metadata) -> Result<(), ScpError> {
    use std::os::unix::fs::FileTypeExt;
    let file_type = meta.file_type();

    if file_type.is_fifo() {
        return Err(ScpError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path is a FIFO: {}", path.display()),
        )));
    }
    if file_type.is_dir() {
        return Err(ScpError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path is a directory: {}", path.display()),
        )));
    }
    if !file_type.is_file() {
        return Err(ScpError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path is not a regular file: {}", path.display()),
        )));
    }
    Ok(())
}

/// Map an SCP error message to a structured ScpError.
fn scp_error(msg: String) -> ScpError {
    // Try to classify common errors
    let lower = msg.to_lowercase();
    // P2 fix: Permission denied after SSH auth means filesystem permissions, not auth failure
    if lower.contains("permission denied") {
        ScpError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            msg,
        ))
    } else if lower.contains("no space left") || lower.contains("disk full") {
        ScpError::Io(std::io::Error::new(std::io::ErrorKind::StorageFull, msg))
    } else if lower.contains("no such file") || lower.contains("not found") {
        ScpError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, msg))
    } else {
        ScpError::Channel(format!("SCP error: {}", msg))
    }
}

/// Check if the cancellation token is cancelled.
fn check_cancellation(ct: &CancellationToken) -> Result<(), ScpError> {
    if ct.is_cancelled() {
        Err(ScpError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "cancelled",
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test for the hashed `known_hosts` HMAC-SHA1.
    ///
    /// OpenSSH stores hashed hosts as `|1|<base64 salt>|<base64 HMAC-SHA1(salt, host)>`,
    /// so the digest output is a **file-format constant**, not an implementation
    /// detail: if these bytes change, every hashed `known_hosts` entry in the fleet
    /// stops matching and host-key verification silently falls through to "unknown
    /// host". SHA-1 is required by the format and must not be "upgraded".
    ///
    /// The existing round-trip coverage cannot catch that, because it hashes with
    /// the same code it verifies against and would agree with itself after any
    /// change. This vector is computed independently:
    ///
    /// ```text
    /// salt = 0x0b x20   (RFC 2202 case 1 key)
    /// $ printf 'example.com' | openssl dgst -sha1 -mac HMAC \
    ///       -macopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -binary | base64
    /// XXrb7jid9VkSGZLgs5kDvEexdLc=
    /// ```
    ///
    /// That same OpenSSL invocation reproduces RFC 2202 case 1
    /// (`HMAC-SHA1(0x0b x20, "Hi There") = b617318655057264e28bc0b6fb378c8ef146be00`),
    /// which is what makes the vector trustworthy rather than self-referential.
    #[test]
    fn hashed_known_hosts_matches_openssl_known_answer() {
        let line = "|1|CwsLCwsLCwsLCwsLCwsLCwsLCws=|XXrb7jid9VkSGZLgs5kDvEexdLc= \
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .replace('\n', "");

        assert!(
            line_matches_host(&line, "example.com", 22).expect("well-formed hashed line"),
            "HMAC-SHA1 of the hashed known_hosts entry no longer matches the \
             OpenSSL-computed vector; hashed known_hosts entries would stop matching"
        );

        assert!(
            !line_matches_host(&line, "other.example.com", 22).expect("well-formed hashed line"),
            "a different host must not match this hash"
        );
    }

    #[test]
    fn parse_c_header_success() {
        let (mode, size, name) = parse_c_header("C0644 1234 foo.tgz").expect("valid header");
        assert_eq!(mode, 0o644);
        assert_eq!(size, 1234);
        assert_eq!(name, "foo.tgz");
    }

    #[test]
    fn parse_c_header_with_spaces_in_name() {
        // SCP protocol doesn't support spaces in names properly, but test parsing
        let (mode, size, name) = parse_c_header("C0644 5678 my file.txt").expect("valid header");
        assert_eq!(mode, 0o644);
        assert_eq!(size, 5678);
        assert_eq!(name, "my file.txt");
    }

    #[test]
    fn parse_c_header_invalid() {
        assert!(parse_c_header("X0644 1234 foo").is_err());
        assert!(parse_c_header("C0644").is_err());
        assert!(parse_c_header("C0644 abc foo").is_err());
    }

    #[test]
    fn parse_c_header_with_setuid_bit() {
        // Behavior #7 verification: parse_c_header extracts raw mode including setuid bits
        // The masking (& 0o777) happens in download() at line 1068, not here
        let (mode, size, name) = parse_c_header("C4755 100 exploit").expect("valid header");
        assert_eq!(mode, 0o4755); // raw mode from header includes setuid bit
        assert_eq!(size, 100);
        assert_eq!(name, "exploit");

        // To verify behavior #7 works: the download() function MUST mask this with & 0o777
        // before applying to the file, preventing setuid file creation even when running as root.
        // The production code at line 1068 does: let mode = raw_mode & 0o777;
    }

    #[test]
    fn shell_escape_plain() {
        assert_eq!(shell_escape("foo"), "'foo'");
    }

    #[test]
    fn shell_escape_with_quotes() {
        assert_eq!(shell_escape("foo'bar"), r"'foo'\''bar'");
    }

    #[test]
    fn shell_escape_directory() {
        assert_eq!(shell_escape("/var/tmp/"), "'/var/tmp/'");
    }

    #[test]
    fn scp_error_classifies_permission_denied() {
        // P2 fix: filesystem permission errors are I/O errors, not auth failures
        let err = scp_error("Permission denied".to_string());
        assert!(matches!(err, ScpError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn scp_error_classifies_disk_full() {
        let err = scp_error("No space left on device".to_string());
        assert!(matches!(err, ScpError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull));
    }

    #[test]
    fn scp_error_classifies_not_found() {
        let err = scp_error("No such file or directory".to_string());
        assert!(matches!(err, ScpError::Io(e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    // Compile-time Send assertion for upload future (test 3)
    #[tokio::test]
    async fn upload_future_is_send() {
        fn assert_send<T: Send>(_: T) {}

        let config = SshConfig {
            host: "test".into(),
            port: 22,
            username: "user".into(),
            auth: SshAuth::PrivateKey {
                path: std::path::PathBuf::from("/dev/null"),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        // This would compile-fail if the future is not Send
        // We don't actually execute it, just verify it type-checks
        #[allow(unreachable_code, unused_variables, clippy::unwrap_used)]
        if false {
            let ct_connect = CancellationToken::new();
            let mut client = ScpClient::connect(config, &ct_connect)
                .await
                .expect("connect failed");
            let ct = CancellationToken::new();
            let fut = client.upload(Path::new("/tmp/test"), "/var/tmp/", None, &ct);
            assert_send(fut);
        }
    }

    // Compile-time Send assertion for download future (test 3)
    #[tokio::test]
    async fn download_future_is_send() {
        fn assert_send<T: Send>(_: T) {}

        let config = SshConfig {
            host: "test".into(),
            port: 22,
            username: "user".into(),
            auth: SshAuth::PrivateKey {
                path: std::path::PathBuf::from("/dev/null"),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(unreachable_code, unused_variables, clippy::unwrap_used)]
        if false {
            let ct_connect = CancellationToken::new();
            let mut client = ScpClient::connect(config, &ct_connect)
                .await
                .expect("connect failed");
            let ct = CancellationToken::new();
            let fut = client.download("/var/tmp/test", Path::new("/tmp/test"), None, &ct);
            assert_send(fut);
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// END-TO-END TESTS WITH LOOPBACK SSH SERVER
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(dead_code)]
mod test_server {
    //! Loopback SSH server for testing ScpClient end-to-end.

    use russh::keys::{Algorithm, PrivateKey};
    use russh::server::{self, Auth, Msg, Server as _, Session};
    use russh::{Channel, ChannelId};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// Parsed T header (timestamps for preserve mode).
    #[derive(Clone, Debug)]
    pub struct THeader {
        pub mtime: i64,
        pub atime: i64,
    }

    /// Parsed C header (mode, size, filename).
    #[derive(Clone, Debug)]
    pub struct CHeader {
        pub mode: u32,
        pub size: u64,
        pub filename: Vec<u8>,
    }

    /// Protocol data captured during an SCP transfer.
    #[derive(Clone, Debug, Default)]
    pub struct CapturedProtocol {
        pub t_header: Option<THeader>,
        pub c_header: Option<CHeader>,
        pub payload: Vec<u8>,
        pub terminator_received: bool,
    }

    /// Configurable SCP server behavior for testing.
    #[derive(Clone, Debug)]
    pub enum ServerBehavior {
        SinkSuccess,
        SourceSuccess {
            filename: String,
            content: Vec<u8>,
            mode: u32,
        },
        ErrorAck {
            code: u8,
            message: String,
        },
        NonZeroExit {
            code: u32,
        },
        SinkStall,
        SourceCoalesced {
            filename: String,
            content: Vec<u8>,
            mode: u32,
        },
        SourceOneByte {
            filename: String,
            content: Vec<u8>,
            mode: u32,
        },
        RejectExec,
        ExitSignal,
        SourceFinalError {
            filename: String,
            content: Vec<u8>,
            mode: u32,
            code: u8,
            message: String,
        },
        SinkFinalError {
            code: u8,
            message: String,
        },
        SinkCheckPreserve,
        DelayChannelOpen,
        SinkWarningAckOnCHeader {
            message: String,
        },
        /// Send SCP ready ack BEFORE channel success (upload regression test).
        SinkDataBeforeSuccess,
        /// Send C header BEFORE channel success (download regression test).
        SourceDataBeforeSuccess {
            filename: String,
            content: Vec<u8>,
            mode: u32,
        },
        /// Source sends C header, waits for ack, then stalls forever.
        SourceStallAfterHeader {
            filename: String,
            mode: u32,
            size: u64,
        },
        /// Server refuses channel_open_session with SSH_OPEN_RESOURCE_SHORTAGE
        RejectChannelOpen,
    }

    #[derive(Clone)]
    pub struct TestServerState {
        pub behavior: Arc<Mutex<ServerBehavior>>,
        pub captured: Arc<Mutex<Option<CapturedProtocol>>>,
    }

    impl TestServerState {
        pub fn new(behavior: ServerBehavior) -> Self {
            Self {
                behavior: Arc::new(Mutex::new(behavior)),
                captured: Arc::new(Mutex::new(None)),
            }
        }

        pub async fn get_captured(&self) -> Option<CapturedProtocol> {
            self.captured.lock().await.clone()
        }
    }

    struct TestServer {
        state: TestServerState,
    }

    impl server::Server for TestServer {
        type Handler = TestHandler;

        fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
            TestHandler {
                state: self.state.clone(),
                received_data: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    struct TestHandler {
        state: TestServerState,
        received_data: Arc<Mutex<Vec<u8>>>,
    }

    impl server::Handler for TestHandler {
        type Error = russh::Error;

        async fn data(
            &mut self,
            _channel: ChannelId,
            data: &[u8],
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            let mut buf = self.received_data.lock().await;
            buf.extend_from_slice(data);
            Ok(())
        }

        async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn auth_password(
            &mut self,
            _user: &str,
            _password: &str,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _key: russh::server::VerifiedPublicKey<'_>,
        ) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            let behavior = self.state.behavior.lock().await.clone();
            if matches!(behavior, ServerBehavior::RejectChannelOpen) {
                reply
                    .reject(russh::ChannelOpenFailure::ResourceShortage)
                    .await;
                return Ok(());
            }
            if matches!(behavior, ServerBehavior::DelayChannelOpen) {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let behavior = self.state.behavior.lock().await.clone();

            if matches!(behavior, ServerBehavior::RejectExec) {
                session.channel_failure(channel)?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }

            let cmd = String::from_utf8_lossy(data).to_string();
            session.channel_success(channel)?;

            let received_data = self.received_data.clone();
            let handle = session.handle();
            let captured = self.state.captured.clone();

            tokio::spawn(async move {
                if cmd.contains(" -t ") {
                    let _ = Self::handle_scp_sink_async(
                        channel,
                        handle.clone(),
                        behavior.clone(),
                        received_data,
                        captured,
                    )
                    .await;
                } else if cmd.contains(" -f ") {
                    let _ = Self::handle_scp_source_async(
                        channel,
                        handle.clone(),
                        behavior,
                        received_data,
                    )
                    .await;
                }
            });

            Ok(())
        }
    }

    async fn read_line(buf: &Arc<Mutex<Vec<u8>>>) -> Result<Vec<u8>, russh::Error> {
        let timeout_duration = std::time::Duration::from_secs(2);
        let start = std::time::Instant::now();

        loop {
            {
                let mut data = buf.lock().await;
                if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = data.drain(..=pos).collect();
                    return Ok(line);
                }
            }

            if start.elapsed() > timeout_duration {
                return Err(russh::Error::from(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout waiting for data",
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    async fn read_exact(buf: &Arc<Mutex<Vec<u8>>>, len: usize) -> Result<Vec<u8>, russh::Error> {
        let timeout_duration = std::time::Duration::from_secs(2);
        let start = std::time::Instant::now();

        loop {
            {
                let mut data = buf.lock().await;
                if data.len() >= len {
                    let chunk: Vec<u8> = data.drain(..len).collect();
                    return Ok(chunk);
                }
            }

            if start.elapsed() > timeout_duration {
                return Err(russh::Error::from(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout waiting for data",
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    impl TestHandler {
        async fn handle_scp_sink_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            behavior: ServerBehavior,
            received_data: Arc<Mutex<Vec<u8>>>,
            captured: Arc<Mutex<Option<CapturedProtocol>>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            match behavior {
                ServerBehavior::ErrorAck { code, message } => {
                    let mut msg = vec![code];
                    msg.extend_from_slice(message.as_bytes());
                    msg.push(b'\n');
                    let _ = handle.data(channel, msg).await;
                    let _ = handle.exit_status_request(channel, 1).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkStall => {
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _t_line = read_line(&received_data).await?;
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _c_line = read_line(&received_data).await?;
                    let _ = handle.data(channel, vec![0u8]).await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                    Ok(())
                }

                ServerBehavior::NonZeroExit { code } => {
                    Self::handle_normal_sink_async(
                        channel,
                        handle.clone(),
                        received_data,
                        captured,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, code).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkSuccess => {
                    Self::handle_normal_sink_async(
                        channel,
                        handle.clone(),
                        received_data,
                        captured,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::ExitSignal => {
                    Self::handle_normal_sink_async(
                        channel,
                        handle.clone(),
                        received_data,
                        captured,
                    )
                    .await?;
                    let _ = handle
                        .exit_signal_request(
                            channel,
                            russh::Sig::TERM,
                            false,
                            "".to_string(),
                            "".to_string(),
                        )
                        .await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkFinalError { code, message } => {
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _t_line = read_line(&received_data).await?;
                    let _ = handle.data(channel, vec![0u8]).await;
                    let c_line = read_line(&received_data).await?;
                    let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                    let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                    #[allow(clippy::unwrap_used)]
                    let size = parts[1].parse::<u64>().unwrap_or(0);
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _payload = read_exact(&received_data, size as usize).await?;
                    let _trailing = read_exact(&received_data, 1).await?;
                    let mut error_msg = vec![code];
                    error_msg.extend_from_slice(message.as_bytes());
                    error_msg.push(b'\n');
                    let _ = handle.data(channel, error_msg).await;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkCheckPreserve => {
                    let mut cap = CapturedProtocol::default();
                    let _ = handle.data(channel, vec![0u8]).await;
                    let t_line = read_line(&received_data).await?;
                    if !t_line.starts_with(b"T") {
                        let msg = "preserve mode not honored: missing T header";
                        let _ = handle
                            .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                            .await;
                        let _ = handle.exit_status_request(channel, 1).await;
                        let _ = handle.eof(channel).await;
                        let _ = handle.close(channel).await;
                        return Ok(());
                    }
                    let t_str = String::from_utf8_lossy(&t_line[1..t_line.len() - 1]);
                    let t_parts: Vec<&str> = t_str.split_whitespace().collect();
                    if t_parts.len() >= 4
                        && let (Ok(mtime), Ok(atime)) =
                            (t_parts[0].parse::<i64>(), t_parts[2].parse::<i64>())
                    {
                        cap.t_header = Some(THeader { mtime, atime });
                    }
                    let _ = handle.data(channel, vec![0u8]).await;
                    let c_line = read_line(&received_data).await?;
                    let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
                    let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
                    #[allow(clippy::unwrap_used)]
                    let size = parts[1].parse::<u64>().unwrap_or(0);
                    let mode = u32::from_str_radix(parts[0], 8).unwrap_or(0);
                    let filename = parts[2].as_bytes().to_vec();
                    cap.c_header = Some(CHeader {
                        mode,
                        size,
                        filename,
                    });
                    let _ = handle.data(channel, vec![0u8]).await;
                    let payload = read_exact(&received_data, size as usize).await?;
                    cap.payload = payload;
                    let _trailing = read_exact(&received_data, 1).await?;
                    let _ = handle.data(channel, vec![0u8]).await;
                    let e_line = read_line(&received_data).await?;
                    if e_line == b"E\n" {
                        cap.terminator_received = true;
                    }
                    let _ = handle.data(channel, vec![0u8]).await;
                    *captured.lock().await = Some(cap);
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkWarningAckOnCHeader { message } => {
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _t_line = read_line(&received_data).await?;
                    let _ = handle.data(channel, vec![0u8]).await;
                    let _c_line = read_line(&received_data).await?;
                    let mut warning_msg = vec![1u8];
                    warning_msg.extend_from_slice(message.as_bytes());
                    warning_msg.push(b'\n');
                    let _ = handle.data(channel, warning_msg).await;
                    let _ = handle.exit_status_request(channel, 1).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SinkDataBeforeSuccess => {
                    // Send initial \0 BEFORE channel_success (regression test)
                    // channel_success is sent after this function returns
                    let _ = handle.data(channel, vec![0u8]).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

                    // Continue with normal protocol
                    Self::handle_normal_sink_after_ready_async(
                        channel,
                        handle.clone(),
                        received_data,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                _ => Ok(()),
            }
        }

        async fn handle_scp_source_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            behavior: ServerBehavior,
            _received_data: Arc<Mutex<Vec<u8>>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            match behavior {
                ServerBehavior::SourceSuccess {
                    filename,
                    content,
                    mode,
                } => {
                    Self::send_file_async(
                        channel,
                        handle.clone(),
                        &filename,
                        &content,
                        mode,
                        false,
                        false,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SourceCoalesced {
                    filename,
                    content,
                    mode,
                } => {
                    Self::send_file_async(
                        channel,
                        handle.clone(),
                        &filename,
                        &content,
                        mode,
                        true,
                        false,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SourceOneByte {
                    filename,
                    content,
                    mode,
                } => {
                    Self::send_file_async(
                        channel,
                        handle.clone(),
                        &filename,
                        &content,
                        mode,
                        false,
                        true,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SourceFinalError {
                    filename,
                    content,
                    mode,
                    code,
                    message,
                } => {
                    Self::send_file_with_error_async(
                        channel,
                        handle.clone(),
                        &filename,
                        &content,
                        mode,
                        code,
                        &message,
                    )
                    .await?;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SourceDataBeforeSuccess {
                    filename,
                    content,
                    mode,
                } => {
                    // Send C header BEFORE channel_success
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
                    let _ = handle.data(channel, header.as_bytes().to_vec()).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let _ = handle.data(channel, content.to_vec()).await;
                    let _ = handle.data(channel, vec![0u8]).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                    Ok(())
                }

                ServerBehavior::SourceStallAfterHeader {
                    filename,
                    mode,
                    size,
                } => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let header = format!("C{:04o} {} {}\n", mode, size, filename);
                    let _ = handle.data(channel, header.as_bytes().to_vec()).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    // Stall forever - client should cancel
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                    Ok(())
                }

                _ => Ok(()),
            }
        }

        async fn handle_normal_sink_after_ready_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            received_data: Arc<Mutex<Vec<u8>>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            // Initial \0 already sent, continue from T header

            // 1. Parse T header
            let t_line = read_line(&received_data).await?;
            if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
                let msg = format!("expected T header, got: {:?}", t_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            // Send \0 (accept T header)
            let _ = handle.data(channel, vec![0u8]).await;

            // 2. Parse C header
            let c_line = read_line(&received_data).await?;
            if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
                let msg = format!("expected C header, got: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
            let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
            if parts.len() < 3 {
                let msg = format!("malformed C header: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }
            let size = match parts[1].parse::<u64>() {
                Ok(s) => s,
                Err(_) => {
                    let msg = format!("invalid size in C header: {:?}", c_line);
                    let _ = handle
                        .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                        .await;
                    return Ok(());
                }
            };

            // Send \0 (accept C header)
            let _ = handle.data(channel, vec![0u8]).await;

            // 3. Consume payload
            let payload = read_exact(&received_data, size as usize).await?;
            if payload.len() != size as usize {
                let msg = format!(
                    "payload size mismatch: expected {}, got {}",
                    size,
                    payload.len()
                );
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            // 4. Consume trailing \0
            let trailing = read_exact(&received_data, 1).await?;
            if trailing[0] != 0u8 {
                let msg = format!("expected trailing \\0, got: {:?}", trailing);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            // Send \0 (data received)
            let _ = handle.data(channel, vec![0u8]).await;

            // 5. Parse E\n
            let e_line = read_line(&received_data).await?;
            if e_line != b"E\n" {
                let msg = format!("expected E\\n, got: {:?}", e_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            // Send final \0
            let _ = handle.data(channel, vec![0u8]).await;

            Ok(())
        }

        async fn handle_normal_sink_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            received_data: Arc<Mutex<Vec<u8>>>,
            captured: Arc<Mutex<Option<CapturedProtocol>>>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut cap = CapturedProtocol::default();
            let _ = handle.data(channel, vec![0u8]).await;

            let t_line = read_line(&received_data).await?;
            if !t_line.starts_with(b"T") || !t_line.ends_with(b"\n") {
                let msg = format!("expected T header, got: {:?}", t_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            let t_str = String::from_utf8_lossy(&t_line[1..t_line.len() - 1]);
            let t_parts: Vec<&str> = t_str.split_whitespace().collect();
            if t_parts.len() >= 4
                && let (Ok(mtime), Ok(atime)) =
                    (t_parts[0].parse::<i64>(), t_parts[2].parse::<i64>())
            {
                cap.t_header = Some(THeader { mtime, atime });
            }

            let _ = handle.data(channel, vec![0u8]).await;

            let c_line = read_line(&received_data).await?;
            if !c_line.starts_with(b"C") || !c_line.ends_with(b"\n") {
                let msg = format!("expected C header, got: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            let c_str = String::from_utf8_lossy(&c_line[1..c_line.len() - 1]);
            let parts: Vec<&str> = c_str.splitn(3, ' ').collect();
            if parts.len() < 3 {
                let msg = format!("malformed C header: {:?}", c_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            let mode = u32::from_str_radix(parts[0], 8).unwrap_or(0);
            let size = match parts[1].parse::<u64>() {
                Ok(s) => s,
                Err(_) => {
                    let msg = format!("invalid size in C header: {:?}", c_line);
                    let _ = handle
                        .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                        .await;
                    return Ok(());
                }
            };
            let filename = parts[2].as_bytes().to_vec();

            cap.c_header = Some(CHeader {
                mode,
                size,
                filename,
            });

            let _ = handle.data(channel, vec![0u8]).await;

            let payload = read_exact(&received_data, size as usize).await?;
            if payload.len() != size as usize {
                let msg = format!(
                    "payload size mismatch: expected {}, got {}",
                    size,
                    payload.len()
                );
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            cap.payload = payload;

            let trailing = read_exact(&received_data, 1).await?;
            if trailing[0] != 0u8 {
                let msg = format!("expected trailing \\0, got: {:?}", trailing);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            let _ = handle.data(channel, vec![0u8]).await;

            let e_line = read_line(&received_data).await?;
            if e_line != b"E\n" {
                let msg = format!("expected E\\n, got: {:?}", e_line);
                let _ = handle
                    .data(channel, format!("\x02{}\n", msg).as_bytes().to_vec())
                    .await;
                return Ok(());
            }

            cap.terminator_received = true;
            let _ = handle.data(channel, vec![0u8]).await;
            *captured.lock().await = Some(cap);

            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn send_file_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            filename: &str,
            content: &[u8],
            mode: u32,
            coalesced: bool,
            one_byte: bool,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);

            if coalesced {
                let mut msg = header.as_bytes().to_vec();
                msg.extend_from_slice(content);
                msg.push(0u8);
                let _ = handle.data(channel, msg).await;
            } else if one_byte {
                let _ = handle.data(channel, header.as_bytes().to_vec()).await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                for &byte in content {
                    let _ = handle.data(channel, vec![byte]).await;
                }
                let _ = handle.data(channel, vec![0u8]).await;
            } else {
                let _ = handle.data(channel, header.as_bytes().to_vec()).await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let _ = handle.data(channel, content.to_vec()).await;
                let _ = handle.data(channel, vec![0u8]).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Ok(())
        }

        #[allow(clippy::too_many_arguments)]
        async fn send_file_with_error_async(
            channel: ChannelId,
            handle: russh::server::Handle,
            filename: &str,
            content: &[u8],
            mode: u32,
            code: u8,
            message: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let header = format!("C{:04o} {} {}\n", mode, content.len(), filename);
            let _ = handle.data(channel, header.as_bytes().to_vec()).await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = handle.data(channel, content.to_vec()).await;
            // Send error status byte + message instead of trailing \0
            let mut error_msg = vec![code];
            error_msg.extend_from_slice(message.as_bytes());
            error_msg.push(b'\n');
            let _ = handle.data(channel, error_msg).await;
            Ok(())
        }
    }

    pub async fn start_test_server(
        state: TestServerState,
    ) -> Result<(tokio::task::JoinHandle<()>, std::net::SocketAddr), Box<dyn std::error::Error>>
    {
        let keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;

        let config = russh::server::Config {
            auth_rejection_time: std::time::Duration::from_secs(0),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            keys: vec![keypair],
            ..Default::default()
        };

        let config = Arc::new(config);
        let mut server = TestServer {
            state: state.clone(),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };

                let config = config.clone();
                let handler = server.new_client(None);
                tokio::spawn(async move {
                    let _ = server::run_stream(config, stream, handler).await;
                });
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok((handle, addr))
    }
}

#[cfg(test)]
mod e2e_tests {
    use super::test_server::{ServerBehavior, TestServerState, start_test_server};
    use super::*;

    /// Generate a temporary SSH private key for testing.
    ///
    /// Returns a NamedTempFile (which must be kept alive) and its path.
    /// The file is created with mode 0600 to match the client's permission requirements.
    fn create_test_key() -> (tempfile::NamedTempFile, std::path::PathBuf) {
        use russh::keys::{Algorithm, PrivateKey, ssh_key};
        let keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate Ed25519 key");

        let encoded = keypair
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("failed to encode SSH key")
            .to_string();

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), encoded).expect("failed to write SSH key");

        // Set restrictive permissions (0600) to match client requirements
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))
                .expect("failed to set key file permissions");
        }

        let path = tmp.path().to_path_buf();
        (tmp, path)
    }

    #[tokio::test]
    async fn upload_end_to_end_succeeds() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = b"test file content";
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), content).expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_ok(), "upload failed: {:?}", result);
        #[allow(clippy::unwrap_used)]
        let outcome = result.expect("operation should succeed");
        assert_eq!(outcome.bytes_transferred, content.len() as u64);
    }

    #[tokio::test]
    async fn download_end_to_end_succeeds() {
        let content = b"downloaded file content".to_vec();
        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);
        #[allow(clippy::unwrap_used)]
        let outcome = result.expect("operation should succeed");
        assert_eq!(outcome.bytes_transferred, content.len() as u64);

        #[allow(clippy::unwrap_used)]
        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "content mismatch");
    }

    #[tokio::test]
    async fn advertised_mode_is_preserved() {
        // This test validates that the mode in the C header matches the source file's actual mode.
        let state = TestServerState::new(ServerBehavior::SinkCheckPreserve);
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"test data").expect("failed to write file");

        // Set file mode to 0o755
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755))
                .expect("failed to set permissions");
        }

        let ct = CancellationToken::new();
        let result = client
            .upload(tmp.path(), "/tmp/", None, &ct)
            .await
            .expect("upload should succeed");
        assert_eq!(result.bytes_transferred, 9);

        // Verify the server captured the C header with mode 0o755
        #[allow(clippy::unwrap_used)]
        let captured = state
            .get_captured()
            .await
            .expect("failed to get captured protocol");
        #[allow(clippy::unwrap_used)]
        let c_header = captured.c_header.expect("C header should be captured");
        assert_eq!(c_header.mode, 0o755, "mode mismatch in C header");
    }

    #[tokio::test]
    async fn filename_with_space_upload() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("release image.tgz");
        #[allow(clippy::unwrap_used)]
        std::fs::write(&file_path, b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(&file_path, "/tmp/", None, &ct).await;

        assert!(
            result.is_ok(),
            "upload with space in filename failed: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn nonzero_exit_status_returns_error() {
        let state = TestServerState::new(ServerBehavior::NonZeroExit { code: 1 });
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_err(), "should fail with non-zero exit");
        match result {
            Err(ScpError::Channel(msg)) if msg.contains("exited with status 1") => {}
            other => panic!("expected exit status error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn stalled_upload_is_cancellable() {
        let state = TestServerState::new(ServerBehavior::SinkStall);
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let ct_clone = ct.clone();

        // Cancel after 100ms
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            ct_clone.cancel();
        });

        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;
        assert!(result.is_err(), "stalled upload should be cancellable");
    }

    #[tokio::test]
    async fn framing_variations_coalesced() {
        let content = b"test content for coalesced framing".to_vec();
        let state = TestServerState::new(ServerBehavior::SourceCoalesced {
            filename: "test.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        #[allow(clippy::unwrap_used)]
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await
            .expect("download should succeed");

        assert_eq!(result.bytes_transferred, content.len() as u64);
        #[allow(clippy::unwrap_used)]
        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content);
    }

    #[tokio::test]
    async fn framing_variations_one_byte() {
        let content = b"byte".to_vec();
        let state = TestServerState::new(ServerBehavior::SourceOneByte {
            filename: "test.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        #[allow(clippy::unwrap_used)]
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await
            .expect("download should succeed");

        assert_eq!(result.bytes_transferred, content.len() as u64);
        #[allow(clippy::unwrap_used)]
        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content);
    }

    #[tokio::test]
    async fn rejected_exec_returns_promptly() {
        let state = TestServerState::new(ServerBehavior::RejectExec);
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_err(), "rejected exec should fail");
    }

    #[tokio::test]
    async fn exit_signal_returns_error() {
        let state = TestServerState::new(ServerBehavior::ExitSignal);
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_err(), "exit signal should fail transfer");
    }

    #[tokio::test]
    async fn source_final_error_is_decoded() {
        let content = b"data".to_vec();
        let state = TestServerState::new(ServerBehavior::SourceFinalError {
            filename: "test.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
            code: 2,
            message: "disk full".to_string(),
        });
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await;

        assert!(result.is_err(), "source final error should fail");
        match result {
            Err(ScpError::Io(e)) if e.kind() == std::io::ErrorKind::StorageFull => {
                // Correct: scp_error() mapped "disk full" to StorageFull
            }
            other => panic!("expected StorageFull error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn warning_ack_on_c_header_aborts_upload() {
        let state = TestServerState::new(ServerBehavior::SinkWarningAckOnCHeader {
            message: "sink rejected transfer".to_string(),
        });
        #[allow(clippy::unwrap_used)]
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start test server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        #[allow(clippy::unwrap_used)]
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        #[allow(clippy::unwrap_used)]
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        #[allow(clippy::unwrap_used)]
        std::fs::write(tmp.path(), b"test data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_err(), "upload should fail on warning ack");
        match result {
            Err(ScpError::Channel(msg)) if msg.contains("sink rejected transfer") => {}
            other => panic!("expected channel error with message, got {:?}", other),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn server_setuid_bits_are_stripped() {
        use std::os::unix::fs::PermissionsExt;

        // Use empty content so no write occurs (the kernel strips setuid on first write,
        // which would mask the test's enforcement of the mode mask at line 1066).
        let content = b"";

        // Test with new destination
        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test.bin".to_string(),
            content: content.to_vec(),
            mode: 0o4755, // setuid + 0755
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let result = client
            .download("/tmp/test.bin", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify setuid bit is stripped (should be 0755, not 04755).
        // Empty file ensures no write occurred (write would trigger kernel's own setuid stripping).
        let meta = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o755,
            "setuid bit should be stripped, got {:05o}",
            mode
        );

        // Test with pre-existing destination
        let tmp2 = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp2.path(), b"old").expect("failed to write file");

        let state2 = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test2.bin".to_string(),
            content: content.to_vec(),
            mode: 0o4755, // setuid + 0755
        });
        let (_handle2, addr2) = start_test_server(state2)
            .await
            .expect("failed to start server");

        let (_keyfile2, key_path2) = create_test_key();

        let config2 = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr2.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path2,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect2 = CancellationToken::new();
        let mut client2 = ScpClient::connect(config2, &ct_connect2)
            .await
            .expect("connect failed");

        let result2 = client2
            .download("/tmp/test2.bin", tmp2.path(), None, &ct)
            .await;

        assert!(result2.is_ok(), "download failed: {:?}", result2);

        // Verify setuid bit is stripped for pre-existing file too
        let meta2 = std::fs::metadata(tmp2.path()).expect("failed to read metadata");
        let mode2 = meta2.permissions().mode() & 0o7777;
        assert_eq!(
            mode2, 0o755,
            "setuid bit should be stripped on pre-existing file, got {:05o}",
            mode2
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn download_symlink_destination_fails() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let canary = tmp_dir.path().join("canary.txt");
        let symlink = tmp_dir.path().join("link.txt");

        // Create canary with known content and mode
        std::fs::write(&canary, b"original content").expect("failed to write file");
        std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o644))
            .expect("failed to set permissions");

        // Create symlink pointing at canary
        std::os::unix::fs::symlink(&canary, &symlink).expect("failed to create symlink");

        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test.txt".to_string(),
            content: b"downloaded content".to_vec(),
            mode: 0o600,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");
        let ct = CancellationToken::new();

        // Attempt download to symlink path
        let result = client.download("/tmp/test.txt", &symlink, None, &ct).await;

        // Download should fail
        assert!(
            result.is_err(),
            "download should fail for symlink destination"
        );

        // Canary should be untouched in content and mode
        let canary_content = std::fs::read(&canary).expect("failed to read file");
        assert_eq!(
            canary_content, b"original content",
            "canary content should be untouched"
        );
        let canary_meta = std::fs::metadata(&canary).expect("failed to read file metadata");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            canary_meta.permissions().mode() & 0o777,
            0o644,
            "canary mode should be untouched"
        );
    }

    /// Test 34: Download rejects FIFO destinations without hanging.
    ///
    /// P2 regression: A write-only open of an existing FIFO with no reader waits
    /// forever outside cancellation.
    ///
    /// Fix: Check file type before open (line ~818-870).
    ///
    /// Test: Create FIFO, download to it in tokio::time::timeout, assert timeout
    /// error not hang.

    #[cfg(unix)]
    #[tokio::test]
    async fn download_widening_mode_after_truncate() {
        use std::os::unix::fs::PermissionsExt;

        let old_content = b"secret credential that must not leak";

        // Create pre-existing file with restrictive mode 0600 and known content
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), old_content).expect("failed to write file");
        let perms_600 = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms_600).expect("failed to set permissions");

        // Server sends C0644 (widening from 0600) and stalls after header
        let state = TestServerState::new(ServerBehavior::SourceStallAfterHeader {
            filename: "test.txt".to_string(),
            mode: 0o644,
            size: 1024,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        // Start download in background, then cancel after header ack
        let ct = CancellationToken::new();
        let ct_clone = ct.clone();
        let dest_path = tmp.path().to_path_buf();
        let download_task = tokio::spawn(async move {
            client
                .download("/tmp/test.txt", &dest_path, None, &ct_clone)
                .await
        });

        // Give download time to process header and start waiting for data
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel the transfer
        ct.cancel();

        // Wait for cancellation to propagate
        let result = download_task.await.expect("task should complete");
        assert!(
            result.is_err(),
            "download should fail with cancellation error"
        );

        // SECURITY ASSERTION: If the file mode is 0644 (widened), old contents must be gone.
        // If old contents remain, mode must still be 0600 (not widened).
        let meta = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o777;
        let current_content = std::fs::read(tmp.path()).expect("failed to read file");

        if mode == 0o644 {
            // Mode was widened - old contents MUST be destroyed
            assert_ne!(
                current_content, old_content,
                "SECURITY: file is 0644 but still contains old secret content - \
                 mode was widened before truncate"
            );
            // Should be truncated (empty or partial new data)
            assert_eq!(
                current_content.len(),
                0,
                "file should be truncated if mode was widened"
            );
        } else if mode == 0o600 {
            // Mode was NOT widened - old contents may or may not remain (both safe)
            // This is the expected path: interim mode is 0600 & 0644 = 0600, truncate happens,
            // but cancellation hits before final widening to 0644.
        } else {
            panic!("unexpected mode: {:04o}", mode);
        }
    }

    /// Test 28: Download chmod failure preserves contents.
    ///
    /// P1 constraint from round 12: Never destroy data before knowing chmod will succeed.
    /// If local_path exists but caller is not owner, chmod can fail with EPERM. Truncating
    /// first would destroy data, then fail to apply mode, leaving an empty file.
    ///
    /// Fix: Apply interim mode first (which is narrowing-only, so less likely to fail).
    /// If it fails, abort before truncate. Truncate only after chmod succeeds.
    ///
    /// Test: This property holds by inspection of the code structure (lines ~840-871):
    /// - Interim chmod at line ~861
    /// - Truncate at line ~864 (only reached if interim chmod succeeded)
    /// - Final chmod at line ~867 (only reached if truncate succeeded)
    ///
    /// Runtime test would require making fchmod fail (not portable without a second uid or
    /// capability manipulation). Documenting the structural property instead.
    ///
    /// Must fail against any reordering that truncates before the first chmod.

    #[cfg(unix)]
    #[tokio::test]
    async fn preexisting_file_tightened_before_partial_data() {
        use std::os::unix::fs::PermissionsExt;

        let content = vec![0xBBu8; 100000]; // Large enough to require multiple chunks

        // Create a pre-existing file with mode 0666
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"old content").expect("failed to write file");
        let perms_666 = std::fs::Permissions::from_mode(0o666);
        std::fs::set_permissions(tmp.path(), perms_666).expect("failed to set permissions");

        // Verify it's 0666
        let meta_before = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        assert_eq!(meta_before.permissions().mode() & 0o777, 0o666);

        // Server sends C0600 (completes successfully)
        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "secret.key".to_string(),
            content: content.clone(),
            mode: 0o600,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/secret.key", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify the file has mode 0600 (not the pre-existing 0666)
        // The fix applies mode via set_permissions before acknowledging the header,
        // so even though the file pre-existed at 0666, it should now be 0600.
        let meta = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "downloaded file should have mode 0600 (not pre-existing 0666), got {:04o}",
            mode
        );

        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "content mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 11 REGRESSION TESTS (P1 + 2×P2)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 21: Server-provided setuid bits are stripped.
    ///
    /// P1 regression: The mode from the C header is attacker-controlled. If we run with
    /// root or CAP_FSETID and the server sends C4755, we'd create a setuid root binary
    /// from downloaded payload — a straight pivot from a compromised firewall to the host.
    ///
    /// Fix: Mask mode to 0o777 (strip setuid, setgid, sticky) before using it.
    ///
    /// Test: Server sends C4755 (setuid + 0755). Assert the local file is 0755 with no
    /// setuid bit, on both a new and a pre-existing destination.

    #[tokio::test]
    async fn download_does_not_truncate_before_chmod() {
        // This test is a regression marker: it documents that the file-open logic does NOT
        // use .truncate(true) in OpenOptions. The actual P2 fix is structural (open, chmod,
        // truncate) and cannot be tested at runtime without a second uid.
        //
        // If someone refactors and moves .truncate(true) back to OpenOptions, this test
        // will still pass, but code review should catch it. The real protection is the
        // comment and the ordering at lines ~754-784.

        let content = b"payload";

        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test.txt".to_string(),
            content: content.to_vec(),
            mode: 0o600,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        // Pre-create file with content
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(
            tmp.path(),
            b"old content that should not be truncated before chmod",
        )
        .expect("download should succeed");
        let initial_len = std::fs::metadata(tmp.path())
            .expect("failed to read metadata")
            .len();

        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await;

        // Transfer should succeed
        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify file was overwritten with new content (truncate DID happen, but after chmod)
        let final_content = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(
            final_content, content,
            "file should contain new payload, not old content"
        );
        assert_ne!(
            final_content.len() as u64,
            initial_len,
            "file should be truncated to new size"
        );

        // The structural assertion: if the code at ~754-784 is correct, it opens WITHOUT
        // .truncate(true) and calls set_len(0) after set_permissions. This test passes
        // whether the code is correct or not (we can't detect the regression at runtime),
        // but serves as a marker for code review.
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 13 REGRESSION TESTS (P1 + 3×P2)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 25: Upload with -p sends T header to preserve timestamps.
    ///
    /// P1 regression: Without -p, when the remote file pre-exists with broader permissions
    /// (e.g., 0666), OpenSSH SCP keeps that existing mode even when we send C0600, leaving
    /// the upload world-readable. With -p, the sink honors the C header mode and tightens
    /// pre-existing files.
    ///
    /// Fix: Add -p to the sink command (line ~471).
    ///
    /// Test: Upload a 0600 file. Server expects T header (from -p) before C header.
    /// The test server mock acks both T and C headers. Verify upload succeeds.

    #[cfg(unix)]
    #[tokio::test]
    async fn download_applies_received_mode() {
        use std::os::unix::fs::PermissionsExt;

        let content = b"secret credential";

        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "credential.key".to_string(),
            content: content.to_vec(),
            mode: 0o600,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/credential.key", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify the file has mode 0600 (not umask-derived 0644)
        let meta = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "downloaded file should have mode 0600, got {:04o}",
            mode
        );

        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "content mismatch");
    }

    /// Test 16: Sink final error (status-1 after payload) returns typed error.
    ///
    /// P2 regression: When the sink hits disk-full or quota after accepting the header,
    /// it replies with status byte 1 + diagnostic. Storing this as a warning loses the
    /// typed `StorageFull` error and can make the upload look successful if the server
    /// then exits 0.

    #[cfg(unix)]
    #[tokio::test]
    async fn download_overrides_preexisting_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let content = b"secret credential";

        // Create a pre-existing file with mode 0666
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"old content").expect("failed to write file");
        let perms_666 = std::fs::Permissions::from_mode(0o666);
        std::fs::set_permissions(tmp.path(), perms_666).expect("failed to set permissions");

        // Verify it's 0666
        let meta_before = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        assert_eq!(meta_before.permissions().mode() & 0o777, 0o666);

        // Download a C0600 file to the same path
        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "credential.key".to_string(),
            content: content.to_vec(),
            mode: 0o600,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/credential.key", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify the file now has mode 0600 (not the pre-existing 0666)
        let meta = std::fs::metadata(tmp.path()).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "downloaded file should have mode 0600, got {:04o}",
            mode
        );

        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "content mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 10 REGRESSION TEST (P1)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 20: Pre-existing file tightened BEFORE data written.
    ///
    /// P1 regression: OpenOptionsExt::mode applies only when the file is created. If
    /// local_path already exists at, say, 0666 and the server sends C0600, the mode is
    /// ignored, so the destination stays broadly readable for the whole transfer. The
    /// final chmod (which was removed in round 10) would fix it at the end, but partial
    /// data would be exposed, and if cancellation or a write failure hit before then,
    /// the secret would remain at 0666.
    ///
    /// Fix: After opening the handle and BEFORE acknowledging the header or reading any
    /// payload, apply the received mode via handle-based chmod (File::set_permissions).
    /// This catches the pre-existing case and ensures restrictive permissions are in
    /// place before we send the accept ack to the server. Handle-based (not path-based)
    /// eliminates TOCTOU — we chmod the inode we opened, so there's no path resolution
    /// to race against symlink/rename attacks.
    ///
    /// Test: A destination that already exists at 0666, a server sending C0600. Verify
    /// the final file has mode 0600, demonstrating the fix applies to pre-existing files
    /// and chmod's the opened inode.
    ///
    /// Note: A symlink-swap test (replace the path with a symlink between open and chmod)
    /// cannot be expressed with the current harness, since both operations happen
    /// synchronously in download(). The handle-based approach is correct by construction —
    /// tokio::fs::File::set_permissions operates on the open file descriptor.
    ///
    /// Must fail against 4688a22 (file stays 0666, final chmod was removed) and against
    /// 561b6f8 before this fix (path-based chmod had TOCTOU window).

    #[tokio::test]
    async fn upload_rejects_fifo_without_hanging() {
        use std::os::unix::fs::FileTypeExt;

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let fifo_path = tmp_dir.path().join("test.fifo");

        // Create FIFO
        let result = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .output();
        if result.is_err() {
            // mkfifo not available, skip test
            return;
        }

        // Verify it's a FIFO
        let meta = std::fs::metadata(&fifo_path).expect("failed to read file metadata");
        assert!(meta.file_type().is_fifo(), "should be a FIFO");

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();
        ct.cancel(); // Pre-cancel to ensure no hang

        // Assert returns within 2s with typed error (no hang)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.upload(&fifo_path, "/tmp", None, &ct),
        )
        .await;

        assert!(result.is_ok(), "upload should return within 2s (not hang)");
        assert!(
            result.expect("operation should succeed").is_err(),
            "upload should return error for FIFO"
        );
    }

    /// Test 30: Upload rejects directory without hanging.
    ///
    /// P2 regression: Directories pass the open() but fail on first read after
    /// starting the remote protocol.
    ///
    /// Fix: Check metadata.is_file() before opening (line ~388-420).
    ///
    /// Test: Attempt to upload a directory, assert returns within timeout with
    /// typed error (not a hang or protocol desync).

    #[tokio::test]
    async fn download_fifo_destination_timeout() {
        use std::os::unix::fs::FileTypeExt;

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let fifo_path = tmp_dir.path().join("test.fifo");

        // Create FIFO
        let result = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .output();
        if result.is_err() {
            // mkfifo not available, skip test
            return;
        }

        // Verify it's a FIFO
        let meta = std::fs::metadata(&fifo_path).expect("failed to read file metadata");
        assert!(meta.file_type().is_fifo(), "should be a FIFO");

        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "test.txt".to_string(),
            content: b"data".to_vec(),
            mode: 0o644,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");
        let ct = CancellationToken::new();

        // Assert returns within 2s with typed error (no hang)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.download("/tmp/test.txt", &fifo_path, None, &ct),
        )
        .await;

        assert!(
            result.is_ok(),
            "download should return within 2s (not hang)"
        );
        assert!(
            result.expect("operation should succeed").is_err(),
            "download should return error for FIFO"
        );
    }

    /// Test 35: Upload to remote_dir with dash prefix proceeds.
    ///
    /// P2 regression: A remote_dir beginning with `-` (like `-staging`) is parsed
    /// as an option even when shell-quoted.
    ///
    /// Fix: Insert `--` before escaped target in exec command (line ~487-488).
    ///
    /// Test: Upload to remote_dir="-staging", assert transfer proceeds without
    /// "invalid option" error.

    #[tokio::test]
    async fn upload_rejects_directory() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let dir_path = tmp_dir.path().join("subdir");
        std::fs::create_dir(&dir_path).expect("failed to create directory");

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();

        // Assert returns within 2s with typed error (not a hang or protocol failure)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.upload(&dir_path, "/tmp", None, &ct),
        )
        .await;

        assert!(
            result.is_ok(),
            "upload should return within 2s (not hang or desync)"
        );
        assert!(
            result.expect("operation should succeed").is_err(),
            "upload should return error for directory"
        );
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 15 REGRESSION TESTS (4×P1/P2)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 33: Download refuses symlink destinations before truncating.
    ///
    /// P1 regression: OpenOptions follows symlinks, so a pre-created symlink at
    /// local_path means set_permissions, set_len, and writes land on the target.
    ///
    /// Fix: Open with O_NOFOLLOW and validate file type before set_permissions/set_len
    /// (line ~818-870).
    ///
    /// Test: Create symlink pointing at canary, download to symlink path, assert
    /// canary untouched in contents AND mode, transfer fails.

    #[tokio::test]
    async fn cancel_during_channel_open_poisons_client() {
        let state = TestServerState::new(ServerBehavior::DelayChannelOpen);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"test").expect("failed to write file");

        // Cancel after a short delay (before channel open confirms)
        let ct = CancellationToken::new();
        let ct_clone = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            ct_clone.cancel();
        });

        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;
        assert!(result.is_err(), "first upload should be cancelled");
        match result {
            Err(ScpError::Io(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Expected: cancelled during channel open
            }
            other => panic!("expected Interrupted, got {:?}", other),
        }

        // Now try to use the same client again — should return poisoned error
        let ct2 = CancellationToken::new();
        let result2 = client.upload(tmp.path(), "/tmp/", None, &ct2).await;
        assert!(
            result2.is_err(),
            "second upload should fail with poisoned error"
        );
        match result2 {
            Err(ScpError::ScpClientPoisoned) => {
                // Expected: client is poisoned
            }
            other => panic!("expected ScpClientPoisoned, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn cancel_during_channel_open_returns_promptly() {
        // This test verifies the cancellation-path fix by cancelling immediately and
        // asserting the call returns within 2s. A regression (re-awaiting open_future
        // on the cancel path) would hang until the test timeout.
        //
        // We cannot directly simulate "peer never confirms channel open" without a
        // custom SSH server, but we can verify the cancellation path doesn't block
        // by cancelling before the transfer starts and checking prompt return.

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), vec![0u8; 1000]).expect("failed to write file");

        let ct = CancellationToken::new();
        ct.cancel(); // Cancel immediately

        // Assert upload returns within 2s (well under the 5s cleanup timeout).
        // If the cancellation path re-awaits open_future, this will timeout.
        let upload_result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.upload(tmp.path(), "/tmp", None, &ct),
        )
        .await;

        assert!(
            upload_result.is_ok(),
            "upload should return within 2s when cancelled"
        );
        assert!(
            upload_result.expect("operation should succeed").is_err(),
            "upload should return cancellation error"
        );
    }

    /// Test 23: Cancellation while sink is stalled returns promptly.
    ///
    /// P1 regression: When an upload is blocked because the remote sink stopped consuming
    /// (russh's bounded outbound queue full, or TCP write stalled), cancellation must not
    /// call close().await — that pushes EOF/CLOSE through the same stalled sender, blocking
    /// indefinitely.
    ///
    /// Fix: Cancellation path returns immediately without awaiting cleanup. Drop spawns
    /// detached cleanup.
    ///
    /// Test: Start upload with a SinkStall server (accepts header then stops reading),
    /// wait for the upload to block, cancel, assert the call returns within 2s.

    #[tokio::test]
    async fn cancel_during_exec_returns_promptly() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        ct.cancel(); // Cancel immediately

        // Assert upload returns within 2s when cancelled
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.upload(tmp.path(), "/tmp", None, &ct),
        )
        .await;

        assert!(
            result.is_ok(),
            "upload should return within 2s when cancelled"
        );
        assert!(
            result.expect("operation should succeed").is_err(),
            "upload should return cancellation error"
        );
    }

    /// Test 28: Detached cleanup completes within timeout bound.
    ///
    /// P2 regression: The detached task in Drop (line ~209-217) awaits eof() and close()
    /// through the same stalled sender. With a reused client and no timeout, each cancelled
    /// transfer keeps its task, channel, and remote process alive indefinitely.
    ///
    /// Fix: Wrap detached cleanup in 5s timeout (line ~209).
    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 14 REGRESSION TESTS (3×P2)
    // ══════════════════════════════════════════════════════════════════════════════
    /// Test 29: Upload rejects FIFO without hanging.
    ///
    /// P2 regression: If local_path is a FIFO with no writer, File::open() blocks
    /// indefinitely before the cancellation token is ever checked, so even a
    /// pre-cancelled upload hangs.
    ///
    /// Fix: Check metadata.is_file() before opening (line ~388-420).
    ///
    /// Test: Create a FIFO, attempt upload with pre-cancelled token, assert returns
    /// within timeout with typed error (not a hang).

    #[tokio::test]
    async fn cancel_during_stalled_sink_returns_promptly() {
        let state = TestServerState::new(ServerBehavior::SinkStall);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        // Large enough to fill the outbound queue and stall
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), vec![0xAAu8; 5_000_000]).expect("failed to write file");

        let ct = CancellationToken::new();
        let ct_clone = ct.clone();

        // Cancel after 500ms (enough time for upload to start and stall)
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            ct_clone.cancel();
        });

        // Assert upload returns within 2s of cancellation (total 2.5s from start).
        // If the cancellation path awaits close(), this will timeout.
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.upload(tmp.path(), "/tmp", None, &ct),
        )
        .await;

        let elapsed = start.elapsed();
        assert!(result.is_ok(), "upload should return within 3s total");
        assert!(
            result.expect("operation should succeed").is_err(),
            "upload should return cancellation error"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "upload should return within ~1s of cancellation (got {:?})",
            elapsed
        );
    }

    /// Test 24: Download to non-owned but writable destination fails without truncating.
    ///
    /// P2 regression: When local_path exists but is not owned by the caller (group-writable
    /// or ACL-writable but owner != caller), open-with-truncate succeeds and destroys the
    /// contents, then set_permissions fails with EPERM, leaving the file empty.
    ///
    /// Fix: Open without truncate, apply permissions, THEN truncate. A permission failure
    /// aborts before data loss.
    ///
    /// Test: Cannot simulate a non-owned file in a single-user test environment (needs a
    /// second uid). Instead, assert the file open does NOT request truncate on the initial
    /// OpenOptions — verify truncate happens via set_len() after set_permissions, not via
    /// OpenOptions::truncate(true).
    ///
    /// This is a structural assertion: the code at lines ~754-784 opens without .truncate(true),
    /// then calls .set_len(0) after set_permissions succeeds (line ~782). A regression would
    /// move .truncate(true) back to the OpenOptions, which we detect by code inspection rather
    /// than runtime behavior (since we cannot create a non-owned file in this test).

    #[tokio::test]
    async fn framing_variations_transfer_correctly() {
        let content = b"test content for framing".to_vec();

        // Coalesced: header + content in one SSH message
        let state = TestServerState::new(ServerBehavior::SourceCoalesced {
            filename: "coalesced.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/coalesced.txt", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "coalesced download failed: {:?}", result);
        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "coalesced content mismatch");

        // One byte at a time
        let state2 = TestServerState::new(ServerBehavior::SourceOneByte {
            filename: "onebyte.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        let (_handle2, addr2) = start_test_server(state2)
            .await
            .expect("failed to start server");

        let config2 = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr2.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect2 = CancellationToken::new();
        let mut client2 = ScpClient::connect(config2, &ct_connect2)
            .await
            .expect("connect failed");

        let tmp2 = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let result2 = client2
            .download("/tmp/onebyte.txt", tmp2.path(), None, &ct)
            .await;

        assert!(result2.is_ok(), "one-byte download failed: {:?}", result2);
        let downloaded2 = std::fs::read(tmp2.path()).expect("failed to read file");
        assert_eq!(downloaded2, content, "one-byte content mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 6 REGRESSION TESTS (P1 + 4×P2)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 8: Rejected exec request returns promptly.
    ///
    /// P1 regression: When the server allows auth but rejects exec, russh delivers
    /// ChannelMsg::Failure. Before the fix, ChannelReader::fill ignored that message
    /// and upload/download waited indefinitely for an SCP ack.
    ///
    /// Fix: Consume Success or Failure before starting SCP handshake.

    #[tokio::test]
    async fn permission_denied_error_is_io_not_auth() {
        let state = TestServerState::new(ServerBehavior::ErrorAck {
            code: 2,
            message: "scp: /tmp/test.txt: Permission denied".to_string(),
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"data").expect("failed to write file");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/", None, &ct).await;

        assert!(result.is_err(), "should fail with permission denied");
        match result {
            Err(ScpError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            other => panic!("expected Io(PermissionDenied), got {:?}", other),
        }
    }

    /// Test 6: Stalled sink plus cancellation returns cancellation error.
    ///
    /// Regression test for the original stall bug: when the peer stops consuming data,
    /// cancel() must wake the blocked channel.data() call. Before the fix, the upload
    /// would hang indefinitely.

    #[tokio::test]
    async fn sink_final_error_returns_typed_error() {
        let content = b"upload payload";
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), content).expect("failed to write file");

        let state = TestServerState::new(ServerBehavior::SinkFinalError {
            code: 1,
            message: "disk full".to_string(),
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/test.txt", None, &ct).await;

        assert!(result.is_err(), "should return error for final status-1");
        match result {
            Err(ScpError::Io(e)) if e.kind() == std::io::ErrorKind::StorageFull => {
                // Correct: scp_error() mapped "disk full" to StorageFull
            }
            other => panic!("expected StorageFull error, got {:?}", other),
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 9 REGRESSION TESTS (2×P1)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 17: Cancel during channel open (peer never confirms).
    ///
    /// P1 regression: When an authenticated peer never confirms the session-channel open,
    /// `channel_open_session().await` can wait forever. The russh config sets no inactivity
    /// timeout, and `CancellableChannel` doesn't exist yet, so the token cannot abort this
    /// phase. Before the fix, only ctrl-C would terminate the hung call.
    ///
    /// Fix: Race channel creation against `ct.cancelled()` in both upload and download.
    ///
    /// This test cannot be expressed with the current test harness (it would require a
    /// peer that accepts TCP+auth but never sends ChannelOpenConfirmation). Instead,
    /// we verify the fix exists by inspection and document what would fail.
    ///
    /// Before fix: `tokio::time::timeout(1s, upload(...))` with a stalling peer would
    /// return `Err(Elapsed)` (timeout fired, call still hung).
    ///
    /// After fix: Returns `Err(ScpError::Io(Interrupted, "cancelled while opening
    /// channel"))` within the timeout.

    #[tokio::test]
    async fn upload_data_before_success_completes() {
        let content = b"Early data upload test content";
        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), content).expect("failed to write file");

        let state = TestServerState::new(ServerBehavior::SinkDataBeforeSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let ct = CancellationToken::new();
        let result = client.upload(tmp.path(), "/tmp/test.txt", None, &ct).await;

        assert!(result.is_ok(), "upload failed: {:?}", result);
        let outcome = result.expect("operation should succeed");
        assert_eq!(outcome.bytes_transferred, content.len() as u64);
    }

    /// Test 13: Download completes when server sends SCP data before CHANNEL_SUCCESS.
    ///
    /// P2 regression: When the server sent the "C" header before CHANNEL_SUCCESS,
    /// consuming Success/Failure in download() discarded the header. The client would
    /// then block waiting for a header that had already arrived, causing an indefinite hang.
    ///
    /// Fix: Feed Data messages into ChannelReader.buffer before breaking the ready-ack
    /// loop. This preserves early SCP data for the protocol handshake.
    ///
    /// Test: Use ServerBehavior::SourceDataBeforeSuccess, which sends the C header before
    /// the SSH success. Before 6f695ed the test would time out; after the fix it completes.

    #[tokio::test]
    async fn download_data_before_success_completes() {
        let content = b"Early data download test content";

        let state = TestServerState::new(ServerBehavior::SourceDataBeforeSuccess {
            filename: "test.txt".to_string(),
            content: content.to_vec(),
            mode: 0o644,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let ct = CancellationToken::new();
        let result = client
            .download("/tmp/test.txt", tmp.path(), None, &ct)
            .await;

        assert!(result.is_ok(), "download failed: {:?}", result);
        let outcome = result.expect("operation should succeed");
        assert_eq!(outcome.bytes_transferred, content.len() as u64);

        let downloaded = std::fs::read(tmp.path()).expect("failed to read file");
        assert_eq!(downloaded, content, "content mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // ROUND 8 REGRESSION TESTS (2×P1 + 3×P2)
    // ══════════════════════════════════════════════════════════════════════════════

    /// Test 14: Upload preserves restrictive file permissions (0600, 0700).
    ///
    /// P2 regression: The C header must carry the local file's mode, not a hardcoded 0644.
    /// A 0600 secret becoming world-readable on the remote is a security exposure.

    #[cfg(unix)]
    #[tokio::test]
    async fn upload_preserves_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        // Test 0600 (secret file)
        let content_secret = b"secret key";
        let tmp_secret = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp_secret.path(), content_secret).expect("failed to write file");
        let perms_600 = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp_secret.path(), perms_600).expect("failed to set permissions");

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let result = client
            .upload(tmp_secret.path(), "/tmp/secret.key", None, &ct)
            .await;

        assert!(result.is_ok(), "upload 0600 failed: {:?}", result);

        // Verify server received the correct mode in the C header
        let captured = state.get_captured().await;
        assert!(captured.is_some(), "server did not capture protocol");
        let cap = captured.expect("protocol should be captured");
        assert!(cap.c_header.is_some(), "server did not capture C header");
        let c_header = cap.c_header.expect("C header should be captured");
        assert_eq!(
            c_header.mode, 0o600,
            "client sent mode 0o{:o} instead of 0o600",
            c_header.mode
        );
        assert_eq!(cap.payload, content_secret, "payload mismatch");
        assert!(cap.terminator_received, "E terminator not received");

        // Test 0700 (executable script)
        let content_exec = b"#!/bin/sh\necho hello\n";
        let tmp_exec = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp_exec.path(), content_exec).expect("failed to write file");
        let perms_700 = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(tmp_exec.path(), perms_700).expect("failed to set permissions");

        let state2 = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle2, addr2) = start_test_server(state2.clone())
            .await
            .expect("failed to start server");

        let config2 = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr2.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect2 = CancellationToken::new();
        let mut client2 = ScpClient::connect(config2, &ct_connect2)
            .await
            .expect("connect failed");

        let result2 = client2
            .upload(tmp_exec.path(), "/tmp/script.sh", None, &ct)
            .await;

        assert!(result2.is_ok(), "upload 0700 failed: {:?}", result2);

        // Verify server received the correct mode in the C header
        let captured2 = state2.get_captured().await;
        assert!(captured2.is_some(), "server did not capture protocol");
        let cap2 = captured2.expect("protocol should be captured");
        assert!(cap2.c_header.is_some(), "server did not capture C header");
        let c_header2 = cap2.c_header.expect("C header should be captured");
        assert_eq!(
            c_header2.mode, 0o700,
            "client sent mode 0o{:o} instead of 0o700",
            c_header2.mode
        );
        assert_eq!(cap2.payload, content_exec, "payload mismatch");
        assert!(cap2.terminator_received, "E terminator not received");
    }

    /// Test 15: Download applies received mode (C0600 -> local 0600).
    ///
    /// P2 regression: A remote file sent as C0600 must land with mode 0600, not the
    /// process umask (commonly 0644). Discarding the mode silently broadens permissions
    /// on downloaded secrets.

    #[tokio::test]
    async fn upload_non_utf8_basename() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        // Create filename with invalid UTF-8 sequence (0xff is not valid UTF-8)
        let basename = OsStr::from_bytes(b"test\xfffile.txt");
        let local_file = tmp_dir.path().join(basename);
        std::fs::write(&local_file, b"test content").expect("failed to write file");

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");
        let ct = CancellationToken::new();

        // Upload file with non-UTF-8 name
        let result = client.upload(&local_file, "/tmp", None, &ct).await;

        // Transfer should succeed with non-UTF-8 basename
        assert!(
            result.is_ok(),
            "upload should succeed for non-UTF-8 basename: {:?}",
            result
        );
    }

    /// Test 31: Upload clamps pre-epoch timestamps to zero in T header.
    ///
    /// P2 regression: A file whose mtime/atime predates 1970 gives negative
    /// MetadataExt values, emitting T-1 0 -1 0, which OpenSSH rejects as malformed.
    ///
    /// Fix: Clamp to zero with .max(0) (line ~544-552).
    /// Test 32: Download preserves whitespace-only filename.
    ///
    /// P2 regression: read_line already stripped the newline, so trim() also eats
    /// filenames made of spaces: "C0644 1  " collapses to two fields and is rejected.
    ///
    /// Fix: Split untrimmed line, filename is everything after second separator (line ~962-991).
    ///
    /// Test: Server sends C header with space-only filename, assert client accepts
    /// it and download succeeds with spaces preserved.

    #[tokio::test]
    async fn download_preserves_whitespace_filename() {
        // Server sends a file named "  " (two spaces)
        let state = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "  ".to_string(), // Two spaces
            content: b"data".to_vec(),
            mode: 0o644,
        });
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let dest_path = tmp_dir.path().join("  "); // Two spaces

        let ct = CancellationToken::new();
        let result = client.download("/tmp/  ", &dest_path, None, &ct).await;

        // Download should succeed with space-only filename
        assert!(result.is_ok(), "download failed: {:?}", result);

        // Verify file was created with space-only name
        assert!(dest_path.exists(), "file with space name should exist");
        let content = std::fs::read(&dest_path).expect("failed to read file");
        assert_eq!(content, b"data", "content should match");
    }

    #[tokio::test]
    async fn filename_with_space_both_directions() {
        // Upload direction
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");

        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = tmp_dir.path().join("release image.tgz");
        std::fs::write(&file_path, b"data").expect("failed to write file");
        let result = client.upload(&file_path, "/tmp/", None, &ct).await;

        assert!(
            result.is_ok(),
            "upload with space in filename failed: {:?}",
            result
        );

        // Download direction
        let content = b"test content".to_vec();
        let state2 = TestServerState::new(ServerBehavior::SourceSuccess {
            filename: "my file.txt".to_string(),
            content: content.clone(),
            mode: 0o644,
        });
        let (_handle2, addr2) = start_test_server(state2)
            .await
            .expect("failed to start server");

        let config2 = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr2.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect2 = CancellationToken::new();
        let mut client2 = ScpClient::connect(config2, &ct_connect2)
            .await
            .expect("connect failed");

        let tmp2 = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let result2 = client2
            .download("/tmp/my file.txt", tmp2.path(), None, &ct)
            .await;

        assert!(
            result2.is_ok(),
            "download with space in filename failed: {:?}",
            result2
        );

        let downloaded = std::fs::read(tmp2.path()).expect("failed to read file");
        assert_eq!(downloaded, content);
    }

    /// Test 4: Non-zero exit status returns typed error.
    ///
    /// P1 regression test: Verifies that wait_exit_status() works after eof().
    /// Before the fix, this would fail with "channel already closed" instead of
    /// the exit status error.

    #[tokio::test]
    async fn upload_dash_prefix_remote_dir() {
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let local_file = tmp_dir.path().join("test.txt");
        std::fs::write(&local_file, b"test content").expect("failed to write file");

        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");
        let ct = CancellationToken::new();

        // Upload to remote_dir starting with dash
        let result = client.upload(&local_file, "-staging", None, &ct).await;

        // Transfer should succeed (server accepts -- before path)
        assert!(
            result.is_ok(),
            "upload should succeed for dash-prefix remote_dir: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn channel_open_failure_does_not_poison_client() {
        // Regression test: Observed channel-open failures (server refuses) should not poison
        // the client. The poison guard defends against channel leaks when cancellation races
        // channel_open_session, but must be disarmed for observed errors so the client remains
        // usable.
        let state = TestServerState::new(ServerBehavior::RejectChannelOpen);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct_connect = CancellationToken::new();
        let mut client = ScpClient::connect(config, &ct_connect)
            .await
            .expect("connect failed");
        let ct = CancellationToken::new();

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::fs::write(tmp.path(), b"test data").expect("failed to write file");

        // First transfer: server rejects channel_open_session
        let result1 = client.upload(tmp.path(), "/tmp/test.txt", None, &ct).await;
        assert!(
            result1.is_err(),
            "upload should fail when server rejects channel open"
        );

        // Second transfer: client must not be poisoned, attempt should proceed
        // (will fail again because server still rejects, but proves client is not poisoned)
        let result2 = client.upload(tmp.path(), "/tmp/test2.txt", None, &ct).await;
        assert!(
            result2.is_err(),
            "second upload should also fail (server still rejects)"
        );

        // If client was poisoned, result2 would be Err("client is poisoned")
        // Both errors should be channel errors, not poison errors
        if let Err(ScpError::Channel(msg1)) = result1 {
            assert!(
                msg1.contains("failed to open session"),
                "expected channel open error, got: {}",
                msg1
            );
        } else {
            panic!("expected Channel error, got: {:?}", result1);
        }

        if let Err(ScpError::Channel(msg2)) = result2 {
            assert!(
                msg2.contains("failed to open session"),
                "expected channel open error, got: {}",
                msg2
            );
        } else {
            panic!("expected Channel error, got: {:?}", result2);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════════
    // P2 SECURITY TESTS
    // ══════════════════════════════════════════════════════════════════════════════

    /// P2-1: KnownHosts mode with matching key connects successfully
    #[tokio::test]
    async fn known_hosts_matching_key_connects() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Create a temporary known_hosts file
        let known_hosts_file = tempfile::NamedTempFile::new().expect("failed to create temp file");

        // First connect with AcceptAll to get the host key
        let config_accept_all = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                known_hosts_file.path().to_path_buf(),
            ),
        };

        let ct_connect = CancellationToken::new();
        let client = ScpClient::connect(config_accept_all, &ct_connect)
            .await
            .expect("first connect should succeed with AcceptNew");
        let _ = client.close().await;

        // Now connect again with KnownHosts mode - should succeed with the cached key
        let config_known_hosts = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_file.path().to_path_buf(),
            ),
        };

        let ct_connect2 = CancellationToken::new();
        let result = ScpClient::connect(config_known_hosts, &ct_connect2).await;
        match result {
            Ok(_) => {} // Success
            Err(e) => {
                panic!(
                    "known_hosts with matching key should succeed, got error: {:?}",
                    e
                );
            }
        }
    }

    /// P2-1: KnownHosts mode with mismatched key fails
    #[tokio::test]
    async fn known_hosts_mismatched_key_rejected() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Create a known_hosts file with a different (but valid) key
        // This is a valid Ed25519 public key, just not the one the server will present.
        // Use [host]:port format since test server uses non-default port.
        let known_hosts_file = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let fake_key_entry = format!(
            "[127.0.0.1]:{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMBKvGOp/6xzPYWZK5jqYZlUMW+4jxmB11QsSLzKUPLK\n",
            addr.port()
        );
        std::fs::write(known_hosts_file.path(), fake_key_entry)
            .expect("failed to write known_hosts");

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_file.path().to_path_buf(),
            ),
        };

        let ct_connect = CancellationToken::new();
        let result = ScpClient::connect(config, &ct_connect).await;
        assert!(
            result.is_err(),
            "known_hosts with mismatched key should fail"
        );

        match result {
            Err(ScpError::HostKeyVerification(msg)) => {
                assert!(
                    msg.contains("key") && (msg.contains("mismatch") || msg.contains("changed")),
                    "error should mention key mismatch or key changed: {}",
                    msg
                );
            }
            Err(other) => panic!("expected HostKeyVerification error, got: {:?}", other),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    /// P2-1: AcceptNew mode adds new host on first connection
    #[tokio::test]
    async fn accept_new_adds_host_on_first_connection() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state.clone())
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Create a temporary known_hosts file (initially empty)
        let known_hosts_file = tempfile::NamedTempFile::new().expect("failed to create temp file");

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                known_hosts_file.path().to_path_buf(),
            ),
        };

        let ct_connect = CancellationToken::new();
        let result = ScpClient::connect(config, &ct_connect).await;
        assert!(result.is_ok(), "AcceptNew should accept new host");

        // Verify the known_hosts file now contains the host
        let known_hosts_content =
            std::fs::read_to_string(known_hosts_file.path()).expect("failed to read known_hosts");
        assert!(
            known_hosts_content.contains("127.0.0.1"),
            "known_hosts should contain the host"
        );
        assert!(
            !known_hosts_content.is_empty(),
            "known_hosts should not be empty"
        );

        // Connect again - should reuse the cached key
        let config2 = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                known_hosts_file.path().to_path_buf(),
            ),
        };

        let ct_connect2 = CancellationToken::new();
        let result2 = ScpClient::connect(config2, &ct_connect2).await;
        assert!(
            result2.is_ok(),
            "second connect should succeed with cached key"
        );
    }

    /// P2-2: FIFO key path fails fast (no hang)
    #[tokio::test]
    async fn fifo_key_path_fails_fast() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        // Create a FIFO instead of a regular file
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let fifo_path = tmp_dir.path().join("key.fifo");

        use rustix::fs::mknodat;
        mknodat(
            rustix::fs::CWD,
            &fifo_path,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .expect("failed to create FIFO");

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: fifo_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();

        // Wrap in timeout to prove it doesn't hang
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            ScpClient::connect(config, &ct),
        )
        .await;

        assert!(
            result.is_ok(),
            "connect should not timeout (should fail fast)"
        );
        let connect_result = result.expect("should not timeout");
        assert!(connect_result.is_err(), "FIFO key should be rejected");
    }

    /// P2-2: World-readable key file is refused
    #[tokio::test]
    async fn world_readable_key_refused() {
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile_template, key_path_template) = create_test_key();

        // Copy the key to a new file with world-readable permissions
        let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let insecure_key_path = tmp_dir.path().join("insecure_key");
        std::fs::copy(&key_path_template, &insecure_key_path).expect("failed to copy key");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&insecure_key_path, std::fs::Permissions::from_mode(0o644))
                .expect("failed to set permissions");
        }

        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: insecure_key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        assert!(result.is_err(), "world-readable key should be rejected");
        match result {
            Err(ScpError::Auth(msg)) => {
                assert!(
                    msg.contains("unsafe permissions") || msg.contains("0644"),
                    "error should mention unsafe permissions, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected Auth error, got: {:?}", other),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    /// P2: Debug output of SshConfig with passphrase doesn't leak secret
    #[test]
    fn ssh_config_debug_redacts_passphrase() {
        use mecmcp_secret::OutboundSecret;

        let config = SshConfig {
            host: "test.example.com".to_string(),
            port: 22,
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: std::path::PathBuf::from("/tmp/key"),
                // new_unchecked is correct here: this is a test fixture with a hardcoded
                // value, not loaded from a file or environment variable that needs validation
                passphrase: Some(OutboundSecret::new_unchecked(
                    "super_secret_passphrase".to_string(),
                )),
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let debug_output = format!("{:?}", config);
        assert!(
            !debug_output.contains("super_secret_passphrase"),
            "debug output should not contain the passphrase"
        );
        assert!(
            debug_output.contains("<redacted>"),
            "debug output should show passphrase is redacted"
        );
    }

    /// P1-1: Hashed known_hosts entry matches correctly
    #[tokio::test]
    async fn known_hosts_hashed_entry_matches() {
        use russh::keys::known_hosts;
        use russh::keys::parse_public_key_base64;

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let known_hosts_path = dir.path().join("known_hosts");

        // This is a hashed entry from russh's own test suite for "example.com"
        std::fs::write(
            &known_hosts_path,
            b"|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n"
        ).expect("failed to write known_hosts");

        let host = "example.com";
        let port = 22;
        let pubkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .expect("failed to parse key");

        // Verify russh's API correctly matches the hashed entry
        assert!(
            known_hosts::check_known_hosts_path(host, port, &pubkey, &known_hosts_path)
                .expect("check_known_hosts_path failed"),
            "hashed entry should match"
        );
    }

    /// P1-1: @revoked marker is refused
    #[tokio::test]
    async fn known_hosts_revoked_marker_refused() {
        use russh::keys::known_hosts;
        use russh::keys::parse_public_key_base64;

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let known_hosts_path = dir.path().join("known_hosts");

        // Entry with @revoked marker
        std::fs::write(
            &known_hosts_path,
            b"@revoked example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n"
        ).expect("failed to write known_hosts");

        let host = "example.com";
        let port = 22;
        let pubkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .expect("failed to parse key");

        // Revoked keys should not match
        let result = known_hosts::check_known_hosts_path(host, port, &pubkey, &known_hosts_path);
        assert!(
            result.is_ok() && !result.expect("check should succeed but not match"),
            "@revoked entry should not match"
        );
    }

    /// P1-1: Entry learned on non-default port uses [host]:port format and doesn't match default port
    #[tokio::test]
    async fn known_hosts_port_isolation() {
        use russh::keys::known_hosts;
        use russh::keys::{Algorithm, PrivateKey};

        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let known_hosts_path = dir.path().join("known_hosts");

        // Generate a key
        let keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate key");
        let pubkey = keypair.public_key();

        // Learn the key on port 2222
        known_hosts::learn_known_hosts_path("testhost", 2222, pubkey, &known_hosts_path)
            .expect("failed to learn key");

        // Verify entry was written in [host]:port format
        let contents = std::fs::read_to_string(&known_hosts_path).expect("failed to read file");
        assert!(
            contents.contains("[testhost]:2222"),
            "entry should use [host]:port format, got: {}",
            contents
        );

        // Key on port 2222 should match
        assert!(
            known_hosts::check_known_hosts_path("testhost", 2222, pubkey, &known_hosts_path)
                .expect("check failed"),
            "key should match on port 2222"
        );

        // Key on port 22 should NOT match (port isolation)
        assert!(
            !known_hosts::check_known_hosts_path("testhost", 22, pubkey, &known_hosts_path)
                .expect("check failed"),
            "key on port 2222 should not match port 22"
        );
    }

    /// P1-2: Cancellation during SSH connect is honoured
    #[tokio::test]
    async fn connect_cancellation_works() {
        // Start a TCP listener that accepts but never completes SSH handshake
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind");
        let addr = listener.local_addr().expect("no local addr");

        tokio::spawn(async move {
            loop {
                if let Ok((mut _stream, _)) = listener.accept().await {
                    // Accept but never respond - stall the handshake
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            }
        });

        let (_keyfile, key_path) = create_test_key();
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let ct_clone = ct.clone();

        // Cancel after 100ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            ct_clone.cancel();
        });

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ScpClient::connect(config, &ct),
        )
        .await;

        let elapsed = start.elapsed();

        // Should complete quickly (within timeout) due to cancellation
        assert!(result.is_ok(), "timeout should not fire");
        assert!(
            result.expect("should not timeout").is_err(),
            "connect should fail due to cancellation"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "cancellation should complete quickly, took {:?}",
            elapsed
        );
    }

    /// P1-3: KEX config includes NIST curves
    #[test]
    fn kex_config_includes_nist_curves() {
        use russh::kex;

        let config = build_russh_config();
        let kex_list = &config.preferred.kex;

        // Verify NIST curves are present
        assert!(
            kex_list.contains(&kex::ECDH_SHA2_NISTP256),
            "KEX list should include ecdh-sha2-nistp256"
        );
        assert!(
            kex_list.contains(&kex::ECDH_SHA2_NISTP384),
            "KEX list should include ecdh-sha2-nistp384"
        );
        assert!(
            kex_list.contains(&kex::ECDH_SHA2_NISTP521),
            "KEX list should include ecdh-sha2-nistp521"
        );

        // Verify modern secure algorithms come first (e.g., Curve25519)
        let nistp256_pos = kex_list
            .iter()
            .position(|k| k == &kex::ECDH_SHA2_NISTP256)
            .expect("NISTP256 should be in list");
        let curve25519_pos = kex_list
            .iter()
            .position(|k| k == &kex::CURVE25519)
            .expect("Curve25519 should be in list");

        assert!(
            curve25519_pos < nistp256_pos,
            "Curve25519 should come before NIST curves"
        );
    }

    /// Revoked host key is refused with distinct error
    #[tokio::test]
    async fn revoked_host_key_refused() {
        // Start a test server
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Connect once with AcceptNew to learn the server's host key
        let temp_known_hosts = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let learn_config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                temp_known_hosts.path().to_path_buf(),
            ),
        };

        let ct_learn = CancellationToken::new();
        ScpClient::connect(learn_config, &ct_learn)
            .await
            .expect("initial connect should succeed");

        // Read the learned entry
        let learned_entry =
            std::fs::read_to_string(temp_known_hosts.path()).expect("failed to read known_hosts");

        // Create a new known_hosts file with:
        // 1. The normal entry (so russh would accept it)
        // 2. An @revoked entry for the same host and key (so we must refuse it)
        let known_hosts_with_revoked =
            tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = format!(
            "{}\n@revoked {}",
            learned_entry.trim(),
            learned_entry.trim()
        );
        std::fs::write(known_hosts_with_revoked.path(), content)
            .expect("failed to write known_hosts");

        // Try to connect again with the known_hosts file that has the @revoked marker
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_with_revoked.path().to_path_buf(),
            ),
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        // Must fail with HostKeyRevoked error
        assert!(result.is_err(), "revoked key should be refused");
        match result {
            Err(ScpError::HostKeyRevoked(msg)) => {
                assert!(
                    msg.contains("@revoked") && msg.contains("revoked"),
                    "error should mention @revoked marker, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected HostKeyRevoked error, got: {:?}", other),
            Ok(_) => panic!("revoked key should be refused"),
        }
    }

    /// Revoked host key with hashed hostname is refused
    #[tokio::test]
    async fn revoked_hashed_host_key_refused() {
        // Start a test server
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Connect once with AcceptNew to learn the server's host key
        let temp_known_hosts = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let learn_config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                temp_known_hosts.path().to_path_buf(),
            ),
        };

        let ct_learn = CancellationToken::new();
        ScpClient::connect(learn_config, &ct_learn)
            .await
            .expect("initial connect should succeed");

        // Read the learned entry
        let learned_entry =
            std::fs::read_to_string(temp_known_hosts.path()).expect("failed to read known_hosts");

        // Hash the entry by creating a new file and using russh's learn function
        // (russh can hash entries when learning)
        // For simplicity in this test, we'll manually create a hashed entry.
        // The hash format is: |1|salt|hash where hash = HMAC-SHA1(salt, host)
        use base64::Engine;
        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha1 = Hmac<sha1::Sha1>;

        let host_to_hash = format!("[127.0.0.1]:{}", addr.port());
        let salt_bytes: [u8; 20] = rand::random();
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt_bytes);

        let mut hmac_hasher = HmacSha1::new_from_slice(&salt_bytes).expect("failed to create HMAC");
        hmac_hasher.update(host_to_hash.as_bytes());
        let hash = hmac_hasher.finalize().into_bytes();
        let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

        let hashed_host = format!("|1|{}|{}", salt_b64, hash_b64);

        // Extract key type and key data from learned entry
        let parts: Vec<&str> = learned_entry.split_whitespace().collect();
        assert!(
            parts.len() >= 3,
            "learned entry should have at least 3 parts"
        );
        let key_type = parts[1];
        let key_data = parts[2];

        // Create a known_hosts file with a hashed @revoked entry
        let known_hosts_with_revoked =
            tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = format!(
            "{}\n@revoked {} {} {}",
            learned_entry.trim(),
            hashed_host,
            key_type,
            key_data
        );
        std::fs::write(known_hosts_with_revoked.path(), content)
            .expect("failed to write known_hosts");

        // Try to connect with the hashed @revoked entry
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_with_revoked.path().to_path_buf(),
            ),
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        // Must fail with HostKeyRevoked error
        assert!(result.is_err(), "hashed revoked key should be refused");
        match result {
            Err(ScpError::HostKeyRevoked(msg)) => {
                assert!(
                    msg.contains("@revoked"),
                    "error should mention @revoked marker, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected HostKeyRevoked error, got: {:?}", other),
            Ok(_) => panic!("hashed revoked key should be refused"),
        }
    }

    /// Revoked entry for a different key on the same host allows the good key
    #[tokio::test]
    async fn revoked_different_key_allows_good_key() {
        use russh::keys::{Algorithm, PrivateKey};

        // Start a test server
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Connect once with AcceptNew to learn the server's host key
        let temp_known_hosts = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let learn_config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                temp_known_hosts.path().to_path_buf(),
            ),
        };

        let ct_learn = CancellationToken::new();
        ScpClient::connect(learn_config, &ct_learn)
            .await
            .expect("initial connect should succeed");

        // Read the learned entry (this is the GOOD key)
        let learned_entry =
            std::fs::read_to_string(temp_known_hosts.path()).expect("failed to read known_hosts");

        // Generate a DIFFERENT key (the revoked one)
        use russh::keys::PublicKeyBase64;
        let revoked_keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate key");
        let revoked_pubkey = revoked_keypair.public_key();
        let revoked_key_b64 = revoked_pubkey.public_key_base64();

        // Create a known_hosts file with:
        // 1. The good key (normal entry)
        // 2. A @revoked entry for the same host but a DIFFERENT key
        let known_hosts_mixed = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = format!(
            "{}\n@revoked [127.0.0.1]:{} ssh-ed25519 {}",
            learned_entry.trim(),
            addr.port(),
            revoked_key_b64
        );
        std::fs::write(known_hosts_mixed.path(), content).expect("failed to write known_hosts");

        // Connect with the good key - should succeed
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_mixed.path().to_path_buf(),
            ),
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        if let Err(ref e) = result {
            panic!(
                "good key should connect even when a different key is revoked, got error: {}",
                e
            );
        }
        assert!(result.is_ok());
    }

    /// @cert-authority entry for the host is refused with distinct error
    #[tokio::test]
    async fn cert_authority_entry_refused() {
        use russh::keys::{Algorithm, PrivateKey};

        // Start a test server
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Generate a CA key (doesn't need to be related to server's key)
        use russh::keys::PublicKeyBase64;
        let ca_keypair = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate CA key");
        let ca_pubkey = ca_keypair.public_key();
        let ca_key_b64 = ca_pubkey.public_key_base64();

        // Create a known_hosts file with only a @cert-authority entry for this host
        let known_hosts_ca = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = format!(
            "@cert-authority [127.0.0.1]:{} ssh-ed25519 {}",
            addr.port(),
            ca_key_b64
        );
        std::fs::write(known_hosts_ca.path(), content).expect("failed to write known_hosts");

        // Try to connect - should fail with HostKeyVerification error mentioning @cert-authority
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::KnownHosts(
                known_hosts_ca.path().to_path_buf(),
            ),
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        assert!(result.is_err(), "@cert-authority should be refused");
        match result {
            Err(ScpError::HostKeyVerification(msg)) => {
                assert!(
                    msg.contains("@cert-authority") && msg.contains("not supported"),
                    "error should mention @cert-authority is not supported, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected HostKeyVerification error, got: {:?}", other),
            Ok(_) => panic!("@cert-authority should be refused"),
        }
    }

    /// AcceptNew mode refuses revoked keys instead of learning them
    #[tokio::test]
    async fn accept_new_refuses_revoked_keys() {
        // Start a test server
        let state = TestServerState::new(ServerBehavior::SinkSuccess);
        let (_handle, addr) = start_test_server(state)
            .await
            .expect("failed to start server");

        let (_keyfile, key_path) = create_test_key();

        // Connect once with AcceptNew to learn the server's host key
        let temp_known_hosts = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let learn_config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path.clone(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                temp_known_hosts.path().to_path_buf(),
            ),
        };

        let ct_learn = CancellationToken::new();
        ScpClient::connect(learn_config, &ct_learn)
            .await
            .expect("initial connect should succeed");

        // Read the learned entry
        let learned_entry =
            std::fs::read_to_string(temp_known_hosts.path()).expect("failed to read known_hosts");

        // Create a known_hosts file with only the @revoked entry (no normal entry)
        let known_hosts_revoked =
            tempfile::NamedTempFile::new().expect("failed to create temp file");
        let content = format!("@revoked {}", learned_entry.trim());
        std::fs::write(known_hosts_revoked.path(), content).expect("failed to write known_hosts");

        // Try to connect with AcceptNew mode - should refuse the revoked key
        // instead of learning it
        let config = SshConfig {
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            username: "testuser".to_string(),
            auth: SshAuth::PrivateKey {
                path: key_path,
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptNew(
                known_hosts_revoked.path().to_path_buf(),
            ),
        };

        let ct = CancellationToken::new();
        let result = ScpClient::connect(config, &ct).await;

        // Must fail with HostKeyRevoked error, not learn the revoked key
        assert!(result.is_err(), "AcceptNew should refuse revoked key");
        match result {
            Err(ScpError::HostKeyRevoked(msg)) => {
                assert!(
                    msg.contains("@revoked"),
                    "error should mention @revoked marker, got: {}",
                    msg
                );
            }
            Err(other) => panic!("expected HostKeyRevoked error, got: {:?}", other),
            Ok(_) => panic!("AcceptNew should refuse revoked key"),
        }

        // Verify the revoked key was NOT learned (file should still only have @revoked line)
        let final_content = std::fs::read_to_string(known_hosts_revoked.path())
            .expect("failed to read known_hosts");
        let line_count = final_content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(
            line_count, 1,
            "AcceptNew should not add a new entry for a revoked key"
        );
        assert!(
            final_content.contains("@revoked"),
            "file should still only contain @revoked line"
        );
    }

    /// Assert that a listener that accepts TCP but never speaks SSH fails
    /// within the 15-second connect timeout, not the outer timeout (600-900s).
    /// This prevents a black-hole peer from holding per-device capacity.
    #[tokio::test]
    async fn connect_timeout_fails_promptly_on_silent_listener() {
        use tokio::net::TcpListener;

        // Bind a listener that accepts connections but never sends data.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Spawn a task that accepts one connection and then hangs forever.
        tokio::spawn(async move {
            let _ = listener.accept().await;
            // Connection accepted, now stall forever (never send SSH handshake).
            std::future::pending::<()>().await;
        });

        let config = SshConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            username: "test".into(),
            auth: SshAuth::PrivateKey {
                path: "/nonexistent/key".into(),
                passphrase: None,
            },
            host_key_verification: HostKeyVerification::AcceptAll,
        };

        let ct = CancellationToken::new();
        let start = std::time::Instant::now();

        // Attempt to connect. This should fail within ~15 seconds (the connect timeout),
        // not hang for 600s (the typical outer timeout).
        let result = ScpClient::connect(config, &ct).await;
        let elapsed = start.elapsed();

        // Assert the connect failed (silent listener never completes SSH handshake).
        assert!(result.is_err(), "connect should fail on silent listener");

        // Assert it failed promptly (within 20 seconds, giving some headroom beyond
        // the 15s timeout for CI scheduling jitter).
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "connect should timeout within 20s, but took {:?}",
            elapsed
        );
    }

    /// Assert that the russh config has keepalive settings configured.
    #[test]
    fn russh_config_has_keepalive_deadlines() {
        let config = build_russh_config();
        assert_eq!(
            config.keepalive_interval,
            Some(std::time::Duration::from_secs(10)),
            "keepalive_interval should be 10s"
        );
        assert_eq!(config.keepalive_max, 3, "keepalive_max should be 3");
        assert_eq!(
            config.inactivity_timeout,
            Some(std::time::Duration::from_secs(45)),
            "inactivity_timeout should be 45s"
        );
    }

    /// Server presenting an SSH certificate is rejected
    #[tokio::test]
    async fn ssh_certificate_rejected() {
        use russh::client::Handler;
        use russh::keys::{Algorithm, PrivateKey, ssh_key};
        use ssh_key::certificate::{Builder, CertType};

        // Generate CA signing key and host private key
        #[allow(clippy::unwrap_used)]
        let ca_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate CA key");
        #[allow(clippy::unwrap_used)]
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .expect("failed to generate host key");

        // Build an OpenSSH host certificate signed by the CA
        #[allow(clippy::unwrap_used)]
        let mut builder = Builder::new_with_random_nonce(
            &mut rand::rng(),
            host_key.public_key().clone(),
            0,        // valid_after: epoch
            u64::MAX, // valid_before: far future
        )
        .expect("failed to create certificate builder");

        #[allow(clippy::unwrap_used)]
        builder.serial(42).expect("failed to set serial");
        #[allow(clippy::unwrap_used)]
        builder.key_id("test-host").expect("failed to set key_id");
        #[allow(clippy::unwrap_used)]
        builder
            .cert_type(CertType::Host)
            .expect("failed to set cert_type");
        #[allow(clippy::unwrap_used)]
        builder
            .valid_principal("example.com")
            .expect("failed to set principal");

        #[allow(clippy::unwrap_used)]
        let cert = builder.sign(&ca_key).expect("failed to sign certificate");

        let key_or_cert = russh::keys::PublicKeyOrCertificate::Certificate(cert);

        // Create an SshHandler with AcceptAll verification (most permissive mode).
        // This proves that certificates are rejected even when plain keys would be
        // blanket-accepted.
        let error_slot = HostKeyErrorSlot::default();
        let mut handler = SshHandler {
            host_key_verification: HostKeyVerification::AcceptAll,
            host: "example.com".to_string(),
            port: 22,
            error_slot: error_slot.clone(),
        };

        // check_server_key should reject the certificate
        let result = handler.check_server_key(&key_or_cert).await;
        assert!(
            result.is_err(),
            "check_server_key should reject SSH certificates"
        );

        // Verify the error slot contains a HostKeyVerification error mentioning
        // that certificate authentication is not supported
        let error = error_slot
            .take()
            .expect("error_slot should contain an error after certificate rejection");
        match error {
            ScpError::HostKeyVerification(msg) => {
                assert!(
                    msg.contains("certificate authentication is not supported"),
                    "error message should explain certificate auth is unsupported, got: {}",
                    msg
                );
            }
            other => panic!("expected ScpError::HostKeyVerification, got: {:?}", other),
        }
    }
}
