//! Reading, validating, hot-reloading, and atomically writing `tokens.json`.

use crate::entry::TokenEntry;
use crate::grant::{Grant, NoGrant};
use crate::scope::ScopeSet;
use crate::store::{StoreError, TokenStore};
use crate::token::TokenSecret;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Failure while reading or writing a token file.
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// The file could not be read or written.
    #[error("token file {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid JSON in the expected shape.
    #[error("token file {path} is not valid JSON: {source}")]
    Parse {
        /// The path involved.
        path: PathBuf,
        /// The underlying deserialization error.
        #[source]
        source: serde_json::Error,
    },
    /// The parsed entries did not form a valid store.
    #[error("token file {path}: {source}")]
    Store {
        /// The path involved.
        path: PathBuf,
        /// The underlying store error.
        #[source]
        source: StoreError,
    },
    /// The file's permissions are too permissive, or unreadable by this process.
    #[error("token file {path}: {detail}")]
    Permissions {
        /// The path involved.
        path: PathBuf,
        /// Operator-facing explanation including uid and mode where known.
        detail: String,
    },
}

/// The envelope version written by the first two consuming servers.
///
/// Server A accepted and wrote `1` (required, no default).
/// Server B accepted `1` or `2` and wrote `2`.
/// Files our own 0.1.0–0.1.2 releases wrote had no version field at all,
/// so we must deserialize that case successfully and treat it as this default.
const DEFAULT_STORE_VERSION: u32 = 1;

/// On-disk document shape. Both existing servers use a `tokens` array.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "G: Grant + Serialize",
    deserialize = "G: Grant + Deserialize<'de>"
))]
struct TokenDocument<G: Grant> {
    /// Envelope version, for rollback-safety to previous consuming binaries.
    ///
    /// Files written by our own 0.1.0–0.1.2 releases omitted this field;
    /// missing is treated as [`DEFAULT_STORE_VERSION`].
    #[serde(default = "default_version")]
    version: u32,
    /// Token entries.
    tokens: Vec<TokenEntry<G>>,
}

/// Serde default for the missing version field.
fn default_version() -> u32 {
    DEFAULT_STORE_VERSION
}

/// The names a token's scopes are allowed to reference.
///
/// Both registries are supplied by the caller so this crate stays
/// vendor-neutral: each consuming server has its own device inventory and its
/// own tool surface.
pub struct KnownNames<'a> {
    /// Device names present in the caller's inventory, or `None` to skip
    /// device-name validation entirely.
    ///
    /// `None` is for callers that legitimately cannot know the device set at
    /// this point — for example a CLI minting a token before the device exists
    /// in inventory. Tool names are always validated regardless, because a
    /// caller's tool surface is fixed at compile time and an unknown tool name
    /// is always a mistake.
    pub devices: Option<&'a [String]>,
    /// Tool names the caller's server actually implements. Always enforced.
    pub tools: &'a [&'a str],
}

/// Validate that a version is supported (1 or 2).
///
/// Single source of truth for supported versions, called from both read and
/// write boundaries so the two can never drift apart.
/// First key present in `raw` but gone after a round trip, as a dotted path.
///
/// Recurses through objects and positionally through arrays. Scalars are never
/// compared — only the presence of keys matters here.
fn first_dropped_key(raw: &serde_json::Value, round_tripped: &serde_json::Value) -> Option<String> {
    match (raw, round_tripped) {
        (serde_json::Value::Object(before), serde_json::Value::Object(after)) => {
            for (key, value) in before {
                match after.get(key) {
                    None => return Some(key.clone()),
                    Some(kept) => {
                        if let Some(nested) = first_dropped_key(value, kept) {
                            return Some(format!("{key}.{nested}"));
                        }
                    }
                }
            }
            None
        }
        (serde_json::Value::Array(before), serde_json::Value::Array(after)) => before
            .iter()
            .zip(after.iter())
            .enumerate()
            .find_map(|(index, (b, a))| {
                first_dropped_key(b, a).map(|nested| format!("[{index}].{nested}"))
            }),
        _ => None,
    }
}

fn check_supported_version(version: u32, path: &Path) -> Result<(), FileError> {
    if version != 1 && version != 2 {
        return Err(FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                "unsupported store version {version}, supported versions: 1, 2"
            ))),
        });
    }
    Ok(())
}

/// A token file plus the store parsed from it, swappable on reload.
#[derive(Debug)]
pub struct TokenStoreFile<G: Grant = NoGrant> {
    path: PathBuf,
    store: ArcSwap<TokenStore<G>>,
    /// The version that was read from the file; preserved on write.
    version: ArcSwap<u32>,
}

impl<G: Grant + serde::Serialize + serde::de::DeserializeOwned> TokenStoreFile<G> {
    /// Read, validate, and parse a token file.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O failure, malformed JSON, unsafe
    /// permissions, or an invalid store.
    pub fn load(path: &Path) -> Result<Self, FileError> {
        let (store, version) = Self::read_store(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            store: ArcSwap::from_pointee(store),
            version: ArcSwap::from_pointee(version),
        })
    }

    /// The current store. Cheap to clone; safe to hold across a reload.
    #[must_use]
    pub fn store(&self) -> Arc<TokenStore<G>> {
        self.store.load_full()
    }

    /// The path this file was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the file and swap the store in on success.
    ///
    /// On failure the previous store stays in place, so a bad edit delivered by
    /// `SIGHUP` cannot take the server's authentication offline.
    ///
    /// # Errors
    /// Returns [`FileError`] if the new contents are unusable.
    pub fn reload(&self) -> Result<(), FileError> {
        let (store, version) = Self::read_store(&self.path)?;
        self.store.store(Arc::new(store));
        self.version.store(Arc::new(version));
        Ok(())
    }

    fn read_store(path: &Path) -> Result<(TokenStore<G>, u32), FileError> {
        // One implementation of the symlink / regular-file / mode / owner / size
        // checks, shared with `mecmcp-inventory` and `mecmcp-secret` (#173). The
        // copy that used to live here validated by path and then reopened by
        // name, so it carried a TOCTOU race, enforced no ownership, rejected no
        // symlinks, and bounded nothing.
        let bytes = mecmcp_secret::read_hardened_file(path, token_file_limits())
            .map_err(|source| map_secret_error(path, source))?;

        // Borrowed, not copied: `SecretBytes` zeroizes on drop, and a `String`
        // built from it would be a second unzeroized copy of the token file.
        // `Io`/`InvalidData`, not `Permissions`: nothing about the file's mode
        // or owner is wrong. Reporting corruption as a permissions failure sends
        // an operator to chmod a file that needs repairing. This is the
        // classification the previous `read_to_string` produced.
        let body = std::str::from_utf8(bytes.expose()).map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })?;

        let document: TokenDocument<G> =
            serde_json::from_str(body).map_err(|source| FileError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        check_supported_version(document.version, path)?;
        Self::reject_dropped_grant_fields(path, body, &document)?;

        let store = TokenStore::try_new(document.tokens).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;
        Ok((store, document.version))
    }

    /// Refuse a store holding a grant field this binary would silently drop.
    ///
    /// Every mutation deserializes the whole document into `G` and reserializes
    /// it, so a field `G` does not know about disappears on the next write. If
    /// that field encoded a *restriction* and its absence reads as permissive,
    /// the rewrite widens the token's authority — with nothing in the output to
    /// say so.
    ///
    /// `#[serde(deny_unknown_fields)]` on the grant prevents this, and
    /// [`crate::StoredGrant`] tells implementors to use it, but a trait bound
    /// cannot require it: the blanket impl accepts any serializable [`Grant`].
    /// So the guarantee is enforced here instead, where it holds for every
    /// consumer whether or not they read the docs.
    ///
    /// Compares only which *keys survive* the round trip, never their values, so
    /// a grant whose serializer normalises a scalar is not flagged. Reports the
    /// first casualty by dotted path.
    fn reject_dropped_grant_fields(
        path: &Path,
        body: &str,
        document: &TokenDocument<G>,
    ) -> Result<(), FileError> {
        let raw: serde_json::Value =
            serde_json::from_str(body).map_err(|source| FileError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        let Some(raw_tokens) = raw.get("tokens").and_then(serde_json::Value::as_array) else {
            return Ok(());
        };

        let invalid = |message: String| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(message)),
        };

        for (index, raw_token) in raw_tokens.iter().enumerate() {
            let Some(raw_grant) = raw_token.get("grant") else {
                continue;
            };
            if raw_grant.is_null() {
                continue;
            }
            let Some(entry) = document.tokens.get(index) else {
                continue;
            };
            let name = entry.name.as_str();

            let Some(grant) = entry.grant.as_ref() else {
                return Err(invalid(format!(
                    "token '{name}' carries a grant this build cannot represent;                      refusing to rewrite the file and drop it"
                )));
            };

            let round_tripped = serde_json::to_value(grant).map_err(|error| {
                invalid(format!("token '{name}' grant is not serializable: {error}"))
            })?;

            if let Some(field) = first_dropped_key(raw_grant, &round_tripped) {
                return Err(invalid(format!(
                    "token '{name}' grant has field '{field}' that this build does not                      understand and would discard on the next write. Upgrade the binary,                      or add #[serde(deny_unknown_fields)] to the grant so this fails at                      parse time"
                )));
            }
        }
        Ok(())
    }

    /// Add one scoped token and return its one-time plaintext.
    ///
    /// # Errors
    /// Returns [`FileError`] if the name already exists, if the scopes reference
    /// unknown devices or tools, or on I/O or validation failure.
    pub fn add(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        Self::add_with_options(
            path, name, devices, tools, None, None, None, None, None, None, None, known,
        )
    }

    /// Add one token with optional expiry, grant, and provenance.
    ///
    /// # Errors
    /// Returns [`FileError`] if the name already exists, if the scopes reference
    /// unknown devices or tools, or on I/O or validation failure.
    #[allow(clippy::too_many_arguments)]
    pub fn add_with_options(
        path: &Path,
        name: &str,
        devices: ScopeSet,
        tools: ScopeSet,
        expires_at: Option<DateTime<Utc>>,
        grant: Option<G>,
        provider: Option<String>,
        provider_tier: Option<crate::Tier>,
        on_behalf_of: Option<String>,
        actor_type: Option<crate::ActorType>,
        oidc_subject: Option<crate::entry::OidcSubject>,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        use crate::token::TokenSecret;

        let (current, version) = if path.exists() {
            Self::read_store(path)?
        } else {
            (TokenStore::default(), DEFAULT_STORE_VERSION)
        };

        if current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Duplicate(format!("token '{name}' already exists")),
            });
        }

        let (secret, digest) = TokenSecret::mint().map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error.to_string())),
        })?;

        let mut entries = current.entries().to_vec();
        entries.push(TokenEntry {
            name: name.to_owned(),
            digest,
            devices,
            tools,
            created_at: Utc::now(),
            expires_at,
            grant,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type: actor_type.unwrap_or(crate::ActorType::Unknown),
            oidc_subject,
        });

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        let minted = updated
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(
                    "minted token missing from store".to_owned(),
                )),
            })?;
        validate_scope_agreement(minted).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries(), version)?;
        Ok(secret)
    }

    /// Atomically replace one token digest while preserving its scopes.
    ///
    /// # Errors
    /// Returns [`FileError`] if the named token does not exist, or on I/O or
    /// validation failure.
    pub fn rotate(
        path: &Path,
        name: &str,
        known: &KnownNames<'_>,
    ) -> Result<TokenSecret, FileError> {
        use crate::token::TokenSecret;

        let (current, version) = Self::read_store(path)?;

        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' does not exist"
                ))),
            });
        }

        let (secret, new_digest) = TokenSecret::mint().map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error.to_string())),
        })?;

        let entries: Vec<TokenEntry<G>> = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: new_digest.clone(),
                        devices: entry.devices.clone(),
                        tools: entry.tools.clone(),
                        // Preserved, not regenerated. Rotation replaces the
                        // secret; it does not create a new credential. Resetting
                        // this would erase when the token was first issued, so a
                        // quarterly-rotated token would always look new — and
                        // "how long has this credential existed" is exactly the
                        // question an audit asks.
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        grant: entry.grant.clone(),
                        provider: entry.provider.clone(),
                        provider_tier: entry.provider_tier,
                        on_behalf_of: entry.on_behalf_of.clone(),
                        actor_type: entry.actor_type,
                        oidc_subject: entry.oidc_subject.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries(), version)?;
        Ok(secret)
    }

    /// Narrow or widen an existing token's scopes without touching its secret.
    ///
    /// Pass `None` for a field to leave it unchanged; `Some(value)` replaces it.
    /// All `None` is a no-op write-through. This can widen as well as narrow;
    /// widening is a privilege escalation that belongs behind whatever
    /// authorization the calling CLI enforces.
    ///
    /// `grant` covers the consumer's own scope — `allowed_xpath_roots` and
    /// `actions` on PAN-OS. Without it this method could not adjust the scope
    /// operators most often need to change, because that is the one encoding
    /// device config paths, and those grow with the deployment (#163). The
    /// alternatives were all wrong: `rotate` and `revoke`+`add` mint a new
    /// secret, forcing every registered client to be reconfigured, and
    /// hand-editing `tokens.json` bypasses the validation performed here.
    ///
    /// # Errors
    /// Returns [`FileError`] if the named token does not exist, if the scopes
    /// reference unknown devices or tools, or on I/O or validation failure.
    pub fn set_scopes(
        path: &Path,
        name: &str,
        devices: Option<ScopeSet>,
        tools: Option<ScopeSet>,
        grant: Option<G>,
        known: &KnownNames<'_>,
    ) -> Result<(), FileError> {
        let (current, version) = Self::read_store(path)?;

        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' does not exist"
                ))),
            });
        }

        let entries: Vec<TokenEntry<G>> = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: entry.digest.clone(),
                        devices: devices.clone().unwrap_or_else(|| entry.devices.clone()),
                        tools: tools.clone().unwrap_or_else(|| entry.tools.clone()),
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        grant: grant.clone().or_else(|| entry.grant.clone()),
                        provider: entry.provider.clone(),
                        provider_tier: entry.provider_tier,
                        on_behalf_of: entry.on_behalf_of.clone(),
                        actor_type: entry.actor_type,
                        oidc_subject: entry.oidc_subject.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        validate_references(&updated, known).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        let changed = updated
            .entries()
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' missing from store after scope change"
                ))),
            })?;
        validate_scope_agreement(changed).map_err(|error| FileError::Store {
            path: path.to_path_buf(),
            source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
        })?;

        write_atomic(path, updated.entries(), version)?;
        Ok(())
    }

    /// Replace an existing token's provenance without touching its secret.
    ///
    /// The mirror of [`set_scopes`](Self::set_scopes), and it exists for the
    /// same reason that one does: every alternative mints a new secret and so
    /// forces every registered client to be reconfigured, while hand-editing
    /// `tokens.json` keeps the secret but skips the validation performed here
    /// (#289). Two rules in particular are easy to get wrong by hand — a
    /// present-but-empty field, and a `provider` alongside `actor_type: human` —
    /// and both are discovered at next start, on a credential file, which is the
    /// worst place to find out.
    ///
    /// All four fields are replaced, not merged: `None` clears. Deciding whether
    /// a clear was intended is the caller's job, because only the CLI layer can
    /// distinguish an omitted flag from a deliberate one.
    ///
    /// Unlike `set_scopes`, this does not re-check device and tool references.
    /// The scopes are copied through untouched, so re-validating them could only
    /// fail for a reason unrelated to this change — a device that has since left
    /// the inventory would make an existing token permanently untaggable, and
    /// tagging the existing fleet is the entire purpose of this call. Entry
    /// validation still runs via [`TokenStore::try_new`], which is what enforces
    /// the provenance rules themselves.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O or validation failure, or if `name` does not
    /// exist in the store.
    pub fn set_provenance(
        path: &Path,
        name: &str,
        provider: Option<String>,
        provider_tier: Option<crate::Tier>,
        on_behalf_of: Option<String>,
        actor_type: Option<crate::ActorType>,
    ) -> Result<(), FileError> {
        let (current, version) = Self::read_store(path)?;

        if !current.entries().iter().any(|entry| entry.name == name) {
            return Err(FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(format!(
                    "token '{name}' does not exist"
                ))),
            });
        }

        let entries: Vec<TokenEntry<G>> = current
            .entries()
            .iter()
            .map(|entry| {
                if entry.name == name {
                    TokenEntry {
                        name: entry.name.clone(),
                        digest: entry.digest.clone(),
                        devices: entry.devices.clone(),
                        tools: entry.tools.clone(),
                        created_at: entry.created_at,
                        expires_at: entry.expires_at,
                        grant: entry.grant.clone(),
                        provider: provider.clone(),
                        provider_tier,
                        on_behalf_of: on_behalf_of.clone(),
                        actor_type: actor_type.unwrap_or_default(),
                        oidc_subject: entry.oidc_subject.clone(),
                    }
                } else {
                    entry.clone()
                }
            })
            .collect();

        let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
            path: path.to_path_buf(),
            source,
        })?;

        write_atomic(path, updated.entries(), version)?;
        Ok(())
    }

    /// Idempotently revoke one named token.
    ///
    /// # Errors
    /// Returns [`FileError`] on I/O or validation failure. Returns `Ok(false)`
    /// if the token was not present.
    pub fn revoke(path: &Path, name: &str, known: &KnownNames<'_>) -> Result<bool, FileError> {
        let (current, version) = Self::read_store(path)?;
        let mut entries = current.entries().to_vec();
        let before = entries.len();
        entries.retain(|entry| entry.name != name);
        let removed = before != entries.len();

        if removed {
            let updated = TokenStore::try_new(entries).map_err(|source| FileError::Store {
                path: path.to_path_buf(),
                source,
            })?;

            validate_references(&updated, known).map_err(|error| FileError::Store {
                path: path.to_path_buf(),
                source: StoreError::Entry(crate::entry::EntryError::Invalid(error)),
            })?;

            write_atomic(path, updated.entries(), version)?;
        }

        Ok(removed)
    }
}

/// Write entries to `path` atomically, via a same-directory temporary file.
///
/// The version is preserved from the file that was read, so a previous
/// consuming binary can still parse our output.
///
/// # Errors
/// Returns [`FileError`] on serialization, I/O failure, or if the version
/// is unsupported (anything other than 1 or 2). An unsupported version is
/// rejected before any filesystem operation, so a bad call touches nothing.
pub fn write_atomic<G: Grant + serde::Serialize>(
    path: &Path,
    entries: &[TokenEntry<G>],
    version: u32,
) -> Result<(), FileError> {
    // Validate version before doing any filesystem work, so we cannot produce
    // a file our own loader would refuse.
    check_supported_version(version, path)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let document = TokenDocument {
        version,
        tokens: entries.to_vec(),
    };
    let body = serde_json::to_vec_pretty(&document).map_err(|source| FileError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let mut temp = tempfile::Builder::new()
        .prefix(".tokens-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|source| FileError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o600)).map_err(
            |source| FileError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }

    use std::io::Write as _;
    temp.write_all(&body).map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    temp.as_file().sync_all().map_err(|source| FileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // Preserve the destination's owner across the replacement.
    //
    // The atomic write replaces the file, so without this the new file is owned
    // by whoever ran the command. An operator minting a token as root — which is
    // exactly what the install instructions tell them to do — would hand the
    // service a tokens.json it cannot read, and the server then refuses to start
    // with a permission error that does not name ownership as the cause. It is
    // on the first-run path of every deployment.
    //
    // Best-effort by design: if the destination does not exist there is nothing
    // to preserve, and if we lack the privilege to chown we are almost certainly
    // already running as the owning user, so the file is correct anyway.
    //
    // Only call chown when it would change something: under a systemd unit with
    // SystemCallFilter=~@privileged, the call is fatal with SIGSYS rather than
    // refused with EPERM, and `let _ =` cannot catch a signal.
    #[cfg(unix)]
    if let Ok(destination_meta) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        let (destination_uid, destination_gid) = (destination_meta.uid(), destination_meta.gid());

        // Stat the temp file to get its actual ownership. In a setgid parent
        // directory, the kernel may give the temp a GID that differs from the
        // process's effective GID.
        if let Ok(temp_meta) = std::fs::metadata(temp.path()) {
            let (temp_uid, temp_gid) = (temp_meta.uid(), temp_meta.gid());

            if needs_ownership_change(temp_uid, temp_gid, destination_uid, destination_gid) {
                let _ = std::os::unix::fs::chown(
                    temp.path(),
                    Some(destination_uid),
                    Some(destination_gid),
                );
            }
        }
    }

    temp.persist(path).map_err(|error| FileError::Io {
        path: path.to_path_buf(),
        source: error.error,
    })?;
    Ok(())
}
/// Refuse a token whose two target scopes contradict each other.
///
/// When a grant's subjects name targets — org/site UUIDs, tenants — they are
/// the same namespace `devices` names, and a `ScopeSet::Wildcard` there makes
/// the early preflight check pass for any target. Reach is then enforced in
/// exactly one place, the handler's grant check, and the layer that fails
/// closed *first* is inert. That is a live deployment shape today
/// (rustmistmcp#17), and it looks identical to a correctly narrowed token.
///
/// Deliberately **not** part of [`validate_references`]: that runs on `rotate`
/// and `revoke` too, and refusing to rotate an existing token's secret because
/// of a scope shape it already has would turn an emergency rotation into an
/// outage. This runs only where scopes are chosen — `add` and `set_scopes`.
///
/// It takes **one entry**, not the store, for the same reason. A file is
/// allowed to contain the legacy shape; validating every entry on each mutation
/// would let one such token block every other token's mint and scope change,
/// and would make two of them unfixable — narrowing either still trips over the
/// one left untouched. Only the entry being written is this check's business.
///
/// Grants whose subjects are regions *within* a target (PAN-OS XPaths) are a
/// different axis and are unaffected; see [`Grant::subjects_are_targets`].
fn validate_scope_agreement<G: Grant>(entry: &TokenEntry<G>) -> Result<(), String> {
    let target_scoped_grant = entry
        .grant
        .as_ref()
        .is_some_and(Grant::subjects_are_targets);
    if target_scoped_grant && matches!(entry.devices, ScopeSet::Wildcard) {
        return Err(format!(
            "token '{}' pairs a wildcard target scope with a grant that names specific \
             targets; narrow the scope to the grant's subjects so both layers agree",
            entry.name
        ));
    }
    Ok(())
}

/// Validate device and tool references against the known registries.
///
/// Reference-validation is deliberately NOT run during [`TokenStoreFile::load`],
/// only during the mutating operations that mint new scopes. Running it on
/// every load would mean a device decommissioned from the inventory would stop
/// every token in the file from loading and take authentication offline
/// server-wide. Catching a typo when a token is minted is worth it; refusing to
/// start because inventory drifted is not.
fn validate_references<G: Grant>(
    store: &TokenStore<G>,
    known: &KnownNames<'_>,
) -> Result<(), String> {
    for entry in store.entries() {
        if let ScopeSet::Allowlist(devices) = &entry.devices {
            // Only validate device names if Some(...) was provided.
            // None means skip device-name checks entirely.
            if let Some(known_devices) = known.devices {
                for device in devices {
                    if !known_devices.iter().any(|known| known == device) {
                        return Err(format!(
                            "token '{}' references unknown device '{device}'",
                            entry.name
                        ));
                    }
                }
            }
        }
        if let ScopeSet::Allowlist(tools) = &entry.tools {
            // Tool validation is always enforced.
            for tool in tools {
                if !known.tools.iter().any(|known| known == tool) {
                    return Err(format!(
                        "token '{}' references unknown tool '{tool}'",
                        entry.name
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Size ceiling for a token file.
///
/// Deliberately **not** `SecretLimits`, which is sized for a single credential
/// at 8 KiB. LXC 609's live `tokens.json` measured 7614 bytes, so the secret
/// ceiling would have left that server a handful of tokens from refusing to
/// start — presenting as corruption rather than as a limit.
fn token_file_limits() -> mecmcp_secret::FileLimits {
    mecmcp_secret::FileLimits::default()
}

/// Translate a hardening failure into this crate's existing error surface.
///
/// No new `FileError` variant: both shipping servers pin this crate and may
/// match exhaustively, so the public enum stays as it is (#173).
fn map_secret_error(path: &Path, source: mecmcp_secret::SecretError) -> FileError {
    use mecmcp_secret::SecretError;

    match source {
        // The original `io::Error` is moved through, not restringified. Callers
        // branch on `kind()` — a missing token file must stay `NotFound`, and
        // flattening everything to `Other` would have them report a chmod
        // problem for a path that does not exist.
        SecretError::FileIo { source, .. } => FileError::Io {
            path: path.to_path_buf(),
            source,
        },
        // Everything else is a refusal to trust the file, which is what
        // `Permissions` has always meant here. `SecretError`'s own messages
        // already name the mode, owner and remedy.
        other => FileError::Permissions {
            path: path.to_path_buf(),
            detail: other.to_string(),
        },
    }
}

/// Result of resolving a token file path with fallback.
///
/// Contains the path to use and metadata about whether the fallback was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTokenPath {
    /// The path to use for the token file.
    pub path: PathBuf,
    /// Whether the fallback path was used instead of the primary.
    pub used_fallback: bool,
    /// The path that was checked for fallback, if any.
    pub fallback_from: Option<PathBuf>,
}

/// Resolve a token file path with fallback support.
///
/// This function implements a read-only resolution strategy to locate token files
/// that may have been moved between `/etc` and `/var/lib` paths due to systemd
/// sandboxing (`ProtectSystem=strict` makes `/etc` read-only to the service
/// process, but startup args may still reference `/etc/<service>/tokens.json`).
///
/// ## Resolution Rules
///
/// 1. If `primary` exists → use it, `used_fallback: false`
/// 2. Else if `fallback` exists → use it, `used_fallback: true`,
///    `fallback_from: Some(primary)`
/// 3. Else → return `primary` (the caller will create it there), `used_fallback: false`
///
/// ## Error Handling
///
/// **This function surfaces permission and access errors instead of silently
/// falling back.** If the primary path exists but metadata retrieval fails
/// (e.g., EACCES from a restrictive parent directory), the error is returned
/// rather than silently choosing the fallback. This prevents the service from
/// loading stale credentials from a deprecated fallback when the real problem
/// is a permission issue on the canonical path.
///
/// Only `NotFound` errors trigger fallback. Any other I/O error is surfaced.
///
/// ## Important: Read-Only Operation
///
/// **This function NEVER copies, moves, writes, or creates anything.** A silent copy
/// would leave a stale credential file behind — exactly the defect this mechanism
/// is designed to prevent. All file system operations are read-only existence checks.
///
/// The caller is responsible for:
/// - Logging a warning if `used_fallback` is true (include both `path` and
///   `fallback_from` so operators know which file was chosen and which was missing)
/// - Creating the file at the resolved path if it doesn't exist
///
/// ## Example
///
/// ```no_run
/// use mecmcp_auth::file::resolve_token_path;
/// use std::path::Path;
///
/// let primary = Path::new("/var/lib/rust-junosmcp/tokens.json");
/// let fallback = Path::new("/etc/rust-junosmcp/tokens.json");
///
/// let resolved = resolve_token_path(primary, fallback)?;
///
/// if resolved.used_fallback {
///     eprintln!(
///         "Warning: using fallback token file at {} (primary {} does not exist)",
///         resolved.path.display(),
///         resolved.fallback_from.as_ref().unwrap().display()
///     );
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn resolve_token_path(primary: &Path, fallback: &Path) -> std::io::Result<ResolvedTokenPath> {
    // Use metadata instead of exists() to detect permission errors.
    // Only fall back if the primary is truly absent (NotFound), not if
    // stat fails with EACCES or other errors.
    match std::fs::metadata(primary) {
        Ok(_) => {
            // Primary exists and is accessible, use it
            Ok(ResolvedTokenPath {
                path: primary.to_path_buf(),
                used_fallback: false,
                fallback_from: None,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Primary not found, try fallback
            match std::fs::metadata(fallback) {
                Ok(_) => {
                    // Fallback exists, use it
                    Ok(ResolvedTokenPath {
                        path: fallback.to_path_buf(),
                        used_fallback: true,
                        fallback_from: Some(primary.to_path_buf()),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Neither exists, return primary so caller can create it there
                    Ok(ResolvedTokenPath {
                        path: primary.to_path_buf(),
                        used_fallback: false,
                        fallback_from: None,
                    })
                }
                Err(e) => {
                    // Fallback exists but cannot be accessed - surface the error
                    Err(e)
                }
            }
        }
        Err(e) => {
            // Primary exists but cannot be accessed (EACCES, etc.) - surface the error
            // instead of silently falling back to potentially stale credentials
            Err(e)
        }
    }
}

/// Returns whether a chown syscall is needed to align the replacement file's
/// ownership with the destination file.
///
/// Compares the replacement inode's actual (uid, gid) against the destination's
/// (uid, gid). In a setgid parent directory the kernel may give a newly created
/// file the directory's GID rather than the process's effective GID, so comparing
/// against `getegid()` would be wrong.
///
/// A service writing its own state file needs no chown, and under a systemd
/// `SystemCallFilter=~@privileged` the call is fatal with SIGSYS, not refused
/// with EPERM. Only call chown when it would change something.
#[cfg(unix)]
fn needs_ownership_change(
    replacement_uid: u32,
    replacement_gid: u32,
    destination_uid: u32,
    destination_gid: u32,
) -> bool {
    replacement_uid != destination_uid || replacement_gid != destination_gid
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::grant::GrantError;
    use std::io::Write;

    const TWO_TOKENS: &str = r#"{
        "tokens": [
            {
                "name": "reader",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["edge-fw"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            },
            {
                "name": "writer",
                "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "routers": ["*"],
                "tools": ["load_and_commit_config"],
                "created_at": "2026-07-12T10:00:00Z"
            }
        ]
    }"#;

    /// Capabilities gained by adopting the shared reader (#173).
    ///
    /// The previous local check validated by path and reopened by name — a
    /// TOCTOU race — and enforced no ownership, rejected no symlinks, and bounded
    /// nothing.
    #[allow(clippy::unwrap_used)]
    mod hardening {
        use super::*;

        #[cfg(unix)]
        #[test]
        fn rejects_a_symlinked_token_file() {
            let dir = tempfile::tempdir().unwrap();
            let real = write_file(&dir, TWO_TOKENS);
            let link = dir.path().join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();

            let error = TokenStoreFile::<NoGrant>::load(&link).unwrap_err();
            assert!(
                matches!(error, FileError::Permissions { .. }),
                "a symlinked token file must be refused, got {error:?}"
            );
            assert!(error.to_string().contains("symlink"), "{error}");
        }

        #[cfg(unix)]
        #[test]
        fn still_rejects_group_or_world_accessible() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = write_file(&dir, TWO_TOKENS);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

            let error = TokenStoreFile::<NoGrant>::load(&path).unwrap_err();
            assert!(
                matches!(error, FileError::Permissions { .. }),
                "got {error:?}"
            );
        }

        #[test]
        fn rejects_a_token_file_over_the_size_limit() {
            let dir = tempfile::tempdir().unwrap();
            let limit = token_file_limits().max_bytes;
            // Valid JSON so the rejection can only come from the size bound.
            let padding = " ".repeat(limit + 1);
            let path = write_file(&dir, &format!("{TWO_TOKENS}{padding}"));

            let error = TokenStoreFile::<NoGrant>::load(&path).unwrap_err();
            assert!(
                matches!(error, FileError::Permissions { .. }),
                "got {error:?}"
            );
            assert!(error.to_string().contains("limit is"), "{error}");
        }

        /// A missing file must stay `NotFound`.
        ///
        /// Callers branch on `kind()`. Flattening every I/O failure to `Other`
        /// would have them report a chmod problem for a path that does not
        /// exist.
        #[test]
        fn a_missing_file_preserves_not_found() {
            let dir = tempfile::tempdir().unwrap();
            let missing = dir.path().join("absent.json");

            let error = TokenStoreFile::<NoGrant>::load(&missing).unwrap_err();
            match error {
                FileError::Io { source, .. } => {
                    assert_eq!(source.kind(), std::io::ErrorKind::NotFound, "{source:?}");
                }
                other => panic!("expected Io/NotFound, got {other:?}"),
            }
        }

        /// Corruption is not a permissions problem.
        ///
        /// A non-UTF-8 token file used to surface as `Io`/`InvalidData`.
        /// Reporting it as `Permissions` would send an operator to chmod a file
        /// that needs repairing.
        #[test]
        fn non_utf8_is_reported_as_invalid_data_not_permissions() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tokens.json");
            std::fs::write(&path, b"\xC3\x28 not utf8").unwrap();
            // Unix-gated: `PermissionsExt` does not exist elsewhere, and the
            // fallback reader has no mode check to satisfy anyway.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }

            let error = TokenStoreFile::<NoGrant>::load(&path).unwrap_err();
            match error {
                FileError::Io { source, .. } => {
                    assert_eq!(source.kind(), std::io::ErrorKind::InvalidData, "{source:?}");
                }
                other => panic!("expected Io/InvalidData, got {other:?}"),
            }
        }

        /// The limit must stay document-sized. 609's live `tokens.json` is 7614
        /// bytes; `SecretLimits`' 8192 ceiling would have been a live hazard.
        #[test]
        fn size_limit_is_document_sized() {
            assert!(token_file_limits().max_bytes >= 1024 * 1024);
        }

        /// A real token file from LXC 609 is 7614 bytes and must load.
        #[test]
        fn a_file_the_size_of_the_live_one_loads() {
            let dir = tempfile::tempdir().unwrap();
            let padding = " ".repeat(7614usize.saturating_sub(TWO_TOKENS.len()));
            let path = write_file(&dir, &format!("{TWO_TOKENS}{padding}"));
            assert!(TokenStoreFile::<NoGrant>::load(&path).is_ok());
        }
    }

    fn write_file(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("tokens.json");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        path
    }

    #[test]
    fn loads_a_file_mixing_both_on_disk_shapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);
    }

    #[test]
    fn a_missing_file_is_an_io_error_naming_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.json");
        let err = TokenStoreFile::<NoGrant>::load(&path).expect_err("should fail");
        assert!(err.to_string().contains("absent.json"));
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "{ not json");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Parse { .. })
        ));
    }

    #[test]
    fn duplicate_names_surface_as_a_store_error() {
        let body = TWO_TOKENS.replace("\"writer\"", "\"reader\"");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, &body);
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Store { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(matches!(
            TokenStoreFile::<NoGrant>::load(&path),
            Err(FileError::Permissions { .. })
        ));
    }

    #[test]
    fn reload_picks_up_a_changed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 2);

        // Write a file with only the first token
        let single = r#"{
            "tokens": [
                {
                    "name": "reader",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["edge-fw"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        write_file(&dir, single);

        file.reload().expect("reload");
        assert_eq!(file.store().len(), 1);
    }

    #[test]
    fn a_failed_reload_leaves_the_previous_store_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, TWO_TOKENS);
        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        write_file(&dir, "{ not json");
        assert!(file.reload().is_err());
        assert_eq!(file.store().len(), 2, "previous store must survive");
    }

    #[test]
    fn atomic_write_round_trips_through_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let file: TokenStoreFile = {
            let source = write_file(&dir, TWO_TOKENS);
            TokenStoreFile::load(&source).expect("load")
        };
        let version = **file.version.load();
        write_atomic(&path, file.store().entries(), version).expect("write");
        let reloaded: TokenStoreFile = TokenStoreFile::load(&path).expect("reload");
        assert_eq!(reloaded.store().len(), 2);
    }

    /// Borrowable for `'static`, so callers can write
    /// `KnownNames { devices: Some(known_devices()), .. }` without the returned
    /// `Vec` being a temporary that is dropped at the end of the statement.
    /// Returning `Vec<String>` here required every call site to borrow a
    /// temporary, which is E0716 on the crate's MSRV.
    fn known_devices() -> &'static [String] {
        static DEVICES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        DEVICES.get_or_init(|| vec!["edge-fw".to_owned(), "core-fw".to_owned()])
    }

    #[test]
    fn add_then_load_authenticates_the_minted_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            &known,
        )
        .expect("add");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        let entry = store.authenticate(secret.expose_secret()).expect("auth");
        assert_eq!(entry.name, "lab");
    }

    #[test]
    fn add_with_duplicate_name_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("first add");

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("lab"));
                assert!(err.to_string().contains("already exists"));
            }
            Ok(_) => panic!("second add should fail"),
        }
    }

    #[test]
    fn add_naming_unknown_device_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["missing-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing-fw"));
                assert!(err.to_string().contains("unknown device"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn add_naming_unknown_tool_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec!["not_a_tool".to_owned()]),
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("not_a_tool"));
                assert!(err.to_string().contains("unknown tool"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn add_with_wildcard_scopes_passes_even_when_known_lists_are_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(&[]),
            tools: &[],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("wildcard scopes bypass reference validation");

        let file: TokenStoreFile = TokenStoreFile::load(&path).expect("load");
        assert!(file.store().authenticate(secret.expose_secret()).is_some());
    }

    #[test]
    fn rotate_preserves_scopes_expiry_and_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        // Use a far-future timestamp so the token is not expired
        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        let original_secret = TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            expires_at,
            None,
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> =
            TokenStoreFile::load(&path).expect("load before rotate");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry");

        let rotated_secret =
            TokenStoreFile::<NoGrant>::rotate(&path, "lab", &known).expect("rotate");

        let after: TokenStoreFile<NoGrant> =
            TokenStoreFile::load(&path).expect("load after rotate");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry");

        // Old secret must not work
        assert!(
            store_after
                .authenticate(original_secret.expose_secret())
                .is_none(),
            "old secret must be invalidated"
        );

        // New secret must work
        assert!(
            store_after
                .authenticate(rotated_secret.expose_secret())
                .is_some(),
            "new secret must authenticate"
        );

        // All other fields must be preserved
        assert_eq!(
            entry_after.devices, entry_before.devices,
            "devices must be preserved"
        );
        assert_eq!(
            entry_after.tools, entry_before.tools,
            "tools must be preserved"
        );
        assert_eq!(
            entry_after.expires_at, entry_before.expires_at,
            "expires_at must be preserved"
        );
        assert_eq!(
            entry_after.grant, entry_before.grant,
            "grant must be preserved"
        );

        // created_at should be updated
        assert!(
            entry_after.created_at >= entry_before.created_at,
            "created_at should be refreshed"
        );
    }

    #[test]
    fn rotate_on_missing_name_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let result = TokenStoreFile::<NoGrant>::rotate(&path, "missing", &known);
        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing"));
                assert!(err.to_string().contains("does not exist"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn revoke_removes_token_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let removed = TokenStoreFile::<NoGrant>::revoke(&path, "lab", &known).expect("revoke");
        assert!(removed, "first revoke should return true");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        assert!(
            store.authenticate(secret.expose_secret()).is_none(),
            "revoked token must not authenticate"
        );

        let removed_again =
            TokenStoreFile::<NoGrant>::revoke(&path, "lab", &known).expect("revoke again");
        assert!(!removed_again, "second revoke should return false");
    }

    #[test]
    fn lifecycle_operations_write_mode_0600_with_no_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes = std::fs::read(&path).expect("read file");
        let body = String::from_utf8_lossy(&bytes);
        assert!(
            !body.contains(secret.expose_secret()),
            "plaintext secret must never appear in file"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path).expect("metadata");
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file must be mode 0600");
        }

        let rotated = TokenStoreFile::<NoGrant>::rotate(&path, "lab", &known).expect("rotate");
        let bytes_after = std::fs::read(&path).expect("read after rotate");
        let body_after = String::from_utf8_lossy(&bytes_after);
        assert!(
            !body_after.contains(rotated.expose_secret()),
            "rotated plaintext must never appear in file"
        );
    }

    #[test]
    fn set_scopes_narrows_tools_from_wildcard_and_preserves_the_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        )
        .expect("set_scopes");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();

        // Original secret must still work
        let entry = store
            .authenticate(secret.expose_secret())
            .expect("original secret must authenticate");
        assert_eq!(entry.name, "lab");

        // Tools scope must be narrowed
        assert_eq!(
            entry.tools,
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
        );

        // Devices scope must be unchanged
        assert_eq!(entry.devices, ScopeSet::Wildcard);
    }

    #[test]
    fn set_scopes_can_change_devices_and_tools_independently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        // Change only devices
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            Some(ScopeSet::Allowlist(vec!["core-fw".to_owned()])),
            None,
            None,
            &known,
        )
        .expect("set devices");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        let entry = store
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry");

        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["core-fw".to_owned()])
        );
        assert_eq!(entry.tools, ScopeSet::Wildcard);

        // Now change only tools
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        )
        .expect("set tools");

        let file_after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = file_after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry after");

        assert_eq!(
            entry_after.devices,
            ScopeSet::Allowlist(vec!["core-fw".to_owned()])
        );
        assert_eq!(
            entry_after.tools,
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
        );
    }

    #[test]
    fn set_scopes_preserves_expires_at_and_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            expires_at,
            None,
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry before");

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry after");

        assert_eq!(entry_after.expires_at, entry_before.expires_at);
        assert_eq!(entry_after.grant, entry_before.grant);
    }

    #[test]
    fn set_scopes_leaves_other_entries_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add lab");

        let secret2 = TokenStoreFile::<NoGrant>::add(
            &path,
            "ci",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            &known,
        )
        .expect("add ci");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let ci_entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "ci")
            .expect("ci before");
        let ci_digest_before = ci_entry_before.digest.clone();
        let ci_created_at_before = ci_entry_before.created_at;
        let ci_devices_before = ci_entry_before.devices.clone();
        let ci_tools_before = ci_entry_before.tools.clone();

        // Modify only lab
        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let ci_entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "ci")
            .expect("ci after");

        // ci token must be completely untouched
        assert_eq!(ci_entry_after.digest, ci_digest_before);
        assert_eq!(ci_entry_after.created_at, ci_created_at_before);
        assert_eq!(ci_entry_after.devices, ci_devices_before);
        assert_eq!(ci_entry_after.tools, ci_tools_before);

        // And its secret must still work
        assert!(store_after.authenticate(secret2.expose_secret()).is_some());
    }

    #[test]
    fn set_scopes_on_nonexistent_token_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "missing",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing"));
                assert!(err.to_string().contains("does not exist"));
            }
            Ok(_) => panic!("should fail"),
        }
    }

    #[test]
    fn set_scopes_with_unknown_device_is_rejected_and_file_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes_before = std::fs::read(&path).expect("read before");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            Some(ScopeSet::Allowlist(vec!["unknown-device".to_owned()])),
            None,
            None,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("unknown-device"));
                assert!(err.to_string().contains("unknown device"));
            }
            Ok(_) => panic!("should fail"),
        }

        let bytes_after = std::fs::read(&path).expect("read after");
        assert_eq!(
            bytes_before, bytes_after,
            "file must be unchanged after failed validation"
        );
    }

    #[test]
    fn set_scopes_with_unknown_tool_is_rejected_and_file_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let bytes_before = std::fs::read(&path).expect("read before");

        let result = TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["unknown_tool".to_owned()])),
            None,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("unknown_tool"));
                assert!(err.to_string().contains("unknown tool"));
            }
            Ok(_) => panic!("should fail"),
        }

        let bytes_after = std::fs::read(&path).expect("read after");
        assert_eq!(
            bytes_before, bytes_after,
            "file must be unchanged after failed validation"
        );
    }

    #[test]
    fn set_scopes_does_not_refresh_created_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry before");
        let created_at_before = entry_before.created_at;

        // Small delay to ensure time has advanced
        std::thread::sleep(std::time::Duration::from_millis(10));

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry after");

        assert_eq!(
            entry_after.created_at, created_at_before,
            "created_at must not be refreshed"
        );
    }

    #[test]
    fn set_scopes_with_both_none_is_a_validating_no_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        let expires_at = DateTime::from_timestamp(4_102_444_800, 0);

        let secret = TokenStoreFile::<NoGrant>::add_with_options(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            expires_at,
            None,
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry before");

        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, None, &known)
            .expect("set_scopes with both None");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry after");

        assert_eq!(entry_after.digest, entry_before.digest);
        assert_eq!(entry_after.devices, entry_before.devices);
        assert_eq!(entry_after.tools, entry_before.tools);
        assert_eq!(entry_after.created_at, entry_before.created_at);
        assert_eq!(entry_after.expires_at, entry_before.expires_at);
        assert_eq!(entry_after.grant, entry_before.grant);

        assert!(
            store_after.authenticate(secret.expose_secret()).is_some(),
            "original secret must still authenticate"
        );
    }

    /// A grant whose subjects are *targets* — org/site UUIDs, tenants — names
    /// the same namespace as `devices`. Pairing it with a wildcard `devices`
    /// scope means two authorization layers disagree, and the one that fails
    /// closed early is the inert one (rustmistmcp#17).
    ///
    /// A grant whose subjects are regions *within* a target (PAN-OS XPaths) is
    /// a different axis and is unaffected — that is what the default says.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TargetScopedGrant {
        subjects: Vec<String>,
    }
    impl Grant for TargetScopedGrant {
        type Action = ();
        fn allows_action(&self, _action: ()) -> bool {
            true
        }
        fn allows_subject(&self, subject: &str) -> bool {
            self.subjects.iter().any(|s| s == subject)
        }
        fn validate(&self) -> Result<(), GrantError> {
            Ok(())
        }
        fn subjects_are_targets(&self) -> bool {
            true
        }
    }

    fn org_grant() -> TargetScopedGrant {
        TargetScopedGrant {
            subjects: vec!["org/11111111-2222-3333-4444-555555555555".to_owned()],
        }
    }

    #[test]
    fn a_wildcard_target_scope_is_refused_beside_a_target_scoped_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None,
            tools: &["get_mist_org"],
        };

        let result = TokenStoreFile::<TargetScopedGrant>::add_with_options(
            &path,
            "acceptance",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            None,
            Some(org_grant()),
            None,
            None,
            None,
            None,
            None,
            &known,
        );

        assert!(
            result.is_err(),
            "a wildcard target scope makes the grant's org scoping unenforceable at preflight"
        );
        assert!(
            !path.exists(),
            "a refused mint must not leave a token file behind"
        );
    }

    #[test]
    fn a_matching_target_scope_is_accepted_beside_the_same_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None,
            tools: &["get_mist_org"],
        };

        TokenStoreFile::<TargetScopedGrant>::add_with_options(
            &path,
            "acceptance",
            ScopeSet::Allowlist(vec!["org/11111111-2222-3333-4444-555555555555".to_owned()]),
            ScopeSet::Wildcard,
            None,
            Some(org_grant()),
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("scopes that agree must mint");
    }

    #[test]
    fn set_scopes_cannot_widen_a_target_scope_back_to_wildcard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None,
            tools: &["get_mist_org"],
        };
        TokenStoreFile::<TargetScopedGrant>::add_with_options(
            &path,
            "acceptance",
            ScopeSet::Allowlist(vec!["org/11111111-2222-3333-4444-555555555555".to_owned()]),
            ScopeSet::Wildcard,
            None,
            Some(org_grant()),
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("add");

        let result = TokenStoreFile::<TargetScopedGrant>::set_scopes(
            &path,
            "acceptance",
            Some(ScopeSet::Wildcard),
            None,
            None,
            &known,
        );

        assert!(
            result.is_err(),
            "widening back to wildcard reopens the same disagreement the mint refuses"
        );
    }

    /// The legacy shape is deliberately still allowed to load, rotate and
    /// revoke, so a file can contain one. Validating the whole store on every
    /// mutation would make that one entry block every *other* token's mint and
    /// scope change — and, with two of them, make narrowing either one
    /// impossible, since the untouched entry keeps failing the check. Only the
    /// entry being mutated is this call's business.
    fn store_with_two_legacy_entries(path: &std::path::Path) {
        let entries: Vec<TokenEntry<TargetScopedGrant>> = ["legacy-a", "legacy-b"]
            .iter()
            .map(|name| {
                let (_secret, digest) = crate::token::TokenSecret::mint().expect("mint");
                TokenEntry {
                    name: (*name).to_owned(),
                    digest,
                    devices: ScopeSet::Wildcard,
                    tools: ScopeSet::Wildcard,
                    created_at: Utc::now(),
                    expires_at: None,
                    grant: Some(org_grant()),
                    provider: None,
                    provider_tier: None,
                    on_behalf_of: None,
                    actor_type: crate::ActorType::Human,
                    oidc_subject: None,
                }
            })
            .collect();
        write_atomic(path, &entries, DEFAULT_STORE_VERSION).expect("seed legacy store");
    }

    #[test]
    fn a_legacy_entry_does_not_block_minting_a_compliant_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        store_with_two_legacy_entries(&path);
        let known = KnownNames {
            devices: None,
            tools: &["get_mist_org"],
        };

        TokenStoreFile::<TargetScopedGrant>::add_with_options(
            &path,
            "compliant",
            ScopeSet::Allowlist(vec!["org/11111111-2222-3333-4444-555555555555".to_owned()]),
            ScopeSet::Wildcard,
            None,
            Some(org_grant()),
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("an unrelated legacy entry must not block a compliant mint");
    }

    #[test]
    fn legacy_entries_can_be_narrowed_one_at_a_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        store_with_two_legacy_entries(&path);
        let known = KnownNames {
            devices: None,
            tools: &["get_mist_org"],
        };
        let narrowed =
            ScopeSet::Allowlist(vec!["org/11111111-2222-3333-4444-555555555555".to_owned()]);

        TokenStoreFile::<TargetScopedGrant>::set_scopes(
            &path,
            "legacy-a",
            Some(narrowed.clone()),
            None,
            None,
            &known,
        )
        .expect("narrowing the first must not be blocked by the second");

        TokenStoreFile::<TargetScopedGrant>::set_scopes(
            &path,
            "legacy-b",
            Some(narrowed),
            None,
            None,
            &known,
        )
        .expect("narrowing the second must then succeed too");
    }

    #[test]
    fn set_scopes_preserves_a_non_default_grant() {
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct TestGrant {
            subjects: Vec<String>,
        }
        impl Grant for TestGrant {
            type Action = ();
            fn allows_action(&self, _action: ()) -> bool {
                true
            }
            fn allows_subject(&self, subject: &str) -> bool {
                self.subjects.iter().any(|s| s == subject)
            }
            fn validate(&self) -> Result<(), GrantError> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        let grant = TestGrant {
            subjects: vec!["/configuration".to_owned(), "/system".to_owned()],
        };

        TokenStoreFile::<TestGrant>::add_with_options(
            &path,
            "writer",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            None,
            Some(grant.clone()),
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("add");

        TokenStoreFile::<TestGrant>::set_scopes(
            &path,
            "writer",
            None,
            Some(ScopeSet::Allowlist(vec![
                "load_and_commit_config".to_owned(),
            ])),
            None,
            &known,
        )
        .expect("set_scopes");

        let after: TokenStoreFile<TestGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "writer")
            .expect("entry after");

        let grant_after = entry_after.grant.as_ref().expect("grant must be present");
        assert_eq!(grant_after, &grant, "grant must be preserved exactly");
        assert!(grant_after.allows_subject("/configuration"));
        assert!(grant_after.allows_subject("/system"));
        assert!(!grant_after.allows_subject("/other"));
    }

    #[test]
    fn version_1_round_trips_through_lifecycle_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let v1_file = r#"{
            "version": 1,
            "tokens": [
                {
                    "name": "lab",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["*"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        let path = write_file(&dir, v1_file);
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        // Run a lifecycle op (set_scopes is cheapest)
        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, None, &known)
            .expect("set_scopes");

        // Reload the raw JSON and verify version is still 1
        let body = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(
            parsed["version"], 1,
            "version 1 must be preserved, not changed"
        );
    }

    #[test]
    fn version_2_round_trips_through_lifecycle_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let v2_file = r#"{
            "version": 2,
            "tokens": [
                {
                    "name": "lab",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["*"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        let path = write_file(&dir, v2_file);
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, None, &known)
            .expect("set_scopes");

        let body = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(
            parsed["version"], 2,
            "version 2 must be preserved as 2, NOT normalised to 1"
        );
    }

    #[test]
    fn missing_version_loads_and_writes_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let no_version_file = r#"{
            "tokens": [
                {
                    "name": "lab",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["*"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        let path = write_file(&dir, no_version_file);

        // Must load successfully
        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        assert_eq!(file.store().len(), 1);

        // After a lifecycle op, version field must appear with DEFAULT_STORE_VERSION
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };
        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, None, &known)
            .expect("set_scopes");

        let body = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(
            parsed["version"], DEFAULT_STORE_VERSION,
            "missing version must write as DEFAULT_STORE_VERSION"
        );
    }

    #[test]
    fn unsupported_version_3_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let v3_file = r#"{
            "version": 3,
            "tokens": []
        }"#;
        let path = write_file(&dir, v3_file);

        let result = TokenStoreFile::<NoGrant>::load(&path);
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("3"), "error must name the found version");
                assert!(msg.contains("unsupported"), "error must say unsupported");
            }
            Ok(_) => panic!("version 3 should be rejected"),
        }
    }

    #[test]
    fn unsupported_version_0_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let v0_file = r#"{
            "version": 0,
            "tokens": []
        }"#;
        let path = write_file(&dir, v0_file);

        let result = TokenStoreFile::<NoGrant>::load(&path);
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("0"), "error must name the found version");
                assert!(msg.contains("unsupported"), "error must say unsupported");
            }
            Ok(_) => panic!("version 0 should be rejected"),
        }
    }

    #[test]
    fn brand_new_file_contains_version_1() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Wildcard,
            &known,
        )
        .expect("add");

        let body = std::fs::read_to_string(&path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("parse");
        assert_eq!(
            parsed["version"], 1,
            "brand-new file must contain version 1"
        );
    }

    #[test]
    fn version_2_file_still_parses_under_strict_envelope() {
        // This is the real regression gate: after a lifecycle op on a v2 file,
        // the resulting JSON must still parse under a strict struct that mirrors
        // the old server envelope with deny_unknown_fields.
        let dir = tempfile::tempdir().expect("tempdir");
        let v2_file = r#"{
            "version": 2,
            "tokens": [
                {
                    "name": "lab",
                    "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                    "devices": ["*"],
                    "tools": ["*"],
                    "created_at_unix": 1783850400
                }
            ]
        }"#;
        let path = write_file(&dir, v2_file);
        let known = KnownNames {
            devices: Some(known_devices()),
            tools: &["get_junos_config"],
        };

        TokenStoreFile::<NoGrant>::set_scopes(&path, "lab", None, None, None, &known)
            .expect("set_scopes");

        let bytes = std::fs::read(&path).expect("read file");

        // The strict envelope that mimics the old server's deserialization
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictEnvelope {
            version: u32,
            #[allow(dead_code)]
            tokens: serde_json::Value,
        }

        let envelope: StrictEnvelope = serde_json::from_slice(&bytes)
            .expect("v2 file must still parse under strict deny_unknown_fields envelope");
        assert_eq!(envelope.version, 2, "version must be 2 in the strict parse");
    }

    #[test]
    fn write_atomic_rejects_an_unsupported_version_without_touching_disk() {
        use crate::token::TokenSecret;

        // Guards the write boundary: read_store validates on the way in, and this
        // ensures we cannot produce a file our own loader would refuse.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");

        let (_secret, digest) = TokenSecret::mint().expect("mint");
        let entry: TokenEntry<NoGrant> = TokenEntry {
            name: "lab".to_owned(),
            digest,
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            created_at: DateTime::from_timestamp(1_783_850_400, 0).expect("timestamp"),
            expires_at: None,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: crate::ActorType::Human,
            oidc_subject: None,
        };
        let entries = vec![entry];

        // Attempt to write with unsupported version 3
        let result = write_atomic(&path, &entries, 3);

        // Must error
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("3"), "error must name the found version");
                assert!(msg.contains("unsupported"), "error must say unsupported");
            }
            Ok(_) => panic!("write_atomic with version 3 should be rejected"),
        }

        // Must not have created the file
        assert!(!path.exists(), "no file must exist after rejected write");

        // Same test with version 0
        let result_v0 = write_atomic(&path, &entries, 0);
        match result_v0 {
            Err(err) => {
                let msg = err.to_string();
                assert!(msg.contains("0"), "error must name the found version");
                assert!(msg.contains("unsupported"), "error must say unsupported");
            }
            Ok(_) => panic!("write_atomic with version 0 should be rejected"),
        }

        assert!(
            !path.exists(),
            "no file must exist after second rejected write"
        );
    }

    #[test]
    fn add_with_none_devices_allows_unknown_device_and_preserves_it() {
        // Regression gate: the exact workflow that failed in the CLI.
        // With `devices: None`, `add` must succeed for a device scope referencing
        // a device name that exists in NO inventory. The scope must survive
        // exactly as written — skipping validation is not license to silently
        // drop or rewrite.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None, // No inventory known
            tools: &["execute_junos_command_batch"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "scoped",
            ScopeSet::Allowlist(vec!["r1".to_owned()]), // r1 is not in any inventory
            ScopeSet::Allowlist(vec!["execute_junos_command_batch".to_owned()]),
            &known,
        )
        .expect("add must succeed when devices is None");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        let entry = store.authenticate(secret.expose_secret()).expect("auth");

        assert_eq!(entry.name, "scoped");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["r1".to_owned()]),
            "device scope must be preserved exactly as written"
        );
        assert_eq!(
            entry.tools,
            ScopeSet::Allowlist(vec!["execute_junos_command_batch".to_owned()])
        );
    }

    #[test]
    fn add_with_none_devices_still_rejects_unknown_tool() {
        // The asymmetry: device validation is optional, tool validation is always on.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None,
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec!["not_a_tool".to_owned()]),
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("not_a_tool"));
                assert!(err.to_string().contains("unknown tool"));
            }
            Ok(_) => panic!("unknown tool must still be rejected even when devices is None"),
        }
    }

    #[test]
    fn add_with_some_devices_still_rejects_unknown_device() {
        // Existing strict behaviour must be intact.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let devices = ["edge-fw".to_owned(), "core-fw".to_owned()];
        let known = KnownNames {
            devices: Some(&devices),
            tools: &["get_junos_config"],
        };

        let result = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["missing-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known,
        );

        match result {
            Err(err) => {
                assert!(err.to_string().contains("missing-fw"));
                assert!(err.to_string().contains("unknown device"));
            }
            Ok(_) => panic!("unknown device must be rejected when devices is Some"),
        }
    }

    #[test]
    fn add_with_none_devices_and_wildcard_device_scope_succeeds() {
        // Nothing to check either way when the scope is Wildcard.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let known = KnownNames {
            devices: None,
            tools: &["get_junos_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Wildcard,
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()]),
            &known,
        )
        .expect("wildcard device scope must succeed regardless of devices");

        let file: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load");
        let store = file.store();
        assert!(store.authenticate(secret.expose_secret()).is_some());
    }

    #[test]
    fn set_scopes_with_none_devices_allows_unknown_device_and_preserves_digest() {
        // Apply the same None case to set_scopes, not just add.
        // Narrowing a token's tools must not fail merely because the CLI lacks an inventory.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tokens.json");
        let add_devices = ["edge-fw".to_owned()];
        let known_add = KnownNames {
            devices: Some(&add_devices),
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        let secret = TokenStoreFile::<NoGrant>::add(
            &path,
            "lab",
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()]),
            ScopeSet::Wildcard,
            &known_add,
        )
        .expect("add");

        let before: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load before");
        let store_before = before.store();
        let entry_before = store_before
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry before");
        let digest_before = entry_before.digest.clone();

        // Now use set_scopes with devices: None to narrow the tools
        let known_narrow = KnownNames {
            devices: None, // No inventory available in this invocation
            tools: &["get_junos_config", "load_and_commit_config"],
        };

        TokenStoreFile::<NoGrant>::set_scopes(
            &path,
            "lab",
            None,
            Some(ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])),
            None,
            &known_narrow,
        )
        .expect("set_scopes must succeed when devices is None");

        let after: TokenStoreFile<NoGrant> = TokenStoreFile::load(&path).expect("load after");
        let store_after = after.store();
        let entry_after = store_after
            .entries()
            .iter()
            .find(|e| e.name == "lab")
            .expect("entry after");

        // Digest must be preserved (secret unchanged)
        assert_eq!(
            entry_after.digest, digest_before,
            "digest must be preserved"
        );

        // Original secret must still work
        assert!(
            store_after.authenticate(secret.expose_secret()).is_some(),
            "original secret must still authenticate"
        );

        // Tools scope must be narrowed
        assert_eq!(
            entry_after.tools,
            ScopeSet::Allowlist(vec!["get_junos_config".to_owned()])
        );

        // Devices scope must be unchanged
        assert_eq!(
            entry_after.devices,
            ScopeSet::Allowlist(vec!["edge-fw".to_owned()])
        );
    }

    // Tests for resolve_token_path

    #[test]
    fn test_resolve_token_path_primary_exists() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");

        // Create only primary
        std::fs::write(&primary, "{}").unwrap();

        let resolved = resolve_token_path(&primary, &fallback).unwrap();

        assert_eq!(resolved.path, primary);
        assert!(!resolved.used_fallback);
        assert_eq!(resolved.fallback_from, None);
    }

    #[test]
    fn test_resolve_token_path_only_fallback_exists() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");

        // Create only fallback
        std::fs::write(&fallback, "{}").unwrap();

        let resolved = resolve_token_path(&primary, &fallback).unwrap();

        assert_eq!(resolved.path, fallback);
        assert!(resolved.used_fallback);
        assert_eq!(resolved.fallback_from, Some(primary.clone()));
    }

    #[test]
    fn test_resolve_token_path_neither_exists() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");

        // Neither file exists

        let resolved = resolve_token_path(&primary, &fallback).unwrap();

        assert_eq!(resolved.path, primary);
        assert!(!resolved.used_fallback);
        assert_eq!(resolved.fallback_from, None);
    }

    #[test]
    fn test_resolve_token_path_both_exist_prefers_primary() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");

        // Create both
        std::fs::write(&primary, "{}").unwrap();
        std::fs::write(&fallback, "{}").unwrap();

        let resolved = resolve_token_path(&primary, &fallback).unwrap();

        assert_eq!(resolved.path, primary);
        assert!(!resolved.used_fallback);
        assert_eq!(resolved.fallback_from, None);
    }

    #[test]
    fn test_resolve_token_path_does_not_create_files() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary.json");
        let fallback = temp.path().join("fallback.json");

        // Create only fallback
        std::fs::write(&fallback, "{}").unwrap();

        // Call resolve
        let _resolved = resolve_token_path(&primary, &fallback).unwrap();

        // Primary should still not exist (proves no copy happened)
        assert!(
            !primary.exists(),
            "Primary path should not have been created by resolve_token_path"
        );

        // Fallback should still exist
        assert!(fallback.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_resolve_token_path_surfaces_permission_errors() {
        use std::os::unix::fs::PermissionsExt;

        // Check if running as root - root bypasses permission checks
        // We test this by creating a file with mode 000 and trying to read it
        let test_temp = tempfile::tempdir().unwrap();
        let test_file = test_temp.path().join("rootcheck");
        std::fs::write(&test_file, "test").unwrap();
        std::fs::set_permissions(&test_file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let running_as_root = std::fs::read(&test_file).is_ok();
        if running_as_root {
            eprintln!("SKIP: test requires non-root user (root bypasses mode bits)");
            return;
        }

        let temp = tempfile::tempdir().unwrap();

        // Create a subdirectory that will be made inaccessible
        let restricted_dir = temp.path().join("restricted");
        std::fs::create_dir(&restricted_dir).unwrap();

        // Create a primary file inside the restricted directory
        let primary = restricted_dir.join("tokens.json");
        std::fs::write(&primary, "{}").unwrap();

        // Create a fallback file that's accessible
        let fallback = temp.path().join("fallback.json");
        std::fs::write(&fallback, "{}").unwrap();

        // Make the directory inaccessible (mode 000 blocks stat on the file inside)
        std::fs::set_permissions(&restricted_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        // The resolver should return an error, not silently fall back to the fallback
        let result = resolve_token_path(&primary, &fallback);

        // Clean up before asserting (so temp dir can be removed)
        std::fs::set_permissions(&restricted_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        // This will fail with the current implementation because resolve_token_path
        // returns ResolvedTokenPath, not Result<ResolvedTokenPath, _>
        // After the fix, this should be an Err with PermissionDenied
        match result {
            Err(e) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied,
                    "Expected PermissionDenied error, got: {:?}",
                    e
                );
            }
            Ok(_) => {
                panic!(
                    "Expected an error when primary path is inaccessible, but got Ok. This means the resolver silently fell back to the fallback, which is the bug."
                );
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn needs_ownership_change_matches_both() {
        // When both uid and gid match, no chown needed
        assert!(!needs_ownership_change(1000, 1000, 1000, 1000));
    }

    #[test]
    #[cfg(unix)]
    fn needs_ownership_change_uid_differs() {
        // When uid differs, chown needed
        assert!(needs_ownership_change(1000, 1000, 0, 1000));
    }

    #[test]
    #[cfg(unix)]
    fn needs_ownership_change_gid_differs() {
        // When gid differs, chown needed
        assert!(needs_ownership_change(1000, 1000, 1000, 0));
    }

    #[test]
    #[cfg(unix)]
    fn needs_ownership_change_both_differ() {
        // When both differ, chown needed
        assert!(needs_ownership_change(1000, 1000, 0, 0));
    }

    #[test]
    #[cfg(unix)]
    fn needs_ownership_change_setgid_directory() {
        // Setgid case: replacement and destination both owned by service:shared (1000:50),
        // even though the process gid is 1000. The kernel gave the temp file gid 50
        // in a setgid parent. Since they match, no chown needed.
        //
        // This would fail if we compared against getegid() (1000) instead of the
        // replacement file's actual gid (50).
        let replacement_uid = 1000;
        let replacement_gid = 50; // From setgid directory
        let destination_uid = 1000;
        let destination_gid = 50; // Same group
        assert!(!needs_ownership_change(
            replacement_uid,
            replacement_gid,
            destination_uid,
            destination_gid
        ));
    }
}
