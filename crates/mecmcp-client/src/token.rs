//! Bearer token loading, delegated to the hardened `mecmcp-secret` loader.

use std::fmt;
use std::path::Path;

use mecmcp_secret::{OutboundSecret, SecretLimits, load_from_env, load_from_file};

use crate::ClientError;

/// A bearer token. `Debug` never prints the value.
#[derive(Clone)]
pub struct BearerToken(OutboundSecret);

impl BearerToken {
    /// Load from a file: must be a regular, non-symlink file, mode 0600, owned
    /// by the effective uid or root (rules enforced by `mecmcp-secret`).
    ///
    /// # Errors
    /// [`ClientError::Token`] with a message naming the path, never the value.
    pub fn from_file(path: &Path) -> Result<Self, ClientError> {
        load_from_file(path, SecretLimits::default())
            .map(Self)
            .map_err(|err| ClientError::Token(err.to_string()))
    }

    /// Load from an environment variable.
    ///
    /// # Errors
    /// [`ClientError::Token`] if the variable is unset, empty or too large.
    pub fn from_env(var: &str) -> Result<Self, ClientError> {
        load_from_env(var, SecretLimits::default())
            .map(Self)
            .map_err(|err| ClientError::Token(err.to_string()))
    }

    /// Wrap an already-loaded secret.
    #[must_use]
    pub fn from_secret(secret: OutboundSecret) -> Self {
        Self(secret)
    }

    /// The plaintext, for the `Authorization` header only.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}
