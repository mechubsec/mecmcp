//! The identity of a caller authenticated by an OAuth access token.

/// Reserved prefix of every [`crate::CallerCtx::token_name`] minted for an OAuth caller.
///
/// [`crate::TokenEntry::validate`] refuses a static token name with this prefix, so a
/// static token and an OAuth caller can never share a name, a rate-limit bucket, or an
/// owner/approver identity key in `mecmcp-changeset`.
pub const OAUTH_TOKEN_NAME_PREFIX: &str = "oauth:";

/// Who an OAuth access token says the caller is. Deliberately three short strings and
/// nothing else: the token itself, and every other claim, are dropped after verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthIdentity {
    /// The `iss` the token was verified against.
    pub issuer: String,
    /// The token's `sub` (validated by the transport: non-empty, <= 128 bytes, no
    /// whitespace or control characters).
    pub subject: String,
    /// `client_id` / `azp`, when the token carried one.
    pub client_id: Option<String>,
}

impl OAuthIdentity {
    /// The non-secret name used for rate limiting and attribution.
    #[must_use]
    pub fn token_name(&self) -> String {
        format!("{OAUTH_TOKEN_NAME_PREFIX}{}", self.subject)
    }
}
