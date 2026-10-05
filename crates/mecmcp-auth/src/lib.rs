//! Vendor-neutral bearer-token authentication, scopes, and grants.
//!
//! This crate is deliberately free of vendor concepts. It knows about tokens,
//! names, and opaque authorization subjects; it does not know what a subject
//! means to any particular device family.

pub mod approver;
pub mod bearer;
pub mod entry;
pub mod grant;
pub mod scope;
pub mod stale;
pub mod store;
pub mod token;

pub mod file;

pub use approver::{
    ApproverClaims, ApproverPolicy, BindingFailure, VerifiedApprover, bind_approver,
};
pub use bearer::{BearerHeaderError, BearerSyntax, parse_bearer_header};
pub use entry::{ActorType, EntryError, MAX_TOKEN_NAME, OidcSubject, Tier, TokenEntry};
pub use file::{
    FileError, KnownNames, ResolvedTokenPath, TokenStoreFile, resolve_token_path, write_atomic,
};
pub use grant::{Grant, GrantError, NoAction, NoGrant, StoredGrant};
pub use scope::{MAX_SCOPE_NAMES, ScopeError, ScopeSet};
pub use stale::{StaleReason, StaleSecret, find_stale_secrets};
pub use store::{
    CallerCtx, MAX_TOKENS, StoreError, TokenStore, filter_device_names, filter_target_names,
};
pub use token::{TokenDigest, TokenError, TokenSecret};
