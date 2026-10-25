//! OAuth 2.1 resource-server mode (mecmcp#498). See `docs/OAUTH.md`.

mod scope_map;

pub use scope_map::{MappedAuthority, OAuthScopeMap, ScopeMapError};
