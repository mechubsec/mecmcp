//! OIDC discovery, JWKS caching, and JWT verification — the resource-server
//! core for verified human identity (MEC-386, phase 1 of MEC-351).
//!
//! This crate answers exactly one question: **given a configured issuer and
//! a bearer token, is the token a currently-valid assertion from that
//! issuer, and if so, who and what role does it name?** It does not decide
//! what a verified identity is allowed to do (that is role-to-tenant mapping,
//! phase 2), does not manage sessions (phase 3), and does not touch
//! `tokens.json`-based bearer auth in `mecmcp-auth` at all — this crate has
//! no dependency on `mecmcp-auth` and `mecmcp-auth` has none on this crate.
//! A server that never configures an issuer never links a JWT/JWKS
//! dependency into its binary in any deeper way than declaring this crate
//! optional at the workspace level; a server that does configure one gets a
//! second, independent path to a verified identity, additive to the
//! existing token store.
//!
//! # Crate boundary (resolving MEC-351's open question)
//!
//! A separate crate, not a feature-gated module inside `mecmcp-auth`. Two
//! reasons:
//!
//! 1. **Dependency graph for offline deployments.** `mecmcp-auth` is on the
//!    spine every other crate in the workspace depends on
//!    (`mecmcp-secret` → `mecmcp-auth` → `mecmcp-audit` → ...). A feature
//!    flag inside it would still mean every consumer's `Cargo.lock` resolves
//!    `jsonwebtoken` and its transitive tree, whether or not the feature is
//!    enabled — Cargo features are additive and unify across a workspace, so
//!    "off by default" does not mean "absent from the lockfile". A separate
//!    crate means a server that never configures an issuer never resolves
//!    this dependency at all.
//! 2. **Independent review and blast radius.** OIDC verification is its own
//!    security surface with its own test matrix (forged signatures, rotation,
//!    IdP outages). Keeping it in its own crate makes that surface reviewable
//!    on its own, the same reasoning the rest of the crate map already
//!    follows for `mecmcp-secret`, `mecmcp-device`, and the other leaves.
//!
//! # What this crate verifies
//!
//! - Signature, against a JWKS fetched from the issuer's discovery document
//!   and cached with a bounded refresh interval (see [`cache`]).
//! - `iss`, `aud`, `exp`, and `nbf` (when present), against the configured
//!   [`OidcConfig`].
//! - Algorithm agreement between the token's header and the matching JWK's
//!   declared algorithm, rejecting a mismatch outright (see
//!   [`verify::TokenVerifier`] for why: JWT "alg confusion").
//!
//! Every rejection reason is a distinct [`VerificationFailure`] variant —
//! never a single "auth failed" — because the audit trail this feature
//! exists to produce needs to say *why* an approval attempt was refused.
//!
//! # Offline-first
//!
//! This crate never opens a socket except through the [`fetch::KeySource`]
//! trait, and the only production implementation
//! ([`fetch::HttpKeySource`]) is built on `mecmcp-http`'s hardened client,
//! never called from this crate's own test suite. Every test in this crate
//! supplies its own in-memory `KeySource` and generates its own ephemeral
//! test keys, so `cargo test -p mecmcp-oidc` requires no network access and
//! commits no key material to the repository.

pub mod cache;
pub mod claims;
pub mod discovery;
pub mod error;
pub mod fetch;
pub mod verify;

pub use cache::CacheConfig;
pub use claims::VerifiedClaims;
pub use discovery::DiscoveryDocument;
pub use error::{FetchError, VerificationFailure};
pub use fetch::{HttpKeySource, KeySource};
pub use verify::{OidcConfig, TokenVerifier, VerifyOptions};
