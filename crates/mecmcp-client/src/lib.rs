//! Shared streamable-HTTP MCP client for mechub tooling.
//!
//! [`McpClient`] speaks MCP over HTTPS only (no redirects, no proxy, no
//! skip-verify), stateless 2026-07-28 with a legacy-session fallback, with
//! bounded responses and per-call timeouts. Bearer tokens and the per-call
//! approver assertion are held in redacted secret types, and server text is
//! returned as [`UntrustedText`] so it cannot reach a terminal unescaped.

mod client;
mod config;
mod error;
mod http;
mod token;
mod untrusted;

pub use client::{McpClient, ToolOutput};
pub use config::{ClientConfig, ProtocolMode};
pub use error::ClientError;
pub use http::APPROVER_ASSERTION_HEADER;
pub use token::BearerToken;
pub use untrusted::UntrustedText;
