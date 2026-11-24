//! Shared streamable-HTTP MCP client for mechub tooling.
//!
//! This crate holds the configuration, credential and error types; the
//! transport lands on top of them.

mod config;
mod error;
#[allow(dead_code, reason = "wired up by McpClient in the next commit")]
mod http;
mod token;
mod untrusted;

pub use config::{ClientConfig, ProtocolMode};
pub use error::ClientError;
pub use token::BearerToken;
pub use untrusted::UntrustedText;
