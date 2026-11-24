//! Shared streamable-HTTP MCP client for mechub tooling.
//!
//! This crate holds the configuration, credential and error types; the
//! transport lands on top of them.

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
