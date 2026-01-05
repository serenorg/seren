//! OAuth2 implementation for hosted MCP server mode
//!
//! This module provides OAuth2 authentication for MCP clients connecting
//! to the hosted Seren MCP server. It supports:
//! - Authorization Code flow with PKCE (for public clients like Claude Desktop)
//! - MCP-issued JWT access tokens (not passthrough of upstream tokens)
//! - Server-side upstream token storage for API calls
//! - Session management with database persistence
//! - RFC 8414 Authorization Server Metadata
//! - RFC 7591 Dynamic Client Registration

pub(crate) mod circuit_breaker;
pub mod jwt;
pub mod routes;
pub mod store;

pub use jwt::McpJwtSigner;
pub use routes::{OAuthState, oauth_router};
