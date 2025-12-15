//! OAuth2 implementation for hosted MCP server mode
//!
//! This module provides OAuth2 authentication for MCP clients connecting
//! to the hosted Seren MCP server. It supports:
//! - Authorization Code flow with PKCE (for public clients like Claude Desktop)
//! - Token storage in PostgreSQL
//! - Session management
//! - RFC 8414 Authorization Server Metadata
//! - RFC 7591 Dynamic Client Registration

pub(crate) mod circuit_breaker;
pub mod routes;
pub mod store;

pub use routes::{OAuthState, oauth_router};
