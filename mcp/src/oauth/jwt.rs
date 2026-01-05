//! JWT signing and validation for MCP-issued tokens.
//!
//! MCP issues its own access tokens to clients. These are JWTs signed with
//! HS256 using a secret key configured via environment variable.
//!
//! Upstream API tokens are stored server-side and never exposed to clients.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// MCP access token TTL (15 minutes)
pub const MCP_ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;

/// JWT claims for MCP-issued access tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpClaims {
    /// Subject (user_id from upstream, stored as UUID string)
    pub sub: String,
    /// Issuer (MCP server URL)
    pub iss: String,
    /// Audience (MCP resource identifier)
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID (unique token identifier, links to refresh token)
    pub jti: String,
    /// OAuth client ID
    pub client_id: String,
    /// Granted scope
    pub scope: String,
    /// User email (for convenience)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// User name (for convenience)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl McpClaims {
    /// Parse the user_id (sub claim) as a UUID
    pub fn user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("JWT encoding failed: {0}")]
    EncodingFailed(#[from] jsonwebtoken::errors::Error),

    #[error("JWT validation failed: {0}")]
    ValidationFailed(String),

    // Reserved for future fine-grained error handling
    #[allow(dead_code)]
    #[error("Token expired")]
    Expired,

    #[allow(dead_code)]
    #[error("Invalid audience")]
    InvalidAudience,

    #[allow(dead_code)]
    #[error("Invalid issuer")]
    InvalidIssuer,
}

/// JWT signer/validator for MCP-issued tokens
pub struct McpJwtSigner {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl McpJwtSigner {
    /// Create a new JWT signer with the given secret and server URL.
    ///
    /// # Arguments
    /// * `secret` - HS256 secret key (should be at least 32 bytes)
    /// * `server_url` - MCP server URL (used as issuer)
    pub fn new(secret: &[u8], server_url: &str) -> Self {
        let server_url = server_url.trim_end_matches('/');
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer: server_url.to_string(),
            // Audience is the MCP resource endpoint
            audience: format!("{}/mcp", server_url),
        }
    }

    /// Generate a unique token ID
    fn generate_jti() -> String {
        use rand::Rng;
        let bytes: [u8; 16] = rand::rng().random();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Sign a new MCP access token
    pub fn sign_access_token(
        &self,
        user_id: Uuid,
        client_id: &str,
        scope: &str,
        email: Option<&str>,
        name: Option<&str>,
    ) -> Result<(String, i64), JwtError> {
        let now = OffsetDateTime::now_utc();
        let exp = now.unix_timestamp() + MCP_ACCESS_TOKEN_TTL_SECS;

        let claims = McpClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp,
            iat: now.unix_timestamp(),
            jti: Self::generate_jti(),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            email: email.map(String::from),
            name: name.map(String::from),
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &self.encoding_key)?;

        Ok((token, MCP_ACCESS_TOKEN_TTL_SECS))
    }

    /// Validate an MCP access token and return its claims
    pub fn validate_access_token(&self, token: &str) -> Result<McpClaims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // Allow some clock skew (60 seconds)
        validation.leeway = 60;

        let token_data = decode::<McpClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| JwtError::ValidationFailed(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// Get the issuer URL
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get the audience URL
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_validate() {
        let secret = b"test-secret-key-at-least-32-bytes!!";
        let signer = McpJwtSigner::new(secret, "https://mcp.example.com");
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let (token, expires_in) = signer
            .sign_access_token(
                user_id,
                "client-456",
                "api",
                Some("test@example.com"),
                Some("Test User"),
            )
            .unwrap();

        assert_eq!(expires_in, MCP_ACCESS_TOKEN_TTL_SECS);

        let claims = signer.validate_access_token(&token).unwrap();
        assert_eq!(claims.sub, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(claims.client_id, "client-456");
        assert_eq!(claims.scope, "api");
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.iss, "https://mcp.example.com");
        assert_eq!(claims.aud, "https://mcp.example.com/mcp");
    }

    #[test]
    fn test_invalid_token() {
        let secret = b"test-secret-key-at-least-32-bytes!!";
        let signer = McpJwtSigner::new(secret, "https://mcp.example.com");

        let result = signer.validate_access_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let secret1 = b"test-secret-key-at-least-32-bytes!!";
        let secret2 = b"different-secret-key-32-bytes!!!!";

        let signer1 = McpJwtSigner::new(secret1, "https://mcp.example.com");
        let signer2 = McpJwtSigner::new(secret2, "https://mcp.example.com");
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let (token, _) = signer1
            .sign_access_token(user_id, "client-456", "api", None, None)
            .unwrap();

        let result = signer2.validate_access_token(&token);
        assert!(result.is_err());
    }
}
