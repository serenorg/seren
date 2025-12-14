//! Token storage for OAuth2 authentication
//!
//! This module provides PostgreSQL-backed storage for OAuth2 tokens,
//! authorization codes, and client registrations.

use crate::error::{McpError, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// OAuth2 Client registration
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Client {
    pub id: String,
    pub name: String,
    pub secret_hash: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grants: Vec<String>,
    pub scopes: Vec<String>,
    // Optional metadata (RFC 7591)
    pub client_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    /// Returns true if the given redirect URI is allowed for this client.
    ///
    /// Supports exact matches and simple wildcard suffixes like `http://localhost:*`.
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        for allowed in &self.redirect_uris {
            if let Some(prefix) = allowed.strip_suffix('*') {
                if redirect_uri.starts_with(prefix) {
                    return true;
                }
            } else if allowed == redirect_uri {
                return true;
            }
        }
        false
    }
}

/// Pending OAuth authorization request (before upstream login completes).
///
/// This tracks the downstream MCP client request and the upstream PKCE verifier
/// so we can complete the code exchange on callback.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthRequest {
    pub id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub client_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub upstream_code_verifier: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Authorization code (short-lived, exchanged for tokens)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub upstream_access_token: String,
    pub upstream_refresh_token: Option<String>,
    pub upstream_expires_at: DateTime<Utc>,
}

/// Access token
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Refresh token
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshToken {
    pub token: String,
    pub access_token: String,
    pub client_id: String,
    pub user_id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Token store backed by PostgreSQL
#[derive(Clone)]
pub struct TokenStore {
    pool: PgPool,
}

impl TokenStore {
    /// Create a new token store
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect to the database and create a new token store
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(McpError::Database)?;
        Ok(Self::new(pool))
    }

    /// Get the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // === Client operations ===

    /// Get a client by ID
    pub async fn get_client(&self, client_id: &str) -> Result<Option<Client>> {
        let client = sqlx::query_as::<_, Client>(
            r#"SELECT id, name, secret_hash, redirect_uris, grants, scopes,
                      client_uri, software_id, software_version, created_at, updated_at
               FROM mcp_oauth.clients WHERE id = $1"#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(client)
    }

    // === Authorization request operations ===

    /// Save a pending authorization request
    pub async fn save_auth_request(&self, req: &AuthRequest) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.auth_requests
               (id, client_id, redirect_uri, scope, client_state, code_challenge, code_challenge_method, upstream_code_verifier, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&req.id)
        .bind(&req.client_id)
        .bind(&req.redirect_uri)
        .bind(&req.scope)
        .bind(&req.client_state)
        .bind(&req.code_challenge)
        .bind(&req.code_challenge_method)
        .bind(&req.upstream_code_verifier)
        .bind(req.expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get and consume a pending authorization request
    pub async fn consume_auth_request(&self, id: &str) -> Result<Option<AuthRequest>> {
        let req = sqlx::query_as::<_, AuthRequest>(
            r#"DELETE FROM mcp_oauth.auth_requests
               WHERE id = $1 AND expires_at > NOW()
               RETURNING id, client_id, redirect_uri, scope, client_state,
                         code_challenge, code_challenge_method, upstream_code_verifier,
                         expires_at, created_at"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(req)
    }

    // === Authorization code operations ===

    /// Save an authorization code
    pub async fn save_authorization_code(&self, code: &AuthorizationCode) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.authorization_codes
               (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method,
                expires_at, upstream_access_token, upstream_refresh_token, upstream_expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(&code.user_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.code_challenge)
        .bind(&code.code_challenge_method)
        .bind(code.expires_at)
        .bind(&code.upstream_access_token)
        .bind(&code.upstream_refresh_token)
        .bind(code.upstream_expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get and consume an authorization code (deletes it after retrieval)
    pub async fn consume_authorization_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>> {
        let auth_code = sqlx::query_as::<_, AuthorizationCode>(
            r#"DELETE FROM mcp_oauth.authorization_codes
               WHERE code = $1 AND expires_at > NOW()
               RETURNING code, client_id, user_id, redirect_uri, scope,
                         code_challenge, code_challenge_method, expires_at, created_at,
                         upstream_access_token, upstream_refresh_token, upstream_expires_at"#,
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(auth_code)
    }

    // === Access token operations ===

    /// Save an access token
    pub async fn save_access_token(&self, token: &AccessToken) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.access_tokens
               (token, client_id, user_id, scope, expires_at)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&token.token)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(&token.scope)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get an access token (validates expiry)
    pub async fn get_access_token(&self, token: &str) -> Result<Option<AccessToken>> {
        let access_token = sqlx::query_as::<_, AccessToken>(
            r#"SELECT token, client_id, user_id, scope, expires_at, created_at
               FROM mcp_oauth.access_tokens
               WHERE token = $1 AND expires_at > NOW()"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(access_token)
    }

    /// Revoke an access token
    pub async fn revoke_access_token(&self, token: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM mcp_oauth.access_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    // === Refresh token operations ===

    /// Save a refresh token
    pub async fn save_refresh_token(&self, token: &RefreshToken) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.refresh_tokens
               (token, access_token, client_id, user_id, expires_at)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&token.token)
        .bind(&token.access_token)
        .bind(&token.client_id)
        .bind(&token.user_id)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get a refresh token
    pub async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"SELECT token, access_token, client_id, user_id, expires_at, created_at
               FROM mcp_oauth.refresh_tokens
               WHERE token = $1 AND (expires_at IS NULL OR expires_at > NOW())"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(refresh_token)
    }

    /// Revoke a refresh token and its associated access token
    pub async fn revoke_refresh_token(&self, token: &str) -> Result<bool> {
        // This will cascade delete the access token due to FK constraint
        let result = sqlx::query("DELETE FROM mcp_oauth.refresh_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    // === Utility operations ===

    /// Clean up expired tokens and codes
    pub async fn cleanup_expired(&self) -> Result<()> {
        sqlx::query("SELECT mcp_oauth.cleanup_expired()")
            .execute(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(())
    }

    /// Generate a secure random token
    pub fn generate_token() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Generate a secure random authorization code
    pub fn generate_code() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Verify PKCE code challenge
    pub fn verify_pkce(code_verifier: &str, code_challenge: &str, method: Option<&str>) -> bool {
        match method {
            Some("S256") | None => {
                // S256 is the default and recommended method
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let hash = hasher.finalize();
                let computed =
                    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash);
                computed == code_challenge
            }
            Some("plain") => {
                // Plain method (not recommended but supported)
                code_verifier == code_challenge
            }
            _ => false,
        }
    }

    /// Create token expiry time
    pub fn token_expiry(duration_hours: i64) -> DateTime<Utc> {
        Utc::now() + Duration::hours(duration_hours)
    }

    /// Create authorization code expiry (short-lived, 10 minutes)
    pub fn code_expiry() -> DateTime<Utc> {
        Utc::now() + Duration::minutes(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_pkce_s256() {
        // Test vector from RFC 7636
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(TokenStore::verify_pkce(
            code_verifier,
            code_challenge,
            Some("S256")
        ));
        assert!(!TokenStore::verify_pkce(
            "wrong_verifier",
            code_challenge,
            Some("S256")
        ));
    }

    #[test]
    fn test_verify_pkce_plain() {
        let code_verifier = "test_verifier_123";
        let code_challenge = "test_verifier_123";

        assert!(TokenStore::verify_pkce(
            code_verifier,
            code_challenge,
            Some("plain")
        ));
        assert!(!TokenStore::verify_pkce(
            "wrong",
            code_challenge,
            Some("plain")
        ));
    }

    #[test]
    fn test_validate_redirect_uri_exact() {
        let client = Client {
            id: "test".into(),
            name: "Test".into(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:8080/callback".into()],
            grants: vec!["authorization_code".into()],
            scopes: vec!["api".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(client.allows_redirect_uri("http://localhost:8080/callback"));
        assert!(!client.allows_redirect_uri("http://localhost:9000/callback"));
    }

    #[test]
    fn test_validate_redirect_uri_wildcard() {
        let client = Client {
            id: "test".into(),
            name: "Test".into(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:*".into()],
            grants: vec!["authorization_code".into()],
            scopes: vec!["api".into()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(client.allows_redirect_uri("http://localhost:8080/callback"));
        assert!(client.allows_redirect_uri("http://localhost:3000"));
        assert!(!client.allows_redirect_uri("http://example.com:8080"));
    }
}
