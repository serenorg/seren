//! Token storage for OAuth2 authentication
//!
//! This module provides PostgreSQL-backed storage for OAuth2 tokens,
//! authorization codes, and client registrations.

use crate::error::{McpError, Result};
use chrono::{DateTime, Duration, Utc};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

// Token TTL constants
pub const REFRESH_TOKEN_TTL_HOURS: i64 = 168; // 7 days
pub const ACCESS_TOKEN_DEFAULT_TTL_SECS: i64 = 900; // 15 minutes

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
    /// Supports exact matches and localhost port wildcards like `http://localhost:*`.
    /// Wildcard matching is restricted to prevent security issues:
    /// - Only `http://localhost:*` or `http://127.0.0.1:*` patterns are allowed
    /// - The wildcard only matches port numbers (digits only)
    /// - Path, query, and fragment must match exactly after the port
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        for allowed in &self.redirect_uris {
            if let Some(prefix) = allowed.strip_suffix('*') {
                // Only allow localhost/127.0.0.1 wildcards for security
                if !prefix.starts_with("http://localhost:")
                    && !prefix.starts_with("http://127.0.0.1:")
                {
                    // Non-localhost wildcards not allowed
                    continue;
                }

                if let Some(remainder) = redirect_uri.strip_prefix(prefix) {
                    // Validate that what follows the prefix is a valid port (digits only)
                    // followed by optional path/query/fragment
                    let port_end = remainder
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(remainder.len());

                    // Port must be non-empty and contain only digits
                    if port_end > 0 && remainder[..port_end].chars().all(|c| c.is_ascii_digit()) {
                        // After port, only path separator or end is allowed
                        let after_port = &remainder[port_end..];
                        if after_port.is_empty()
                            || after_port.starts_with('/')
                            || after_port.starts_with('?')
                            || after_port.starts_with('#')
                        {
                            return true;
                        }
                    }
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

/// Pending consent prompt during the OAuth callback flow.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PendingConsent {
    pub id: String,
    pub user_id: String,
    pub client_id: String,
    pub authorization_code: String,
    pub redirect_uri: String,
    pub client_state: Option<String>,
    pub scope: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Token store backed by PostgreSQL with LRU cache for client metadata
#[derive(Clone)]
pub struct TokenStore {
    pool: PgPool,
    /// LRU cache for client metadata (client_id -> Client)
    /// Wrapped in Arc<Mutex<>> for interior mutability across clones
    client_cache: Arc<Mutex<LruCache<String, Client>>>,
}

impl TokenStore {
    /// Create a new token store with default cache size (100 clients)
    pub fn new(pool: PgPool) -> Self {
        Self::with_cache_size(pool, 100)
    }

    /// Create a new token store with custom cache size
    pub fn with_cache_size(pool: PgPool, cache_size: usize) -> Self {
        Self {
            pool,
            client_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap(),
            ))),
        }
    }

    /// Connect to the database and create a new token store
    /// P1 fix: Configure connection pool with proper limits
    pub async fn connect(database_url: &str) -> Result<Self> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let pool = PgPoolOptions::new()
            .max_connections(20) // Limit concurrent connections
            .min_connections(2) // Keep some connections warm
            .acquire_timeout(Duration::from_secs(10)) // Timeout for acquiring connections
            .idle_timeout(Duration::from_secs(300)) // Close idle connections after 5 minutes
            .max_lifetime(Duration::from_secs(1800)) // Recycle connections after 30 minutes
            .connect(database_url)
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
        // Check cache first
        {
            let mut cache = self.client_cache.lock().unwrap();
            if let Some(client) = cache.get(client_id) {
                return Ok(Some(client.clone()));
            }
        }

        // Cache miss - fetch from database
        let client = sqlx::query_as::<_, Client>(
            r#"SELECT id, name, secret_hash, redirect_uris, grants, scopes,
                      client_uri, software_id, software_version, created_at, updated_at
               FROM mcp_oauth.clients WHERE id = $1"#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        // Store in cache if found
        if let Some(ref c) = client {
            let mut cache = self.client_cache.lock().unwrap();
            cache.put(client_id.to_string(), c.clone());
        }

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

    /// Update a refresh token with new values (for token rotation)
    pub async fn update_refresh_token(
        &self,
        old_token: &str,
        new_token: &str,
        new_access_token: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE mcp_oauth.refresh_tokens SET token = $1, access_token = $2, expires_at = $3 WHERE token = $4",
        )
        .bind(new_token)
        .bind(new_access_token)
        .bind(expires_at)
        .bind(old_token)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    // === Consent operations ===

    /// Returns true if the given user has approved the given OAuth client.
    pub async fn is_client_approved(&self, user_id: &str, client_id: &str) -> Result<bool> {
        let exists: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM mcp_oauth.approved_clients WHERE user_id = $1 AND client_id = $2 LIMIT 1",
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(exists.is_some())
    }

    /// Records a user's approval for a given OAuth client.
    pub async fn approve_client(&self, user_id: &str, client_id: &str) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.approved_clients (user_id, client_id)
               VALUES ($1, $2)
               ON CONFLICT (user_id, client_id) DO NOTHING"#,
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Create a pending consent record.
    pub async fn save_pending_consent(&self, consent: &PendingConsent) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO mcp_oauth.pending_consents
               (id, user_id, client_id, authorization_code, redirect_uri, client_state, scope, csrf_token, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&consent.id)
        .bind(&consent.user_id)
        .bind(&consent.client_id)
        .bind(&consent.authorization_code)
        .bind(&consent.redirect_uri)
        .bind(&consent.client_state)
        .bind(&consent.scope)
        .bind(&consent.csrf_token)
        .bind(consent.expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;
        Ok(())
    }

    /// Get a pending consent record (without consuming it).
    pub async fn get_pending_consent(&self, id: &str) -> Result<Option<PendingConsent>> {
        let consent = sqlx::query_as::<_, PendingConsent>(
            r#"SELECT id, user_id, client_id, authorization_code, redirect_uri, client_state, scope, csrf_token, expires_at, created_at
               FROM mcp_oauth.pending_consents
               WHERE id = $1 AND expires_at > NOW()"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(consent)
    }

    /// Consume a pending consent record (delete and return it).
    pub async fn consume_pending_consent(&self, id: &str) -> Result<Option<PendingConsent>> {
        let consent = sqlx::query_as::<_, PendingConsent>(
            r#"DELETE FROM mcp_oauth.pending_consents
               WHERE id = $1 AND expires_at > NOW()
               RETURNING id, user_id, client_id, authorization_code, redirect_uri, client_state, scope, csrf_token, expires_at, created_at"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(consent)
    }

    /// Delete an authorization code without consuming it (used when consent is denied).
    pub async fn delete_authorization_code(&self, code: &str) -> Result<()> {
        sqlx::query("DELETE FROM mcp_oauth.authorization_codes WHERE code = $1")
            .bind(code)
            .execute(&self.pool)
            .await
            .map_err(McpError::Database)?;
        Ok(())
    }

    // === Utility operations ===

    /// Clean up expired tokens and codes with optional batch limit
    /// Returns the number of records deleted
    pub async fn cleanup_expired(&self, batch_limit: Option<i32>) -> Result<i64> {
        let limit = batch_limit.unwrap_or(1000);

        let row: (i32,) = sqlx::query_as("SELECT mcp_oauth.cleanup_expired($1)")
            .bind(limit)
            .fetch_one(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(row.0 as i64)
    }

    /// Health check: verify database connectivity
    /// Returns Ok(()) if the database is accessible
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(McpError::Database)?;
        Ok(())
    }

    /// Generate a secure random token
    pub fn generate_token() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::rng().random();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Generate a secure random authorization code
    pub fn generate_code() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::rng().random();
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
            client_uri: None,
            software_id: None,
            software_version: None,
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
            client_uri: None,
            software_id: None,
            software_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Valid localhost wildcards
        assert!(client.allows_redirect_uri("http://localhost:8080/callback"));
        assert!(client.allows_redirect_uri("http://localhost:3000"));
        assert!(client.allows_redirect_uri("http://localhost:3000/"));
        assert!(client.allows_redirect_uri("http://localhost:3000?foo=bar"));

        // Security: reject non-localhost
        assert!(!client.allows_redirect_uri("http://example.com:8080"));

        // Security: reject host injection attacks
        assert!(!client.allows_redirect_uri("http://localhost:8080@evil.com"));
        assert!(!client.allows_redirect_uri("http://localhost:8080.evil.com"));

        // Security: reject empty port
        assert!(!client.allows_redirect_uri("http://localhost:/callback"));
    }

    #[test]
    fn test_validate_redirect_uri_127_0_0_1_wildcard() {
        let client = Client {
            id: "test".into(),
            name: "Test".into(),
            secret_hash: None,
            redirect_uris: vec!["http://127.0.0.1:*".into()],
            grants: vec!["authorization_code".into()],
            scopes: vec!["api".into()],
            client_uri: None,
            software_id: None,
            software_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(client.allows_redirect_uri("http://127.0.0.1:8080/callback"));
        assert!(client.allows_redirect_uri("http://127.0.0.1:3000"));
        assert!(!client.allows_redirect_uri("http://127.0.0.1:8080@evil.com"));
    }

    #[test]
    fn test_validate_redirect_uri_non_localhost_wildcard_rejected() {
        let client = Client {
            id: "test".into(),
            name: "Test".into(),
            secret_hash: None,
            redirect_uris: vec!["https://example.com/*".into()],
            grants: vec!["authorization_code".into()],
            scopes: vec!["api".into()],
            client_uri: None,
            software_id: None,
            software_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Non-localhost wildcards should be rejected for security
        assert!(!client.allows_redirect_uri("https://example.com/callback"));
        assert!(!client.allows_redirect_uri("https://example.com/anything"));
    }
}
