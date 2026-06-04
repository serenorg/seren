//! Token storage for OAuth2 authentication
//!
//! This module provides PostgreSQL-backed storage for OAuth2 tokens,
//! authorization codes, and client registrations.

use super::crypto::TokenCipher;
use crate::error::{McpError, Result};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

/// PKCE code challenge methods (RFC 7636)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "mcp_oauth.pkce_method")]
pub enum PkceMethod {
    #[sqlx(rename = "plain")]
    Plain,
    #[sqlx(rename = "S256")]
    S256,
}

impl std::fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkceMethod::Plain => write!(f, "plain"),
            PkceMethod::S256 => write!(f, "S256"),
        }
    }
}

impl std::str::FromStr for PkceMethod {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(PkceMethod::Plain),
            "s256" => Ok(PkceMethod::S256),
            _ => Err(format!("Invalid PKCE method: {}", s)),
        }
    }
}

// Token TTL constants
// NOTE: Keep this aligned with MCP's long-lived access token strategy so clients are not
// invalidated due to token-vault expiry while their bearer token is still valid.
pub const REFRESH_TOKEN_TTL_HOURS: i64 = 10 * 365 * 24; // 10 years
/// Minimum interval between sliding-expiry renewals (write throttling).
pub const SLIDING_EXPIRY_RENEWAL_INTERVAL_HOURS: i64 = 24;

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
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
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
    pub code_challenge_method: PkceMethod,
    pub upstream_code_verifier: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Authorization code (short-lived, exchanged for tokens)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<PkceMethod>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub upstream_access_token: String,
    pub upstream_refresh_token: Option<String>,
    pub upstream_expires_at: OffsetDateTime,
}

/// MCP refresh token with server-side upstream token storage.
/// The MCP refresh token is what clients use; upstream tokens are used internally for API calls.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RefreshToken {
    /// Hash of the refresh token (SHA-256 hex). We never store plaintext refresh tokens.
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scope: String,
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    // Upstream token vault (server-side only, never exposed to clients)
    pub upstream_access_token: String,
    pub upstream_refresh_token: Option<String>,
    pub upstream_expires_at: OffsetDateTime,
}

/// Unified MCP session storage
/// Combines auth binding (access token) and protocol state (init request/response)
/// for complete session persistence across pod restarts.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct McpSession {
    pub session_id: String,
    // Auth binding
    pub access_token: Option<String>,
    pub client_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub expires_at: Option<OffsetDateTime>,
    /// Links this session to its specific refresh token and upstream token vault.
    /// Each session maintains independent upstream tokens to support multiple concurrent
    /// sessions per user (e.g., Claude Code + Cursor) without token conflicts.
    pub refresh_token_hash: Option<String>,
    // Protocol state for restoration
    pub initialize_request: Option<serde_json::Value>,
    pub initialize_response: Option<serde_json::Value>,
    pub protocol_version: Option<String>,
    // Timestamps
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_activity: OffsetDateTime,
}

/// Pending consent prompt during the OAuth callback flow.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PendingConsent {
    pub id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub authorization_code: String,
    pub redirect_uri: String,
    pub client_state: Option<String>,
    pub scope: String,
    pub csrf_token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Hosted Seren Passwords agent credential decrypted from the token vault.
///
/// The secret fields are wrapped in `Zeroizing` so they are scrubbed when the
/// request-scoped value is dropped.
#[derive(Clone)]
pub struct HostedPasswordsAgent {
    pub kem_private: Zeroizing<String>,
    pub api_key: Zeroizing<String>,
}

/// Pending hosted agent keypair waiting for browser-side vault consent.
#[derive(Clone)]
pub struct HostedPasswordsAgentRequest {
    pub kem_public: String,
    pub signing_public: String,
    pub kem_private: Zeroizing<String>,
}

pub struct PendingHostedPasswordsAgentRequest<'a> {
    pub user_id: Uuid,
    pub request_id: Uuid,
    pub display_name: &'a str,
    pub kem_public: &'a str,
    pub signing_public: &'a str,
    pub kem_private: &'a str,
    pub expires_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
struct HostedPasswordsAgentSecretBundle {
    user_id: Uuid,
    identity_id: Uuid,
    kem_private: String,
    api_key: String,
}

#[derive(Serialize)]
struct HostedPasswordsAgentSecretBundleRef<'a> {
    user_id: Uuid,
    identity_id: Uuid,
    kem_private: &'a str,
    api_key: &'a str,
}

#[derive(Serialize, Deserialize)]
struct HostedPasswordsAgentRequestSecretBundle {
    user_id: Uuid,
    request_id: Uuid,
    kem_private: String,
}

#[derive(Serialize)]
struct HostedPasswordsAgentRequestSecretBundleRef<'a> {
    user_id: Uuid,
    request_id: Uuid,
    kem_private: &'a str,
}

/// Token store backed by PostgreSQL with LRU cache for client metadata
#[derive(Clone)]
pub struct TokenStore {
    pool: PgPool,
    /// LRU cache for client metadata (client_id -> Client)
    /// Wrapped in Arc<Mutex<>> for interior mutability across clones
    client_cache: Arc<Mutex<LruCache<String, Client>>>,
    token_cipher: Option<TokenCipher>,
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
            token_cipher: None,
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

        let token_cipher = TokenCipher::from_env()?;
        let mut store = Self::new(pool);
        store.token_cipher = token_cipher;
        Ok(store)
    }

    /// Get the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Whether upstream OAuth tokens will be encrypted at rest when stored in Postgres.
    pub fn token_encryption_enabled(&self) -> bool {
        self.token_cipher.is_some()
    }

    #[allow(clippy::result_large_err)]
    fn encrypt_upstream_token(&self, token: &str) -> Result<String> {
        match self.token_cipher.as_ref() {
            Some(cipher) => cipher.encrypt(token),
            None => Ok(token.to_string()),
        }
    }

    #[allow(clippy::result_large_err)]
    fn decrypt_upstream_token(&self, token: &str) -> Result<String> {
        match self.token_cipher.as_ref() {
            Some(cipher) => cipher.decrypt_or_plain(token),
            None => {
                if TokenCipher::is_encrypted(token) {
                    return Err(McpError::Config(
                        "Encrypted upstream tokens present but OAUTH_TOKEN_ENCRYPTION_KEYS is not configured"
                            .into(),
                    ));
                }
                Ok(token.to_string())
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn hosted_passwords_agent_cipher(&self, action: &str) -> Result<&TokenCipher> {
        self.token_cipher.as_ref().ok_or_else(|| {
            McpError::Config(format!(
                "OAUTH_TOKEN_ENCRYPTION_KEYS must be configured before {action} hosted Seren Passwords agents"
            ))
        })
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
            r#"
            SELECT id, name, secret_hash, redirect_uris, grants, scopes,
                client_uri, software_id, software_version, created_at, updated_at
            FROM mcp_oauth.clients
            WHERE id = $1
            "#,
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

    /// Store or replace a hosted Seren Passwords agent credential for a user.
    ///
    /// The caller must pass plaintext secret fields only in request-scoped
    /// buffers. This method encrypts them before they reach Postgres.
    pub async fn upsert_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        identity_id: Uuid,
        display_name: &str,
        kem_private: &str,
        api_key: &str,
        granted_vaults: &serde_json::Value,
    ) -> Result<()> {
        let credential_bundle = HostedPasswordsAgentSecretBundleRef {
            user_id,
            identity_id,
            kem_private,
            api_key,
        };
        let credential_json =
            Zeroizing::new(serde_json::to_string(&credential_bundle).map_err(|e| {
                McpError::Config(format!("Hosted passwords credential encode failed: {e}"))
            })?);
        let credential_ciphertext = self
            .hosted_passwords_agent_cipher("storing")?
            .encrypt(&credential_json)?;

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.hosted_passwords_agents
                (user_id, identity_id, display_name, credential_ciphertext, granted_vaults)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, identity_id)
            DO UPDATE SET
                display_name = EXCLUDED.display_name,
                credential_ciphertext = EXCLUDED.credential_ciphertext,
                granted_vaults = EXCLUDED.granted_vaults
            "#,
        )
        .bind(user_id)
        .bind(identity_id)
        .bind(display_name)
        .bind(&credential_ciphertext)
        .bind(granted_vaults)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    pub async fn upsert_pending_hosted_passwords_agent(
        &self,
        request: PendingHostedPasswordsAgentRequest<'_>,
    ) -> Result<()> {
        let credential_bundle = HostedPasswordsAgentRequestSecretBundleRef {
            user_id: request.user_id,
            request_id: request.request_id,
            kem_private: request.kem_private,
        };
        let credential_json =
            Zeroizing::new(serde_json::to_string(&credential_bundle).map_err(|e| {
                McpError::Config(format!("Hosted passwords request encode failed: {e}"))
            })?);
        let credential_ciphertext = self
            .hosted_passwords_agent_cipher("storing pending")?
            .encrypt(&credential_json)?;

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.hosted_passwords_agent_requests
                (user_id, request_id, display_name, kem_public, signing_public,
                    credential_ciphertext, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id)
            DO UPDATE SET
                request_id = EXCLUDED.request_id,
                display_name = EXCLUDED.display_name,
                kem_public = EXCLUDED.kem_public,
                signing_public = EXCLUDED.signing_public,
                credential_ciphertext = EXCLUDED.credential_ciphertext,
                expires_at = EXCLUDED.expires_at,
                finalizing_at = NULL,
                created_at = NOW()
            "#,
        )
        .bind(request.user_id)
        .bind(request.request_id)
        .bind(request.display_name)
        .bind(request.kem_public)
        .bind(request.signing_public)
        .bind(&credential_ciphertext)
        .bind(request.expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    pub async fn get_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<HostedPasswordsAgentRequest>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            request_id: Uuid,
            kem_public: String,
            signing_public: String,
            credential_ciphertext: String,
        }

        let row = sqlx::query_as::<_, Row>(
            r#"
            SELECT request_id, kem_public, signing_public, credential_ciphertext
            FROM mcp_oauth.hosted_passwords_agent_requests
            WHERE user_id = $1 AND request_id = $2 AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        let Some(row) = row else {
            return Ok(None);
        };
        if !TokenCipher::is_encrypted(&row.credential_ciphertext) {
            return Err(McpError::Config(
                "Hosted passwords pending credential is not encrypted".into(),
            ));
        }
        let credential_json = Zeroizing::new(
            self.hosted_passwords_agent_cipher("reading pending")?
                .decrypt_or_plain(&row.credential_ciphertext)?,
        );
        let bundle: HostedPasswordsAgentRequestSecretBundle =
            serde_json::from_str(&credential_json).map_err(|e| {
                McpError::Config(format!("Hosted passwords request decode failed: {e}"))
            })?;
        if bundle.user_id != user_id || bundle.request_id != row.request_id {
            return Err(McpError::Config(
                "Hosted passwords pending credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgentRequest {
            kem_public: row.kem_public,
            signing_public: row.signing_public,
            kem_private: Zeroizing::new(bundle.kem_private),
        }))
    }

    pub async fn claim_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        request_id: Uuid,
    ) -> Result<Option<HostedPasswordsAgentRequest>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            request_id: Uuid,
            kem_public: String,
            signing_public: String,
            credential_ciphertext: String,
        }

        let row = sqlx::query_as::<_, Row>(
            r#"
            UPDATE mcp_oauth.hosted_passwords_agent_requests
            SET finalizing_at = NOW()
            WHERE user_id = $1
                AND request_id = $2
                AND expires_at > NOW()
                AND (
                    finalizing_at IS NULL
                    OR finalizing_at < NOW() - INTERVAL '5 minutes'
                )
            RETURNING request_id, kem_public, signing_public, credential_ciphertext
            "#,
        )
        .bind(user_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        let Some(row) = row else {
            return Ok(None);
        };
        if !TokenCipher::is_encrypted(&row.credential_ciphertext) {
            return Err(McpError::Config(
                "Hosted passwords pending credential is not encrypted".into(),
            ));
        }
        let credential_json = Zeroizing::new(
            self.hosted_passwords_agent_cipher("reading pending")?
                .decrypt_or_plain(&row.credential_ciphertext)?,
        );
        let bundle: HostedPasswordsAgentRequestSecretBundle =
            serde_json::from_str(&credential_json).map_err(|e| {
                McpError::Config(format!("Hosted passwords request decode failed: {e}"))
            })?;
        if bundle.user_id != user_id || bundle.request_id != row.request_id {
            return Err(McpError::Config(
                "Hosted passwords pending credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgentRequest {
            kem_public: row.kem_public,
            signing_public: row.signing_public,
            kem_private: Zeroizing::new(bundle.kem_private),
        }))
    }

    pub async fn delete_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        request_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.hosted_passwords_agent_requests
            WHERE user_id = $1 AND request_id = $2
            "#,
        )
        .bind(user_id)
        .bind(request_id)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;
        Ok(result.rows_affected())
    }

    pub async fn delete_expired_pending_hosted_passwords_agents(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.hosted_passwords_agent_requests
            WHERE expires_at <= NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;
        Ok(result.rows_affected())
    }

    /// Return the most recently uploaded hosted Seren Passwords agent for a user.
    pub async fn get_hosted_passwords_agent(
        &self,
        user_id: Uuid,
    ) -> Result<Option<HostedPasswordsAgent>> {
        #[derive(sqlx::FromRow)]
        struct HostedPasswordsAgentRow {
            identity_id: Uuid,
            credential_ciphertext: String,
        }

        let row = sqlx::query_as::<_, HostedPasswordsAgentRow>(
            r#"
            SELECT
                identity_id,
                credential_ciphertext
            FROM mcp_oauth.hosted_passwords_agents
            WHERE user_id = $1
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        let Some(row) = row else {
            return Ok(None);
        };

        if !TokenCipher::is_encrypted(&row.credential_ciphertext) {
            tracing::error!(
                event = "plaintext_hosted_passwords_agent_credential_detected",
                user_id = %user_id,
                identity_id = %row.identity_id,
                "Hosted Seren Passwords agent credential is not encrypted"
            );
            return Err(McpError::Config(
                "Hosted passwords agent credential is not encrypted".into(),
            ));
        }
        let credential_json = Zeroizing::new(
            self.hosted_passwords_agent_cipher("reading")?
                .decrypt_or_plain(&row.credential_ciphertext)?,
        );
        let bundle: HostedPasswordsAgentSecretBundle = serde_json::from_str(&credential_json)
            .map_err(|e| {
                McpError::Config(format!("Hosted passwords credential decode failed: {e}"))
            })?;
        if bundle.user_id != user_id || bundle.identity_id != row.identity_id {
            return Err(McpError::Config(
                "Hosted passwords agent credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgent {
            kem_private: Zeroizing::new(bundle.kem_private),
            api_key: Zeroizing::new(bundle.api_key),
        }))
    }

    /// Delete a hosted Seren Passwords agent credential for a user.
    pub async fn delete_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        identity_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.hosted_passwords_agents
            WHERE user_id = $1 AND identity_id = $2
            "#,
        )
        .bind(user_id)
        .bind(identity_id)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected())
    }

    // === Authorization request operations ===

    /// Save a pending authorization request
    pub async fn save_auth_request(&self, req: &AuthRequest) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.auth_requests
                (id, client_id, redirect_uri, scope, client_state, code_challenge,
                code_challenge_method, upstream_code_verifier, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7::mcp_oauth.pkce_method, $8, $9)
            "#,
        )
        .bind(&req.id)
        .bind(&req.client_id)
        .bind(&req.redirect_uri)
        .bind(&req.scope)
        .bind(&req.client_state)
        .bind(&req.code_challenge)
        .bind(req.code_challenge_method)
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
            r#"
            DELETE FROM mcp_oauth.auth_requests
            WHERE id = $1 AND expires_at > NOW()
            RETURNING id, client_id, redirect_uri, scope, client_state,
                code_challenge, code_challenge_method, upstream_code_verifier,
                expires_at, created_at
            "#,
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
        let upstream_access_token = self.encrypt_upstream_token(&code.upstream_access_token)?;
        let upstream_refresh_token = match code.upstream_refresh_token.as_deref() {
            Some(token) => Some(self.encrypt_upstream_token(token)?),
            None => None,
        };

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.authorization_codes
                (code, client_id, user_id, redirect_uri, scope, code_challenge,
                code_challenge_method, expires_at, upstream_access_token,
                upstream_refresh_token, upstream_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7::mcp_oauth.pkce_method, $8, $9, $10, $11)
            "#,
        )
        .bind(&code.code)
        .bind(&code.client_id)
        .bind(code.user_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.code_challenge)
        .bind(code.code_challenge_method)
        .bind(code.expires_at)
        .bind(&upstream_access_token)
        .bind(upstream_refresh_token.as_deref())
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
        let mut auth_code = sqlx::query_as::<_, AuthorizationCode>(
            r#"
            DELETE FROM mcp_oauth.authorization_codes
            WHERE code = $1 AND expires_at > NOW()
            RETURNING code, client_id, user_id, redirect_uri, scope,
                code_challenge, code_challenge_method, expires_at, created_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at
            "#,
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        if let Some(ref mut auth_code) = auth_code {
            auth_code.upstream_access_token =
                self.decrypt_upstream_token(&auth_code.upstream_access_token)?;
            auth_code.upstream_refresh_token = match auth_code.upstream_refresh_token.as_deref() {
                Some(token) => Some(self.decrypt_upstream_token(token)?),
                None => None,
            };
        }

        Ok(auth_code)
    }

    // === Refresh token operations ===

    /// Save a refresh token with upstream token vault
    pub async fn save_refresh_token(&self, token: &RefreshToken) -> Result<()> {
        let upstream_access_token = self.encrypt_upstream_token(&token.upstream_access_token)?;
        let upstream_refresh_token = match token.upstream_refresh_token.as_deref() {
            Some(token) => Some(self.encrypt_upstream_token(token)?),
            None => None,
        };

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.refresh_tokens
                (token_hash, client_id, user_id, scope, expires_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&token.token_hash)
        .bind(&token.client_id)
        .bind(token.user_id)
        .bind(&token.scope)
        .bind(token.expires_at)
        .bind(&upstream_access_token)
        .bind(upstream_refresh_token.as_deref())
        .bind(token.upstream_expires_at)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get a refresh token (includes upstream token vault)
    pub async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let token_hash = Self::hash_refresh_token(token);
        let mut refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT token_hash, client_id, user_id, scope, expires_at, created_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at
            FROM mcp_oauth.refresh_tokens
            WHERE (token_hash = $1 OR token_hash = $2)
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(&token_hash)
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        // Opportunistically upgrade legacy plaintext refresh tokens to hashed storage.
        if let Some(ref refresh_token) = refresh_token
            && refresh_token.token_hash == token
            && !Self::looks_like_sha256_hex(token)
        {
            // Best-effort: don't fail the request if migration write fails.
            let _ = sqlx::query(
                r#"
                UPDATE mcp_oauth.refresh_tokens
                SET token_hash = $1
                WHERE token_hash = $2
                "#,
            )
            .bind(&token_hash)
            .bind(token)
            .execute(&self.pool)
            .await;
        }

        if let Some(ref mut refresh_token) = refresh_token {
            refresh_token.upstream_access_token =
                self.decrypt_upstream_token(&refresh_token.upstream_access_token)?;
            refresh_token.upstream_refresh_token =
                match refresh_token.upstream_refresh_token.as_deref() {
                    Some(token) => Some(self.decrypt_upstream_token(token)?),
                    None => None,
                };
        }

        Ok(refresh_token)
    }

    /// Get a refresh token by its hash (for session-linked lookups).
    ///
    /// Unlike `get_refresh_token` which takes a plaintext token and hashes it,
    /// this function takes a pre-computed hash directly. Used when looking up
    /// upstream tokens via the session's `refresh_token_hash` link.
    pub async fn get_refresh_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>> {
        let mut refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT token_hash, client_id, user_id, scope, expires_at, created_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at
            FROM mcp_oauth.refresh_tokens
            WHERE token_hash = $1
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        if let Some(ref mut refresh_token) = refresh_token {
            refresh_token.upstream_access_token =
                self.decrypt_upstream_token(&refresh_token.upstream_access_token)?;
            refresh_token.upstream_refresh_token =
                match refresh_token.upstream_refresh_token.as_deref() {
                    Some(token) => Some(self.decrypt_upstream_token(token)?),
                    None => None,
                };
        }

        Ok(refresh_token)
    }

    /// Revoke a refresh token
    pub async fn revoke_refresh_token(&self, token: &str) -> Result<bool> {
        let token_hash = Self::hash_refresh_token(token);
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.refresh_tokens
            WHERE token_hash = $1 OR token_hash = $2
            "#,
        )
        .bind(&token_hash)
        .bind(token)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Extend a refresh token's expiry if it's far enough in the past that renewing would meaningfully extend it.
    ///
    /// This supports "non-expiring sessions" UX without writing on every request: we only renew
    /// if the existing expiry is before `renew_before` (typically `now + TTL - renewal_interval`).
    ///
    /// Accepts either the raw MCP refresh token or the stored SHA-256 hex token hash.
    pub async fn extend_refresh_token_expiry_if_needed(
        &self,
        refresh_token_or_hash: &str,
        new_expires_at: OffsetDateTime,
        renew_before: OffsetDateTime,
    ) -> Result<bool> {
        let token_hash = if Self::looks_like_sha256_hex(refresh_token_or_hash) {
            refresh_token_or_hash.to_string()
        } else {
            Self::hash_refresh_token(refresh_token_or_hash)
        };

        let result = sqlx::query(
            r#"
            UPDATE mcp_oauth.refresh_tokens
            SET expires_at = $3
            WHERE (token_hash = $1 OR token_hash = $2)
            AND expires_at IS NOT NULL
            AND expires_at > NOW()
            AND expires_at < $4
            "#,
        )
        .bind(&token_hash)
        .bind(refresh_token_or_hash)
        .bind(new_expires_at)
        .bind(renew_before)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the upstream token vault for a refresh token without rotating the MCP refresh token.
    /// Keeps the existing upstream refresh token if the upstream provider omits it.
    ///
    /// Accepts either the raw MCP refresh token or the stored SHA-256 hex token hash.
    pub async fn update_upstream_tokens(
        &self,
        refresh_token_or_hash: &str,
        upstream_access_token: &str,
        upstream_refresh_token: Option<&str>,
        upstream_expires_at: OffsetDateTime,
    ) -> Result<bool> {
        let token_hash = if Self::looks_like_sha256_hex(refresh_token_or_hash) {
            refresh_token_or_hash.to_string()
        } else {
            Self::hash_refresh_token(refresh_token_or_hash)
        };

        let upstream_access_token = self.encrypt_upstream_token(upstream_access_token)?;
        let upstream_refresh_token = match upstream_refresh_token {
            Some(token) => Some(self.encrypt_upstream_token(token)?),
            None => None,
        };

        let result = sqlx::query(
            r#"
            UPDATE mcp_oauth.refresh_tokens
            SET upstream_access_token = $2,
                upstream_refresh_token = COALESCE($3, upstream_refresh_token),
                upstream_expires_at = $4
            WHERE (token_hash = $1 OR token_hash = $5)
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(&token_hash)
        .bind(&upstream_access_token)
        .bind(upstream_refresh_token.as_deref())
        .bind(upstream_expires_at)
        .bind(refresh_token_or_hash)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Get the upstream access token for a given MCP refresh token.
    /// Reserved for future use when looking up tokens by MCP refresh token.
    ///
    /// Accepts either the raw MCP refresh token or the stored SHA-256 hex token hash.
    #[allow(dead_code)]
    pub async fn get_upstream_token(
        &self,
        refresh_token_or_hash: &str,
    ) -> Result<Option<(String, OffsetDateTime)>> {
        let token_hash = if Self::looks_like_sha256_hex(refresh_token_or_hash) {
            refresh_token_or_hash.to_string()
        } else {
            Self::hash_refresh_token(refresh_token_or_hash)
        };

        let result: Option<(String, OffsetDateTime)> = sqlx::query_as(
            r#"
            SELECT upstream_access_token, upstream_expires_at
            FROM mcp_oauth.refresh_tokens
            WHERE (token_hash = $1 OR token_hash = $2)
            AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(&token_hash)
        .bind(refresh_token_or_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        match result {
            Some((token, expires_at)) => {
                let token = self.decrypt_upstream_token(&token)?;
                Ok(Some((token, expires_at)))
            }
            None => Ok(None),
        }
    }

    /// Find refresh token by user and client (for looking up upstream tokens during auth)
    pub async fn get_refresh_token_by_user_client(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<RefreshToken>> {
        let mut refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT token_hash, client_id, user_id, scope, expires_at, created_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at
            FROM mcp_oauth.refresh_tokens
            WHERE user_id = $1 AND client_id = $2 AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        if let Some(ref mut token) = refresh_token {
            // Opportunistically upgrade legacy plaintext refresh tokens to hashed storage.
            if !Self::looks_like_sha256_hex(&token.token_hash) {
                let new_hash = Self::hash_refresh_token(&token.token_hash);
                match sqlx::query(
                    r#"
                    UPDATE mcp_oauth.refresh_tokens
                    SET token_hash = $1
                    WHERE token_hash = $2
                    "#,
                )
                .bind(&new_hash)
                .bind(&token.token_hash)
                .execute(&self.pool)
                .await
                {
                    Ok(_) => token.token_hash = new_hash,
                    Err(e) => tracing::warn!(
                        event = "refresh_token_hash_upgrade_failed",
                        error = %e,
                        "Failed to upgrade legacy refresh token hash"
                    ),
                }
            }

            let stored_upstream_access_token = token.upstream_access_token.clone();
            let stored_upstream_refresh_token = token.upstream_refresh_token.clone();

            token.upstream_access_token =
                self.decrypt_upstream_token(&stored_upstream_access_token)?;
            token.upstream_refresh_token = match stored_upstream_refresh_token.as_deref() {
                Some(token) => Some(self.decrypt_upstream_token(token)?),
                None => None,
            };

            // If encryption is enabled, upgrade legacy plaintext upstream tokens to encrypted storage.
            if self.token_cipher.is_some()
                && (!TokenCipher::is_encrypted(&stored_upstream_access_token)
                    || stored_upstream_refresh_token
                        .as_deref()
                        .is_some_and(|v| !TokenCipher::is_encrypted(v)))
            {
                // Best-effort: don't fail requests if the upgrade write fails.
                if let Err(e) = self
                    .update_upstream_tokens(
                        &token.token_hash,
                        &token.upstream_access_token,
                        token.upstream_refresh_token.as_deref(),
                        token.upstream_expires_at,
                    )
                    .await
                {
                    tracing::warn!(
                        event = "upstream_token_encrypt_upgrade_failed",
                        error = %e,
                        "Failed to upgrade upstream tokens to encrypted storage"
                    );
                }
            }
        }

        Ok(refresh_token)
    }

    // === Consent operations ===

    /// Returns true if the given user has approved the given OAuth client.
    pub async fn is_client_approved(&self, user_id: Uuid, client_id: &str) -> Result<bool> {
        let exists: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT 1
            FROM mcp_oauth.approved_clients
            WHERE user_id = $1 AND client_id = $2
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(exists.is_some())
    }

    /// Records a user's approval for a given OAuth client.
    pub async fn approve_client(&self, user_id: Uuid, client_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.approved_clients (user_id, client_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, client_id) DO NOTHING
            "#,
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
            r#"
            INSERT INTO mcp_oauth.pending_consents
                (id, user_id, client_id, authorization_code, redirect_uri,
                client_state, scope, csrf_token, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&consent.id)
        .bind(consent.user_id)
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
            r#"
            SELECT id, user_id, client_id, authorization_code, redirect_uri,
                client_state, scope, csrf_token, expires_at, created_at
            FROM mcp_oauth.pending_consents
            WHERE id = $1 AND expires_at > NOW()
            "#,
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
            r#"
            DELETE FROM mcp_oauth.pending_consents
            WHERE id = $1 AND expires_at > NOW()
            RETURNING id, user_id, client_id, authorization_code, redirect_uri,
                client_state, scope, csrf_token, expires_at, created_at
            "#,
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

    // === Unified MCP Session operations ===
    // All session data (auth binding + protocol state) is stored in mcp_oauth.mcp_sessions

    /// Create or update an MCP session.
    /// Called when a new session is created via create_session().
    pub async fn create_mcp_session(&self, session_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.mcp_sessions (session_id, created_at, updated_at, last_activity)
            VALUES ($1, NOW(), NOW(), NOW())
            ON CONFLICT (session_id) DO UPDATE SET
                last_activity = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Save protocol state (init request/response) for session restoration.
    /// Called after initialize_session() to persist the MCP handshake.
    pub async fn save_session_state(
        &self,
        session_id: &str,
        init_request: &serde_json::Value,
        init_response: &serde_json::Value,
        protocol_version: Option<&str>,
    ) -> Result<()> {
        // Use an upsert to avoid a silent no-op if the session row wasn't created.
        // (e.g. transient DB error during create_session tracking).
        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.mcp_sessions
                (session_id, initialize_request, initialize_response, protocol_version,
                created_at, updated_at, last_activity)
            VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW())
            ON CONFLICT (session_id) DO UPDATE SET
                initialize_request = EXCLUDED.initialize_request,
                initialize_response = EXCLUDED.initialize_response,
                protocol_version = EXCLUDED.protocol_version,
                updated_at = NOW(),
                last_activity = NOW()
            "#,
        )
        .bind(session_id)
        .bind(init_request)
        .bind(init_response)
        .bind(protocol_version)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get MCP session state for restoration.
    /// Returns None if session doesn't exist or has no init state.
    pub async fn get_session_for_restore(&self, session_id: &str) -> Result<Option<McpSession>> {
        let session = sqlx::query_as::<_, McpSession>(
            r#"
            SELECT session_id, access_token, client_id, user_id, expires_at,
                refresh_token_hash, initialize_request, initialize_response, protocol_version,
                created_at, updated_at, last_activity
            FROM mcp_oauth.mcp_sessions
            WHERE session_id = $1 AND initialize_request IS NOT NULL
            "#,
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(session)
    }

    /// Extend a session's token expiry if it's far enough in the past.
    /// Uses a conditional update to avoid per-request writes.
    pub async fn extend_session_expiry_if_needed(
        &self,
        session_id: &str,
        new_expires_at: OffsetDateTime,
        renew_before: OffsetDateTime,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE mcp_oauth.mcp_sessions
            SET expires_at = $2, updated_at = NOW()
            WHERE session_id = $1
                AND expires_at IS NOT NULL
                AND expires_at > NOW()
                AND expires_at < $3
            "#,
        )
        .bind(session_id)
        .bind(new_expires_at)
        .bind(renew_before)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if an MCP session exists.
    pub async fn has_session(&self, session_id: &str) -> Result<bool> {
        let exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM mcp_oauth.mcp_sessions WHERE session_id = $1)",
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(exists.0)
    }

    /// Update the last activity timestamp for an MCP session.
    pub async fn touch_session(&self, session_id: &str) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE mcp_oauth.mcp_sessions SET last_activity = NOW() WHERE session_id = $1",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Update last activity timestamp, but only if it hasn't been updated recently.
    /// This throttles writes while still preventing cleanup of active sessions.
    pub async fn touch_session_if_older_than(
        &self,
        session_id: &str,
        min_interval: Duration,
    ) -> Result<bool> {
        let threshold = OffsetDateTime::now_utc() - min_interval;
        let result = sqlx::query(
            "UPDATE mcp_oauth.mcp_sessions SET last_activity = NOW() WHERE session_id = $1 AND last_activity < $2",
        )
        .bind(session_id)
        .bind(threshold)
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete an MCP session.
    #[allow(dead_code)]
    pub async fn delete_session(&self, session_id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM mcp_oauth.mcp_sessions WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    /// Count active MCP sessions (for metrics/observability).
    pub async fn count_sessions(&self) -> Result<i64> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mcp_oauth.mcp_sessions")
            .fetch_one(&self.pool)
            .await
            .map_err(McpError::Database)?;

        Ok(count.0)
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
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Hash a refresh token using SHA-256, returning lowercase hex.
    pub fn hash_refresh_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(token.as_bytes());
        hex::encode(digest)
    }

    fn looks_like_sha256_hex(value: &str) -> bool {
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Generate a secure random authorization code
    pub fn generate_code() -> String {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    }

    /// Verify PKCE code challenge
    pub fn verify_pkce(
        code_verifier: &str,
        code_challenge: &str,
        method: Option<PkceMethod>,
    ) -> bool {
        match method.unwrap_or(PkceMethod::S256) {
            PkceMethod::S256 => {
                // S256 is the default and recommended method
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(code_verifier.as_bytes());
                let hash = hasher.finalize();
                let computed =
                    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash);
                computed == code_challenge
            }
            PkceMethod::Plain => {
                // Plain method (not recommended but supported)
                code_verifier == code_challenge
            }
        }
    }

    /// Create token expiry time
    pub fn token_expiry(duration_hours: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::hours(duration_hours)
    }

    /// Create authorization code expiry (short-lived, 10 minutes)
    pub fn code_expiry() -> OffsetDateTime {
        OffsetDateTime::now_utc() + Duration::minutes(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_without_token_cipher() -> TokenStore {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost/seren_mcp_test")
            .expect("lazy pool");
        TokenStore::new(pool)
    }

    #[tokio::test]
    async fn hosted_passwords_agent_storage_requires_token_cipher() {
        let store = store_without_token_cipher();
        let err = match store.hosted_passwords_agent_cipher("storing") {
            Ok(_) => panic!("missing token cipher must fail closed"),
            Err(err) => err,
        };
        match err {
            McpError::Config(message) => {
                assert!(message.contains("OAUTH_TOKEN_ENCRYPTION_KEYS"));
                assert!(message.contains("storing"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_verify_pkce_s256() {
        // Test vector from RFC 7636
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        assert!(TokenStore::verify_pkce(
            code_verifier,
            code_challenge,
            Some(PkceMethod::S256)
        ));
        assert!(!TokenStore::verify_pkce(
            "wrong_verifier",
            code_challenge,
            Some(PkceMethod::S256)
        ));
    }

    #[test]
    fn test_verify_pkce_plain() {
        let code_verifier = "test_verifier_123";
        let code_challenge = "test_verifier_123";

        assert!(TokenStore::verify_pkce(
            code_verifier,
            code_challenge,
            Some(PkceMethod::Plain)
        ));
        assert!(!TokenStore::verify_pkce(
            "wrong",
            code_challenge,
            Some(PkceMethod::Plain)
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
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
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
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
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
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
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
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        // Non-localhost wildcards should be rejected for security
        assert!(!client.allows_redirect_uri("https://example.com/callback"));
        assert!(!client.allows_redirect_uri("https://example.com/anything"));
    }
}
