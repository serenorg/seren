//! Token storage for OAuth2 authentication
//!
//! This module provides PostgreSQL-backed storage for OAuth2 tokens,
//! authorization codes, and client registrations.

use super::crypto::TokenCipher;
use crate::error::{McpError, Result};
use jiff::{SignedDuration, Timestamp};
use jiff_sqlx::ToSqlx;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
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

/// Every stored column that holds an encrypted token or agent credential, grouped by table.
const STORED_TOKEN_COLUMNS: &[(&str, &str)] = &[
    ("refresh_tokens", "upstream_access_token"),
    ("refresh_tokens", "upstream_refresh_token"),
    ("authorization_codes", "upstream_access_token"),
    ("authorization_codes", "upstream_refresh_token"),
    ("hosted_passwords_agents", "credential_ciphertext"),
    ("hosted_passwords_agent_requests", "credential_ciphertext"),
];

/// Most rewrites and deletions one start-up sweep makes per table.
pub const STORED_TOKEN_SWEEP_CHANGE_LIMIT: usize = 10_000;

/// Counts one table's stored values by what the start-up sweep found. Holds no values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTokenSweepReport {
    pub table: &'static str,
    /// Values found under each key position of `OAUTH_TOKEN_ENCRYPTION_KEYS`.
    pub values_by_key: Vec<u64>,
    pub unencrypted: u64,
    /// Encrypted values that open with no listed key.
    pub unopenable: u64,
    pub rewritten: u64,
    pub deleted: u64,
    changes_planned: usize,
}

impl StoredTokenSweepReport {
    fn new(table: &'static str, key_count: usize) -> Self {
        Self {
            table,
            values_by_key: vec![0; key_count],
            unencrypted: 0,
            unopenable: 0,
            rewritten: 0,
            deleted: 0,
            changes_planned: 0,
        }
    }

    /// The sweep's log line for this table: counts only.
    pub fn log_message(&self) -> String {
        let by_key = self
            .values_by_key
            .iter()
            .enumerate()
            .map(|(position, count)| format!("key {position}: {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "Stored token sweep of mcp_oauth.{}: values by key position [{by_key}], \
             unencrypted {}, opened by no key {}, rewritten {}, deleted {}",
            self.table, self.unencrypted, self.unopenable, self.rewritten, self.deleted
        )
    }
}

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
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub created_at: Timestamp,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub updated_at: Timestamp,
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
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub expires_at: Timestamp,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub created_at: Timestamp,
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
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub expires_at: Timestamp,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub created_at: Timestamp,
    pub upstream_access_token: String,
    pub upstream_refresh_token: Option<String>,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub upstream_expires_at: Timestamp,
}

/// MCP refresh token with server-side upstream token storage.
/// The MCP refresh token is what clients use; upstream tokens are used internally for API calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    /// Hash of the refresh token (SHA-256 hex). We never store plaintext refresh tokens.
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub scope: String,
    pub expires_at: Option<Timestamp>,
    pub created_at: Timestamp,
    // Upstream token vault (server-side only, never exposed to clients)
    pub upstream_access_token: String,
    pub upstream_refresh_token: Option<String>,
    pub upstream_expires_at: Timestamp,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for RefreshToken {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            token_hash: row.try_get("token_hash")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            scope: row.try_get("scope")?,
            expires_at: row
                .try_get::<Option<jiff_sqlx::Timestamp>, _>("expires_at")?
                .map(jiff_sqlx::Timestamp::to_jiff),
            created_at: row
                .try_get::<jiff_sqlx::Timestamp, _>("created_at")?
                .to_jiff(),
            upstream_access_token: row.try_get("upstream_access_token")?,
            upstream_refresh_token: row.try_get("upstream_refresh_token")?,
            upstream_expires_at: row
                .try_get::<jiff_sqlx::Timestamp, _>("upstream_expires_at")?
                .to_jiff(),
        })
    }
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
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub expires_at: Timestamp,
    #[sqlx(try_from = "jiff_sqlx::Timestamp")]
    pub created_at: Timestamp,
}

/// Hosted Seren Passwords agent credential decrypted from the token vault.
///
/// The secret fields are wrapped in `Zeroizing` so they are scrubbed when the
/// request-scoped value is dropped.
#[derive(Clone)]
pub struct HostedPasswordsAgent {
    pub identity_id: Uuid,
    pub display_name: String,
    pub kem_private: Zeroizing<String>,
    pub api_key: Option<Zeroizing<String>>,
    pub api_key_id: Option<Uuid>,
    pub api_key_organization_id: Option<Uuid>,
    pub granted_vaults: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostedPasswordsCredentialSubject {
    User,
    UserApiKey(Uuid),
}

impl HostedPasswordsCredentialSubject {
    pub fn storage_key(&self) -> String {
        match self {
            Self::User => "user".to_string(),
            Self::UserApiKey(api_key_id) => format!("user_api_key:{api_key_id}"),
        }
    }

    pub fn is_user_api_key(&self) -> bool {
        matches!(self, Self::UserApiKey(_))
    }
}

/// Pending hosted agent keypair waiting for browser-side vault consent.
#[derive(Clone)]
pub struct HostedPasswordsAgentRequest {
    pub kem_public: String,
    pub signing_public: String,
    pub kem_private: Zeroizing<String>,
    pub consent_capability: Option<Zeroizing<String>>,
}

pub struct HostedPasswordsPendingAgentRequest {
    pub request_id: Uuid,
    pub consent_capability: Option<Zeroizing<String>>,
}

pub struct PendingHostedPasswordsAgentRequest<'a> {
    pub user_id: Uuid,
    pub credential_subject: &'a str,
    pub request_id: Uuid,
    pub display_name: &'a str,
    pub kem_public: &'a str,
    pub signing_public: &'a str,
    pub kem_private: &'a str,
    pub consent_capability: Option<&'a str>,
    pub expires_at: Timestamp,
}

pub struct HostedPasswordsAgentUpsert<'a> {
    pub user_id: Uuid,
    pub credential_subject: &'a str,
    pub identity_id: Uuid,
    pub display_name: &'a str,
    pub kem_private: &'a str,
    pub api_key: Option<&'a str>,
    pub api_key_id: Option<Uuid>,
    pub api_key_organization_id: Option<Uuid>,
    pub granted_vaults: &'a serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct HostedPasswordsAgentSecretBundle {
    user_id: Uuid,
    #[serde(default = "default_hosted_passwords_credential_subject")]
    credential_subject: String,
    identity_id: Uuid,
    kem_private: String,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    api_key_id: Option<Uuid>,
    #[serde(default)]
    api_key_organization_id: Option<Uuid>,
}

#[derive(Serialize)]
struct HostedPasswordsAgentSecretBundleRef<'a> {
    user_id: Uuid,
    credential_subject: &'a str,
    identity_id: Uuid,
    kem_private: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_organization_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize)]
struct HostedPasswordsAgentRequestSecretBundle {
    user_id: Uuid,
    #[serde(default = "default_hosted_passwords_credential_subject")]
    credential_subject: String,
    request_id: Uuid,
    kem_private: String,
    #[serde(default)]
    consent_capability: Option<String>,
}

#[derive(Serialize)]
struct HostedPasswordsAgentRequestSecretBundleRef<'a> {
    user_id: Uuid,
    credential_subject: &'a str,
    request_id: Uuid,
    kem_private: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    consent_capability: Option<&'a str>,
}

fn default_hosted_passwords_credential_subject() -> String {
    "user".to_string()
}

/// Token store backed by PostgreSQL with LRU cache for client metadata
#[derive(Clone)]
pub struct TokenStore {
    pool: PgPool,
    /// LRU cache for client metadata (client_id -> Client)
    /// Wrapped in Arc<Mutex<>> for interior mutability across clones
    client_cache: Arc<Mutex<LruCache<String, Client>>>,
    token_cipher: TokenCipher,
}

impl TokenStore {
    /// Create a new token store with default cache size (100 clients).
    ///
    /// A store persists upstream tokens and agent credentials, so it always needs a cipher.
    pub(crate) fn new(pool: PgPool, token_cipher: TokenCipher) -> Self {
        Self::with_cache_size(pool, 100, token_cipher)
    }

    /// Create a new token store with custom cache size
    pub(crate) fn with_cache_size(
        pool: PgPool,
        cache_size: usize,
        token_cipher: TokenCipher,
    ) -> Self {
        Self {
            pool,
            client_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap(),
            ))),
            token_cipher,
        }
    }

    /// Connect to the database and create a new token store
    /// P1 fix: Configure connection pool with proper limits
    pub async fn connect(database_url: &str) -> Result<Self> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        // Read the keys before connecting: a store without a cipher must never exist.
        let token_cipher = TokenCipher::from_env()?.ok_or_else(|| {
            McpError::Config("OAUTH_TOKEN_ENCRYPTION_KEYS is required to store tokens".into())
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(20) // Limit concurrent connections
            .min_connections(2) // Keep some connections warm
            .acquire_timeout(Duration::from_secs(10)) // Timeout for acquiring connections
            .idle_timeout(Duration::from_secs(300)) // Close idle connections after 5 minutes
            .max_lifetime(Duration::from_secs(1800)) // Recycle connections after 30 minutes
            .connect(database_url)
            .await
            .map_err(McpError::Database)?;

        Ok(Self::new(pool, token_cipher))
    }

    /// Get the underlying connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[allow(clippy::result_large_err)]
    fn encrypt_upstream_token(&self, token: &str) -> Result<String> {
        self.token_cipher.encrypt(token)
    }

    /// Opens the stored upstream tokens of one row. Returns `None`, after one log event naming
    /// the table and the row's hash, when a value is unencrypted or no listed key opens it:
    /// callers then treat the row as absent and the client signs in again. The flag says
    /// whether a value opened with a key other than the first.
    fn open_upstream_tokens(
        &self,
        table: &'static str,
        row_hash: &str,
        access_token: &str,
        refresh_token: Option<&str>,
    ) -> Option<(String, Option<String>, bool)> {
        let open = |value: &str| match self.token_cipher.decrypt_with_key_position(value) {
            Ok(opened) => Some(opened),
            Err(error) => {
                tracing::warn!(
                    event = "stored_token_unusable",
                    table,
                    row_hash = %row_hash,
                    reason = %error,
                    "Stored token is unusable; the client must sign in again"
                );
                None
            }
        };
        let (access, access_position) = open(access_token)?;
        let (refresh, refresh_position) = match refresh_token {
            Some(value) => {
                let (refresh, position) = open(value)?;
                (Some(refresh), position)
            }
            None => (None, 0),
        };
        Some((
            access,
            refresh,
            access_position != 0 || refresh_position != 0,
        ))
    }

    /// Opens a refresh-token row and, when a value is under an older key, rewrites it under
    /// the first key. Returns `None` when the row is unusable.
    async fn open_refresh_token(&self, mut token: RefreshToken) -> Option<RefreshToken> {
        let stored_access = std::mem::take(&mut token.upstream_access_token);
        let stored_refresh = token.upstream_refresh_token.take();
        let (access, refresh, stale) = self.open_upstream_tokens(
            "refresh_tokens",
            &token.token_hash,
            &stored_access,
            stored_refresh.as_deref(),
        )?;
        if stale {
            self.rewrite_stored_value("refresh_tokens", "upstream_access_token", &stored_access)
                .await;
            if let Some(stored_refresh) = stored_refresh.as_deref() {
                self.rewrite_stored_value(
                    "refresh_tokens",
                    "upstream_refresh_token",
                    stored_refresh,
                )
                .await;
            }
        }
        token.upstream_access_token = access;
        token.upstream_refresh_token = refresh;
        Some(token)
    }

    /// Opens a hosted Seren Passwords credential and, when it is under an older key, rewrites
    /// it under the first key. Unencrypted or unopenable credentials are refused.
    #[allow(clippy::result_large_err)]
    async fn open_hosted_passwords_credential(
        &self,
        table: &'static str,
        stored: &str,
    ) -> Result<Zeroizing<String>> {
        let (plaintext, position) = self.token_cipher.decrypt_with_key_position(stored)?;
        let plaintext = Zeroizing::new(plaintext);
        if position != 0 {
            self.rewrite_stored_value(table, "credential_ciphertext", stored)
                .await;
        }
        Ok(plaintext)
    }

    /// Rewrites one stored value under the first key. The update matches the old stored value,
    /// so a concurrent writer or another replica's sweep is never overwritten. Best-effort:
    /// returns how many rows changed and logs a failure without failing the caller.
    async fn rewrite_stored_value(
        &self,
        table: &'static str,
        column: &'static str,
        stored: &str,
    ) -> u64 {
        if !STORED_TOKEN_COLUMNS.contains(&(table, column)) {
            return 0;
        }
        let rewritten = match self.token_cipher.decrypt(stored) {
            Ok(plaintext) => {
                let plaintext = Zeroizing::new(plaintext);
                self.token_cipher.encrypt(&plaintext)
            }
            Err(error) => Err(error),
        };
        let rewritten = match rewritten {
            Ok(rewritten) => rewritten,
            Err(error) => {
                tracing::warn!(event = "stored_token_rewrite_failed", table, column, reason = %error);
                return 0;
            }
        };
        let query = format!("UPDATE mcp_oauth.{table} SET {column} = $1 WHERE {column} = $2");
        // Table and column names come only from STORED_TOKEN_COLUMNS (checked above).
        match sqlx::query(sqlx::AssertSqlSafe(query))
            .bind(&rewritten)
            .bind(stored)
            .execute(&self.pool)
            .await
        {
            Ok(result) => result.rows_affected(),
            Err(error) => {
                tracing::warn!(event = "stored_token_rewrite_failed", table, column, error = %error);
                0
            }
        }
    }

    /// Start-up sweep over every stored token and agent credential. Rewrites values under an
    /// older key to the first key and deletes rows whose value is unencrypted or opens with no
    /// listed key. Each table makes at most `change_limit` changes per run. Every update and
    /// delete matches the stored value it read, so replicas can run it at the same time.
    /// Logs, per table, counts only: values found under each key position, unencrypted values,
    /// unopenable values, rewrites and deletions.
    pub async fn sweep_stored_tokens(
        &self,
        change_limit: usize,
    ) -> Result<Vec<StoredTokenSweepReport>> {
        use futures::TryStreamExt;

        let mut reports: Vec<StoredTokenSweepReport> = Vec::new();
        for &(table, column) in STORED_TOKEN_COLUMNS {
            if reports.last().is_none_or(|report| report.table != table) {
                reports.push(StoredTokenSweepReport::new(
                    table,
                    self.token_cipher.key_count(),
                ));
            }
            let report = reports.last_mut().expect("report pushed above");

            let mut to_rewrite = Vec::new();
            let mut to_delete = Vec::new();
            // Table and column names come only from STORED_TOKEN_COLUMNS.
            let query =
                format!("SELECT {column} FROM mcp_oauth.{table} WHERE {column} IS NOT NULL");
            let mut rows =
                sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(query)).fetch(&self.pool);
            while let Some(stored) = rows.try_next().await.map_err(McpError::Database)? {
                let changes = report.changes_planned;
                if !TokenCipher::is_encrypted(&stored) {
                    report.unencrypted += 1;
                    if changes < change_limit {
                        report.changes_planned += 1;
                        to_delete.push(stored);
                    }
                    continue;
                }
                match self.token_cipher.decrypt_with_key_position(&stored) {
                    Ok((plaintext, position)) => {
                        drop(Zeroizing::new(plaintext));
                        report.values_by_key[position] += 1;
                        if position != 0 && changes < change_limit {
                            report.changes_planned += 1;
                            to_rewrite.push(stored);
                        }
                    }
                    Err(_) => {
                        report.unopenable += 1;
                        if changes < change_limit {
                            report.changes_planned += 1;
                            to_delete.push(stored);
                        }
                    }
                }
            }
            drop(rows);

            let delete = format!("DELETE FROM mcp_oauth.{table} WHERE {column} = $1");
            for stored in &to_delete {
                let result = sqlx::query(sqlx::AssertSqlSafe(delete.clone()))
                    .bind(stored)
                    .execute(&self.pool)
                    .await
                    .map_err(McpError::Database)?;
                report.deleted += result.rows_affected();
            }
            for stored in &to_rewrite {
                report.rewritten += self.rewrite_stored_value(table, column, stored).await;
            }
        }

        for report in &reports {
            tracing::info!(
                event = "stored_token_key_sweep",
                table = report.table,
                values_by_key = ?report.values_by_key,
                unencrypted = report.unencrypted,
                unopenable = report.unopenable,
                rewritten = report.rewritten,
                deleted = report.deleted,
                "{}",
                report.log_message()
            );
        }
        Ok(reports)
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
        request: HostedPasswordsAgentUpsert<'_>,
    ) -> Result<()> {
        let credential_bundle = HostedPasswordsAgentSecretBundleRef {
            user_id: request.user_id,
            credential_subject: request.credential_subject,
            identity_id: request.identity_id,
            kem_private: request.kem_private,
            api_key: request.api_key,
            api_key_id: request.api_key_id,
            api_key_organization_id: request.api_key_organization_id,
        };
        let credential_json =
            Zeroizing::new(serde_json::to_string(&credential_bundle).map_err(|e| {
                McpError::Config(format!("Hosted passwords credential encode failed: {e}"))
            })?);
        let credential_ciphertext = self.token_cipher.encrypt(&credential_json)?;

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.hosted_passwords_agents
                (user_id, credential_subject, identity_id, display_name,
                    credential_ciphertext, granted_vaults)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, credential_subject)
            DO UPDATE SET
                identity_id = EXCLUDED.identity_id,
                display_name = EXCLUDED.display_name,
                credential_ciphertext = EXCLUDED.credential_ciphertext,
                granted_vaults = EXCLUDED.granted_vaults
            "#,
        )
        .bind(request.user_id)
        .bind(request.credential_subject)
        .bind(request.identity_id)
        .bind(request.display_name)
        .bind(&credential_ciphertext)
        .bind(request.granted_vaults)
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
            credential_subject: request.credential_subject,
            request_id: request.request_id,
            kem_private: request.kem_private,
            consent_capability: request.consent_capability,
        };
        let credential_json =
            Zeroizing::new(serde_json::to_string(&credential_bundle).map_err(|e| {
                McpError::Config(format!("Hosted passwords request encode failed: {e}"))
            })?);
        let credential_ciphertext = self.token_cipher.encrypt(&credential_json)?;

        sqlx::query(
            r#"
            INSERT INTO mcp_oauth.hosted_passwords_agent_requests
                (user_id, credential_subject, request_id, display_name,
                    kem_public, signing_public, credential_ciphertext, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (user_id, credential_subject)
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
        .bind(request.credential_subject)
        .bind(request.request_id)
        .bind(request.display_name)
        .bind(request.kem_public)
        .bind(request.signing_public)
        .bind(&credential_ciphertext)
        .bind(request.expires_at.to_sqlx())
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    pub async fn get_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        credential_subject: &str,
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
            WHERE user_id = $1
                AND credential_subject = $2
                AND request_id = $3
                AND expires_at > NOW()
            "#,
        )
        .bind(user_id)
        .bind(credential_subject)
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
        let credential_json = self
            .open_hosted_passwords_credential(
                "hosted_passwords_agent_requests",
                &row.credential_ciphertext,
            )
            .await?;
        let bundle: HostedPasswordsAgentRequestSecretBundle =
            serde_json::from_str(&credential_json).map_err(|e| {
                McpError::Config(format!("Hosted passwords request decode failed: {e}"))
            })?;
        if bundle.user_id != user_id
            || bundle.credential_subject != credential_subject
            || bundle.request_id != row.request_id
        {
            return Err(McpError::Config(
                "Hosted passwords pending credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgentRequest {
            kem_public: row.kem_public,
            signing_public: row.signing_public,
            kem_private: Zeroizing::new(bundle.kem_private),
            consent_capability: bundle.consent_capability.map(Zeroizing::new),
        }))
    }

    pub async fn get_pending_hosted_passwords_agent_for_subject(
        &self,
        user_id: Uuid,
        credential_subject: &str,
    ) -> Result<Option<HostedPasswordsPendingAgentRequest>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            request_id: Uuid,
            credential_ciphertext: String,
        }

        let row = sqlx::query_as::<_, Row>(
            r#"
            SELECT request_id, credential_ciphertext
            FROM mcp_oauth.hosted_passwords_agent_requests
            WHERE user_id = $1
                AND credential_subject = $2
                AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(credential_subject)
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
        let credential_json = self
            .open_hosted_passwords_credential(
                "hosted_passwords_agent_requests",
                &row.credential_ciphertext,
            )
            .await?;
        let bundle: HostedPasswordsAgentRequestSecretBundle =
            serde_json::from_str(&credential_json).map_err(|e| {
                McpError::Config(format!("Hosted passwords request decode failed: {e}"))
            })?;
        if bundle.user_id != user_id
            || bundle.credential_subject != credential_subject
            || bundle.request_id != row.request_id
        {
            return Err(McpError::Config(
                "Hosted passwords pending credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsPendingAgentRequest {
            request_id: row.request_id,
            consent_capability: bundle.consent_capability.map(Zeroizing::new),
        }))
    }

    pub async fn claim_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        credential_subject: &str,
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
                AND credential_subject = $2
                AND request_id = $3
                AND expires_at > NOW()
                AND (
                    finalizing_at IS NULL
                    OR finalizing_at < NOW() - INTERVAL '5 minutes'
                )
            RETURNING request_id, kem_public, signing_public, credential_ciphertext
            "#,
        )
        .bind(user_id)
        .bind(credential_subject)
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
        let credential_json = self
            .open_hosted_passwords_credential(
                "hosted_passwords_agent_requests",
                &row.credential_ciphertext,
            )
            .await?;
        let bundle: HostedPasswordsAgentRequestSecretBundle =
            serde_json::from_str(&credential_json).map_err(|e| {
                McpError::Config(format!("Hosted passwords request decode failed: {e}"))
            })?;
        if bundle.user_id != user_id
            || bundle.credential_subject != credential_subject
            || bundle.request_id != row.request_id
        {
            return Err(McpError::Config(
                "Hosted passwords pending credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgentRequest {
            kem_public: row.kem_public,
            signing_public: row.signing_public,
            kem_private: Zeroizing::new(bundle.kem_private),
            consent_capability: bundle.consent_capability.map(Zeroizing::new),
        }))
    }

    pub async fn delete_pending_hosted_passwords_agent(
        &self,
        user_id: Uuid,
        credential_subject: &str,
        request_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.hosted_passwords_agent_requests
            WHERE user_id = $1 AND credential_subject = $2 AND request_id = $3
            "#,
        )
        .bind(user_id)
        .bind(credential_subject)
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
        credential_subject: &str,
    ) -> Result<Option<HostedPasswordsAgent>> {
        #[derive(sqlx::FromRow)]
        struct HostedPasswordsAgentRow {
            identity_id: Uuid,
            display_name: String,
            credential_ciphertext: String,
            granted_vaults: serde_json::Value,
        }

        let row = sqlx::query_as::<_, HostedPasswordsAgentRow>(
            r#"
            SELECT
                identity_id,
                display_name,
                credential_ciphertext,
                granted_vaults
            FROM mcp_oauth.hosted_passwords_agents
            WHERE user_id = $1 AND credential_subject = $2
            ORDER BY updated_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(credential_subject)
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
        let credential_json = self
            .open_hosted_passwords_credential("hosted_passwords_agents", &row.credential_ciphertext)
            .await?;
        let bundle: HostedPasswordsAgentSecretBundle = serde_json::from_str(&credential_json)
            .map_err(|e| {
                McpError::Config(format!("Hosted passwords credential decode failed: {e}"))
            })?;
        if bundle.user_id != user_id
            || bundle.credential_subject != credential_subject
            || bundle.identity_id != row.identity_id
        {
            return Err(McpError::Config(
                "Hosted passwords agent credential binding mismatch".into(),
            ));
        }

        Ok(Some(HostedPasswordsAgent {
            identity_id: row.identity_id,
            display_name: row.display_name,
            kem_private: Zeroizing::new(bundle.kem_private),
            api_key: bundle.api_key.map(Zeroizing::new),
            api_key_id: bundle.api_key_id,
            api_key_organization_id: bundle.api_key_organization_id,
            granted_vaults: row.granted_vaults,
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
        .bind(req.expires_at.to_sqlx())
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
        .bind(code.expires_at.to_sqlx())
        .bind(&upstream_access_token)
        .bind(upstream_refresh_token.as_deref())
        .bind(code.upstream_expires_at.to_sqlx())
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

        // The code is already consumed, so a value under an older key needs no rewrite.
        let Some(mut auth_code) = auth_code else {
            return Ok(None);
        };
        let Some((access, refresh, _)) = self.open_upstream_tokens(
            "authorization_codes",
            &Self::hash_refresh_token(&auth_code.code),
            &auth_code.upstream_access_token,
            auth_code.upstream_refresh_token.as_deref(),
        ) else {
            return Ok(None);
        };
        auth_code.upstream_access_token = access;
        auth_code.upstream_refresh_token = refresh;
        Ok(Some(auth_code))
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
        .bind(token.expires_at.map(ToSqlx::to_sqlx))
        .bind(&upstream_access_token)
        .bind(upstream_refresh_token.as_deref())
        .bind(token.upstream_expires_at.to_sqlx())
        .execute(&self.pool)
        .await
        .map_err(McpError::Database)?;

        Ok(())
    }

    /// Get a refresh token (includes upstream token vault)
    pub async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let token_hash = Self::hash_refresh_token(token);
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
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

        match refresh_token {
            Some(refresh_token) => Ok(self.open_refresh_token(refresh_token).await),
            None => Ok(None),
        }
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
        let refresh_token = sqlx::query_as::<_, RefreshToken>(
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

        match refresh_token {
            Some(refresh_token) => Ok(self.open_refresh_token(refresh_token).await),
            None => Ok(None),
        }
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

    /// Revoke the session row an MCP access token names: its `rth` hash, owned by the token's
    /// user and client. Returns whether a row was deleted.
    pub async fn revoke_refresh_token_by_hash(
        &self,
        token_hash: &str,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<bool> {
        let result = sqlx::query(
            r#"
            DELETE FROM mcp_oauth.refresh_tokens
            WHERE token_hash = $1 AND user_id = $2 AND client_id = $3
            "#,
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(client_id)
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
        new_expires_at: Timestamp,
        renew_before: Timestamp,
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
        .bind(new_expires_at.to_sqlx())
        .bind(renew_before.to_sqlx())
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
        upstream_expires_at: Timestamp,
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
        .bind(upstream_expires_at.to_sqlx())
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
    ) -> Result<Option<(String, Timestamp)>> {
        let token_hash = if Self::looks_like_sha256_hex(refresh_token_or_hash) {
            refresh_token_or_hash.to_string()
        } else {
            Self::hash_refresh_token(refresh_token_or_hash)
        };

        let refresh_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT token_hash, client_id, user_id, scope, expires_at, created_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at
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

        let Some(refresh_token) = refresh_token else {
            return Ok(None);
        };
        Ok(self
            .open_refresh_token(refresh_token)
            .await
            .map(|token| (token.upstream_access_token, token.upstream_expires_at)))
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
        }

        match refresh_token {
            Some(refresh_token) => Ok(self.open_refresh_token(refresh_token).await),
            None => Ok(None),
        }
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
        .bind(consent.expires_at.to_sqlx())
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

    pub(crate) fn looks_like_sha256_hex(value: &str) -> bool {
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
    pub fn token_expiry(duration_hours: i64) -> Timestamp {
        Timestamp::now() + SignedDuration::from_hours(duration_hours)
    }

    /// Create authorization code expiry (short-lived, 10 minutes)
    pub fn code_expiry() -> Timestamp {
        Timestamp::now() + SignedDuration::from_mins(10)
    }
}

#[cfg(test)]
pub(crate) fn integration_tests_enabled() -> bool {
    std::env::var("SEREN_MCP_INTEGRATION_TESTS")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| v == "1" || v == "true" || v == "yes" || v == "on")
}

/// Fixture cipher for tests that need a store.
#[cfg(test)]
pub(crate) fn test_token_cipher() -> TokenCipher {
    TokenCipher::from_keys(&["synthetic-token-encryption-key-32-bytes"]).unwrap()
}

#[cfg(test)]
pub(crate) async fn test_token_store() -> (
    testcontainers::ContainerAsync<testcontainers::GenericImage>,
    TokenStore,
) {
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };

    let container = GenericImage::new("postgres", "11-alpine")
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_wait_for(WaitFor::message_on_stdout(
            "database system is ready to accept connections",
        ))
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_DB", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_cmd(["-c", "fsync=off"])
        .with_mapped_port(0, 5432.tcp())
        .with_host_config_modifier(|config| {
            if let Some(ports) = config.port_bindings.as_mut() {
                for bindings in ports.values_mut().flatten() {
                    for binding in bindings {
                        binding.host_ip = Some("127.0.0.1".into());
                    }
                }
            }
        })
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);

    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrator = sqlx::migrate::Migrator::new(migrations_dir).await.unwrap();
    migrator.run(&pool).await.unwrap();

    let store = TokenStore::new(pool, test_token_cipher());
    (container, store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_without_token_cipher_cannot_be_created() {
        // The keys are checked before any connection, so an unreachable database is enough.
        let result = temp_env::async_with_vars(
            [("OAUTH_TOKEN_ENCRYPTION_KEYS", None::<&str>)],
            TokenStore::connect("postgresql://postgres@127.0.0.1:1/unreachable"),
        )
        .await;
        match result {
            Err(McpError::Config(message)) => {
                assert!(message.contains("OAUTH_TOKEN_ENCRYPTION_KEYS"), "{message}");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("a store without a cipher must not be created"),
        }
    }

    async fn insert_refresh_token_row(pool: &PgPool, token_hash: &str, access: &str) {
        sqlx::query(
            "INSERT INTO mcp_oauth.refresh_tokens
                (token_hash, client_id, user_id, scope, expires_at,
                upstream_access_token, upstream_refresh_token, upstream_expires_at)
            VALUES ($1, 'key-client', $2, 'api', NULL, $3, NULL, NOW() + INTERVAL '1 hour')",
        )
        .bind(token_hash)
        .bind(Uuid::new_v4())
        .bind(access)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn stored_access_token(pool: &PgPool, token_hash: &str) -> Option<String> {
        sqlx::query_scalar(
            "SELECT upstream_access_token FROM mcp_oauth.refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn stored_tokens_are_refused_moved_to_the_first_key_and_swept() {
        if !integration_tests_enabled() {
            eprintln!("skipping: set SEREN_MCP_INTEGRATION_TESTS=1 to run Postgres tests");
            return;
        }
        let (_container, store) = test_token_store().await;
        let pool = store.pool().clone();
        sqlx::query(
            "INSERT INTO mcp_oauth.clients (id, name, redirect_uris, grants, scopes)
            VALUES ('key-client', 'Key client', ARRAY['http://localhost/callback'],
                ARRAY['authorization_code'], ARRAY['api'])",
        )
        .execute(&pool)
        .await
        .unwrap();

        const OLD_KEY: &str = "old-synthetic-token-encryption-key-32b";
        const NEW_KEY: &str = "new-synthetic-token-encryption-key-32b";
        const LOST_KEY: &str = "lost-synthetic-token-encryption-key-32";
        let old = TokenCipher::from_keys(&[OLD_KEY]).unwrap();
        let lost = TokenCipher::from_keys(&[LOST_KEY]).unwrap();
        let rotated = TokenStore::new(
            pool.clone(),
            TokenCipher::from_keys(&[NEW_KEY, OLD_KEY]).unwrap(),
        );
        let only_new = TokenCipher::from_keys(&[NEW_KEY]).unwrap();

        // An unencrypted stored value is refused: the row reads as absent (sign in again).
        let plain_hash = TokenStore::hash_refresh_token("plain-row");
        insert_refresh_token_row(&pool, &plain_hash, "plain-upstream-token").await;
        assert!(
            rotated
                .get_refresh_token_by_hash(&plain_hash)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            rotated
                .get_refresh_token("plain-row")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            rotated
                .get_upstream_token(&plain_hash)
                .await
                .unwrap()
                .is_none()
        );

        // A value under the second key is under the first key after one read.
        let read_hash = TokenStore::hash_refresh_token("read-row");
        insert_refresh_token_row(&pool, &read_hash, &old.encrypt("read-access").unwrap()).await;
        let token = rotated
            .get_refresh_token_by_hash(&read_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.upstream_access_token, "read-access");
        let stored = stored_access_token(&pool, &read_hash).await.unwrap();
        assert_eq!(only_new.decrypt(&stored).unwrap(), "read-access");

        // An idle value under the second key moves with the sweep, without any read.
        let idle_hash = TokenStore::hash_refresh_token("idle-row");
        insert_refresh_token_row(&pool, &idle_hash, &old.encrypt("idle-access").unwrap()).await;
        // A value no listed key opens is deleted by the sweep.
        let lost_hash = TokenStore::hash_refresh_token("lost-row");
        let lost_value = lost.encrypt("lost-access").unwrap();
        insert_refresh_token_row(&pool, &lost_hash, &lost_value).await;
        // An unencrypted hosted passwords credential is deleted too.
        sqlx::query(
            "INSERT INTO mcp_oauth.hosted_passwords_agents
                (user_id, credential_subject, identity_id, display_name,
                credential_ciphertext, granted_vaults)
            VALUES ($1, 'user', $2, 'Plain', 'plain-credential', '[]'::jsonb)",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();

        let reports = rotated
            .sweep_stored_tokens(STORED_TOKEN_SWEEP_CHANGE_LIMIT)
            .await
            .unwrap();
        let refresh = reports
            .iter()
            .find(|r| r.table == "refresh_tokens")
            .unwrap();
        assert_eq!(refresh.values_by_key, vec![1, 1]);
        assert_eq!(refresh.unencrypted, 1);
        assert_eq!(refresh.unopenable, 1);
        assert_eq!(refresh.rewritten, 1);
        assert_eq!(refresh.deleted, 2);
        let message = refresh.log_message();
        assert!(message.contains("opened by no key 1"), "{message}");
        assert!(message.contains("deleted 2"), "{message}");
        for secret in [
            "plain-upstream-token",
            "idle-access",
            "lost-access",
            lost_value.as_str(),
        ] {
            assert!(!message.contains(secret), "{message}");
        }
        let agents = reports
            .iter()
            .find(|r| r.table == "hosted_passwords_agents")
            .unwrap();
        assert_eq!((agents.unencrypted, agents.deleted), (1, 1));

        let stored = stored_access_token(&pool, &idle_hash).await.unwrap();
        assert_eq!(only_new.decrypt(&stored).unwrap(), "idle-access");
        assert!(stored_access_token(&pool, &lost_hash).await.is_none());
        assert!(stored_access_token(&pool, &plain_hash).await.is_none());

        // A second run finds nothing under the old key and nothing to clear.
        let reports = rotated
            .sweep_stored_tokens(STORED_TOKEN_SWEEP_CHANGE_LIMIT)
            .await
            .unwrap();
        for report in &reports {
            assert_eq!(report.values_by_key[1], 0, "{}", report.log_message());
            assert_eq!(
                report.unencrypted + report.unopenable,
                0,
                "{}",
                report.log_message()
            );
        }

        // The retired session table is gone and cleanup still runs.
        let exists: bool =
            sqlx::query_scalar("SELECT to_regclass('mcp_oauth.mcp_sessions') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!exists);
        store.cleanup_expired(Some(10)).await.unwrap();
    }

    #[test]
    fn sweep_log_message_carries_counts_only() {
        let mut report = StoredTokenSweepReport::new("refresh_tokens", 2);
        report.values_by_key = vec![4, 1];
        report.unencrypted = 2;
        report.unopenable = 3;
        report.rewritten = 1;
        report.deleted = 5;
        assert_eq!(
            report.log_message(),
            "Stored token sweep of mcp_oauth.refresh_tokens: values by key position \
             [key 0: 4, key 1: 1], unencrypted 2, opened by no key 3, rewritten 1, deleted 5"
        );
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
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
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
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
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
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
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
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
        };

        // Non-localhost wildcards should be rejected for security
        assert!(!client.allows_redirect_uri("https://example.com/callback"));
        assert!(!client.allows_redirect_uri("https://example.com/anything"));
    }
    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL through Docker"]
    async fn postgres_timestamps_preserve_instants_and_nullable_expiry() {
        use testcontainers::{
            GenericImage, ImageExt,
            core::{IntoContainerPort, WaitFor},
            runners::AsyncRunner,
        };

        let container = GenericImage::new("postgres", "11-alpine")
            .with_wait_for(WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            ))
            .with_wait_for(WaitFor::message_on_stdout(
                "database system is ready to accept connections",
            ))
            .with_exposed_port(5432.tcp())
            .with_env_var("POSTGRES_DB", "postgres")
            .with_env_var("POSTGRES_USER", "postgres")
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_cmd(["-c", "fsync=off"])
            .with_mapped_port(0, 5432.tcp())
            .with_host_config_modifier(|config| {
                if let Some(ports) = config.port_bindings.as_mut() {
                    for bindings in ports.values_mut().flatten() {
                        for binding in bindings {
                            binding.host_ip = Some("127.0.0.1".into());
                        }
                    }
                }
            })
            .start()
            .await
            .unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let pool = PgPool::connect(&format!(
            "postgres://postgres:postgres@127.0.0.1:{port}/postgres"
        ))
        .await
        .unwrap();
        let user_id = Uuid::new_v4();
        for (input, expected) in [
            (
                "1960-01-02T03:04:05.123456-05:30",
                "1960-01-02T03:04:05.123456-05:30",
            ),
            (
                "2030-01-02T03:04:05.987654+05:30",
                "2030-01-02T03:04:05.987654+05:30",
            ),
            (
                "1960-01-02T03:04:05.123456789-05:30",
                "1960-01-02T03:04:05.123457-05:30",
            ),
            (
                "2030-01-02T03:04:05.987654321+05:30",
                "2030-01-02T03:04:05.987654+05:30",
            ),
        ] {
            let instant: Timestamp = input.parse().unwrap();
            let expected: Timestamp = expected.parse().unwrap();
            for expiry in [None, Some(instant)] {
                let token = sqlx::query_as::<_, RefreshToken>(
                    "SELECT 'hash'::TEXT AS token_hash, 'client'::TEXT AS client_id,
                        $1::UUID AS user_id, 'scope'::TEXT AS scope,
                        $2::TIMESTAMPTZ AS expires_at, $3::TIMESTAMPTZ AS created_at,
                        'access'::TEXT AS upstream_access_token,
                        NULL::TEXT AS upstream_refresh_token,
                        $3::TIMESTAMPTZ AS upstream_expires_at",
                )
                .bind(user_id)
                .bind(expiry.map(ToSqlx::to_sqlx))
                .bind(instant.to_sqlx())
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(token.expires_at, expiry.map(|_| expected));
                assert_eq!(token.created_at, expected);
                assert_eq!(token.upstream_expires_at, expected);
                assert_eq!(token.user_id, user_id);
                assert_eq!(token.upstream_access_token, "access");
                assert_eq!(token.upstream_refresh_token, None);
            }
        }
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO mcp_oauth.clients
            (id, name, redirect_uris, grants, scopes)
            VALUES ('timestamp-client', 'Timestamp client',
                ARRAY['http://localhost/callback'], ARRAY['authorization_code'], ARRAY['api'])",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut store = TokenStore::new(pool.clone(), test_token_cipher());
        let now = Timestamp::from_microsecond(Timestamp::now().as_microsecond()).unwrap();
        let future = now + SignedDuration::from_hours(1);
        for (index, expiry) in [None, Some(future), Some(now - SignedDuration::from_mins(1))]
            .into_iter()
            .enumerate()
        {
            let hash = TokenStore::hash_refresh_token(&format!("timestamp-token-{index}"));
            store
                .save_refresh_token(&RefreshToken {
                    token_hash: hash.clone(),
                    client_id: "timestamp-client".into(),
                    user_id,
                    scope: "api".into(),
                    expires_at: expiry,
                    created_at: now,
                    upstream_access_token: "initial-access".into(),
                    upstream_refresh_token: Some("initial-refresh".into()),
                    upstream_expires_at: future,
                })
                .await
                .unwrap();
            let active = expiry.is_none_or(|expires| expires > now);
            assert_eq!(
                store
                    .get_refresh_token_by_hash(&hash)
                    .await
                    .unwrap()
                    .is_some(),
                active
            );
            let renewed = future + SignedDuration::from_hours(1);
            assert_eq!(
                store
                    .extend_refresh_token_expiry_if_needed(&hash, renewed, renewed)
                    .await
                    .unwrap(),
                expiry.is_some() && active
            );
            let persisted: Option<jiff_sqlx::Timestamp> = sqlx::query_scalar(
                "SELECT expires_at FROM mcp_oauth.refresh_tokens WHERE token_hash = $1",
            )
            .bind(&hash)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                persisted.map(jiff_sqlx::Timestamp::to_jiff),
                if expiry.is_some() && active {
                    Some(renewed)
                } else {
                    expiry
                }
            );
            let upstream_expiry = future + SignedDuration::from_mins(15);
            assert_eq!(
                store
                    .update_upstream_tokens(
                        &hash,
                        "updated-access",
                        Some("updated-refresh"),
                        upstream_expiry
                    )
                    .await
                    .unwrap(),
                active
            );
            let upstream = store.get_upstream_token(&hash).await.unwrap();
            assert_eq!(
                upstream,
                active.then(|| ("updated-access".into(), upstream_expiry))
            );
            if let Some(token) = store.get_refresh_token_by_hash(&hash).await.unwrap() {
                assert_eq!(token.upstream_expires_at, upstream_expiry);
                assert_eq!(
                    token.upstream_refresh_token.as_deref(),
                    Some("updated-refresh")
                );
            }
        }
        // Build the existing cipher from a scoped disposable key before any await.
        store.token_cipher = temp_env::with_var(
            "OAUTH_TOKEN_ENCRYPTION_KEYS",
            Some("0707070707070707070707070707070707070707070707070707070707070707"),
            || TokenCipher::from_env().unwrap().expect("key set"),
        );
        let request_id = Uuid::new_v4();
        for expiry in [future, future + SignedDuration::from_mins(30)] {
            store
                .upsert_pending_hosted_passwords_agent(PendingHostedPasswordsAgentRequest {
                    user_id,
                    credential_subject: "user",
                    request_id,
                    display_name: "Fixture",
                    kem_public: "fixture-public",
                    signing_public: "fixture-signing",
                    kem_private: "fixture-private",
                    consent_capability: Some("fixture-consent"),
                    expires_at: expiry,
                })
                .await
                .unwrap();
            let persisted: jiff_sqlx::Timestamp = sqlx::query_scalar(
                "SELECT expires_at FROM mcp_oauth.hosted_passwords_agent_requests
                    WHERE user_id = $1 AND credential_subject = 'user'",
            )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(persisted.to_jiff(), expiry);
            assert!(
                store
                    .get_pending_hosted_passwords_agent(user_id, "user", request_id)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        pool.close().await;
    }

    #[test]
    fn token_and_code_expiry_use_absolute_durations() {
        let before = Timestamp::now();
        let token_expiry = TokenStore::token_expiry(24);
        let code_expiry = TokenStore::code_expiry();
        let after = Timestamp::now();
        assert!(token_expiry >= before + SignedDuration::from_hours(24));
        assert!(token_expiry <= after + SignedDuration::from_hours(24));
        assert!(code_expiry >= before + SignedDuration::from_mins(10));
        assert!(code_expiry <= after + SignedDuration::from_mins(10));
    }
}
