//! Seren MCP Server implementation using rmcp SDK
//!
//! This module provides the MCP server with all tools for managing
//! Seren database projects, branches, and SQL execution.
//!
//! # Local Wallet Support
//!
//! When running locally, users can provide a `WALLET_PRIVATE_KEY` environment
//! variable to enable local wallet signing for x402 payments. This allows AI
//! agents to make crypto payments without relying on the managed wallet API.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::signers::local::PrivateKeySigner;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, Extensions, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

#[derive(Clone)]
enum SerenAuth {
    StaticToken(String),
    FromRequestBearer,
}

/// Seren MCP Server
#[derive(Clone)]
pub struct SerenMcpServer {
    api_base_url: String,
    auth: SerenAuth,
    http_client: reqwest::Client,
    tool_router: ToolRouter<Self>,
    /// Optional local wallet for x402 payments when running locally.
    /// Loaded from WALLET_PRIVATE_KEY environment variable.
    local_wallet: Option<Arc<PrivateKeySigner>>,
}

// ============================================================================
// Path Parameter Types (reusable)
// ============================================================================

/// Path parameters for project-level operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ProjectPath {
    /// The project ID (UUID)
    pub project_id: Uuid,
}

/// Path parameters for branch-level operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct BranchPath {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
}

/// Path parameters for endpoint-level operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct EndpointPath {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// The endpoint ID (UUID)
    pub endpoint_id: Uuid,
}

/// Path parameters for endpoint restart (no branch_id needed)
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct EndpointRestartPath {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The endpoint ID (UUID)
    pub endpoint_id: Uuid,
}

/// Path parameters for organization-level operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct OrganizationPath {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
}

/// Path parameters for API key operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ApiKeyPath {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The API key ID (UUID)
    pub key_id: Uuid,
}

// ============================================================================
// Tool Parameter Types (path + body composition)
// ============================================================================

// Project operations (path only, no body for these)
pub type DescribeProjectParams = ProjectPath;
pub type DeleteProjectParams = ProjectPath;
pub type ListBranchesParams = ProjectPath;

// Branch operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateBranchParams {
    #[serde(flatten)]
    pub path: ProjectPath,
    #[serde(flatten)]
    pub body: seren::CreateBranchRequest,
}

pub type DescribeBranchParams = BranchPath;
pub type DeleteBranchParams = BranchPath;
pub type ListDatabasesParams = BranchPath;
pub type ListRolesParams = BranchPath;
pub type ListEndpointsParams = BranchPath;

// Database operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateDatabaseParams {
    #[serde(flatten)]
    pub path: BranchPath,
    #[serde(flatten)]
    pub body: seren::CreateDatabaseRequest,
}

// Endpoint operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateEndpointParams {
    #[serde(flatten)]
    pub path: BranchPath,
    #[serde(flatten)]
    pub body: seren::CreateEndpointRequest,
}

// API key operations
pub type ListApiKeysParams = OrganizationPath;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateApiKeyParams {
    #[serde(flatten)]
    pub path: OrganizationPath,
    #[serde(flatten)]
    pub body: seren::CreateApiKeyRequest,
}

pub type RevokeApiKeyParams = ApiKeyPath;

// Connection and SQL operations (branch path + additional params)
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetConnectionStringParams {
    #[serde(flatten)]
    pub path: BranchPath,
    #[serde(flatten)]
    pub query: seren::ConnectionStringQueryParams,
    /// Database name to include in the connection string (optional override)
    #[serde(default)]
    pub database: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RunSqlParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Database name
    pub database: String,
    /// SQL query to execute
    pub query: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RunSqlTransactionParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Database name
    pub database: String,
    /// SQL statements to run in a single transaction
    pub queries: Vec<String>,
    /// If set, request a read-only transaction
    #[serde(default)]
    pub read_only: Option<bool>,
    /// Transaction isolation level (e.g. "read_committed")
    #[serde(default)]
    pub isolation_level: Option<String>,
    /// If set, request a deferrable transaction
    #[serde(default)]
    pub deferrable: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetDatabaseTablesParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Database name
    pub database: String,
    /// Schema name (default: public)
    #[serde(default)]
    pub schema: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExplainSqlStatementParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Database name
    pub database: String,
    /// SQL query to explain
    pub query: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DescribeTableSchemaParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Database name
    pub database: String,
    /// Table name
    pub table_name: String,
    /// Schema name (default: public)
    #[serde(default)]
    pub schema: Option<String>,
}

// ============================================================================
// Agent Marketplace Parameter Types (agent paid access)
// ============================================================================

/// Parameters for listing publishers in the agent marketplace
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListAgentPublishersParams {
    /// Filter to only verified publishers
    #[serde(default)]
    pub is_verified: Option<bool>,
    /// Maximum number of publishers to return
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(default)]
    pub offset: Option<i64>,
    /// Search query to filter publishers by name or description
    #[serde(default)]
    pub search: Option<String>,
}

/// Parameters for getting a specific publisher by slug
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentPublisherParams {
    /// Publisher slug (URL-friendly identifier)
    pub slug: String,
}

/// Parameters for estimating query cost
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EstimateQueryCostParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// SQL query to estimate cost for
    pub query: String,
    /// Optional asset ID for cost estimate (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
}

/// Parameters for getting agent balance summary
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentBalanceParams {
    /// Agent wallet address (0x...)
    pub wallet_address: String,
}

/// Parameters for getting prepaid balance summary for the authenticated user
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetUserPrepaidBalanceParams {}

/// Parameters for creating a prepaid deposit for the authenticated user
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreatePrepaidDepositParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// Target asset UUID to credit after conversion
    pub target_asset_id: String,
    /// Amount in the currency's standard unit (e.g., 10.00 for $10 USD)
    pub amount: f64,
    /// ISO 4217 currency code (default: USD)
    #[serde(default)]
    pub currency: Option<String>,
    /// Payment provider (default: stripe)
    #[serde(default)]
    pub provider: Option<String>,
}

/// Parameters for getting agent balance at a specific publisher
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentPublisherBalanceParams {
    /// Agent wallet address (0x...)
    pub wallet_address: String,
    /// Publisher ID (UUID)
    pub publisher_id: Uuid,
}

/// Parameters for executing a paid query
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecutePaidQueryParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// SQL query to execute
    pub query: String,
    /// Database name (optional, defaults to publisher's default database)
    #[serde(default)]
    pub database: Option<String>,
    /// Optional asset ID for payment (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
    /// Optional idempotency key (UUID)
    #[serde(default)]
    pub request_id: Option<Uuid>,
}

/// Parameters for executing a prepaid API request
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecutePaidApiParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// Optional asset ID for payment (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
    /// HTTP method (default: POST)
    #[serde(default)]
    pub method: Option<String>,
    /// Optional relative path to append to the publisher base URL
    #[serde(default)]
    pub path: Option<String>,
    /// Optional request headers (will not override publisher headers)
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// Optional JSON body to send
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Optional estimated rows for pricing (default: 1000)
    #[serde(default)]
    pub estimated_rows: Option<i64>,
    /// Optional idempotency key (UUID)
    #[serde(default)]
    pub request_id: Option<Uuid>,
}

/// Parameters for creating a managed wallet
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateManagedWalletParams {
    /// Optional: set as primary wallet
    #[serde(default)]
    pub set_as_primary: Option<bool>,
}

/// Parameters for wallet operations that require a wallet ID
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct WalletIdParams {
    /// The wallet ID (UUID)
    pub wallet_id: Uuid,
}

/// Parameters for getting x402 on-chain deposit requirements
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetX402DepositRequirementsParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// Amount to deposit (decimal string, e.g., "10.50")
    pub amount: String,
    /// Agent wallet address to deposit for (0x...)
    pub agent_wallet: String,
    /// Optional asset ID for deposit (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
}

/// Parameters for creating a publisher (no params, uses empty object)
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetSupportedParams {}

/// Parameters for creating a publisher in the marketplace
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreatePublisherParams {
    /// Publisher display name
    pub name: String,
    /// URL-friendly slug (unique identifier)
    pub slug: String,
    /// Wallet address for receiving payments (0x...)
    pub wallet_address: String,
    /// Network ID for wallet (CAIP-2 format, e.g., "eip155:8453" for Base)
    pub wallet_network_id: String,
    /// Data source type (serendb or api)
    #[serde(default)]
    pub source_type: Option<String>,
    /// Publisher description
    #[serde(default)]
    pub description: Option<String>,
    /// External API URL (required for api source_type)
    #[serde(default)]
    pub api_url: Option<String>,
    /// SerenDB project ID (required for serendb source_type)
    #[serde(default)]
    pub project_id: Option<Uuid>,
    /// SerenDB branch ID (required for serendb source_type)
    #[serde(default)]
    pub branch_id: Option<Uuid>,
    /// Database name within the SerenDB project (default: serendb)
    #[serde(default)]
    pub database_name: Option<String>,
    /// Base price per 1000 rows (decimal string, e.g., "0.001")
    #[serde(default)]
    pub base_price_per_1000_rows: Option<String>,
    /// Billing model (x402_per_request, prepaid_credits, x402_passthrough)
    #[serde(default)]
    pub billing_model: Option<String>,
    /// Publisher categories (e.g., ["blockchain", "defi"])
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    /// Logo URL for marketplace listing
    #[serde(default)]
    pub logo_url: Option<String>,
}

/// Parameters for executing a paid streaming API request
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecutePaidApiStreamParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// Optional asset ID for payment (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
    /// HTTP method (default: POST)
    #[serde(default)]
    pub method: Option<String>,
    /// Optional relative path to append to the publisher base URL
    #[serde(default)]
    pub path: Option<String>,
    /// Optional request headers (will not override publisher headers)
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// Optional JSON body to send
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Optional estimated rows for pricing (default: 1000)
    #[serde(default)]
    pub estimated_rows: Option<i64>,
    /// Optional idempotency key (UUID)
    #[serde(default)]
    pub request_id: Option<Uuid>,
}

// ============================================================================
// SQL Response Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize)]
struct SqlRequest {
    query: String,
    params: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SqlBatchQuery {
    query: String,
    params: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SqlBatchRequest {
    queries: Vec<SqlBatchQuery>,
}

// ============================================================================
// Helper to convert to JSON content
// ============================================================================

fn json_content<T: Serialize>(data: &T) -> Result<Content, McpError> {
    let text = serde_json::to_string_pretty(data)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(Content::text(text))
}

async fn resolve_publisher_id(
    api_client: &seren::Client,
    publisher: &str,
) -> Result<Uuid, McpError> {
    if let Ok(uuid) = Uuid::parse_str(publisher) {
        return Ok(uuid);
    }

    let response = api_client
        .get_marketplace_publisher(publisher)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .into_inner();
    Ok(response.data.id)
}

fn connection_string_with_database(
    connection_string: &str,
    database: &str,
) -> Result<String, McpError> {
    validate_identifier(database, "database")?;

    let mut url = reqwest::Url::parse(connection_string)
        .map_err(|e| McpError::internal_error(format!("Invalid connection string: {}", e), None))?;
    url.set_path(&format!("/{}", database));
    Ok(url.to_string())
}

fn sql_proxy_url_from_connection_string(connection_string: &str) -> Result<String, McpError> {
    if let Ok(base_url) = std::env::var("SQL_PROXY_URL") {
        let base_url = base_url.trim();
        if !base_url.is_empty() {
            let mut url = reqwest::Url::parse(base_url).map_err(|e| {
                McpError::internal_error(format!("Invalid SQL_PROXY_URL: {}", e), None)
            })?;
            url.set_path("/sql");
            url.set_query(None);
            url.set_fragment(None);
            return Ok(url.to_string());
        }
    }

    let url = reqwest::Url::parse(connection_string)
        .map_err(|e| McpError::internal_error(format!("Invalid connection string: {}", e), None))?;
    let host = url.host_str().ok_or_else(|| {
        McpError::internal_error("Connection string missing host".to_string(), None)
    })?;
    Ok(format!("https://{}/sql", host))
}

/// Check if read-only mode is enabled.
///
/// Read-only mode can be enabled in two ways:
/// 1. Environment variable `READ_ONLY=true` (global, applies to all requests)
/// 2. HTTP header `x-read-only: true` (per-request, must be sent on each call)
///
/// Note: The `x-read-only` header is evaluated per-request. Clients must include
/// it on every request where they want write operations blocked.
fn is_read_only(extensions: &Extensions) -> bool {
    let env_read_only = std::env::var("READ_ONLY")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| v == "1" || v == "true" || v == "yes" || v == "on");
    if env_read_only {
        return true;
    }

    // Per-request header check - must be sent on each request
    let parts = extensions.get::<axum::http::request::Parts>();
    let header = parts
        .and_then(|p| p.headers.get("x-read-only"))
        .and_then(|v| v.to_str().ok());
    header
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| v == "1" || v == "true" || v == "yes" || v == "on")
}

fn ensure_writes_allowed(extensions: &Extensions) -> Result<(), McpError> {
    if is_read_only(extensions) {
        return Err(McpError::invalid_request(
            "Read-only mode: write operations are disabled",
            None,
        ));
    }
    Ok(())
}

fn extract_bearer_token_from_extensions(extensions: &Extensions) -> Option<String> {
    let parts = extensions.get::<axum::http::request::Parts>()?;
    let header = parts.headers.get(axum::http::header::AUTHORIZATION)?;
    let header = header.to_str().ok()?;
    let (scheme, token) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    } else {
        None
    }
}

/// Agent metadata extracted from OAuth client registration
#[derive(Debug, Clone, Default)]
struct AgentMetadata {
    client_id: Option<String>,
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
}

fn extract_agent_metadata_from_extensions(extensions: &Extensions) -> AgentMetadata {
    let parts = match extensions.get::<axum::http::request::Parts>() {
        Some(p) => p,
        None => return AgentMetadata::default(),
    };

    AgentMetadata {
        client_id: parts
            .headers
            .get("x-agent-client-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        client_name: parts
            .headers
            .get("x-agent-client-name")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        software_id: parts
            .headers
            .get("x-agent-software-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        software_version: parts
            .headers
            .get("x-agent-software-version")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    }
}

// ============================================================================
// Input Validation Helpers
// ============================================================================

/// Strict validation for PostgreSQL identifiers (database, schema, table names)
/// Must follow PostgreSQL naming rules: start with letter/underscore,
/// alphanumeric + underscore only
fn validate_identifier(name: &str, field: &str) -> Result<(), McpError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(McpError::invalid_params(
            format!("{} must not be empty", field),
            None,
        ));
    }
    if name.len() > 63 {
        return Err(McpError::invalid_params(
            format!("{} must not exceed 63 characters", field),
            None,
        ));
    }
    // PostgreSQL identifier rules: must start with letter or underscore
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return Err(McpError::invalid_params(
            format!("{} must start with a letter or underscore", field),
            None,
        ));
    }
    // Rest must be alphanumeric or underscore (strict PostgreSQL rules)
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(McpError::invalid_params(
            format!(
                "{} must contain only letters, numbers, and underscores",
                field
            ),
            None,
        ));
    }
    Ok(())
}

/// Relaxed validation for project/branch names (allows more characters)
fn validate_resource_name(name: &str, field: &str) -> Result<(), McpError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(McpError::invalid_params(
            format!("{} must not be empty", field),
            None,
        ));
    }
    if name.len() > 63 {
        return Err(McpError::invalid_params(
            format!("{} must not exceed 63 characters", field),
            None,
        ));
    }
    // Project/branch names: allow letters, numbers, spaces, hyphens, underscores
    // Must start with letter or number
    let first_char = name.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(McpError::invalid_params(
            format!("{} must start with a letter or number", field),
            None,
        ));
    }
    // Allow more characters for user-friendly naming
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ' || c == '.')
    {
        return Err(McpError::invalid_params(
            format!(
                "{} must contain only letters, numbers, spaces, hyphens, underscores, or dots",
                field
            ),
            None,
        ));
    }
    Ok(())
}

fn validate_sql_query(query: &str) -> Result<(), McpError> {
    let query = query.trim();
    if query.is_empty() {
        return Err(McpError::invalid_params("query must not be empty", None));
    }
    if query.len() > 1_000_000 {
        return Err(McpError::invalid_params("query must not exceed 1MB", None));
    }
    Ok(())
}

// ============================================================================
// Tool Implementations
// ============================================================================

impl SerenMcpServer {
    fn bearer_token(&self, extensions: &Extensions) -> Result<String, McpError> {
        match &self.auth {
            SerenAuth::StaticToken(token) => Ok(token.clone()),
            SerenAuth::FromRequestBearer => extract_bearer_token_from_extensions(extensions)
                .ok_or_else(|| McpError::invalid_request("Missing Bearer token", None)),
        }
    }

    fn build_http_client(
        &self,
        token: &str,
        agent_metadata: &AgentMetadata,
    ) -> Result<reqwest::Client, McpError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| McpError::internal_error(format!("Invalid token: {}", e), None))?;
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        // Forward agent metadata headers to the backend for tracking
        if let Some(ref client_id) = agent_metadata.client_id {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(client_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-agent-client-id"),
                    v,
                );
            }
        }
        if let Some(ref client_name) = agent_metadata.client_name {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(client_name) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-agent-client-name"),
                    v,
                );
            }
        }
        if let Some(ref software_id) = agent_metadata.software_id {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(software_id) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-agent-software-id"),
                    v,
                );
            }
        }
        if let Some(ref software_version) = agent_metadata.software_version {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(software_version) {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-agent-software-version"),
                    v,
                );
            }
        }

        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                McpError::internal_error(format!("Failed to build HTTP client: {}", e), None)
            })
    }

    fn api_client(&self, extensions: &Extensions) -> Result<seren::Client, McpError> {
        let token = self.bearer_token(extensions)?;
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(&token, &agent_metadata)?;
        Ok(seren::Client::new_with_client(
            &self.api_base_url,
            http_client,
        ))
    }

    #[instrument(skip(self, connection_string), fields(query_len = query.len()))]
    async fn execute_sql(
        &self,
        connection_string: &str,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, McpError> {
        let http_url = sql_proxy_url_from_connection_string(connection_string)?;

        tracing::debug!(url = %http_url, "Executing SQL query");

        let response = self
            .http_client
            .post(&http_url)
            .header("SerenDB-Connection-String", connection_string)
            .header("SerenDB-Pool-Opt-In", "true")
            .json(&SqlRequest {
                query: query.to_string(),
                params,
            })
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "SQL HTTP request failed");
                McpError::internal_error(e.to_string(), None)
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            // Log only status code by default to avoid leaking sensitive info
            // The full error is returned to the client but not logged
            tracing::error!(status = %status, "SQL execution failed");
            // Truncate error message for client to avoid exposing internal details
            let client_error = if error_text.len() > 500 {
                format!("{}... (truncated)", &error_text[..500])
            } else {
                error_text
            };
            return Err(McpError::internal_error(
                format!("SQL execution failed ({}): {}", status, client_error),
                None,
            ));
        }

        let result: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse SQL response");
            McpError::internal_error(format!("Failed to parse SQL response: {}", e), None)
        })?;

        tracing::debug!("SQL query completed");
        Ok(result)
    }

    #[instrument(skip(self, connection_string, queries), fields(query_count = queries.len()))]
    async fn execute_sql_transaction(
        &self,
        connection_string: &str,
        queries: Vec<String>,
        read_only: Option<bool>,
        isolation_level: Option<String>,
        deferrable: Option<bool>,
    ) -> Result<serde_json::Value, McpError> {
        let http_url = sql_proxy_url_from_connection_string(connection_string)?;

        tracing::debug!(url = %http_url, "Executing SQL transaction");

        let batch_queries: Vec<SqlBatchQuery> = queries
            .into_iter()
            .map(|query| SqlBatchQuery {
                query,
                params: vec![],
            })
            .collect();

        let mut request_builder = self
            .http_client
            .post(&http_url)
            .header("SerenDB-Connection-String", connection_string)
            .header("SerenDB-Pool-Opt-In", "true");

        if read_only.unwrap_or(false) {
            request_builder = request_builder.header("SerenDB-Batch-Read-Only", "true");
        }
        if let Some(level) = isolation_level.as_deref() {
            request_builder = request_builder.header("SerenDB-Batch-Isolation-Level", level);
        }
        if deferrable.unwrap_or(false) {
            request_builder = request_builder.header("SerenDB-Batch-Deferrable", "true");
        }

        let response = request_builder
            .json(&SqlBatchRequest {
                queries: batch_queries,
            })
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "SQL batch HTTP request failed");
                McpError::internal_error(e.to_string(), None)
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(status = %status, "SQL batch execution failed");
            let client_error = if error_text.len() > 500 {
                format!("{}... (truncated)", &error_text[..500])
            } else {
                error_text
            };
            return Err(McpError::internal_error(
                format!("SQL execution failed ({}): {}", status, client_error),
                None,
            ));
        }

        let result: serde_json::Value = response.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse SQL batch response");
            McpError::internal_error(format!("Failed to parse SQL batch response: {}", e), None)
        })?;

        Ok(result)
    }
}

#[tool_router]
impl SerenMcpServer {
    /// Try to load a local wallet from the WALLET_PRIVATE_KEY environment variable.
    ///
    /// The private key should be a hex string (with or without 0x prefix).
    fn load_local_wallet() -> Option<Arc<PrivateKeySigner>> {
        std::env::var("WALLET_PRIVATE_KEY").ok().and_then(|key| {
            let key = key.strip_prefix("0x").unwrap_or(&key);
            hex::decode(key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .and_then(|arr: [u8; 32]| PrivateKeySigner::from_bytes(&arr.into()).ok())
                .map(Arc::new)
        })
    }

    /// Create a new Seren MCP Server
    #[allow(clippy::result_large_err)]
    pub fn new(api_key: &str, api_base_url: &str) -> Result<Self, seren::Error> {
        let local_wallet = Self::load_local_wallet();
        if local_wallet.is_some() {
            tracing::info!("Local wallet loaded from WALLET_PRIVATE_KEY");
        }
        Ok(Self {
            api_base_url: api_base_url.to_string(),
            auth: SerenAuth::StaticToken(api_key.to_string()),
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
            local_wallet,
        })
    }

    /// Create a new Seren MCP Server in OAuth mode.
    ///
    /// In this mode the Seren API token is taken from each incoming HTTP request's
    /// `Authorization: Bearer ...` header (injected into [`Extensions`] by rmcp).
    #[allow(clippy::result_large_err)]
    pub fn new_oauth(api_base_url: &str) -> Result<Self, seren::Error> {
        let local_wallet = Self::load_local_wallet();
        if local_wallet.is_some() {
            tracing::info!("Local wallet loaded from WALLET_PRIVATE_KEY");
        }
        Ok(Self {
            api_base_url: api_base_url.to_string(),
            auth: SerenAuth::FromRequestBearer,
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
            local_wallet,
        })
    }

    #[tool(
        description = "List all Seren projects accessible to the authenticated user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_projects(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let projects = api_client
            .list_projects(None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&projects)?]))
    }

    #[tool(
        description = "Get detailed information about a specific project",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn describe_project(
        &self,
        Parameters(params): Parameters<DescribeProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let project = api_client
            .get_project(&params.project_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&project)?]))
    }

    #[tool(
        description = "Create a new Seren project",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    #[instrument(skip(self, extensions), fields(name = %request.name))]
    async fn create_project(
        &self,
        Parameters(request): Parameters<seren::CreateProjectRequest>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&request.name, "project name")?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .create_project(&request)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete a Seren project",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_project(
        &self,
        Parameters(params): Parameters<DeleteProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .delete_project(&params.project_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Project {} deleted successfully",
            params.project_id
        ))]))
    }

    #[tool(
        description = "Create a new branch in a project",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    #[instrument(
        skip(self, extensions),
        fields(project_id = %params.path.project_id, name = %params.body.name)
    )]
    async fn create_branch(
        &self,
        Parameters(params): Parameters<CreateBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&params.body.name, "branch name")?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .create_branch(&params.path.project_id, &params.body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete a branch",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_branch(
        &self,
        Parameters(params): Parameters<DeleteBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .delete_branch(&params.project_id, &params.branch_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Branch {} deleted successfully",
            params.branch_id
        ))]))
    }

    #[tool(
        description = "List all databases in a branch",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_databases(
        &self,
        Parameters(params): Parameters<ListDatabasesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let databases = api_client
            .list_databases(&params.project_id, &params.branch_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&databases)?]))
    }

    #[tool(
        description = "Create a new database in a branch",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    #[instrument(skip(self, extensions), fields(project_id = %params.path.project_id, branch_id = %params.path.branch_id, name = %params.body.name))]
    async fn create_database(
        &self,
        Parameters(params): Parameters<CreateDatabaseParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_identifier(&params.body.name, "database name")?;

        let api_client = self.api_client(&extensions)?;
        let database = api_client
            .create_database(
                &params.path.project_id,
                &params.path.branch_id,
                &params.body,
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&database)?]))
    }

    #[tool(
        description = "List all roles in a branch",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_roles(
        &self,
        Parameters(params): Parameters<ListRolesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let roles = api_client
            .list_branch_roles(&params.project_id, &params.branch_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&roles)?]))
    }

    #[tool(
        description = "Get connection string for a branch",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_connection_string(
        &self,
        Parameters(params): Parameters<GetConnectionStringParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .get_connection_string(
                &params.path.project_id,
                &params.path.branch_id,
                params.query.pooled,
                params.query.role.as_deref(),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let mut conn_str = response.data.connection_string;
        if let Some(database) = params.database.as_deref() {
            conn_str = connection_string_with_database(&conn_str, database)?;
        }

        Ok(CallToolResult::success(vec![json_content(
            &serde_json::json!({
                "connection_string": conn_str
            }),
        )?]))
    }

    #[tool(
        description = "Execute a SQL query against a database",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    #[instrument(skip(self, extensions, params), fields(project_id = %params.path.project_id, branch_id = %params.path.branch_id, database = %params.database))]
    async fn run_sql(
        &self,
        Parameters(params): Parameters<RunSqlParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_identifier(&params.database, "database")?;
        validate_sql_query(&params.query)?;

        // Get connection info from API
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .get_connection_string(&params.path.project_id, &params.path.branch_id, None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self.execute_sql(&conn_str, &params.query, vec![]).await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Execute multiple SQL statements in a single transaction",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn run_sql_transaction(
        &self,
        Parameters(params): Parameters<RunSqlTransactionParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_identifier(&params.database, "database")?;

        if params.queries.is_empty() {
            return Err(McpError::invalid_params("queries must not be empty", None));
        }
        if params.queries.len() > 100 {
            return Err(McpError::invalid_params(
                "queries must not exceed 100 statements",
                None,
            ));
        }
        for (idx, query) in params.queries.iter().enumerate() {
            if let Err(err) = validate_sql_query(query) {
                return Err(McpError::invalid_params(
                    format!("queries[{idx}]: {}", err.message),
                    None,
                ));
            }
        }

        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .get_connection_string(&params.path.project_id, &params.path.branch_id, None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self
            .execute_sql_transaction(
                &conn_str,
                params.queries,
                params.read_only,
                params.isolation_level,
                params.deferrable,
            )
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List tables in a database schema",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_database_tables(
        &self,
        Parameters(params): Parameters<GetDatabaseTablesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        validate_identifier(&params.database, "database")?;
        if let Some(ref schema) = params.schema {
            validate_identifier(schema, "schema")?;
        }
        let schema = params.schema.unwrap_or_else(|| "public".to_string());

        let query = r#"
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = $1
              AND table_type = 'BASE TABLE'
            ORDER BY table_name
        "#;

        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .get_connection_string(&params.path.project_id, &params.path.branch_id, None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self
            .execute_sql(&conn_str, query, vec![schema.into()])
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Explain a SQL statement (FORMAT JSON)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn explain_sql_statement(
        &self,
        Parameters(params): Parameters<ExplainSqlStatementParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        validate_identifier(&params.database, "database")?;
        validate_sql_query(&params.query)?;

        let query_trimmed = params.query.trim().trim_end_matches(';');
        let explain_query = format!("EXPLAIN (FORMAT JSON) {query_trimmed}");

        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .get_connection_string(&params.path.project_id, &params.path.branch_id, None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self.execute_sql(&conn_str, &explain_query, vec![]).await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Get schema information for a table",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    #[instrument(skip(self, extensions), fields(project_id = %params.path.project_id, branch_id = %params.path.branch_id, database = %params.database, table = %params.table_name))]
    async fn describe_table_schema(
        &self,
        Parameters(params): Parameters<DescribeTableSchemaParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        validate_identifier(&params.database, "database")?;
        validate_identifier(&params.table_name, "table_name")?;
        if let Some(ref schema) = params.schema {
            validate_identifier(schema, "schema")?;
        }

        let schema = params.schema.unwrap_or_else(|| "public".to_string());
        let query = r#"
            SELECT
                column_name,
                data_type,
                is_nullable,
                column_default,
                character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = $1
              AND table_name = $2
            ORDER BY ordinal_position
        "#;

        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .get_connection_string(&params.path.project_id, &params.path.branch_id, None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self
            .execute_sql(
                &conn_str,
                query,
                vec![schema.into(), params.table_name.into()],
            )
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List organizations accessible to the authenticated user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_organizations(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let orgs = api_client
            .list_organizations()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&orgs)?]))
    }

    #[tool(
        description = "List branches for a project",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_branches(
        &self,
        Parameters(params): Parameters<ListBranchesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let branches = api_client
            .list_branches(&params.project_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&branches)?]))
    }

    #[tool(
        description = "Describe a branch",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn describe_branch(
        &self,
        Parameters(params): Parameters<DescribeBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let branch = api_client
            .get_branch(&params.project_id, &params.branch_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&branch)?]))
    }

    // ========================================================================
    // Endpoint Tools
    // ========================================================================

    #[tool(
        description = "List all endpoints for a branch",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_endpoints(
        &self,
        Parameters(params): Parameters<ListEndpointsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let endpoints = api_client
            .list_endpoints(&params.project_id, &params.branch_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&endpoints)?]))
    }

    #[tool(
        description = "Create a new endpoint for a branch",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_endpoint(
        &self,
        Parameters(params): Parameters<CreateEndpointParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let endpoint = api_client
            .create_endpoint(
                &params.path.project_id,
                &params.path.branch_id,
                &params.body,
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&endpoint)?]))
    }

    #[tool(
        description = "Delete an endpoint",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_endpoint(
        &self,
        Parameters(params): Parameters<EndpointPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .delete_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Endpoint {} deleted successfully",
            params.endpoint_id
        ))]))
    }

    #[tool(
        description = "Start a suspended endpoint",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn start_endpoint(
        &self,
        Parameters(params): Parameters<EndpointPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let endpoint = api_client
            .start_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&endpoint)?]))
    }

    #[tool(
        description = "Suspend an endpoint",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn suspend_endpoint(
        &self,
        Parameters(params): Parameters<EndpointPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .stop_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Endpoint {} suspended successfully",
            params.endpoint_id
        ))]))
    }

    #[tool(
        description = "Restart an endpoint (rolling restart via Kubernetes)",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn restart_endpoint(
        &self,
        Parameters(params): Parameters<EndpointRestartPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .restart_project_endpoint(&params.project_id, &params.endpoint_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let status = response.into_inner();
        Ok(CallToolResult::success(vec![json_content(&status)?]))
    }

    // ========================================================================
    // API Key Tools
    // ========================================================================

    #[tool(
        description = "List all API keys for an organization",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_api_keys(
        &self,
        Parameters(params): Parameters<ListApiKeysParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let api_keys = api_client
            .list_org_api_keys(&params.organization_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&api_keys)?]))
    }

    #[tool(
        description = "Create a new API key for an organization",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    #[instrument(skip(self, extensions), fields(organization_id = %params.path.organization_id, name = %params.body.name))]
    async fn create_api_key(
        &self,
        Parameters(params): Parameters<CreateApiKeyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&params.body.name, "API key name")?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .create_org_api_key(&params.path.organization_id, &params.body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Revoke an API key",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn revoke_api_key(
        &self,
        Parameters(params): Parameters<RevokeApiKeyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .revoke_org_api_key(&params.organization_id, &params.key_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "API key {} revoked successfully",
            params.key_id
        ))]))
    }

    // ========================================================================
    // Agent Marketplace Tools (agent paid access)
    // ========================================================================

    #[tool(
        description = "List all active publishers in the agent marketplace. Publishers provide databases that AI agents can query with micropayments.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_agent_publishers(
        &self,
        Parameters(params): Parameters<ListAgentPublishersParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publishers = api_client
            .list_marketplace_publishers(
                params.is_verified,
                params.limit,
                params.offset,
                params.search.as_deref(),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&publishers)?]))
    }

    #[tool(
        description = "Get details about a specific publisher including pricing info by slug",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_agent_publisher(
        &self,
        Parameters(params): Parameters<GetAgentPublisherParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher = api_client
            .get_marketplace_publisher(&params.slug)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&publisher)?]))
    }

    #[tool(
        description = "Estimate the cost of a SQL query against a publisher's database without executing it",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn estimate_query_cost(
        &self,
        Parameters(params): Parameters<EstimateQueryCostParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;
        let body = seren::EstimateRequestBody {
            publisher_id,
            asset_id: params.asset_id,
            query: params.query,
        };
        let estimate = api_client
            .estimate_query(&body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&estimate)?]))
    }

    #[tool(
        description = "Get agent balance summary across all publishers for a given wallet address",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_agent_balance(
        &self,
        Parameters(params): Parameters<GetAgentBalanceParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let balance = api_client
            .get_agent_balance_summary(&params.wallet_address)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&balance)?]))
    }

    #[tool(
        description = "Get prepaid balance summary for the authenticated user (virtual wallet)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_prepaid_balance(
        &self,
        Parameters(_params): Parameters<GetUserPrepaidBalanceParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let balance = api_client
            .get_user_balance_summary()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&balance)?]))
    }

    #[tool(
        description = "Create a prepaid deposit for the authenticated user. Returns provider client data (e.g., Stripe client_secret) to complete payment.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_prepaid_deposit(
        &self,
        Parameters(params): Parameters<CreatePrepaidDepositParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;
        let currency = params.currency.unwrap_or_else(|| "USD".to_string());
        let provider = params.provider.as_deref().unwrap_or("stripe");
        let provider_enum = match provider {
            "stripe" => seren::FiatPaymentProvider::Stripe,
            "paypal" => seren::FiatPaymentProvider::Paypal,
            "coinbase" => seren::FiatPaymentProvider::Coinbase,
            "wire" => seren::FiatPaymentProvider::Wire,
            _ => {
                return Err(McpError::invalid_request(
                    format!("Unsupported provider: {}", provider),
                    None,
                ));
            }
        };

        let target_asset_id = uuid::Uuid::parse_str(&params.target_asset_id).map_err(|e| {
            McpError::invalid_request(format!("Invalid target_asset_id: {}", e), None)
        })?;
        let request = seren::CreateUserDepositRequest {
            publisher_id,
            target_asset_id,
            amount: params.amount,
            currency: Some(currency),
            provider: Some(provider_enum),
        };

        let deposit = api_client
            .create_user_deposit(&request)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&deposit)?]))
    }

    #[tool(
        description = "Get agent balance for a specific publisher",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_agent_publisher_balance(
        &self,
        Parameters(params): Parameters<GetAgentPublisherBalanceParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let balance = api_client
            .get_agent_publisher_balance(&params.wallet_address, &params.publisher_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&balance)?]))
    }

    #[tool(
        description = "Execute a prepaid SQL query against a publisher's database using the authenticated user's virtual wallet. This uses prepaid balance (fiat/Stripe) and does not require x402 signatures.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn execute_paid_query(
        &self,
        Parameters(params): Parameters<ExecutePaidQueryParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;
        let body = seren::QueryRequestBody {
            publisher_id,
            asset_id: params.asset_id,
            query: params.query,
            database: params.database,
            request_id: params.request_id,
        };

        match api_client.execute_query(&body).await {
            Ok(response) => {
                let result = response.into_inner();
                Ok(CallToolResult::success(vec![json_content(&result)?]))
            }
            Err(e) => {
                // Handle specific error codes with user-friendly messages
                if let Some(status) = e.status() {
                    if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                        return Err(McpError::invalid_request(
                            "Insufficient prepaid balance. Fund your wallet in the Seren console and retry.".to_string(),
                            None,
                        ));
                    }
                    if status == reqwest::StatusCode::CONFLICT {
                        return Err(McpError::invalid_request(
                            "Duplicate request_id. Provide a new UUID and retry.".to_string(),
                            None,
                        ));
                    }
                }
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    #[tool(
        description = "Execute a prepaid API request against a publisher's endpoint using the authenticated user's virtual wallet. This uses prepaid balance (fiat/Stripe) and does not require x402 signatures.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn execute_paid_api(
        &self,
        Parameters(params): Parameters<ExecutePaidApiParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;
        let body = seren::ApiRequestBody {
            publisher_id,
            asset_id: params.asset_id,
            method: params.method,
            path: params.path,
            headers: params.headers,
            body: params.body,
            estimated_rows: params.estimated_rows,
            request_id: params.request_id,
        };

        match api_client.execute_api(&body).await {
            Ok(response) => {
                let result = response.into_inner();
                Ok(CallToolResult::success(vec![json_content(&result)?]))
            }
            Err(e) => {
                // Handle specific error codes with user-friendly messages
                if let Some(status) = e.status() {
                    if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                        return Err(McpError::invalid_request(
                            "Insufficient prepaid balance. Fund your wallet in the Seren console and retry.".to_string(),
                            None,
                        ));
                    }
                    if status == reqwest::StatusCode::CONFLICT {
                        return Err(McpError::invalid_request(
                            "Duplicate request_id. Provide a new UUID and retry.".to_string(),
                            None,
                        ));
                    }
                }
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    // ========================================================================
    // Wallet Management Tools
    // ========================================================================

    #[tool(
        description = "Create a new managed EVM wallet. The server generates a keypair and stores the encrypted private key. Use export_wallet_key to retrieve the private key later.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_managed_wallet(
        &self,
        Parameters(params): Parameters<CreateManagedWalletParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let body = seren::CreateManagedWalletRequest {
            set_as_primary: Some(params.set_as_primary.unwrap_or(false)),
        };
        let result = api_client
            .create_managed_wallet(&body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List all wallets for the authenticated user. Returns wallet addresses, types (virtual, managed, onchain), and whether each is verified/primary.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_wallets(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let result = api_client
            .list_wallets()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Export the private key of a managed wallet. WARNING: Store this securely! Anyone with the private key can control the wallet. Only works for 'managed' wallet types.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn export_wallet_key(
        &self,
        Parameters(params): Parameters<WalletIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let result = api_client
            .export_wallet_key(&params.wallet_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Set a wallet as the primary wallet. The primary wallet is used by default for marketplace operations.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn set_wallet_primary(
        &self,
        Parameters(params): Parameters<WalletIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let result = api_client
            .set_wallet_primary(&params.wallet_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Delete a wallet (soft delete). Cannot delete the primary wallet - set another wallet as primary first.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_wallet(
        &self,
        Parameters(params): Parameters<WalletIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        api_client
            .delete_wallet(&params.wallet_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(
            "Wallet deleted successfully".to_string(),
        )]))
    }

    // ========================================================================
    // Local Wallet Tools (for users running seren-mcp locally)
    // ========================================================================

    #[tool(
        description = "Get the local wallet address. Only available when running seren-mcp locally with WALLET_PRIVATE_KEY environment variable set. Returns the EVM wallet address derived from the private key.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_local_wallet_address(&self) -> Result<CallToolResult, McpError> {
        let wallet = self.local_wallet.as_ref().ok_or_else(|| {
            McpError::invalid_request(
                "Local wallet not configured. Set WALLET_PRIVATE_KEY environment variable."
                    .to_string(),
                None,
            )
        })?;

        let address = format!("{:?}", wallet.address());
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Local wallet address: {}",
            address
        ))]))
    }

    #[tool(
        description = "Check if a local wallet is configured. Returns true if WALLET_PRIVATE_KEY is set and a valid wallet is loaded.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn has_local_wallet(&self) -> Result<CallToolResult, McpError> {
        let has_wallet = self.local_wallet.is_some();
        let response = serde_json::json!({
            "has_local_wallet": has_wallet,
            "message": if has_wallet {
                "Local wallet is configured and ready for x402 payments"
            } else {
                "No local wallet configured. Set WALLET_PRIVATE_KEY to enable local signing."
            }
        });
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get x402 on-chain deposit requirements for depositing USDC to a publisher. Returns EIP-712 typed data that an agent with an Ethereum wallet must sign to complete the deposit. This is for agents with real crypto wallets; for fiat deposits use create_prepaid_deposit instead.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_x402_deposit_requirements(
        &self,
        Parameters(params): Parameters<GetX402DepositRequirementsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;

        // Build request without auth - this endpoint returns 402 with payment requirements
        let http_client = reqwest::Client::new();
        let body = seren::OnchainDepositRequest {
            publisher_id,
            asset_id: params.asset_id,
            amount: params.amount,
        };

        let url = format!("{}/api/agent/deposit", self.api_base_url);
        let response = http_client
            .post(&url)
            .header("X-AGENT-WALLET", &params.agent_wallet)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // We expect 402 Payment Required with the EIP-712 data
        if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            let requirements: serde_json::Value = response
                .json()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![json_content(&requirements)?]));
        }

        // If we got 200, the deposit was already paid (unlikely without payment header)
        if response.status().is_success() {
            let result: serde_json::Value = response
                .json()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![json_content(&result)?]));
        }

        // Handle errors
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        Err(McpError::internal_error(
            format!(
                "Failed to get deposit requirements: {} - {}",
                status, error_body
            ),
            None,
        ))
    }

    // ========================================================================
    // Additional Agent Marketplace Tools
    // ========================================================================

    #[tool(
        description = "Get supported payment protocols and configuration. Returns x402 protocol details including supported payment kinds, networks, and facilitator information for payment protocol discovery.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_supported(
        &self,
        Parameters(_params): Parameters<GetSupportedParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let supported = api_client
            .get_supported()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&supported)?]))
    }

    #[tool(
        description = "Create a new publisher in the agent marketplace. Publishers provide databases or APIs that AI agents can query with micropayments. Requires API key authentication (organization-level).",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_publisher(
        &self,
        Parameters(params): Parameters<CreatePublisherParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        // Convert source_type string to enum
        let source_type = params.source_type.as_deref().map(|s| match s {
            "serendb" => seren::SourceType::Serendb,
            "api" => seren::SourceType::Api,
            _ => seren::SourceType::Serendb, // default
        });

        let body = seren::CreatePublisherRequest {
            name: params.name,
            slug: params.slug,
            wallet_address: seren::WalletAddress(params.wallet_address),
            wallet_network_id: params.wallet_network_id,
            source_type,
            description: params.description,
            api_url: params.api_url,
            project_id: params.project_id,
            branch_id: params.branch_id,
            database_name: params.database_name,
            base_price_per_1000_rows: params.base_price_per_1000_rows,
            billing_model: params.billing_model,
            categories: params.categories.unwrap_or_default(),
            logo_url: params.logo_url,
            // Set defaults for other fields
            accepted_asset_ids: None,
            allowed_passthrough_headers: vec![],
            api_headers: None,
            api_key_header: None,
            api_key_query_param: None,
            auth_type: None,
            cache_ttl_seconds: None,
            gateway_fee_percent: None,
            grace_period_minutes: None,
            hourly_rate: None,
            jwt_access_key: None,
            jwt_algorithm: None,
            jwt_expiration_seconds: None,
            jwt_secret_key: None,
            low_balance_threshold: None,
            markup_multiplier: None,
            minimum_balance: None,
            ownership_tracking_enabled: None,
            price_per_call: None,
            price_per_delete: None,
            price_per_get: None,
            price_per_patch: None,
            price_per_post: None,
            price_per_put: None,
            protected_operations: None,
            publisher_type: None,
            resource_description: None,
            resource_id_response_path: None,
            resource_id_url_pattern: None,
            resource_name: None,
            upstream_api_key: None,
            usage_example: None,
        };

        let result = api_client
            .create_publisher_api_key(&body)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Execute a paid streaming API request against a publisher's endpoint using the authenticated user's virtual wallet. Returns a streaming response for large payloads. This uses prepaid balance (fiat/Stripe) and does not require x402 signatures.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn execute_paid_api_stream(
        &self,
        Parameters(params): Parameters<ExecutePaidApiStreamParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let publisher_id = resolve_publisher_id(&api_client, &params.publisher).await?;

        let body = seren::ApiRequestBody {
            publisher_id,
            asset_id: params.asset_id,
            method: params.method,
            path: params.path,
            headers: params.headers,
            body: params.body,
            estimated_rows: params.estimated_rows,
            request_id: params.request_id,
        };

        match api_client.execute_api_stream(&body).await {
            Ok(response) => {
                // For streaming responses, we collect the full response into memory
                // In a real streaming scenario, you'd want to handle chunks incrementally
                use futures::StreamExt;
                let stream = response.into_inner();
                futures::pin_mut!(stream);

                let mut collected = Vec::new();
                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(bytes) => collected.extend_from_slice(&bytes),
                        Err(e) => {
                            return Err(McpError::internal_error(
                                format!("Stream error: {}", e),
                                None,
                            ));
                        }
                    }
                }

                let text = String::from_utf8_lossy(&collected);
                Ok(CallToolResult::success(vec![Content::text(
                    text.to_string(),
                )]))
            }
            Err(e) => {
                if let Some(status) = e.status() {
                    if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                        return Err(McpError::invalid_request(
                            "Insufficient prepaid balance. Fund your wallet in the Seren console and retry.".to_string(),
                            None,
                        ));
                    }
                    if status == reqwest::StatusCode::CONFLICT {
                        return Err(McpError::invalid_request(
                            "Duplicate request_id. Provide a new UUID and retry.".to_string(),
                            None,
                        ));
                    }
                }
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }
}

// ============================================================================
// Server Handler Implementation
// ============================================================================

#[tool_handler]
impl ServerHandler for SerenMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: rmcp::model::Implementation {
                name: "seren-mcp".into(),
                title: Some("Seren MCP Server".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                icons: None,
                website_url: Some("https://serendb.com".into()),
            },
            instructions: Some(
                "Seren MCP Server - Manage Seren database projects, branches, and execute SQL queries."
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;

    fn extensions_with_headers(headers: &[(&str, &str)]) -> Extensions {
        let mut builder = Request::builder().uri("http://localhost/");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let request = builder.body(Body::empty()).unwrap();
        let (parts, _body) = request.into_parts();
        let mut extensions = Extensions::default();
        extensions.insert(parts);
        extensions
    }

    #[test]
    fn connection_string_with_database_replaces_path_preserves_query() {
        let conn = "postgresql://user:pass@db.serendb.com:5432/postgres?sslmode=require";
        let out = connection_string_with_database(conn, "mydb").unwrap();
        assert!(out.contains("/mydb?"));
        assert!(out.contains("sslmode=require"));
        assert!(out.starts_with("postgresql://user:pass@db.serendb.com:5432/"));
        assert!(!out.contains("/postgres?"));
    }

    #[test]
    fn connection_string_with_database_validates_database_name() {
        let conn = "postgresql://user@db.serendb.com/postgres";
        assert!(connection_string_with_database(conn, "").is_err());
        assert!(connection_string_with_database(conn, " ").is_err());
        assert!(connection_string_with_database(conn, "a/b").is_err());
    }

    #[test]
    fn sql_proxy_url_from_connection_string_uses_host_only() {
        let conn = "postgresql://user:pass@proxy.serendb.com:5432/postgres";
        let out = sql_proxy_url_from_connection_string(conn).unwrap();
        assert_eq!(out, "https://proxy.serendb.com/sql");
    }

    #[test]
    fn sql_proxy_url_from_connection_string_requires_host() {
        let conn = "postgresql:///postgres";
        assert!(sql_proxy_url_from_connection_string(conn).is_err());
    }

    #[test]
    fn validate_identifier_enforces_postgres_rules() {
        assert!(validate_identifier("valid_name", "db").is_ok());
        assert!(validate_identifier("_valid_2", "db").is_ok());

        assert!(validate_identifier("", "db").is_err());
        assert!(validate_identifier("1invalid", "db").is_err());
        assert!(validate_identifier("has-dash", "db").is_err());
    }

    #[test]
    fn validate_resource_name_allows_relaxed_characters() {
        assert!(validate_resource_name("my branch-1", "branch").is_ok());
        assert!(validate_resource_name("My.Project 2", "project").is_ok());

        assert!(validate_resource_name("", "branch").is_err());
        assert!(validate_resource_name("_starts_with_underscore", "branch").is_err());
        assert!(validate_resource_name("bad/char", "branch").is_err());
    }

    #[test]
    fn validate_sql_query_enforces_size_and_non_empty() {
        assert!(validate_sql_query("select 1").is_ok());
        assert!(validate_sql_query("  ").is_err());

        let too_large = "a".repeat(1_000_001);
        assert!(validate_sql_query(&too_large).is_err());
    }

    #[test]
    fn extract_bearer_token_from_extensions_is_case_insensitive_and_trims() {
        let extensions = extensions_with_headers(&[("authorization", "bearer   token123  ")]);
        assert_eq!(
            extract_bearer_token_from_extensions(&extensions).as_deref(),
            Some("token123")
        );

        let extensions = extensions_with_headers(&[("authorization", "Basic abc")]);
        assert_eq!(extract_bearer_token_from_extensions(&extensions), None);
    }

    #[test]
    fn read_only_header_enables_read_only_mode() {
        temp_env::with_var_unset("READ_ONLY", || {
            let extensions = extensions_with_headers(&[("x-read-only", "true")]);
            assert!(is_read_only(&extensions));
            assert!(ensure_writes_allowed(&extensions).is_err());

            let extensions = extensions_with_headers(&[("x-read-only", "0")]);
            assert!(!is_read_only(&extensions));
            assert!(ensure_writes_allowed(&extensions).is_ok());
        });
    }

    #[test]
    fn read_only_env_enables_read_only_mode() {
        temp_env::with_var("READ_ONLY", Some("yes"), || {
            let extensions = extensions_with_headers(&[]);
            assert!(is_read_only(&extensions));
            assert!(ensure_writes_allowed(&extensions).is_err());
        });
    }

    #[tokio::test]
    async fn execute_sql_sends_required_headers_and_body_to_proxy() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_uri = proxy.uri();

        temp_env::async_with_vars([("SQL_PROXY_URL", Some(&proxy_uri))], async {
            let conn = "postgresql://user:pass@db.serendb.com/postgres?sslmode=require";

            Mock::given(method("POST"))
                .and(path("/sql"))
                .and(header("SerenDB-Connection-String", conn))
                .and(header("SerenDB-Pool-Opt-In", "true"))
                .and(body_json(serde_json::json!({
                    "query": "select $1",
                    "params": [1],
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                })))
                .mount(&proxy)
                .await;

            let server = SerenMcpServer::new("test-key", "https://api.serendb.com/api").unwrap();
            let result = server
                .execute_sql(conn, "select $1", vec![serde_json::json!(1)])
                .await
                .unwrap();
            assert_eq!(result, serde_json::json!({ "ok": true }));
        })
        .await;
    }

    #[tokio::test]
    async fn execute_sql_transaction_sets_batch_headers() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_uri = proxy.uri();

        temp_env::async_with_vars([("SQL_PROXY_URL", Some(&proxy_uri))], async {
            let conn = "postgresql://user:pass@db.serendb.com/postgres?sslmode=require";

            Mock::given(method("POST"))
                .and(path("/sql"))
                .and(header("SerenDB-Connection-String", conn))
                .and(header("SerenDB-Pool-Opt-In", "true"))
                .and(header("SerenDB-Batch-Read-Only", "true"))
                .and(header("SerenDB-Batch-Isolation-Level", "read_committed"))
                .and(header("SerenDB-Batch-Deferrable", "true"))
                .and(body_json(serde_json::json!({
                    "queries": [
                        {"query": "select 1", "params": []},
                        {"query": "select 2", "params": []},
                    ],
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true,
                })))
                .mount(&proxy)
                .await;

            let server = SerenMcpServer::new("test-key", "https://api.serendb.com/api").unwrap();
            let result = server
                .execute_sql_transaction(
                    conn,
                    vec!["select 1".to_string(), "select 2".to_string()],
                    Some(true),
                    Some("read_committed".to_string()),
                    Some(true),
                )
                .await
                .unwrap();
            assert_eq!(result, serde_json::json!({ "ok": true }));
        })
        .await;
    }
}
