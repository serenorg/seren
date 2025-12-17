//! Seren MCP Server implementation using rmcp SDK
//!
//! This module provides the MCP server with all tools for managing
//! Seren database projects, branches, and SQL execution.

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
    fn api_client(&self, extensions: &Extensions) -> Result<seren::Client, McpError> {
        let token = match &self.auth {
            SerenAuth::StaticToken(token) => token.clone(),
            SerenAuth::FromRequestBearer => extract_bearer_token_from_extensions(extensions)
                .ok_or_else(|| McpError::invalid_request("Missing Bearer token", None))?,
        };

        // Build HTTP client with auth header
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| McpError::internal_error(format!("Invalid token: {}", e), None))?;
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| {
                McpError::internal_error(format!("Failed to build HTTP client: {}", e), None)
            })?;

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
    /// Create a new Seren MCP Server
    #[allow(clippy::result_large_err)]
    pub fn new(api_key: &str, api_base_url: &str) -> Result<Self, seren::Error> {
        Ok(Self {
            api_base_url: api_base_url.to_string(),
            auth: SerenAuth::StaticToken(api_key.to_string()),
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
        })
    }

    /// Create a new Seren MCP Server in OAuth mode.
    ///
    /// In this mode the Seren API token is taken from each incoming HTTP request's
    /// `Authorization: Bearer ...` header (injected into [`Extensions`] by rmcp).
    #[allow(clippy::result_large_err)]
    pub fn new_oauth(api_base_url: &str) -> Result<Self, seren::Error> {
        Ok(Self {
            api_base_url: api_base_url.to_string(),
            auth: SerenAuth::FromRequestBearer,
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
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
