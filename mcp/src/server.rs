//! Seren MCP Server implementation using rmcp SDK
//!
//! This module provides the MCP server with all tools for managing
//! Seren database projects, branches, and SQL execution.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, Extensions, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
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
// Tool Parameter Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DescribeProjectParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateProjectParams {
    /// Project name
    pub name: String,
    /// Region for the project (e.g., aws-us-east-1)
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteProjectParams {
    /// The project ID (UUID) to delete
    pub project_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateBranchParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// Branch name
    pub name: String,
    /// Parent branch ID (UUID, optional, defaults to main)
    #[serde(default)]
    pub parent_branch_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteBranchParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID) to delete
    pub branch_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListDatabasesParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateDatabaseParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Database name
    pub name: String,
    /// Owner role name
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListRolesParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetConnectionStringParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Database name
    #[serde(default)]
    pub database: Option<String>,
    /// Role name
    #[serde(default)]
    pub role: Option<String>,
    /// Use connection pooling
    #[serde(default)]
    pub pooled: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RunSqlParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Database name
    pub database: String,
    /// SQL query to execute
    pub query: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DescribeTableSchemaParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
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
struct SqlResponse {
    rows: Vec<serde_json::Value>,
    fields: Option<Vec<FieldInfo>>,
    row_count: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
struct FieldInfo {
    name: String,
    data_type: Option<String>,
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
    if database.trim().is_empty() {
        return Err(McpError::invalid_params("database must not be empty", None));
    }
    if database.contains('/') {
        return Err(McpError::invalid_params(
            "database must not contain '/'",
            None,
        ));
    }

    let mut url = reqwest::Url::parse(connection_string)
        .map_err(|e| McpError::internal_error(format!("Invalid connection string: {}", e), None))?;
    url.set_path(&format!("/{}", database));
    Ok(url.to_string())
}

fn sql_proxy_url_from_connection_string(connection_string: &str) -> Result<String, McpError> {
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
/// 1. Environment variable `SEREN_MCP_READ_ONLY=true` (global, applies to all requests)
/// 2. HTTP header `x-read-only: true` (per-request, must be sent on each call)
///
/// Note: The `x-read-only` header is evaluated per-request. Clients must include
/// it on every request where they want write operations blocked.
fn is_read_only(extensions: &Extensions) -> bool {
    let env_read_only = std::env::var("SEREN_MCP_READ_ONLY")
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
/// Must follow PostgreSQL naming rules: start with letter/underscore, alphanumeric + underscore only
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

        let config = seren::ClientConfig::new(token).with_base_url(&self.api_base_url);
        seren::Client::new(config).map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    #[instrument(skip(self, connection_string), fields(query_len = query.len()))]
    async fn execute_sql(
        &self,
        connection_string: &str,
        query: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<SqlResponse, McpError> {
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

        let result: SqlResponse = response.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse SQL response");
            McpError::internal_error(format!("Failed to parse SQL response: {}", e), None)
        })?;

        tracing::debug!(row_count = ?result.row_count, "SQL query completed");
        Ok(result)
    }
}

#[tool_router]
impl SerenMcpServer {
    /// Create a new Seren MCP Server
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
    pub fn new_oauth(api_base_url: &str) -> Result<Self, seren::Error> {
        Ok(Self {
            api_base_url: api_base_url.to_string(),
            auth: SerenAuth::FromRequestBearer,
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
        })
    }

    #[tool(description = "List all Seren projects accessible to the authenticated user")]
    async fn list_projects(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let projects = api_client
            .projects()
            .list()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&projects)?]))
    }

    #[tool(description = "Get detailed information about a specific project")]
    async fn describe_project(
        &self,
        Parameters(params): Parameters<DescribeProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let project = api_client
            .projects()
            .get(&params.project_id.to_string())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&project)?]))
    }

    #[tool(description = "Create a new Seren project")]
    #[instrument(skip(self, extensions), fields(name = %params.name))]
    async fn create_project(
        &self,
        Parameters(params): Parameters<CreateProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&params.name, "project name")?;

        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateProjectRequest {
            name: params.name,
            region: params.region.unwrap_or_else(|| "aws-us-east-1".to_string()),
            block_public_connections: None,
            block_vpc_connections: None,
            compute_unit_max: None,
            compute_unit_min: None,
            enable_logical_replication: None,
            hipaa: None,
            protected_branches_only: None,
        };
        let response = api_client
            .projects()
            .create(request)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(description = "Delete a Seren project")]
    async fn delete_project(
        &self,
        Parameters(params): Parameters<DeleteProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .projects()
            .delete(&params.project_id.to_string())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Project {} deleted successfully",
            params.project_id
        ))]))
    }

    #[tool(description = "Create a new branch in a project")]
    #[instrument(skip(self, extensions), fields(project_id = %params.project_id, name = %params.name))]
    async fn create_branch(
        &self,
        Parameters(params): Parameters<CreateBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&params.name, "branch name")?;

        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateBranchRequest {
            name: params.name,
            parent_branch_id: params.parent_branch_id,
            add_endpoint: Some(true),
            archived: None,
            endpoints: vec![],
            init_source: None,
            parent_lsn: None,
            parent_timestamp: None,
            protected: None,
            expires_at: None,
            schema_only: None,
        };
        let response = api_client
            .branches(params.project_id.to_string())
            .create(request)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(description = "Delete a branch")]
    async fn delete_branch(
        &self,
        Parameters(params): Parameters<DeleteBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .branches(params.project_id.to_string())
            .delete(&params.branch_id.to_string())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Branch {} deleted successfully",
            params.branch_id
        ))]))
    }

    #[tool(description = "List all databases in a branch")]
    async fn list_databases(
        &self,
        Parameters(params): Parameters<ListDatabasesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let databases = api_client
            .databases(params.project_id.to_string(), params.branch_id.to_string())
            .list()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&databases)?]))
    }

    #[tool(description = "Create a new database in a branch")]
    #[instrument(skip(self, extensions), fields(project_id = %params.project_id, branch_id = %params.branch_id, name = %params.name))]
    async fn create_database(
        &self,
        Parameters(params): Parameters<CreateDatabaseParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_identifier(&params.name, "database name")?;

        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateDatabaseRequest {
            name: params.name,
            owner_name: params.owner,
        };
        let database = api_client
            .databases(params.project_id.to_string(), params.branch_id.to_string())
            .create(request)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&database)?]))
    }

    #[tool(description = "List all roles in a branch")]
    async fn list_roles(
        &self,
        Parameters(params): Parameters<ListRolesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let roles = api_client
            .roles(params.project_id.to_string(), params.branch_id.to_string())
            .list()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&roles)?]))
    }

    #[tool(description = "Get connection string for a branch")]
    async fn get_connection_string(
        &self,
        Parameters(params): Parameters<GetConnectionStringParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let mut response = api_client
            .branches(params.project_id.to_string())
            .connection_string_with_options(
                &params.branch_id.to_string(),
                params.pooled,
                params.role.as_deref(),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if let Some(database) = params.database.as_deref() {
            response.data.connection_string =
                connection_string_with_database(&response.data.connection_string, database)?;
        }

        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(description = "Execute a SQL query against a database")]
    #[instrument(skip(self, extensions, params), fields(project_id = %params.project_id, branch_id = %params.branch_id, database = %params.database))]
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
            .branches(params.project_id.to_string())
            .connection_string_with_options(&params.branch_id.to_string(), None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let conn_str = connection_string_with_database(
            &conn_response.data.connection_string,
            &params.database,
        )?;

        let result = self.execute_sql(&conn_str, &params.query, vec![]).await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(description = "Get schema information for a table")]
    #[instrument(skip(self, extensions), fields(project_id = %params.project_id, branch_id = %params.branch_id, database = %params.database, table = %params.table_name))]
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
            .branches(params.project_id.to_string())
            .connection_string_with_options(&params.branch_id.to_string(), None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

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
