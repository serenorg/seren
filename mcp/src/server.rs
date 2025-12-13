//! Seren MCP Server implementation using rmcp SDK
//!
//! This module provides the MCP server with all tools for managing
//! Seren database projects, branches, and SQL execution.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Seren MCP Server
#[derive(Clone)]
pub struct SerenMcpServer {
    api_client: Arc<seren::Client>,
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

// ============================================================================
// Tool Implementations
// ============================================================================

#[tool_router]
impl SerenMcpServer {
    /// Create a new Seren MCP Server
    pub fn new(api_key: &str, api_base_url: &str) -> Result<Self, seren::Error> {
        let config = seren::ClientConfig::new(api_key).with_base_url(api_base_url);
        let api_client = Arc::new(seren::Client::new(config)?);
        Ok(Self {
            api_client,
            http_client: reqwest::Client::new(),
            tool_router: Self::tool_router(),
        })
    }

    #[tool(description = "List all Seren projects accessible to the authenticated user")]
    async fn list_projects(&self) -> Result<CallToolResult, McpError> {
        let projects = self
            .api_client
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
    ) -> Result<CallToolResult, McpError> {
        let project = self
            .api_client
            .projects()
            .get(&params.project_id.to_string())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&project)?]))
    }

    #[tool(description = "Create a new Seren project")]
    async fn create_project(
        &self,
        Parameters(params): Parameters<CreateProjectParams>,
    ) -> Result<CallToolResult, McpError> {
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
        let response = self
            .api_client
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
    ) -> Result<CallToolResult, McpError> {
        self.api_client
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
    async fn create_branch(
        &self,
        Parameters(params): Parameters<CreateBranchParams>,
    ) -> Result<CallToolResult, McpError> {
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
        };
        let response = self
            .api_client
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
    ) -> Result<CallToolResult, McpError> {
        self.api_client
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
    ) -> Result<CallToolResult, McpError> {
        let databases = self
            .api_client
            .databases(params.project_id.to_string(), params.branch_id.to_string())
            .list()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&databases)?]))
    }

    #[tool(description = "Create a new database in a branch")]
    async fn create_database(
        &self,
        Parameters(params): Parameters<CreateDatabaseParams>,
    ) -> Result<CallToolResult, McpError> {
        let request = seren::CreateDatabaseRequest {
            name: params.name,
            owner_name: params.owner,
        };
        let database = self
            .api_client
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
    ) -> Result<CallToolResult, McpError> {
        let roles = self
            .api_client
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
    ) -> Result<CallToolResult, McpError> {
        let response = self
            .api_client
            .branches(params.project_id.to_string())
            .connection_string_with_options(
                &params.branch_id.to_string(),
                params.pooled,
                params.role.as_deref(),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(description = "Execute a SQL query against a database")]
    async fn run_sql(
        &self,
        Parameters(params): Parameters<RunSqlParams>,
    ) -> Result<CallToolResult, McpError> {
        // Get connection info from API
        let conn_response = self
            .api_client
            .branches(params.project_id.to_string())
            .connection_string_with_options(&params.branch_id.to_string(), None, None)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Parse the connection string to extract the host for the HTTP proxy
        let conn_str = &conn_response.data.connection_string;
        let host = conn_str
            .split('@')
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .unwrap_or("proxy.serendb.com");

        let http_url = format!("https://{}/sql", host);

        // Execute via HTTP proxy
        let response = self
            .http_client
            .post(&http_url)
            .header("SerenDB-Connection-String", conn_str)
            .header("SerenDB-Pool-Opt-In", "true")
            .json(&SqlRequest {
                query: params.query,
                params: vec![],
            })
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!("SQL execution failed: {}", error_text),
                None,
            ));
        }

        let result: SqlResponse = response.json().await.map_err(|e| {
            McpError::internal_error(format!("Failed to parse SQL response: {}", e), None)
        })?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(description = "Get schema information for a table")]
    async fn describe_table_schema(
        &self,
        Parameters(params): Parameters<DescribeTableSchemaParams>,
    ) -> Result<CallToolResult, McpError> {
        let schema = params.schema.as_deref().unwrap_or("public");
        let query = format!(
            r#"
            SELECT
                column_name,
                data_type,
                is_nullable,
                column_default,
                character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = '{}'
              AND table_name = '{}'
            ORDER BY ordinal_position
            "#,
            schema, params.table_name
        );

        self.run_sql(Parameters(RunSqlParams {
            project_id: params.project_id,
            branch_id: params.branch_id,
            database: params.database,
            query,
        }))
        .await
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
