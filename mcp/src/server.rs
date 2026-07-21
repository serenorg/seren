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

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::U256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::TryStreamExt;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, Content, Extensions, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerInfo,
    },
    service::{RequestContext, RoleServer},
    tool, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tracing::instrument;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::money::{format_usd_micros, parse_usd_to_cents, usd_f64_to_cents};
use crate::wallet::{
    PaymentRequirements, PrivateKeyWallet, SignerConfig, build_x402_payment_payload,
};

#[derive(Clone)]
enum SerenAuth {
    StaticToken(String),
    FromRequestBearer,
}

/// Seren MCP Server
#[derive(Clone)]
pub struct SerenMcpServer {
    pub(crate) api_base_url: String,
    passwords_api_base_url: String,
    auth: SerenAuth,
    pub(crate) http_client: reqwest::Client,
    tool_router: ToolRouter<Self>,
    /// Optional local wallet for x402 payments when running locally.
    /// Loaded from WALLET_PRIVATE_KEY environment variable.
    /// Only enabled in stdio mode, not in hosted (OAuth/HTTP) modes.
    wallet: Option<Arc<PrivateKeyWallet>>,
    /// Signer configuration (auto-approve threshold, etc.)
    signer_config: SignerConfig,
    /// true for local run modes (stdio, start:http); false for hosted start:server.
    pub(crate) passwords_local_mode: bool,
    /// User-mode (master-password) unlocked session; None until passwords_unlock (added later).
    passwords_session: Arc<tokio::sync::Mutex<Option<crate::passwords::PasswordsSession>>>,
    passwords_master_password_file: Option<PathBuf>,
    /// Provisioned agent identity (agent-key mode), loaded once at startup.
    passwords_agent: Option<Arc<crate::passwords::PasswordsAgentIdentity>>,
    /// Hosted token-vault storage for remote MCP passwords agent credentials.
    pub(crate) passwords_hosted_store: Option<Arc<crate::oauth::store::TokenStore>>,
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

/// Seren Storage publisher bucket selector.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageBucketPath {
    /// Seren Storage bucket slug
    pub bucket_slug: String,
}

/// Seren Storage publisher object selector.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageObjectPath {
    /// Seren Storage bucket slug
    pub bucket_slug: String,
    /// Object ID
    pub object_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageAgentGrantParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Agent identity ID
    pub agent_identity_id: Uuid,
    /// Access level to grant: "reader" or "writer"
    pub permission: seren::SerenStorageObjectStorageAgentPermission,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageAgentGrantSelectorParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Agent identity ID
    pub agent_identity_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageSnapshotListParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Deployment ID to list snapshots for
    pub deployment_id: Uuid,
    /// Maximum number of snapshots to return
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageSnapshotLatestParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Deployment ID to fetch the latest snapshot for
    pub deployment_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageSnapshotCreateParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    #[serde(flatten)]
    pub body: seren::SerenStorageCreateObjectStorageWorkspaceSnapshotRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageListObjectsParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Optional key prefix filter
    pub prefix: Option<String>,
    /// Maximum number of objects to return
    pub limit: Option<i64>,
    /// Pagination cursor from a previous response's next_cursor
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageCreateUploadParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    #[serde(flatten)]
    pub body: seren::SerenStorageCreateObjectStorageUploadRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStoragePutObjectBase64Params {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Object key to store
    pub object_key: String,
    /// Object bytes, base64-encoded
    pub content_base64: String,
    /// Optional content type. Defaults to application/octet-stream.
    pub content_type: Option<String>,
    /// Optional metadata JSON object
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageConfirmUploadParams {
    #[serde(flatten)]
    pub path: SerenStorageObjectPath,
    #[serde(flatten)]
    pub body: seren::SerenStorageConfirmObjectStorageUploadRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenStorageDownloadByKeyParams {
    #[serde(flatten)]
    pub path: SerenStorageBucketPath,
    /// Exact object key to download
    pub object_key: String,
}

/// Seren Memory private-memory selector.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SerenMemoryIdPath {
    /// Memory ID
    pub memory_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SerenMemoryListParams {
    pub is_consolidated: Option<bool>,
    pub is_pinned: Option<bool>,
    /// active, draft, canonical, or deprecated
    pub lifecycle_status: Option<seren::SerenMemoryMemoryLifecycle>,
    pub limit: Option<i64>,
    pub memory_type: Option<String>,
    pub offset: Option<i64>,
    pub org_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
}

// Organization OAuth provider operations
/// Path parameters for org OAuth provider operations
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct OrgOAuthProviderPath {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The OAuth provider ID (UUID)
    pub provider_id: Uuid,
}

pub type ListOrgOAuthProvidersParams = OrganizationPath;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOrgOAuthProviderParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The OAuth provider ID (UUID)
    pub provider_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateOrgOAuthProviderParams {
    #[serde(flatten)]
    pub path: OrganizationPath,
    #[serde(flatten)]
    pub body: seren::CreateOAuthProviderRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateOrgOAuthProviderParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The OAuth provider ID (UUID)
    pub provider_id: Uuid,
    #[serde(flatten)]
    pub body: seren::UpdateOAuthProviderRequest,
}

pub type DeleteOrgOAuthProviderParams = OrgOAuthProviderPath;

// Organization custom skill operations
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct OrgCustomSkillPath {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The custom skill ID (UUID)
    pub skill_id: Uuid,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct OrgCustomSkillRevisionPath {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The custom skill ID (UUID)
    pub skill_id: Uuid,
    /// The revision ID (UUID)
    pub revision_id: Uuid,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListOrgCustomSkillsParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// Include archived skills in the result set
    #[serde(default)]
    pub include_archived: Option<bool>,
    /// Optional search query matched against skill metadata
    #[serde(default)]
    pub q: Option<String>,
}

#[allow(dead_code)]
pub type GetOrgCustomSkillParams = OrgCustomSkillPath;
#[allow(dead_code)]
pub type ListOrgCustomSkillRevisionsParams = OrgCustomSkillPath;
#[allow(dead_code)]
pub type GetOrgCustomSkillRevisionParams = OrgCustomSkillRevisionPath;
#[allow(dead_code)]
pub type PublishOrgCustomSkillRevisionParams = OrgCustomSkillRevisionPath;
#[allow(dead_code)]
pub type DownloadOrgCustomSkillRevisionBundleParams = OrgCustomSkillRevisionPath;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateOrgCustomSkillParams {
    #[serde(flatten)]
    pub path: OrganizationPath,
    #[serde(flatten)]
    pub body: seren::CreateOrganizationCustomSkillRequest,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateOrgCustomSkillParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The custom skill ID (UUID)
    pub skill_id: Uuid,
    #[serde(flatten)]
    pub body: seren::UpdateOrganizationCustomSkillRequest,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateOrgCustomSkillRevisionParams {
    #[serde(flatten)]
    pub path: OrgCustomSkillPath,
    #[serde(flatten)]
    pub body: seren::CreateOrganizationCustomSkillRevisionRequest,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOrgCustomSkillRevisionFileParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// The custom skill ID (UUID)
    pub skill_id: Uuid,
    /// The revision ID (UUID)
    pub revision_id: Uuid,
    /// Relative path to the file within the skill bundle
    pub file_path: String,
}

// Connection and SQL operations (branch path + additional params)
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetConnectionStringParams {
    #[serde(flatten)]
    pub path: BranchPath,
    /// Whether to use pooled connection
    #[serde(default)]
    pub pooled: Option<bool>,
    /// Role name for the connection
    #[serde(default)]
    pub role: Option<String>,
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
    /// Optional timeout in milliseconds for the query (default: 120000ms = 2 minutes)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
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
    /// Optional timeout in milliseconds for the transaction (default: 120000ms = 2 minutes)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
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
// Agent Store Parameter Types (agent paid access)
// ============================================================================

/// Parameters for listing publishers in the agent store
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListAgentPublishersParams {
    /// Filter by category (database, integration, compute)
    #[serde(default)]
    pub category: Option<String>,
    /// Filter to only verified publishers
    #[serde(default)]
    pub is_verified: Option<bool>,
    /// Maximum number of publishers to return (default: 20, max: 50)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(default)]
    pub offset: Option<i64>,
    /// Search query to filter publishers by name or description
    #[serde(default)]
    pub search: Option<String>,
    /// Return full publisher objects (may be large). Default is compact summaries.
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Serialize)]
struct PublisherPricingSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_symbol: Option<String>,
    pricing_model: seren::PricingModel,
    base_price_per_1000_rows: String,
    markup_multiplier: String,
    min_charge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hourly_rate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price_per_call: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price_per_execution: Option<String>,
}

#[derive(Debug, Serialize)]
struct PublisherListEntry {
    slug: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    categories: Vec<String>,
    is_verified: bool,
    billing_model: String,
    publisher_category: seren::PublisherCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pricing: Option<PublisherPricingSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_example: Option<seren::UsageExample>,
}

/// List response with pagination info (standard REST API fields)
#[derive(Debug, Serialize)]
struct PublishersListResponse<T> {
    publishers: Vec<T>,
    /// Total number of publishers across all pages (from API pagination)
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    /// Number of publishers in this response
    count: usize,
    limit: i64,
    offset: i64,
    has_more: bool,
}

// ============================================================================
// Enhanced Database Response Types (Issue #69)
// ============================================================================

/// Response for list_databases with context
#[derive(Debug, Serialize)]
struct DatabaseListResponse {
    /// Project name for context
    project_name: String,
    /// Branch name for context
    branch_name: String,
    /// Whether this is the default branch
    is_default_branch: bool,
    /// List of databases
    databases: Vec<DatabaseInfo>,
}

/// Simplified database info for list response
#[derive(Debug, Serialize)]
struct DatabaseInfo {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_name: Option<String>,
    created_at: String,
}

/// Entry for list_all_databases response
#[derive(Debug, Serialize)]
struct AllDatabasesEntry {
    /// Project name
    project: String,
    /// Project ID
    project_id: Uuid,
    /// Branch name
    branch: String,
    /// Branch ID
    branch_id: Uuid,
    /// Whether this is the default branch
    is_default: bool,
    /// Database name
    database: String,
    /// Database ID
    database_id: Uuid,
}

/// Response for list_all_databases
#[derive(Debug, Serialize)]
struct AllDatabasesResponse {
    /// Total count of databases
    total: usize,
    /// All databases with context
    databases: Vec<AllDatabasesEntry>,
}

/// Parameters for getting a specific publisher by slug
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentPublisherParams {
    /// Publisher slug (URL-friendly identifier)
    pub slug: String,
}

/// Parameters for suggesting publishers/agents for a task
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SuggestForTaskParams {
    /// The task or query to find suitable publishers/agents for.
    /// Examples: "scrape website", "research topic", "search the web"
    pub query: String,
    /// Type of suggestions: "publisher", "agent", or "both" (default: "both")
    #[serde(default = "default_suggest_type")]
    pub r#type: Option<String>,
    /// Maximum number of suggestions (default: 5, max: 10)
    #[serde(default)]
    pub limit: Option<i64>,
}

fn default_suggest_type() -> Option<String> {
    Some("both".to_string())
}

/// Parameters for estimating query cost
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EstimateQueryCostParams {
    /// Publisher slug or UUID
    pub publisher: String,
    /// Query payload to estimate cost for (SQL string for SQL publishers, JSON string for MongoDB publishers)
    pub query: String,
    /// Optional asset ID for cost estimate (defaults to publisher's default asset)
    #[serde(default)]
    pub asset_id: Option<Uuid>,
}

/// Parameters for getting prepaid balance summary for the authenticated user
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetUserPrepaidBalanceParams {}

/// Parameters for creating a prepaid deposit for the authenticated user
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreatePrepaidDepositParams {
    /// Amount in USD (e.g., "25.00"). Minimum $5.00.
    ///
    /// Prefer passing a string to avoid floating-point rounding.
    pub amount_usd: UsdAmount,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct WalletTransferRequestParams {
    /// Recipient email address.
    pub recipient_email: String,
    /// Amount in USD (e.g., "25.00"). Prefer passing a string to avoid floating-point rounding.
    pub amount_usd: UsdAmount,
    /// Optional memo shown to the recipient.
    #[serde(default)]
    pub memo: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExecuteWalletTransferParams {
    /// Recipient email address.
    pub recipient_email: String,
    /// Amount in USD (e.g., "25.00"). Prefer passing a string to avoid floating-point rounding.
    pub amount_usd: UsdAmount,
    /// Optional memo shown to the recipient.
    #[serde(default)]
    pub memo: Option<String>,
    /// Idempotency key for safe retries. Reuse the same key when retrying.
    pub idempotency_key: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListWalletTransfersParams {
    /// Direction filter: sent, received, or all.
    #[serde(default)]
    pub direction: Option<String>,
    /// Status filter, such as settled, pending, claimed, recalled, or expired.
    #[serde(default)]
    pub status: Option<String>,
    /// Cursor from a previous response.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Maximum number of transfers to return.
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ClaimWalletTransferParams {
    /// Raw invite token from the claim link.
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RecallWalletTransferParams {
    /// Pending transfer ID.
    pub pending_transfer_id: Uuid,
}

// NOTE: UserRoutingPublisherParams, EnableUserRoutingParams, DisableUserRoutingParams
// were removed along with their corresponding routing tools (removed from the API spec).

/// A USD amount passed by a client/tool call.
///
/// We accept either a string (preferred) or a number (best-effort) for backwards compatibility.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum UsdAmount {
    String(String),
    Number(f64),
}

fn wallet_transfer_request(
    recipient_email: String,
    amount_usd: &UsdAmount,
    memo: Option<String>,
) -> Result<seren::WalletTransferRequest, McpError> {
    let amount_cents = match amount_usd {
        UsdAmount::String(value) => parse_usd_to_cents(value)
            .map_err(|e| McpError::invalid_request(format!("Invalid amount_usd: {e}"), None))?,
        UsdAmount::Number(_) => {
            return Err(McpError::invalid_request(
                "amount_usd must be a string for wallet transfers to avoid rounding.".to_string(),
                None,
            ));
        }
    };
    if amount_cents <= 0 {
        return Err(McpError::invalid_request(
            "Amount must be positive.".to_string(),
            None,
        ));
    }

    Ok(seren::WalletTransferRequest {
        recipient_email,
        amount_cents,
        memo,
    })
}

/// Operation type for unified call_publisher routing
#[derive(Debug, Clone, Copy)]
enum PublisherOperation {
    Database,
    Api,
    McpTool,
    McpResource,
}

/// Parameters for the unified call_publisher tool
///
/// This tool handles all publisher interactions based on publisher type:
/// - Database publishers: provide `query` (and optionally `database`)
/// - API publishers: provide `method`, `path`, `headers`, `body`, or `body_base64`
/// - MCP publishers: provide `tool` + `tool_args` OR `resource_uri`
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CallPublisherParams {
    /// Publisher slug or UUID
    pub publisher: String,

    // === Database publisher parameters ===
    /// Query payload to execute (SQL string for SQL publishers, JSON string for MongoDB publishers)
    #[serde(default)]
    pub query: Option<String>,
    /// Database name (optional, defaults to publisher's default database)
    #[serde(default)]
    pub database: Option<String>,

    // === API publisher parameters ===
    /// HTTP method (GET, POST, PUT, DELETE, PATCH). Default: POST
    #[serde(default)]
    pub method: Option<String>,
    /// Relative path to append to the publisher base URL
    #[serde(default)]
    pub path: Option<String>,
    /// Request headers (will not override publisher headers)
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    /// JSON body to send (for API or database publishers)
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Raw request body, base64-encoded. Mutually exclusive with body.
    #[serde(default)]
    pub body_base64: Option<String>,

    // === MCP publisher parameters ===
    /// MCP tool name to call
    #[serde(default)]
    pub tool: Option<String>,
    /// Arguments for MCP tool call (JSON object)
    #[serde(default)]
    pub tool_args: Option<serde_json::Map<String, serde_json::Value>>,
    /// MCP resource URI to read
    #[serde(default)]
    pub resource_uri: Option<String>,

    // === Common parameters ===
    /// Response format: "json" (default) or "text"
    #[serde(default)]
    pub response_format: Option<String>,
    /// Optional idempotency key (UUID)
    #[serde(default)]
    pub request_id: Option<Uuid>,
    /// Set to true to confirm a payment that exceeded the auto-approve limit
    #[serde(default)]
    pub confirm: bool,
    /// Pre-signed x402 payment payload (base64-encoded JSON).
    /// Used for payment proxy mode where the client signs payments locally.
    #[serde(default, rename = "_x402_payment")]
    pub x402_payment: Option<String>,
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

/// Endpoint definition for publisher API documentation and access control
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct EndpointDefinitionParam {
    /// HTTP method (GET, POST, PUT, DELETE, PATCH)
    pub method: String,
    /// URL path pattern (e.g., "/users/{id}" or "/api/*")
    pub path: String,
    /// Human-readable description of what this endpoint does
    #[serde(default)]
    pub description: Option<String>,
    /// Query parameters accepted by this endpoint
    #[serde(default)]
    pub query_params: Option<Vec<QueryParamDefinitionParam>>,
    /// Endpoint-specific upstream Content-Type.
    #[serde(default)]
    pub request_content_type: Option<String>,
    /// Gateway access policy for this endpoint.
    ///
    /// Defaults to `authenticated` when omitted. Use `public_anonymous` only
    /// for unprotected GET endpoints.
    #[serde(default)]
    pub access: Option<EndpointAccessParam>,
    /// If true, this endpoint is blocked (documented but not accessible)
    #[serde(default)]
    pub is_protected: bool,
    /// Reason why this endpoint is protected (shown in error messages)
    #[serde(default)]
    pub protection_reason: Option<String>,
    /// Endpoint-specific price override (in asset decimals, e.g., "0.49" for $0.49)
    /// If set, takes precedence over method-level pricing (price_per_post, etc.)
    #[serde(default)]
    pub price: Option<String>,
}

/// Endpoint gateway access policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EndpointAccessParam {
    Authenticated,
    PublicAnonymous,
}

/// Query parameter definition for endpoint documentation
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct QueryParamDefinitionParam {
    /// Parameter name
    pub name: String,
    /// Parameter description
    #[serde(default)]
    pub description: Option<String>,
    /// Whether this parameter is required
    #[serde(default)]
    pub required: bool,
    /// Parameter type
    #[serde(default)]
    pub param_type: ParamTypeParam,
    /// Example value for documentation
    #[serde(default)]
    pub example: Option<String>,
}

/// Parameter type for query/path parameters
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ParamTypeParam {
    #[default]
    String,
    Integer,
    Boolean,
    Number,
    Array,
}

/// Convert MCP endpoint definition param to SDK endpoint definition
fn endpoint_param_to_definition(
    param: EndpointDefinitionParam,
) -> Result<seren::EndpointDefinition, McpError> {
    let method = param.method.trim();
    if method.is_empty() {
        return Err(McpError::invalid_params(
            "endpoints[].method must not be empty",
            None,
        ));
    }

    let method = match method.to_ascii_uppercase().as_str() {
        "GET" => seren::HttpMethod::Get,
        "POST" => seren::HttpMethod::Post,
        "PUT" => seren::HttpMethod::Put,
        "DELETE" => seren::HttpMethod::Delete,
        "PATCH" => seren::HttpMethod::Patch,
        other => {
            return Err(McpError::invalid_params(
                format!(
                    "Invalid endpoints[].method '{}'. Expected one of: GET, POST, PUT, DELETE, PATCH",
                    other
                ),
                None,
            ));
        }
    };

    let path = param.path.trim();
    if path.is_empty() {
        return Err(McpError::invalid_params(
            "endpoints[].path must not be empty",
            None,
        ));
    }

    let query_params = param.query_params.map(|qps| {
        qps.into_iter()
            .map(|qp| seren::QueryParamDefinition {
                name: qp.name,
                description: qp.description,
                required: Some(qp.required),
                param_type: Some(match qp.param_type {
                    ParamTypeParam::String => seren::ParamType::String,
                    ParamTypeParam::Integer => seren::ParamType::Integer,
                    ParamTypeParam::Boolean => seren::ParamType::Boolean,
                    ParamTypeParam::Number => seren::ParamType::Number,
                    ParamTypeParam::Array => seren::ParamType::Array,
                }),
                example: qp.example,
            })
            .collect::<Vec<_>>()
    });

    if param.access == Some(EndpointAccessParam::PublicAnonymous)
        && method != seren::HttpMethod::Get
    {
        return Err(McpError::invalid_params(
            "endpoints[].access='public_anonymous' is only valid for GET endpoints",
            None,
        ));
    }
    if param.access == Some(EndpointAccessParam::PublicAnonymous) && param.is_protected {
        return Err(McpError::invalid_params(
            "endpoints[].access='public_anonymous' cannot be combined with is_protected=true",
            None,
        ));
    }

    let access = match param.access.unwrap_or(EndpointAccessParam::Authenticated) {
        EndpointAccessParam::Authenticated => "authenticated",
        EndpointAccessParam::PublicAnonymous => "public_anonymous",
    };

    let endpoint = serde_json::json!({
        "access": access,
        "method": method,
        "path": path,
        "description": param.description,
        "query_params": query_params,
        "is_protected": param.is_protected,
        "protection_reason": param.protection_reason,
        "price": param.price,
        "example_request": null,
        "example_response": null,
        "request_body": null,
        "request_content_type": param.request_content_type,
        "required_headers": null,
        "response": null,
        "body_template": null,
        "is_default": null,
    });

    serde_json::from_value(endpoint).map_err(|e| {
        McpError::invalid_params(
            format!("Invalid endpoint definition after normalization: {}", e),
            None,
        )
    })
}

/// Parameters for creating a publisher in the store
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreatePublisherParams {
    /// Organization ID that owns this publisher
    pub organization_id: uuid::Uuid,
    /// Publisher display name
    pub name: String,
    /// URL-friendly slug (unique identifier)
    pub slug: String,
    /// Contact email for notifications and support
    #[serde(default)]
    pub email: Option<String>,
    /// Wallet address for receiving payments (0x...)
    pub wallet_address: String,
    /// Network ID for wallet (CAIP-2 format, e.g., "eip155:8453" for Base)
    pub wallet_network_id: String,
    /// Publisher category: database, integration, or compute
    pub publisher_category: String,
    /// Database type: serendb, neon, supabase, or mongodb (for database category)
    #[serde(default)]
    pub database_type: Option<String>,
    /// Integration type: api or mcp (for integration category)
    #[serde(default)]
    pub integration_type: Option<String>,
    /// Publisher description
    #[serde(default)]
    pub description: Option<String>,
    /// Human-readable use case descriptions (e.g., ["Scrape dynamic JavaScript websites"])
    #[serde(default)]
    pub use_cases: Option<Vec<String>>,
    /// External API URL (required for integration_type: api)
    #[serde(default)]
    pub api_url: Option<String>,
    /// MCP server endpoint URL (required for integration_type: mcp)
    #[serde(default)]
    pub mcp_endpoint: Option<String>,
    /// SerenDB project ID (required for database_type: serendb)
    #[serde(default)]
    pub project_id: Option<Uuid>,
    /// SerenDB branch ID (required for database_type: serendb)
    #[serde(default)]
    pub branch_id: Option<Uuid>,
    /// Database name within the SerenDB project (default: serendb)
    #[serde(default)]
    pub database_name: Option<String>,
    /// Database connection string shorthand (for database_type: neon or supabase).
    /// This is converted to database_config = {"connection_string": "..."}.
    #[serde(default)]
    pub connection_string: Option<String>,
    /// Generic provider-specific configuration object passed through as database_config.
    /// Neon/Supabase: {"connection_string":"postgresql://..."}
    /// MongoDB Atlas: {"default_data_source":"MyCluster","max_limit":200,"read_only":true}
    #[serde(default)]
    pub database_config: Option<serde_json::Value>,
    /// Base price per 1000 rows (decimal string, e.g., "0.001")
    #[serde(default)]
    pub base_price_per_1000_rows: Option<String>,
    /// Price per API call (decimal string, e.g., "0.01")
    /// Used for per-request billing on API publishers
    #[serde(default)]
    pub price_per_call: Option<String>,
    /// Price per execution for agent templates (decimal string, e.g., "0.01")
    #[serde(default)]
    pub price_per_execution: Option<String>,
    /// Price per GET request (decimal string)
    #[serde(default)]
    pub price_per_get: Option<String>,
    /// Price per POST request (decimal string)
    #[serde(default)]
    pub price_per_post: Option<String>,
    /// Price per PUT request (decimal string)
    #[serde(default)]
    pub price_per_put: Option<String>,
    /// Price per PATCH request (decimal string)
    #[serde(default)]
    pub price_per_patch: Option<String>,
    /// Price per DELETE request (decimal string)
    #[serde(default)]
    pub price_per_delete: Option<String>,
    /// Billing model (x402_per_request, prepaid_credits, x402_passthrough, pay_per_use)
    /// pay_per_use requires: publisher_category="integration", integration_type="api",
    /// auth_type != "passthrough", and upstream_cost_response_path must be set
    #[serde(default)]
    pub billing_model: Option<String>,
    /// Dot-separated path to upstream cost in response body (required for pay_per_use billing).
    /// Example: "usage.cost" extracts the cost from {"usage": {"cost": 0.0023}}
    #[serde(default)]
    pub upstream_cost_response_path: Option<String>,
    /// Publisher categories (e.g., ["blockchain", "defi"])
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    /// Logo URL for store listing
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Content-Type for upstream API requests (default: application/json)
    /// Use "application/x-www-form-urlencoded" for APIs like Twilio
    #[serde(default)]
    pub request_content_type: Option<String>,
    /// Non-sensitive headers to send to upstream API (e.g., {"User-Agent": "MyAgent/1.0"})
    /// Unlike api_key_headers, these values are NOT encrypted
    #[serde(default)]
    pub upstream_headers: Option<HashMap<String, String>>,
    /// Whitelist of agent-provided headers allowed to pass through to upstream.
    ///
    /// Common use cases:
    /// - Upstream auth_type="passthrough" (forward HMAC-signed headers)
    /// - Allow forwarding request-scoped correlation IDs
    #[serde(default)]
    pub allowed_passthrough_headers: Option<Vec<String>>,
    /// Map of client header names to upstream header names for passthrough auth.
    /// Use this to map a non-reserved client header to Authorization upstream.
    #[serde(default)]
    pub passthrough_header_rewrite: Option<HashMap<String, String>>,
    /// Structured endpoint definitions for LLM discoverability and access control
    /// Each endpoint can specify method, path, description, and protection status
    #[serde(default)]
    pub endpoints: Option<Vec<EndpointDefinitionParam>>,
    /// Policy for handling requests to paths not in the endpoints catalog
    /// "allow" (default) passes through undocumented paths, "block" returns 403
    #[serde(default)]
    pub undocumented_endpoint_policy: Option<String>,
    /// URL to call for exchanging Seren API keys for publisher auth tokens.
    /// When set, the gateway will call this URL to exchange agent credentials
    /// for tokens the publisher's API understands.
    #[serde(default)]
    pub token_exchange_url: Option<String>,
    /// HTTP method for token exchange endpoint (POST or GET, default: POST)
    #[serde(default)]
    pub token_exchange_method: Option<String>,
    /// How to send Seren token to exchange endpoint: header, body, or query (default: header)
    #[serde(default)]
    pub token_exchange_mode: Option<String>,
    /// TTL for cached exchanged tokens in seconds (60-86400, default: 3600)
    #[serde(default)]
    pub token_cache_ttl_seconds: Option<i32>,
    /// JSON field in exchange response containing the token (default: access_token)
    #[serde(default)]
    pub token_response_field: Option<String>,
    /// Upstream static API key (will be encrypted). Used for static API key authentication.
    #[serde(default)]
    pub upstream_api_key: Option<String>,
    /// Header name to inject upstream_api_key into (e.g., "Authorization", "X-API-Key", "X-cb-user-key")
    #[serde(default)]
    pub api_key_header: Option<String>,
    /// Query parameter name to inject upstream_api_key into (e.g., "api_key")
    #[serde(default)]
    pub api_key_query_param: Option<String>,
    /// Upstream auth mode: "static", "jwt", "oauth2_cc", or "passthrough" (default: static)
    ///
    /// For OAuth2 Client Credentials flow, set auth_type="oauth2_cc" and provide oauth2_* fields.
    #[serde(default)]
    pub auth_type: Option<String>,
    /// OAuth2 token endpoint URL for Client Credentials flow
    #[serde(default)]
    pub oauth2_token_url: Option<String>,
    /// OAuth2 client ID for Client Credentials flow
    #[serde(default)]
    pub oauth2_client_id: Option<String>,
    /// OAuth2 client secret for Client Credentials flow (will be encrypted)
    #[serde(default)]
    pub oauth2_client_secret: Option<String>,
    /// OAuth2 scopes to request during Client Credentials flow (optional)
    #[serde(default)]
    pub oauth2_scopes: Option<Vec<String>>,
    /// Display name for the publisher resource (shown on website)
    #[serde(default)]
    pub resource_name: Option<String>,
    /// Description of the publisher resource (shown on website)
    #[serde(default)]
    pub resource_description: Option<String>,
    /// OAuth provider slug for BYOC (Bring Your Own Credentials) authentication
    #[serde(default)]
    pub oauth_provider_slug: Option<String>,
    /// If true, users must connect via OAuth before using this publisher
    #[serde(default)]
    pub requires_user_oauth: Option<bool>,
}

/// Parameters for updating a publisher in the store
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdatePublisherParams {
    /// Organization ID that owns this publisher
    pub organization_id: uuid::Uuid,
    /// Publisher ID (UUID) to update
    pub publisher_id: uuid::Uuid,
    /// New publisher display name
    #[serde(default)]
    pub name: Option<String>,
    /// New publisher description
    #[serde(default)]
    pub description: Option<String>,
    /// New logo URL for store listing
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Publisher categories (e.g., ["blockchain", "defi"])
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    /// Publisher-declared capabilities for task matching (e.g., ["web_scraping", "ai_search"])
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    /// Human-readable use case descriptions (e.g., ["Scrape dynamic JavaScript websites"])
    #[serde(default)]
    pub use_cases: Option<Vec<String>>,
    /// New wallet address for receiving payments (0x...)
    /// Must be provided together with wallet_network_id
    #[serde(default)]
    pub wallet_address: Option<String>,
    /// Network ID for wallet (CAIP-2 format, e.g., "eip155:8453" for Base)
    /// Must be provided together with wallet_address
    #[serde(default)]
    pub wallet_network_id: Option<String>,
    /// Whether the publisher is active
    #[serde(default)]
    pub is_active: Option<bool>,
    /// External API URL (for integration_type: api)
    #[serde(default)]
    pub api_url: Option<String>,
    /// MCP server endpoint URL (for integration_type: mcp)
    #[serde(default)]
    pub mcp_endpoint: Option<String>,
    /// SerenDB project ID (for database_type: serendb)
    #[serde(default)]
    pub project_id: Option<Uuid>,
    /// SerenDB branch ID (for database_type: serendb)
    #[serde(default)]
    pub branch_id: Option<Uuid>,
    /// Database name within the SerenDB project
    #[serde(default)]
    pub database_name: Option<String>,
    /// Database connection string shorthand (for database_type: neon or supabase).
    /// Converted to database_config = {"connection_string": "..."}.
    /// Leave blank to keep existing, provide new value to update.
    #[serde(default)]
    pub connection_string: Option<String>,
    /// Generic provider-specific configuration object passed through as database_config.
    #[serde(default)]
    pub database_config: Option<serde_json::Value>,
    /// Billing model (x402_per_request, prepaid_credits, x402_passthrough, pay_per_use)
    /// pay_per_use requires: publisher_category="integration", integration_type="api",
    /// auth_type != "passthrough", and upstream_cost_response_path must be set
    #[serde(default)]
    pub billing_model: Option<String>,
    /// Dot-separated path to upstream cost in response body (required for pay_per_use billing).
    /// Example: "usage.cost" extracts the cost from {"usage": {"cost": 0.0023}}
    #[serde(default)]
    pub upstream_cost_response_path: Option<String>,
    /// Contact email for notifications and support
    #[serde(default)]
    pub email: Option<String>,
    /// Structured endpoint definitions for LLM discoverability and access control
    #[serde(default)]
    pub endpoints: Option<Vec<EndpointDefinitionParam>>,
    /// Policy for handling requests to paths not in the endpoints catalog
    /// "allow" (default) passes through undocumented paths, "block" returns 403
    #[serde(default)]
    pub undocumented_endpoint_policy: Option<String>,
    /// URL to call for exchanging Seren API keys for publisher auth tokens
    #[serde(default)]
    pub token_exchange_url: Option<String>,
    /// HTTP method for token exchange endpoint (POST or GET)
    #[serde(default)]
    pub token_exchange_method: Option<String>,
    /// How to send Seren token to exchange endpoint: header, body, or query
    #[serde(default)]
    pub token_exchange_mode: Option<String>,
    /// TTL for cached exchanged tokens in seconds (60-86400)
    #[serde(default)]
    pub token_cache_ttl_seconds: Option<i32>,
    /// JSON field in exchange response containing the token (default: access_token)
    #[serde(default)]
    pub token_response_field: Option<String>,
    /// Upstream static API key (will be encrypted). Used for static API key authentication.
    #[serde(default)]
    pub upstream_api_key: Option<String>,
    /// Header name to inject upstream_api_key into (e.g., "Authorization", "X-API-Key", "X-cb-user-key")
    #[serde(default)]
    pub api_key_header: Option<String>,
    /// Query parameter name to inject upstream_api_key into (e.g., "api_key")
    #[serde(default)]
    pub api_key_query_param: Option<String>,
    /// Whitelist of agent-provided headers allowed to pass through to upstream
    #[serde(default)]
    pub allowed_passthrough_headers: Option<Vec<String>>,
    /// Map of client header names to upstream header names for passthrough auth.
    /// Use this to map a non-reserved client header to Authorization upstream.
    #[serde(default)]
    pub passthrough_header_rewrite: Option<HashMap<String, String>>,
    /// Default headers included in upstream requests
    #[serde(default)]
    pub upstream_headers: Option<HashMap<String, String>>,
    /// Upstream auth mode: "static", "jwt", "oauth2_cc", or "passthrough"
    #[serde(default)]
    pub auth_type: Option<String>,
    /// OAuth2 token endpoint URL for Client Credentials flow
    #[serde(default)]
    pub oauth2_token_url: Option<String>,
    /// OAuth2 client ID for Client Credentials flow
    #[serde(default)]
    pub oauth2_client_id: Option<String>,
    /// OAuth2 client secret for Client Credentials flow (will be encrypted)
    #[serde(default)]
    pub oauth2_client_secret: Option<String>,
    /// OAuth2 scopes to request during Client Credentials flow
    #[serde(default)]
    pub oauth2_scopes: Option<Vec<String>>,
    /// Display name for the publisher resource (shown on website)
    #[serde(default)]
    pub resource_name: Option<String>,
    /// Description of the publisher resource (shown on website)
    #[serde(default)]
    pub resource_description: Option<String>,
    /// OAuth provider ID for BYOC (Bring Your Own Credentials) authentication
    #[serde(default)]
    pub oauth_provider_id: Option<Uuid>,
    /// If true, users must connect via OAuth before using this publisher
    #[serde(default)]
    pub requires_user_oauth: Option<bool>,
}

/// Parameters for updating a publisher's pricing configuration
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdatePublisherPricingParams {
    /// Publisher slug (unique identifier) to update pricing for
    pub slug: String,
    /// Price per API call (decimal string, e.g., "0.01" for $0.01 per call)
    #[serde(default)]
    pub price_per_call: Option<String>,
    /// Price per execution for agent templates (decimal string)
    #[serde(default)]
    pub price_per_execution: Option<String>,
    /// Base price per 1000 rows for database queries (decimal string)
    #[serde(default)]
    pub base_price_per_1000_rows: Option<String>,
    /// Price per GET request (decimal string)
    #[serde(default)]
    pub price_per_get: Option<String>,
    /// Price per POST request (decimal string)
    #[serde(default)]
    pub price_per_post: Option<String>,
    /// Price per PUT request (decimal string)
    #[serde(default)]
    pub price_per_put: Option<String>,
    /// Price per PATCH request (decimal string)
    #[serde(default)]
    pub price_per_patch: Option<String>,
    /// Price per DELETE request (decimal string)
    #[serde(default)]
    pub price_per_delete: Option<String>,
    /// Minimum charge per request (decimal string)
    #[serde(default)]
    pub min_charge: Option<String>,
    /// Maximum amount to reserve up-front for pay_per_use pre-authorization (decimal string)
    #[serde(default)]
    pub reserve_max_charge: Option<String>,
    /// Fallback charge when cost cannot be resolved from upstream response (decimal string)
    #[serde(default)]
    pub unresolved_fallback_charge: Option<String>,
    /// Whether prepaid credits are enabled
    #[serde(default)]
    pub prepaid_enabled: Option<bool>,
    /// Whether on-chain payments are enabled
    #[serde(default)]
    pub onchain_enabled: Option<bool>,
}

/// Parameters for uploading a publisher logo
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UploadPublisherLogoParams {
    /// Organization ID that owns this publisher
    pub organization_id: uuid::Uuid,
    /// Publisher ID (UUID)
    pub publisher_id: uuid::Uuid,
    /// Base64 encoded image data (PNG, JPEG, WebP, or SVG)
    pub logo: String,
    /// Content type of the image (image/png, image/jpeg, image/webp, image/svg+xml)
    pub content_type: String,
}

// ============================================================================
// Agent Template Parameter Types
// ============================================================================

/// Parameters for listing agent templates
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListAgentTemplatesParams {
    /// Filter by programming language (python, typescript, javascript)
    #[serde(default)]
    pub language: Option<String>,
    /// Filter to verified templates only
    #[serde(default)]
    pub verified_only: Option<bool>,
    /// Search templates by name or description
    #[serde(default)]
    pub search: Option<String>,
    /// Maximum number of templates to return (default: 20, max: 50)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(default)]
    pub offset: Option<i64>,
    /// Filter by minimum price (atomic units)
    #[serde(default)]
    pub min_price: Option<i64>,
    /// Filter by maximum price (atomic units)
    #[serde(default)]
    pub max_price: Option<i64>,
}

/// Parameters for getting a specific agent template
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentTemplateParams {
    /// Template slug (URL-friendly identifier)
    pub slug: String,
}

/// Parameters for invoking an agent template
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct InvokeAgentTemplateParams {
    /// Template slug (URL-friendly identifier)
    pub slug: String,
    /// Input data for the template (JSON object)
    pub input: serde_json::Value,
    /// Set to true to confirm a payment that exceeded the auto-approve limit.
    #[serde(default)]
    pub confirm: bool,
}

// ============================================================================
// MCP Publisher Parameter Types
// ============================================================================

/// Parameters for listing tools available on an MCP publisher
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListMcpToolsParams {
    /// Publisher slug (URL-friendly identifier) of the MCP publisher
    pub publisher: String,
}

/// Parameters for listing resources available on an MCP publisher
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListMcpResourcesParams {
    /// Publisher slug (URL-friendly identifier) of the MCP publisher
    pub publisher: String,
}

/// Parameters for retrieving generated skill.md guidance for a publisher
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetPublisherSkillDocParams {
    /// Publisher slug or UUID
    pub publisher: String,
}

// ============================================================================
// Additional Parameter Types for Extended Functionality
// ============================================================================

// Project update operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateProjectParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// New project name
    #[serde(default)]
    pub name: Option<String>,
    /// Block public connections
    #[serde(default)]
    pub block_public_connections: Option<bool>,
    /// Block VPC connections
    #[serde(default)]
    pub block_vpc_connections: Option<bool>,
    /// Enable HIPAA controls
    #[serde(default)]
    pub hipaa: Option<bool>,
    /// Apply IP allow list only to protected branches
    #[serde(default)]
    pub protected_branches_only: Option<bool>,
    /// Default compute unit minimum
    #[serde(default)]
    pub compute_unit_min: Option<i32>,
    /// Default compute unit maximum
    #[serde(default)]
    pub compute_unit_max: Option<i32>,
    /// Enable logical replication (cannot be disabled once enabled)
    #[serde(default)]
    pub enable_logical_replication: Option<bool>,
    /// History retention period in seconds for point-in-time recovery (PITR).
    /// Default is 21600 (6 hours). Minimum is 3600 (1 hour). Maximum is 2592000 (30 days).
    #[serde(default)]
    pub history_retention_seconds: Option<i64>,
}

// Branch management operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RenameBranchParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// New branch name
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetDefaultBranchParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID) to set as default
    pub branch_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ResetBranchParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID) to reset
    pub branch_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SetBranchExpirationParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Expiration date in RFC3339 format (e.g., "2025-12-31T23:59:59Z"), or null to remove expiration
    #[serde(default)]
    pub expires_at: Option<String>,
}

// Role management operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateRoleParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Role name
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteRoleParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Role ID (UUID)
    pub role_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ResetRolePasswordParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Role ID (UUID)
    pub role_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RevealRolePasswordParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Role name
    pub role_name: String,
}

// Endpoint management operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateEndpointParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// The endpoint ID (UUID)
    pub endpoint_id: Uuid,
    /// Minimum autoscaling compute units
    #[serde(default)]
    pub autoscaling_min: Option<i32>,
    /// Maximum autoscaling compute units
    #[serde(default)]
    pub autoscaling_max: Option<i32>,
    /// Suspend timeout in seconds (0 for default, -1 for never)
    #[serde(default)]
    pub suspend_timeout_seconds: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetEndpointStatusParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// The endpoint ID (UUID)
    pub endpoint_id: Uuid,
}

// Database management operations
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteDatabaseParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Database ID (UUID)
    pub database_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetDatabaseParams {
    /// The project ID (UUID)
    pub project_id: Uuid,
    /// The branch ID (UUID)
    pub branch_id: Uuid,
    /// Database ID (UUID)
    pub database_id: Uuid,
}

// Wallet transaction history
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetTransactionHistoryParams {
    /// Maximum number of transactions to return (default 50, max 100)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RunAgentCloudParams {
    /// Publisher slug of the A2A agent to invoke
    pub publisher_slug: String,
    /// Input message (text string or JSON object)
    pub message: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListSerenAgentPrivateModelsParams {
    /// Optional private model region for live discovery. Defaults to us-east-1.
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PrivateModelsChatParams {
    /// Optional model identifier. Omit to use the publisher default.
    #[serde(default)]
    pub model: Option<String>,
    /// Simple user message. Mutually exclusive with messages.
    #[serde(default)]
    pub message: Option<String>,
    /// Full OpenAI-compatible message objects.
    #[serde(default)]
    pub messages: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
    /// Sampling temperature.
    #[serde(default)]
    pub temperature: Option<f32>,
    /// Maximum output tokens.
    #[serde(default)]
    pub max_tokens: Option<i32>,
    /// Top-p sampling value.
    #[serde(default)]
    pub top_p: Option<f32>,
    /// Top-k sampling value.
    #[serde(default)]
    pub top_k: Option<i32>,
    /// JSON schema object for structured responses.
    #[serde(default)]
    pub response_schema: Option<serde_json::Map<String, serde_json::Value>>,
    /// Tool definition objects.
    #[serde(default)]
    pub tools: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
}

pub type GetPrivateModelsPolicyParams = OrganizationPath;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdatePrivateModelsPolicyParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    #[serde(flatten)]
    pub body: seren::UpdateOrganizationPrivateModelsPolicyRequest,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListAgentTasksParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// Maximum number of tasks to return (default: 20, max: 100)
    #[serde(default)]
    pub limit: Option<i64>,
    /// Offset for pagination
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetAgentTaskParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// Task ID (UUID)
    pub task_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CancelAgentTaskParams {
    /// The organization ID (UUID)
    pub organization_id: Uuid,
    /// Task ID (UUID)
    pub task_id: Uuid,
}

// ============================================================================
// Cloud Deployment Parameter Types
// ============================================================================

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeployCloudAgentParams {
    /// Skill slug identifier (e.g., "coinbase-grid-trader")
    pub skill_slug: String,
    /// Display name for the deployment
    pub name: String,
    /// Optional reusable execution environment UUID (AWS container backend only)
    #[serde(default)]
    pub environment_id: Option<Uuid>,
    /// Deployment mode: "always_on", "cron", or "job"
    pub mode: String,
    /// Cron schedule expression (required if mode is "cron")
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// Cron timezone as an IANA name (defaults to UTC)
    #[serde(default)]
    pub cron_timezone: Option<String>,
    /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
    #[serde(default)]
    pub eval_gate_set_id: Option<Uuid>,
    /// Freshness window in seconds for the eval gate (required with eval_gate_set_id)
    #[serde(default)]
    pub eval_gate_max_age_seconds: Option<i32>,
    /// Optional compute backend override ("auto", "aws_container", "cloudflare_worker", or "daytona"). Omit for AWS-first auto-routing.
    #[serde(default)]
    pub compute_backend: Option<String>,
    /// Optional runtime override ("auto", "python", "javascript", "typescript", "rust", or "rust_wasm_adk"). Omit to infer from the bundle.
    #[serde(default)]
    pub runtime_kind: Option<String>,
    /// Uploaded deployment bundle UUID. Provide this or deployment_bundle_content_base64.
    #[serde(default)]
    pub deployment_bundle_id: Option<Uuid>,
    /// Base64-encoded tar.gz deployment bundle. The tool registers it by SHA-256, uploads raw bytes only if needed, then deploys by bundle id.
    #[serde(default)]
    pub deployment_bundle_content_base64: Option<String>,
    /// pip requirements.txt content
    #[serde(default)]
    pub requirements_txt: Option<String>,
    /// JSON config object
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// JSON secrets object (key-value pairs for .env)
    #[serde(default)]
    pub secrets: Option<serde_json::Value>,
    /// Optional maximum LLM loop iterations
    #[serde(default)]
    pub max_iterations: Option<i32>,
    /// Optional maximum wall-clock timeout per run in seconds
    #[serde(default)]
    pub max_timeout_seconds: Option<i32>,
    /// Optional maximum tool output size in characters
    #[serde(default)]
    pub max_tool_output_chars: Option<i32>,
    /// Optional cumulative context token budget
    #[serde(default)]
    pub context_budget_tokens: Option<i32>,
    /// Optional deployment requirements validated at deploy time
    #[serde(default)]
    pub requirements: Option<serde_json::Value>,
    /// Optional dashboard rendering config
    #[serde(default)]
    pub dashboard_config: Option<serde_json::Value>,
    /// Optional visibility mode ("open" or "opaque")
    #[serde(default)]
    pub visibility: Option<String>,
}

fn validate_deploy_cloud_secrets(secrets: Option<&serde_json::Value>) -> Result<(), McpError> {
    let Some(secrets) = secrets else {
        return Ok(());
    };
    let Some(object) = secrets.as_object() else {
        return Err(McpError::invalid_params(
            "secrets must be a JSON object.",
            None,
        ));
    };
    if let Some(key) = object.keys().find(|key| {
        key.get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SEREN_"))
    }) {
        let guidance = if key.eq_ignore_ascii_case("SEREN_API_KEY") {
            " SEREN_API_KEY is generated and injected automatically for each deployment."
        } else {
            " Seren reserves this namespace for deployment-managed runtime values."
        };
        return Err(McpError::invalid_params(
            format!("Secret '{key}' uses the reserved SEREN_ runtime namespace.{guidance}"),
            None,
        ));
    }
    Ok(())
}

fn build_deploy_cloud_agent_request(
    params: DeployCloudAgentParams,
    deployment_bundle_id: Uuid,
) -> Result<seren::CreateCloudDeploymentRequest, McpError> {
    let mode = parse_cloud_enum::<seren::CloudDeploymentMode>("mode", &params.mode)?;
    let compute_backend = match params.compute_backend.as_deref() {
        Some("auto") | None => None,
        Some(value) => Some(parse_cloud_enum::<seren::CloudDeploymentComputeBackend>(
            "compute_backend",
            value,
        )?),
    };
    let runtime_kind = match params.runtime_kind.as_deref() {
        Some("auto") | None => None,
        Some(value) => Some(parse_cloud_enum::<seren::CloudDeploymentRuntimeKind>(
            "runtime_kind",
            value,
        )?),
    };
    let eval_gate = match (params.eval_gate_set_id, params.eval_gate_max_age_seconds) {
        (Some(set_id), Some(max_age_seconds)) => Some(seren::EvalGate {
            block_on_failure: None,
            drift_baseline: None,
            max_age_seconds,
            schedule: None,
            set_id,
        }),
        (None, None) => None,
        (Some(_), None) => {
            return Err(McpError::invalid_params(
                "eval_gate_max_age_seconds is required with eval_gate_set_id.",
                None,
            ));
        }
        (None, Some(_)) => {
            return Err(McpError::invalid_params(
                "eval_gate_set_id is required with eval_gate_max_age_seconds.",
                None,
            ));
        }
    };
    let requirements = params
        .requirements
        .map(serde_json::from_value::<Vec<seren::RequirementSpec>>)
        .transpose()
        .map_err(|e| McpError::invalid_params(format!("Invalid requirements: {e}"), None))?;
    let limits = if params.context_budget_tokens.is_some()
        || params.max_iterations.is_some()
        || params.max_timeout_seconds.is_some()
        || params.max_tool_output_chars.is_some()
    {
        Some(seren::WorkloadLimits {
            context_budget_tokens: params.context_budget_tokens,
            max_iterations: params.max_iterations,
            max_timeout_seconds: params.max_timeout_seconds,
            max_tool_calls_per_run: None,
            max_tool_output_chars: params.max_tool_output_chars,
        })
    } else {
        None
    };

    Ok(seren::CreateCloudDeploymentRequest {
        alert_policy: None,
        cron_schedule: params.cron_schedule,
        cron_timezone: params.cron_timezone,
        dashboard_config: params.dashboard_config,
        environment_id: params.environment_id,
        eval_gate,
        mode,
        name: Some(params.name),
        skill_slug: params.skill_slug,
        visibility: params.visibility,
        workload: seren::WorkloadSpec {
            compute_backend,
            config: params.config,
            execution: seren::WorkloadExecution::Code {
                deployment_bundle_id,
                requirements_txt: params.requirements_txt,
                runtime_kind,
            },
            external_databases: Vec::new(),
            limits,
            network_policy: None,
            publisher_only: None,
            requirements,
            secrets: params.secrets,
            side_effect_policy: None,
        },
    })
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetCloudDeploymentBundleParams {
    /// Deployment bundle UUID
    pub deployment_bundle_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TestSerenAgentDraftRunParams {
    #[serde(flatten)]
    pub body: seren::AgentSpec,
    /// Optional test message. When omitted, the server uses a generic first-run prompt.
    #[serde(default)]
    pub test_message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetSerenAgentDeploymentParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListSerenAgentDeploymentToolsParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Optional case-insensitive search over tool names, descriptions, and sources
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DescribeSerenAgentDeploymentToolParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Tool name exactly as reported by list_seren_agent_deployment_tools
    pub tool_name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetSerenAgentDeploymentActivityParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Max run activity entries to return
    #[serde(default)]
    pub limit: Option<i64>,
    /// Pagination offset
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateSerenAgentDeploymentParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Updated stable agent slug identifier
    #[serde(default)]
    pub agent_slug: Option<String>,
    /// Updated display name for the managed agent
    #[serde(default)]
    pub name: Option<String>,
    /// Updated cron schedule expression (cron deployments only)
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// Updated cron timezone (cron deployments only)
    #[serde(default)]
    pub cron_timezone: Option<String>,
    /// Updated eval set ID that gates execution
    #[serde(default)]
    pub eval_gate_set_id: Option<Uuid>,
    /// Updated eval gate freshness window in seconds
    #[serde(default)]
    pub eval_gate_max_age_seconds: Option<i32>,
    /// Clear any existing eval gate configuration
    #[serde(default)]
    pub clear_eval_gate: bool,
    /// Updated main instructions for the managed agent
    #[serde(default)]
    pub prompt: Option<String>,
    /// Updated model identifier
    #[serde(default)]
    pub model_id: Option<String>,
    /// Updated agent style (`research_monitor` or `workflow_agent`)
    #[serde(default)]
    pub template: Option<String>,
    /// Alias for `template` with more product-oriented wording
    #[serde(default)]
    pub agent_style: Option<String>,
    /// Updated capability list (`live_data`, `publisher_actions`, `database`)
    #[serde(default)]
    pub tool_presets: Option<Vec<String>>,
    /// Alias for `tool_presets`
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    /// Typed tool refs for scoped publisher, connector, MCP, or remote tools.
    #[serde(default)]
    pub tool_refs: Option<Vec<seren::AgentToolRef>>,
    /// Clear typed tool refs from the managed agent.
    #[serde(default)]
    pub clear_tool_refs: bool,
    /// Updated access mode (`read_only` or `allow_mutations`)
    #[serde(default)]
    pub approval_policy: Option<String>,
    /// Alias for `approval_policy`
    #[serde(default)]
    pub access_mode: Option<String>,
    /// Updated performance profile (`fast`, `balanced`, or `deep`)
    #[serde(default)]
    pub model_policy: Option<String>,
    /// Alias for `model_policy`
    #[serde(default)]
    pub performance_profile: Option<String>,
    /// Updated allowlist for remote A2A delegation targets
    #[serde(default)]
    pub allowed_remote_agent_origins: Option<Vec<String>>,
    /// Updated JSON config object
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// Updated JSON secrets object
    #[serde(default)]
    pub secrets: Option<serde_json::Value>,
    /// Updated optional model configuration
    #[serde(default)]
    pub model_config: Option<serde_json::Value>,
    /// Updated optional fallback model list
    #[serde(default)]
    pub fallback_models: Option<Vec<String>>,
    /// Updated optional maximum wall-clock timeout per run in seconds
    #[serde(default)]
    pub max_timeout_seconds: Option<i32>,
    /// Updated optional deployment requirements validated at deploy time
    #[serde(default)]
    pub requirements: Option<serde_json::Value>,
    /// Updated optional dashboard rendering config
    #[serde(default)]
    pub dashboard_config: Option<serde_json::Value>,
    /// Updated runtime capability policy
    #[serde(default)]
    pub capability_policy: Option<serde_json::Value>,
    /// Clear any existing capability policy
    #[serde(default)]
    pub clear_capability_policy: bool,
    /// Updated optional visibility mode ("open" or "opaque")
    #[serde(default)]
    pub visibility: Option<String>,
}

fn resolve_guided_string_alias(
    raw: Option<&String>,
    alias: Option<&String>,
    raw_label: &str,
    alias_label: &str,
) -> Result<Option<String>, McpError> {
    match (raw, alias) {
        (Some(raw), Some(alias)) if raw.trim() != alias.trim() => Err(McpError::invalid_params(
            format!("Provide either {raw_label} or {alias_label}, or use matching values."),
            None,
        )),
        (Some(raw), _) => Ok(Some(raw.trim().to_string())),
        (None, Some(alias)) => Ok(Some(alias.trim().to_string())),
        (None, None) => Ok(None),
    }
}

fn resolve_guided_list_alias(
    raw: Option<&Vec<String>>,
    alias: Option<&Vec<String>>,
    raw_label: &str,
    alias_label: &str,
) -> Result<Option<Vec<String>>, McpError> {
    match (raw, alias) {
        (Some(raw), Some(alias)) if raw != alias => Err(McpError::invalid_params(
            format!("Provide either {raw_label} or {alias_label}, or use matching values."),
            None,
        )),
        (Some(raw), _) => Ok(Some(raw.clone())),
        (None, Some(alias)) => Ok(Some(alias.clone())),
        (None, None) => Ok(None),
    }
}

async fn build_update_seren_agent_deployment_request(
    api_client: &seren::Client,
    params: &UpdateSerenAgentDeploymentParams,
) -> Result<seren::AgentSpecUpdate, McpError> {
    let template = resolve_guided_string_alias(
        params.template.as_ref(),
        params.agent_style.as_ref(),
        "template",
        "agent_style",
    )?;
    let tool_presets = resolve_guided_list_alias(
        params.tool_presets.as_ref(),
        params.capabilities.as_ref(),
        "tool_presets",
        "capabilities",
    )?;
    let approval_policy = resolve_guided_string_alias(
        params.approval_policy.as_ref(),
        params.access_mode.as_ref(),
        "approval_policy",
        "access_mode",
    )?;
    let model_policy = resolve_guided_string_alias(
        params.model_policy.as_ref(),
        params.performance_profile.as_ref(),
        "model_policy",
        "performance_profile",
    )?;
    let template = seren::parse_managed_agent_template(template.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let tool_presets = tool_presets
        .as_ref()
        .map(|values| seren::parse_managed_agent_tool_presets(values.iter().map(String::as_str)))
        .transpose()
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?
        .flatten();
    let approval_policy = seren::parse_managed_agent_approval_policy(approval_policy.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let model_policy = seren::parse_managed_agent_model_policy(model_policy.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let capability_policy = parse_capability_policy(params.capability_policy.clone())?;
    if capability_policy.is_some() && params.clear_capability_policy {
        return Err(McpError::invalid_params(
            "Provide either capability_policy or clear_capability_policy, not both.",
            None,
        ));
    }
    if params.tool_refs.is_some() && params.clear_tool_refs {
        return Err(McpError::invalid_params(
            "Provide either tool_refs or clear_tool_refs, not both.",
            None,
        ));
    }
    let eval_gate = match (
        params.eval_gate_set_id,
        params.eval_gate_max_age_seconds,
        params.clear_eval_gate,
    ) {
        (Some(set_id), Some(max_age_seconds), false) => Some(seren::EvalGate {
            block_on_failure: None,
            drift_baseline: None,
            max_age_seconds,
            schedule: None,
            set_id,
        }),
        (None, None, _) => None,
        (Some(_), None, false) => {
            return Err(McpError::invalid_params(
                "eval_gate_max_age_seconds is required with eval_gate_set_id.",
                None,
            ));
        }
        (None, Some(_), false) => {
            return Err(McpError::invalid_params(
                "eval_gate_set_id is required with eval_gate_max_age_seconds.",
                None,
            ));
        }
        (Some(_), _, true) | (_, Some(_), true) => {
            return Err(McpError::invalid_params(
                "Provide either clear_eval_gate or eval_gate_set_id plus eval_gate_max_age_seconds, not both.",
                None,
            ));
        }
    };
    let workload = if update_requires_workload_replacement(params) {
        Some(build_replacement_workload(api_client, params).await?)
    } else {
        None
    };

    Ok(seren::AgentSpecUpdate {
        agent_identity_id: None,
        agent_slug: params.agent_slug.clone(),
        alert_policy: None,
        allowed_remote_agent_origins: params.allowed_remote_agent_origins.clone(),
        approval_policy,
        capability_policy,
        clear_alert_policy: None,
        clear_capability_policy: params.clear_capability_policy.then_some(true),
        clear_credentials: None,
        clear_dashboard_config: None,
        clear_eval_gate: params.clear_eval_gate.then_some(true),
        clear_guardrails: None,
        clear_memory_policy: None,
        clear_runtime_policy: None,
        clear_secret_resolution_delegation: None,
        clear_session_database: None,
        clear_tool_refs: params.clear_tool_refs.then_some(true),
        credentials: None,
        cron_schedule: params.cron_schedule.clone(),
        cron_timezone: params.cron_timezone.clone(),
        dashboard_config: params.dashboard_config.clone(),
        eval_gate,
        guardrails: None,
        memory_policy: None,
        model_policy,
        name: params.name.clone(),
        private_output_policy: None,
        runtime_policy: None,
        secret_resolution_delegation: None,
        session_database: None,
        template,
        tool_presets,
        tool_refs: params.tool_refs.clone(),
        visibility: params.visibility.clone(),
        workload,
    })
}

fn update_requires_workload_replacement(params: &UpdateSerenAgentDeploymentParams) -> bool {
    params.prompt.is_some()
        || params.model_id.is_some()
        || params.config.is_some()
        || params.secrets.is_some()
        || params.model_config.is_some()
        || params.fallback_models.is_some()
        || params.max_timeout_seconds.is_some()
        || params.requirements.is_some()
}

async fn build_replacement_workload(
    api_client: &seren::Client,
    params: &UpdateSerenAgentDeploymentParams,
) -> Result<seren::WorkloadSpec, McpError> {
    let detail = api_client
        .seren_agent_get_managed_deployment(&params.deployment_id)
        .into_mcp_result()
        .await?
        .into_inner()
        .data;

    if !detail.secret_keys.is_empty() && params.secrets.is_none() {
        return Err(McpError::invalid_params(
            "This deployment has existing secrets. Because managed-agent workload updates are full replacements, provide the complete replacement secrets object when changing workload-level fields.",
            None,
        ));
    }

    let requirements = params
        .requirements
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| McpError::invalid_params(format!("Invalid requirements payload: {e}"), None))?
        .unwrap_or(detail.requirements);

    Ok(seren::WorkloadSpec {
        compute_backend: Some(detail.compute_backend),
        config: params.config.clone().or(detail.config),
        execution: seren::WorkloadExecution::Llm {
            adapter: Some(detail.runtime_adapter),
            bundle: bundle_with_prompt_override(detail.bundle, params.prompt.clone()),
            fallback_models: params.fallback_models.clone().or(detail.fallback_models),
            llm_connection: detail.llm_connection,
            model_config: Some(params.model_config.clone().unwrap_or(detail.model_config)),
            model_id: Some(params.model_id.clone().unwrap_or(detail.model_id)),
            tool_definitions: None,
        },
        external_databases: detail.external_databases,
        limits: Some(seren::WorkloadLimits {
            context_budget_tokens: detail.context_budget_tokens,
            max_iterations: detail.max_iterations,
            max_timeout_seconds: params.max_timeout_seconds.or(detail.max_timeout_seconds),
            max_tool_calls_per_run: detail.max_tool_calls_per_run,
            max_tool_output_chars: detail.max_tool_output_chars,
        }),
        network_policy: detail.network_policy,
        publisher_only: None,
        requirements: Some(requirements),
        secrets: params.secrets.clone(),
        side_effect_policy: detail.side_effect_policy,
    })
}

fn bundle_with_prompt_override(
    mut bundle: seren::AgentBundle,
    prompt_override: Option<String>,
) -> seren::AgentBundle {
    let Some(prompt) = prompt_override else {
        return bundle;
    };

    if let Some(instruction) = bundle
        .instructions
        .iter_mut()
        .find(|instruction| instruction.kind == seren::AgentInstructionKind::Skill)
    {
        instruction.content = prompt;
        instruction.sha256 = None;
    } else {
        bundle.instructions.push(seren::AgentInstructionFile {
            allowed_tools: None,
            content: prompt,
            kind: seren::AgentInstructionKind::Skill,
            path: Some("SKILL.md".to_string()),
            sha256: None,
            skill_name: None,
        });
    }

    bundle
}

fn bundle_for_prompt(prompt: String) -> seren::AgentBundle {
    seren::AgentBundle {
        assets: Vec::new(),
        instructions: vec![seren::AgentInstructionFile {
            allowed_tools: None,
            content: prompt,
            kind: seren::AgentInstructionKind::Skill,
            path: Some("SKILL.md".to_string()),
            sha256: None,
            skill_name: None,
        }],
    }
}

fn default_employee_memory_policy() -> Result<seren::AgentMemoryPolicy, McpError> {
    serde_json::from_value(serde_json::json!({
        "graph_memory": {
            "enabled": true,
            "store": "seren_managed",
            "write_policy": "on_observation",
            "read_policy": "explicit_tool"
        },
        "semantic_memory": {
            "enabled": false,
            "store": "seren_managed",
            "write_policy": "none",
            "read_policy": "explicit_tool",
            "retention_days": null
        },
        "knowledge": {
            "enabled": true,
            "store": "seren_managed",
            "source": "agent_instructions",
            "read_policy": "explicit_tool",
            "index_policy": "encrypted_scan",
            "chunk_size": null,
            "chunk_overlap": null,
            "top_k": null
        },
        "transcript_retention_days": 30,
        "compaction": {
            "token_threshold": 120000,
            "event_retention_count": 24,
            "overlap_tokens": 1500
        }
    }))
    .map_err(|error| {
        McpError::internal_error(
            format!("Failed to build default employee memory policy: {error}"),
            None,
        )
    })
}

fn default_employee_capability_policy() -> Result<seren::AgentCapabilityPolicy, McpError> {
    serde_json::from_value(serde_json::json!({
        "tool_error_recovery": {
            "enabled": true,
            "max_attempts": 3,
            "global_limit": 12,
            "backoff": {
                "kind": "exponential",
                "base_delay_ms": 100,
                "max_delay_ms": 2000
            },
            "allow_tools": [],
            "deny_tools": []
        },
        "browser": {
            "enabled": false,
            "profile": "minimal"
        },
        "audio": {
            "enabled": false,
            "speech_to_text": false,
            "text_to_speech": false,
            "voice_activity_detection": false
        },
        "realtime_sessions": {
            "enabled": false,
            "provider": "open_ai",
            "voice_activity_detection": true,
            "input_transcription": true,
            "persist_transcripts": true,
            "store_to_memory": true
        }
    }))
    .map_err(|error| {
        McpError::internal_error(
            format!("Failed to build default employee capability policy: {error}"),
            None,
        )
    })
}

fn parse_capability_policy(
    value: Option<serde_json::Value>,
) -> Result<Option<seren::AgentCapabilityPolicy>, McpError> {
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            McpError::invalid_params(format!("Invalid capability_policy payload: {error}"), None)
        })
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RollbackSerenAgentDeploymentParams {
    /// Managed deployment ID
    pub deployment_id: uuid::Uuid,
    /// Revision to preview or restore
    pub revision_id: uuid::Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeploySerenAgentParams {
    /// Stable agent slug identifier (e.g., "btc-price-watcher")
    #[serde(default)]
    pub agent_slug: Option<String>,
    /// Display name for the managed agent
    pub name: String,
    /// Deployment mode: "always_on", "cron", or "job"
    pub mode: String,
    /// Cron schedule expression (required if mode is "cron")
    #[serde(default)]
    pub cron_schedule: Option<String>,
    /// Cron timezone as an IANA name (defaults to UTC)
    #[serde(default)]
    pub cron_timezone: Option<String>,
    /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
    #[serde(default)]
    pub eval_gate_set_id: Option<Uuid>,
    /// Freshness window in seconds for the eval gate (required with eval_gate_set_id)
    #[serde(default)]
    pub eval_gate_max_age_seconds: Option<i32>,
    /// Main instructions, encoded as a skill instruction in the LLM workload bundle
    pub prompt: String,
    /// Optional model identifier. Omit to use the platform default.
    #[serde(default)]
    pub model_id: Option<String>,
    /// Optional compute backend override ("aws_container", "cloudflare_worker", or "daytona"). Omit for AWS-first managed routing.
    #[serde(default)]
    pub compute_backend: Option<String>,
    /// Agent style (`research_monitor` or `workflow_agent`)
    #[serde(default)]
    pub template: Option<String>,
    /// Alias for `template` with more product-oriented wording
    #[serde(default)]
    pub agent_style: Option<String>,
    /// Capability list (`live_data`, `publisher_actions`, and/or `database`)
    #[serde(default)]
    pub tool_presets: Option<Vec<String>>,
    /// Alias for `tool_presets`
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    /// Typed tool refs for scoped publisher, connector, MCP, or remote tools.
    #[serde(default)]
    pub tool_refs: Option<Vec<seren::AgentToolRef>>,
    /// Access mode (`read_only` or `allow_mutations`)
    #[serde(default)]
    pub approval_policy: Option<String>,
    /// Alias for `approval_policy`
    #[serde(default)]
    pub access_mode: Option<String>,
    /// Performance profile (`fast`, `balanced`, or `deep`)
    #[serde(default)]
    pub model_policy: Option<String>,
    /// Alias for `model_policy`
    #[serde(default)]
    pub performance_profile: Option<String>,
    /// Allow remote A2A delegation to these hostnames or origins
    #[serde(default)]
    pub allowed_remote_agent_origins: Option<Vec<String>>,
    /// JSON config object
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// JSON secrets object (key-value pairs for .env)
    #[serde(default)]
    pub secrets: Option<serde_json::Value>,
    /// Optional model configuration (temperature, max_tokens, etc.)
    #[serde(default)]
    pub model_config: Option<serde_json::Value>,
    /// Optional fallback model list for transient failures
    #[serde(default)]
    pub fallback_models: Option<Vec<String>>,
    /// Optional maximum wall-clock timeout per run in seconds
    #[serde(default)]
    pub max_timeout_seconds: Option<i32>,
    /// Optional deployment requirements validated at deploy time
    #[serde(default)]
    pub requirements: Option<serde_json::Value>,
    /// Optional dashboard rendering config
    #[serde(default)]
    pub dashboard_config: Option<serde_json::Value>,
    /// Optional runtime capability policy for browser, audio, skills, realtime, and code execution
    #[serde(default)]
    pub capability_policy: Option<serde_json::Value>,
    /// Optional visibility mode ("open" or "opaque")
    #[serde(default)]
    pub visibility: Option<String>,
}

fn build_deploy_seren_agent_request(
    params: DeploySerenAgentParams,
) -> Result<seren::AgentSpec, McpError> {
    let template = resolve_guided_string_alias(
        params.template.as_ref(),
        params.agent_style.as_ref(),
        "template",
        "agent_style",
    )?;
    let tool_presets = resolve_guided_list_alias(
        params.tool_presets.as_ref(),
        params.capabilities.as_ref(),
        "tool_presets",
        "capabilities",
    )?;
    let approval_policy = resolve_guided_string_alias(
        params.approval_policy.as_ref(),
        params.access_mode.as_ref(),
        "approval_policy",
        "access_mode",
    )?;
    let model_policy = resolve_guided_string_alias(
        params.model_policy.as_ref(),
        params.performance_profile.as_ref(),
        "model_policy",
        "performance_profile",
    )?;
    let template = seren::parse_managed_agent_template(template.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let tool_presets = tool_presets
        .as_ref()
        .map(|values| seren::parse_managed_agent_tool_presets(values.iter().map(String::as_str)))
        .transpose()
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?
        .flatten();
    let approval_policy = seren::parse_managed_agent_approval_policy(approval_policy.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let model_policy = seren::parse_managed_agent_model_policy(model_policy.as_deref())
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let capability_policy = parse_capability_policy(params.capability_policy)?;
    let mode: seren::CloudDeploymentMode =
        serde_json::from_value(serde_json::json!(params.mode))
            .map_err(|e| McpError::invalid_params(format!("Invalid mode: {e}"), None))?;
    let compute_backend = params
        .compute_backend
        .map(|value| serde_json::from_value(serde_json::json!(value)))
        .transpose()
        .map_err(|e| McpError::invalid_params(format!("Invalid compute_backend: {e}"), None))?;
    let eval_gate = match (params.eval_gate_set_id, params.eval_gate_max_age_seconds) {
        (Some(set_id), Some(max_age_seconds)) => Some(seren::EvalGate {
            block_on_failure: None,
            drift_baseline: None,
            max_age_seconds,
            schedule: None,
            set_id,
        }),
        (None, None) => None,
        (Some(_), None) => {
            return Err(McpError::invalid_params(
                "eval_gate_max_age_seconds is required with eval_gate_set_id.",
                None,
            ));
        }
        (None, Some(_)) => {
            return Err(McpError::invalid_params(
                "eval_gate_set_id is required with eval_gate_max_age_seconds.",
                None,
            ));
        }
    };
    let requirements = params
        .requirements
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| {
            McpError::invalid_params(format!("Invalid requirements payload: {e}"), None)
        })?;

    Ok(seren::AgentSpec {
        agent_identity_id: None,
        agent_slug: params.agent_slug,
        alert_policy: None,
        allowed_remote_agent_origins: params.allowed_remote_agent_origins,
        approval_policy,
        credentials: None,
        cron_schedule: params.cron_schedule,
        cron_timezone: params.cron_timezone,
        dashboard_config: params.dashboard_config,
        eval_gate,
        guardrails: None,
        memory_policy: Some(default_employee_memory_policy()?),
        capability_policy: Some(capability_policy.unwrap_or(default_employee_capability_policy()?)),
        mode,
        model_policy,
        name: Some(params.name),
        private_output_policy: None,
        runtime_policy: None,
        secret_resolution_delegation: None,
        session_database: None,
        template,
        tool_presets,
        tool_refs: params.tool_refs,
        visibility: params.visibility,
        workload: seren::WorkloadSpec {
            compute_backend,
            config: params.config,
            execution: seren::WorkloadExecution::Llm {
                adapter: None,
                bundle: bundle_for_prompt(params.prompt),
                fallback_models: params.fallback_models,
                llm_connection: None,
                model_config: params.model_config,
                model_id: params.model_id,
                tool_definitions: None,
            },
            external_databases: Vec::new(),
            limits: Some(seren::WorkloadLimits {
                context_budget_tokens: None,
                max_iterations: None,
                max_timeout_seconds: params.max_timeout_seconds,
                max_tool_calls_per_run: None,
                max_tool_output_chars: None,
            }),
            network_policy: None,
            publisher_only: None,
            requirements: Some(requirements.unwrap_or_default()),
            secrets: params.secrets,
            side_effect_policy: None,
        },
    })
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEnvironmentIdParams {
    /// Environment UUID
    pub environment_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateCloudEnvironmentParams {
    /// Environment display name
    pub name: String,
    /// Docker image reference
    pub docker_image: String,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// Setup command list executed before agent entrypoint
    #[serde(default)]
    pub setup_commands: Option<Vec<String>>,
    /// Mark this environment as default
    #[serde(default)]
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateCloudEnvironmentParams {
    /// Environment UUID
    pub environment_id: Uuid,
    /// New display name
    #[serde(default)]
    pub name: Option<String>,
    /// New description
    #[serde(default)]
    pub description: Option<String>,
    /// New Docker image reference
    #[serde(default)]
    pub docker_image: Option<String>,
    /// Replacement setup command list
    #[serde(default)]
    pub setup_commands: Option<Vec<String>>,
    /// Set/unset default environment
    #[serde(default)]
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudDeploymentIdParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudRunAgentParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Optional message payload for orchestrated/always_on agents
    #[serde(default)]
    pub message: Option<String>,
    /// Optional run identifier (useful for resumable orchestrations)
    #[serde(default)]
    pub run_id: Option<String>,
    /// Optional full JSON request body forwarded to the run endpoint
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    /// Request async execution for always_on deployments
    #[serde(default, rename = "async")]
    pub async_run: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudDeploymentRunParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Run event UUID
    pub run_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAuditQueryParams {
    /// Filter by exact audit action
    #[serde(default)]
    pub action: Option<String>,
    /// Maximum audit entries to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Case-insensitive search across action, actor, and details
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudRunAuditParams {
    /// Run event UUID
    pub run_id: Uuid,
    /// Filter by exact audit action
    #[serde(default)]
    pub action: Option<String>,
    /// Maximum audit entries to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Case-insensitive search across action, actor, and details
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAuditEntryParams {
    /// Audit entry UUID
    pub entry_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAuditVerifyParams {
    /// Maximum audit entries to verify
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudDeploymentAuditParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Filter by exact audit action
    #[serde(default)]
    pub action: Option<String>,
    /// Maximum audit entries to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Case-insensitive search across action, actor, and details
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudRunEventsParams {
    /// Run event UUID
    pub run_id: Uuid,
    /// Filter by tool/output item ID
    #[serde(default)]
    pub item_id: Option<String>,
    /// Filter by event kind
    #[serde(default)]
    pub kind: Option<String>,
    /// Maximum events to return
    #[serde(default = "default_cloud_events_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Case-insensitive search across event type, kind, item ID, and payload
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudDeploymentRunEventsParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Run event UUID
    pub run_id: Uuid,
    /// Filter by tool/output item ID
    #[serde(default)]
    pub item_id: Option<String>,
    /// Filter by event kind
    #[serde(default)]
    pub kind: Option<String>,
    /// Maximum events to return
    #[serde(default = "default_cloud_events_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
    /// Case-insensitive search across event type, kind, item ID, and payload
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudConversationsParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Maximum conversations to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Opaque keyset cursor returned by a previous page
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudConversationMessagesParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Durable conversation ID
    pub conversation_id: String,
    /// Maximum messages to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Opaque keyset cursor returned by a previous page
    #[serde(default)]
    pub cursor: Option<String>,
    /// Message page order: asc or desc
    #[serde(default)]
    pub order: Option<String>,
    /// Include full run records for run-backed messages
    #[serde(default)]
    pub include_run: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudRunIdParams {
    /// Run event UUID
    pub run_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudRunStateParams {
    /// Optional deployment UUID for deployment-scoped lookup
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
    /// Run event UUID
    pub run_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAgentSchedulesParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Maximum schedules to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Pagination offset
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateCloudAgentScheduleParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Stable idempotency key for this schedule
    #[serde(default)]
    pub schedule_key: Option<String>,
    /// User-facing message payload for the future run
    #[serde(default)]
    pub message: Option<String>,
    /// Optional structured JSON payload for the future run
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    /// Durable conversation ID to continue when the schedule fires
    #[serde(default)]
    pub conversation_id: Option<String>,
    /// RFC3339 timestamp for a one-shot future run
    #[serde(default)]
    pub run_at: Option<String>,
    /// Relative delay in seconds for a one-shot future run
    #[serde(default)]
    pub delay_seconds: Option<i64>,
    /// Cron expression for a recurring future run
    #[serde(default)]
    pub cron: Option<String>,
    /// Timezone for cron schedules
    #[serde(default)]
    pub timezone: Option<String>,
    /// Maximum worker retry attempts
    #[serde(default)]
    pub max_attempts: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CancelCloudAgentScheduleParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Schedule UUID
    pub schedule_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudPendingApprovalsParams {
    /// Maximum awaiting-approval runs to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudOverviewParams {
    /// Maximum recent runs to include
    #[serde(default = "default_cloud_overview_limit")]
    pub runs_limit: i64,
    /// Maximum pending-approval runs to include
    #[serde(default = "default_cloud_overview_limit")]
    pub approvals_limit: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudDeploymentPendingApprovalsParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Maximum awaiting-approval runs to return
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CompareCloudRunsParams {
    /// Baseline run event UUID
    pub baseline_run_id: Uuid,
    /// Candidate run event UUID
    pub candidate_run_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalSetsParams {
    /// Optional deployment UUID scope
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
    /// Maximum eval sets to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateCloudEvalSetParams {
    /// Eval set name
    pub name: String,
    /// Optional deployment UUID scope
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
    /// Optional description
    #[serde(default)]
    pub description: Option<String>,
    /// Optional eval criteria JSON object
    #[serde(default)]
    pub criteria: Option<serde_json::Value>,
    /// Optional metadata JSON object
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Optional cron schedule for automatically running the eval set
    #[serde(default)]
    pub schedule_cron: Option<String>,
    /// Optional timezone for the scheduled eval cron expression
    #[serde(default)]
    pub schedule_timezone: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalSetIdParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateCloudEvalSetParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Updated eval set name
    #[serde(default)]
    pub name: Option<String>,
    /// Updated deployment UUID scope
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
    /// Remove deployment scoping from the eval set
    #[serde(default)]
    pub clear_deployment: bool,
    /// Updated description (empty string clears it)
    #[serde(default)]
    pub description: Option<String>,
    /// Updated eval criteria JSON object
    #[serde(default)]
    pub criteria: Option<serde_json::Value>,
    /// Updated metadata JSON object
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// Updated cron schedule for automatically running the eval set
    #[serde(default)]
    pub schedule_cron: Option<String>,
    /// Updated timezone for the scheduled eval cron expression
    #[serde(default)]
    pub schedule_timezone: Option<String>,
    /// Disable scheduled execution for this eval set
    #[serde(default)]
    pub clear_schedule: bool,
}

fn build_cloud_eval_set_schedule_request(
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
) -> Result<Option<seren::CloudEvalSetScheduleRequest>, McpError> {
    seren::build_cloud_eval_set_schedule_request(schedule_cron, schedule_timezone)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))
}

fn resolve_cloud_eval_set_schedule_request(
    eval_set: &seren::CloudEvalSet,
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
    clear_schedule: bool,
) -> Result<Option<seren::CloudEvalSetScheduleRequest>, McpError> {
    seren::resolve_cloud_eval_set_schedule_request(
        eval_set,
        schedule_cron,
        schedule_timezone,
        clear_schedule,
    )
    .map_err(|e| McpError::invalid_params(e.to_string(), None))
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalCasesParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Maximum eval cases to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalCaseIdParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Eval case UUID
    pub case_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PromoteCloudRunToEvalCaseParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Source run event UUID
    pub run_id: Uuid,
    /// Optional eval case name override
    #[serde(default)]
    pub name: Option<String>,
    /// Optional metadata JSON object merged onto the generated case metadata
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateCloudEvalRunParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Optional deployment override when the eval set is not deployment-scoped
    #[serde(default)]
    pub deployment_id: Option<Uuid>,
    /// Optional metadata JSON object
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalRunsParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Maximum eval runs to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalRunIdParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Eval run UUID
    pub eval_run_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalRunResultsParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Eval run UUID
    pub eval_run_id: Uuid,
    /// Maximum results to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudEvalCaseResultIdParams {
    /// Eval set UUID
    pub eval_set_id: Uuid,
    /// Eval run UUID
    pub eval_run_id: Uuid,
    /// Eval case UUID
    pub case_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAgentRunsParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// Maximum runs to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
    /// Filter by status (repeat or comma-separate values)
    #[serde(default)]
    pub status: Vec<String>,
    /// Filter by compute backend
    #[serde(default)]
    pub compute_backend: Option<String>,
    /// Filter by run source (api, cli, scheduler, ui, system, unknown)
    #[serde(default)]
    pub source: Option<String>,
    /// Filter by artifact existence
    #[serde(default)]
    pub has_artifacts: Option<bool>,
    /// Filter runs with started_at >= RFC3339 timestamp
    #[serde(default)]
    pub started_after: Option<String>,
    /// Filter runs with started_at <= RFC3339 timestamp
    #[serde(default)]
    pub started_before: Option<String>,
    /// Search query across execution ID/status/output/metadata
    #[serde(default)]
    pub q: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudAllRunsParams {
    /// Maximum runs to return (default 50)
    #[serde(default = "default_cloud_runs_limit")]
    pub limit: i64,
    /// Offset for pagination (default 0)
    #[serde(default)]
    pub offset: i64,
    /// Filter by status (repeat or comma-separate values)
    #[serde(default)]
    pub status: Vec<String>,
    /// Filter by compute backend
    #[serde(default)]
    pub compute_backend: Option<String>,
    /// Filter by run source (api, cli, scheduler, ui, system, unknown)
    #[serde(default)]
    pub source: Option<String>,
    /// Filter by artifact existence
    #[serde(default)]
    pub has_artifacts: Option<bool>,
    /// Filter runs with started_at >= RFC3339 timestamp
    #[serde(default)]
    pub started_after: Option<String>,
    /// Filter runs with started_at <= RFC3339 timestamp
    #[serde(default)]
    pub started_before: Option<String>,
    /// Search query across execution ID/status/output/metadata
    #[serde(default)]
    pub q: Option<String>,
}

fn default_cloud_runs_limit() -> i64 {
    50
}

fn default_cloud_events_limit() -> i64 {
    100
}

fn default_cloud_overview_limit() -> i64 {
    8
}

fn parse_conversation_message_order(
    value: Option<&str>,
) -> Result<Option<seren::ConversationMessageOrder>, McpError> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("asc") => Ok(Some(seren::ConversationMessageOrder::Asc)),
        Some("desc") => Ok(Some(seren::ConversationMessageOrder::Desc)),
        Some(other) => Err(McpError::invalid_params(
            format!("Invalid order '{other}'. Expected asc or desc."),
            None,
        )),
        None => Ok(None),
    }
}

fn parse_optional_timestamp(
    value: Option<&str>,
    field_name: &str,
) -> Result<Option<jiff::Timestamp>, McpError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(jiff::Timestamp::from_str)
        .transpose()
        .map_err(|e| McpError::invalid_params(format!("Invalid {field_name}: {e}"), None))
}

fn build_deployment_name_map(deployments: &[serde_json::Value]) -> HashMap<String, String> {
    deployments
        .iter()
        .filter_map(|deployment| {
            let deployment_id = deployment.get("id").and_then(|value| value.as_str())?;
            let deployment_name = deployment
                .get("name")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    deployment
                        .get("skill_slug")
                        .and_then(|value| value.as_str())
                })
                .unwrap_or(deployment_id);
            Some((deployment_id.to_string(), deployment_name.to_string()))
        })
        .collect()
}

fn enrich_with_deployment_name(
    entries: &[serde_json::Value],
    deployment_names: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            if let Some(object) = entry.as_object_mut()
                && let Some(deployment_id) =
                    object.get("deployment_id").and_then(|value| value.as_str())
                && let Some(name) = deployment_names.get(deployment_id)
            {
                object.insert(
                    "deployment_name".to_string(),
                    serde_json::Value::String(name.clone()),
                );
            }
            entry
        })
        .collect()
}

fn enrich_data_envelope_with_deployment_names(
    envelope: &serde_json::Value,
    deployment_names: &HashMap<String, String>,
) -> serde_json::Value {
    let mut envelope = envelope.clone();
    if let Some(object) = envelope.as_object_mut()
        && let Some(entries) = object.get("data").and_then(|value| value.as_array())
    {
        object.insert(
            "data".to_string(),
            serde_json::Value::Array(enrich_with_deployment_name(entries, deployment_names)),
        );
    }
    envelope
}

fn build_cloud_run_body(
    message: Option<&str>,
    run_id: Option<&str>,
    payload: Option<&serde_json::Value>,
    async_run: Option<bool>,
) -> Result<Option<serde_json::Value>, McpError> {
    let mut body = payload.cloned();

    if let Some(message) = message {
        let message = message.trim();
        if message.is_empty() {
            return Err(McpError::invalid_params("message must not be empty", None));
        }

        match body.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("message".to_string(), serde_json::json!(message));
            }
            Some(_) => {
                return Err(McpError::invalid_params(
                    "payload must be a JSON object when message is provided",
                    None,
                ));
            }
            None => {
                body = Some(serde_json::json!({ "message": message }));
            }
        }
    }

    if let Some(run_id) = run_id.map(str::trim).filter(|v| !v.is_empty()) {
        match body.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("run_id".to_string(), serde_json::json!(run_id));
            }
            Some(_) => {
                return Err(McpError::invalid_params(
                    "payload must be a JSON object when run_id is provided",
                    None,
                ));
            }
            None => {
                body = Some(serde_json::json!({ "run_id": run_id }));
            }
        }
    }

    if let Some(async_run) = async_run {
        match body.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("async".to_string(), serde_json::Value::Bool(async_run));
            }
            Some(_) => {
                return Err(McpError::invalid_params(
                    "payload must be a JSON object when async is provided",
                    None,
                ));
            }
            None => {
                body = Some(serde_json::json!({ "async": async_run }));
            }
        }
    }

    Ok(body)
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloudUpdateConfigParams {
    /// Deployment UUID
    pub deployment_id: Uuid,
    /// JSON config object to update
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// JSON secrets object (key-value pairs) to update
    #[serde(default)]
    pub secrets: Option<serde_json::Value>,
    /// Optional alert webhook policy JSON object
    #[serde(default)]
    pub alert_policy: Option<serde_json::Value>,
    /// Remove the deployment alert policy
    #[serde(default)]
    pub clear_alert_policy: bool,
    /// Optional network policy JSON object
    #[serde(default)]
    pub network_policy: Option<serde_json::Value>,
    /// Remove the deployment network policy
    #[serde(default)]
    pub clear_network_policy: bool,
    /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
    #[serde(default)]
    pub eval_gate_set_id: Option<Uuid>,
    /// Freshness window in seconds for the eval gate (required with eval_gate_set_id)
    #[serde(default)]
    pub eval_gate_max_age_seconds: Option<i32>,
    /// Remove the eval gate from the deployment
    #[serde(default)]
    pub clear_eval_gate: bool,
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

pub(crate) fn json_content<T: Serialize>(data: &T) -> Result<Content, McpError> {
    let text = serde_json::to_string_pretty(data)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(Content::text(text))
}

fn text_and_json_content<T: Serialize>(text: String, data: &T) -> Result<Vec<Content>, McpError> {
    Ok(vec![Content::text(text), json_content(data)?])
}

fn cloud_run_state_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let state = envelope.get("data").unwrap_or(&envelope);
    if !state.is_object() {
        return Ok("Run state is unavailable.".to_string());
    }

    let mut parts = Vec::new();
    if let Some(run_id) = json_string_field(state, "run_id") {
        parts.push(format!("run={run_id}"));
    }
    if let Some(status) = json_string_field(state, "status") {
        parts.push(format!("status={status}"));
    }
    if let Some(phase) = json_string_field(state, "phase") {
        parts.push(format!("phase={phase}"));
    }
    if let Some(step) = json_string_field(state, "current_step") {
        parts.push(format!("step={step}"));
    }
    if let Some(tool) = json_string_field(state, "current_tool") {
        parts.push(format!("tool={tool}"));
    }
    if let Some(approvals) = json_scalar_field(state, "pending_approval_count") {
        parts.push(format!("pending_approvals={approvals}"));
    }
    if let Some(checkpoint_id) = json_string_field(state, "checkpoint_id") {
        parts.push(format!("checkpoint={checkpoint_id}"));
    }
    if let Some(sequence) = json_scalar_field(state, "latest_sequence") {
        parts.push(format!("latest_sequence={sequence}"));
    }
    if let Some(kind) = json_string_field(state, "latest_event_kind") {
        parts.push(format!("latest_event={kind}"));
    }
    if let Some(terminal) = json_scalar_field(state, "terminal") {
        parts.push(format!("terminal={terminal}"));
    }
    if let Some(message) = json_string_field(state, "status_message") {
        parts.push(format!(
            "message={}",
            truncate_for_client(message.as_str(), 180)
        ));
    }

    if parts.is_empty() {
        Ok("Run state is available.".to_string())
    } else {
        Ok(format!("Run state: {}", parts.join(" ")))
    }
}

fn pending_cloud_approvals_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let runs = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if runs.is_empty() {
        return Ok("No runs are currently awaiting approval.".to_string());
    }

    let mut lines = vec![format!("{} run(s) awaiting approval:", runs.len())];
    for run in runs.iter().take(8) {
        lines.push(format!("- {}", format_pending_approval_run_summary(run)));
    }
    if runs.len() > 8 {
        lines.push(format!("- {} more run(s)", runs.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn cloud_runs_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let runs = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if runs.is_empty() {
        return Ok("No cloud runs found.".to_string());
    }

    let mut lines = vec![format!("{} cloud run(s):", runs.len())];
    for run in runs.iter().take(8) {
        lines.push(format!("- {}", format_cloud_run_summary(run)));
    }
    if runs.len() > 8 {
        lines.push(format!("- {} more run(s)", runs.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn cloud_run_summary<T: Serialize>(response: &T, title: &str) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let run = envelope.get("data").unwrap_or(&envelope);
    if !run.is_object() {
        return Ok(format!("{title}: unavailable."));
    }

    let summary = format_cloud_run_summary(run);
    if summary.is_empty() {
        Ok(format!("{title}: available."))
    } else {
        Ok(format!("{title}: {summary}"))
    }
}

fn format_cloud_run_summary(run: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(run_id) = json_string_field(run, "run_id").or_else(|| json_string_field(run, "id"))
    {
        parts.push(format!("run={run_id}"));
    }
    if let Some(deployment) = json_string_field(run, "deployment_name")
        .or_else(|| json_string_field(run, "deployment_id"))
    {
        parts.push(format!("deployment={deployment}"));
    }
    if let Some(status) = json_string_field(run, "status") {
        parts.push(format!("status={status}"));
    }
    if let Some(source) = json_string_field(run, "source") {
        parts.push(format!("source={source}"));
    }
    if let Some(created_at) = json_string_field(run, "created_at") {
        parts.push(format!("created={created_at}"));
    } else if let Some(started_at) = json_string_field(run, "started_at") {
        parts.push(format!("started={started_at}"));
    }
    if let Some(model) = json_string_field(run, "model_id") {
        parts.push(format!("model={model}"));
    }
    if let Some(sequence) = json_scalar_field(run, "latest_sequence") {
        parts.push(format!("latest_sequence={sequence}"));
    }
    if let Some(approvals) = run
        .get("pending_approvals")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .filter(|count| *count > 0)
    {
        parts.push(format!("pending_approvals={approvals}"));
    }
    if let Some(error) = json_string_field(run, "error") {
        parts.push(format!(
            "error={}",
            truncate_for_client(&compact_text(&error), 160)
        ));
    }
    parts.join(" ")
}

fn cloud_agents_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let deployments = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if deployments.is_empty() {
        return Ok("No cloud agent deployments found.".to_string());
    }

    let mut lines = vec![format!("{} cloud agent deployment(s):", deployments.len())];
    for deployment in deployments.iter().take(8) {
        lines.push(format!("- {}", format_cloud_agent_summary(deployment)));
    }
    if deployments.len() > 8 {
        lines.push(format!("- {} more deployment(s)", deployments.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn cloud_agent_summary<T: Serialize>(response: &T, title: &str) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let deployment = envelope.get("data").unwrap_or(&envelope);
    if !deployment.is_object() {
        return Ok(format!("{title}: unavailable."));
    }

    let summary = format_cloud_agent_summary(deployment);
    if summary.is_empty() {
        Ok(format!("{title}: available."))
    } else {
        Ok(format!("{title}: {summary}"))
    }
}

fn cloud_overview_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let payload = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let summary = payload
        .get("summary")
        .or_else(|| payload.get("data").and_then(|data| data.get("summary")));
    let Some(summary) = summary else {
        return Ok("Cloud overview is available.".to_string());
    };

    let mut parts = Vec::new();
    if let Some(count) = json_scalar_field(summary, "deployment_count") {
        parts.push(format!("deployments={count}"));
    }
    if let Some(count) = json_scalar_field(summary, "running_count") {
        parts.push(format!("running={count}"));
    }
    if let Some(count) = json_scalar_field(summary, "managed_count") {
        parts.push(format!("managed={count}"));
    }
    if let Some(count) = json_scalar_field(summary, "cron_count") {
        parts.push(format!("cron={count}"));
    }
    if let Some(count) = json_scalar_field(summary, "recent_runs_loaded") {
        parts.push(format!("recent_runs={count}"));
    }
    if let Some(count) = json_scalar_field(summary, "pending_approvals_loaded") {
        parts.push(format!("pending_approvals={count}"));
    }

    if parts.is_empty() {
        Ok("Cloud overview is available.".to_string())
    } else {
        Ok(format!("Cloud overview: {}", parts.join(" ")))
    }
}

fn cloud_deployment_spend_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let spend = envelope.get("data").unwrap_or(&envelope);
    if !spend.is_object() {
        return Ok("Deployment spend is unavailable.".to_string());
    }

    let mut parts = Vec::new();
    if let Some(total) = json_scalar_field(spend, "total_cost_usd") {
        parts.push(format!("total_usd={total}"));
    }
    if let Some(compute) = json_scalar_field(spend, "compute_cost_usd") {
        parts.push(format!("compute_usd={compute}"));
    }
    if let Some(inference) = json_scalar_field(spend, "inference_cost_usd") {
        parts.push(format!("inference_usd={inference}"));
    }
    if let Some(runs) = json_scalar_field(spend, "run_count") {
        parts.push(format!("runs={runs}"));
    }
    if let Some(first_event) = json_string_field(spend, "first_event_at") {
        parts.push(format!("first={first_event}"));
    }
    if let Some(last_event) = json_string_field(spend, "last_event_at") {
        parts.push(format!("last={last_event}"));
    }

    if parts.is_empty() {
        Ok("Deployment spend is available.".to_string())
    } else {
        Ok(format!("Deployment spend: {}", parts.join(" ")))
    }
}

fn cloud_audit_entries_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let entries = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if entries.is_empty() {
        return Ok("No cloud audit entries found.".to_string());
    }

    let mut lines = vec![format!("{} cloud audit entry(s):", entries.len())];
    for entry in entries.iter().take(8) {
        lines.push(format!("- {}", format_cloud_audit_entry_summary(entry)));
    }
    if entries.len() > 8 {
        lines.push(format!("- {} more audit entry(s)", entries.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn cloud_audit_entry_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let entry = envelope.get("data").unwrap_or(&envelope);
    if !entry.is_object() {
        return Ok("Cloud audit entry is unavailable.".to_string());
    }

    let summary = format_cloud_audit_entry_summary(entry);
    if summary.is_empty() {
        Ok("Cloud audit entry is available.".to_string())
    } else {
        Ok(format!("Cloud audit entry: {summary}"))
    }
}

fn cloud_audit_verify_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let result = envelope.get("data").unwrap_or(&envelope);
    if !result.is_object() {
        return Ok("Cloud audit verification is unavailable.".to_string());
    }

    let mut parts = Vec::new();
    if let Some(verified) = json_scalar_field(result, "verified") {
        parts.push(format!("verified={verified}"));
    }
    if let Some(entries_checked) = json_scalar_field(result, "entries_checked") {
        parts.push(format!("entries_checked={entries_checked}"));
    }
    if let Some(sequence) = json_scalar_field(result, "first_invalid_sequence") {
        parts.push(format!("first_invalid_sequence={sequence}"));
    }
    if let Some(error) = json_string_field(result, "error") {
        parts.push(format!(
            "error={}",
            truncate_for_client(&compact_text(&error), 160)
        ));
    }

    if parts.is_empty() {
        Ok("Cloud audit verification is available.".to_string())
    } else {
        Ok(format!("Cloud audit verification: {}", parts.join(" ")))
    }
}

fn format_cloud_audit_entry_summary(entry: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(sequence) = json_scalar_field(entry, "sequence_number") {
        parts.push(format!("#{sequence}"));
    }
    if let Some(action) = json_string_field(entry, "action") {
        parts.push(format!("action={action}"));
    }
    if let Some(actor) = json_string_field(entry, "actor") {
        parts.push(format!("actor={actor}"));
    }
    if let Some(id) = json_string_field(entry, "id") {
        parts.push(format!("id={id}"));
    }
    if let Some(invocation_id) = json_string_field(entry, "invocation_id") {
        parts.push(format!("invocation={invocation_id}"));
    }
    if let Some(publisher_id) = json_string_field(entry, "publisher_id") {
        parts.push(format!("publisher={publisher_id}"));
    }
    if let Some(created_at) = json_string_field(entry, "created_at") {
        parts.push(format!("created={created_at}"));
    }
    parts.join(" ")
}

fn format_cloud_agent_summary(deployment: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(name) = json_string_field(deployment, "name") {
        parts.push(format!(
            "name={}",
            truncate_for_client(&compact_text(&name), 80)
        ));
    }
    if let Some(id) = json_string_field(deployment, "id")
        .or_else(|| json_string_field(deployment, "deployment_id"))
    {
        parts.push(format!("id={id}"));
    }
    if let Some(status) = json_string_field(deployment, "status") {
        parts.push(format!("status={status}"));
    }
    if let Some(mode) = json_string_field(deployment, "mode") {
        parts.push(format!("mode={mode}"));
    }
    if let Some(backend) = json_string_field(deployment, "compute_backend") {
        parts.push(format!("backend={backend}"));
    }
    if let Some(model) = deployment
        .get("managed_agent")
        .and_then(|agent| json_string_field(agent, "model_id"))
        .or_else(|| json_string_field(deployment, "model_id"))
    {
        parts.push(format!("model={model}"));
    }
    if let Some(updated_at) = json_string_field(deployment, "updated_at") {
        parts.push(format!("updated={updated_at}"));
    }
    parts.join(" ")
}

fn cloud_run_artifacts_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let artifacts = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if artifacts.is_empty() {
        return Ok("No run artifacts found.".to_string());
    }

    let mut lines = vec![format!("{} run artifact(s):", artifacts.len())];
    for artifact in artifacts.iter().take(8) {
        lines.push(format!("- {}", format_cloud_run_artifact_summary(artifact)));
    }
    if artifacts.len() > 8 {
        lines.push(format!("- {} more artifact(s)", artifacts.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn format_cloud_run_artifact_summary(artifact: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(id) = json_string_field(artifact, "id") {
        parts.push(format!("id={id}"));
    }
    if let Some(artifact_type) = json_string_field(artifact, "artifact_type") {
        parts.push(format!("type={artifact_type}"));
    }
    if let Some(title) = json_string_field(artifact, "title") {
        parts.push(format!(
            "title={}",
            truncate_for_client(&compact_text(&title), 80)
        ));
    }
    if let Some(url) = json_string_field(artifact, "url") {
        parts.push(format!(
            "url={}",
            truncate_for_client(&compact_text(&url), 120)
        ));
    }
    if let Some(created_at) = json_string_field(artifact, "created_at") {
        parts.push(format!("created={created_at}"));
    }
    parts.join(" ")
}

fn cloud_run_evals_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let data = envelope.get("data").unwrap_or(&envelope);
    if !data.is_object() {
        return Ok("Run eval links are unavailable.".to_string());
    }

    let source_cases = data
        .get("source_eval_cases")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let actual_results = data
        .get("actual_eval_case_results")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut parts = Vec::new();
    if let Some(run_id) = json_string_field(data, "run_id") {
        parts.push(format!("run={run_id}"));
    }
    parts.push(format!("source_eval_cases={}", source_cases.len()));
    parts.push(format!("actual_eval_results={}", actual_results.len()));
    if let Some(first_case) = source_cases.first()
        && let Some(case_id) = json_string_field(first_case, "id")
    {
        parts.push(format!("first_source_case={case_id}"));
    }
    if let Some(first_result) = actual_results.first()
        && let Some(case_id) = json_string_field(first_result, "eval_case_id")
    {
        parts.push(format!("first_result_case={case_id}"));
    }
    if let Some(first_result) = actual_results.first()
        && let Some(status) = json_string_field(first_result, "status")
    {
        parts.push(format!("first_result_status={status}"));
    }

    Ok(format!("Run eval links: {}", parts.join(" ")))
}

fn cloud_agent_schedules_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let schedules = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if schedules.is_empty() {
        return Ok("No agent schedules found.".to_string());
    }

    let mut lines = vec![format!("{} agent schedule(s):", schedules.len())];
    for schedule in schedules.iter().take(8) {
        lines.push(format!(
            "- {}",
            format_cloud_agent_schedule_summary(schedule)
        ));
    }
    if schedules.len() > 8 {
        lines.push(format!("- {} more schedule(s)", schedules.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn cloud_agent_schedule_summary<T: Serialize>(
    response: &T,
    title: &str,
) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let schedule = envelope.get("data").unwrap_or(&envelope);
    if !schedule.is_object() {
        return Ok(format!("{title}: unavailable."));
    }

    let summary = format_cloud_agent_schedule_summary(schedule);
    if summary.is_empty() {
        Ok(format!("{title}: available."))
    } else {
        Ok(format!("{title}: {summary}"))
    }
}

fn format_cloud_agent_schedule_summary(schedule: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(id) = json_string_field(schedule, "id") {
        parts.push(format!("id={id}"));
    }
    if let Some(key) = json_string_field(schedule, "schedule_key") {
        parts.push(format!("key={key}"));
    }
    if let Some(kind) = json_string_field(schedule, "schedule_kind") {
        parts.push(format!("kind={kind}"));
    }
    if let Some(status) = json_string_field(schedule, "status") {
        parts.push(format!("status={status}"));
    }
    if let Some(next_run_at) = json_string_field(schedule, "next_run_at") {
        parts.push(format!("next={next_run_at}"));
    }
    if let Some(cron) = json_string_field(schedule, "cron_schedule") {
        parts.push(format!("cron={cron}"));
    }
    if let Some(timezone) = json_string_field(schedule, "cron_timezone") {
        parts.push(format!("tz={timezone}"));
    }
    let attempts = json_scalar_field(schedule, "attempts");
    let max_attempts = json_scalar_field(schedule, "max_attempts");
    if attempts.is_some() || max_attempts.is_some() {
        parts.push(format!(
            "attempts={}/{}",
            attempts.unwrap_or_else(|| "-".to_string()),
            max_attempts.unwrap_or_else(|| "-".to_string())
        ));
    }
    if let Some(last_error) = json_string_field(schedule, "last_error") {
        parts.push(format!(
            "error={}",
            truncate_for_client(&compact_text(&last_error), 160)
        ));
    }
    parts.join(" ")
}

fn format_pending_approval_run_summary(run: &serde_json::Value) -> String {
    let approvals = run
        .get("pending_approvals")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tools = approval_tool_names(&approvals);
    let mut parts = Vec::new();
    if let Some(run_id) = json_string_field(run, "run_id").or_else(|| json_string_field(run, "id"))
    {
        parts.push(format!("run={run_id}"));
    }
    if let Some(deployment) = json_string_field(run, "deployment_name")
        .or_else(|| json_string_field(run, "deployment_id"))
    {
        parts.push(format!("deployment={deployment}"));
    }
    if let Some(status) = json_string_field(run, "status") {
        parts.push(format!("status={status}"));
    }
    parts.push(format!("pending_approvals={}", approvals.len()));
    if !tools.is_empty() {
        parts.push(format!("tools={}", truncate_for_client(&tools, 120)));
    }
    parts.join(" ")
}

fn run_pending_approvals_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let run = envelope.get("data").unwrap_or(&envelope);
    if !run.is_object() {
        return Ok("Pending approval state is unavailable.".to_string());
    }

    let approvals = run
        .get("pending_approvals")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let tools = approval_tool_names(&approvals);
    let mut parts = Vec::new();
    if let Some(run_id) = json_string_field(run, "run_id").or_else(|| json_string_field(run, "id"))
    {
        parts.push(format!("run={run_id}"));
    }
    if let Some(status) = json_string_field(run, "status") {
        parts.push(format!("status={status}"));
    }
    if let Some(checkpoint_id) = json_string_field(run, "checkpoint_id") {
        parts.push(format!("checkpoint={checkpoint_id}"));
    }
    parts.push(format!("pending_approvals={}", approvals.len()));
    if !tools.is_empty() {
        parts.push(format!("tools={}", truncate_for_client(&tools, 120)));
    }

    if approvals.is_empty() {
        Ok(format!(
            "No pending approvals for this run{}.",
            parts
                .first()
                .map(|run| format!(" ({run})"))
                .unwrap_or_default()
        ))
    } else {
        Ok(format!("Pending approval state: {}", parts.join(" ")))
    }
}

fn approval_tool_names(approvals: &[serde_json::Value]) -> String {
    approvals
        .iter()
        .filter_map(|approval| approval.get("tool").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>()
        .join(", ")
}

fn cloud_conversations_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let data = envelope.get("data").unwrap_or(&envelope);
    let conversations = data
        .get("conversations")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if conversations.is_empty() {
        return Ok("No employee conversations found.".to_string());
    }

    let mut lines = vec![format!("{} employee conversation(s):", conversations.len())];
    for conversation in conversations.iter().take(8) {
        lines.push(format!(
            "- {}",
            format_cloud_conversation_summary(conversation)
        ));
    }
    if conversations.len() > 8 {
        lines.push(format!(
            "- {} more conversation(s)",
            conversations.len() - 8
        ));
    }
    if let Some(cursor) = data
        .get("next_cursor")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("next_cursor={cursor}"));
    }
    Ok(lines.join("\n"))
}

fn format_cloud_conversation_summary(conversation: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(conversation_id) = json_string_field(conversation, "conversation_id") {
        parts.push(format!("id={conversation_id}"));
    }
    if let Some(title) = json_string_field(conversation, "title") {
        parts.push(format!(
            "title={}",
            truncate_for_client(&compact_text(&title), 80)
        ));
    }
    if let Some(count) = json_scalar_field(conversation, "message_count") {
        parts.push(format!("messages={count}"));
    }
    if let Some(source) = json_string_field(conversation, "last_source") {
        parts.push(format!("source={source}"));
    }
    if let Some(last_activity) = json_string_field(conversation, "last_activity_at") {
        parts.push(format!("last={last_activity}"));
    }
    parts.join(" ")
}

fn cloud_conversation_messages_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let data = envelope.get("data").unwrap_or(&envelope);
    let messages = data
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if messages.is_empty() {
        return Ok("No employee conversation messages found.".to_string());
    }

    let mut lines = vec![format!("{} conversation message(s):", messages.len())];
    for message in messages.iter().take(8) {
        lines.push(format!(
            "- {}",
            format_cloud_conversation_message_summary(message)
        ));
    }
    if messages.len() > 8 {
        lines.push(format!("- {} more message(s)", messages.len() - 8));
    }
    if let Some(cursor) = data
        .get("next_cursor")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("next_cursor={cursor}"));
    }
    Ok(lines.join("\n"))
}

fn format_cloud_conversation_message_summary(message: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(created_at) = json_string_field(message, "created_at") {
        parts.push(created_at);
    }
    if let Some(role) = json_string_field(message, "role") {
        parts.push(format!("role={role}"));
    }
    if let Some(source) = json_string_field(message, "source") {
        parts.push(format!("source={source}"));
    }
    if let Some(run_id) = json_string_field(message, "run_id").or_else(|| {
        message
            .get("run_summary")
            .and_then(|summary| json_string_field(summary, "run_id"))
    }) {
        parts.push(format!("run={run_id}"));
    }
    if let Some(status) = message
        .get("run_summary")
        .and_then(|summary| json_string_field(summary, "status"))
        .or_else(|| {
            message
                .get("run")
                .and_then(|run| json_string_field(run, "status"))
        })
    {
        parts.push(format!("status={status}"));
    }
    if let Some(events) = message.get("events").and_then(serde_json::Value::as_array)
        && !events.is_empty()
    {
        parts.push(format!("events={}", events.len()));
    }
    if let Some(content) = json_string_field(message, "content") {
        parts.push(format!(
            "content={}",
            truncate_for_client(&compact_text(&content), 180)
        ));
    }
    parts.join(" ")
}

fn compact_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn cloud_run_events_summary<T: Serialize>(response: &T) -> Result<String, McpError> {
    let envelope = serde_json::to_value(response)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let events = envelope
        .get("data")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if events.is_empty() {
        return Ok("No run events found.".to_string());
    }

    let mut lines = vec![format!("{} run event(s):", events.len())];
    for event in events.iter().take(8) {
        lines.push(format!("- {}", format_cloud_run_event_summary(event)));
    }
    if events.len() > 8 {
        lines.push(format!("- {} more event(s)", events.len() - 8));
    }
    Ok(lines.join("\n"))
}

fn format_cloud_run_event_summary(envelope: &serde_json::Value) -> String {
    let event = envelope.get("event").unwrap_or(&serde_json::Value::Null);
    let sequence = json_scalar_field(envelope, "sequence_number");
    let kind = json_string_field(envelope, "kind")
        .or_else(|| json_string_field(envelope, "event_type"))
        .unwrap_or_else(|| "event".to_string());
    let mut parts = Vec::new();
    if let Some(sequence) = sequence {
        parts.push(format!("#{sequence}"));
    }
    parts.push(kind);
    if let Some(id) =
        json_string_field(event, "id").or_else(|| json_string_field(envelope, "item_id"))
    {
        parts.push(format!("id={id}"));
    }
    if let Some(tool) = json_string_field(event, "name") {
        parts.push(format!("tool={tool}"));
    }
    if let Some(code) = json_string_field(event, "code") {
        parts.push(format!("code={code}"));
    }
    if event
        .get("retryable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        parts.push("retryable=true".to_string());
    }
    if let Some(summary) = summarize_cloud_run_event_payload(event) {
        parts.push(format!("summary={}", truncate_for_client(&summary, 180)));
    }
    parts.join(" ")
}

fn summarize_cloud_run_event_payload(event: &serde_json::Value) -> Option<String> {
    for key in ["message", "text", "content", "reason"] {
        if let Some(value) = event.get(key).and_then(json_value_to_string) {
            return Some(value);
        }
    }
    event.get("details").and_then(json_value_to_string)
}

fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_scalar_field(value: &serde_json::Value, key: &str) -> Option<String> {
    match value.get(key)? {
        serde_json::Value::String(text) => {
            let text = text.trim();
            if text.is_empty() {
                None
            } else {
                Some(text.to_string())
            }
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        serde_json::Value::Array(items) => {
            let rendered = items
                .iter()
                .filter_map(json_value_to_string)
                .collect::<Vec<_>>()
                .join(", ");
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
        serde_json::Value::Object(object) => {
            let rendered = object
                .iter()
                .filter_map(|(key, value)| {
                    json_value_to_string(value).map(|value| format!("{key}={value}"))
                })
                .collect::<Vec<_>>()
                .join(", ");
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
    }
}

fn truncate_for_client(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_none() {
        return truncated;
    }

    const SUFFIX: &str = "... (truncated)";
    let suffix_chars = SUFFIX.chars().count();
    if max_chars <= suffix_chars {
        return SUFFIX.chars().take(max_chars).collect();
    }

    let prefix: String = value.chars().take(max_chars - suffix_chars).collect();
    format!("{prefix}{SUFFIX}")
}

fn api_error_message(status: reqwest::StatusCode, body: &str, request_id: Option<&str>) -> String {
    let request_context = request_id
        .map(|value| format!(" (request ID: {value})"))
        .unwrap_or_default();
    if body.is_empty() {
        format!("API error {status}{request_context}")
    } else {
        format!(
            "API error {status}{request_context}: {}",
            truncate_for_client(body, 1200)
        )
    }
}

fn publisher_skill_doc_url(api_base_url: &str, publisher: &str) -> Result<String, McpError> {
    skill_doc_url(api_base_url, &["publishers", publisher, "skill.md"])
}

fn seren_api_skill_doc_url(api_base_url: &str) -> Result<String, McpError> {
    skill_doc_url(api_base_url, &["skill.md"])
}

fn skill_doc_url(api_base_url: &str, segments: &[&str]) -> Result<String, McpError> {
    let mut url = reqwest::Url::parse(api_base_url.trim_end_matches('/'))
        .map_err(|e| McpError::invalid_params(format!("Invalid API base URL: {e}"), None))?;
    url.path_segments_mut()
        .map_err(|_| {
            McpError::invalid_params("API base URL cannot be used for path-based requests", None)
        })?
        .extend(segments);
    Ok(url.to_string())
}

/// Convert a seren SDK error to an MCP error.
pub(crate) async fn seren_error_to_mcp_error<T: std::fmt::Debug>(e: seren::Error<T>) -> McpError {
    match e {
        seren::Error::UnexpectedResponse(response) => {
            let status = response.status();
            let request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let body = response.text().await.unwrap_or_default();
            McpError::internal_error(
                api_error_message(status, &body, request_id.as_deref()),
                Some(serde_json::json!({
                    "kind": "http_error",
                    "status": status.as_u16(),
                    "body": truncate_for_client(&body, 1200),
                    "request_id": request_id,
                })),
            )
        }
        seren::Error::ErrorResponse(resp) => {
            let status = resp.status();
            let request_id = resp
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok());
            let body = format!("{:?}", resp.as_ref());
            McpError::internal_error(
                api_error_message(status, &body, request_id),
                Some(serde_json::json!({
                    "kind": "http_error",
                    "status": status.as_u16(),
                    "body": truncate_for_client(&body, 1200),
                    "request_id": request_id,
                })),
            )
        }
        seren::Error::InvalidRequest(msg) => {
            McpError::invalid_params(format!("Invalid request: {msg}"), None)
        }
        seren::Error::CommunicationError(e) => {
            let message = e.without_url().to_string();
            McpError::internal_error(
                format!("Communication error: {message}"),
                Some(serde_json::json!({
                    "kind": "transport_error",
                    "message": message,
                })),
            )
        }
        seren::Error::InvalidUpgrade(e) => {
            McpError::internal_error(format!("Upgrade error: {}", e.without_url()), None)
        }
        seren::Error::ResponseBodyError(e) => {
            McpError::internal_error(format!("Response body error: {}", e.without_url()), None)
        }
        seren::Error::InvalidResponsePayload(_bytes, e) => {
            McpError::internal_error(format!("Invalid response payload: {e}"), None)
        }
        seren::Error::Custom(msg) => McpError::internal_error(format!("Custom error: {msg}"), None),
    }
}

/// Preserves structured HTTP response details from generated SDK calls.
trait SerenApiFutureExt<T, E>:
    std::future::Future<Output = Result<T, seren::Error<E>>> + Sized
where
    E: std::fmt::Debug,
{
    async fn into_mcp_result(self) -> Result<T, McpError> {
        match self.await {
            Ok(value) => Ok(value),
            Err(error) => Err(seren_error_to_mcp_error(error).await),
        }
    }
}

impl<F, T, E> SerenApiFutureExt<T, E> for F
where
    F: std::future::Future<Output = Result<T, seren::Error<E>>> + Sized,
    E: std::fmt::Debug,
{
}

/// Converts generated SDK results that have already been awaited in parallel.
async fn seren_result_to_mcp<T, E>(result: Result<T, seren::Error<E>>) -> Result<T, McpError>
where
    E: std::fmt::Debug,
{
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(seren_error_to_mcp_error(error).await),
    }
}

pub(crate) fn decode_publisher_gateway_body<T>(bytes: &[u8]) -> Result<T, String>
where
    T: DeserializeOwned,
{
    if let Ok(response) = serde_json::from_slice::<T>(bytes) {
        return Ok(response);
    }

    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON body: {e}"))?;
    let data = value
        .get("data")
        .ok_or_else(|| "missing data field".to_string())?;
    let status = data.get("status").and_then(serde_json::Value::as_u64);
    if status != Some(200) {
        let status_text = status
            .and_then(|value| u16::try_from(value).ok())
            .and_then(|value| reqwest::StatusCode::from_u16(value).ok())
            .map(|value| value.to_string())
            .unwrap_or_else(|| {
                status
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            });
        let body = data
            .get("body")
            .map(|body| match body.as_str() {
                Some(raw) => raw.to_string(),
                None => body.to_string(),
            })
            .unwrap_or_default();
        if body.is_empty() {
            return Err(format!("gateway returned upstream status {status_text}"));
        }
        return Err(format!(
            "gateway returned upstream status {status_text}: {}",
            truncate_for_client(&body, 1200)
        ));
    }
    let body = data
        .get("body")
        .ok_or_else(|| "missing data.body field".to_string())?;
    let body = match body.as_str() {
        Some(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| format!("invalid JSON in data.body: {e}"))?,
        None => body.clone(),
    };

    serde_json::from_value::<T>(body)
        .map_err(|e| format!("invalid typed response in data.body: {e}"))
}

/// Check if a seren SDK error is retryable (transient connection/timeout errors).
///
/// Returns true for:
/// - Connection errors (DNS, TCP, connection refused)
/// - Timeout errors
/// - 502/503/504 gateway errors
///
/// Returns false for:
/// - Client errors (4xx)
/// - Server errors (500) that indicate application-level issues
/// - Response parsing errors
fn is_retryable_error(e: &seren::Error) -> bool {
    match e {
        seren::Error::InvalidRequest(_) => false,
        seren::Error::CommunicationError(reqwest_err) => {
            // Connection errors, timeouts are retryable
            reqwest_err.is_connect() || reqwest_err.is_timeout()
        }
        seren::Error::UnexpectedResponse(response) => {
            // Gateway errors are retryable (upstream may be temporarily unavailable)
            let status = response.status();
            status == reqwest::StatusCode::BAD_GATEWAY
                || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                || status == reqwest::StatusCode::GATEWAY_TIMEOUT
        }
        _ => false,
    }
}

/// Timeout duration for long-running database queries (2 minutes).
/// Some publishers like sec-filings-intelligence can take 60-120s for complex queries.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Timeout duration for API list/get operations (60 seconds).
/// Marketplace and publisher endpoints can be slower than basic project operations.
const API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Small extra window for logo uploads to return their normal timeout error
/// before the handler falls back to a generic timeout response.
const OUTER_TIMEOUT_SLACK: std::time::Duration = std::time::Duration::from_secs(5);

/// Timeout duration for local on-chain balance queries.
const ONCHAIN_RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Maximum number of retries for transient errors.
const MAX_RETRIES: u32 = 2;

/// Base delay for exponential backoff (doubles each retry).
const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

const BASE_CHAIN_ID: u64 = 8453;
const BASE_NETWORK_NAME: &str = "base";
const BASE_NATIVE_ASSET_SYMBOL: &str = "ETH";
const BASE_USDC_ADDRESS: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const DEFAULT_BASE_RPC_URL: &str = "https://mainnet.base.org";
const ERC20_BALANCE_OF_SELECTOR: &str = "70a08231";

fn x402_proxy_payment_header_name(x402_payment: &str) -> Result<&'static str, McpError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(x402_payment.trim())
        .map_err(|e| {
            McpError::invalid_request(
                format!("Invalid _x402_payment payload (base64 decode failed): {e}"),
                None,
            )
        })?;

    let value: serde_json::Value = serde_json::from_slice(&decoded).map_err(|e| {
        McpError::invalid_request(
            format!("Invalid _x402_payment payload (invalid JSON): {e}"),
            None,
        )
    })?;

    match value.get("x402Version").and_then(|v| v.as_u64()) {
        Some(1) => Ok("X-PAYMENT"),
        Some(2) => Ok("PAYMENT-SIGNATURE"),
        Some(other) => Err(McpError::invalid_request(
            format!("Unsupported x402Version in _x402_payment payload: {other}"),
            None,
        )),
        None => Err(McpError::invalid_request(
            "Missing x402Version in _x402_payment payload".to_string(),
            None,
        )),
    }
}

fn payment_required_has_non_prepaid_option(body_text: &str) -> bool {
    let Ok(body_json) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return false;
    };

    let payment_response = body_json
        .get("payment_response")
        .or_else(|| body_json.get("paymentResponse"))
        .unwrap_or(&body_json);

    let Some(accepts) = payment_response
        .get("accepts")
        .and_then(|accepts| accepts.as_array())
    else {
        return false;
    };

    accepts.iter().any(|accept| {
        accept
            .get("scheme")
            .and_then(|v| v.as_str())
            .is_some_and(|scheme| scheme != "prepaid")
    })
}

fn format_payment_required_body(status: reqwest::StatusCode, body_text: &str) -> String {
    if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(body_text) {
        let payment_response = body_json
            .get("payment_response")
            .or_else(|| body_json.get("paymentResponse"));
        let accepts = payment_response
            .and_then(|p| p.get("accepts"))
            .and_then(|a| a.as_array());

        if let (Some(payment_response), Some(accepts)) = (payment_response, accepts)
            && let Some(first) = accepts.first()
        {
            let scheme = first
                .get("scheme")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let network = first
                .get("network")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            if scheme == "prepaid" {
                let extra = first.get("extra").unwrap_or(&serde_json::Value::Null);
                let required = extra
                    .get("requiredAmount")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let available = extra
                    .get("availableBalance")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let deficit = extra.get("deficit").and_then(|v| v.as_str()).unwrap_or("?");

                let top_up = extra.get("topUp").unwrap_or(&serde_json::Value::Null);
                let balance_endpoint = top_up
                    .get("balanceEndpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/wallet/balance");
                let deposit_endpoint = top_up
                    .get("depositEndpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/wallet/deposit");

                let mut message = format!(
                    "Insufficient SerenBucks balance. Required ${required}, available ${available}, deficit ${deficit}. Deposit more via {deposit_endpoint} and check balance via {balance_endpoint}."
                );

                if let Some(resource_desc) = payment_response
                    .get("resource")
                    .and_then(|r| r.get("description"))
                    .and_then(|v| v.as_str())
                {
                    message.push_str(&format!(" Resource: {resource_desc}."));
                }

                return message;
            }

            return format!(
                "Payment required via {scheme} ({network}). {}",
                truncate_for_client(body_text, 1200)
            );
        }
    }

    format!(
        "Payment required ({status}). {}",
        truncate_for_client(body_text, 1200)
    )
}

fn format_decimal_units(raw: &str, decimals: usize) -> String {
    let digits = raw.trim_start_matches('0');
    if digits.is_empty() {
        return "0".to_string();
    }

    if decimals == 0 {
        return digits.to_string();
    }

    if digits.len() <= decimals {
        let fractional = format!("{}{}", "0".repeat(decimals - digits.len()), digits);
        return format!("0.{}", fractional.trim_end_matches('0'));
    }

    let split_at = digits.len() - decimals;
    let whole = &digits[..split_at];
    let fractional = digits[split_at..].trim_end_matches('0');
    if fractional.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fractional}")
    }
}

fn parse_rpc_quantity_to_decimal(value: &str) -> Result<String, McpError> {
    let hex_value = value.trim().trim_start_matches("0x");
    if hex_value.is_empty() {
        return Ok("0".to_string());
    }

    let normalized = if hex_value.len().is_multiple_of(2) {
        hex_value.to_string()
    } else {
        format!("0{hex_value}")
    };

    let bytes = hex::decode(&normalized).map_err(|e| {
        McpError::internal_error(format!("Invalid hex quantity from RPC: {e}"), None)
    })?;
    Ok(U256::from_be_slice(&bytes).to_string())
}

fn erc20_balance_of_call_data(address: &str) -> String {
    let normalized = address.trim().trim_start_matches("0x");
    format!("{ERC20_BALANCE_OF_SELECTOR}{normalized:0>64}")
}

/// Format a payment-required error for the payment proxy pattern.
/// Returns a JSON structure that clients can parse to extract payment requirements
/// and retry with a pre-signed `_x402_payment` parameter.
fn format_payment_proxy_error(body_text: &str, payment_required_header: Option<&str>) -> String {
    // Build a structured response that includes:
    // 1. A marker indicating this is a proxy payment error
    // 2. The raw payment requirements for client-side signing
    // 3. A human-readable message
    let proxy_error = serde_json::json!({
        "error": "payment_required",
        "proxy_payment": true,
        "payment_required_header": payment_required_header,
        "payment_requirements": serde_json::from_str::<serde_json::Value>(body_text).ok(),
        "message": "Payment required. Sign the payment locally and retry with _x402_payment parameter.",
        "instructions": "Parse payment_requirements or payment_required_header, sign with your wallet, and call this tool again with _x402_payment set to the base64-encoded signed payload."
    });

    serde_json::to_string(&proxy_error).unwrap_or_else(|_| {
        format!(
            "Payment required for proxy mode. Raw requirements: {}",
            truncate_for_client(body_text, 1200)
        )
    })
}

async fn resolve_publisher_id(
    api_client: &seren::Client,
    publisher: &str,
) -> Result<Uuid, McpError> {
    if let Ok(uuid) = Uuid::parse_str(publisher) {
        return Ok(uuid);
    }

    let response = api_client
        .get_store_publisher(publisher)
        .into_mcp_result()
        .await?
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
    let url = reqwest::Url::parse(connection_string)
        .map_err(|e| McpError::internal_error(format!("Invalid connection string: {}", e), None))?;
    let host = url.host().ok_or_else(|| {
        McpError::internal_error("Connection string missing host".to_string(), None)
    })?;
    let host_str = host.to_string();

    // Default to HTTPS for hosted usage, but allow plain HTTP for localhost in tests/dev.
    let is_localhost = host_str == "localhost" || host_str == "127.0.0.1" || host_str == "::1";
    let scheme = if is_localhost { "http" } else { "https" };

    let port = url.port();
    // Postgres connection strings commonly include `:5432`, but SQL-over-HTTP typically runs
    // on the default HTTPS port. Keep the port when it's explicitly non-Postgres (e.g. local).
    let include_port = match (scheme, port) {
        ("http", Some(_)) => true,
        ("https", Some(p)) => p != 5432 && p != 443,
        _ => false,
    };

    let mut out =
        reqwest::Url::parse(&format!("{scheme}://example.invalid/sql")).expect("valid base url");
    out.set_host(Some(&host_str)).map_err(|_| {
        McpError::internal_error("Connection string host invalid".to_string(), None)
    })?;
    out.set_path("/sql");
    out.set_query(None);
    out.set_fragment(None);
    if include_port {
        out.set_port(port).map_err(|_| {
            McpError::internal_error("Connection string port invalid".to_string(), None)
        })?;
    } else {
        // Ensure we don't accidentally carry over a port from the placeholder URL.
        out.set_port(None).ok();
    }

    Ok(out.to_string())
}

fn connection_string_is_passwordless(connection_string: &str) -> bool {
    match reqwest::Url::parse(connection_string) {
        Ok(url) => match url.password() {
            None => true,
            Some(password) => password.is_empty(),
        },
        Err(_) => false,
    }
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

pub(crate) fn ensure_writes_allowed(extensions: &Extensions) -> Result<(), McpError> {
    if is_read_only(extensions) {
        return Err(McpError::invalid_request(
            "Read-only mode: write operations are disabled",
            None,
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn put_presigned_deployment_bundle(
    upload_url: &str,
    upload_headers: &HashMap<String, String>,
    content: Vec<u8>,
) -> Result<(), McpError> {
    let client = reqwest::Client::new();
    let mut request = client.put(upload_url).body(content);
    for (name, value) in upload_headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request = request.header(name, value);
    }

    let response = request
        .send()
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(McpError::internal_error(
            format!(
                "Failed to upload deployment bundle to object storage: HTTP {} {}",
                status,
                truncate_for_client(&body, 1200)
            ),
            None,
        ));
    }
    Ok(())
}

async fn put_presigned_object_storage_object(
    upload_url: &str,
    upload_headers: &HashMap<String, String>,
    content: Vec<u8>,
) -> Result<Option<String>, McpError> {
    let client = reqwest::Client::new();
    let mut request = client.put(upload_url).body(content);
    for (name, value) in upload_headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        request = request.header(name, value);
    }

    let response = request
        .send()
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(McpError::internal_error(
            format!(
                "Failed to upload object storage object: HTTP {} {}",
                status,
                truncate_for_client(&body, 1200)
            ),
            None,
        ));
    }

    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty());

    Ok(etag)
}

fn validate_object_storage_key(object_key: &str) -> Result<(), McpError> {
    if object_key.trim_matches('/').is_empty() {
        return Err(McpError::invalid_params(
            "object_key must not be empty",
            None,
        ));
    }
    Ok(())
}

fn validate_object_storage_metadata(
    metadata: Option<serde_json::Value>,
) -> Result<Option<serde_json::Value>, McpError> {
    match metadata {
        Some(value @ serde_json::Value::Object(_)) => Ok(Some(value)),
        Some(_) => Err(McpError::invalid_params(
            "metadata must be a JSON object",
            None,
        )),
        None => Ok(None),
    }
}

fn parse_cloud_enum<T>(label: &str, value: &str) -> Result<T, McpError>
where
    T: FromStr,
{
    value
        .replace('-', "_")
        .parse::<T>()
        .map_err(|_| McpError::invalid_params(format!("Invalid {label}: {value}"), None))
}

async fn register_cloud_deployment_bundle(
    api_client: &seren::Client,
    content: Vec<u8>,
) -> Result<Uuid, McpError> {
    if content.is_empty() {
        return Err(McpError::invalid_params(
            "deployment_bundle_content_base64 decoded to an empty bundle.",
            None,
        ));
    }

    let request = seren::CreateCloudDeploymentBundleRequest {
        sha256: sha256_hex(&content),
        size_bytes: i64::try_from(content.len()).map_err(|_| {
            McpError::invalid_params("deployment bundle content is too large.", None)
        })?,
        source_kind: seren::CloudDeploymentBundleSourceKind::TarGz,
    };
    let registration = match api_client
        .seren_cloud_create_deployment_bundle(&request)
        .await
    {
        Ok(response) => response.into_inner().data,
        Err(error) => return Err(seren_error_to_mcp_error(error).await),
    };

    if registration.upload_required {
        let upload_url = registration.upload_url.as_deref().ok_or_else(|| {
            McpError::internal_error(
                "Deployment bundle registration did not return an upload_url.",
                None,
            )
        })?;
        put_presigned_deployment_bundle(upload_url, &registration.upload_headers, content).await?;
        if let Err(error) = api_client
            .seren_cloud_complete_deployment_bundle_upload(&registration.deployment_bundle_id)
            .await
        {
            return Err(seren_error_to_mcp_error(error).await);
        }
    }

    Ok(registration.deployment_bundle_id)
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

pub(crate) fn extract_user_id_from_extensions(extensions: &Extensions) -> Option<Uuid> {
    let parts = extensions.get::<axum::http::request::Parts>()?;
    let header = parts
        .headers
        .get(axum::http::HeaderName::from_static("x-user-id"))?;
    let user_id = header.to_str().ok()?.trim();
    Uuid::parse_str(user_id).ok()
}

fn request_auth_context_from_extensions(
    extensions: &Extensions,
) -> Option<&crate::SerenRequestAuthContext> {
    let parts = extensions.get::<axum::http::request::Parts>()?;
    parts.extensions.get::<crate::SerenRequestAuthContext>()
}

pub(crate) fn hosted_passwords_credential_subject_from_extensions(
    extensions: &Extensions,
) -> Result<crate::oauth::store::HostedPasswordsCredentialSubject, McpError> {
    let Some(auth) = request_auth_context_from_extensions(extensions) else {
        return Ok(crate::oauth::store::HostedPasswordsCredentialSubject::User);
    };

    match &auth.credential {
        crate::SerenRequestCredential::UserSession => {
            Ok(crate::oauth::store::HostedPasswordsCredentialSubject::User)
        }
        crate::SerenRequestCredential::UserApiKey {
            api_key_id: Some(api_key_id),
        } => Ok(crate::oauth::store::HostedPasswordsCredentialSubject::UserApiKey(*api_key_id)),
        crate::SerenRequestCredential::UserApiKey { api_key_id: None }
        | crate::SerenRequestCredential::ApiKey { .. } => Err(McpError::invalid_request(
            "Hosted password access requires API key metadata from Seren Core",
            None,
        )),
        crate::SerenRequestCredential::AgentApiKey { .. } => Err(McpError::invalid_request(
            "Hosted password access setup requires a user API key or OAuth session",
            None,
        )),
    }
}

/// Agent metadata extracted from OAuth client registration
#[derive(Debug, Clone, Default)]
struct AgentMetadata {
    user_id: Option<String>,
    client_id: Option<String>,
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
}

struct CallPublisherErrorContext<'a, T: Serialize> {
    publisher: &'a str,
    publisher_type: &'a str,
    confirm: bool,
    request_id: Option<Uuid>,
    method: &'a reqwest::Method,
    publisher_path: &'a str,
    query_string: Option<&'a str>,
    body: Option<&'a T>,
    raw_body: Option<&'a [u8]>,
    headers: Option<&'a HashMap<String, String>>,
    agent_metadata: &'a AgentMetadata,
    return_text: bool,
}

fn normalize_api_request_body(
    body: Option<&serde_json::Value>,
) -> Option<Cow<'_, serde_json::Value>> {
    let body = body?;

    match body {
        // Some MCP clients hand nested JSON arguments to us as a pre-stringified
        // object/array. Forward the parsed document so upstream API publishers
        // receive JSON, not a JSON string literal.
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if !matches!(trimmed.chars().next(), Some('{') | Some('[')) {
                return Some(Cow::Borrowed(body));
            }

            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(parsed @ serde_json::Value::Object(_))
                | Ok(parsed @ serde_json::Value::Array(_)) => Some(Cow::Owned(parsed)),
                _ => Some(Cow::Borrowed(body)),
            }
        }
        _ => Some(Cow::Borrowed(body)),
    }
}

fn decode_call_publisher_body_base64(value: Option<&str>) -> Result<Option<Vec<u8>>, McpError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map(Some)
        .map_err(|e| McpError::invalid_params(format!("Invalid body_base64: {}", e), None))
}

fn extract_agent_metadata_from_extensions(extensions: &Extensions) -> AgentMetadata {
    let parts = match extensions.get::<axum::http::request::Parts>() {
        Some(p) => p,
        None => return AgentMetadata::default(),
    };

    AgentMetadata {
        user_id: parts
            .headers
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
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

/// Validation for publisher slugs (URL-friendly identifiers).
///
/// Enforces a conservative subset to avoid ambiguity in URLs and downstream systems:
/// - lowercase letters, digits, and hyphens only
/// - must start with a lowercase letter or digit
/// - max length 63 (matches common DB identifier limits)
fn validate_slug(slug: &str, field: &str) -> Result<(), McpError> {
    let slug = slug.trim();
    if slug.is_empty() {
        return Err(McpError::invalid_params(
            format!("{} must not be empty", field),
            None,
        ));
    }
    if slug.len() > 63 {
        return Err(McpError::invalid_params(
            format!("{} must not exceed 63 characters", field),
            None,
        ));
    }
    let first_char = slug.chars().next().unwrap();
    if !first_char.is_ascii_lowercase() && !first_char.is_ascii_digit() {
        return Err(McpError::invalid_params(
            format!("{} must start with a lowercase letter or number", field),
            None,
        ));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(McpError::invalid_params(
            format!(
                "{} must contain only lowercase letters, numbers, and hyphens",
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

fn normalize_nonempty_optional_string(
    value: Option<String>,
    field: &str,
) -> Result<Option<String>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(McpError::invalid_params(
            format!("{} must not be empty", field),
            None,
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_undocumented_endpoint_policy(
    value: Option<String>,
) -> Result<Option<seren::UndocumentedEndpointPolicy>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(McpError::invalid_params(
            "undocumented_endpoint_policy must not be empty",
            None,
        ));
    }
    match normalized.as_str() {
        "default_allow" | "allow" => Ok(Some(seren::UndocumentedEndpointPolicy::DefaultAllow)),
        "default_deny" | "block" => Ok(Some(seren::UndocumentedEndpointPolicy::DefaultDeny)),
        other => Err(McpError::invalid_params(
            format!(
                "Invalid undocumented_endpoint_policy '{}'. Expected one of: allow, block",
                other
            ),
            None,
        )),
    }
}

fn normalize_token_exchange_method(value: Option<String>) -> Result<Option<String>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(McpError::invalid_params(
            "token_exchange_method must not be empty",
            None,
        ));
    }
    if normalized != "GET" && normalized != "POST" {
        return Err(McpError::invalid_params(
            "token_exchange_method must be GET or POST",
            None,
        ));
    }
    Ok(Some(normalized))
}

fn normalize_token_exchange_mode(value: Option<String>) -> Result<Option<String>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(McpError::invalid_params(
            "token_exchange_mode must not be empty",
            None,
        ));
    }
    if normalized != "header" && normalized != "body" && normalized != "query" {
        return Err(McpError::invalid_params(
            "token_exchange_mode must be header, body, or query",
            None,
        ));
    }
    Ok(Some(normalized))
}

fn validate_token_cache_ttl_seconds(value: Option<i32>) -> Result<Option<i32>, McpError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !(60..=86_400).contains(&value) {
        return Err(McpError::invalid_params(
            "token_cache_ttl_seconds must be between 60 and 86400",
            None,
        ));
    }
    Ok(Some(value))
}

fn passwords_generated_api_base_url(passwords_api_base_url: &str) -> String {
    // Generated Seren client methods include the publisher prefix in their
    // operation paths; VaultClient appends raw Passwords paths to this stored
    // publisher gateway URL.
    let trimmed = passwords_api_base_url.trim_end_matches('/');
    let publisher_prefix = "/publishers/seren-passwords";
    trimmed
        .strip_suffix(publisher_prefix)
        .unwrap_or(trimmed)
        .to_string()
}

// ============================================================================
// Tool Implementations
// ============================================================================

impl SerenMcpServer {
    pub(crate) fn bearer_token(&self, extensions: &Extensions) -> Result<String, McpError> {
        match &self.auth {
            SerenAuth::StaticToken(token) => Ok(token.clone()),
            SerenAuth::FromRequestBearer => extract_bearer_token_from_extensions(extensions)
                .ok_or_else(|| McpError::invalid_request("Missing Bearer token", None)),
        }
    }

    pub(crate) fn api_client_for_bearer(
        &self,
        bearer: &str,
        extensions: &Extensions,
    ) -> Result<seren::Client, McpError> {
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(bearer, &agent_metadata)?;
        Ok(seren::Client::new_with_client(
            &self.api_base_url,
            http_client,
        ))
    }

    pub(crate) async fn passwords_api_client(
        &self,
        extensions: &Extensions,
    ) -> Result<seren::Client, McpError> {
        let (bearer, _) = self.passwords_vault_auth(extensions).await?;
        let base_url = passwords_generated_api_base_url(&self.passwords_api_base_url);
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(&bearer, &agent_metadata)?;
        Ok(seren::Client::new_with_client(&base_url, http_client))
    }

    /// Build a Seren Passwords vault client for the active credential.
    ///
    /// A fresh in-memory user-mode session takes priority: a deliberate
    /// `passwords_unlock` selects user mode and stores derived identity keys
    /// until the idle TTL expires. Otherwise agent-key mode (loaded at startup)
    /// is the default. The server never emits unwrapped key material.
    pub(crate) async fn passwords_vault_client(
        &self,
        extensions: &Extensions,
    ) -> Result<seren_secrets_resolver::VaultClient, McpError> {
        use seren_secrets_resolver::{VaultClient, VaultClientConfig, VaultKeySource};

        let (bearer, kem_private) = self.passwords_vault_auth(extensions).await?;

        VaultClient::new(VaultClientConfig {
            base_url: self.passwords_api_base_url.clone(),
            bearer_token: bearer,
            key_source: VaultKeySource::AgentKey { kem_private },
        })
        .map_err(crate::passwords::vault_err)
    }

    pub(crate) async fn passwords_vault_auth(
        &self,
        extensions: &Extensions,
    ) -> Result<(String, seren_secrets_crypto::keys::IdentityKemPrivateKey), McpError> {
        let session_kem = {
            let mut guard = self.passwords_session.lock().await;
            match guard.as_mut() {
                Some(session) => {
                    if session.last_activity.elapsed() > crate::passwords::SESSION_IDLE_TTL {
                        *guard = None;
                        return Err(McpError::invalid_request(
                            "Vault session expired. Call passwords_unlock again.",
                            None,
                        ));
                    }
                    session.last_activity = std::time::Instant::now();
                    Some(session.kem_private.clone())
                }
                None => None,
            }
        };

        if let Some(kem_private) = session_kem {
            let bearer = self.bearer_token(extensions)?;
            Ok((bearer, kem_private))
        } else if let Some(agent) = &self.passwords_agent {
            Ok((agent.api_key.as_str().to_owned(), agent.kem_private.clone()))
        } else if let Some(store) = &self.passwords_hosted_store {
            let user_id = extract_user_id_from_extensions(extensions).ok_or_else(|| {
                McpError::invalid_request(
                    "Missing authenticated user for hosted vault access",
                    None,
                )
            })?;
            let credential_subject =
                hosted_passwords_credential_subject_from_extensions(extensions)?;
            let credential_subject_key = credential_subject.storage_key();
            let agent = store
                .get_hosted_passwords_agent(user_id, &credential_subject_key)
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
                .ok_or_else(|| {
                    McpError::invalid_request(
                        "Hosted vault access is not configured. Call passwords_request_access and open the returned consent URL.",
                        None,
                    )
                })?;
            let kem_bytes =
                Zeroizing::new(BASE64.decode(agent.kem_private.as_bytes()).map_err(|_| {
                    McpError::internal_error("Stored hosted agent key is invalid", None)
                })?);
            let kem_private = seren_secrets_crypto::keys::IdentityKemPrivateKey::from_slice(
                &kem_bytes,
            )
            .map_err(|_| McpError::internal_error("Stored hosted agent key is invalid", None))?;
            let bearer = match (credential_subject, agent.api_key.as_ref()) {
                (crate::oauth::store::HostedPasswordsCredentialSubject::UserApiKey(_), _) => {
                    self.bearer_token(extensions)?
                }
                (_, Some(api_key)) => api_key.as_str().to_owned(),
                (_, None) => {
                    return Err(McpError::internal_error(
                        "Stored hosted agent API key is missing",
                        None,
                    ));
                }
            };
            Ok((bearer, kem_private))
        } else if !self.passwords_local_mode {
            Err(McpError::invalid_request(
                "Vault access requires a delegated agent key in hosted mode.",
                None,
            ))
        } else {
            Err(McpError::invalid_request(
                "Vault locked. Configure an agent key or call passwords_unlock.",
                None,
            ))
        }
    }

    pub(crate) async fn passwords_user_signing_auth(
        &self,
        extensions: &Extensions,
    ) -> Result<
        (
            String,
            seren_secrets_crypto::keys::IdentityKemPrivateKey,
            seren_secrets_crypto::keys::IdentitySigningPrivateKey,
        ),
        McpError,
    > {
        if !self.passwords_local_mode {
            return Err(McpError::invalid_request(
                "This operation is only available in local MCP modes after passwords_unlock.",
                None,
            ));
        }

        let session_keys = {
            let mut guard = self.passwords_session.lock().await;
            match guard.as_mut() {
                Some(session) => {
                    if session.last_activity.elapsed() > crate::passwords::SESSION_IDLE_TTL {
                        *guard = None;
                        return Err(McpError::invalid_request(
                            "Vault session expired. Call passwords_unlock again.",
                            None,
                        ));
                    }
                    session.last_activity = std::time::Instant::now();
                    Some((session.kem_private.clone(), session.signing_private.clone()))
                }
                None => None,
            }
        };

        if let Some((kem_private, signing_private)) = session_keys {
            let bearer = self.bearer_token(extensions)?;
            Ok((bearer, kem_private, signing_private))
        } else {
            Err(McpError::invalid_request(
                "Vault locked. Call passwords_unlock before this local-only operation.",
                None,
            ))
        }
    }

    /// Establish a user-mode (master-password) unlocked session.
    ///
    /// The master password is sourced outside tool arguments and dropped after
    /// deriving the identity keys. User mode is forbidden in hosted mode.
    pub(crate) async fn passwords_unlock_session(
        &self,
        extensions: &Extensions,
    ) -> Result<(), McpError> {
        if !self.passwords_local_mode {
            return Err(McpError::invalid_request(
                "passwords_unlock is only available in local MCP modes (stdio, start:http); hosted mode must use an agent key.",
                None,
            ));
        }

        let master_password =
            crate::passwords::read_master_password(self.passwords_master_password_file.as_deref())
                .await?;
        let bearer = self.bearer_token(extensions)?;
        let key_source = seren_secrets_resolver::fetch_master_password_key_source(
            &self.passwords_api_base_url,
            &bearer,
            master_password,
        )
        .await
        .map_err(crate::passwords::vault_err)?;
        let (kem_private, signing_private) = tokio::task::spawn_blocking(move || {
            use seren_secrets_resolver::VaultKeySource;

            match key_source {
                VaultKeySource::MasterPassword {
                    secrets,
                    master_password,
                } => seren_secrets_crypto::protocol::account::unlock_account(
                    &master_password,
                    &secrets,
                )
                .map(|unlocked| (unlocked.kem_private, unlocked.signing_private))
                .map_err(seren_secrets_resolver::ResolverError::Crypto),
                VaultKeySource::AgentKey { .. } => {
                    Err(seren_secrets_resolver::ResolverError::NotImplemented(
                        "passwords_unlock with agent-key source",
                    ))
                }
            }
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut guard = self.passwords_session.lock().await;
        // One active session slot needs at most one idle reaper.
        let needs_reaper = guard.is_none();
        *guard = Some(crate::passwords::PasswordsSession {
            kem_private,
            signing_private,
            last_activity: std::time::Instant::now(),
        });
        drop(guard);

        // Proactively zeroize the session after the idle TTL even if no further
        // tool call arrives to drive the lazy check.
        if needs_reaper {
            tokio::spawn(crate::passwords::reap_idle_session(
                self.passwords_session.clone(),
            ));
        }
        Ok(())
    }

    /// Discard any user-mode session, zeroizing its derived key material.
    ///
    /// Idempotent and allowed in any mode.
    pub(crate) async fn passwords_lock_session(&self) {
        let mut guard = self.passwords_session.lock().await;
        *guard = None;
    }

    fn insert_agent_metadata_headers(
        headers: &mut reqwest::header::HeaderMap,
        agent_metadata: &AgentMetadata,
    ) {
        // Forward user identity header to the backend for BYOC OAuth token lookup
        if let Some(ref user_id) = agent_metadata.user_id
            && let Ok(v) = reqwest::header::HeaderValue::from_str(user_id)
        {
            headers.insert(reqwest::header::HeaderName::from_static("x-user-id"), v);
        }
        // Forward agent metadata headers to the backend for tracking
        if let Some(ref client_id) = agent_metadata.client_id
            && let Ok(v) = reqwest::header::HeaderValue::from_str(client_id)
        {
            headers.insert(
                reqwest::header::HeaderName::from_static("x-agent-client-id"),
                v,
            );
        }
        if let Some(ref client_name) = agent_metadata.client_name
            && let Ok(v) = reqwest::header::HeaderValue::from_str(client_name)
        {
            headers.insert(
                reqwest::header::HeaderName::from_static("x-agent-client-name"),
                v,
            );
        }
        if let Some(ref software_id) = agent_metadata.software_id
            && let Ok(v) = reqwest::header::HeaderValue::from_str(software_id)
        {
            headers.insert(
                reqwest::header::HeaderName::from_static("x-agent-software-id"),
                v,
            );
        }
        if let Some(ref software_version) = agent_metadata.software_version
            && let Ok(v) = reqwest::header::HeaderValue::from_str(software_version)
        {
            headers.insert(
                reqwest::header::HeaderName::from_static("x-agent-software-version"),
                v,
            );
        }
    }

    fn build_http_client(
        &self,
        token: &str,
        agent_metadata: &AgentMetadata,
    ) -> Result<reqwest::Client, McpError> {
        self.build_http_client_with_timeout(
            token,
            agent_metadata,
            std::time::Duration::from_secs(30),
        )
    }

    fn build_http_client_with_timeout(
        &self,
        token: &str,
        agent_metadata: &AgentMetadata,
        timeout: std::time::Duration,
    ) -> Result<reqwest::Client, McpError> {
        self.build_http_client_with_timeout_and_request_id(token, agent_metadata, timeout, None)
    }

    fn build_http_client_with_timeout_and_request_id(
        &self,
        token: &str,
        agent_metadata: &AgentMetadata,
        timeout: std::time::Duration,
        request_id: Option<Uuid>,
    ) -> Result<reqwest::Client, McpError> {
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| McpError::internal_error(format!("Invalid token: {}", e), None))?;
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        Self::insert_agent_metadata_headers(&mut headers, agent_metadata);
        if let Some(request_id) = request_id {
            let value =
                reqwest::header::HeaderValue::from_str(&request_id.to_string()).map_err(|e| {
                    McpError::internal_error(format!("Invalid request id: {}", e), None)
                })?;
            headers.insert(
                reqwest::header::HeaderName::from_static("x-request-id"),
                value,
            );
        }

        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                McpError::internal_error(format!("Failed to build HTTP client: {}", e), None)
            })
    }

    fn build_public_http_client(
        &self,
        agent_metadata: &AgentMetadata,
    ) -> Result<reqwest::Client, McpError> {
        let mut headers = reqwest::header::HeaderMap::new();
        Self::insert_agent_metadata_headers(&mut headers, agent_metadata);

        reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| {
                McpError::internal_error(format!("Failed to build HTTP client: {}", e), None)
            })
    }

    pub(crate) fn api_client(&self, extensions: &Extensions) -> Result<seren::Client, McpError> {
        let token = self.bearer_token(extensions)?;
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(&token, &agent_metadata)?;
        Ok(seren::Client::new_with_client(
            &self.api_base_url,
            http_client,
        ))
    }

    /// Create an API client with a custom timeout for long-running operations.
    fn api_client_with_timeout(
        &self,
        extensions: &Extensions,
        timeout: std::time::Duration,
    ) -> Result<seren::Client, McpError> {
        self.api_client_with_timeout_request_id(extensions, timeout, None)
    }

    fn api_client_with_timeout_request_id(
        &self,
        extensions: &Extensions,
        timeout: std::time::Duration,
        request_id: Option<Uuid>,
    ) -> Result<seren::Client, McpError> {
        let token = self.bearer_token(extensions)?;
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client_with_timeout_and_request_id(
            &token,
            &agent_metadata,
            timeout,
            request_id,
        )?;
        Ok(seren::Client::new_with_client(
            &self.api_base_url,
            http_client,
        ))
    }

    /// Execute a direct JSON request to the Seren API using the server's configured auth
    /// and agent-metadata headers.
    ///
    /// This intentionally does NOT add the SDK-generated `api-version` header.
    async fn execute_api_json<T: Serialize>(
        &self,
        extensions: &Extensions,
        method: reqwest::Method,
        url: String,
        body: Option<&T>,
    ) -> Result<serde_json::Value, McpError> {
        let token = self.bearer_token(extensions)?;
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(&token, &agent_metadata)?;

        let mut req = http_client.request(method, &url).header(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        if let Some(body) = body {
            req = req.json(body);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.without_url().to_string(), None))?;

        let status = resp.status();
        if !status.is_success() {
            let request_id = resp
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let body = resp.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                api_error_message(status, &body, request_id.as_deref()),
                Some(serde_json::json!({
                    "kind": "http_error",
                    "status": status.as_u16(),
                    "body": truncate_for_client(&body, 1200),
                    "request_id": request_id,
                })),
            ));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    async fn execute_api_text(
        &self,
        extensions: &Extensions,
        url: String,
        accept: &'static str,
    ) -> Result<String, McpError> {
        let token = self.bearer_token(extensions)?;
        let agent_metadata = extract_agent_metadata_from_extensions(extensions);
        let http_client = self.build_http_client(&token, &agent_metadata)?;

        let resp = http_client
            .get(&url)
            .header(reqwest::header::ACCEPT, accept)
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.without_url().to_string(), None))?;

        let status = resp.status();
        if !status.is_success() {
            let request_id = resp
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let body = resp.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                api_error_message(status, &body, request_id.as_deref()),
                Some(serde_json::json!({
                    "kind": "http_error",
                    "status": status.as_u16(),
                    "body": truncate_for_client(&body, 1200),
                    "request_id": request_id,
                })),
            ));
        }

        resp.text()
            .await
            .map_err(|e| McpError::internal_error(e.without_url().to_string(), None))
    }

    async fn resolve_cloud_run_pending_approvals(
        &self,
        extensions: &Extensions,
        run_id: Uuid,
        decision: &str,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(extensions)?;
        let run_detail = api_client
            .seren_cloud_run_detail(&run_id)
            .into_mcp_result()
            .await?;
        let deployment_id = run_detail.into_inner().data.deployment_id;

        let approval_state = api_client
            .seren_cloud_run_pending_approvals(&run_id)
            .into_mcp_result()
            .await?;
        let approval_state = approval_state.into_inner();
        let approval_state_json = serde_json::to_value(&approval_state)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let maybe_body = seren::build_cloud_approval_resume_request(&approval_state_json, decision)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        if maybe_body.is_none() {
            let payload = serde_json::json!({
                "resolved": false,
                "decision": decision,
                "run_id": run_id,
                "deployment_id": deployment_id,
                "approval_state": approval_state_json,
                "message": "This run is not currently awaiting approval.",
            });
            return Ok(CallToolResult::success(vec![
                Content::text(format!(
                    "Run {} is not currently awaiting approval.",
                    run_id
                )),
                json_content(&payload)?,
            ]));
        }

        let body = maybe_body.unwrap_or_default();
        let response_json = api_client
            .seren_cloud_run(&deployment_id, &body)
            .into_mcp_result()
            .await?;
        let response_json = response_json.into_inner();
        let data = serde_json::to_value(&response_json)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let data = data.get("data").cloned().unwrap_or(data);
        let resumed_run_id = data
            .get("run_id")
            .or_else(|| data.get("id"))
            .and_then(|value| value.as_str());
        let execution_id = data.get("execution_id").and_then(|value| value.as_str());

        let action_label = if decision == "approve" {
            "Approved"
        } else {
            "Rejected"
        };
        let mut content = Vec::new();
        if let (Some(resumed_run_id), Some(execution_id)) = (resumed_run_id, execution_id) {
            content.push(Content::text(format!(
                "{} pending approvals for run {} and resumed deployment {}.\nrun_id: {}\nexecution_id: {}",
                action_label, run_id, deployment_id, resumed_run_id, execution_id
            )));
        } else if let Some(resumed_run_id) = resumed_run_id {
            content.push(Content::text(format!(
                "{} pending approvals for run {} and resumed deployment {} (run_id: {}).",
                action_label, run_id, deployment_id, resumed_run_id
            )));
        } else {
            content.push(Content::text(format!(
                "{} pending approvals for run {} and resumed deployment {}.",
                action_label, run_id, deployment_id
            )));
        }
        let payload = serde_json::json!({
            "resolved": true,
            "decision": decision,
            "run_id": run_id,
            "deployment_id": deployment_id,
            "response": response_json,
        });
        content.push(json_content(&payload)?);
        Ok(CallToolResult::success(content))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_publisher_proxy_raw<T: Serialize>(
        &self,
        extensions: &Extensions,
        agent_metadata: &AgentMetadata,
        timeout: std::time::Duration,
        method: &reqwest::Method,
        publisher_path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        query_string: Option<&str>,
    ) -> Result<reqwest::Response, seren::Error<()>> {
        let token = self
            .bearer_token(extensions)
            .map_err(|e| seren::Error::InvalidRequest(e.to_string()))?;
        let http_client = self
            .build_http_client_with_timeout_and_request_id(
                &token,
                agent_metadata,
                timeout,
                request_id,
            )
            .map_err(|e| seren::Error::InvalidRequest(e.to_string()))?;
        let mut request_url = format!(
            "{}/{}",
            self.api_base_url.trim_end_matches('/'),
            publisher_path.trim_start_matches('/')
        );
        if let Some(qs) = query_string {
            request_url.push('?');
            request_url.push_str(qs);
        }

        let mut request_builder = http_client.request(method.clone(), &request_url);
        if let Some(headers) = headers {
            for (key, value) in headers {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    && let Ok(header_value) = reqwest::header::HeaderValue::from_str(value)
                {
                    request_builder = request_builder.header(header_name, header_value);
                }
            }
        }
        if let Some(raw_body) = raw_body {
            request_builder = request_builder.body(raw_body.to_vec());
        } else if let Some(body) = body {
            request_builder = request_builder.json(body);
        }

        request_builder
            .send()
            .await
            .map_err(seren::Error::CommunicationError)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_x402_roundtrip<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        confirm: bool,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<reqwest::Response, McpError> {
        let wallet = self.wallet.as_ref().ok_or_else(|| {
            McpError::invalid_request(
                "Local wallet not configured. Set WALLET_PRIVATE_KEY to enable x402 payments."
                    .to_string(),
                None,
            )
        })?;

        let wallet_address = wallet.address().to_string();
        let http_client = self.build_public_http_client(agent_metadata)?;
        let mut url = format!(
            "{}/{}",
            self.api_base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        if let Some(qs) = query_string {
            url.push('?');
            url.push_str(qs);
        }

        // First request: trigger 402 (PAYMENT-REQUIRED)
        let mut request_builder = http_client
            .request(method.clone(), &url)
            .header("X-AGENT-WALLET", &wallet_address);
        if let Some(headers) = headers {
            for (key, value) in headers {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    && let Ok(header_value) = reqwest::header::HeaderValue::from_str(value)
                {
                    request_builder = request_builder.header(header_name, header_value);
                }
            }
        }
        if let Some(request_id) = request_id {
            request_builder = request_builder.header("x-request-id", request_id.to_string());
        }
        if let Some(raw_body) = raw_body {
            request_builder = request_builder.body(raw_body.to_vec());
        } else if let Some(body) = body {
            request_builder = request_builder.json(body);
        }
        let response = request_builder
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Some publishers may have zero-cost routes; accept success without payment.
        if response.status().is_success() {
            return Ok(response);
        }

        if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!(
                    "x402 request failed ({}): {}",
                    status,
                    truncate_for_client(&body, 500)
                ),
                None,
            ));
        }

        let payment_required_header = response
            .headers()
            .get("PAYMENT-REQUIRED")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_text = response.text().await.unwrap_or_default();

        // Prefer the x402 v2 header transport when present, but fall back to
        // spec-accurate x402 v1 body parsing when a server uses v1 transport.
        let requirements = match payment_required_header.as_deref() {
            Some(header_b64) => PaymentRequirements::parse_payment_required_header(header_b64)
                .or_else(|_| PaymentRequirements::parse(&body_text)),
            None => PaymentRequirements::parse(&body_text),
        }
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let x402_option = requirements.x402_option().ok_or_else(|| {
            McpError::invalid_request(
                "Publisher did not provide any x402 payment options".to_string(),
                None,
            )
        })?;

        let amount_atomic: i64 = x402_option
            .amount
            .parse()
            .map_err(|_| McpError::internal_error("Invalid x402 amount".to_string(), None))?;

        if !confirm && !self.signer_config.should_auto_approve(amount_atomic) {
            let amount_usd = format_usd_micros(amount_atomic);
            let limit_usd = format_usd_micros(self.signer_config.auto_approve_limit_micros);
            return Err(McpError::invalid_request(
                format!(
                    "Payment requires confirmation (${} > ${}). Re-run with confirm=true or raise auto_approve_limit in your signer config.",
                    amount_usd, limit_usd
                ),
                None,
            ));
        }

        let payload = build_x402_payment_payload(wallet, &requirements, x402_option)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let payload_b64 = payload
            .encode_b64()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Second request: retry with x402 payment header (v2 = PAYMENT-SIGNATURE, v1 = X-PAYMENT)
        let mut request_builder = http_client
            .request(method.clone(), &url)
            .header("X-AGENT-WALLET", &wallet_address)
            .header(payload.header_name(), payload_b64);
        if let Some(headers) = headers {
            for (key, value) in headers {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    && let Ok(header_value) = reqwest::header::HeaderValue::from_str(value)
                {
                    request_builder = request_builder.header(header_name, header_value);
                }
            }
        }
        if let Some(request_id) = request_id {
            request_builder = request_builder.header("x-request-id", request_id.to_string());
        }

        if let Some(request_id) = x402_option
            .extra
            .get("paymentRequestId")
            .and_then(|v| v.as_str())
        {
            request_builder = request_builder.header("X-PAYMENT-REQUEST-ID", request_id);
        }

        if let Some(raw_body) = raw_body {
            request_builder = request_builder.body(raw_body.to_vec());
        } else if let Some(body) = body {
            request_builder = request_builder.json(body);
        }
        let paid = request_builder
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if !paid.status().is_success() {
            let status = paid.status();
            let payment_required_header = paid
                .headers()
                .get("PAYMENT-REQUIRED")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body = paid.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                let requirements = match payment_required_header.as_deref() {
                    Some(header_b64) => {
                        PaymentRequirements::parse_payment_required_header(header_b64)
                            .or_else(|_| PaymentRequirements::parse(&body))
                    }
                    None => PaymentRequirements::parse(&body),
                };

                if let Ok(requirements) = requirements {
                    let reason = requirements.error.as_deref().unwrap_or("Payment required");

                    if let Some(opt) = requirements.x402_option() {
                        return Err(McpError::invalid_request(
                            format!(
                                "x402 payment rejected ({}): {} (amount={}, network={}, asset={})",
                                status, reason, opt.amount, opt.network, opt.asset
                            ),
                            None,
                        ));
                    }

                    return Err(McpError::invalid_request(
                        format!("x402 payment rejected ({}): {}", status, reason),
                        None,
                    ));
                }
            }

            return Err(McpError::invalid_request(
                format!(
                    "x402 payment failed ({}): {}",
                    status,
                    truncate_for_client(&body, 500)
                ),
                None,
            ));
        }

        Ok(paid)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_x402_roundtrip_json<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        confirm: bool,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<serde_json::Value, McpError> {
        let response = self
            .execute_x402_roundtrip(
                method,
                path,
                body,
                raw_body,
                headers,
                request_id,
                confirm,
                agent_metadata,
                query_string,
            )
            .await?;
        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(json)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_x402_roundtrip_text<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        confirm: bool,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<String, McpError> {
        let response = self
            .execute_x402_roundtrip(
                method,
                path,
                body,
                raw_body,
                headers,
                request_id,
                confirm,
                agent_metadata,
                query_string,
            )
            .await?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Execute a request with a pre-signed x402 payment (payment proxy mode).
    /// The client has already signed the payment and we just forward it.
    #[allow(clippy::too_many_arguments)]
    async fn execute_with_proxy_payment<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        x402_payment: &str,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<reqwest::Response, McpError> {
        let http_client = self.build_public_http_client(agent_metadata)?;
        let mut url = format!(
            "{}/{}",
            self.api_base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        if let Some(qs) = query_string {
            url.push('?');
            url.push_str(qs);
        }

        let payment_header = x402_proxy_payment_header_name(x402_payment)?;

        // Make the request with the pre-signed payment header.
        // v1: X-PAYMENT, v2: PAYMENT-SIGNATURE
        let mut request_builder = http_client
            .request(method.clone(), &url)
            .header(payment_header, x402_payment);
        if let Some(headers) = headers {
            for (key, value) in headers {
                if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes())
                    && let Ok(header_value) = reqwest::header::HeaderValue::from_str(value)
                {
                    request_builder = request_builder.header(header_name, header_value);
                }
            }
        }
        if let Some(request_id) = request_id {
            request_builder = request_builder.header("x-request-id", request_id.to_string());
        }
        if let Some(raw_body) = raw_body {
            request_builder = request_builder.body(raw_body.to_vec());
        } else if let Some(body) = body {
            request_builder = request_builder.json(body);
        }
        let response = request_builder
            .send()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();

            if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                // Payment was rejected - return the new requirements
                return Err(McpError::invalid_request(
                    format!(
                        "x402 payment rejected ({}). The payment may have expired or been invalid. New requirements: {}",
                        status,
                        truncate_for_client(&body_text, 1200)
                    ),
                    None,
                ));
            }

            return Err(McpError::internal_error(
                format!(
                    "Request with proxy payment failed ({}): {}",
                    status,
                    truncate_for_client(&body_text, 500)
                ),
                None,
            ));
        }

        Ok(response)
    }

    /// Execute a request with a pre-signed x402 payment and return JSON result.
    #[allow(clippy::too_many_arguments)]
    async fn execute_with_proxy_payment_json<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        x402_payment: &str,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<serde_json::Value, McpError> {
        let response = self
            .execute_with_proxy_payment(
                method,
                path,
                body,
                raw_body,
                headers,
                request_id,
                x402_payment,
                agent_metadata,
                query_string,
            )
            .await?;
        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(json)
    }

    /// Execute a request with a pre-signed x402 payment and return text result.
    #[allow(clippy::too_many_arguments)]
    async fn execute_with_proxy_payment_text<T: Serialize>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: Option<&T>,
        raw_body: Option<&[u8]>,
        headers: Option<&HashMap<String, String>>,
        request_id: Option<Uuid>,
        x402_payment: &str,
        agent_metadata: &AgentMetadata,
        query_string: Option<&str>,
    ) -> Result<String, McpError> {
        let response = self
            .execute_with_proxy_payment(
                method,
                path,
                body,
                raw_body,
                headers,
                request_id,
                x402_payment,
                agent_metadata,
                query_string,
            )
            .await?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    #[instrument(skip(self, connection_string), fields(query_len = query.len()))]
    async fn execute_sql(
        &self,
        connection_string: &str,
        query: &str,
        params: Vec<serde_json::Value>,
        bearer_token: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value, McpError> {
        let http_url = sql_proxy_url_from_connection_string(connection_string)?;

        tracing::debug!(url = %http_url, timeout_secs = timeout.as_secs(), "Executing SQL query");

        let mut request_builder = self.http_client.post(&http_url);
        request_builder = request_builder
            .header("SerenDB-Connection-String", connection_string)
            .header("SerenDB-Pool-Opt-In", "true");

        // If the connection string has no password, the proxy expects a Bearer JWT
        // (e.g. SerenDB auth-broker mode). Only attach Authorization in that case.
        if connection_string_is_passwordless(connection_string)
            && let Some(token) = bearer_token
            && !token.trim().is_empty()
        {
            request_builder =
                request_builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token));
        }

        // Wrap the HTTP request with a timeout to handle long-running queries
        let send_future = request_builder
            .json(&SqlRequest {
                query: query.to_string(),
                params,
            })
            .timeout(timeout)
            .send();

        let response = tokio::time::timeout(timeout, send_future)
            .await
            .map_err(|_| {
                tracing::error!(timeout_secs = timeout.as_secs(), "SQL query timed out");
                McpError::internal_error(
                    format!(
                        "Query timed out after {} seconds. For long-running queries, increase the timeout_ms parameter.",
                        timeout.as_secs()
                    ),
                    None,
                )
            })?
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
            let client_error = truncate_for_client(&error_text, 500);
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

    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, connection_string, queries), fields(query_count = queries.len()))]
    async fn execute_sql_transaction(
        &self,
        connection_string: &str,
        queries: Vec<String>,
        read_only: Option<bool>,
        isolation_level: Option<String>,
        deferrable: Option<bool>,
        bearer_token: Option<&str>,
        timeout: std::time::Duration,
    ) -> Result<serde_json::Value, McpError> {
        let http_url = sql_proxy_url_from_connection_string(connection_string)?;

        tracing::debug!(url = %http_url, timeout_secs = timeout.as_secs(), "Executing SQL transaction");

        let batch_queries: Vec<SqlBatchQuery> = queries
            .into_iter()
            .map(|query| SqlBatchQuery {
                query,
                params: vec![],
            })
            .collect();

        let mut request_builder = self.http_client.post(&http_url);
        request_builder = request_builder
            .header("SerenDB-Connection-String", connection_string)
            .header("SerenDB-Pool-Opt-In", "true");

        // If the connection string has no password, the proxy expects a Bearer JWT
        // (e.g. SerenDB auth-broker mode). Only attach Authorization in that case.
        if connection_string_is_passwordless(connection_string)
            && let Some(token) = bearer_token
            && !token.trim().is_empty()
        {
            request_builder =
                request_builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token));
        }

        if read_only.unwrap_or(false) {
            request_builder = request_builder.header("SerenDB-Batch-Read-Only", "true");
        }
        if let Some(level) = isolation_level.as_deref() {
            request_builder = request_builder.header("SerenDB-Batch-Isolation-Level", level);
        }
        if deferrable.unwrap_or(false) {
            request_builder = request_builder.header("SerenDB-Batch-Deferrable", "true");
        }

        // Wrap the HTTP request with a timeout to handle long-running transactions
        let send_future = request_builder
            .json(&SqlBatchRequest {
                queries: batch_queries,
            })
            .timeout(timeout)
            .send();

        let response = tokio::time::timeout(timeout, send_future)
            .await
            .map_err(|_| {
                tracing::error!(timeout_secs = timeout.as_secs(), "SQL transaction timed out");
                McpError::internal_error(
                    format!(
                        "Transaction timed out after {} seconds. For long-running transactions, increase the timeout_ms parameter.",
                        timeout.as_secs()
                    ),
                    None,
                )
            })?
            .map_err(|e| {
                tracing::error!(error = %e, "SQL batch HTTP request failed");
                McpError::internal_error(e.to_string(), None)
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(status = %status, "SQL batch execution failed");
            let client_error = truncate_for_client(&error_text, 500);
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
    ///
    /// The private key is not logged, including on parse failure.
    fn load_wallet_from_env() -> Option<PrivateKeyWallet> {
        match std::env::var("WALLET_PRIVATE_KEY") {
            Ok(key) => match PrivateKeyWallet::from_env_or_key(Some(key)) {
                Ok(Some(w)) => Some(w),
                Ok(None) => None,
                Err(e) => {
                    // Keep key material out of diagnostics.
                    tracing::error!("Failed to load wallet from WALLET_PRIVATE_KEY: {}", e);
                    None
                }
            },
            Err(_) => None,
        }
    }

    /// Create a new Seren MCP Server for stdio mode (local usage).
    ///
    /// In stdio mode, the optional wallet from WALLET_PRIVATE_KEY is loaded
    /// to enable local x402 payment signing.
    #[allow(clippy::result_large_err, dead_code)]
    pub fn new(api_key: &str, api_base_url: &str) -> Result<Self, seren::Error> {
        Self::new_with_passwords_api_url(api_key, api_base_url, api_base_url)
    }

    /// Create a new Seren MCP Server with a separate passwords gateway URL.
    #[allow(clippy::result_large_err)]
    pub fn new_with_passwords_api_url(
        api_key: &str,
        api_base_url: &str,
        passwords_api_base_url: &str,
    ) -> Result<Self, seren::Error> {
        Self::new_with_passwords_api_url_and_master_password_file(
            api_key,
            api_base_url,
            passwords_api_base_url,
            None,
        )
    }

    /// Create a new Seren MCP Server with a separate passwords gateway URL and unlock file.
    #[allow(clippy::result_large_err)]
    pub fn new_with_passwords_api_url_and_master_password_file(
        api_key: &str,
        api_base_url: &str,
        passwords_api_base_url: &str,
        passwords_master_password_file: Option<PathBuf>,
    ) -> Result<Self, seren::Error> {
        let wallet = Self::load_wallet_from_env();
        let signer_config = SignerConfig::load_or_create();

        // Log only derived wallet status.
        if let Some(ref w) = wallet {
            tracing::info!(
                wallet_address = %w.address(),
                auto_approve_limit_usd = %format_usd_micros(signer_config.auto_approve_limit_micros),
                "X402 signing enabled"
            );
        } else {
            tracing::debug!("X402 signing disabled (no WALLET_PRIVATE_KEY)");
        }

        // Configure HTTP client with timeouts to prevent hanging requests
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Ok(Self {
            api_base_url: api_base_url.to_string(),
            passwords_api_base_url: passwords_api_base_url.to_string(),
            auth: SerenAuth::StaticToken(api_key.to_string()),
            http_client,
            tool_router: Self::tool_router() + Self::passwords_tool_router(),
            wallet: wallet.map(Arc::new),
            signer_config,
            passwords_local_mode: true,
            passwords_session: Arc::new(tokio::sync::Mutex::new(None)),
            passwords_master_password_file,
            passwords_agent: crate::passwords::load_agent_identity(),
            passwords_hosted_store: None,
        })
    }

    /// Create a new Seren MCP Server in OAuth mode (hosted usage).
    ///
    /// In this mode the Seren API token is taken from each incoming HTTP request's
    /// `Authorization: Bearer ...` header (injected into [`Extensions`] by rmcp).
    ///
    /// NOTE: Local wallet is DISABLED in hosted mode for security.
    /// Users must use prepaid balance or the hosted wallet API.
    #[allow(clippy::result_large_err, dead_code)]
    pub fn new_oauth(api_base_url: &str) -> Result<Self, seren::Error> {
        Self::new_oauth_with_store(api_base_url, None)
    }

    /// Create a new Seren MCP Server in OAuth mode with hosted credential storage.
    #[allow(clippy::result_large_err)]
    pub fn new_oauth_with_store(
        api_base_url: &str,
        passwords_hosted_store: Option<Arc<crate::oauth::store::TokenStore>>,
    ) -> Result<Self, seren::Error> {
        let passwords_api_base_url =
            crate::config::publisher_api_base_url(api_base_url, "seren-passwords");
        Self::new_oauth_with_store_and_passwords_api_url(
            api_base_url,
            &passwords_api_base_url,
            passwords_hosted_store,
        )
    }

    /// Create a new Seren MCP Server in OAuth mode with a separate passwords gateway URL.
    #[allow(clippy::result_large_err)]
    pub fn new_oauth_with_store_and_passwords_api_url(
        api_base_url: &str,
        passwords_api_base_url: &str,
        passwords_hosted_store: Option<Arc<crate::oauth::store::TokenStore>>,
    ) -> Result<Self, seren::Error> {
        // Hosted mode: explicitly disable local wallet
        tracing::debug!("X402 local signing disabled (hosted mode)");

        // Configure HTTP client with timeouts to prevent hanging requests
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Ok(Self {
            api_base_url: api_base_url.to_string(),
            passwords_api_base_url: passwords_api_base_url.to_string(),
            auth: SerenAuth::FromRequestBearer,
            http_client,
            tool_router: Self::tool_router() + Self::passwords_tool_router(),
            wallet: None,
            signer_config: SignerConfig::default(),
            // Local agent-key signing is DISABLED in hosted mode (mirrors wallet).
            passwords_local_mode: false,
            passwords_session: Arc::new(tokio::sync::Mutex::new(None)),
            passwords_master_password_file: None,
            passwords_agent: None,
            passwords_hosted_store,
        })
    }

    /// Check if x402 local signing is available.
    #[allow(dead_code)]
    pub fn has_wallet(&self) -> bool {
        self.wallet.is_some()
    }

    /// Return a confirmation request to the agent for payments above threshold.
    ///
    /// This is used when an x402 payment exceeds the auto_approve_limit and
    /// the user hasn't confirmed the payment.
    #[allow(dead_code)]
    fn confirmation_required(
        &self,
        amount_micros: i64,
        amount_raw: &str,
        recipient: &str,
        network: &str,
    ) -> CallToolResult {
        let amount_usd = format_usd_micros(amount_micros);
        let limit_usd = format_usd_micros(self.signer_config.auto_approve_limit_micros);
        let content = serde_json::json!({
            "status": "confirmation_required",
            "message": format!(
                "Payment of ${} requires approval (above ${} auto-approve limit)",
                amount_usd,
                limit_usd
            ),
            "payment": {
                "amount_usd": amount_usd,
                "amount_raw": amount_raw,
                "recipient": recipient,
                "network": network,
            },
            "instructions": "To approve, call this tool again with confirm: true"
        });

        CallToolResult::success(vec![Content::text(content.to_string())])
    }

    /// Convert raw USDC amount (6 decimals) to micro-USD.
    #[allow(dead_code)]
    fn raw_to_micros(amount_raw: &str) -> Option<i64> {
        amount_raw
            .parse::<u64>()
            .ok()
            .and_then(|raw| i64::try_from(raw).ok())
    }

    fn base_rpc_url() -> String {
        std::env::var("BASE_RPC_URL").unwrap_or_else(|_| DEFAULT_BASE_RPC_URL.to_string())
    }

    async fn execute_json_rpc(
        &self,
        rpc_url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        let response = self
            .http_client
            .post(rpc_url)
            .timeout(ONCHAIN_RPC_TIMEOUT)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|e| {
                McpError::internal_error(format!("On-chain RPC request failed: {e}"), None)
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(McpError::internal_error(
                format!(
                    "On-chain RPC failed ({}): {}",
                    status,
                    truncate_for_client(&body, 500)
                ),
                None,
            ));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            McpError::internal_error(format!("Invalid on-chain RPC response: {e}"), None)
        })?;

        if let Some(error) = body.get("error") {
            return Err(McpError::internal_error(
                format!("On-chain RPC returned error: {error}"),
                None,
            ));
        }

        body.get("result").cloned().ok_or_else(|| {
            McpError::internal_error("On-chain RPC response missing result".to_string(), None)
        })
    }

    async fn fetch_onchain_wallet_status(
        &self,
        rpc_url: &str,
        wallet: &PrivateKeyWallet,
    ) -> Result<serde_json::Value, McpError> {
        let address = wallet.address().to_string();

        let native_balance_hex = self
            .execute_json_rpc(
                rpc_url,
                "eth_getBalance",
                serde_json::json!([address.clone(), "latest"]),
            )
            .await?;
        let native_balance_wei =
            parse_rpc_quantity_to_decimal(native_balance_hex.as_str().ok_or_else(|| {
                McpError::internal_error(
                    "On-chain RPC returned non-string eth_getBalance result".to_string(),
                    None,
                )
            })?)?;

        let usdc_balance_hex = self
            .execute_json_rpc(
                rpc_url,
                "eth_call",
                serde_json::json!([
                    {
                        "to": BASE_USDC_ADDRESS,
                        "data": erc20_balance_of_call_data(&address),
                    },
                    "latest"
                ]),
            )
            .await?;
        let usdc_balance_raw =
            parse_rpc_quantity_to_decimal(usdc_balance_hex.as_str().ok_or_else(|| {
                McpError::internal_error(
                    "On-chain RPC returned non-string eth_call result".to_string(),
                    None,
                )
            })?)?;
        let native_balance = format_decimal_units(&native_balance_wei, 18);
        let usdc_balance = format_decimal_units(&usdc_balance_raw, 6);

        Ok(serde_json::json!({
            "address": address,
            "network": BASE_NETWORK_NAME,
            "chain_id": BASE_CHAIN_ID,
            "native": {
                "asset_symbol": BASE_NATIVE_ASSET_SYMBOL,
                "balance_wei": native_balance_wei,
                "balance": native_balance,
            },
            "usdc": {
                "asset_symbol": "USDC",
                "contract_address": BASE_USDC_ADDRESS,
                "balance_raw": usdc_balance_raw,
                "balance": usdc_balance.clone(),
                "balance_usd": usdc_balance,
            }
        }))
    }

    #[tool(
        description = "List all Seren projects accessible to the authenticated user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_projects(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let projects = api_client
            .seren_db_list_projects()
            .into_mcp_result()
            .await?
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
            .seren_db_get_project(&params.project_id)
            .into_mcp_result()
            .await?
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
            .seren_db_create_project(&request)
            .into_mcp_result()
            .await?
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
            .seren_db_delete_project(&params.project_id)
            .into_mcp_result()
            .await?;
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
            .seren_db_create_branch(&params.path.project_id, &params.body)
            .into_mcp_result()
            .await?
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
            .seren_db_delete_branch(&params.project_id, &params.branch_id)
            .into_mcp_result()
            .await?;
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

        // Fetch databases, project, and branch in parallel for efficiency
        let (databases_result, project_result, branch_result) = tokio::join!(
            api_client.seren_db_list_databases(&params.project_id, &params.branch_id),
            api_client.seren_db_get_project(&params.project_id),
            api_client.seren_db_get_branch(&params.project_id, &params.branch_id)
        );

        let databases = seren_result_to_mcp(databases_result).await?.into_inner();
        let project = seren_result_to_mcp(project_result).await?.into_inner();
        let branch = seren_result_to_mcp(branch_result).await?.into_inner();

        // Build enhanced response with human-readable context
        let response = DatabaseListResponse {
            project_name: project.data.name.clone(),
            branch_name: branch.data.name.clone(),
            is_default_branch: branch.data.is_default.unwrap_or(false),
            databases: databases
                .data
                .iter()
                .map(|db| DatabaseInfo {
                    id: db.id,
                    name: db.name.clone(),
                    owner_name: db.owner_name.clone(),
                    created_at: db.created_at.to_string(),
                })
                .collect(),
        };

        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List all databases across all projects. Returns a flat list with project and branch names for easy identification.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_all_databases(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        // Call the dedicated endpoint that returns all databases with context
        let databases = api_client
            .list_all_databases()
            .into_mcp_result()
            .await?
            .into_inner();

        // Map the API response to our response format
        let all_databases: Vec<AllDatabasesEntry> = databases
            .data
            .into_iter()
            .map(|db| AllDatabasesEntry {
                project: db.project_name,
                project_id: db.project_id,
                branch: db.branch_name,
                branch_id: db.branch_id,
                is_default: db.is_default_branch,
                database: db.name,
                database_id: db.id,
            })
            .collect();

        let response = AllDatabasesResponse {
            total: all_databases.len(),
            databases: all_databases,
        };

        Ok(CallToolResult::success(vec![json_content(&response)?]))
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
            .seren_db_create_database(
                &params.path.project_id,
                &params.path.branch_id,
                &params.body,
            )
            .into_mcp_result()
            .await?
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
            .seren_db_list_roles(&params.project_id, &params.branch_id)
            .into_mcp_result()
            .await?
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
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                params.pooled,
                params.role.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let mut conn_str = response.data.uri;
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
        description = "Execute a query against a database (SQL for SQL publishers)",
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
        let bearer_token = self.bearer_token(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let conn_str = connection_string_with_database(&conn_response.data.uri, &params.database)?;

        // Use custom timeout if provided, otherwise default to QUERY_TIMEOUT (120s)
        let timeout = params
            .timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or(QUERY_TIMEOUT);

        let result = self
            .execute_sql(
                &conn_str,
                &params.query,
                vec![],
                Some(&bearer_token),
                timeout,
            )
            .await?;

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

        let bearer_token = self.bearer_token(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let conn_str = connection_string_with_database(&conn_response.data.uri, &params.database)?;

        // Use custom timeout if provided, otherwise default to QUERY_TIMEOUT (120s)
        let timeout = params
            .timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or(QUERY_TIMEOUT);

        let result = self
            .execute_sql_transaction(
                &conn_str,
                params.queries,
                params.read_only,
                params.isolation_level,
                params.deferrable,
                Some(&bearer_token),
                timeout,
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

        let bearer_token = self.bearer_token(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let conn_str = connection_string_with_database(&conn_response.data.uri, &params.database)?;

        let result = self
            .execute_sql(
                &conn_str,
                query,
                vec![schema.into()],
                Some(&bearer_token),
                QUERY_TIMEOUT,
            )
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

        let bearer_token = self.bearer_token(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let conn_str = connection_string_with_database(&conn_response.data.uri, &params.database)?;

        let result = self
            .execute_sql(
                &conn_str,
                &explain_query,
                vec![],
                Some(&bearer_token),
                QUERY_TIMEOUT,
            )
            .await?;

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

        let bearer_token = self.bearer_token(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let conn_response = api_client
            .seren_db_connection_uri(
                &params.path.project_id,
                Some(&params.path.branch_id),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let conn_str = connection_string_with_database(&conn_response.data.uri, &params.database)?;

        let result = self
            .execute_sql(
                &conn_str,
                query,
                vec![schema.into(), params.table_name.into()],
                Some(&bearer_token),
                QUERY_TIMEOUT,
            )
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List organizations accessible to the authenticated user",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_organizations(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let orgs = api_client
            .list_organizations()
            .into_mcp_result()
            .await?
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
            .seren_db_list_branches(&params.project_id)
            .into_mcp_result()
            .await?
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
            .seren_db_get_branch(&params.project_id, &params.branch_id)
            .into_mcp_result()
            .await?
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
            .seren_db_list_endpoints(&params.project_id, &params.branch_id)
            .into_mcp_result()
            .await?
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
            .seren_db_create_endpoint(
                &params.path.project_id,
                &params.path.branch_id,
                &params.body,
            )
            .into_mcp_result()
            .await?
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
            .seren_db_delete_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .into_mcp_result()
            .await?;
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
            .seren_db_start_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .into_mcp_result()
            .await?
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
            .seren_db_stop_endpoint(&params.project_id, &params.branch_id, &params.endpoint_id)
            .into_mcp_result()
            .await?;
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
            .seren_db_restart_endpoint(&params.project_id, &params.endpoint_id)
            .into_mcp_result()
            .await?;
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
            .into_mcp_result()
            .await?
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
            .into_mcp_result()
            .await?
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
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "API key {} revoked successfully",
            params.key_id
        ))]))
    }

    // ========================================================================
    // Seren Memory Publisher Tools
    // ========================================================================

    #[tool(
        description = "Check the Seren Memory publisher health.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_health(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_health().await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Bootstrap private Seren Memory context for a session.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_session_bootstrap(
        &self,
        Parameters(params): Parameters<seren::SerenMemorySessionBootstrapParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_session_bootstrap(&params).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Recall relevant private memories. Results may contain private content and should be handled accordingly.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_recall(
        &self,
        Parameters(params): Parameters<seren::SerenMemoryRecallParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_recall(&params).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Store durable private context in Seren Memory.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn seren_memory_remember(
        &self,
        Parameters(params): Parameters<seren::SerenMemoryRememberParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_remember(&params).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List the caller's private memories. Each result includes the memory's stored content.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_list_memories(
        &self,
        Parameters(params): Parameters<SerenMemoryListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_memory_list_memories(
                params.is_consolidated,
                params.is_pinned,
                params.lifecycle_status,
                params.limit,
                params.memory_type.as_deref(),
                params.offset,
                params.org_id.as_ref(),
                params.project_id.as_ref(),
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get one private Seren Memory entry by ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_get_memory(
        &self,
        Parameters(params): Parameters<SerenMemoryIdPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_get_memory(&params.memory_id).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Soft-delete one private Seren Memory entry.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn seren_memory_forget_memory(
        &self,
        Parameters(params): Parameters<SerenMemoryIdPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_memory_forget_memory(&seren::SerenMemoryForgetParams {
                memory_id: params.memory_id,
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Permanently delete one private Seren Memory entry.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn seren_memory_delete_memory(
        &self,
        Parameters(params): Parameters<SerenMemoryIdPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_memory_delete_memory(&params.memory_id)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List governed organizational knowledge domains available through Seren Memory.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_list_knowledge_domains(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_list_knowledge_domains().await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Search governed organizational knowledge through Seren Memory.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_search_knowledge(
        &self,
        Parameters(params): Parameters<seren::SerenMemorySearchKnowledgeRequest>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_search_knowledge(&params).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Open one governed organizational knowledge entity through Seren Memory.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_memory_open_knowledge_entity(
        &self,
        Parameters(params): Parameters<seren::SerenMemoryOpenKnowledgeEntityRequest>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_memory_open_knowledge_entity(&params).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    // ========================================================================
    // Seren Storage Publisher Tools
    // ========================================================================

    #[tool(
        description = "Check the Seren Storage publisher health.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_storage_health(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_storage_health().await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List buckets available through the Seren Storage publisher for the authenticated organization.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_storage_list_buckets(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_storage_list_buckets().await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List objects in a Seren Storage bucket, optionally filtered by key prefix.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_storage_list_objects(
        &self,
        Parameters(params): Parameters<SerenStorageListObjectsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_list_objects(
                &params.path.bucket_slug,
                params.cursor.as_deref(),
                None,
                params.limit,
                params.prefix.as_deref(),
                None,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a presigned upload through the Seren Storage publisher. Upload the bytes to upload_url, then call seren_storage_confirm_upload.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn seren_storage_create_upload(
        &self,
        Parameters(params): Parameters<SerenStorageCreateUploadParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_create_upload(&params.path.bucket_slug, &params.body)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Upload a base64-encoded object through the Seren Storage publisher in one call.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn seren_storage_put_object_base64(
        &self,
        Parameters(params): Parameters<SerenStoragePutObjectBase64Params>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_object_storage_key(&params.object_key)?;
        let metadata = validate_object_storage_metadata(params.metadata)?;
        let content = BASE64
            .decode(params.content_base64.as_bytes())
            .map_err(|error| {
                McpError::invalid_params(format!("Invalid content_base64: {error}"), None)
            })?;
        let byte_length = i64::try_from(content.len()).map_err(|_| {
            McpError::invalid_params("content_base64 decoded to an oversized object", None)
        })?;
        let sha256 = sha256_hex(&content);
        let content_type = params
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let api_client = self.api_client(&extensions)?;
        let upload = match api_client
            .seren_storage_create_upload(
                &params.path.bucket_slug,
                &seren::SerenStorageCreateObjectStorageUploadRequest {
                    byte_length,
                    checksum: seren::SerenStorageObjectStorageChecksum {
                        algorithm: seren::SerenStorageObjectStorageChecksumAlgorithm::Sha256,
                        value: sha256,
                    },
                    content_type: Some(content_type),
                    metadata,
                    object_key: params.object_key,
                },
            )
            .await
        {
            Ok(response) => response.into_inner().data,
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };

        let etag = put_presigned_object_storage_object(
            &upload.upload_url,
            &upload.upload_headers,
            content,
        )
        .await?;

        let response = match api_client
            .seren_storage_confirm_upload(
                &params.path.bucket_slug,
                &upload.object.id,
                &seren::SerenStorageConfirmObjectStorageUploadRequest { etag },
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Confirm a pending upload through the Seren Storage publisher.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn seren_storage_confirm_upload(
        &self,
        Parameters(params): Parameters<SerenStorageConfirmUploadParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_confirm_upload(
                &params.path.bucket_slug,
                &params.path.object_id,
                &params.body,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a presigned download URL for a Seren Storage object by key.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn seren_storage_download_object(
        &self,
        Parameters(params): Parameters<SerenStorageDownloadByKeyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_download_object(&params.path.bucket_slug, &params.object_key)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a presigned download URL for a Seren Storage object by ID.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn seren_storage_download_object_by_id(
        &self,
        Parameters(params): Parameters<SerenStorageObjectPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_download_object_by_id(&params.bucket_slug, &params.object_id)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete a Seren Storage object by ID.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn seren_storage_delete_object(
        &self,
        Parameters(params): Parameters<SerenStorageObjectPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_delete_object(&params.bucket_slug, &params.object_id)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List agent access grants on a Seren Storage bucket.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_storage_list_bucket_agent_grants(
        &self,
        Parameters(params): Parameters<SerenStorageBucketPath>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_list_bucket_agent_grants(&params.bucket_slug)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Grant or update an agent's access to a Seren Storage bucket. Permission is \"reader\" or \"writer\".",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn seren_storage_put_bucket_agent_grant(
        &self,
        Parameters(params): Parameters<SerenStorageAgentGrantParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_put_bucket_agent_grant(
                &params.path.bucket_slug,
                &params.agent_identity_id,
                &seren::SerenStoragePutObjectStorageBucketAgentGrantRequest {
                    permission: params.permission,
                },
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Revoke an agent's access to a Seren Storage bucket.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn seren_storage_delete_bucket_agent_grant(
        &self,
        Parameters(params): Parameters<SerenStorageAgentGrantSelectorParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        if let Err(error) = api_client
            .seren_storage_delete_bucket_agent_grant(
                &params.path.bucket_slug,
                &params.agent_identity_id,
            )
            .await
        {
            return Err(seren_error_to_mcp_error(error).await);
        }
        Ok(CallToolResult::success(vec![json_content(
            &serde_json::json!({
                "revoked": params.agent_identity_id,
            }),
        )?]))
    }

    #[tool(
        description = "List workspace snapshots for a deployment in a Seren Storage bucket.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn seren_storage_list_workspace_snapshots(
        &self,
        Parameters(params): Parameters<SerenStorageSnapshotListParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_list_workspace_snapshots(
                &params.path.bucket_slug,
                &params.deployment_id,
                params.limit,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Fetch the latest workspace snapshot for a deployment, including a presigned download URL for the archive.",
        annotations(read_only_hint = true, open_world_hint = true)
    )]
    async fn seren_storage_latest_workspace_snapshot(
        &self,
        Parameters(params): Parameters<SerenStorageSnapshotLatestParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_latest_workspace_snapshot(
                &params.path.bucket_slug,
                &params.deployment_id,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Record a workspace snapshot from an already-uploaded archive object in a Seren Storage bucket.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn seren_storage_create_workspace_snapshot(
        &self,
        Parameters(params): Parameters<SerenStorageSnapshotCreateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_storage_create_workspace_snapshot(&params.path.bucket_slug, &params.body)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    // Organization OAuth Provider Management Tools
    // ========================================================================

    #[tool(
        description = "List OAuth providers configured for an organization. These are BYOC (Bring Your Own Credentials) OAuth configurations that can be linked to publishers.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_org_oauth_providers(
        &self,
        Parameters(params): Parameters<ListOrgOAuthProvidersParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .list_org_oauth_providers(&params.organization_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get details about a specific OAuth provider configuration for an organization.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_org_oauth_provider(
        &self,
        Parameters(params): Parameters<GetOrgOAuthProviderParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .get_org_oauth_provider(&params.organization_id, &params.provider_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a new OAuth provider configuration for an organization. This enables BYOC (Bring Your Own Credentials) authentication for publishers.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_org_oauth_provider(
        &self,
        Parameters(params): Parameters<CreateOrgOAuthProviderParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&params.body.name, "OAuth provider name")?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .create_org_oauth_provider(&params.path.organization_id, &params.body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update an OAuth provider configuration for an organization.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_org_oauth_provider(
        &self,
        Parameters(params): Parameters<UpdateOrgOAuthProviderParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .update_org_oauth_provider(&params.organization_id, &params.provider_id, &params.body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete an OAuth provider configuration from an organization. Warning: This will break any publishers using this OAuth provider.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_org_oauth_provider(
        &self,
        Parameters(params): Parameters<DeleteOrgOAuthProviderParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        api_client
            .delete_org_oauth_provider(&params.organization_id, &params.provider_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "OAuth provider {} deleted successfully",
            params.provider_id
        ))]))
    }

    // ========================================================================
    // Private Model Tools
    // ========================================================================

    #[tool(
        description = "Get the private-model policy for an organization, including mode, allowed local/cloud agents, selected deployment, model IDs, provider restrictions, and private output/session database settings.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_private_models_policy(
        &self,
        Parameters(params): Parameters<GetPrivateModelsPolicyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .get_private_models_policy(&params.organization_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update the private-model policy for an organization. Provide mode plus any optional policy fields you need to change, such as deployment_id, model_id, ordered_model_ids, fallback_models, allowed agent flags, provider restrictions, private_output_policy, or session_database.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_private_models_policy(
        &self,
        Parameters(params): Parameters<UpdatePrivateModelsPolicyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .update_private_models_policy(&params.organization_id, &params.body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List OpenAI-compatible models available from the seren-private-models publisher.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_private_models(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .get_private_models()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List the private model catalog exposed through seren-agent, including the default model, catalog source, custom model support, and optional live-discovery region.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_seren_agent_private_models(
        &self,
        Parameters(params): Parameters<ListSerenAgentPrivateModelsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_private_models(params.region.as_deref())
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Send one non-streaming chat completion request to seren-private-models. Use message for a simple user prompt or messages for full OpenAI-compatible message objects.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn chat_private_models(
        &self,
        Parameters(params): Parameters<PrivateModelsChatParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let messages = match (params.message, params.messages) {
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "Provide either message or messages, not both.",
                    None,
                ));
            }
            (Some(message), None) => {
                let mut map = serde_json::Map::new();
                map.insert("role".to_string(), serde_json::json!("user"));
                map.insert("content".to_string(), serde_json::json!(message));
                vec![map]
            }
            (None, Some(messages)) if !messages.is_empty() => messages,
            (None, Some(_)) => {
                return Err(McpError::invalid_params(
                    "messages must not be empty.",
                    None,
                ));
            }
            (None, None) => {
                return Err(McpError::invalid_params(
                    "Provide message or messages.",
                    None,
                ));
            }
        };

        let mut request = serde_json::Map::new();
        request.insert(
            "messages".to_string(),
            serde_json::Value::Array(
                messages
                    .into_iter()
                    .map(serde_json::Value::Object)
                    .collect(),
            ),
        );
        request.insert("stream".to_string(), serde_json::Value::Bool(false));
        if let Some(model) = params.model {
            request.insert("model".to_string(), serde_json::Value::String(model));
        }
        if let Some(temperature) = params.temperature {
            request.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        if let Some(max_tokens) = params.max_tokens {
            request.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(top_p) = params.top_p {
            request.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if let Some(top_k) = params.top_k {
            request.insert("top_k".to_string(), serde_json::json!(top_k));
        }
        if let Some(response_schema) = params.response_schema {
            request.insert(
                "response_schema".to_string(),
                serde_json::Value::Object(response_schema),
            );
        }
        if let Some(tools) = params.tools {
            request.insert(
                "tools".to_string(),
                serde_json::Value::Array(
                    tools.into_iter().map(serde_json::Value::Object).collect(),
                ),
            );
        }
        let request = serde_json::from_value::<seren::PrivateModelsChatCompletionsRequest>(
            serde_json::Value::Object(request),
        )
        .map_err(|e| {
            McpError::invalid_params(format!("Invalid chat completions request: {e}"), None)
        })?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .post_chat_completions(&request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    // ========================================================================
    // Agent Store Tools (agent paid access)
    // ========================================================================

    #[tool(
        description = "List custom skills for an organization. Use include_archived=true to include archived skills, and q to filter by name, slug, or description.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_org_custom_skills(
        &self,
        Parameters(params): Parameters<ListOrgCustomSkillsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .list_custom_skills(
                &params.organization_id,
                params.include_archived,
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get one organization custom skill by ID, including its published and latest revision summaries.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_org_custom_skill(
        &self,
        Parameters(params): Parameters<GetOrgCustomSkillParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .get_custom_skill(&params.organization_id, &params.skill_id)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a new organization custom skill from inline skill files. The payload must include a root SKILL.md file in initial_revision.files.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_org_custom_skill(
        &self,
        Parameters(params): Parameters<CreateOrgCustomSkillParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .create_custom_skill(&params.path.organization_id, &params.body)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update organization custom skill metadata such as display name, description, or archived status.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_org_custom_skill(
        &self,
        Parameters(params): Parameters<UpdateOrgCustomSkillParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .update_custom_skill(&params.organization_id, &params.skill_id, &params.body)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List all revisions for an organization custom skill.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_org_custom_skill_revisions(
        &self,
        Parameters(params): Parameters<ListOrgCustomSkillRevisionsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .list_custom_skill_revisions(&params.organization_id, &params.skill_id)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get one custom skill revision, including its parsed manifest and full file metadata.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_org_custom_skill_revision(
        &self,
        Parameters(params): Parameters<GetOrgCustomSkillRevisionParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .get_custom_skill_revision(
                &params.organization_id,
                &params.skill_id,
                &params.revision_id,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a new revision for an organization custom skill from inline files. The payload must include a root SKILL.md file.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_org_custom_skill_revision(
        &self,
        Parameters(params): Parameters<CreateOrgCustomSkillRevisionParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .create_custom_skill_revision(
                &params.path.organization_id,
                &params.path.skill_id,
                &params.body,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Publish a custom skill revision so it becomes the active organization version consumed by clients.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn publish_org_custom_skill_revision(
        &self,
        Parameters(params): Parameters<PublishOrgCustomSkillRevisionParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .publish_custom_skill_revision(
                &params.organization_id,
                &params.skill_id,
                &params.revision_id,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Fetch one file from an organization custom skill revision. Text files are returned as base64 plus metadata so the caller can decode or preserve bytes exactly.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_org_custom_skill_revision_file(
        &self,
        Parameters(params): Parameters<GetOrgCustomSkillRevisionFileParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .get_custom_skill_revision_file(
                &params.organization_id,
                &params.skill_id,
                &params.revision_id,
                &params.file_path,
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Download a custom skill revision bundle as a base64-encoded tar.gz payload with size metadata. Prefer file-level access when you only need specific files.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn download_org_custom_skill_revision_bundle(
        &self,
        Parameters(params): Parameters<DownloadOrgCustomSkillRevisionBundleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .download_custom_skill_revision_bundle(
                &params.organization_id,
                &params.skill_id,
                &params.revision_id,
            )
            .await
        {
            Ok(response) => response,
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };

        let mut stream = response.into_inner().into_inner();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
        {
            bytes.extend_from_slice(&chunk);
        }

        let payload = serde_json::json!({
            "organization_id": params.organization_id,
            "skill_id": params.skill_id,
            "revision_id": params.revision_id,
            "content_type": "application/gzip",
            "bundle_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            "size_bytes": bytes.len(),
        });

        Ok(CallToolResult::success(vec![json_content(&payload)?]))
    }

    #[tool(
        description = "List active publishers in the agent store (compact by default). Set verbose=true for full publisher objects. For task-specific recommendations, use suggest_for_task instead.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_agent_publishers(
        &self,
        Parameters(params): Parameters<ListAgentPublishersParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;

        // Apply default limit of 20, max of 50 to prevent token overflow
        let limit = params.limit.unwrap_or(20).clamp(1, 50);
        let offset = params.offset.unwrap_or(0).max(0);

        // Parse category string to enum if provided
        let category =
            params
                .category
                .as_ref()
                .and_then(|c| match c.trim().to_ascii_lowercase().as_str() {
                    "database" => Some(seren::PublisherCategory::Database),
                    "integration" => Some(seren::PublisherCategory::Integration),
                    "compute" => Some(seren::PublisherCategory::Compute),
                    _ => None,
                });

        let response = api_client
            .list_store_publishers(
                category,
                params.is_verified,
                Some(limit),
                Some(offset),
                params.search.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();

        // Use pagination metadata from API response
        let publishers = response.data;
        let count = publishers.len();
        let total = Some(response.pagination.total as u64);
        let has_more = response.pagination.has_more;

        if params.verbose {
            let response = PublishersListResponse {
                publishers,
                total,
                count,
                limit,
                offset,
                has_more,
            };
            return Ok(CallToolResult::success(vec![json_content(&response)?]));
        }

        let entries = publishers
            .into_iter()
            .map(|p| {
                let pricing = p.pricing.as_ref().and_then(|configs| {
                    let config = configs
                        .iter()
                        .find(|c| c.asset_symbol.as_deref() == Some("USDC"))
                        .or_else(|| configs.first())?;
                    Some(PublisherPricingSummary {
                        asset_symbol: config.asset_symbol.clone(),
                        pricing_model: config.pricing_model,
                        base_price_per_1000_rows: config.base_price_per_1000_rows.clone(),
                        markup_multiplier: config.markup_multiplier.clone(),
                        min_charge: config.min_charge.clone(),
                        hourly_rate: config.hourly_rate.clone(),
                        price_per_call: config.price_per_call.clone(),
                        price_per_execution: config.price_per_execution.clone(),
                    })
                });

                let usage_example = p
                    .usage_examples
                    .as_ref()
                    .and_then(|examples| examples.first())
                    .cloned();

                PublisherListEntry {
                    slug: p.slug,
                    name: p.name,
                    description: p.description,
                    categories: p.categories,
                    is_verified: p.is_verified,
                    billing_model: p.billing_model,
                    publisher_category: p.publisher_category,
                    pricing,
                    usage_example,
                }
            })
            .collect::<Vec<_>>();

        let response = PublishersListResponse {
            publishers: entries,
            total,
            count,
            limit,
            offset,
            has_more,
        };

        Ok(CallToolResult::success(vec![json_content(&response)?]))
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
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let publisher = api_client
            .get_store_publisher(&params.slug)
            .await
            .map_err(|e| {
                // Check status code directly instead of string matching
                if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    McpError::internal_error(
                        format!(
                            "Publisher '{}' not found. Use list_agent_publishers to see available publishers and their slugs.",
                            params.slug
                        ),
                        None,
                    )
                } else {
                    McpError::internal_error(e.to_string(), None)
                }
            })?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&publisher)?]))
    }

    #[tool(
        description = "Get publisher and agent recommendations for a task. Call this BEFORE using WebSearch/WebFetch to check if a Seren publisher can do the task better. Examples: 'scrape website' returns Firecrawl, 'research topic' returns Perplexity, 'AI search' returns Perplexity. Note: Agent templates are coming soon.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn suggest_for_task(
        &self,
        Parameters(params): Parameters<SuggestForTaskParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let limit = params.limit.map(|l| l.min(10));
        let query_type = params.r#type.as_deref();

        let response = api_client
            .suggest_publishers(limit, &params.query, query_type)
            .await
            .map_err(|e| McpError::internal_error(format!("Suggest API failed: {}", e), None))?
            .into_inner();

        // Return the response data
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Estimate the cost of a publisher query payload without executing it",
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
            .estimate_query(&params.publisher, &body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&estimate)?]))
    }

    #[tool(
        description = "Get your SerenBucks balance. SerenBucks are credits used to pay for API calls and database queries.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_prepaid_balance(
        &self,
        Parameters(_params): Parameters<GetUserPrepaidBalanceParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let balance = api_client
            .get_wallet_balance()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&balance)?]))
    }

    #[tool(
        description = "Get your wallet balance and SerenBucks funding breakdown.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_wallet_status(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let balance = api_client
            .get_wallet_balance()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&balance)?]))
    }

    #[tool(
        description = "Deposit SerenBucks with a credit card via Stripe. Returns a checkout URL to complete payment. After payment, SerenBucks are automatically added to your balance.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_prepaid_deposit(
        &self,
        Parameters(params): Parameters<CreatePrepaidDepositParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let amount_cents = match &params.amount_usd {
            UsdAmount::String(s) => parse_usd_to_cents(s)
                .map_err(|e| McpError::invalid_request(format!("Invalid amount_usd: {e}"), None))?,
            UsdAmount::Number(n) => usd_f64_to_cents(*n)
                .map_err(|e| McpError::invalid_request(format!("Invalid amount_usd: {e}"), None))?,
        };

        if amount_cents <= 0 {
            return Err(McpError::invalid_request(
                "Amount must be positive.".to_string(),
                None,
            ));
        }
        if amount_cents < 500 {
            return Err(McpError::invalid_request(
                "Minimum deposit is $5.00.".to_string(),
                None,
            ));
        }

        let request = seren::DepositRequest {
            amount_cents,
            referral_code: None,
        };

        let deposit = api_client
            .create_deposit(&request)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&deposit)?]))
    }

    #[tool(
        description = "Preview a SerenBucks wallet transfer before sending it. Returns whether the transfer would settle instantly or create an invite.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn preview_wallet_transfer(
        &self,
        Parameters(params): Parameters<WalletTransferRequestParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let request =
            wallet_transfer_request(params.recipient_email, &params.amount_usd, params.memo)?;

        let preview = api_client
            .preview_wallet_transfer(&request)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&preview)?]))
    }

    #[tool(
        description = "Send SerenBucks to an email address. Existing verified users receive funds immediately; other recipients receive a pending invite.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn execute_wallet_transfer(
        &self,
        Parameters(params): Parameters<ExecuteWalletTransferParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let request =
            wallet_transfer_request(params.recipient_email, &params.amount_usd, params.memo)?;
        let idempotency_key = params.idempotency_key.trim();
        if idempotency_key.is_empty() {
            return Err(McpError::invalid_request(
                "idempotency_key must not be empty".to_string(),
                None,
            ));
        }

        let transfer = api_client
            .execute_wallet_transfer(idempotency_key, &request)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&transfer)?]))
    }

    #[tool(
        description = "List SerenBucks wallet transfers with optional direction, status, cursor, and limit filters.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_wallet_transfers(
        &self,
        Parameters(params): Parameters<ListWalletTransfersParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let direction = params
            .direction
            .as_deref()
            .map(str::parse::<seren::WalletTransferDirection>)
            .transpose()
            .map_err(|_| {
                McpError::invalid_request(
                    "Invalid direction. Use sent, received, or all.".to_string(),
                    None,
                )
            })?;

        let transfers = api_client
            .list_wallet_transfers(
                params.cursor.as_deref(),
                direction,
                params.limit,
                params.status.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&transfers)?]))
    }

    #[tool(
        description = "Claim a pending SerenBucks transfer invite using the raw invite token.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn claim_wallet_transfer(
        &self,
        Parameters(params): Parameters<ClaimWalletTransferParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let request = seren::WalletTransferClaimRequest {
            token: params.token,
        };

        let claim = api_client
            .claim_wallet_transfer(&request)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&claim)?]))
    }

    #[tool(
        description = "Recall a pending outbound SerenBucks transfer and refund the sender.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn recall_wallet_transfer(
        &self,
        Parameters(params): Parameters<RecallWalletTransferParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let recall = api_client
            .recall_wallet_transfer(&params.pending_transfer_id)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&recall)?]))
    }

    // NOTE: User geographic routing tools (list_user_routing, get_user_routing,
    // enable_user_routing, disable_user_routing) were removed from the API.
    // Geographic routing is now configured at the publisher level via the
    // routing field in CreatePublisherRequest/UpdatePublisherRequest.

    // =========================================================================
    // Unified Publisher Tool
    // =========================================================================

    #[tool(
        description = "Call a publisher to execute queries, API requests, or MCP operations. This unified tool automatically routes based on parameters:

- DATABASE publishers: provide `query` (SQL) and optionally `database`
- API publishers: provide `method`, `path`, `headers`, `body`
- MCP publishers: provide `tool` + `tool_args` OR `resource_uri`
- Built-in Seren Passwords helper tools: use publisher \"seren-passwords\" with tool \"passwords_vaults_list\", \"passwords_items_list\", or \"passwords_item_get\"

Examples:
- Database: call_publisher(publisher: \"my-db\", query: \"SELECT * FROM users\")
- API: call_publisher(publisher: \"firecrawl\", method: \"POST\", path: \"/scrape\", body: {url: \"...\"})
- MCP tool: call_publisher(publisher: \"my-mcp\", tool: \"search\", tool_args: {query: \"...\"})
- Seren Passwords helper: call_publisher(publisher: \"seren-passwords\", tool: \"passwords_vaults_list\")
- MCP resource: call_publisher(publisher: \"my-mcp\", resource_uri: \"file:///data.json\")",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = true
        )
    )]
    async fn call_publisher(
        &self,
        Parameters(params): Parameters<CallPublisherParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let agent_metadata = extract_agent_metadata_from_extensions(&extensions);
        let return_text = params.response_format.as_deref() == Some("text");

        let selector_count = (params.query.is_some() as u8)
            + (params.tool.is_some() as u8)
            + (params.resource_uri.is_some() as u8);
        if selector_count > 1 {
            return Err(McpError::invalid_params(
                "call_publisher: provide only one of 'query', 'tool', or 'resource_uri'"
                    .to_string(),
                None,
            ));
        }
        if params.tool_args.is_some() && params.tool.is_none() {
            return Err(McpError::invalid_params(
                "call_publisher: 'tool_args' requires 'tool'".to_string(),
                None,
            ));
        }
        if params.database.is_some() && params.query.is_none() {
            return Err(McpError::invalid_params(
                "call_publisher: 'database' requires 'query'".to_string(),
                None,
            ));
        }

        // Determine operation type from parameters
        let operation = if params.query.is_some() {
            PublisherOperation::Database
        } else if params.tool.is_some() {
            PublisherOperation::McpTool
        } else if params.resource_uri.is_some() {
            PublisherOperation::McpResource
        } else {
            PublisherOperation::Api
        };

        match operation {
            PublisherOperation::Database => {
                self.call_publisher_database(&params, &extensions, &agent_metadata, return_text)
                    .await
            }
            PublisherOperation::Api => {
                self.call_publisher_api(&params, &extensions, &agent_metadata, return_text)
                    .await
            }
            PublisherOperation::McpTool => {
                self.call_publisher_mcp_tool(&params, &extensions, &agent_metadata, return_text)
                    .await
            }
            PublisherOperation::McpResource => {
                self.call_publisher_mcp_resource(&params, &extensions, &agent_metadata, return_text)
                    .await
            }
        }
    }

    /// Handle database publisher calls (internal helper for call_publisher)
    async fn call_publisher_database(
        &self,
        params: &CallPublisherParams,
        extensions: &Extensions,
        agent_metadata: &AgentMetadata,
        return_text: bool,
    ) -> Result<CallToolResult, McpError> {
        let query = params.query.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "query is required for database operations".to_string(),
                None,
            )
        })?;

        let body = seren::DatabaseQueryRequest {
            query: query.clone(),
            database: params.database.clone(),
            params: vec![],
        };
        let publisher_path = format!("/publishers/{}", params.publisher);

        // Payment proxy mode
        if let Some(ref x402_payment) = params.x402_payment {
            if return_text {
                let text = self
                    .execute_with_proxy_payment_text(
                        &reqwest::Method::POST,
                        &publisher_path,
                        Some(&body),
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![Content::text(text)]));
            } else {
                let result = self
                    .execute_with_proxy_payment_json(
                        &reqwest::Method::POST,
                        &publisher_path,
                        Some(&body),
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![json_content(&result)?]));
            }
        }

        let root_body: seren::PublisherRootRequest = body.clone().into();

        // Retry loop with exponential backoff
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let query_result: Result<(), seren::Error<()>> = if return_text {
                let query_response = self
                    .execute_publisher_proxy_raw(
                        extensions,
                        agent_metadata,
                        QUERY_TIMEOUT,
                        &reqwest::Method::POST,
                        &publisher_path,
                        Some(&body),
                        None,
                        None,
                        params.request_id,
                        None,
                    )
                    .await;

                match query_response {
                    Ok(resp) if resp.status().is_success() => {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![Content::text(text)]));
                    }
                    Ok(resp) => Err(seren::Error::UnexpectedResponse(resp)),
                    Err(e) => Err(e),
                }
            } else {
                match self.api_client_with_timeout_request_id(
                    extensions,
                    QUERY_TIMEOUT,
                    params.request_id,
                ) {
                    Ok(api_client) => {
                        match api_client
                            .publisher_root_handler(&params.publisher, &root_body)
                            .await
                        {
                            Ok(response) => {
                                let result = serde_json::to_value(response.into_inner())
                                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                                return Ok(CallToolResult::success(vec![json_content(&result)?]));
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(seren::Error::InvalidRequest(e.to_string())),
                }
            };

            match query_result {
                Ok(_) => unreachable!(),
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        last_error = Some(e);
                        continue;
                    }
                    return self
                        .handle_call_publisher_error(
                            e,
                            CallPublisherErrorContext {
                                publisher: &params.publisher,
                                publisher_type: "database",
                                confirm: params.confirm,
                                request_id: params.request_id,
                                method: &reqwest::Method::POST,
                                publisher_path: &publisher_path,
                                query_string: None,
                                body: Some(&body),
                                raw_body: None,
                                headers: None,
                                agent_metadata,
                                return_text,
                            },
                        )
                        .await;
                }
            }
        }

        Err(McpError::internal_error(
            format!(
                "Query failed after {} retries: {}",
                MAX_RETRIES,
                last_error.map(|e| e.to_string()).unwrap_or_default()
            ),
            None,
        ))
    }

    /// Handle API publisher calls (internal helper for call_publisher)
    async fn call_publisher_api(
        &self,
        params: &CallPublisherParams,
        extensions: &Extensions,
        agent_metadata: &AgentMetadata,
        return_text: bool,
    ) -> Result<CallToolResult, McpError> {
        if params.body.is_some() && params.body_base64.is_some() {
            return Err(McpError::invalid_params(
                "call_publisher: provide only one of 'body' or 'body_base64'".to_string(),
                None,
            ));
        }
        let raw_body = decode_call_publisher_body_base64(params.body_base64.as_deref())?;
        let normalized_body = if raw_body.is_some() {
            None
        } else {
            normalize_api_request_body(params.body.as_ref())
        };
        let body = normalized_body.as_deref();
        let raw_body_ref = raw_body.as_deref();
        // Keep wildcard proxy calls manual for now:
        // we need dynamic HTTP methods, request-scoped passthrough headers, and
        // per-call x-request-id support that generated OpenAPI methods do not expose.
        let publisher_path = match &params.path {
            Some(p) if !p.is_empty() => format!(
                "/publishers/{}/{}",
                params.publisher,
                p.trim_start_matches('/')
            ),
            _ => format!("/publishers/{}", params.publisher),
        };
        let method = params.method.as_deref().unwrap_or("POST");
        let method = match method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            _ => {
                return Err(McpError::invalid_params(
                    "Invalid method. Use GET, POST, PUT, DELETE, or PATCH.".to_string(),
                    None,
                ));
            }
        };

        // Payment proxy mode
        if let Some(ref x402_payment) = params.x402_payment {
            if return_text {
                let text = self
                    .execute_with_proxy_payment_text(
                        &method,
                        &publisher_path,
                        body,
                        raw_body_ref,
                        params.headers.as_ref(),
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![Content::text(text)]));
            } else {
                let result = self
                    .execute_with_proxy_payment_json(
                        &method,
                        &publisher_path,
                        body,
                        raw_body_ref,
                        params.headers.as_ref(),
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![json_content(&result)?]));
            }
        }

        // Retry loop
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let api_response = self
                .execute_publisher_proxy_raw(
                    extensions,
                    agent_metadata,
                    QUERY_TIMEOUT,
                    &method,
                    &publisher_path,
                    body,
                    raw_body_ref,
                    params.headers.as_ref(),
                    params.request_id,
                    None,
                )
                .await;

            let api_result: Result<(), seren::Error<()>> = match api_response {
                Ok(resp) if resp.status().is_success() => {
                    if return_text {
                        // Collect streaming response as text
                        use futures::StreamExt;
                        let stream = resp.bytes_stream();
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
                        let text = String::from_utf8_lossy(&collected).to_string();
                        return Ok(CallToolResult::success(vec![Content::text(text)]));
                    } else {
                        let result: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![json_content(&result)?]));
                    }
                }
                Ok(resp) => Err(seren::Error::UnexpectedResponse(resp)),
                Err(e) => Err(e),
            };

            match api_result {
                Ok(_) => unreachable!(),
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        last_error = Some(e);
                        continue;
                    }
                    return self
                        .handle_call_publisher_error(
                            e,
                            CallPublisherErrorContext {
                                publisher: &params.publisher,
                                publisher_type: "api",
                                confirm: params.confirm,
                                request_id: params.request_id,
                                method: &method,
                                publisher_path: &publisher_path,
                                query_string: None,
                                body,
                                raw_body: raw_body_ref,
                                headers: params.headers.as_ref(),
                                agent_metadata,
                                return_text,
                            },
                        )
                        .await;
                }
            }
        }

        Err(McpError::internal_error(
            format!(
                "API call failed after {} retries: {}",
                MAX_RETRIES,
                last_error.map(|e| e.to_string()).unwrap_or_default()
            ),
            None,
        ))
    }

    /// Handle MCP tool calls (internal helper for call_publisher)
    async fn call_publisher_mcp_tool(
        &self,
        params: &CallPublisherParams,
        extensions: &Extensions,
        agent_metadata: &AgentMetadata,
        return_text: bool,
    ) -> Result<CallToolResult, McpError> {
        let tool_name = params.tool.as_ref().ok_or_else(|| {
            McpError::invalid_params("tool is required for MCP tool operations".to_string(), None)
        })?;

        let tool_path = tool_name.trim_start_matches('/');
        if tool_path.is_empty() {
            return Err(McpError::invalid_params(
                "tool cannot be empty".to_string(),
                None,
            ));
        }

        if params.publisher == "seren-passwords"
            && let Some(result) = self
                .call_builtin_passwords_tool(
                    tool_path,
                    params.tool_args.clone(),
                    extensions.clone(),
                )
                .await
        {
            return result;
        }

        let body = serde_json::Value::Object(params.tool_args.clone().unwrap_or_default());
        let publisher_path = format!("/publishers/{}/_mcp/tools/{}", params.publisher, tool_path);

        // Payment proxy mode
        if let Some(ref x402_payment) = params.x402_payment {
            if return_text {
                let text = self
                    .execute_with_proxy_payment_text(
                        &reqwest::Method::POST,
                        &publisher_path,
                        Some(&body),
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![Content::text(text)]));
            } else {
                let result = self
                    .execute_with_proxy_payment_json(
                        &reqwest::Method::POST,
                        &publisher_path,
                        Some(&body),
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        None,
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![json_content(&result)?]));
            }
        }

        // Retry loop
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let tool_response = self
                .execute_publisher_proxy_raw(
                    extensions,
                    agent_metadata,
                    API_TIMEOUT,
                    &reqwest::Method::POST,
                    &publisher_path,
                    Some(&body),
                    None,
                    None,
                    params.request_id,
                    None,
                )
                .await;

            let tool_result: Result<(), seren::Error<()>> = match tool_response {
                Ok(resp) if resp.status().is_success() => {
                    if return_text {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![Content::text(text)]));
                    } else {
                        let result: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![json_content(&result)?]));
                    }
                }
                Ok(resp) => Err(seren::Error::UnexpectedResponse(resp)),
                Err(e) => Err(e),
            };

            match tool_result {
                Ok(_) => unreachable!(),
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        last_error = Some(e);
                        continue;
                    }

                    match e {
                        seren::Error::UnexpectedResponse(response)
                            if response.status() == reqwest::StatusCode::NOT_FOUND =>
                        {
                            return Err(McpError::internal_error(
                                format!(
                                    "Publisher '{}' or tool '{}' not found. Use list_mcp_tools to see available tools.",
                                    params.publisher, tool_name
                                ),
                                None,
                            ));
                        }
                        seren::Error::UnexpectedResponse(response)
                            if response.status() == reqwest::StatusCode::BAD_REQUEST =>
                        {
                            let body_text = response.text().await.unwrap_or_default();
                            return Err(McpError::invalid_params(
                                format!(
                                    "MCP tool call failed ({}): {}",
                                    reqwest::StatusCode::BAD_REQUEST,
                                    truncate_for_client(&body_text, 1200)
                                ),
                                None,
                            ));
                        }
                        _ => {
                            return self
                                .handle_call_publisher_error(
                                    e,
                                    CallPublisherErrorContext {
                                        publisher: &params.publisher,
                                        publisher_type: "mcp tool",
                                        confirm: params.confirm,
                                        request_id: params.request_id,
                                        method: &reqwest::Method::POST,
                                        publisher_path: &publisher_path,
                                        query_string: None,
                                        body: Some(&body),
                                        raw_body: None,
                                        headers: None,
                                        agent_metadata,
                                        return_text,
                                    },
                                )
                                .await;
                        }
                    }
                }
            }
        }

        Err(McpError::internal_error(
            format!(
                "MCP tool call failed after {} retries: {}",
                MAX_RETRIES,
                last_error.map(|e| e.to_string()).unwrap_or_default()
            ),
            None,
        ))
    }

    /// Handle MCP resource reads (internal helper for call_publisher)
    async fn call_publisher_mcp_resource(
        &self,
        params: &CallPublisherParams,
        extensions: &Extensions,
        agent_metadata: &AgentMetadata,
        return_text: bool,
    ) -> Result<CallToolResult, McpError> {
        let uri = params.resource_uri.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "resource_uri is required for MCP resource operations".to_string(),
                None,
            )
        })?;
        if uri.trim().is_empty() {
            return Err(McpError::invalid_params(
                "resource_uri cannot be empty".to_string(),
                None,
            ));
        }

        let encoded_uri = urlencoding::encode(uri);
        let publisher_path = format!("/publishers/{}/_mcp/resources", params.publisher);
        let query_string = format!("uri={}", encoded_uri);
        let method = reqwest::Method::GET;

        // Payment proxy mode
        if let Some(ref x402_payment) = params.x402_payment {
            if return_text {
                let text = self
                    .execute_with_proxy_payment_text::<serde_json::Value>(
                        &method,
                        &publisher_path,
                        None,
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        Some(&query_string),
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![Content::text(text)]));
            } else {
                let result = self
                    .execute_with_proxy_payment_json::<serde_json::Value>(
                        &method,
                        &publisher_path,
                        None,
                        None,
                        None,
                        params.request_id,
                        x402_payment,
                        agent_metadata,
                        Some(&query_string),
                    )
                    .await?;
                return Ok(CallToolResult::success(vec![json_content(&result)?]));
            }
        }

        // Retry loop
        let mut last_error = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = RETRY_BASE_DELAY * 2u32.pow(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let resource_response = self
                .execute_publisher_proxy_raw::<serde_json::Value>(
                    extensions,
                    agent_metadata,
                    API_TIMEOUT,
                    &method,
                    &publisher_path,
                    None,
                    None,
                    None,
                    params.request_id,
                    Some(&query_string),
                )
                .await;

            let resource_result: Result<(), seren::Error<()>> = match resource_response {
                Ok(resp) if resp.status().is_success() => {
                    if return_text {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![Content::text(text)]));
                    } else {
                        let result: serde_json::Value = resp
                            .json()
                            .await
                            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        return Ok(CallToolResult::success(vec![json_content(&result)?]));
                    }
                }
                Ok(resp) => Err(seren::Error::UnexpectedResponse(resp)),
                Err(e) => Err(e),
            };

            match resource_result {
                Ok(_) => unreachable!(),
                Err(e) => {
                    if is_retryable_error(&e) && attempt < MAX_RETRIES {
                        last_error = Some(e);
                        continue;
                    }

                    match e {
                        seren::Error::UnexpectedResponse(response)
                            if response.status() == reqwest::StatusCode::NOT_FOUND =>
                        {
                            return Err(McpError::internal_error(
                                format!(
                                    "Publisher '{}' or resource '{}' not found. Use list_mcp_resources to see available resources.",
                                    params.publisher, uri
                                ),
                                None,
                            ));
                        }
                        seren::Error::UnexpectedResponse(response)
                            if response.status() == reqwest::StatusCode::BAD_REQUEST =>
                        {
                            let body_text = response.text().await.unwrap_or_default();
                            return Err(McpError::invalid_params(
                                format!(
                                    "MCP resource read failed ({}): {}",
                                    reqwest::StatusCode::BAD_REQUEST,
                                    truncate_for_client(&body_text, 1200)
                                ),
                                None,
                            ));
                        }
                        _ => {
                            return self
                                .handle_call_publisher_error::<serde_json::Value>(
                                    e,
                                    CallPublisherErrorContext {
                                        publisher: &params.publisher,
                                        publisher_type: "mcp resource",
                                        confirm: params.confirm,
                                        request_id: params.request_id,
                                        method: &method,
                                        publisher_path: &publisher_path,
                                        query_string: Some(&query_string),
                                        body: None,
                                        raw_body: None,
                                        headers: None,
                                        agent_metadata,
                                        return_text,
                                    },
                                )
                                .await;
                        }
                    }
                }
            }
        }

        Err(McpError::internal_error(
            format!(
                "MCP resource read failed after {} retries: {}",
                MAX_RETRIES,
                last_error.map(|e| e.to_string()).unwrap_or_default()
            ),
            None,
        ))
    }

    /// Handle errors from call_publisher with x402 payment flow
    async fn handle_call_publisher_error<T: Serialize>(
        &self,
        error: seren::Error<()>,
        ctx: CallPublisherErrorContext<'_, T>,
    ) -> Result<CallToolResult, McpError> {
        match error {
            seren::Error::UnexpectedResponse(response) => {
                let status = response.status();
                if status == reqwest::StatusCode::PAYMENT_REQUIRED {
                    let payment_required_header = response
                        .headers()
                        .get("PAYMENT-REQUIRED")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let body_text = response.text().await.unwrap_or_default();
                    let has_x402_option = payment_required_header.is_some()
                        || payment_required_has_non_prepaid_option(&body_text);

                    if self.wallet.is_some() && has_x402_option {
                        if ctx.return_text {
                            let text = self
                                .execute_x402_roundtrip_text(
                                    ctx.method,
                                    ctx.publisher_path,
                                    ctx.body,
                                    ctx.raw_body,
                                    ctx.headers,
                                    ctx.request_id,
                                    ctx.confirm,
                                    ctx.agent_metadata,
                                    ctx.query_string,
                                )
                                .await?;
                            return Ok(CallToolResult::success(vec![Content::text(text)]));
                        } else {
                            let result = self
                                .execute_x402_roundtrip_json(
                                    ctx.method,
                                    ctx.publisher_path,
                                    ctx.body,
                                    ctx.raw_body,
                                    ctx.headers,
                                    ctx.request_id,
                                    ctx.confirm,
                                    ctx.agent_metadata,
                                    ctx.query_string,
                                )
                                .await?;
                            return Ok(CallToolResult::success(vec![json_content(&result)?]));
                        }
                    }

                    if has_x402_option {
                        return Err(McpError::invalid_request(
                            format_payment_proxy_error(
                                &body_text,
                                payment_required_header.as_deref(),
                            ),
                            None,
                        ));
                    }

                    return Err(McpError::invalid_request(
                        format_payment_required_body(status, &body_text),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::CONFLICT {
                    return Err(McpError::invalid_request(
                        "Duplicate request_id. Provide a new UUID and retry.".to_string(),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(McpError::internal_error(
                        format!(
                            "Publisher '{}' {} endpoint returned 404. Use get_agent_publisher to check the publisher's category.",
                            ctx.publisher, ctx.publisher_type
                        ),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::BAD_REQUEST {
                    let body_text = response.text().await.unwrap_or_default();
                    // Provide helpful messages for category mismatches
                    if body_text.contains("not a database category publisher") {
                        return Err(McpError::invalid_request(
                            format!(
                                "Publisher '{}' is not a database publisher. Remove the 'query' parameter and use 'method'/'path' for API calls instead.",
                                ctx.publisher
                            ),
                            None,
                        ));
                    }
                    if body_text.contains("not an integration category publisher") {
                        return Err(McpError::invalid_request(
                            format!(
                                "Publisher '{}' is a database publisher. Use the 'query' parameter instead of 'method'/'path'.",
                                ctx.publisher
                            ),
                            None,
                        ));
                    }
                    return Err(McpError::internal_error(
                        format!(
                            "{} call failed ({}): {}",
                            ctx.publisher_type,
                            status,
                            truncate_for_client(&body_text, 1200)
                        ),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::FORBIDDEN {
                    let body_text = response.text().await.unwrap_or_default();
                    if body_text.contains("geo_restricted") {
                        if let Ok(geo_error) = serde_json::from_str::<serde_json::Value>(&body_text)
                        {
                            let publisher = geo_error
                                .get("publisher")
                                .and_then(|v| v.as_str())
                                .unwrap_or(ctx.publisher);
                            let region_raw = geo_error
                                .get("proxy_region")
                                .and_then(|v| v.as_str())
                                .unwrap_or("EU");
                            let region = region_raw.to_ascii_uppercase();
                            let endpoint = geo_error
                                .get("opt_in_endpoint")
                                .and_then(|v| v.as_str())
                                .unwrap_or("publisher routing opt-in endpoint (not provided)");

                            tracing::info!(
                                publisher = %publisher,
                                region = %region,
                                endpoint = %endpoint,
                                "Geo-restricted: user has not opted in"
                            );
                            #[cfg(feature = "telemetry")]
                            crate::metrics::GEO_RESTRICTED
                                .with_label_values(&[publisher, region.as_str()])
                                .inc();

                            return Err(McpError::invalid_request(
                                format!(
                                    "Publisher '{publisher}' requires geographic routing via region {region}, but you have not opted in.\n\
Configure publisher routing (via create_publisher/update_publisher `routing`) or call the API endpoint directly.\n\
API endpoint: {endpoint}",
                                ),
                                None,
                            ));
                        }
                        return Err(McpError::invalid_request(
                            format!(
                                "Publisher '{}' requires geographic routing opt-in. \
                                Check the error details for the opt-in endpoint.",
                                ctx.publisher
                            ),
                            None,
                        ));
                    }
                    return Err(McpError::internal_error(
                        format!(
                            "{} call failed ({}): {}",
                            ctx.publisher_type,
                            status,
                            truncate_for_client(&body_text, 1200)
                        ),
                        None,
                    ));
                }
                let body = response.text().await.unwrap_or_default();
                Err(McpError::internal_error(
                    format!(
                        "{} call failed ({}): {}",
                        ctx.publisher_type,
                        status,
                        truncate_for_client(&body, 1200)
                    ),
                    None,
                ))
            }
            _ => {
                if let Some(status) = error.status()
                    && status == reqwest::StatusCode::CONFLICT
                {
                    return Err(McpError::invalid_request(
                        "Duplicate request_id. Provide a new UUID and retry.".to_string(),
                        None,
                    ));
                }
                Err(McpError::internal_error(error.to_string(), None))
            }
        }
    }

    // =========================================================================
    // Legacy Publisher Tools (Deprecated - use call_publisher instead)
    // =========================================================================

    // ========================================================================
    // Local Wallet Tools (for users running seren-mcp locally)
    // ========================================================================

    #[tool(
        description = "Get the local wallet address. Only available when running seren-mcp locally with WALLET_PRIVATE_KEY environment variable set. Returns the EVM wallet address derived from the private key.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_local_wallet_address(&self) -> Result<CallToolResult, McpError> {
        let wallet = self.wallet.as_ref().ok_or_else(|| {
            McpError::invalid_request(
                "Local wallet not configured. Set WALLET_PRIVATE_KEY environment variable."
                    .to_string(),
                None,
            )
        })?;

        let address = wallet.address().to_string();
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
        let has_wallet = self.wallet.is_some();
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
        description = "Get the configured local wallet's on-chain status on Base, including address, ETH balance, and USDC balance.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_onchain_wallet_status(&self) -> Result<CallToolResult, McpError> {
        let wallet = self.wallet.as_ref().ok_or_else(|| {
            McpError::invalid_request(
                "Local wallet not configured. Set WALLET_PRIVATE_KEY environment variable."
                    .to_string(),
                None,
            )
        })?;

        let status = self
            .fetch_onchain_wallet_status(&Self::base_rpc_url(), wallet)
            .await?;
        Ok(CallToolResult::success(vec![json_content(&status)?]))
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

        let url = format!("{}/wallet/deposit/crypto", self.api_base_url);
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
    // Additional Agent Store Tools
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
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&supported)?]))
    }

    #[tool(
        description = "Create a new publisher in the agent store. Publishers provide databases or APIs that AI agents can query with micropayments. Requires API key authentication (organization-level).",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_publisher(
        &self,
        Parameters(params): Parameters<CreatePublisherParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let CreatePublisherParams {
            organization_id,
            name,
            slug,
            email,
            wallet_address,
            wallet_network_id,
            publisher_category,
            database_type,
            integration_type,
            description,
            api_url,
            mcp_endpoint,
            project_id,
            branch_id,
            database_name,
            connection_string,
            database_config,
            base_price_per_1000_rows,
            price_per_call,
            price_per_execution,
            price_per_get,
            price_per_post,
            price_per_put,
            price_per_patch,
            price_per_delete,
            billing_model,
            categories,
            logo_url,
            request_content_type,
            upstream_headers,
            allowed_passthrough_headers,
            passthrough_header_rewrite,
            endpoints,
            undocumented_endpoint_policy,
            token_exchange_url,
            token_exchange_method,
            token_exchange_mode,
            token_cache_ttl_seconds,
            token_response_field,
            upstream_api_key,
            api_key_header,
            api_key_query_param,
            auth_type,
            oauth2_token_url,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_scopes,
            use_cases,
            resource_name,
            resource_description,
            oauth_provider_slug,
            requires_user_oauth,
            upstream_cost_response_path,
        } = params;

        ensure_writes_allowed(&extensions)?;
        validate_resource_name(&name, "Publisher name")?;
        validate_slug(&slug, "Publisher slug")?;
        if wallet_address.trim().is_empty() {
            return Err(McpError::invalid_params(
                "wallet_address must not be empty",
                None,
            ));
        }
        if wallet_network_id.trim().is_empty() {
            return Err(McpError::invalid_params(
                "wallet_network_id must not be empty",
                None,
            ));
        }

        let name = name.trim().to_string();
        let slug = slug.trim().to_string();
        let wallet_address = wallet_address.trim().to_string();
        let wallet_network_id = wallet_network_id.trim().to_ascii_lowercase();

        let publisher_category_enum = seren::parse_publisher_category(&publisher_category)
            .map_err(|e| McpError::invalid_request(e.to_string(), None))?;
        let database_type_enum = seren::parse_database_type(database_type.as_deref())
            .map_err(|e| McpError::invalid_request(e.to_string(), None))?;
        let integration_type_enum = seren::parse_integration_type(integration_type.as_deref())
            .map_err(|e| McpError::invalid_request(e.to_string(), None))?;

        let endpoints = match endpoints {
            None => None,
            Some(endpoints) => Some(
                endpoints
                    .into_iter()
                    .map(endpoint_param_to_definition)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };

        let undocumented_endpoint_policy =
            parse_undocumented_endpoint_policy(undocumented_endpoint_policy)?;

        let token_exchange_url =
            normalize_nonempty_optional_string(token_exchange_url, "token_exchange_url")?;
        if let Some(ref url) = token_exchange_url
            && !url.starts_with("https://")
        {
            return Err(McpError::invalid_params(
                "token_exchange_url must use HTTPS",
                None,
            ));
        }
        let token_exchange_method = normalize_token_exchange_method(token_exchange_method)?;
        let token_exchange_mode = normalize_token_exchange_mode(token_exchange_mode)?;
        let token_cache_ttl_seconds = validate_token_cache_ttl_seconds(token_cache_ttl_seconds)?;
        let token_response_field =
            normalize_nonempty_optional_string(token_response_field, "token_response_field")?;

        if token_exchange_url.is_none()
            && (token_exchange_method.is_some()
                || token_exchange_mode.is_some()
                || token_cache_ttl_seconds.is_some()
                || token_response_field.is_some())
        {
            return Err(McpError::invalid_params(
                "token_exchange_url is required when setting token exchange fields",
                None,
            ));
        }

        let auth_type = seren::normalize_auth_type(auth_type.as_deref())
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_token_url =
            seren::normalize_optional_string(oauth2_token_url.as_deref(), "oauth2_token_url")
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        seren::ensure_https(oauth2_token_url.as_deref(), "oauth2_token_url")
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_client_id =
            seren::normalize_optional_string(oauth2_client_id.as_deref(), "oauth2_client_id")
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_client_secret = seren::normalize_optional_string(
            oauth2_client_secret.as_deref(),
            "oauth2_client_secret",
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_scopes = seren::normalize_string_list(
            oauth2_scopes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(String::as_str),
            "oauth2_scopes",
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        seren::validate_oauth2_create_fields(
            auth_type.as_deref(),
            oauth2_token_url.as_deref(),
            oauth2_client_id.as_deref(),
            oauth2_client_secret.as_deref(),
            !oauth2_scopes.is_empty(),
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let upstream_headers = match upstream_headers {
            None => None,
            Some(headers) => Some(
                serde_json::to_value(headers)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ),
        };

        let allowed_passthrough_headers = seren::normalize_string_list(
            allowed_passthrough_headers
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(String::as_str),
            "allowed_passthrough_headers",
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let use_cases = seren::normalize_string_list(
            use_cases
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(String::as_str),
            "use_cases",
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        if connection_string.is_some() && database_config.is_some() {
            return Err(McpError::invalid_params(
                "connection_string cannot be combined with database_config",
                None,
            ));
        }

        if let Some(ref cfg) = database_config
            && !cfg.is_object()
        {
            return Err(McpError::invalid_params(
                "database_config must be a JSON object",
                None,
            ));
        }

        let database_config = if let Some(cs) = connection_string {
            Some(serde_json::json!({ "connection_string": cs }))
        } else {
            database_config
        };

        let body = seren::CreatePublisherRequest {
            name,
            slug,
            email,
            wallet_address: seren::WalletAddress(wallet_address),
            wallet_network_id,
            publisher_category: publisher_category_enum,
            database_type: database_type_enum,
            integration_type: integration_type_enum,
            compute_type: None,
            description,
            api_url,
            mcp_endpoint,
            project_id,
            branch_id,
            database_name,
            base_price_per_1000_rows,
            billing_model,
            categories: categories.unwrap_or_default(),
            capabilities: vec![],
            use_cases,
            logo_url,
            // Set defaults for other fields
            accepted_asset_ids: None,
            allowed_passthrough_headers,
            api_headers: None,
            api_key_header,
            api_key_query_param,
            auth_type,
            oauth2_token_url,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_scopes,
            database_config,
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
            passthrough_header_rewrite: passthrough_header_rewrite
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            price_per_call,
            price_per_delete,
            price_per_execution,
            price_per_get,
            price_per_patch,
            price_per_post,
            price_per_put,
            protected_operations: None,
            publisher_type: None,
            resource_description,
            resource_id_response_path: None,
            resource_id_url_pattern: None,
            upstream_cost_response_path,
            resource_name,
            upstream_api_key,
            usage_examples: None,
            request_content_type,
            upstream_headers,
            endpoints,
            undocumented_endpoint_policy,
            token_exchange_url,
            token_exchange_method,
            token_exchange_mode,
            token_cache_ttl_seconds,
            token_response_field,
            oauth_provider_slug,
            requires_user_oauth,
            routing: None,
            a2a_endpoint_url: None,
            reserve_max_charge: None,
            unresolved_fallback_charge: None,
        };

        let api_base_url = self.api_base_url.trim_end_matches('/');
        let url = format!(
            "{}/organizations/{}/publishers",
            api_base_url, organization_id
        );

        let result = self
            .execute_api_json(&extensions, reqwest::Method::POST, url, Some(&body))
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Update an existing publisher's details. Supports both API key and OAuth authentication. Only fields provided will be updated.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn update_publisher(
        &self,
        Parameters(params): Parameters<UpdatePublisherParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let UpdatePublisherParams {
            organization_id,
            publisher_id,
            name,
            description,
            logo_url,
            categories,
            capabilities,
            use_cases,
            wallet_address,
            wallet_network_id,
            is_active,
            api_url,
            mcp_endpoint,
            project_id,
            branch_id,
            database_name,
            connection_string,
            database_config,
            billing_model,
            email,
            endpoints,
            undocumented_endpoint_policy,
            token_exchange_url,
            token_exchange_method,
            token_exchange_mode,
            token_cache_ttl_seconds,
            token_response_field,
            upstream_api_key,
            api_key_header,
            api_key_query_param,
            allowed_passthrough_headers,
            passthrough_header_rewrite,
            upstream_headers,
            auth_type,
            oauth2_token_url,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_scopes,
            resource_name,
            resource_description,
            oauth_provider_id,
            requires_user_oauth,
            upstream_cost_response_path,
        } = params;

        ensure_writes_allowed(&extensions)?;

        let wallet_address = normalize_nonempty_optional_string(wallet_address, "wallet_address")?;
        let wallet_network_id =
            normalize_nonempty_optional_string(wallet_network_id, "wallet_network_id")?
                .map(|v| v.to_ascii_lowercase());

        // Validate wallet updates (must provide both or neither)
        if wallet_address.is_some() != wallet_network_id.is_some() {
            return Err(McpError::invalid_params(
                "wallet_address and wallet_network_id must be provided together",
                None,
            ));
        }

        let endpoints = match endpoints {
            None => None,
            Some(endpoints) => Some(
                endpoints
                    .into_iter()
                    .map(endpoint_param_to_definition)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };

        let undocumented_endpoint_policy =
            parse_undocumented_endpoint_policy(undocumented_endpoint_policy)?;

        let api_url = normalize_nonempty_optional_string(api_url, "api_url")?;
        let database_name = normalize_nonempty_optional_string(database_name, "database_name")?;
        let billing_model = normalize_nonempty_optional_string(billing_model, "billing_model")?;
        let email = normalize_nonempty_optional_string(email, "email")?;

        let token_exchange_url =
            normalize_nonempty_optional_string(token_exchange_url, "token_exchange_url")?;
        if let Some(ref url) = token_exchange_url
            && !url.starts_with("https://")
        {
            return Err(McpError::invalid_params(
                "token_exchange_url must use HTTPS",
                None,
            ));
        }
        let token_exchange_method = normalize_token_exchange_method(token_exchange_method)?;
        let token_exchange_mode = normalize_token_exchange_mode(token_exchange_mode)?;
        let token_cache_ttl_seconds = validate_token_cache_ttl_seconds(token_cache_ttl_seconds)?;
        let token_response_field =
            normalize_nonempty_optional_string(token_response_field, "token_response_field")?;

        let allowed_passthrough_headers = allowed_passthrough_headers
            .map(|values| {
                seren::normalize_string_list(
                    values.iter().map(String::as_str),
                    "allowed_passthrough_headers",
                )
            })
            .transpose()
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let auth_type = seren::normalize_auth_type(auth_type.as_deref())
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_token_url =
            seren::normalize_optional_string(oauth2_token_url.as_deref(), "oauth2_token_url")
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        seren::ensure_https(oauth2_token_url.as_deref(), "oauth2_token_url")
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_client_id =
            seren::normalize_optional_string(oauth2_client_id.as_deref(), "oauth2_client_id")
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_client_secret = seren::normalize_optional_string(
            oauth2_client_secret.as_deref(),
            "oauth2_client_secret",
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let oauth2_scopes = oauth2_scopes
            .map(|values| {
                seren::normalize_string_list(values.iter().map(String::as_str), "oauth2_scopes")
            })
            .transpose()
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let oauth2_scopes_provided = oauth2_scopes.is_some();
        seren::validate_oauth2_update_fields(
            auth_type.as_deref(),
            oauth2_token_url.as_deref(),
            oauth2_client_id.as_deref(),
            oauth2_client_secret.as_deref(),
            oauth2_scopes_provided,
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        if connection_string.is_some() && database_config.is_some() {
            return Err(McpError::invalid_params(
                "connection_string cannot be combined with database_config",
                None,
            ));
        }

        if let Some(ref cfg) = database_config
            && !cfg.is_object()
        {
            return Err(McpError::invalid_params(
                "database_config must be a JSON object",
                None,
            ));
        }

        let database_config = if let Some(cs) = connection_string {
            Some(serde_json::json!({ "connection_string": cs }))
        } else {
            database_config
        };

        let body = seren::UpdatePublisherRequest {
            name,
            description,
            logo_url,
            categories,
            capabilities,
            use_cases,
            wallet_address: wallet_address.map(seren::WalletAddress),
            wallet_network_id,
            is_active,
            api_url,
            project_id,
            branch_id,
            database_name,
            billing_model,
            email,
            endpoints,
            undocumented_endpoint_policy,
            // Token exchange fields
            token_exchange_url,
            token_exchange_method,
            token_exchange_mode,
            token_cache_ttl_seconds,
            token_response_field,
            // Resource display fields
            resource_name,
            resource_description,
            // Set defaults for fields not exposed in MCP params
            usage_examples: None,
            api_headers: None,
            auth_type,
            oauth2_token_url,
            oauth2_client_id,
            oauth2_client_secret,
            oauth2_scopes,
            upstream_api_key,
            api_key_header,
            api_key_query_param,
            jwt_access_key: None,
            jwt_secret_key: None,
            jwt_expiration_seconds: None,
            jwt_algorithm: None,
            allowed_passthrough_headers,
            request_content_type: None,
            upstream_headers: upstream_headers
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            gateway_fee_percent: None,
            ownership_tracking_enabled: None,
            passthrough_header_rewrite: passthrough_header_rewrite
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            resource_id_response_path: None,
            resource_id_url_pattern: None,
            upstream_cost_response_path,
            protected_operations: None,
            add_asset_ids: None,
            remove_asset_ids: None,
            // Database config fields
            database_config,
            // Pricing fields (not exposed in this tool - use update_publisher_pricing instead)
            base_price_per_1000_rows: None,
            markup_multiplier: None,
            price_per_call: None,
            price_per_get: None,
            price_per_post: None,
            price_per_put: None,
            price_per_patch: None,
            price_per_delete: None,
            hourly_rate: None,
            minimum_balance: None,
            low_balance_threshold: None,
            grace_period_minutes: None,
            price_per_execution: None,
            // Publisher category fields - category cannot be changed after creation
            publisher_category: None,
            database_type: None,
            integration_type: None,
            compute_type: None,
            mcp_endpoint,
            // BYOC OAuth fields
            oauth_provider_id,
            requires_user_oauth,
            routing: None,
            a2a_endpoint_url: None,
            reserve_max_charge: None,
            unresolved_fallback_charge: None,
        };

        let api_base_url = self.api_base_url.trim_end_matches('/');
        let url = format!(
            "{}/organizations/{}/publishers/{}",
            api_base_url, organization_id, publisher_id
        );

        let result = self
            .execute_api_json(&extensions, reqwest::Method::PUT, url, Some(&body))
            .await?;

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Update a publisher's pricing configuration. This updates prices for API calls, database queries, and other billable operations. Requires API key authentication (organization-level). Use get_agent_publisher first to see current pricing.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn update_publisher_pricing(
        &self,
        Parameters(params): Parameters<UpdatePublisherPricingParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        let slug = params.slug.trim().to_string();
        validate_slug(&slug, "Publisher slug")?;

        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;

        // First, get the publisher to retrieve its ID and current pricing (including asset_id)
        let publisher_response = api_client
            .get_store_publisher(&slug)
            .await
            .map_err(|e| {
                if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    McpError::internal_error(
                        format!(
                            "Publisher '{}' not found. Use list_agent_publishers to see available publishers.",
                            slug
                        ),
                        None,
                    )
                } else {
                    McpError::internal_error(e.to_string(), None)
                }
            })?
            .into_inner();

        let publisher = publisher_response.data;
        let publisher_id = publisher.id;

        // Get the asset_id from the publisher's pricing config
        let asset_id = publisher
            .pricing
            .as_ref()
            .and_then(|p| p.first())
            .map(|pc| pc.asset_id)
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!(
                        "Publisher '{}' has no pricing configuration. Cannot update pricing for a publisher without an existing pricing config.",
                        slug
                    ),
                    None,
                )
            })?;

        // Get the organization_id from list_organizations (API key is scoped to org)
        let orgs_response = api_client
            .list_organizations()
            .into_mcp_result()
            .await?
            .into_inner();

        let organization_id = orgs_response
            .data
            .first()
            .map(|org| org.id)
            .ok_or_else(|| {
                McpError::internal_error(
                    "No organization found for this API key. Cannot update publisher pricing."
                        .to_string(),
                    None,
                )
            })?;

        // Build the pricing update request
        let body = seren::UpdatePricingRequest {
            asset_id,
            price_per_call: params.price_per_call,
            price_per_execution: params.price_per_execution,
            base_price_per_1000_rows: params.base_price_per_1000_rows,
            price_per_get: params.price_per_get,
            price_per_post: params.price_per_post,
            price_per_put: params.price_per_put,
            price_per_patch: params.price_per_patch,
            price_per_delete: params.price_per_delete,
            min_charge: params.min_charge,
            reserve_max_charge: params.reserve_max_charge,
            unresolved_fallback_charge: params.unresolved_fallback_charge,
            prepaid_enabled: params.prepaid_enabled,
            onchain_enabled: params.onchain_enabled,
            // Set defaults for fields not exposed in MCP params
            grace_period_minutes: None,
            hourly_rate: None,
            low_balance_threshold: None,
            markup_multiplier: None,
            max_queries_per_minute: None,
            min_display_price: None,
            minimum_balance: None,
            payment_expiry_minutes: None,
            pricing_display_text: None,
            pricing_model: None,
            token_cache_ttl_seconds: None,
            token_exchange_method: None,
            token_exchange_mode: None,
            token_exchange_url: None,
            token_response_field: None,
        };

        let result = match api_client
            .update_publisher_pricing(&organization_id, &publisher_id, &body)
            .await
        {
            Ok(resp) => resp.into_inner(),
            Err(e) => return Err(seren_error_to_mcp_error(e).await),
        };

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }
    #[tool(
        description = "Upload a logo image for a publisher. Accepts base64-encoded PNG, JPEG, WebP, or SVG images. Maximum size 100KB, automatically resized to 200x200 if larger. Supports both API key and OAuth authentication.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn upload_publisher_logo(
        &self,
        Parameters(params): Parameters<UploadPublisherLogoParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        // Validate content type
        let allowed_types = ["image/png", "image/jpeg", "image/webp", "image/svg+xml"];
        if !allowed_types.contains(&params.content_type.as_str()) {
            return Err(McpError::invalid_params(
                format!(
                    "Invalid content_type. Allowed: {}",
                    allowed_types.join(", ")
                ),
                None,
            ));
        }

        // Use extended timeout for logo uploads (may involve large base64 payloads)
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;

        let logo_size = params.logo.len();
        tracing::info!(
            publisher_id = %params.publisher_id,
            organization_id = %params.organization_id,
            content_type = %params.content_type,
            logo_base64_size = logo_size,
            "upload_publisher_logo: dispatching to seren-core"
        );

        let body = seren::LogoUploadRequest {
            logo: params.logo,
            content_type: params.content_type,
        };

        // Ensure this tool returns a bounded error even if the upload does not
        // complete within the expected request window.
        let call_fut =
            api_client.upload_publisher_logo(&params.organization_id, &params.publisher_id, &body);
        let upload_timeout = API_TIMEOUT + OUTER_TIMEOUT_SLACK;
        let result = match tokio::time::timeout(upload_timeout, call_fut).await {
            Ok(Ok(resp)) => {
                tracing::info!(
                    publisher_id = %params.publisher_id,
                    "upload_publisher_logo: success"
                );
                resp.into_inner()
            }
            Ok(Err(e)) => {
                tracing::error!(
                    publisher_id = %params.publisher_id,
                    error = %e,
                    "upload_publisher_logo: SDK error"
                );
                return Err(seren_error_to_mcp_error(e).await);
            }
            Err(_elapsed) => {
                tracing::error!(
                    publisher_id = %params.publisher_id,
                    logo_base64_size = logo_size,
                    timeout_seconds = upload_timeout.as_secs(),
                    "upload_publisher_logo: outer timeout exceeded"
                );
                return Err(McpError::internal_error(
                    format!(
                        "Upload timed out after {}s (payload {} bytes)",
                        upload_timeout.as_secs(),
                        logo_size
                    ),
                    None,
                ));
            }
        };
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    // ========================================================================
    // Project Management Tools
    // ========================================================================

    #[tool(
        description = "Update a project's settings including name, security options, and compute defaults",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn update_project(
        &self,
        Parameters(params): Parameters<UpdateProjectParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let request = seren::UpdateProjectRequest {
            name: params.name,
            block_public_connections: params.block_public_connections,
            block_vpc_connections: params.block_vpc_connections,
            hipaa: params.hipaa,
            protected_branches_only: params.protected_branches_only,
            compute_unit_min: params.compute_unit_min,
            compute_unit_max: params.compute_unit_max,
            enable_logical_replication: params.enable_logical_replication,
            history_retention_seconds: params.history_retention_seconds,
        };

        let project = api_client
            .seren_db_update_project(&params.project_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&project)?]))
    }

    // ========================================================================
    // Branch Management Tools
    // ========================================================================

    #[tool(
        description = "Rename a branch",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn rename_branch(
        &self,
        Parameters(params): Parameters<RenameBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let request = seren::RenameBranchRequest { name: params.name };

        let branch = api_client
            .seren_db_rename_branch(&params.project_id, &params.branch_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&branch)?]))
    }

    #[tool(
        description = "Set a branch as the default branch for the project",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn set_default_branch(
        &self,
        Parameters(params): Parameters<SetDefaultBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        api_client
            .seren_db_set_default_branch(&params.project_id, &params.branch_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&())?]))
    }

    #[tool(
        description = "Reset a branch to its parent's latest state (destroys all data on the branch)",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn reset_branch(
        &self,
        Parameters(params): Parameters<ResetBranchParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let request = seren::ResetBranchRequest { parent: true };

        let branch = api_client
            .seren_db_reset_branch(&params.project_id, &params.branch_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&branch)?]))
    }

    #[tool(
        description = "Set or remove branch expiration date",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn set_branch_expiration(
        &self,
        Parameters(params): Parameters<SetBranchExpirationParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        // Parse the optional timestamp string to a Timestamp
        let expires_at = params.expires_at.map(|s| {
            jiff::Timestamp::from_str(&s).map_err(|e| {
                McpError::invalid_params(format!("Invalid timestamp format: {}. Expected RFC3339 format like '2025-12-31T23:59:59Z'", e), None)
            })
        }).transpose()?;

        let request = seren::SetBranchExpirationRequest { expires_at };

        api_client
            .seren_db_set_branch_expiration(&params.project_id, &params.branch_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&())?]))
    }
    // ========================================================================
    // Role Management Tools
    // ========================================================================

    #[tool(
        description = "Create a new database role on a branch",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_role(
        &self,
        Parameters(params): Parameters<CreateRoleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let request = seren::CreateDbRoleRequest { name: params.name };

        let role = api_client
            .seren_db_create_role(&params.project_id, &params.branch_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&role)?]))
    }

    #[tool(
        description = "Delete a database role from a branch",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn delete_role(
        &self,
        Parameters(params): Parameters<DeleteRoleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        api_client
            .seren_db_delete_role(&params.project_id, &params.branch_id, &params.role_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(
            "Role deleted successfully".to_string(),
        )]))
    }

    #[tool(
        description = "Reset a database role's password, generating a new secure password",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn reset_role_password(
        &self,
        Parameters(params): Parameters<ResetRolePasswordParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let role = api_client
            .seren_db_reset_role_password(&params.project_id, &params.branch_id, &params.role_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&role)?]))
    }

    #[tool(
        description = "Reveal the current password for a database role",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn reveal_role_password(
        &self,
        Parameters(params): Parameters<RevealRolePasswordParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        let role = api_client
            .seren_db_reveal_role_password(&params.project_id, &params.branch_id, &params.role_name)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&role)?]))
    }

    // ========================================================================
    // Endpoint Management Tools
    // ========================================================================

    #[tool(
        description = "Update an endpoint's settings including autoscaling and suspend timeout",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn update_endpoint(
        &self,
        Parameters(params): Parameters<UpdateEndpointParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        let request = seren::UpdateEndpointRequest {
            autoscaling_min: params.autoscaling_min,
            autoscaling_max: params.autoscaling_max,
            compute_unit: None,
            suspend_timeout_seconds: params.suspend_timeout_seconds,
            pooler_enabled: None,
            pooler_mode: None,
        };

        let endpoint = api_client
            .seren_db_update_endpoint(
                &params.project_id,
                &params.branch_id,
                &params.endpoint_id,
                &request,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&endpoint)?]))
    }

    #[tool(
        description = "Get the current status of an endpoint (running, suspended, etc.)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_endpoint_status(
        &self,
        Parameters(params): Parameters<GetEndpointStatusParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        let status = api_client
            .seren_db_get_endpoint_status(
                &params.project_id,
                &params.branch_id,
                &params.endpoint_id,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&status)?]))
    }

    // ========================================================================
    // Database Management Tools
    // ========================================================================

    #[tool(
        description = "Get details about a specific database",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_database(
        &self,
        Parameters(params): Parameters<GetDatabaseParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        let database = api_client
            .seren_db_get_database(&params.project_id, &params.branch_id, &params.database_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&database)?]))
    }

    #[tool(
        description = "Delete a database from a branch",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn delete_database(
        &self,
        Parameters(params): Parameters<DeleteDatabaseParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;

        api_client
            .seren_db_delete_database(&params.project_id, &params.branch_id, &params.database_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(
            "Database deleted successfully".to_string(),
        )]))
    }

    // ========================================================================
    // Wallet Transaction History
    // ========================================================================

    #[tool(
        description = "Get transaction history for your wallet (deposits, charges, refunds)",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_transaction_history(
        &self,
        Parameters(params): Parameters<GetTransactionHistoryParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        let transactions = api_client
            .get_transactions(None, None, None, None, params.limit, params.offset, None)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&transactions)?]))
    }

    // ========================================================================
    // Agent Template Tools
    // ========================================================================

    #[tool(
        description = "List available agent templates in the catalog. Templates are executable code (Python, TypeScript, JavaScript) that can be invoked via micropayments.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_agent_templates(
        &self,
        Parameters(params): Parameters<ListAgentTemplatesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;

        // Apply default limit of 20, max of 50 to prevent token overflow
        let limit = params.limit.unwrap_or(20).clamp(1, 50);

        let response = api_client
            .list_templates(
                params.language.as_deref(),
                Some(limit),
                params.max_price,
                params.min_price,
                params.offset,
                params.search.as_deref(),
                None, // sort_by
                params.verified_only,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get details about a specific agent template by slug",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_agent_template(
        &self,
        Parameters(params): Parameters<GetAgentTemplateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        validate_slug(&params.slug, "template slug")?;

        let api_client = self.api_client(&extensions)?;

        let template = api_client
            .get_template(&params.slug)
            .await
            .map_err(|e| {
                if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    McpError::internal_error(
                        format!(
                            "Template '{}' not found. Use list_agent_templates to see available templates.",
                            params.slug
                        ),
                        None,
                    )
                } else {
                    McpError::internal_error(e.to_string(), None)
                }
            })?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&template)?]))
    }

    #[tool(
        description = "Invoke an agent template with input data. Uses SerenBucks when authenticated; otherwise pays via x402 using your configured local wallet. Templates execute code in a sandboxed environment and return structured output.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn invoke_agent_template(
        &self,
        Parameters(params): Parameters<InvokeAgentTemplateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        validate_slug(&params.slug, "template slug")?;

        // Check write permissions
        ensure_writes_allowed(&extensions)?;

        let agent_metadata = extract_agent_metadata_from_extensions(&extensions);

        let body = seren::InvokeTemplateRequest {
            input: params.input,
        };

        // Dual-mode:
        // - If we have a Bearer token, invoke via SerenBucks.
        // - Otherwise, fall back to x402 using the configured local wallet.
        if matches!(self.auth, SerenAuth::FromRequestBearer)
            && extract_bearer_token_from_extensions(&extensions).is_none()
        {
            let path = format!("/templates/{}/invoke", params.slug);
            let result = self
                .execute_x402_roundtrip_json(
                    &reqwest::Method::POST,
                    &path,
                    Some(&body),
                    None,
                    None,
                    None,
                    params.confirm,
                    &agent_metadata,
                    None,
                )
                .await?;
            return Ok(CallToolResult::success(vec![json_content(&result)?]));
        }

        let api_client = self.api_client(&extensions)?;
        let result = api_client
            .invoke_template(&params.slug, &body)
            .await
            .map_err(|e| {
                if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                    McpError::internal_error(
                        format!(
                            "Template '{}' not found. Use list_agent_templates to see available templates.",
                            params.slug
                        ),
                        None,
                    )
                } else if e.status() == Some(reqwest::StatusCode::PAYMENT_REQUIRED) {
                    McpError::internal_error(
                        "Insufficient SerenBucks balance. Use get_prepaid_balance to check balance and create_prepaid_deposit to add funds.".to_string(),
                        None,
                    )
                } else {
                    McpError::internal_error(e.to_string(), None)
                }
            })?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    // ========================================================================
    // Agent Task Tools
    // ========================================================================

    #[tool(
        description = "Run an agent task via the unified publisher proxy. Sends a message to a remote A2A agent publisher and returns 202 with the created task. Use get_agent_task to poll for completion.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn run_agent_cloud(
        &self,
        Parameters(params): Parameters<RunAgentCloudParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let url = format!("{}/publishers/{}", self.api_base_url, params.publisher_slug);
        let result = self
            .execute_api_json(
                &extensions,
                reqwest::Method::POST,
                url,
                Some(&params.message),
            )
            .await?;
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List agent tasks for an organization. Returns tasks ordered by creation time (newest first) with pagination support.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_agent_tasks(
        &self,
        Parameters(params): Parameters<ListAgentTasksParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(20);
        let offset = params.offset.unwrap_or(0);
        let url = format!(
            "{}/organizations/{}/agents/tasks?limit={}&offset={}",
            self.api_base_url, params.organization_id, limit, offset
        );
        let result = self
            .execute_api_json::<()>(&extensions, reqwest::Method::GET, url, None)
            .await?;
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Get details of a specific agent task including status, output, cost breakdown, and A2A protocol metadata.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_agent_task(
        &self,
        Parameters(params): Parameters<GetAgentTaskParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/organizations/{}/agents/tasks/{}",
            self.api_base_url, params.organization_id, params.task_id
        );
        let result = self
            .execute_api_json::<()>(&extensions, reqwest::Method::GET, url, None)
            .await?;
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "Cancel a running agent task. Releases any billing reservation and stops execution. Only works on tasks that are not yet in a terminal state (completed, failed, or already cancelled).",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn cancel_agent_task(
        &self,
        Parameters(params): Parameters<CancelAgentTaskParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let url = format!(
            "{}/organizations/{}/agents/tasks/{}/cancel",
            self.api_base_url, params.organization_id, params.task_id
        );
        let result = self
            .execute_api_json::<()>(&extensions, reqwest::Method::POST, url, None)
            .await?;
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    // ========================================================================
    // Publisher Context and MCP Tools
    // These tools call Seren API for proper billing/metering
    // ========================================================================

    #[tool(
        description = "Fetch generated skill.md guidance for a Seren publisher. Use this to inspect the publisher's documented capabilities, endpoints, and usage notes before choosing tools.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_publisher_skill_doc(
        &self,
        Parameters(params): Parameters<GetPublisherSkillDocParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let url = publisher_skill_doc_url(&self.api_base_url, &params.publisher)?;
        let skill_md = self
            .execute_api_text(&extensions, url, "text/markdown")
            .await?;
        Ok(CallToolResult::success(vec![Content::text(skill_md)]))
    }

    #[tool(
        description = "Fetch generated skill.md guidance for the core Seren API. Use this to learn the platform's conventions, auth, and endpoints before choosing publisher tools.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_seren_api_skill_doc(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let url = seren_api_skill_doc_url(&self.api_base_url)?;
        let skill_md = self
            .execute_api_text(&extensions, url, "text/markdown")
            .await?;
        Ok(CallToolResult::success(vec![Content::text(skill_md)]))
    }

    #[tool(
        description = "List tools available on an MCP publisher. MCP publishers expose tools, resources, and prompts that can be invoked. Use this to discover what capabilities an MCP publisher provides.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_mcp_tools(
        &self,
        Parameters(params): Parameters<ListMcpToolsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let result_json = match api_client
            .proxy_to_publisher_get(
                &params.publisher,
                "_mcp/tools",
                None,
                None,
                Vec::<u8>::new(),
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(seren::Error::ErrorResponse(err_response)) => {
                let status = err_response.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(McpError::internal_error(
                        format!(
                            "Publisher '{}' not found or does not have MCP capabilities. Use list_agent_publishers to see available publishers.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::BAD_REQUEST {
                    return Err(McpError::invalid_params(
                        format!(
                            "Publisher '{}' does not have an MCP endpoint configured.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                return Err(McpError::internal_error(
                    format!("List MCP tools failed ({})", status),
                    None,
                ));
            }
            Err(seren::Error::UnexpectedResponse(response)) => {
                let status = response.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(McpError::internal_error(
                        format!(
                            "Publisher '{}' not found or does not have MCP capabilities. Use list_agent_publishers to see available publishers.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                let body_text = response.text().await.unwrap_or_default();
                return Err(McpError::internal_error(
                    format!(
                        "List MCP tools failed ({}): {}",
                        status,
                        truncate_for_client(&body_text, 1200)
                    ),
                    None,
                ));
            }
            Err(e) => return Err(McpError::internal_error(e.to_string(), None)),
        };

        Ok(CallToolResult::success(vec![json_content(&result_json)?]))
    }
    #[tool(
        description = "List resources available on an MCP publisher. MCP publishers can expose resources (like files, data sources) that can be read. Use this to discover what resources an MCP publisher provides.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_mcp_resources(
        &self,
        Parameters(params): Parameters<ListMcpResourcesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client_with_timeout(&extensions, API_TIMEOUT)?;
        let result_json = match api_client
            .proxy_to_publisher_get(
                &params.publisher,
                "_mcp/resources",
                None,
                None,
                Vec::<u8>::new(),
            )
            .await
        {
            Ok(response) => response.into_inner(),
            Err(seren::Error::ErrorResponse(err_response)) => {
                let status = err_response.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(McpError::internal_error(
                        format!(
                            "Publisher '{}' not found or does not have MCP capabilities. Use list_agent_publishers to see available publishers.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                if status == reqwest::StatusCode::BAD_REQUEST {
                    return Err(McpError::invalid_params(
                        format!(
                            "Publisher '{}' does not have an MCP endpoint configured.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                return Err(McpError::internal_error(
                    format!("List MCP resources failed ({})", status),
                    None,
                ));
            }
            Err(seren::Error::UnexpectedResponse(response)) => {
                let status = response.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(McpError::internal_error(
                        format!(
                            "Publisher '{}' not found or does not have MCP capabilities. Use list_agent_publishers to see available publishers.",
                            params.publisher
                        ),
                        None,
                    ));
                }
                let body_text = response.text().await.unwrap_or_default();
                return Err(McpError::internal_error(
                    format!(
                        "List MCP resources failed ({}): {}",
                        status,
                        truncate_for_client(&body_text, 1200)
                    ),
                    None,
                ));
            }
            Err(e) => return Err(McpError::internal_error(e.to_string(), None)),
        };

        Ok(CallToolResult::success(vec![json_content(&result_json)?]))
    }

    // ========================================================================
    // Cloud Deployment Tools
    // ========================================================================

    #[tool(
        description = "Deploy a content-addressed deployment bundle to the seren-cloud publisher for managed hosting. Provide either deployment_bundle_id for an already-uploaded bundle or deployment_bundle_content_base64 for a tar.gz bundle that this tool should register and upload before deployment. Supports always_on, cron, and job modes. Leave compute_backend/runtime_kind unset, or set them to auto, for AWS-first bundle-based routing.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn deploy_cloud_agent(
        &self,
        Parameters(params): Parameters<DeployCloudAgentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;
        validate_deploy_cloud_secrets(params.secrets.as_ref())?;
        let api_client = self.api_client(&extensions)?;

        let deployment_bundle_id = match (
            params.deployment_bundle_id,
            params.deployment_bundle_content_base64.as_deref(),
        ) {
            (Some(id), None) => id,
            (None, Some(encoded)) if !encoded.trim().is_empty() => {
                let content = base64::engine::general_purpose::STANDARD
                    .decode(encoded.trim())
                    .map_err(|e| {
                        McpError::invalid_params(
                            format!("Invalid deployment_bundle_content_base64: {e}"),
                            None,
                        )
                    })?;
                register_cloud_deployment_bundle(&api_client, content).await?
            }
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "Provide either deployment_bundle_id or deployment_bundle_content_base64, not both.",
                    None,
                ));
            }
            _ => {
                return Err(McpError::invalid_params(
                    "deploy_cloud_agent requires deployment_bundle_id or deployment_bundle_content_base64. Use deploy_seren_agent for prompt-only managed agents.",
                    None,
                ));
            }
        };

        let request = build_deploy_cloud_agent_request(params, deployment_bundle_id)?;
        let response = match api_client.seren_cloud_deploy(&request).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get Seren Cloud deployment bundle metadata without returning raw bundle content.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_cloud_deployment_bundle(
        &self,
        Parameters(params): Parameters<GetCloudDeploymentBundleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_deployment_bundle(&params.deployment_bundle_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Inspect available seren-agent orchestration features, deployment targets, and runtime limits.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_capabilities(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_capabilities()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List deployments through the first-class seren-agent publisher.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_seren_agent_deployments(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_list_deployments()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get organization-level health for managed seren-agent deployments, including deployment readiness and managed file storage status.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_health(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_health()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Run an unsaved managed seren-agent draft once before deploying. The request body matches deploy_seren_agent inputs and may include optional test_message.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn test_seren_agent_draft_run(
        &self,
        Parameters(params): Parameters<TestSerenAgentDraftRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let request = seren::TestSerenAgentDraftRunRequest {
            deployment: params.body,
            message: params
                .test_message
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        };
        let api_client = self.api_client(&extensions)?;
        let response = match api_client.seren_agent_test_run(&request).await {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get the resolved managed deployment detail for a seren-agent deployment, including the saved prompt, template, resolved tool presets, allowed publisher operations, remote A2A delegation allowlist, runtime overrides, visible config, and secret key names.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_get_managed_deployment(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get health for a single managed seren-agent deployment.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_deployment_health(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_get_deployment_health(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get a managed-agent resource summary for a seren-agent deployment, including runtime, storage, connector, schedule, tool, memory, and capability summaries. Use seren-cloud deployment APIs for full runtime operations.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_deployment_resources(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_get_deployment_resources(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List tools visible to a managed seren-agent deployment, including effective policy metadata. Use this to inspect what an employee can read or act on without loading every tool as a top-level MCP tool.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_seren_agent_deployment_tools(
        &self,
        Parameters(params): Parameters<ListSerenAgentDeploymentToolsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_list_deployment_tools(&params.deployment_id, params.q.as_deref())
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Describe one tool visible to a managed seren-agent deployment, including source, input schema, side-effecting status, checkpoint status, and effective policy metadata.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn describe_seren_agent_deployment_tool(
        &self,
        Parameters(params): Parameters<DescribeSerenAgentDeploymentToolParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_describe_deployment_tool(&params.deployment_id, &params.tool_name)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List resolved tool groups for a managed seren-agent deployment, including aggregate effective policy metadata. Tool groups are the display/read model derived from enabled tool presets and future explicit groups.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_seren_agent_deployment_tool_groups(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_list_deployment_tool_groups(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get recent managed-agent activity for a seren-agent deployment, including run status, timing, source, cost, token, and artifact-count summaries. This tool omits prompts, outputs, tool arguments, connector payloads, and secrets; use seren-cloud run-history APIs for full runtime history.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn get_seren_agent_deployment_activity(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentActivityParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_get_deployment_activity(&params.deployment_id, params.limit, params.offset)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List immutable revision snapshots for a managed seren-agent deployment so callers can inspect version history before rollback.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn list_seren_agent_deployment_revisions(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_list_managed_deployment_revisions(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Start a managed seren-agent deployment through the seren-agent lifecycle endpoint.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn start_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_start_managed_deployment(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Stop a managed seren-agent deployment through the seren-agent lifecycle endpoint.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn stop_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_stop_managed_deployment(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete a managed seren-agent deployment through the seren-agent lifecycle endpoint.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<GetSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        ensure_writes_allowed(&extensions)?;

        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_delete_managed_deployment(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Preview an existing managed seren-agent deployment update before applying it. This returns the current resolved managed spec, the proposed resolved spec, and the changed fields so callers can inspect the diff before mutation, including eval-gate changes.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn preview_seren_agent_deployment_update(
        &self,
        Parameters(params): Parameters<UpdateSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let body = build_update_seren_agent_deployment_request(&api_client, &params).await?;
        let response = api_client
            .seren_agent_preview_managed_deployment_update(&params.deployment_id, &body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Preview rolling a managed seren-agent deployment back to a prior revision. This returns the target revision metadata plus the resolved diff against the current deployment.",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn preview_seren_agent_deployment_rollback(
        &self,
        Parameters(params): Parameters<RollbackSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let body = seren::RollbackSerenAgentDeploymentRequest {
            revision_id: params.revision_id,
        };
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_preview_managed_deployment_rollback(&params.deployment_id, &body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update an existing managed seren-agent deployment. Use prompt plus optional agent_style, capabilities, access_mode, and performance_profile for the common path, or send the advanced fields when you need eval gates, remote delegation, fallback models, config, secrets, or timeouts.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<UpdateSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let body = build_update_seren_agent_deployment_request(&api_client, &params).await?;
        let response = api_client
            .seren_agent_update_managed_deployment(&params.deployment_id, &body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Roll a managed seren-agent deployment back to a prior revision. Use the preview tool first to inspect the resolved diff before applying the rollback.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn rollback_seren_agent_deployment(
        &self,
        Parameters(params): Parameters<RollbackSerenAgentDeploymentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let body = seren::RollbackSerenAgentDeploymentRequest {
            revision_id: params.revision_id,
        };
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_agent_rollback_managed_deployment(&params.deployment_id, &body)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Deploy a managed prompt-based agent through the first-class seren-agent publisher. The simplest inputs are name, mode, prompt, plus optional agent_style, capabilities, access_mode, and performance_profile. Advanced fields still exist for eval gates, remote delegation, fallback models, config, secrets, and timeouts. This path is AWS-first and hides raw runtime internals.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn deploy_seren_agent(
        &self,
        Parameters(params): Parameters<DeploySerenAgentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let request = build_deploy_seren_agent_request(params)?;

        let result = match api_client.seren_agent_deploy(&request).await {
            Ok(result) => result,
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        let result = serde_json::to_value(result.into_inner())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![json_content(&result)?]))
    }

    #[tool(
        description = "List reusable cloud deployment environments in the current organization.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_environments(
        &self,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_list_environments()
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get details for a reusable cloud deployment environment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_environment(
        &self,
        Parameters(params): Parameters<CloudEnvironmentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_environment(&params.environment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a reusable cloud deployment environment.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_cloud_environment(
        &self,
        Parameters(params): Parameters<CreateCloudEnvironmentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateCloudDeploymentEnvironmentRequest {
            name: params.name,
            docker_image: params.docker_image,
            description: params.description,
            setup_commands: params.setup_commands,
            is_default: params.is_default,
        };
        let response = api_client
            .seren_cloud_create_environment(&request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update a reusable cloud deployment environment.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_cloud_environment(
        &self,
        Parameters(params): Parameters<UpdateCloudEnvironmentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let request = seren::UpdateCloudDeploymentEnvironmentRequest {
            name: params.name,
            description: params.description,
            docker_image: params.docker_image,
            setup_commands: params.setup_commands,
            is_default: params.is_default,
        };
        let response = api_client
            .seren_cloud_update_environment(&params.environment_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Delete a reusable cloud deployment environment.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn delete_cloud_environment(
        &self,
        Parameters(params): Parameters<CloudEnvironmentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        api_client
            .seren_cloud_delete_environment(&params.environment_id)
            .into_mcp_result()
            .await?;
        let payload = serde_json::json!({
            "deleted": true,
            "environment_id": params.environment_id,
        });
        Ok(CallToolResult::success(vec![json_content(&payload)?]))
    }

    #[tool(
        description = "List cloud agent deployments in the current organization.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agents(&self, extensions: Extensions) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_list_deployments()
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_agents_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get an organization-wide seren-cloud overview with deployment counts, recent runs, and pending approvals.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_overview(
        &self,
        Parameters(params): Parameters<CloudOverviewParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let deployments = api_client
            .seren_cloud_list_deployments()
            .into_mcp_result()
            .await?
            .into_inner();
        let recent_runs = api_client
            .seren_cloud_runs(
                None,
                None,
                None,
                Some(params.runs_limit),
                Some(0),
                None,
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let pending_approvals = api_client
            .seren_cloud_pending_approvals(
                None,
                None,
                Some(params.approvals_limit),
                Some(0),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();

        let deployments_value = serde_json::to_value(&deployments)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let deployments_data = deployments_value
            .get("data")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let recent_runs_value = serde_json::to_value(&recent_runs)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let recent_runs_data = recent_runs_value
            .get("data")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let pending_approvals_value = serde_json::to_value(&pending_approvals)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let pending_approvals_data = pending_approvals_value
            .get("data")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let deployment_names = build_deployment_name_map(&deployments_data);
        let recent_runs_data = enrich_with_deployment_name(&recent_runs_data, &deployment_names);
        let pending_approvals_data =
            enrich_with_deployment_name(&pending_approvals_data, &deployment_names);

        let payload = serde_json::json!({
            "summary": {
                "deployment_count": deployments_data.len(),
                "running_count": deployments_data
                    .iter()
                    .filter(|deployment| deployment.get("status").and_then(|value| value.as_str()) == Some("running"))
                    .count(),
                "managed_count": deployments_data
                    .iter()
                    .filter(|deployment| !deployment.get("managed_agent").unwrap_or(&serde_json::Value::Null).is_null())
                    .count(),
                "cron_count": deployments_data
                    .iter()
                    .filter(|deployment| deployment.get("mode").and_then(|value| value.as_str()) == Some("cron"))
                    .count(),
                "recent_runs_loaded": recent_runs_data.len(),
                "pending_approvals_loaded": pending_approvals_data.len(),
            },
            "recent_runs": recent_runs_data,
            "pending_approvals": pending_approvals_data,
        });

        let summary = cloud_overview_summary(&payload)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &payload,
        )?))
    }

    #[tool(
        description = "Get status and details of a cloud agent deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn cloud_agent_status(
        &self,
        Parameters(params): Parameters<CloudDeploymentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_deployment(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_agent_summary(&response, "Cloud agent")?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get spend summary for a cloud agent deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_deployment_spend(
        &self,
        Parameters(params): Parameters<CloudDeploymentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_deployment_spend(&params.deployment_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_deployment_spend_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List tamper-evident audit entries for seren-cloud.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_audit_entries(
        &self,
        Parameters(params): Parameters<CloudAuditQueryParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_list_audit_entries(
                params.action.as_deref(),
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_audit_entries_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get a single seren-cloud audit entry.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_audit_entry(
        &self,
        Parameters(params): Parameters<CloudAuditEntryParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_audit_entry(&params.entry_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_audit_entry_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Verify the seren-cloud tamper-evident audit hash chain.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn verify_cloud_audit(
        &self,
        Parameters(params): Parameters<CloudAuditVerifyParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_verify_audit(params.limit)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_audit_verify_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List tamper-evident audit entries scoped to a cloud agent deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_deployment_audit_entries(
        &self,
        Parameters(params): Parameters<CloudDeploymentAuditParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_audit(
                &params.deployment_id,
                params.action.as_deref(),
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_audit_entries_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Start a stopped always-on cloud agent.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn start_cloud_agent(
        &self,
        Parameters(params): Parameters<CloudDeploymentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        api_client
            .seren_cloud_start(&params.deployment_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Deployment {} started.",
            params.deployment_id
        ))]))
    }

    #[tool(
        description = "Stop a running always-on cloud agent.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn stop_cloud_agent(
        &self,
        Parameters(params): Parameters<CloudDeploymentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        api_client
            .seren_cloud_stop(&params.deployment_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Deployment {} stopped.",
            params.deployment_id
        ))]))
    }

    #[tool(
        description = "Trigger a run for a cloud agent. For always_on deployments this proxies the request to the running service; for cron/ephemeral deployments this enqueues a one-shot execution.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn run_cloud_agent(
        &self,
        Parameters(params): Parameters<CloudRunAgentParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let body = build_cloud_run_body(
            params.message.as_deref(),
            params.run_id.as_deref(),
            params.payload.as_ref(),
            params.async_run,
        )?;
        let body: seren::CloudDeploymentRunRequest =
            serde_json::from_value(body.unwrap_or_else(|| serde_json::json!({})))
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let api_client = self.api_client(&extensions)?;
        let response_json = match api_client
            .seren_cloud_run(&params.deployment_id, &body)
            .await
        {
            Ok(response) => response,
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        let response_json = response_json.into_inner();
        let data = serde_json::to_value(&response_json)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let data = data.get("data").cloned().unwrap_or(data);
        let run_id = data
            .get("run_id")
            .or_else(|| data.get("id"))
            .and_then(|v| v.as_str());
        let execution_id = data.get("execution_id").and_then(|v| v.as_str());

        let mut content = Vec::new();
        if let (Some(run_id), Some(execution_id)) = (run_id, execution_id) {
            content.push(Content::text(format!(
                "Run accepted for deployment {}.\nrun_id: {}\nexecution_id: {}",
                params.deployment_id, run_id, execution_id
            )));
        } else if let Some(run_id) = run_id {
            content.push(Content::text(format!(
                "Run triggered for deployment {} (run_id: {}).",
                params.deployment_id, run_id
            )));
        } else {
            content.push(Content::text(format!(
                "Run triggered for deployment {}.",
                params.deployment_id
            )));
        }
        content.push(json_content(&response_json)?);
        Ok(CallToolResult::success(content))
    }

    #[tool(
        description = "Destroy a cloud agent deployment and clean up all K8s resources. This is irreversible.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn destroy_cloud_agent(
        &self,
        Parameters(params): Parameters<CloudDeploymentIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        api_client
            .seren_cloud_delete(&params.deployment_id)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Deployment {} destroyed successfully.",
            params.deployment_id
        ))]))
    }

    #[tool(
        description = "List run history for a cloud agent deployment. Supports filters: status, compute_backend, source, has_artifacts, started_after, started_before, and q.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_runs(
        &self,
        Parameters(params): Parameters<CloudAgentRunsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let status_str = params.status.join(",");
        let response = api_client
            .seren_cloud_deployment_runs(
                &params.deployment_id,
                params.compute_backend.as_deref(),
                None,
                params.has_artifacts,
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
                params.source.as_deref(),
                params.started_after.as_deref(),
                params.started_before.as_deref(),
                if status_str.is_empty() {
                    None
                } else {
                    Some(status_str.as_str())
                },
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_runs_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get details of a specific run event for a cloud agent deployment, including output, structured events, trace_context, output provenance, and eval_capture trajectory summaries.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_agent_run(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run(&params.deployment_id, &params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_summary(&response, "Cloud run")?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List artifacts emitted by a specific run event for a cloud agent deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_run_artifacts(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run_artifacts(&params.deployment_id, &params.run_id, None, None)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_artifacts_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List eval records linked to a specific cloud agent deployment run.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_run_evals(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run_evals(&params.deployment_id, &params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_evals_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List structured output events emitted by a specific cloud agent deployment run.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_run_events(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunEventsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run_events(
                &params.deployment_id,
                &params.run_id,
                params.item_id.as_deref(),
                params.kind.as_deref(),
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_events_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List durable employee conversations for a seren-cloud deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_conversations(
        &self,
        Parameters(params): Parameters<CloudConversationsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_list_conversations(
                &params.deployment_id,
                params.cursor.as_deref(),
                Some(params.limit),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_conversations_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List messages for one durable employee conversation in a seren-cloud deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_agent_conversation_messages(
        &self,
        Parameters(params): Parameters<CloudConversationMessagesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let conversation_id = params.conversation_id.trim();
        if conversation_id.is_empty() {
            return Err(McpError::invalid_params(
                "conversation_id must not be empty.",
                None,
            ));
        }
        let order = parse_conversation_message_order(params.order.as_deref())?;
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_conversation_messages(
                &params.deployment_id,
                conversation_id,
                params.cursor.as_deref(),
                params.include_run,
                Some(params.limit),
                order,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_conversation_messages_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get the current live state for a seren-cloud run, optionally scoped to a deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_run_state(
        &self,
        Parameters(params): Parameters<CloudRunStateParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = if let Some(deployment_id) = params.deployment_id {
            api_client
                .seren_cloud_deployment_run_state(&deployment_id, &params.run_id)
                .into_mcp_result()
                .await?
                .into_inner()
        } else {
            api_client
                .seren_cloud_run_state(&params.run_id)
                .into_mcp_result()
                .await?
                .into_inner()
        };
        let summary = cloud_run_state_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List agent-owned future run schedules for a seren-cloud deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_agent_schedules(
        &self,
        Parameters(params): Parameters<CloudAgentSchedulesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_list_agent_schedules(
                &params.deployment_id,
                Some(params.limit),
                Some(params.offset),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_agent_schedules_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Create or update an agent-owned future run schedule for a seren-cloud deployment. This operation currently requires mode=always_on and compute_backend=aws_container; use run_cloud_agent for an immediate verification run of a cron or job deployment.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_cloud_agent_schedule(
        &self,
        Parameters(params): Parameters<CreateCloudAgentScheduleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let body = seren::CloudDeploymentAgentScheduleRequest {
            conversation_id: params
                .conversation_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            cron: params
                .cron
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            delay_seconds: params.delay_seconds,
            max_attempts: params.max_attempts,
            message: params
                .message
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            payload: params.payload,
            run_at: parse_optional_timestamp(params.run_at.as_deref(), "run_at")?,
            schedule_key: params
                .schedule_key
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            timezone: params
                .timezone
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        };
        let api_client = self.api_client(&extensions)?;
        let response = match api_client
            .seren_cloud_create_agent_schedule(&params.deployment_id, &body)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => return Err(seren_error_to_mcp_error(error).await),
        };
        let summary = cloud_agent_schedule_summary(&response, "Agent schedule")?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Cancel an active agent-owned future run schedule for a seren-cloud deployment.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn cancel_cloud_agent_schedule(
        &self,
        Parameters(params): Parameters<CancelCloudAgentScheduleParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_cancel_agent_schedule(&params.deployment_id, &params.schedule_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_agent_schedule_summary(&response, "Cancelled agent schedule")?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Cancel a queued/running run event for a cloud agent deployment.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn cancel_cloud_agent_run(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run_cancel(&params.deployment_id, &params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List all runs across all cloud agent deployments in the organization. Supports filters: status, compute_backend, source, has_artifacts, started_after, started_before, and q.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_all_cloud_runs(
        &self,
        Parameters(params): Parameters<CloudAllRunsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let deployments = api_client
            .seren_cloud_list_deployments()
            .into_mcp_result()
            .await?
            .into_inner();
        let deployments_value = serde_json::to_value(&deployments)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let deployment_names = build_deployment_name_map(
            &deployments_value
                .get("data")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default(),
        );
        let status_str = params.status.join(",");
        let response = api_client
            .seren_cloud_runs(
                params.compute_backend.as_deref(),
                None,
                params.has_artifacts,
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
                params.source.as_deref(),
                params.started_after.as_deref(),
                params.started_before.as_deref(),
                if status_str.is_empty() {
                    None
                } else {
                    Some(status_str.as_str())
                },
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let enriched_response = enrich_data_envelope_with_deployment_names(
            &serde_json::to_value(&response)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            &deployment_names,
        );
        let summary = cloud_runs_summary(&enriched_response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary,
            &enriched_response,
        )?))
    }

    #[tool(
        description = "List all seren-cloud runs currently awaiting approval across the organization.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_pending_cloud_approvals(
        &self,
        Parameters(params): Parameters<CloudPendingApprovalsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let deployments = api_client
            .seren_cloud_list_deployments()
            .into_mcp_result()
            .await?
            .into_inner();
        let deployments_value = serde_json::to_value(&deployments)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let deployment_names = build_deployment_name_map(
            &deployments_value
                .get("data")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default(),
        );
        let response = api_client
            .seren_cloud_pending_approvals(
                None,
                None,
                Some(params.limit),
                Some(params.offset),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let enriched_response = enrich_data_envelope_with_deployment_names(
            &serde_json::to_value(&response)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            &deployment_names,
        );
        Ok(CallToolResult::success(vec![json_content(
            &enriched_response,
        )?]))
    }

    #[tool(
        description = "List seren-cloud runs currently awaiting approval for a specific deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_deployment_pending_cloud_approvals(
        &self,
        Parameters(params): Parameters<CloudDeploymentPendingApprovalsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_pending_approvals(
                &params.deployment_id,
                None,
                None,
                Some(params.limit),
                Some(params.offset),
                None,
                None,
                None,
                None,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = pending_cloud_approvals_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get the current pending approvals for a seren-cloud run by run ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_run_pending_approvals(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_pending_approvals(&params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = run_pending_approvals_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Approve all current pending approvals for a seren-cloud run by run ID and resume it.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn approve_cloud_run_pending_approvals(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.resolve_cloud_run_pending_approvals(&extensions, params.run_id, "approve")
            .await
    }

    #[tool(
        description = "Reject all current pending approvals for a seren-cloud run by run ID and resume it.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = false
        )
    )]
    async fn reject_cloud_run_pending_approvals(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        self.resolve_cloud_run_pending_approvals(&extensions, params.run_id, "reject")
            .await
    }

    #[tool(
        description = "Get the current pending approvals for a seren-cloud run within a deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_deployment_cloud_run_pending_approvals(
        &self,
        Parameters(params): Parameters<CloudDeploymentRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_deployment_run_pending_approvals(&params.deployment_id, &params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = run_pending_approvals_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Get details of a run event by run ID (global path, no deployment ID required), including trace_context, output provenance, and eval_capture trajectory summaries.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_run_by_id(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_detail(&params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Compare eval_capture summaries and replay artifacts for two cloud runs by run ID. Useful for regression checks after rerunning a deployment or managed agent.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn compare_cloud_runs(
        &self,
        Parameters(params): Parameters<CompareCloudRunsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_compare(&params.baseline_run_id, &params.candidate_run_id)
            .into_mcp_result()
            .await?
            .into_inner();

        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List durable eval sets for seren-cloud runs. Optionally scope the list to a single deployment.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_eval_sets(
        &self,
        Parameters(params): Parameters<CloudEvalSetsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_eval_sets(
                params.deployment_id.as_ref(),
                Some(params.limit),
                Some(params.offset),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Create a durable eval set for seren-cloud runs. Use deployment_id to scope the set to a specific deployment, criteria to define pass/fail thresholds, metadata for labels or ownership data, and schedule_cron plus schedule_timezone to run the eval set automatically.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_cloud_eval_set(
        &self,
        Parameters(params): Parameters<CreateCloudEvalSetParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if let Some(criteria) = &params.criteria
            && !criteria.is_object()
        {
            return Err(McpError::invalid_params(
                "criteria must be a JSON object when provided.",
                None,
            ));
        }
        if let Some(metadata) = &params.metadata
            && !metadata.is_object()
        {
            return Err(McpError::invalid_params(
                "metadata must be a JSON object when provided.",
                None,
            ));
        }

        let criteria = serde_json::from_value::<seren::CloudEvalCriteria>(
            params.criteria.unwrap_or_else(|| serde_json::json!({})),
        )
        .map_err(|e| McpError::invalid_params(format!("Invalid criteria payload: {e}"), None))?;
        let schedule = build_cloud_eval_set_schedule_request(
            params.schedule_cron.as_deref(),
            params.schedule_timezone.as_deref(),
        )?;

        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateCloudEvalSetRequest {
            criteria: Some(criteria),
            deployment_id: params.deployment_id,
            description: params.description,
            metadata: Some(params.metadata.unwrap_or_else(|| serde_json::json!({}))),
            name: params.name,
            schedule,
        };
        let response = api_client
            .seren_cloud_create_eval_set(&request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get a single eval set by ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_eval_set(
        &self,
        Parameters(params): Parameters<CloudEvalSetIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_eval_set(&params.eval_set_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Replace an existing eval set. Use clear_deployment to remove deployment scoping, or clear_schedule to disable scheduled execution.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn update_cloud_eval_set(
        &self,
        Parameters(params): Parameters<UpdateCloudEvalSetParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if params.clear_deployment && params.deployment_id.is_some() {
            return Err(McpError::invalid_params(
                "Do not combine clear_deployment with deployment_id.",
                None,
            ));
        }
        if let Some(name) = &params.name
            && name.trim().is_empty()
        {
            return Err(McpError::invalid_params(
                "name must not be empty when provided.",
                None,
            ));
        }
        if let Some(criteria) = &params.criteria
            && !criteria.is_object()
        {
            return Err(McpError::invalid_params(
                "criteria must be a JSON object when provided.",
                None,
            ));
        }
        if let Some(metadata) = &params.metadata
            && !metadata.is_object()
        {
            return Err(McpError::invalid_params(
                "metadata must be a JSON object when provided.",
                None,
            ));
        }

        let api_client = self.api_client(&extensions)?;
        let current = api_client
            .seren_cloud_get_eval_set(&params.eval_set_id)
            .into_mcp_result()
            .await?
            .into_inner()
            .data;

        let criteria = match params.criteria {
            Some(criteria) => serde_json::from_value::<seren::CloudEvalCriteria>(criteria)
                .map_err(|e| {
                    McpError::invalid_params(format!("Invalid criteria payload: {e}"), None)
                })?,
            None => current.criteria.clone(),
        };
        let metadata = params.metadata.unwrap_or_else(|| current.metadata.clone());
        let schedule = resolve_cloud_eval_set_schedule_request(
            &current,
            params.schedule_cron.as_deref(),
            params.schedule_timezone.as_deref(),
            params.clear_schedule,
        )?;
        let request = seren::UpdateCloudEvalSetRequest {
            name: params
                .name
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| current.name.clone()),
            description: match params.description {
                Some(description) => {
                    let trimmed = description.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
                None => current.description.clone(),
            },
            deployment_id: if params.clear_deployment {
                None
            } else {
                params.deployment_id.or(current.deployment_id)
            },
            criteria: Some(criteria),
            metadata: Some(metadata),
            schedule,
        };
        let response = api_client
            .seren_cloud_update_eval_set(&params.eval_set_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List eval cases within an eval set.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_eval_cases(
        &self,
        Parameters(params): Parameters<CloudEvalCasesParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_eval_cases(&params.eval_set_id, Some(params.limit), Some(params.offset))
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get a single eval case within an eval set.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_eval_case(
        &self,
        Parameters(params): Parameters<CloudEvalCaseIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_eval_case(&params.eval_set_id, &params.case_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Promote a terminal seren-cloud run into a durable eval case inside an eval set. The run must already have replay and eval capture data.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn promote_cloud_run_to_eval_case(
        &self,
        Parameters(params): Parameters<PromoteCloudRunToEvalCaseParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if let Some(metadata) = &params.metadata
            && !metadata.is_object()
        {
            return Err(McpError::invalid_params(
                "metadata must be a JSON object when provided.",
                None,
            ));
        }

        let api_client = self.api_client(&extensions)?;
        let request = seren::PromoteRunToCloudEvalCaseRequest {
            metadata: params.metadata,
            name: params.name,
        };
        let response = api_client
            .seren_cloud_promote_run_to_eval_case(&params.eval_set_id, &params.run_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Execute an eval set against a deployment and create durable per-case results.",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn create_cloud_eval_run(
        &self,
        Parameters(params): Parameters<CreateCloudEvalRunParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if let Some(metadata) = &params.metadata
            && !metadata.is_object()
        {
            return Err(McpError::invalid_params(
                "metadata must be a JSON object when provided.",
                None,
            ));
        }

        let api_client = self.api_client(&extensions)?;
        let request = seren::CreateCloudEvalRunRequest {
            deployment_id: params.deployment_id,
            metadata: params.metadata,
        };
        let response = api_client
            .seren_cloud_run_eval_set(&params.eval_set_id, &request)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List eval runs within an eval set.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_eval_runs(
        &self,
        Parameters(params): Parameters<CloudEvalRunsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_eval_runs(&params.eval_set_id, Some(params.limit), Some(params.offset))
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get a single eval run by eval set ID and eval run ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_eval_run(
        &self,
        Parameters(params): Parameters<CloudEvalRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_eval_run(&params.eval_set_id, &params.eval_run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List per-case results for an eval run.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_eval_run_results(
        &self,
        Parameters(params): Parameters<CloudEvalRunResultsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_eval_run_results(
                &params.eval_set_id,
                &params.eval_run_id,
                Some(params.limit),
                Some(params.offset),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Get a single per-case result from an eval run.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn get_cloud_eval_case_result(
        &self,
        Parameters(params): Parameters<CloudEvalCaseResultIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_get_eval_case_result(
                &params.eval_set_id,
                &params.eval_run_id,
                &params.case_id,
            )
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "List artifacts emitted by a run event using the global run path (no deployment ID required).",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_run_artifacts(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_artifacts(&params.run_id, None, None)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_artifacts_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List tamper-evident audit entries scoped to a cloud run by run ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_run_audit_entries(
        &self,
        Parameters(params): Parameters<CloudRunAuditParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_audit(
                &params.run_id,
                params.action.as_deref(),
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_audit_entries_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List eval records linked to a cloud run by run ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_run_evals(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_evals(&params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_evals_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "List structured output events emitted by a cloud run by run ID.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    async fn list_cloud_run_events(
        &self,
        Parameters(params): Parameters<CloudRunEventsParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_events(
                &params.run_id,
                params.item_id.as_deref(),
                params.kind.as_deref(),
                Some(params.limit),
                Some(params.offset),
                params.q.as_deref(),
            )
            .into_mcp_result()
            .await?
            .into_inner();
        let summary = cloud_run_events_summary(&response)?;
        Ok(CallToolResult::success(text_and_json_content(
            summary, &response,
        )?))
    }

    #[tool(
        description = "Cancel a queued/running run event by run ID (global path, no deployment ID required).",
        annotations(read_only_hint = false, open_world_hint = false)
    )]
    async fn cancel_cloud_run_by_id(
        &self,
        Parameters(params): Parameters<CloudRunIdParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        let api_client = self.api_client(&extensions)?;
        let response = api_client
            .seren_cloud_run_cancel(&params.run_id)
            .into_mcp_result()
            .await?
            .into_inner();
        Ok(CallToolResult::success(vec![json_content(&response)?]))
    }

    #[tool(
        description = "Update alert_policy and/or the deployment eval gate for a cloud agent without redeploying code. Workload-level config, secrets, and network_policy updates are not exposed by this helper; redeploy the cloud agent or use the managed-agent update tools for managed seren-agent deployments.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    async fn update_cloud_agent_config(
        &self,
        Parameters(params): Parameters<CloudUpdateConfigParams>,
        extensions: Extensions,
    ) -> Result<CallToolResult, McpError> {
        if params.config.is_none()
            && params.secrets.is_none()
            && params.alert_policy.is_none()
            && !params.clear_alert_policy
            && params.network_policy.is_none()
            && !params.clear_network_policy
            && params.eval_gate_set_id.is_none()
            && params.eval_gate_max_age_seconds.is_none()
            && !params.clear_eval_gate
        {
            return Err(McpError::invalid_params(
                "Provide alert_policy, clear_alert_policy, eval_gate_set_id plus eval_gate_max_age_seconds, or clear_eval_gate.",
                None,
            ));
        }
        if params.config.is_some()
            || params.secrets.is_some()
            || params.network_policy.is_some()
            || params.clear_network_policy
        {
            return Err(McpError::invalid_params(
                "config, secrets, and network_policy are workload-level fields and cannot be changed through this cloud settings helper. Redeploy the cloud agent with the new bundle and config, or use update_seren_agent_deployment for managed seren-agent deployments.",
                None,
            ));
        }
        let api_client = self.api_client(&extensions)?;
        let alert_policy = params
            .alert_policy
            .map(serde_json::from_value::<seren::CloudDeploymentAlertPolicy>)
            .transpose()
            .map_err(|e| {
                McpError::invalid_params(format!("Invalid alert_policy payload: {e}"), None)
            })?;
        let eval_gate = match (
            params.eval_gate_set_id,
            params.eval_gate_max_age_seconds,
            params.clear_eval_gate,
        ) {
            (Some(set_id), Some(max_age_seconds), false) => Some(seren::EvalGate {
                block_on_failure: None,
                drift_baseline: None,
                max_age_seconds,
                schedule: None,
                set_id,
            }),
            (None, None, _) => None,
            (Some(_), None, false) => {
                return Err(McpError::invalid_params(
                    "eval_gate_max_age_seconds is required with eval_gate_set_id.",
                    None,
                ));
            }
            (None, Some(_), false) => {
                return Err(McpError::invalid_params(
                    "eval_gate_set_id is required with eval_gate_max_age_seconds.",
                    None,
                ));
            }
            (Some(_), _, true) | (_, Some(_), true) => {
                return Err(McpError::invalid_params(
                    "Provide either clear_eval_gate or eval_gate_set_id plus eval_gate_max_age_seconds, not both.",
                    None,
                ));
            }
        };
        let request = seren::UpdateCloudDeploymentRequest {
            alert_policy,
            clear_alert_policy: Some(params.clear_alert_policy),
            clear_eval_gate: Some(params.clear_eval_gate),
            clear_dashboard_config: None,
            dashboard_config: None,
            eval_gate,
            visibility: None,
        };
        api_client
            .seren_cloud_update_config(&params.deployment_id, &request)
            .into_mcp_result()
            .await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Deployment settings updated for {}.",
            params.deployment_id
        ))]))
    }
}

// ============================================================================
// Tool input schema normalization
// ============================================================================

/// JSON Schema keywords whose value is a single subschema.
const SCHEMA_SLOT_KEYWORDS: &[&str] = &[
    "items",
    "contains",
    "not",
    "propertyNames",
    "if",
    "then",
    "else",
    "additionalItems",
    "additionalProperties",
    "unevaluatedItems",
    "unevaluatedProperties",
];
/// JSON Schema keywords whose value maps names to subschemas.
const SCHEMA_MAP_KEYWORDS: &[&str] = &[
    "properties",
    "patternProperties",
    "$defs",
    "definitions",
    "dependentSchemas",
];
/// JSON Schema keywords whose value is an array of subschemas.
const SCHEMA_ARRAY_KEYWORDS: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
/// Keywords whose value is literal instance data, not a subschema. Never recurse
/// into these: a boolean or object here is a value, not a schema to normalize.
const SCHEMA_DATA_KEYWORDS: &[&str] = &["default", "const", "enum", "examples", "example"];

/// Rewrite boolean subschemas to equivalent object schemas throughout a JSON Schema document.
fn normalize_json_schema(node: &mut serde_json::Value) {
    match node {
        serde_json::Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                let key = key.as_str();
                if SCHEMA_DATA_KEYWORDS.contains(&key) {
                    continue;
                } else if SCHEMA_MAP_KEYWORDS.contains(&key) {
                    if let serde_json::Value::Object(entries) = value {
                        for entry in entries.values_mut() {
                            normalize_schema_slot(entry);
                        }
                    }
                } else if SCHEMA_ARRAY_KEYWORDS.contains(&key) {
                    if let serde_json::Value::Array(items) = value {
                        for item in items.iter_mut() {
                            normalize_schema_slot(item);
                        }
                    }
                } else if SCHEMA_SLOT_KEYWORDS.contains(&key) {
                    normalize_schema_slot(value);
                } else {
                    // Recurse through unknown objects without treating scalar keyword values as schemas.
                    normalize_json_schema(value);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                normalize_json_schema(item);
            }
        }
        _ => {}
    }
}

/// Normalize a value that occupies a subschema slot.
fn normalize_schema_slot(node: &mut serde_json::Value) {
    if let serde_json::Value::Bool(accepts_any) = node {
        *node = if *accepts_any {
            serde_json::json!({})
        } else {
            serde_json::json!({ "not": {} })
        };
        return;
    }
    normalize_json_schema(node);
}

/// Apply [`normalize_json_schema`] to a tool's input schema before serving it.
fn normalize_tool_input_schema(mut tool: rmcp::model::Tool) -> rmcp::model::Tool {
    let mut schema = serde_json::Value::Object((*tool.input_schema).clone());
    normalize_json_schema(&mut schema);
    if let serde_json::Value::Object(map) = schema {
        tool.input_schema = std::sync::Arc::new(map);
    }
    tool
}

// ============================================================================
// Server Handler Implementation
// ============================================================================

impl ServerHandler for SerenMcpServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        #[cfg(feature = "telemetry")]
        let tool_name = request.name.clone().into_owned();
        #[cfg(feature = "telemetry")]
        let start = std::time::Instant::now();

        let tcc = ToolCallContext::new(self, request, context);
        let result = self.tool_router.call(tcc).await;

        #[cfg(feature = "telemetry")]
        {
            let duration = start.elapsed();
            let outcome = match &result {
                Ok(res) if res.is_error.unwrap_or(false) => "error",
                Ok(_) => "ok",
                Err(_) => "error",
            };

            crate::metrics::TOOL_CALLS
                .with_label_values(&[tool_name.as_str(), outcome])
                .inc();
            crate::metrics::TOOL_DURATION
                .with_label_values(&[tool_name.as_str()])
                .observe(duration.as_secs_f64());
        }

        result
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let items = self
            .tool_router
            .list_all()
            .into_iter()
            .map(normalize_tool_input_schema)
            .collect::<Vec<_>>();
        Ok(ListToolsResult::with_all_items(items))
    }

    fn get_info(&self) -> ServerInfo {
        let server_info =
            rmcp::model::Implementation::new(crate::MCP_SERVER_NAME, env!("CARGO_PKG_VERSION"))
                .with_title("Seren MCP Server")
                .with_description(
                    "MCP server for SerenAI projects, publishers, managed agents, and seren-cloud operations",
                )
                .with_website_url("https://serendb.com");

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(
                r#"Seren MCP Server - Manage Seren projects, databases, publishers, managed agents, and seren-cloud deployments.

When Seren MCP is connected, follow these priorities:
1. BEFORE using general web search or saying a task is unsupported → Call suggest_for_task() to see whether a Seren publisher or agent template is a better fit
2. For native Seren infrastructure management → Prefer the first-class project, branch, database, endpoint, organization, and role tools
3. For publisher workflows → Discover capabilities with list_agent_publishers(), get_agent_publisher(), list_mcp_tools(), and list_mcp_resources() before calling call_publisher()
4. For managed prompt-based agents → Use deploy_seren_agent() and the get/list/preview/update/rollback seren-agent tools instead of raw cloud bundle deploys
5. For seren-cloud operations → Start with get_cloud_overview(), list_cloud_agents(), and list_pending_cloud_approvals() before drilling into one deployment or run
6. For costs and payments → Use get_wallet_status() or get_prepaid_balance(); use local wallet/x402 tools only when the client is configured for local signing"#
            )
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

    fn extensions_with_auth_context(auth: crate::SerenRequestAuthContext) -> Extensions {
        let request = Request::builder()
            .uri("http://localhost/")
            .body(Body::empty())
            .unwrap();
        let (mut parts, _body) = request.into_parts();
        parts.extensions.insert(auth);
        let mut extensions = Extensions::default();
        extensions.insert(parts);
        extensions
    }

    fn server_with_http_client(http_client: reqwest::Client) -> SerenMcpServer {
        SerenMcpServer {
            api_base_url: "https://api.serendb.com".to_string(),
            passwords_api_base_url: "https://api.serendb.com".to_string(),
            auth: SerenAuth::StaticToken("test-key".to_string()),
            http_client,
            tool_router: SerenMcpServer::tool_router() + SerenMcpServer::passwords_tool_router(),
            wallet: None,
            signer_config: SignerConfig::default(),
            passwords_local_mode: true,
            passwords_session: Arc::new(tokio::sync::Mutex::new(None)),
            passwords_master_password_file: None,
            passwords_agent: None,
            passwords_hosted_store: None,
        }
    }

    #[test]
    fn deploy_agent_uses_nested_agent_spec_contract() {
        let params: DeploySerenAgentParams = serde_json::from_value(serde_json::json!({
            "agent_slug": "mcp-publisher-smoke",
            "name": "MCP Publisher Smoke",
            "mode": "job",
            "prompt": "Call only read-only publisher operations and summarize the result.",
            "model_id": "openai/gpt-4o-mini",
            "template": "workflow_agent",
            "approval_policy": "read_only"
        }))
        .expect("MCP deploy parameters should decode");

        let request = build_deploy_seren_agent_request(params)
            .expect("MCP deploy parameters should build an AgentSpec");
        let payload = serde_json::to_value(request).expect("AgentSpec should serialize");

        assert!(payload.get("prompt").is_none());
        assert!(payload.get("system_prompt").is_none());
        assert_eq!(
            payload.pointer("/workload/execution/type"),
            Some(&serde_json::json!("llm"))
        );
        assert_eq!(
            payload.pointer("/workload/execution/bundle/instructions/0/content"),
            Some(&serde_json::json!(
                "Call only read-only publisher operations and summarize the result."
            ))
        );
        assert_eq!(
            payload.get("template"),
            Some(&serde_json::json!("workflow_agent"))
        );
        assert_eq!(
            payload.get("approval_policy"),
            Some(&serde_json::json!("read_only"))
        );
        assert!(payload.pointer("/workload/side_effect_policy").is_none());
    }

    #[test]
    fn deploy_cloud_agent_rejects_platform_managed_api_key() {
        let secrets = serde_json::json!({
            "SEREN_API_KEY": "must-not-be-reported"
        });

        let error = validate_deploy_cloud_secrets(Some(&secrets))
            .expect_err("platform-managed API key must be rejected before upload");

        assert!(error.message.contains("reserved SEREN_ runtime namespace"));
        assert!(
            error
                .message
                .contains("generated and injected automatically")
        );
        assert!(!error.message.contains("must-not-be-reported"));
    }

    #[test]
    fn deploy_cloud_agent_builds_python_cron_request() {
        let deployment_bundle_id = Uuid::new_v4();
        let params: DeployCloudAgentParams = serde_json::from_value(serde_json::json!({
            "skill_slug": "3d-recovery-case-origination",
            "name": "3D Recovery Case Origination",
            "mode": "cron",
            "cron_schedule": "0 6 * * 1-5",
            "cron_timezone": "America/New_York",
            "runtime_kind": "python",
            "visibility": "opaque",
            "deployment_bundle_content_base64": "registered-before-request-build",
            "requirements_txt": "httpx>=0.27\npytest>=8\n",
            "config": {
                "live_mode": false,
                "offline_fixture": false,
                "skill": "case-origination",
                "auth.api_key_env": "SEREN_API_KEY",
                "serendb.database": "bat_sales_coach",
                "serendb.project_id": "3dbd443a-86f6-4120-9b56-b8f61a021838",
                "serendb.branch_id": "5c1bcdc5-875d-4528-90c0-65d86780e4c1",
                "schedule.cron_expression": "0 6 * * 1-5",
                "schedule.timezone": "America/New_York"
            }
        }))
        .expect("reported MCP parameters should decode");

        validate_deploy_cloud_secrets(params.secrets.as_ref())
            .expect("corrected request should not provide platform-managed secrets");
        let request = build_deploy_cloud_agent_request(params, deployment_bundle_id)
            .expect("reported Python cron request should build");
        let payload = serde_json::to_value(request).expect("deploy request should serialize");

        assert_eq!(payload.get("mode"), Some(&serde_json::json!("cron")));
        assert_eq!(
            payload.get("cron_schedule"),
            Some(&serde_json::json!("0 6 * * 1-5"))
        );
        assert_eq!(
            payload.get("cron_timezone"),
            Some(&serde_json::json!("America/New_York"))
        );
        assert_eq!(
            payload.pointer("/workload/execution/type"),
            Some(&serde_json::json!("code"))
        );
        assert_eq!(
            payload.pointer("/workload/execution/runtime_kind"),
            Some(&serde_json::json!("python"))
        );
        assert_eq!(
            payload.pointer("/workload/execution/deployment_bundle_id"),
            Some(&serde_json::json!(deployment_bundle_id))
        );
        assert_eq!(
            payload.pointer("/workload/config/auth.api_key_env"),
            Some(&serde_json::json!("SEREN_API_KEY"))
        );
        assert!(payload.pointer("/workload/secrets").is_none());
    }

    #[test]
    fn object_storage_metadata_validation_requires_object() {
        let valid = validate_object_storage_metadata(Some(serde_json::json!({"team": "ops"})))
            .expect("object metadata should be accepted");
        assert_eq!(valid, Some(serde_json::json!({"team": "ops"})));

        let err = validate_object_storage_metadata(Some(serde_json::json!(["ops"])))
            .expect_err("array metadata should be rejected");
        assert!(err.message.contains("metadata must be a JSON object"));
    }

    #[test]
    fn object_storage_key_validation_rejects_empty_key() {
        validate_object_storage_key("reports/q1.txt").expect("non-empty key should be accepted");

        let err = validate_object_storage_key("/").expect_err("empty key should be rejected");
        assert!(err.message.contains("object_key must not be empty"));
    }

    #[test]
    fn seren_storage_publisher_tools_are_exposed() {
        let server = server_with_http_client(reqwest::Client::new());
        let tool_names = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect::<std::collections::HashSet<_>>();

        for expected in [
            "seren_storage_health",
            "seren_storage_list_buckets",
            "seren_storage_list_objects",
            "seren_storage_create_upload",
            "seren_storage_put_object_base64",
            "seren_storage_confirm_upload",
            "seren_storage_download_object",
            "seren_storage_download_object_by_id",
            "seren_storage_delete_object",
            "seren_storage_list_bucket_agent_grants",
            "seren_storage_put_bucket_agent_grant",
            "seren_storage_delete_bucket_agent_grant",
            "seren_storage_list_workspace_snapshots",
            "seren_storage_latest_workspace_snapshot",
            "seren_storage_create_workspace_snapshot",
        ] {
            assert!(tool_names.contains(expected), "missing MCP tool {expected}");
        }
    }

    #[test]
    fn seren_memory_publisher_tools_are_exposed() {
        let server = server_with_http_client(reqwest::Client::new());
        let tool_names = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect::<std::collections::HashSet<_>>();

        for expected in [
            "seren_memory_health",
            "seren_memory_session_bootstrap",
            "seren_memory_recall",
            "seren_memory_remember",
            "seren_memory_list_memories",
            "seren_memory_get_memory",
            "seren_memory_forget_memory",
            "seren_memory_delete_memory",
            "seren_memory_list_knowledge_domains",
            "seren_memory_search_knowledge",
            "seren_memory_open_knowledge_entity",
        ] {
            assert!(tool_names.contains(expected), "missing MCP tool {expected}");
        }
    }

    #[tokio::test]
    async fn seren_error_to_mcp_error_includes_unexpected_response_body() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": {
                    "message": "user authentication required",
                    "code": 403
                }
            })))
            .mount(&server)
            .await;

        let response = reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .expect("mock response should be returned");
        let error =
            seren_error_to_mcp_error::<()>(seren::Error::UnexpectedResponse(response)).await;

        assert!(error.message.contains("API error 403 Forbidden:"));
        assert!(error.message.contains("user authentication required"));
    }

    #[tokio::test]
    async fn seren_error_to_mcp_error_includes_server_request_id() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("x-request-id", "request-198")
                    .set_body_json(serde_json::json!({
                        "error": "InternalError",
                        "message": "Draft runtime could not be initialized"
                    })),
            )
            .mount(&server)
            .await;

        let response = reqwest::Client::new()
            .post(server.uri())
            .send()
            .await
            .expect("mock response should be returned");
        let error =
            seren_error_to_mcp_error::<()>(seren::Error::UnexpectedResponse(response)).await;

        assert!(
            error
                .message
                .contains("API error 500 Internal Server Error")
        );
        assert!(error.message.contains("request ID: request-198"));
        assert!(
            error
                .message
                .contains("Draft runtime could not be initialized")
        );
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("kind")),
            Some(&serde_json::json!("http_error"))
        );
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("status")),
            Some(&serde_json::json!(500))
        );
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("request_id")),
            Some(&serde_json::json!("request-198"))
        );
    }

    #[tokio::test]
    async fn seren_error_to_mcp_error_includes_typed_error_body() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-request-id", "request-typed-1".parse().unwrap());
        let response = seren::ResponseValue::new(
            serde_json::json!({"message": "publisher configuration rejected"}),
            reqwest::StatusCode::BAD_REQUEST,
            headers,
        );

        let error = seren_error_to_mcp_error(seren::Error::ErrorResponse(response)).await;

        assert!(error.message.contains("publisher configuration rejected"));
        assert!(error.message.contains("request ID: request-typed-1"));
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("status")),
            Some(&serde_json::json!(400))
        );
    }

    #[tokio::test]
    async fn execute_api_json_bounds_error_body_and_preserves_request_id() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let response_body = format!("prefix-{}-suffix", "x".repeat(2000));
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("x-request-id", "request-direct-1")
                    .set_body_string(response_body),
            )
            .mount(&upstream)
            .await;
        let server = SerenMcpServer::new("test-key", &upstream.uri()).unwrap();

        let error = server
            .execute_api_json::<()>(
                &Extensions::new(),
                reqwest::Method::GET,
                upstream.uri(),
                None,
            )
            .await
            .expect_err("error response should fail");

        assert!(error.message.contains("prefix-"));
        assert!(!error.message.contains("-suffix"));
        assert!(error.message.contains("request ID: request-direct-1"));
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("status")),
            Some(&serde_json::json!(400))
        );
    }

    #[tokio::test]
    async fn execute_api_text_bounds_error_body_and_preserves_request_id() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let response_body = format!("prefix-{}-suffix", "x".repeat(2000));
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("x-request-id", "request-text-1")
                    .set_body_string(response_body),
            )
            .mount(&upstream)
            .await;
        let server = SerenMcpServer::new("test-key", &upstream.uri()).unwrap();

        let error = server
            .execute_api_text(&Extensions::new(), upstream.uri(), "text/markdown")
            .await
            .expect_err("error response should fail");

        assert!(error.message.contains("prefix-"));
        assert!(!error.message.contains("-suffix"));
        assert!(error.message.contains("request ID: request-text-1"));
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("status")),
            Some(&serde_json::json!(400))
        );
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("request_id")),
            Some(&serde_json::json!("request-text-1"))
        );
        assert!(
            error
                .data
                .as_ref()
                .and_then(|data| data.get("body"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|body| body.chars().count() <= 1200)
        );
    }

    #[tokio::test]
    async fn seren_error_to_mcp_error_distinguishes_transport_failures() {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("temporary listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have an address");
        drop(listener);

        let transport_error = reqwest::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .expect_err("closed local port should reject the connection");
        let error =
            seren_error_to_mcp_error::<()>(seren::Error::CommunicationError(transport_error)).await;

        assert!(error.message.contains("Communication error:"));
        assert!(!error.message.contains("API error"));
        assert!(!error.message.contains("http://"));
        assert_eq!(
            error.data.as_ref().and_then(|data| data.get("kind")),
            Some(&serde_json::json!("transport_error"))
        );
    }

    #[test]
    fn cloud_run_events_summary_includes_tool_result_error_code() {
        let response = serde_json::json!({
            "data": [
                {
                    "sequence_number": 4,
                    "event_type": "response.output_item.done",
                    "kind": "tool_call_completed",
                    "item_id": "call_123",
                    "event": {
                        "type": "tool_result",
                        "id": "call_123",
                        "content": "Provider rate limit exceeded",
                        "is_error": true,
                        "code": "tool_rate_limited",
                        "retryable": true
                    }
                }
            ]
        });

        let summary = cloud_run_events_summary(&response).unwrap();
        assert!(summary.contains("1 run event(s):"));
        assert!(summary.contains("#4"));
        assert!(summary.contains("tool_call_completed"));
        assert!(summary.contains("id=call_123"));
        assert!(summary.contains("code=tool_rate_limited"));
        assert!(summary.contains("retryable=true"));
        assert!(summary.contains("summary=Provider rate limit exceeded"));
    }

    #[test]
    fn cloud_run_events_summary_handles_empty_pages() {
        let response = serde_json::json!({ "data": [] });

        let summary = cloud_run_events_summary(&response).unwrap();
        assert_eq!(summary, "No run events found.");
    }

    #[test]
    fn cloud_run_state_summary_includes_live_progress_fields() {
        let response = serde_json::json!({
            "data": {
                "run_id": "run-1",
                "deployment_id": "dep-1",
                "status": "awaiting_approval",
                "phase": "waiting",
                "current_step": "approval",
                "current_tool": "send_email",
                "pending_approval_count": 2,
                "checkpoint_id": "chk-1",
                "latest_sequence": 7,
                "latest_event_kind": "approval_wait",
                "terminal": false
            }
        });

        let summary = cloud_run_state_summary(&response).unwrap();
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("status=awaiting_approval"));
        assert!(summary.contains("phase=waiting"));
        assert!(summary.contains("tool=send_email"));
        assert!(summary.contains("pending_approvals=2"));
        assert!(summary.contains("checkpoint=chk-1"));
        assert!(summary.contains("latest_sequence=7"));
        assert!(summary.contains("terminal=false"));
    }

    #[test]
    fn pending_cloud_approvals_summary_lists_runs_and_tools() {
        let response = serde_json::json!({
            "data": [
                {
                    "run_id": "run-1",
                    "deployment_name": "Quinn",
                    "status": "awaiting_approval",
                    "pending_approvals": [
                        { "id": "approval-1", "tool": "send_email" },
                        { "id": "approval-2", "tool": "create_ticket" }
                    ]
                }
            ]
        });

        let summary = pending_cloud_approvals_summary(&response).unwrap();
        assert!(summary.contains("1 run(s) awaiting approval:"));
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("deployment=Quinn"));
        assert!(summary.contains("status=awaiting_approval"));
        assert!(summary.contains("pending_approvals=2"));
        assert!(summary.contains("tools=send_email, create_ticket"));
    }

    #[test]
    fn cloud_runs_summary_lists_general_run_metadata() {
        let response = serde_json::json!({
            "data": [
                {
                    "run_id": "run-1",
                    "deployment_name": "Quinn",
                    "status": "completed",
                    "source": "interactive_session",
                    "created_at": "2026-07-06T00:00:00Z",
                    "model_id": "anthropic.claude-sonnet-4"
                }
            ]
        });

        let summary = cloud_runs_summary(&response).unwrap();
        assert!(summary.contains("1 cloud run(s):"));
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("deployment=Quinn"));
        assert!(summary.contains("status=completed"));
        assert!(summary.contains("source=interactive_session"));
        assert!(summary.contains("model=anthropic.claude-sonnet-4"));
        assert!(!summary.contains("awaiting approval"));
    }

    #[test]
    fn cloud_run_summary_includes_error_preview() {
        let response = serde_json::json!({
            "data": {
                "id": "run-1",
                "deployment_id": "dep-1",
                "status": "failed",
                "source": "scheduler",
                "error": "provider returned an error"
            }
        });

        let summary = cloud_run_summary(&response, "Cloud run").unwrap();
        assert!(summary.contains("Cloud run:"));
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("deployment=dep-1"));
        assert!(summary.contains("status=failed"));
        assert!(summary.contains("source=scheduler"));
        assert!(summary.contains("error=provider returned an error"));
    }

    #[test]
    fn cloud_agents_summary_lists_deployment_metadata() {
        let response = serde_json::json!({
            "data": [
                {
                    "id": "dep-1",
                    "name": "Quinn Atlas",
                    "status": "running",
                    "mode": "always_on",
                    "compute_backend": "aws_container",
                    "managed_agent": {
                        "model_id": "anthropic.claude-sonnet-4"
                    },
                    "updated_at": "2026-07-06T00:00:00Z"
                }
            ]
        });

        let summary = cloud_agents_summary(&response).unwrap();
        assert!(summary.contains("1 cloud agent deployment(s):"));
        assert!(summary.contains("name=Quinn Atlas"));
        assert!(summary.contains("id=dep-1"));
        assert!(summary.contains("status=running"));
        assert!(summary.contains("mode=always_on"));
        assert!(summary.contains("backend=aws_container"));
        assert!(summary.contains("model=anthropic.claude-sonnet-4"));
    }

    #[test]
    fn cloud_agent_summary_unwraps_data_envelope() {
        let response = serde_json::json!({
            "data": {
                "id": "dep-1",
                "name": "Quinn Atlas",
                "status": "stopped"
            }
        });

        let summary = cloud_agent_summary(&response, "Cloud agent").unwrap();
        assert!(summary.contains("Cloud agent:"));
        assert!(summary.contains("name=Quinn Atlas"));
        assert!(summary.contains("id=dep-1"));
        assert!(summary.contains("status=stopped"));
    }

    #[test]
    fn cloud_overview_summary_lists_counts() {
        let response = serde_json::json!({
            "summary": {
                "deployment_count": 4,
                "running_count": 2,
                "managed_count": 3,
                "cron_count": 1,
                "recent_runs_loaded": 8,
                "pending_approvals_loaded": 1
            }
        });

        let summary = cloud_overview_summary(&response).unwrap();
        assert!(summary.contains("deployments=4"));
        assert!(summary.contains("running=2"));
        assert!(summary.contains("managed=3"));
        assert!(summary.contains("cron=1"));
        assert!(summary.contains("recent_runs=8"));
        assert!(summary.contains("pending_approvals=1"));
    }

    #[test]
    fn cloud_deployment_spend_summary_lists_costs_and_window() {
        let response = serde_json::json!({
            "data": {
                "total_cost_usd": "12.34",
                "compute_cost_usd": "3.21",
                "inference_cost_usd": "9.13",
                "run_count": 42,
                "first_event_at": "2026-07-01T00:00:00Z",
                "last_event_at": "2026-07-06T00:00:00Z"
            }
        });

        let summary = cloud_deployment_spend_summary(&response).unwrap();
        assert!(summary.contains("Deployment spend:"));
        assert!(summary.contains("total_usd=12.34"));
        assert!(summary.contains("compute_usd=3.21"));
        assert!(summary.contains("inference_usd=9.13"));
        assert!(summary.contains("runs=42"));
        assert!(summary.contains("first=2026-07-01T00:00:00Z"));
        assert!(summary.contains("last=2026-07-06T00:00:00Z"));
    }

    #[test]
    fn cloud_audit_entries_summary_uses_top_level_metadata() {
        let response = serde_json::json!({
            "data": [
                {
                    "id": "entry-1",
                    "sequence_number": 42,
                    "action": "run.created",
                    "actor": "system",
                    "invocation_id": "11111111-1111-4111-8111-111111111111",
                    "publisher_id": "22222222-2222-4222-8222-222222222222",
                    "created_at": "2026-07-06T00:00:00Z",
                    "details": { "ignored": true }
                }
            ]
        });

        let summary = cloud_audit_entries_summary(&response).unwrap();
        assert!(summary.contains("1 cloud audit entry(s):"));
        assert!(summary.contains("#42"));
        assert!(summary.contains("action=run.created"));
        assert!(summary.contains("actor=system"));
        assert!(summary.contains("id=entry-1"));
        assert!(summary.contains("invocation=11111111-1111-4111-8111-111111111111"));
        assert!(summary.contains("publisher=22222222-2222-4222-8222-222222222222"));
        assert!(summary.contains("created=2026-07-06T00:00:00Z"));
        assert!(!summary.contains("ignored"));
    }

    #[test]
    fn cloud_audit_entry_summary_unwraps_data_envelope() {
        let response = serde_json::json!({
            "data": {
                "id": "entry-1",
                "sequence_number": 42,
                "action": "run.created",
                "actor": "system",
                "created_at": "2026-07-06T00:00:00Z"
            }
        });

        let summary = cloud_audit_entry_summary(&response).unwrap();
        assert!(summary.contains("Cloud audit entry:"));
        assert!(summary.contains("#42"));
        assert!(summary.contains("action=run.created"));
        assert!(summary.contains("actor=system"));
        assert!(summary.contains("id=entry-1"));
    }

    #[test]
    fn cloud_audit_verify_summary_shows_integrity_result() {
        let response = serde_json::json!({
            "data": {
                "verified": false,
                "entries_checked": 100,
                "first_invalid_sequence": 42,
                "error": "hash mismatch"
            }
        });

        let summary = cloud_audit_verify_summary(&response).unwrap();
        assert!(summary.contains("Cloud audit verification:"));
        assert!(summary.contains("verified=false"));
        assert!(summary.contains("entries_checked=100"));
        assert!(summary.contains("first_invalid_sequence=42"));
        assert!(summary.contains("error=hash mismatch"));
    }

    #[test]
    fn cloud_run_artifacts_summary_lists_declared_metadata() {
        let response = serde_json::json!({
            "data": [
                {
                    "id": "artifact-1",
                    "artifact_type": "screenshot",
                    "title": "Home page screenshot",
                    "url": "https://example.com/artifacts/1",
                    "created_at": "2026-07-06T00:00:00Z"
                }
            ]
        });

        let summary = cloud_run_artifacts_summary(&response).unwrap();
        assert!(summary.contains("1 run artifact(s):"));
        assert!(summary.contains("id=artifact-1"));
        assert!(summary.contains("type=screenshot"));
        assert!(summary.contains("title=Home page screenshot"));
        assert!(summary.contains("url=https://example.com/artifacts/1"));
        assert!(summary.contains("created=2026-07-06T00:00:00Z"));
    }

    #[test]
    fn cloud_run_evals_summary_lists_counts_and_first_links() {
        let response = serde_json::json!({
            "data": {
                "run_id": "run-1",
                "source_eval_cases": [
                    { "id": "case-1", "name": "Homepage loads" }
                ],
                "actual_eval_case_results": [
                    { "eval_case_id": "case-1", "status": "passed" }
                ]
            }
        });

        let summary = cloud_run_evals_summary(&response).unwrap();
        assert!(summary.contains("Run eval links:"));
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("source_eval_cases=1"));
        assert!(summary.contains("actual_eval_results=1"));
        assert!(summary.contains("first_source_case=case-1"));
        assert!(summary.contains("first_result_case=case-1"));
        assert!(summary.contains("first_result_status=passed"));
    }

    #[test]
    fn run_pending_approvals_summary_lists_checkpoint_and_tools() {
        let response = serde_json::json!({
            "data": {
                "run_id": "run-1",
                "status": "awaiting_approval",
                "checkpoint_id": "chk-1",
                "pending_approvals": [
                    { "id": "approval-1", "tool": "send_email" }
                ]
            }
        });

        let summary = run_pending_approvals_summary(&response).unwrap();
        assert!(summary.contains("run=run-1"));
        assert!(summary.contains("status=awaiting_approval"));
        assert!(summary.contains("checkpoint=chk-1"));
        assert!(summary.contains("pending_approvals=1"));
        assert!(summary.contains("tools=send_email"));
    }

    #[test]
    fn cloud_agent_schedules_summary_lists_status_and_timing() {
        let response = serde_json::json!({
            "data": [
                {
                    "id": "sched-1",
                    "schedule_key": "daily-report",
                    "schedule_kind": "cron",
                    "status": "active",
                    "next_run_at": "2026-07-07T00:00:00Z",
                    "cron_schedule": "0 0 * * *",
                    "cron_timezone": "UTC",
                    "attempts": 1,
                    "max_attempts": 3
                }
            ]
        });

        let summary = cloud_agent_schedules_summary(&response).unwrap();
        assert!(summary.contains("1 agent schedule(s):"));
        assert!(summary.contains("id=sched-1"));
        assert!(summary.contains("key=daily-report"));
        assert!(summary.contains("kind=cron"));
        assert!(summary.contains("status=active"));
        assert!(summary.contains("next=2026-07-07T00:00:00Z"));
        assert!(summary.contains("cron=0 0 * * *"));
        assert!(summary.contains("tz=UTC"));
        assert!(summary.contains("attempts=1/3"));
    }

    #[test]
    fn cloud_agent_schedule_summary_includes_terminal_error() {
        let response = serde_json::json!({
            "data": {
                "id": "sched-1",
                "schedule_key": "daily-report",
                "schedule_kind": "cron",
                "status": "failed_terminal",
                "next_run_at": "2026-07-07T00:00:00Z",
                "attempts": 3,
                "max_attempts": 3,
                "last_error": "provider error"
            }
        });

        let summary = cloud_agent_schedule_summary(&response, "Agent schedule").unwrap();
        assert!(summary.contains("Agent schedule:"));
        assert!(summary.contains("id=sched-1"));
        assert!(summary.contains("key=daily-report"));
        assert!(summary.contains("status=failed_terminal"));
        assert!(summary.contains("error=provider error"));
    }

    #[test]
    fn cloud_conversations_summary_lists_counts_and_cursor() {
        let response = serde_json::json!({
            "data": {
                "conversations": [
                    {
                        "conversation_id": "thread-1",
                        "title": "Research notes",
                        "message_count": 5,
                        "last_source": "interactive_session",
                        "last_activity_at": "2026-07-06T00:00:00Z"
                    }
                ],
                "has_more": true,
                "next_cursor": "cursor-2"
            }
        });

        let summary = cloud_conversations_summary(&response).unwrap();
        assert!(summary.contains("1 employee conversation(s):"));
        assert!(summary.contains("id=thread-1"));
        assert!(summary.contains("title=Research notes"));
        assert!(summary.contains("messages=5"));
        assert!(summary.contains("source=interactive_session"));
        assert!(summary.contains("next_cursor=cursor-2"));
    }

    #[test]
    fn cloud_conversation_messages_summary_lists_run_status_and_preview() {
        let response = serde_json::json!({
            "data": {
                "messages": [
                    {
                        "created_at": "2026-07-06T00:00:05Z",
                        "role": "assistant",
                        "source": "interactive_session",
                        "run_id": "11111111-1111-4111-8111-111111111111",
                        "run_summary": { "status": "completed" },
                        "events": [{ "kind": "text" }, { "kind": "done" }],
                        "content": "Hello\n\nfrom the employee"
                    }
                ],
                "has_more": false
            }
        });

        let summary = cloud_conversation_messages_summary(&response).unwrap();
        assert!(summary.contains("1 conversation message(s):"));
        assert!(summary.contains("role=assistant"));
        assert!(summary.contains("source=interactive_session"));
        assert!(summary.contains("run=11111111-1111-4111-8111-111111111111"));
        assert!(summary.contains("status=completed"));
        assert!(summary.contains("events=2"));
        assert!(summary.contains("content=Hello from the employee"));
    }

    /// Collect boolean subschemas using the same position logic as `normalize_json_schema`.
    fn collect_schema_slot_booleans(node: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let child = format!("{path}/{key}");
                    if super::SCHEMA_DATA_KEYWORDS.contains(&key.as_str()) {
                        continue;
                    } else if super::SCHEMA_MAP_KEYWORDS.contains(&key.as_str()) {
                        if let serde_json::Value::Object(entries) = value {
                            for (name, entry) in entries {
                                check_schema_slot(entry, &format!("{child}/{name}"), out);
                            }
                        }
                    } else if super::SCHEMA_ARRAY_KEYWORDS.contains(&key.as_str()) {
                        if let serde_json::Value::Array(items) = value {
                            for (index, item) in items.iter().enumerate() {
                                check_schema_slot(item, &format!("{child}/{index}"), out);
                            }
                        }
                    } else if super::SCHEMA_SLOT_KEYWORDS.contains(&key.as_str()) {
                        check_schema_slot(value, &child, out);
                    } else {
                        collect_schema_slot_booleans(value, &child, out);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    collect_schema_slot_booleans(item, &format!("{path}/{index}"), out);
                }
            }
            _ => {}
        }
    }

    fn check_schema_slot(node: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        if node.is_boolean() {
            out.push(path.to_string());
        } else {
            collect_schema_slot_booleans(node, path, out);
        }
    }

    #[test]
    fn no_served_tool_input_schema_has_boolean_subschema() {
        let server = server_with_http_client(reqwest::Client::new());
        let mut offenders = Vec::new();
        for tool in server.tool_router.list_all() {
            let normalized = super::normalize_tool_input_schema(tool);
            let schema = serde_json::Value::Object((*normalized.input_schema).clone());
            let mut out = Vec::new();
            collect_schema_slot_booleans(&schema, "", &mut out);
            if !out.is_empty() {
                offenders.push(format!("{}: {}", normalized.name, out.join(", ")));
            }
        }
        assert!(
            offenders.is_empty(),
            "served tool schemas still contain boolean subschemas:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn normalize_json_schema_rewrites_boolean_slots_but_keeps_data_bools() {
        let mut schema = serde_json::json!({
            "type": "object",
            "properties": {
                "metadata": true,
                "tags": { "type": "array", "items": true },
                "nested": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { "inner": true }
                }
            },
            "additionalProperties": false,
            "$defs": { "Blob": true },
            "default": true
        });
        super::normalize_json_schema(&mut schema);

        assert_eq!(schema["properties"]["metadata"], serde_json::json!({}));
        assert_eq!(schema["properties"]["tags"]["items"], serde_json::json!({}));
        assert_eq!(
            schema["properties"]["nested"]["properties"]["inner"],
            serde_json::json!({})
        );
        assert_eq!(schema["$defs"]["Blob"], serde_json::json!({}));
        assert_eq!(
            schema["additionalProperties"],
            serde_json::json!({ "not": {} })
        );
        assert_eq!(
            schema["properties"]["nested"]["additionalProperties"],
            serde_json::json!({ "not": {} })
        );
        // Literal instance data remains unchanged.
        assert_eq!(schema["default"], serde_json::json!(true));
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

    #[tokio::test]
    async fn call_publisher_routes_seren_passwords_tools_to_builtin_mcp_tools() {
        let server = server_with_http_client(reqwest::Client::new());
        let params = CallPublisherParams {
            publisher: "seren-passwords".to_string(),
            query: None,
            database: None,
            method: None,
            path: None,
            headers: None,
            body: None,
            body_base64: None,
            tool: Some("passwords_vaults_list".to_string()),
            tool_args: None,
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let err = server
            .call_publisher_mcp_tool(
                &params,
                &Extensions::default(),
                &AgentMetadata::default(),
                false,
            )
            .await
            .expect_err("unconfigured built-in passwords tool should fail locally");

        assert!(
            err.to_string().contains("Vault locked"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn call_publisher_seren_passwords_vaults_list_maps_invalid_gateway_url_to_setup_error() {
        let mut server = server_with_http_client(reqwest::Client::new());
        server.passwords_api_base_url =
            "http://gateway.internal.example/publishers/seren-passwords".to_string();
        let kem = seren_secrets_crypto::keys::IdentityKemKeypair::generate();
        let signing = seren_secrets_crypto::keys::IdentitySigningKeypair::generate();
        *server.passwords_session.lock().await = Some(crate::passwords::PasswordsSession {
            kem_private: kem.private,
            signing_private: signing.private,
            last_activity: std::time::Instant::now(),
        });
        let params = CallPublisherParams {
            publisher: "seren-passwords".to_string(),
            query: None,
            database: None,
            method: None,
            path: None,
            headers: None,
            body: None,
            body_base64: None,
            tool: Some("passwords_vaults_list".to_string()),
            tool_args: None,
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let err = server
            .call_publisher_mcp_tool(
                &params,
                &Extensions::default(),
                &AgentMetadata::default(),
                false,
            )
            .await
            .expect_err("invalid passwords gateway URL must fail before network access");

        assert!(
            err.message.contains("Seren Passwords is misconfigured"),
            "unexpected error: {err}"
        );
        assert!(err.message.contains("SEREN_PASSWORDS_API_URL"));
        assert!(!err.message.contains("uri shape is invalid"));
    }

    #[tokio::test]
    async fn call_publisher_seren_passwords_vaults_list_rejects_tool_args() {
        let server = server_with_http_client(reqwest::Client::new());
        let mut tool_args = serde_json::Map::new();
        tool_args.insert("vault_id".to_string(), serde_json::json!("anything"));
        let params = CallPublisherParams {
            publisher: "seren-passwords".to_string(),
            query: None,
            database: None,
            method: None,
            path: None,
            headers: None,
            body: None,
            body_base64: None,
            tool: Some("passwords_vaults_list".to_string()),
            tool_args: Some(tool_args),
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let err = server
            .call_publisher_mcp_tool(
                &params,
                &Extensions::default(),
                &AgentMetadata::default(),
                false,
            )
            .await
            .expect_err("vaults_list must reject tool_args before any vault access");

        assert!(
            err.to_string().contains("does not accept tool_args"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn call_publisher_seren_passwords_item_get_requires_item_id() {
        let server = server_with_http_client(reqwest::Client::new());
        let params = CallPublisherParams {
            publisher: "seren-passwords".to_string(),
            query: None,
            database: None,
            method: None,
            path: None,
            headers: None,
            body: None,
            body_base64: None,
            tool: Some("passwords_item_get".to_string()),
            tool_args: Some(serde_json::Map::new()),
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let err = server
            .call_publisher_mcp_tool(
                &params,
                &Extensions::default(),
                &AgentMetadata::default(),
                false,
            )
            .await
            .expect_err("item_get must reject missing item_id at decode time");

        assert!(
            err.to_string().contains("invalid tool_args"),
            "unexpected error: {err}"
        );
    }

    fn endpoint_param(method: &str, path: &str) -> EndpointDefinitionParam {
        EndpointDefinitionParam {
            method: method.to_string(),
            path: path.to_string(),
            description: None,
            query_params: None,
            request_content_type: None,
            access: None,
            is_protected: false,
            protection_reason: None,
            price: None,
        }
    }

    #[test]
    fn endpoint_param_to_definition_preserves_public_anonymous_access() {
        let mut param = endpoint_param("GET", "/skills/{slug}/download/manifest");
        param.access = Some(EndpointAccessParam::PublicAnonymous);

        let endpoint = endpoint_param_to_definition(param).unwrap();
        let value = serde_json::to_value(endpoint).unwrap();

        assert_eq!(value["access"], "public_anonymous");
    }

    #[test]
    fn endpoint_param_to_definition_defaults_access_when_omitted() {
        let endpoint = endpoint_param_to_definition(endpoint_param("GET", "/skills")).unwrap();
        let value = serde_json::to_value(endpoint).unwrap();

        assert_eq!(value["access"], "authenticated");
    }

    #[test]
    fn endpoint_param_to_definition_rejects_public_anonymous_post() {
        let mut param = endpoint_param("POST", "/organizations/{org_id}/folder/transfer");
        param.access = Some(EndpointAccessParam::PublicAnonymous);

        let error = endpoint_param_to_definition(param).expect_err("POST cannot be public");

        assert!(error.to_string().contains("only valid for GET endpoints"));
    }

    #[test]
    fn endpoint_param_to_definition_rejects_public_anonymous_protected_endpoint() {
        let mut param = endpoint_param("GET", "/skills/{slug}/download");
        param.access = Some(EndpointAccessParam::PublicAnonymous);
        param.is_protected = true;

        let error =
            endpoint_param_to_definition(param).expect_err("protected endpoint cannot be public");

        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn x402_proxy_payment_header_name_detects_v1_and_v2() {
        let v1_payload = serde_json::json!({ "x402Version": 1 });
        let v1_b64 = base64::engine::general_purpose::STANDARD.encode(v1_payload.to_string());
        assert_eq!(
            x402_proxy_payment_header_name(&v1_b64).unwrap(),
            "X-PAYMENT"
        );

        let v2_payload = serde_json::json!({ "x402Version": 2 });
        let v2_b64 = base64::engine::general_purpose::STANDARD.encode(v2_payload.to_string());
        assert_eq!(
            x402_proxy_payment_header_name(&v2_b64).unwrap(),
            "PAYMENT-SIGNATURE"
        );

        assert!(x402_proxy_payment_header_name("not-base64").is_err());
    }

    #[test]
    fn validate_sql_query_enforces_size_and_non_empty() {
        assert!(validate_sql_query("select 1").is_ok());
        assert!(validate_sql_query("  ").is_err());

        let too_large = "a".repeat(1_000_001);
        assert!(validate_sql_query(&too_large).is_err());
    }

    #[test]
    fn format_decimal_units_trims_trailing_zeroes() {
        assert_eq!(format_decimal_units("1000000000000000000", 18), "1");
        assert_eq!(format_decimal_units("2500000", 6), "2.5");
        assert_eq!(format_decimal_units("1", 6), "0.000001");
        assert_eq!(format_decimal_units("0", 6), "0");
    }

    #[test]
    fn bundle_prompt_override_preserves_assets_and_clears_sha() {
        let bundle = seren::AgentBundle {
            assets: vec![seren::AgentAssetFile {
                content_base64: "Zm9v".to_string(),
                content_type: None,
                path: "notes.txt".to_string(),
                purpose: None,
                sha256: Some("asset-sha".to_string()),
            }],
            instructions: vec![seren::AgentInstructionFile {
                allowed_tools: None,
                content: "old prompt".to_string(),
                kind: seren::AgentInstructionKind::Skill,
                path: Some("SKILL.md".to_string()),
                sha256: Some("old-sha".to_string()),
                skill_name: None,
            }],
        };

        let bundle = bundle_with_prompt_override(bundle, Some("new prompt".to_string()));

        assert_eq!(bundle.assets.len(), 1);
        assert_eq!(bundle.instructions.len(), 1);
        assert_eq!(bundle.instructions[0].content, "new prompt");
        assert!(bundle.instructions[0].sha256.is_none());
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
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user:pass@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .and(header("SerenDB-Connection-String", conn.as_str()))
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

        let server = SerenMcpServer::new("test-key", "https://api.serendb.com").unwrap();
        let result = server
            .execute_sql(
                &conn,
                "select $1",
                vec![serde_json::json!(1)],
                None,
                QUERY_TIMEOUT,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_sql_includes_bearer_for_passwordless_connection_string() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .and(header("SerenDB-Connection-String", conn.as_str()))
            .and(header("SerenDB-Pool-Opt-In", "true"))
            .and(header("Authorization", "Bearer token123"))
            .and(body_json(serde_json::json!({
                "query": "select $1",
                "params": [1],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", "https://api.serendb.com").unwrap();
        let result = server
            .execute_sql(
                &conn,
                "select $1",
                vec![serde_json::json!(1)],
                Some("token123"),
                QUERY_TIMEOUT,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_sql_includes_bearer_for_empty_password_connection_string() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user:@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .and(header("SerenDB-Connection-String", conn.as_str()))
            .and(header("SerenDB-Pool-Opt-In", "true"))
            .and(header("Authorization", "Bearer token123"))
            .and(body_json(serde_json::json!({
                "query": "select $1",
                "params": [1],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", "https://api.serendb.com").unwrap();
        let result = server
            .execute_sql(
                &conn,
                "select $1",
                vec![serde_json::json!(1)],
                Some("token123"),
                QUERY_TIMEOUT,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_sql_request_timeout_overrides_client_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user:pass@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(150))
                    .set_body_json(serde_json::json!({
                        "ok": true,
                    })),
            )
            .mount(&proxy)
            .await;

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let server = server_with_http_client(http_client);
        let result = server
            .execute_sql(
                &conn,
                "select 1",
                vec![],
                None,
                std::time::Duration::from_millis(500),
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_sql_transaction_sets_batch_headers() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user:pass@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .and(header("SerenDB-Connection-String", conn.as_str()))
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

        let server = SerenMcpServer::new("test-key", "https://api.serendb.com").unwrap();
        let result = server
            .execute_sql_transaction(
                &conn,
                vec!["select 1".to_string(), "select 2".to_string()],
                Some(true),
                Some("read_committed".to_string()),
                Some(true),
                None,
                QUERY_TIMEOUT,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_sql_transaction_request_timeout_overrides_client_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let proxy_url = reqwest::Url::parse(&proxy.uri()).unwrap();
        let host = proxy_url.host_str().unwrap();
        let port = proxy_url.port().unwrap();
        let conn = format!("postgresql://user:pass@{host}:{port}/postgres?sslmode=require");

        Mock::given(method("POST"))
            .and(path("/sql"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_millis(150))
                    .set_body_json(serde_json::json!({
                        "ok": true,
                    })),
            )
            .mount(&proxy)
            .await;

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let server = server_with_http_client(http_client);
        let result = server
            .execute_sql_transaction(
                &conn,
                vec!["select 1".to_string()],
                None,
                None,
                None,
                None,
                std::time::Duration::from_millis(500),
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({ "ok": true }));
    }

    #[tokio::test]
    async fn execute_publisher_proxy_raw_forwards_headers_and_request_id() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let request_id = Uuid::new_v4();
        let request_id_value = request_id.to_string();
        let mut passthrough_headers = HashMap::new();
        passthrough_headers.insert("x-custom-header".to_string(), "custom-value".to_string());

        Mock::given(method("POST"))
            .and(path("/publishers/test-publisher/echo"))
            .and(header("Authorization", "Bearer test-key"))
            .and(header("x-request-id", request_id_value.as_str()))
            .and(header("x-custom-header", "custom-value"))
            .and(body_json(serde_json::json!({
                "hello": "world",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let extensions = extensions_with_headers(&[]);
        let response = server
            .execute_publisher_proxy_raw(
                &extensions,
                &AgentMetadata::default(),
                QUERY_TIMEOUT,
                &reqwest::Method::POST,
                "/publishers/test-publisher/echo",
                Some(&serde_json::json!({
                    "hello": "world",
                })),
                None,
                Some(&passthrough_headers),
                Some(request_id),
                None,
            )
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn call_publisher_api_forwards_body_base64_as_raw_bytes() {
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/publishers/deepgram-serenai/v1/listen"))
            .and(header("Authorization", "Bearer test-key"))
            .and(header("Content-Type", "audio/mp3"))
            .and(body_string_contains("hello"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "audio/mp3".to_string());
        let params = CallPublisherParams {
            publisher: "deepgram-serenai".to_string(),
            query: None,
            database: None,
            method: Some("POST".to_string()),
            path: Some("/v1/listen".to_string()),
            headers: Some(headers),
            body: None,
            body_base64: Some("aGVsbG8=".to_string()),
            tool: None,
            tool_args: None,
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let result = server
            .call_publisher_api(
                &params,
                &extensions_with_headers(&[]),
                &AgentMetadata::default(),
                false,
            )
            .await
            .unwrap();

        assert!(!result.is_error.unwrap_or(false));
    }

    #[tokio::test]
    async fn fetch_onchain_wallet_status_reads_base_eth_and_usdc_balances() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let rpc = MockServer::start().await;
        let server = SerenMcpServer::new("test-key", "https://api.serendb.com").unwrap();
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();
        let address = wallet.address().to_string();

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBalance",
                "params": [address.clone(), "latest"],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0xde0b6b3a7640000",
            })))
            .mount(&rpc)
            .await;

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_call",
                "params": [
                    {
                        "to": BASE_USDC_ADDRESS,
                        "data": erc20_balance_of_call_data(&address),
                    },
                    "latest"
                ],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x1e8480",
            })))
            .mount(&rpc)
            .await;

        let status = server
            .fetch_onchain_wallet_status(&rpc.uri(), &wallet)
            .await
            .unwrap();

        assert_eq!(
            status,
            serde_json::json!({
                "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                "network": "base",
                "chain_id": 8453,
                "native": {
                    "asset_symbol": "ETH",
                    "balance_wei": "1000000000000000000",
                    "balance": "1",
                },
                "usdc": {
                    "asset_symbol": "USDC",
                    "contract_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "balance_raw": "2000000",
                    "balance": "2",
                    "balance_usd": "2",
                }
            })
        );
    }

    #[tokio::test]
    async fn call_publisher_api_unwraps_stringified_json_body() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/publishers/test-publisher/echo"))
            .and(header("Authorization", "Bearer test-key"))
            .and(body_json(serde_json::json!({
                "hello": "world",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let extensions = extensions_with_headers(&[]);
        let params = CallPublisherParams {
            publisher: "test-publisher".to_string(),
            query: None,
            database: None,
            method: Some("POST".to_string()),
            path: Some("/echo".to_string()),
            headers: None,
            body: Some(serde_json::Value::String(
                r#"{"hello":"world"}"#.to_string(),
            )),
            body_base64: None,
            tool: None,
            tool_args: None,
            resource_uri: None,
            response_format: None,
            request_id: None,
            confirm: false,
            x402_payment: None,
        };

        let result = server
            .call_publisher_api(&params, &extensions, &AgentMetadata::default(), false)
            .await
            .unwrap();

        assert!(!result.is_error.unwrap_or(false));
    }

    #[tokio::test]
    async fn execute_with_proxy_payment_json_forwards_query_string() {
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let resource_uri = "file:///data.json";
        let query_string = format!("uri={}", urlencoding::encode(resource_uri));
        let x402_payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::json!({ "x402Version": 2 }).to_string());

        let wrapped_response = serde_json::json!({
            "data": {
                "status": 200,
                "body": { "ok": true },
                "cost": "0.001",
                "asset_symbol": "USDC"
            }
        });

        Mock::given(method("GET"))
            .and(path("/publishers/test-publisher/_mcp/resources"))
            .and(query_param("uri", resource_uri))
            .and(header("PAYMENT-SIGNATURE", x402_payload.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(wrapped_response.clone()))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let result = server
            .execute_with_proxy_payment_json::<serde_json::Value>(
                &reqwest::Method::GET,
                "/publishers/test-publisher/_mcp/resources",
                None,
                None,
                None,
                None,
                &x402_payload,
                &AgentMetadata::default(),
                Some(&query_string),
            )
            .await
            .unwrap();

        assert_eq!(result, wrapped_response);
    }

    #[tokio::test]
    async fn execute_x402_roundtrip_json_preserves_query_string() {
        use wiremock::matchers::{header_exists, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let resource_uri = "file:///data.json";
        let query_string = format!("uri={}", urlencoding::encode(resource_uri));
        let payment_required = serde_json::json!({
            "x402Version": 2,
            "resource": {
                "url": "/publishers/test-publisher/_mcp/resources",
                "description": "MCP resource",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "paymentRequestId": "req-1"
                }
            }]
        });

        Mock::given(method("GET"))
            .and(path("/publishers/test-publisher/_mcp/resources"))
            .and(query_param("uri", resource_uri))
            .and(header_exists("X-AGENT-WALLET"))
            .respond_with(ResponseTemplate::new(402).set_body_json(payment_required))
            .with_priority(2)
            .up_to_n_times(1)
            .mount(&proxy)
            .await;

        let wrapped_response = serde_json::json!({
            "data": {
                "status": 200,
                "body": { "ok": true },
                "cost": "0.001",
                "asset_symbol": "USDC"
            }
        });

        Mock::given(method("GET"))
            .and(path("/publishers/test-publisher/_mcp/resources"))
            .and(query_param("uri", resource_uri))
            .and(header_exists("X-AGENT-WALLET"))
            .and(header_exists("PAYMENT-SIGNATURE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(wrapped_response.clone()))
            .with_priority(1)
            .mount(&proxy)
            .await;

        let mut server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        server.wallet = Some(Arc::new(
            PrivateKeyWallet::from_env_or_key(Some(
                "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
            ))
            .unwrap()
            .unwrap(),
        ));
        server.signer_config.auto_approve_limit_micros = 1_000_000;

        let result = server
            .execute_x402_roundtrip_json::<serde_json::Value>(
                &reqwest::Method::GET,
                "/publishers/test-publisher/_mcp/resources",
                None,
                None,
                None,
                None,
                false,
                &AgentMetadata::default(),
                Some(&query_string),
            )
            .await
            .unwrap();

        assert_eq!(result, wrapped_response);
    }

    #[tokio::test]
    async fn api_client_with_timeout_request_id_forwards_header_on_generated_call() {
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let publisher_slug = "db-publisher";
        let request_id = Uuid::new_v4();
        let request_id_value = request_id.to_string();

        Mock::given(method("POST"))
            .and(path(format!("/publishers/{publisher_slug}")))
            .and(header("Authorization", "Bearer test-key"))
            .and(header("x-request-id", request_id_value.as_str()))
            .and(body_string_contains("select 1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let extensions = extensions_with_headers(&[]);
        let api_client = server
            .api_client_with_timeout_request_id(&extensions, QUERY_TIMEOUT, Some(request_id))
            .unwrap();
        let body: seren::PublisherRootRequest = seren::DatabaseQueryRequest {
            query: "select 1".to_string(),
            database: None,
            params: vec![],
        }
        .into();

        api_client
            .publisher_root_handler(publisher_slug, &body)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upload_publisher_logo_accepts_large_base64_payload() {
        use wiremock::matchers::{body_string_contains, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let organization_id = Uuid::new_v4();
        let publisher_id = Uuid::new_v4();
        let logo = "A".repeat(30_000);

        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{organization_id}/publishers/{publisher_id}/logo"
            )))
            .and(header("Authorization", "Bearer test-key"))
            .and(body_string_contains("\"content_type\":\"image/png\""))
            .and(body_string_contains(&logo))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "message": "Logo uploaded successfully",
                    "logo_url": "/publishers/test/logo"
                }
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let extensions = extensions_with_headers(&[]);
        let params = UploadPublisherLogoParams {
            organization_id,
            publisher_id,
            logo,
            content_type: "image/png".to_string(),
        };

        let result = server
            .upload_publisher_logo(Parameters(params), extensions)
            .await
            .unwrap();

        assert!(!result.is_error.unwrap_or(false));
        // Verify the response body actually round-tripped, not just that
        // is_error is unset (which is the default for a successful tool call).
        let json = serde_json::to_value(&result).expect("CallToolResult is JSON-serializable");
        let serialized = json.to_string();
        assert!(
            serialized.contains("Logo uploaded successfully"),
            "missing success message in CallToolResult: {serialized}"
        );
        assert!(
            serialized.contains("/publishers/test/logo"),
            "missing logo_url in CallToolResult: {serialized}"
        );
    }

    #[tokio::test]
    async fn upload_publisher_logo_surfaces_upstream_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let proxy = MockServer::start().await;
        let organization_id = Uuid::new_v4();
        let publisher_id = Uuid::new_v4();

        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{organization_id}/publishers/{publisher_id}/logo"
            )))
            .respond_with(ResponseTemplate::new(413).set_body_json(serde_json::json!({
                "message": "payload too large"
            })))
            .mount(&proxy)
            .await;

        let server = SerenMcpServer::new("test-key", &proxy.uri()).unwrap();
        let extensions = extensions_with_headers(&[]);
        let params = UploadPublisherLogoParams {
            organization_id,
            publisher_id,
            logo: "A".repeat(8),
            content_type: "image/png".to_string(),
        };

        let err = server
            .upload_publisher_logo(Parameters(params), extensions)
            .await
            .expect_err("upstream 413 should surface as McpError, not hang or succeed");
        let msg = err.message.to_string();
        assert!(
            msg.contains("413") || msg.to_ascii_lowercase().contains("payload too large"),
            "expected 413/payload-too-large in error, got: {msg}"
        );
    }

    #[test]
    fn extract_agent_metadata_includes_user_id_from_header() {
        let extensions =
            extensions_with_headers(&[("x-user-id", "550e8400-e29b-41d4-a716-446655440000")]);
        let metadata = extract_agent_metadata_from_extensions(&extensions);
        assert_eq!(
            metadata.user_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn extract_agent_metadata_returns_none_for_missing_user_id() {
        let extensions = extensions_with_headers(&[]);
        let metadata = extract_agent_metadata_from_extensions(&extensions);
        assert!(metadata.user_id.is_none());
    }

    #[test]
    fn hosted_passwords_credential_subject_uses_user_api_key_id() {
        let api_key_id = Uuid::new_v4();
        let extensions = extensions_with_auth_context(crate::SerenRequestAuthContext {
            user_id: Uuid::new_v4(),
            email: None,
            credential: crate::SerenRequestCredential::UserApiKey {
                api_key_id: Some(api_key_id),
            },
        });

        let subject = hosted_passwords_credential_subject_from_extensions(&extensions).unwrap();

        assert_eq!(
            subject,
            crate::oauth::store::HostedPasswordsCredentialSubject::UserApiKey(api_key_id)
        );
    }

    #[test]
    fn hosted_passwords_credential_subject_defaults_to_user_for_oauth() {
        let extensions = extensions_with_auth_context(crate::SerenRequestAuthContext {
            user_id: Uuid::new_v4(),
            email: None,
            credential: crate::SerenRequestCredential::UserSession,
        });

        let subject = hosted_passwords_credential_subject_from_extensions(&extensions).unwrap();

        assert_eq!(
            subject,
            crate::oauth::store::HostedPasswordsCredentialSubject::User
        );
    }

    #[test]
    fn hosted_passwords_credential_subject_rejects_api_key_without_metadata() {
        let extensions = extensions_with_auth_context(crate::SerenRequestAuthContext {
            user_id: Uuid::new_v4(),
            email: None,
            credential: crate::SerenRequestCredential::UserApiKey { api_key_id: None },
        });

        assert!(hosted_passwords_credential_subject_from_extensions(&extensions).is_err());
    }

    #[test]
    fn extract_agent_metadata_includes_all_agent_headers() {
        let extensions = extensions_with_headers(&[
            ("x-user-id", "user-123"),
            ("x-agent-client-id", "client-456"),
            ("x-agent-client-name", "Test Agent"),
            ("x-agent-software-id", "software-789"),
            ("x-agent-software-version", "1.0.0"),
        ]);
        let metadata = extract_agent_metadata_from_extensions(&extensions);
        assert_eq!(metadata.user_id.as_deref(), Some("user-123"));
        assert_eq!(metadata.client_id.as_deref(), Some("client-456"));
        assert_eq!(metadata.client_name.as_deref(), Some("Test Agent"));
        assert_eq!(metadata.software_id.as_deref(), Some("software-789"));
        assert_eq!(metadata.software_version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn insert_agent_metadata_headers_forwards_user_id() {
        let metadata = AgentMetadata {
            user_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            client_id: None,
            client_name: None,
            software_id: None,
            software_version: None,
        };
        let mut headers = reqwest::header::HeaderMap::new();
        SerenMcpServer::insert_agent_metadata_headers(&mut headers, &metadata);

        assert_eq!(
            headers.get("x-user-id").and_then(|v| v.to_str().ok()),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn insert_agent_metadata_headers_forwards_all_metadata() {
        let metadata = AgentMetadata {
            user_id: Some("user-123".to_string()),
            client_id: Some("client-456".to_string()),
            client_name: Some("Test Agent".to_string()),
            software_id: Some("software-789".to_string()),
            software_version: Some("1.0.0".to_string()),
        };
        let mut headers = reqwest::header::HeaderMap::new();
        SerenMcpServer::insert_agent_metadata_headers(&mut headers, &metadata);

        assert_eq!(
            headers.get("x-user-id").and_then(|v| v.to_str().ok()),
            Some("user-123")
        );
        assert_eq!(
            headers
                .get("x-agent-client-id")
                .and_then(|v| v.to_str().ok()),
            Some("client-456")
        );
        assert_eq!(
            headers
                .get("x-agent-client-name")
                .and_then(|v| v.to_str().ok()),
            Some("Test Agent")
        );
        assert_eq!(
            headers
                .get("x-agent-software-id")
                .and_then(|v| v.to_str().ok()),
            Some("software-789")
        );
        assert_eq!(
            headers
                .get("x-agent-software-version")
                .and_then(|v| v.to_str().ok()),
            Some("1.0.0")
        );
    }

    #[test]
    fn insert_agent_metadata_headers_skips_none_values() {
        let metadata = AgentMetadata::default();
        let mut headers = reqwest::header::HeaderMap::new();
        SerenMcpServer::insert_agent_metadata_headers(&mut headers, &metadata);

        assert!(headers.get("x-user-id").is_none());
        assert!(headers.get("x-agent-client-id").is_none());
        assert!(headers.get("x-agent-client-name").is_none());
        assert!(headers.get("x-agent-software-id").is_none());
        assert!(headers.get("x-agent-software-version").is_none());
    }

    #[test]
    fn build_deployment_name_map_prefers_name_then_skill_slug() {
        let deployments = vec![
            serde_json::json!({
                "id": "dep-1",
                "name": "Ops Router",
                "skill_slug": "ops-router"
            }),
            serde_json::json!({
                "id": "dep-2",
                "skill_slug": "btc-watcher"
            }),
        ];

        let map = super::build_deployment_name_map(&deployments);
        assert_eq!(map.get("dep-1").map(String::as_str), Some("Ops Router"));
        assert_eq!(map.get("dep-2").map(String::as_str), Some("btc-watcher"));
    }

    #[test]
    fn enrich_data_envelope_with_deployment_names_adds_deployment_name_field() {
        let deployment_names = HashMap::from([("dep-123".to_string(), "BTC Watcher".to_string())]);
        let envelope = serde_json::json!({
            "data": [
                {
                    "run_id": "run-1",
                    "deployment_id": "dep-123",
                    "status": "awaiting_approval"
                }
            ]
        });

        let enriched =
            super::enrich_data_envelope_with_deployment_names(&envelope, &deployment_names);
        let first = &enriched["data"][0];
        assert_eq!(first["deployment_name"], "BTC Watcher");
        assert_eq!(first["deployment_id"], "dep-123");
    }

    #[test]
    fn publisher_skill_doc_url_builds_seren_cloud_path() {
        let url = super::publisher_skill_doc_url("https://api.serendb.com", "seren-cloud").unwrap();
        assert_eq!(
            url,
            "https://api.serendb.com/publishers/seren-cloud/skill.md"
        );
    }

    #[test]
    fn seren_api_skill_doc_url_builds_root_path() {
        let url = super::seren_api_skill_doc_url("https://api.serendb.com").unwrap();
        assert_eq!(url, "https://api.serendb.com/skill.md");
    }

    #[test]
    fn build_cloud_approval_resume_payload_returns_none_without_pending_approvals() {
        let approval_state = serde_json::json!({
            "data": {
                "status": "completed",
                "pending_approvals": []
            }
        });

        let payload =
            seren::build_cloud_approval_resume_request(&approval_state, "approve").unwrap();
        assert!(payload.is_none());
    }

    #[test]
    fn build_cloud_approval_resume_payload_includes_checkpoint_and_decisions() {
        let approval_state = serde_json::json!({
            "data": {
                "status": "awaiting_approval",
                "checkpoint_id": "chk_123",
                "pending_approvals": [
                    { "id": "approval-1", "tool": "shell" },
                    { "id": "approval-2", "tool": "browser" }
                ]
            }
        });

        let payload = seren::build_cloud_approval_resume_request(&approval_state, "reject")
            .unwrap()
            .unwrap();
        assert_eq!(payload.resume_checkpoint_id.as_deref(), Some("chk_123"));
        let approval_decisions = payload.approval_decisions.unwrap();
        assert_eq!(approval_decisions[0].id, "approval-1");
        assert_eq!(
            approval_decisions[0].decision,
            seren::CloudRunApprovalDecisionValue::Reject
        );
        assert_eq!(approval_decisions[1].id, "approval-2");
    }

    #[tokio::test]
    async fn update_agent_rejects_tool_refs_with_clear_tool_refs() {
        let api_client =
            seren::Client::new_with_client("https://api.serendb.com", reqwest::Client::new());
        let tool_ref = serde_json::from_value::<seren::AgentToolRef>(serde_json::json!({
            "kind": "publisher",
            "publisher_slug": "microsoft",
            "operation_id": "calendar.events.list"
        }))
        .unwrap();
        let params = UpdateSerenAgentDeploymentParams {
            deployment_id: Uuid::new_v4(),
            agent_slug: None,
            name: None,
            cron_schedule: None,
            cron_timezone: None,
            eval_gate_set_id: None,
            eval_gate_max_age_seconds: None,
            clear_eval_gate: false,
            prompt: None,
            model_id: None,
            template: None,
            agent_style: None,
            tool_presets: None,
            capabilities: None,
            tool_refs: Some(vec![tool_ref]),
            clear_tool_refs: true,
            approval_policy: None,
            access_mode: None,
            model_policy: None,
            performance_profile: None,
            allowed_remote_agent_origins: None,
            config: None,
            secrets: None,
            model_config: None,
            fallback_models: None,
            max_timeout_seconds: None,
            requirements: None,
            dashboard_config: None,
            capability_policy: None,
            clear_capability_policy: false,
            visibility: None,
        };

        let err = build_update_seren_agent_deployment_request(&api_client, &params)
            .await
            .unwrap_err();

        assert!(
            err.message.contains("tool_refs or clear_tool_refs"),
            "unexpected error: {}",
            err.message
        );
    }

    fn base_update_agent_params() -> UpdateSerenAgentDeploymentParams {
        UpdateSerenAgentDeploymentParams {
            deployment_id: Uuid::new_v4(),
            agent_slug: None,
            name: None,
            cron_schedule: None,
            cron_timezone: None,
            eval_gate_set_id: None,
            eval_gate_max_age_seconds: None,
            clear_eval_gate: false,
            prompt: None,
            model_id: None,
            template: None,
            agent_style: None,
            tool_presets: None,
            capabilities: None,
            tool_refs: None,
            clear_tool_refs: false,
            approval_policy: None,
            access_mode: None,
            model_policy: None,
            performance_profile: None,
            allowed_remote_agent_origins: None,
            config: None,
            secrets: None,
            model_config: None,
            fallback_models: None,
            max_timeout_seconds: None,
            requirements: None,
            dashboard_config: None,
            capability_policy: None,
            clear_capability_policy: false,
            visibility: None,
        }
    }

    #[tokio::test]
    async fn update_agent_passes_tool_refs_through() {
        let api_client =
            seren::Client::new_with_client("https://api.serendb.com", reqwest::Client::new());
        let tool_ref = serde_json::from_value::<seren::AgentToolRef>(serde_json::json!({
            "kind": "publisher",
            "publisher_slug": "microsoft",
            "operation_id": "calendar.events.list"
        }))
        .unwrap();
        let mut params = base_update_agent_params();
        params.tool_refs = Some(vec![tool_ref]);

        let request = build_update_seren_agent_deployment_request(&api_client, &params)
            .await
            .unwrap();

        assert!(
            request
                .tool_refs
                .as_ref()
                .is_some_and(|refs| refs.len() == 1),
            "tool_refs should pass through to the update request",
        );
        assert_eq!(
            request.clear_tool_refs, None,
            "clear_tool_refs must stay unset when only tool_refs is provided",
        );
    }

    #[tokio::test]
    async fn update_agent_clear_tool_refs_sets_flag_without_refs() {
        let api_client =
            seren::Client::new_with_client("https://api.serendb.com", reqwest::Client::new());
        let mut params = base_update_agent_params();
        params.clear_tool_refs = true;

        let request = build_update_seren_agent_deployment_request(&api_client, &params)
            .await
            .unwrap();

        assert_eq!(request.clear_tool_refs, Some(true));
        assert!(
            request.tool_refs.is_none(),
            "tool_refs must stay unset when clearing",
        );
    }

    #[tokio::test]
    async fn passwords_unlock_is_rejected_in_hosted_mode() {
        // Hosted mode uses delegated agent keys only.
        let server = SerenMcpServer::new_oauth("https://api.serendb.com").unwrap();
        assert!(!server.passwords_local_mode);

        let extensions = extensions_with_headers(&[("authorization", "Bearer test-token")]);
        let err = server
            .passwords_unlock_session(&extensions)
            .await
            .expect_err("passwords_unlock must be rejected in hosted mode");
        assert!(
            err.message.contains("hosted mode must use an agent key"),
            "unexpected error message: {}",
            err.message
        );

        // The hosted-mode gate leaves the session untouched.
        assert!(server.passwords_session.lock().await.is_none());
    }

    #[test]
    fn new_oauth_derives_passwords_publisher_gateway_url() {
        let server = SerenMcpServer::new_oauth("https://api.serendb.com/").unwrap();
        assert_eq!(
            server.passwords_api_base_url,
            "https://api.serendb.com/publishers/seren-passwords"
        );
    }

    #[test]
    fn new_oauth_does_not_duplicate_passwords_publisher_gateway_prefix() {
        let server =
            SerenMcpServer::new_oauth("https://api.serendb.com/publishers/seren-passwords/")
                .unwrap();
        assert_eq!(
            server.passwords_api_base_url,
            "https://api.serendb.com/publishers/seren-passwords"
        );
    }

    #[tokio::test]
    async fn passwords_user_signing_auth_is_rejected_in_hosted_mode() {
        let server = SerenMcpServer::new_oauth("https://api.serendb.com").unwrap();
        assert!(!server.passwords_local_mode);

        let extensions = extensions_with_headers(&[("authorization", "Bearer test-token")]);
        let err = server
            .passwords_user_signing_auth(&extensions)
            .await
            .expect_err("hosted mode must not expose local signing operations");
        assert!(
            err.message
                .contains("only available in local MCP modes after passwords_unlock"),
            "unexpected error message: {}",
            err.message
        );

        assert!(server.passwords_session.lock().await.is_none());
    }
}
