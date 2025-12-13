use serde::{Deserialize, Serialize};

pub use crate::generated::types::*;

/// Legacy alias retained for compatibility with previous SDK versions.
pub type User = crate::generated::types::UserInfoResponse;

/// Generic API response wrapper mirroring the backend `DataResponse<T>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

/// Schema diff result comparing two branches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    pub base_branch_id: String,
    pub compare_branch_id: String,
    pub differences: Vec<SchemaDifference>,
}

/// Types of schema differences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SchemaDifference {
    TableAdded {
        table_name: String,
        schema_name: String,
    },
    TableRemoved {
        table_name: String,
        schema_name: String,
    },
    TableModified {
        table_name: String,
        schema_name: String,
        changes: Vec<TableChange>,
    },
}

/// Changes within a modified table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change_type", rename_all = "snake_case")]
pub enum TableChange {
    ColumnAdded {
        column_name: String,
        data_type: String,
        is_nullable: bool,
    },
    ColumnRemoved {
        column_name: String,
        data_type: String,
    },
    ColumnModified {
        column_name: String,
        old_type: String,
        new_type: String,
        nullable_changed: Option<bool>,
    },
    IndexAdded {
        index_name: String,
        is_unique: bool,
        columns: Vec<String>,
    },
    IndexRemoved {
        index_name: String,
    },
    ConstraintAdded {
        constraint_name: String,
        constraint_type: String,
    },
    ConstraintRemoved {
        constraint_name: String,
        constraint_type: String,
    },
}

/// Request parameters for schema diff.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaDiffRequest {
    pub base_branch_id: String,
    pub compare_branch_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

impl SchemaDiffRequest {
    pub fn new(base_branch_id: impl Into<String>, compare_branch_id: impl Into<String>) -> Self {
        Self {
            base_branch_id: base_branch_id.into(),
            compare_branch_id: compare_branch_id.into(),
            database: None,
        }
    }

    pub fn with_database(mut self, database: impl Into<String>) -> Self {
        self.database = Some(database.into());
        self
    }
}

/// Health status for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHealth {
    pub status: String,
    pub replicas: i32,
    pub ready_replicas: i32,
    pub available_replicas: i32,
    pub unavailable_replicas: i32,
}

/// Resource metrics for an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetrics {
    pub pod_count: i32,
    pub cpu_request_millicores: i64,
    pub memory_request_bytes: i64,
}

// Billing and Invoice types

/// Request to generate monthly invoices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateInvoicesRequest {
    pub year: i32,
    pub month: u8,
}

/// Response from generating invoices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateInvoicesResponse {
    pub invoice_ids: Vec<String>,
    pub count: usize,
}

/// Invoice details with line items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub organization_id: String,
    pub invoice_number: String,
    pub period_start: String,
    pub period_end: String,
    pub subtotal_usd: f64,
    pub tax_usd: f64,
    pub total_usd: f64,
    pub status: String,
    pub line_items: Vec<InvoiceLineItem>,
}

/// Individual line item on an invoice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceLineItem {
    pub description: String,
    pub line_type: String,
    pub quantity: f64,
    pub unit_price: f64,
    pub amount_usd: f64,
}

/// Usage summary for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageSummary {
    pub organization_id: String,
    pub project_id: String,
    pub project_name: String,
    pub project_region: String,
    pub period_start: String,
    pub period_end: String,
    pub compute_hours_small: f64,
    pub compute_hours_medium: f64,
    pub compute_hours_large: f64,
    pub compute_hours_xlarge: f64,
    pub storage_gb_avg: f64,
    pub pitr_gb_avg: f64,
    pub compute_cost_usd: f64,
    pub storage_cost_usd: f64,
    pub total_cost_usd: f64,
}

/// Billing job health for a single background job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingJobHealth {
    pub job: String,
    pub failures_total: u64,
}

/// High-level billing health summary from Seren Core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingHealthResponse {
    pub last_daily_aggregation_run_utc: Option<String>,
    pub daily_aggregation_ok: bool,
    pub has_recent_daily_run: bool,
    pub daily_aggregation_failures_total: u64,
    pub jobs: Vec<BillingJobHealth>,
}

/// Endpoint balance for agentic billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: f64,
    pub endpoint_id: String,
}

/// Request to validate x402 token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateTokenRequest {
    pub token: String,
}

/// Response from validating x402 token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateTokenResponse {
    pub endpoint_id: String,
    pub balance: f64,
    pub expires_at: u64,
}

/// Request to deduct balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeductBalanceRequest {
    pub endpoint_id: String,
    pub amount: f64,
    pub query_hash: String,
    pub timestamp: u64,
}

/// Response from deducting balance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeductBalanceResponse {
    pub new_balance: f64,
    pub transaction_id: String,
}

/// Request to refund a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundTransactionRequest {
    pub endpoint_id: String,
    pub transaction_id: String,
    pub amount: f64,
    pub reason: String,
    pub timestamp: u64,
}

/// Response from refunding a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundTransactionResponse {
    pub new_balance: f64,
    pub refund_id: String,
}

// ===================== Session Management Types =====================

/// Response for listing user sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub id: uuid::Uuid,
    pub created_at: jiff::Timestamp,
    pub last_active_at: jiff::Timestamp,
    pub expires_at: jiff::Timestamp,
    pub is_current: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// Response when revoking sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeSessionResponse {
    pub revoked_count: i64,
}

// ===================== Webhook Types =====================

/// Webhook configuration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    pub is_active: bool,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Response when creating a webhook (includes secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookCreatedResponse {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub url: String,
    pub event_types: Vec<String>,
    pub is_active: bool,
    pub secret: String,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub event_types: Vec<String>,
    #[serde(default)]
    pub is_active: Option<bool>,
}

/// Request to update a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateWebhookRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Webhook delivery record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: uuid::Uuid,
    pub webhook_id: uuid::Uuid,
    pub event_type: String,
    pub status_code: Option<i32>,
    pub success: bool,
    pub attempt_count: i32,
    pub delivered_at: Option<jiff::Timestamp>,
    pub created_at: jiff::Timestamp,
}

// ===================== Audit Log Types =====================

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: jiff::Timestamp,
}

/// Response for listing audit logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogListResponse {
    pub logs: Vec<AuditLog>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

// ===================== RBAC Types =====================

/// RBAC Role response (organization-level roles, distinct from database roles)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationRoleResponse {
    pub id: uuid::Uuid,
    pub organization_id: Option<uuid::Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub is_built_in: bool,
    pub permissions: Vec<String>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create an organization role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRoleRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

/// Request to update an organization role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRoleRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
}

/// Request to assign a role to a member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignOrganizationRoleRequest {
    pub role_id: uuid::Uuid,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationPermission {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub resource_type: String,
    pub action: String,
}

// ===================== Branch Protection Types =====================

/// Branch protection rule response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchProtectionResponse {
    pub id: uuid::Uuid,
    pub project_id: uuid::Uuid,
    pub branch_id: uuid::Uuid,
    pub prevent_deletion: bool,
    pub prevent_reset: bool,
    pub require_approval_for_changes: bool,
    pub allowed_bypass_roles: Vec<String>,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create branch protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBranchProtectionRequest {
    #[serde(default = "default_true")]
    pub prevent_deletion: bool,
    #[serde(default = "default_true")]
    pub prevent_reset: bool,
    #[serde(default)]
    pub require_approval_for_changes: bool,
    #[serde(default)]
    pub allowed_bypass_roles: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Request to update branch protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateBranchProtectionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prevent_deletion: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prevent_reset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_approval_for_changes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_bypass_roles: Option<Vec<String>>,
}

// ===================== Logical Replication Types =====================

/// Logical replication settings for a project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicalReplicationSettings {
    pub project_id: uuid::Uuid,
    pub logical_replication_enabled: bool,
}

/// Request to update logical replication settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLogicalReplicationRequest {
    pub logical_replication_enabled: bool,
}

/// Publication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationResponse {
    pub id: uuid::Uuid,
    pub branch_id: uuid::Uuid,
    pub name: String,
    pub table_names: Vec<String>,
    pub all_tables: bool,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create a publication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePublicationRequest {
    pub name: String,
    #[serde(default)]
    pub table_names: Vec<String>,
    #[serde(default)]
    pub all_tables: bool,
}

/// Request to update a publication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePublicationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_tables: Option<bool>,
}

/// Replication slot response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationSlotResponse {
    pub id: uuid::Uuid,
    pub branch_id: uuid::Uuid,
    pub name: String,
    pub plugin: String,
    pub created_at: jiff::Timestamp,
    pub updated_at: jiff::Timestamp,
}

/// Request to create a replication slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReplicationSlotRequest {
    pub name: String,
    #[serde(default = "default_pgoutput")]
    pub plugin: String,
}

fn default_pgoutput() -> String {
    "pgoutput".to_string()
}
