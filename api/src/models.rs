use serde::{Deserialize, Serialize};

pub use crate::generated::types::*;

/// Legacy alias retained for compatibility with previous SDK versions.
pub type User = crate::generated::types::UserResponse;

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
