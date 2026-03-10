use serde::{Deserialize, Serialize};

/// Legacy alias retained for compatibility with previous SDK versions.
pub type User = crate::generated::types::UserInfo;

// ===================== Schema Diff Types (not in OpenAPI spec) =====================

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

// ===================== Endpoint Types (not in OpenAPI spec) =====================

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

// ===================== Session Management Types (not in OpenAPI spec) =====================

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

// ===================== Webhook Types (not in OpenAPI spec) =====================

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

// ===================== RBAC Types (not in OpenAPI spec) =====================

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

// ===================== Publication/Replication Types (not in OpenAPI spec) =====================

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
