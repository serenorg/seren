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
