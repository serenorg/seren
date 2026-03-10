use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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

// ===================== Cloud Run Replay Comparison Types =====================

/// Comparison result between two cloud run replay/eval captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRunReplayComparison {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_status: Option<String>,
    pub baseline_eval_capture_present: bool,
    pub candidate_eval_capture_present: bool,
    pub baseline_replay_artifact_present: bool,
    pub candidate_replay_artifact_present: bool,
    pub overall_match: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_matches: Vec<CloudRunReplayFieldComparison>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_event_mismatch: Option<CloudRunReplayEventMismatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Comparison for a single replay summary field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRunReplayFieldComparison {
    pub field: String,
    pub label: String,
    pub baseline: Value,
    pub candidate: Value,
    pub matches: bool,
}

/// The first replay event that differs between two runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRunReplayEventMismatch {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_kind: Option<String>,
    pub baseline: Value,
    pub candidate: Value,
}

const CLOUD_RUN_REPLAY_FIELDS: &[(&str, &str)] = &[
    ("event_count", "Event Count"),
    ("trajectory", "Trajectory"),
    ("tool_call_sequence", "Tool Calls"),
    ("workflow_states", "Workflow States"),
    ("text_segment_count", "Text Segments"),
    ("thinking_segment_count", "Thinking Segments"),
    ("tool_result_count", "Tool Results"),
    ("tool_result_error_count", "Tool Result Errors"),
    ("error_count", "Errors"),
    ("final_text_sha256", "Final Text SHA256"),
    ("final_text_bytes", "Final Text Bytes"),
];

/// Compare two cloud runs using their eval-capture summaries and optional replay artifacts.
pub fn compare_cloud_run_replays(
    baseline_detail: &Value,
    candidate_detail: &Value,
    baseline_artifacts: Option<&Value>,
    candidate_artifacts: Option<&Value>,
) -> CloudRunReplayComparison {
    let baseline_run = extract_data_object(baseline_detail);
    let candidate_run = extract_data_object(candidate_detail);

    let baseline_eval = baseline_run.and_then(|run| metadata_section(run, "eval_capture"));
    let candidate_eval = candidate_run.and_then(|run| metadata_section(run, "eval_capture"));

    let baseline_replay_events = baseline_artifacts.and_then(extract_replay_events);
    let candidate_replay_events = candidate_artifacts.and_then(extract_replay_events);

    let mut notes = Vec::new();
    if baseline_eval.is_none() {
        notes.push("Baseline run is missing metadata.eval_capture.".to_string());
    }
    if candidate_eval.is_none() {
        notes.push("Candidate run is missing metadata.eval_capture.".to_string());
    }
    if baseline_artifacts.is_some() && baseline_replay_events.is_none() {
        notes.push("Baseline run has no replay artifact events.".to_string());
    }
    if candidate_artifacts.is_some() && candidate_replay_events.is_none() {
        notes.push("Candidate run has no replay artifact events.".to_string());
    }
    if baseline_replay_events.is_some() ^ candidate_replay_events.is_some() {
        notes.push(
            "Only one run has replay artifact events, so event-level replay diff is partial."
                .to_string(),
        );
    }

    let mut field_matches = Vec::new();
    for (field, label) in CLOUD_RUN_REPLAY_FIELDS {
        let baseline_value = baseline_eval
            .and_then(|section| section.get(*field))
            .cloned();
        let candidate_value = candidate_eval
            .and_then(|section| section.get(*field))
            .cloned();
        if baseline_value.is_none() && candidate_value.is_none() {
            continue;
        }
        let baseline = baseline_value.unwrap_or(Value::Null);
        let candidate = candidate_value.unwrap_or(Value::Null);
        field_matches.push(CloudRunReplayFieldComparison {
            field: (*field).to_string(),
            label: (*label).to_string(),
            matches: baseline == candidate,
            baseline,
            candidate,
        });
    }

    let first_event_mismatch =
        find_first_event_mismatch(baseline_replay_events, candidate_replay_events);
    let overall_match = baseline_eval.is_some()
        && candidate_eval.is_some()
        && field_matches.iter().all(|field| field.matches)
        && first_event_mismatch.is_none();

    CloudRunReplayComparison {
        baseline_run_id: baseline_run.and_then(|run| json_string(run.get("id"))),
        candidate_run_id: candidate_run.and_then(|run| json_string(run.get("id"))),
        baseline_deployment_id: baseline_run.and_then(|run| json_string(run.get("deployment_id"))),
        candidate_deployment_id: candidate_run
            .and_then(|run| json_string(run.get("deployment_id"))),
        baseline_status: baseline_run.and_then(|run| json_string(run.get("status"))),
        candidate_status: candidate_run.and_then(|run| json_string(run.get("status"))),
        baseline_eval_capture_present: baseline_eval.is_some(),
        candidate_eval_capture_present: candidate_eval.is_some(),
        baseline_replay_artifact_present: baseline_replay_events.is_some(),
        candidate_replay_artifact_present: candidate_replay_events.is_some(),
        overall_match,
        field_matches,
        first_event_mismatch,
        notes,
    }
}

fn extract_data_object(value: &Value) -> Option<&Map<String, Value>> {
    value.get("data").unwrap_or(value).as_object()
}

fn metadata_section<'a>(
    run: &'a Map<String, Value>,
    section: &str,
) -> Option<&'a Map<String, Value>> {
    run.get("metadata")?.get(section)?.as_object()
}

fn extract_replay_events(value: &Value) -> Option<&Vec<Value>> {
    let artifacts = value.get("data").unwrap_or(value).as_array()?;
    artifacts.iter().find_map(|artifact| {
        let artifact = artifact.as_object()?;
        let artifact_type = artifact.get("artifact_type")?.as_str()?;
        if artifact_type != "replay" {
            return None;
        }
        artifact.get("payload")?.get("events")?.as_array()
    })
}

fn find_first_event_mismatch(
    baseline: Option<&Vec<Value>>,
    candidate: Option<&Vec<Value>>,
) -> Option<CloudRunReplayEventMismatch> {
    let (baseline, candidate) = match (baseline, candidate) {
        (Some(baseline), Some(candidate)) => (baseline, candidate),
        _ => return None,
    };

    let shared_len = baseline.len().min(candidate.len());
    for index in 0..shared_len {
        if baseline[index] != candidate[index] {
            return Some(CloudRunReplayEventMismatch {
                index,
                baseline_kind: event_kind(&baseline[index]),
                candidate_kind: event_kind(&candidate[index]),
                baseline: baseline[index].clone(),
                candidate: candidate[index].clone(),
            });
        }
    }

    if baseline.len() != candidate.len() {
        let index = shared_len;
        let baseline_event = baseline.get(index).cloned().unwrap_or(Value::Null);
        let candidate_event = candidate.get(index).cloned().unwrap_or(Value::Null);
        return Some(CloudRunReplayEventMismatch {
            index,
            baseline_kind: event_kind(&baseline_event),
            candidate_kind: event_kind(&candidate_event),
            baseline: baseline_event,
            candidate: candidate_event,
        });
    }

    None
}

fn event_kind(value: &Value) -> Option<String> {
    value
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| value.get("type").and_then(Value::as_str))
        .map(str::to_string)
}

fn json_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(raw) => Some(raw.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        other => serde_json::to_string(other).ok(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compare_cloud_run_replays_detects_summary_and_event_differences() {
        let baseline_detail = json!({
            "data": {
                "id": "run-baseline",
                "deployment_id": "dep-1",
                "status": "completed",
                "metadata": {
                    "eval_capture": {
                        "event_count": 4,
                        "trajectory": ["text", "tool_call_started", "tool_call_completed", "text"],
                        "tool_call_sequence": ["web_search"],
                        "workflow_states": [],
                        "text_segment_count": 2,
                        "thinking_segment_count": 0,
                        "tool_result_count": 1,
                        "tool_result_error_count": 0,
                        "error_count": 0,
                        "final_text_sha256": "hash-a",
                        "final_text_bytes": 18
                    }
                }
            }
        });
        let candidate_detail = json!({
            "data": {
                "id": "run-candidate",
                "deployment_id": "dep-1",
                "status": "completed",
                "metadata": {
                    "eval_capture": {
                        "event_count": 5,
                        "trajectory": ["text", "tool_call_started", "tool_call_completed", "text", "workflow"],
                        "tool_call_sequence": ["web_search", "db_query"],
                        "workflow_states": ["completed"],
                        "text_segment_count": 2,
                        "thinking_segment_count": 0,
                        "tool_result_count": 2,
                        "tool_result_error_count": 1,
                        "error_count": 0,
                        "final_text_sha256": "hash-b",
                        "final_text_bytes": 22
                    }
                }
            }
        });
        let baseline_artifacts = json!({
            "data": [{
                "artifact_type": "replay",
                "payload": {
                    "events": [
                        {"kind": "text", "type": "text", "text": "start"},
                        {"kind": "tool_call_started", "type": "tool_call", "name": "web_search"},
                        {"kind": "tool_call_completed", "type": "tool_result", "content": "done"},
                        {"kind": "text", "type": "text", "text": "done"}
                    ]
                }
            }]
        });
        let candidate_artifacts = json!({
            "data": [{
                "artifact_type": "replay",
                "payload": {
                    "events": [
                        {"kind": "text", "type": "text", "text": "start"},
                        {"kind": "tool_call_started", "type": "tool_call", "name": "web_search"},
                        {"kind": "tool_call_completed", "type": "tool_result", "content": "done"},
                        {"kind": "text", "type": "text", "text": "changed"}
                    ]
                }
            }]
        });

        let comparison = compare_cloud_run_replays(
            &baseline_detail,
            &candidate_detail,
            Some(&baseline_artifacts),
            Some(&candidate_artifacts),
        );

        assert!(!comparison.overall_match);
        assert!(comparison.baseline_eval_capture_present);
        assert!(comparison.candidate_eval_capture_present);
        assert!(comparison.baseline_replay_artifact_present);
        assert!(comparison.candidate_replay_artifact_present);
        assert_eq!(comparison.baseline_run_id.as_deref(), Some("run-baseline"));
        assert_eq!(
            comparison.candidate_run_id.as_deref(),
            Some("run-candidate")
        );
        assert!(
            comparison
                .field_matches
                .iter()
                .any(|field| field.field == "final_text_sha256" && !field.matches)
        );
        let mismatch = comparison
            .first_event_mismatch
            .expect("expected event mismatch");
        assert_eq!(mismatch.index, 3);
        assert_eq!(mismatch.baseline_kind.as_deref(), Some("text"));
        assert_eq!(mismatch.candidate_kind.as_deref(), Some("text"));
    }

    #[test]
    fn compare_cloud_run_replays_handles_missing_replay_artifacts() {
        let detail = json!({
            "data": {
                "id": "run-1",
                "deployment_id": "dep-1",
                "status": "completed",
                "metadata": {
                    "eval_capture": {
                        "event_count": 1,
                        "trajectory": ["text"],
                        "final_text_sha256": "same"
                    }
                }
            }
        });

        let comparison = compare_cloud_run_replays(&detail, &detail, None, None);

        assert!(comparison.overall_match);
        assert!(!comparison.baseline_replay_artifact_present);
        assert!(!comparison.candidate_replay_artifact_present);
        assert!(comparison.first_event_mismatch.is_none());
        assert!(comparison.notes.is_empty());
    }
}
