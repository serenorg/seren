use thiserror::Error;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub fn normalize_optional_string(
    value: Option<&str>,
    field: &str,
) -> Result<Option<String>, ValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::new(format!("{field} must not be empty")));
    }
    Ok(Some(trimmed.to_string()))
}

pub fn normalize_string_list<I, S>(values: I, field: &str) -> Result<Vec<String>, ValidationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for (index, value) in values.into_iter().enumerate() {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            return Err(ValidationError::new(format!(
                "{field}[{index}] must not be empty"
            )));
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
}

pub fn ensure_https(value: Option<&str>, field: &str) -> Result<(), ValidationError> {
    if let Some(value) = value
        && !value.starts_with("https://")
    {
        return Err(ValidationError::new(format!("{field} must use HTTPS")));
    }
    Ok(())
}

pub fn normalize_auth_type(value: Option<&str>) -> Result<Option<String>, ValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(ValidationError::new("auth_type must not be empty"));
    }
    match normalized.as_str() {
        "static" | "jwt" | "oauth2_cc" | "passthrough" => Ok(Some(normalized)),
        other => Err(ValidationError::new(format!(
            "Invalid auth_type '{}'. Expected one of: static, jwt, oauth2_cc, passthrough",
            other
        ))),
    }
}

pub fn validate_oauth2_create_fields(
    auth_type: Option<&str>,
    oauth2_token_url: Option<&str>,
    oauth2_client_id: Option<&str>,
    oauth2_client_secret: Option<&str>,
    oauth2_scopes_present: bool,
) -> Result<(), ValidationError> {
    if auth_type == Some("oauth2_cc")
        && (oauth2_token_url.is_none()
            || oauth2_client_id.is_none()
            || oauth2_client_secret.is_none())
    {
        return Err(ValidationError::new(
            "oauth2_token_url, oauth2_client_id, and oauth2_client_secret are required when auth_type is oauth2_cc",
        ));
    }

    if auth_type != Some("oauth2_cc")
        && (oauth2_token_url.is_some()
            || oauth2_client_id.is_some()
            || oauth2_client_secret.is_some()
            || oauth2_scopes_present)
    {
        return Err(ValidationError::new(
            "oauth2_* fields require auth_type=oauth2_cc",
        ));
    }

    Ok(())
}

pub fn validate_oauth2_update_fields(
    auth_type: Option<&str>,
    oauth2_token_url: Option<&str>,
    oauth2_client_id: Option<&str>,
    oauth2_client_secret: Option<&str>,
    oauth2_scopes_present: bool,
) -> Result<(), ValidationError> {
    if auth_type == Some("oauth2_cc")
        && (oauth2_token_url.is_none()
            || oauth2_client_id.is_none()
            || oauth2_client_secret.is_none())
    {
        return Err(ValidationError::new(
            "oauth2_token_url, oauth2_client_id, and oauth2_client_secret are required when auth_type is oauth2_cc",
        ));
    }

    if auth_type.is_some()
        && auth_type != Some("oauth2_cc")
        && (oauth2_token_url.is_some()
            || oauth2_client_id.is_some()
            || oauth2_client_secret.is_some()
            || oauth2_scopes_present)
    {
        return Err(ValidationError::new(
            "oauth2_* fields require auth_type=oauth2_cc",
        ));
    }

    Ok(())
}

pub fn parse_publisher_category(value: &str) -> Result<crate::PublisherCategory, ValidationError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "database" => Ok(crate::PublisherCategory::Database),
        "integration" => Ok(crate::PublisherCategory::Integration),
        "compute" => Ok(crate::PublisherCategory::Compute),
        other => Err(ValidationError::new(format!(
            "Invalid publisher_category '{}'. Expected one of: database, integration, compute",
            other
        ))),
    }
}

pub fn parse_database_type(
    value: Option<&str>,
) -> Result<Option<crate::DatabaseType>, ValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    let parsed = match normalized.as_str() {
        "serendb" => crate::DatabaseType::Serendb,
        "neon" => crate::DatabaseType::Neon,
        "supabase" => crate::DatabaseType::Supabase,
        "mongodb" => crate::DatabaseType::Mongodb,
        other => {
            return Err(ValidationError::new(format!(
                "Invalid database_type '{}'. Expected one of: serendb, neon, supabase, mongodb",
                other
            )));
        }
    };
    Ok(Some(parsed))
}

pub fn parse_integration_type(
    value: Option<&str>,
) -> Result<Option<crate::IntegrationType>, ValidationError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let normalized = value.trim().to_ascii_lowercase();
    let parsed = match normalized.as_str() {
        "api" => crate::IntegrationType::Api,
        "mcp" => crate::IntegrationType::Mcp,
        other => {
            return Err(ValidationError::new(format!(
                "Invalid integration_type '{}'. Expected one of: api, mcp",
                other
            )));
        }
    };
    Ok(Some(parsed))
}

pub fn parse_managed_agent_template(
    value: Option<&str>,
) -> Result<Option<crate::ManagedAgentTemplate>, ValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value.parse().map(Some).map_err(|_| {
        ValidationError::new("Invalid template. Expected one of: research_monitor, workflow_agent")
    })
}

pub fn parse_managed_agent_approval_policy(
    value: Option<&str>,
) -> Result<Option<crate::ManagedAgentApprovalPolicy>, ValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value.parse().map(Some).map_err(|_| {
        ValidationError::new("Invalid approval_policy. Expected one of: read_only, allow_mutations")
    })
}

pub fn parse_managed_agent_model_policy(
    value: Option<&str>,
) -> Result<Option<crate::ManagedAgentModelPolicy>, ValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value.parse().map(Some).map_err(|_| {
        ValidationError::new("Invalid model_policy. Expected one of: fast, balanced, deep")
    })
}

pub fn parse_managed_agent_tool_presets<I, S>(
    values: I,
) -> Result<Option<Vec<crate::ManagedAgentToolPreset>>, ValidationError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = Vec::new();
    for value in values {
        let trimmed = value.as_ref().trim();
        if trimmed.is_empty() {
            continue;
        }
        parsed.push(trimmed.parse().map_err(|_| {
            ValidationError::new(
                "Invalid tool_presets entry. Expected values from: live_data, publisher_actions, database",
            )
        })?);
    }

    if parsed.is_empty() {
        return Ok(None);
    }

    Ok(Some(parsed))
}

pub fn parse_schedule_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub fn eval_set_schedule_string(eval_set: &crate::CloudEvalSet, key: &str) -> Option<String> {
    serde_json::to_value(&eval_set.schedule)
        .ok()?
        .as_object()?
        .get(key)?
        .as_str()
        .map(ToString::to_string)
}

pub fn build_cloud_eval_set_schedule_request(
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
) -> Result<Option<crate::CloudEvalSetScheduleRequest>, ValidationError> {
    match (
        parse_schedule_field(schedule_cron),
        parse_schedule_field(schedule_timezone),
    ) {
        (None, None) => Ok(None),
        (Some(schedule_cron), Some(schedule_timezone)) => {
            Ok(Some(crate::CloudEvalSetScheduleRequest {
                schedule_cron,
                schedule_timezone,
            }))
        }
        _ => Err(ValidationError::new(
            "Provide both schedule_cron and schedule_timezone together.",
        )),
    }
}

pub fn resolve_cloud_eval_set_schedule_request(
    eval_set: &crate::CloudEvalSet,
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
    clear_schedule: bool,
) -> Result<Option<crate::CloudEvalSetScheduleRequest>, ValidationError> {
    if clear_schedule {
        if parse_schedule_field(schedule_cron).is_some()
            || parse_schedule_field(schedule_timezone).is_some()
        {
            return Err(ValidationError::new(
                "Do not combine clear_schedule with schedule_cron or schedule_timezone.",
            ));
        }
        return Ok(None);
    }

    match (
        parse_schedule_field(schedule_cron).or(eval_set_schedule_string(eval_set, "schedule_cron")),
        parse_schedule_field(schedule_timezone)
            .or(eval_set_schedule_string(eval_set, "schedule_timezone")),
    ) {
        (None, None) => Ok(None),
        (Some(schedule_cron), Some(schedule_timezone)) => {
            Ok(Some(crate::CloudEvalSetScheduleRequest {
                schedule_cron,
                schedule_timezone,
            }))
        }
        _ => Err(ValidationError::new(
            "Eval set schedule requires both cron and timezone values.",
        )),
    }
}

pub fn build_cloud_approval_resume_request(
    approval_state: &serde_json::Value,
    decision: &str,
) -> Result<Option<crate::CloudDeploymentRunRequest>, ValidationError> {
    let data = approval_state.get("data").unwrap_or(approval_state);
    let status = data
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let approvals = data
        .get("pending_approvals")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    if status != "awaiting_approval" || approvals.is_empty() {
        return Ok(None);
    }

    let checkpoint_id = data
        .get("checkpoint_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ValidationError::new("Run is awaiting approval but no checkpoint_id was returned.")
        })?;

    let approval_decisions = approvals
        .into_iter()
        .filter_map(|approval| {
            approval
                .get("id")
                .and_then(|value| value.as_str())
                .map(|id| crate::CloudRunApprovalDecision {
                    id: id.to_string(),
                    decision: decision.to_string(),
                })
        })
        .collect::<Vec<_>>();

    Ok(Some(crate::CloudDeploymentRunRequest {
        resume_checkpoint_id: Some(checkpoint_id.to_string()),
        approval_decisions: Some(approval_decisions),
        ..Default::default()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cloud_approval_resume_request_returns_none_without_pending_approvals() {
        let approval_state = serde_json::json!({
            "status": "running",
            "pending_approvals": [],
        });

        let payload = build_cloud_approval_resume_request(&approval_state, "approve").unwrap();
        assert!(payload.is_none());
    }

    #[test]
    fn build_cloud_approval_resume_request_includes_checkpoint_and_decisions() {
        let approval_state = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": "checkpoint-123",
            "pending_approvals": [
                { "id": "approval-a" },
                { "id": "approval-b" }
            ]
        });

        let payload = build_cloud_approval_resume_request(&approval_state, "reject")
            .unwrap()
            .unwrap();

        assert_eq!(
            payload.resume_checkpoint_id.as_deref(),
            Some("checkpoint-123")
        );
        assert_eq!(payload.approval_decisions.as_ref().map(Vec::len), Some(2));
        assert_eq!(payload.approval_decisions.unwrap()[0].decision, "reject");
    }
}
