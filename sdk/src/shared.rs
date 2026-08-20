use thiserror::Error;

pub const MANAGED_AGENT_SECRETS_REDIRECT_ORIGIN: &str = "https://passwords.serendb.com";

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Debug, Clone)]
pub enum ManagedAgentSecretsApplication {
    AlreadyApplied,
    Update(Box<crate::AgentSpecUpdate>),
}

fn valid_environment_name(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
        && !reserved_environment_name(value)
}

fn reserved_environment_name(value: &str) -> bool {
    const NAMES: &[&str] = &[
        "BASH_ENV",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "HOME",
        "LANG",
        "LC_ALL",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LOGNAME",
        "NODE_OPTIONS",
        "NODE_PATH",
        "OLDPWD",
        "PATH",
        "PWD",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUSTFLAGS",
        "RUST_LOG",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "TMPDIR",
        "USER",
    ];
    const PREFIXES: &[&str] = &["AWS_", "GCP_", "GOOGLE_", "KUBERNETES_", "SEREN_"];
    const SUFFIXES: &[&str] = &["_SERVICE_HOST", "_SERVICE_PORT"];

    NAMES.iter().any(|name| value.eq_ignore_ascii_case(name))
        || PREFIXES.iter().any(|prefix| {
            value
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
        || SUFFIXES.iter().any(|suffix| {
            value.len() > suffix.len()
                && value
                    .get(value.len() - suffix.len()..)
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        })
}

fn valid_seren_secrets_reference(value: &str) -> bool {
    let Some(path) = value.strip_prefix("seren-secrets://") else {
        return false;
    };
    let mut parts = path.split('/');
    let (Some(vault_id), Some(item_id), Some(field), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    uuid::Uuid::parse_str(vault_id).is_ok()
        && uuid::Uuid::parse_str(item_id).is_ok()
        && !field.is_empty()
        && !field
            .bytes()
            .any(|byte| byte <= b' ' || byte == b'?' || byte == b'#' || byte == 0x7f)
}

fn compose_managed_agent_secrets_credentials(
    current: &[crate::AgentCredentialRef],
    mapping: &[crate::DelegationEffectiveMapping],
) -> Result<Vec<crate::AgentCredentialRef>, ValidationError> {
    let mut replacements = std::collections::BTreeMap::new();
    for entry in mapping {
        if !valid_environment_name(&entry.environment_name) {
            return Err(ValidationError::new(format!(
                "The approved mapping contains invalid environment name '{}'.",
                entry.environment_name
            )));
        }
        let ref_uri = entry.ref_uri.trim();
        if !valid_seren_secrets_reference(ref_uri) {
            return Err(ValidationError::new(format!(
                "The approved mapping for '{}' is not a valid Seren Passwords reference.",
                entry.environment_name
            )));
        }
        let credential = crate::AgentCredentialRef {
            binding: crate::AgentCredentialBinding::ReferenceEnv,
            binding_target: None,
            kind: crate::AgentCredentialKind::ApiKey,
            name: entry.environment_name.clone(),
            publisher_slug: None,
            ref_uri: ref_uri.to_string(),
            rotation: None,
        };
        if replacements
            .insert(entry.environment_name.clone(), credential)
            .is_some()
        {
            return Err(ValidationError::new(format!(
                "The approved mapping contains duplicate environment name '{}'.",
                entry.environment_name
            )));
        }
    }

    let mut credentials = current
        .iter()
        .filter(|credential| {
            // Only environment-reference Secrets bindings are owned by the
            // approved mapping. Header, body, and proxy-inject credentials may
            // legitimately carry a seren-secrets:// reference and must survive.
            let superseded_reference = credential.binding
                == crate::AgentCredentialBinding::ReferenceEnv
                && credential.ref_uri.trim().starts_with("seren-secrets://");
            !superseded_reference && !replacements.contains_key(&credential.name)
        })
        .cloned()
        .collect::<Vec<_>>();
    credentials.extend(replacements.into_values());
    Ok(credentials)
}

fn credential_set_key(credential: &crate::AgentCredentialRef) -> Result<String, ValidationError> {
    // Compare a canonical shape: reference URIs are trimmed, and for an
    // environment-reference binding a target equal to the credential name is
    // the same contract as no target, which other clients write explicitly.
    let mut canonical = credential.clone();
    canonical.ref_uri = canonical.ref_uri.trim().to_string();
    if canonical.binding == crate::AgentCredentialBinding::ReferenceEnv
        && canonical.binding_target.as_deref() == Some(canonical.name.as_str())
    {
        canonical.binding_target = None;
    }
    serde_json::to_string(&canonical).map_err(|error| {
        ValidationError::new(format!("Could not compare credential references: {error}"))
    })
}

fn same_credential_set(
    left: &[crate::AgentCredentialRef],
    right: &[crate::AgentCredentialRef],
) -> Result<bool, ValidationError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    let mut left = left
        .iter()
        .map(credential_set_key)
        .collect::<Result<Vec<_>, _>>()?;
    let mut right = right
        .iter()
        .map(credential_set_key)
        .collect::<Result<Vec<_>, _>>()?;
    left.sort_unstable();
    right.sort_unstable();
    Ok(left == right)
}

pub fn managed_agent_secrets_application(
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: &crate::DelegationPolicyRequestView,
) -> Result<ManagedAgentSecretsApplication, ValidationError> {
    if !matches!(
        request.status,
        crate::DelegationPolicyRequestStatus::Approved
            | crate::DelegationPolicyRequestStatus::Applied
    ) {
        return Err(ValidationError::new(format!(
            "The Seren Passwords setup is {} and cannot be applied.",
            request.status
        )));
    }
    let now = jiff::Timestamp::now();
    let expired = match request.status {
        crate::DelegationPolicyRequestStatus::Approved => request.expires_at <= now,
        crate::DelegationPolicyRequestStatus::Applied => request
            .grant_expires_at
            .is_some_and(|expires_at| expires_at <= now),
        _ => false,
    };
    if expired {
        return Err(ValidationError::new(
            "The Seren Passwords setup has expired and cannot be applied.",
        ));
    }
    if request.scope_kind != crate::DelegationPolicyScopeKind::SecretFields {
        return Err(ValidationError::new(
            "The setup request is not a secret-fields policy.",
        ));
    }
    if request.deployment_id != Some(detail.deployment_id) {
        return Err(ValidationError::new(
            "The setup request belongs to another managed agent deployment.",
        ));
    }
    if request.destination_organization_id != organization_id {
        return Err(ValidationError::new(
            "The setup request belongs to another organization.",
        ));
    }
    if request.effective_mapping.is_empty() {
        return Err(ValidationError::new(
            "The approved Seren Passwords setup has no credential mapping.",
        ));
    }
    let requested_names = request
        .requested_fields
        .iter()
        .map(|field| field.environment_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if requested_names.len() != request.requested_fields.len() {
        return Err(ValidationError::new(
            "The Seren Passwords setup contains duplicate requested environment names.",
        ));
    }
    let mapped_names = request
        .effective_mapping
        .iter()
        .map(|mapping| mapping.environment_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if requested_names != mapped_names {
        return Err(ValidationError::new(
            "The approved Seren Passwords mapping does not cover the exact requested fields.",
        ));
    }
    if detail
        .agent_identity_id
        .is_some_and(|identity_id| identity_id != request.agent_identity_id)
    {
        return Err(ValidationError::new(
            "The setup request names a different Seren Passwords agent identity than the managed agent.",
        ));
    }

    let credentials =
        compose_managed_agent_secrets_credentials(&detail.credentials, &request.effective_mapping)?;
    if detail.secret_resolution_result_id == Some(request.result_id) {
        if detail.agent_identity_id == Some(request.agent_identity_id)
            && same_credential_set(&detail.credentials, &credentials)?
        {
            return Ok(ManagedAgentSecretsApplication::AlreadyApplied);
        }
        return Err(ValidationError::new(
            "The managed agent names this policy result but its Seren Passwords binding does not match.",
        ));
    }

    let active_revision_id = detail
        .active_revision_id
        .ok_or_else(|| ValidationError::new("The managed agent has no active revision to bind."))?;
    if request.deployment_revision_id != Some(active_revision_id) {
        return Err(ValidationError::new(
            "The setup request does not match the managed agent's active revision.",
        ));
    }

    Ok(ManagedAgentSecretsApplication::Update(Box::new(
        crate::AgentSpecUpdate {
            agent_identity_id: Some(request.agent_identity_id),
            credentials: Some(credentials),
            expected_active_revision_id: Some(active_revision_id),
            secret_resolution_result_id: Some(request.result_id),
            ..Default::default()
        },
    )))
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
) -> Result<Option<crate::CloudDeploymentRunResumeRequest>, ValidationError> {
    let decision = crate::CloudRunApprovalDecisionValue::try_from(decision).map_err(|_| {
        ValidationError::new("Invalid approval decision. Expected approve or reject.")
    })?;
    let data = approval_state.get("data").unwrap_or(approval_state);
    let status = data
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if status != "awaiting_approval" {
        return Ok(None);
    }

    let approvals = data
        .get("pending_approvals")
        .and_then(|value| value.as_array())
        .filter(|approvals| !approvals.is_empty())
        .cloned()
        .ok_or_else(|| {
            ValidationError::new("Run is awaiting approval but no pending_approvals were returned.")
        })?;

    let checkpoint_id = data
        .get("checkpoint_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty() && *value == value.trim())
        .ok_or_else(|| {
            ValidationError::new("Run is awaiting approval but no checkpoint_id was returned.")
        })?;

    let mut approval_ids = std::collections::HashSet::with_capacity(approvals.len());
    let approval_decisions = approvals
        .into_iter()
        .enumerate()
        .map(|(index, approval)| {
            let id = approval
                .get("id")
                .and_then(|value| value.as_str())
                .filter(|id| !id.is_empty() && *id == id.trim())
                .ok_or_else(|| {
                    ValidationError::new(format!("pending_approvals[{index}] has no approval id"))
                })?;
            if !approval_ids.insert(id.to_string()) {
                return Err(ValidationError::new(
                    "pending_approvals contains a duplicate approval id",
                ));
            }
            Ok(crate::CloudRunApprovalDecision {
                id: id.to_string(),
                decision,
            })
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;

    Ok(Some(crate::CloudDeploymentRunResumeRequest {
        resume_checkpoint_id: Some(checkpoint_id.to_string()),
        approval_decisions: Some(approval_decisions),
        ..Default::default()
    }))
}

pub fn validate_cloud_approval_resume_identity(
    expected_run_id: &uuid::Uuid,
    expected_execution_id: &str,
    resumed_run_id: &uuid::Uuid,
    resumed_execution_id: &str,
) -> Result<(), ValidationError> {
    if resumed_run_id != expected_run_id || resumed_execution_id != expected_execution_id {
        return Err(ValidationError::new(
            "The resume response did not match the suspended run identity.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bound_secrets_credentials_survive_the_approved_mapping() {
        let mut header = credential("slack_authorization", "seren-secrets://vault/item/password");
        header.binding = crate::AgentCredentialBinding::Header;
        header.binding_target = Some("Authorization".to_string());
        let mapping = vec![mapping("API_TOKEN", "token")];
        let composed = compose_managed_agent_secrets_credentials(&[header.clone()], &mapping)
            .expect("compose");
        assert!(composed.iter().any(|entry| entry.name == header.name));
        assert!(composed.iter().any(|entry| entry.name == "API_TOKEN"));
    }

    #[test]
    fn explicit_reference_binding_target_compares_equal() {
        let ours = credential("API_TOKEN", &secrets_ref("token"));
        let mut theirs = ours.clone();
        theirs.binding_target = Some("API_TOKEN".to_string());
        theirs.ref_uri = format!(" {} ", theirs.ref_uri);
        assert!(same_credential_set(&[ours], &[theirs]).expect("compare"));
    }

    fn credential(name: &str, ref_uri: &str) -> crate::AgentCredentialRef {
        crate::AgentCredentialRef {
            binding: crate::AgentCredentialBinding::ReferenceEnv,
            binding_target: None,
            kind: crate::AgentCredentialKind::ApiKey,
            name: name.to_string(),
            publisher_slug: None,
            ref_uri: ref_uri.to_string(),
            rotation: None,
        }
    }

    fn secrets_ref(field: &str) -> String {
        format!(
            "seren-secrets://11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/{field}"
        )
    }

    fn mapping(name: &str, field: &str) -> crate::DelegationEffectiveMapping {
        crate::DelegationEffectiveMapping {
            environment_name: name.to_string(),
            field: field.to_string(),
            field_group: None,
            item_id: "22222222-2222-2222-2222-222222222222".parse().unwrap(),
            ref_uri: secrets_ref(field),
            vault_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
        }
    }

    fn managed_detail(
        deployment_id: uuid::Uuid,
        active_revision_id: uuid::Uuid,
    ) -> crate::ManagedAgentDeploymentDetail {
        serde_json::from_value(serde_json::json!({
            "deployment_id": deployment_id,
            "active_revision_id": active_revision_id,
            "name": "Secrets Test",
            "agent_slug": "secrets-test",
            "mode": "job",
            "compute_backend": "aws_container",
            "runtime_kind": "python",
            "status": "running",
            "bundle": {},
            "model_id": "openai/gpt-5",
            "model_config": {},
            "template": "research_monitor",
            "tool_presets": [],
            "allowed_publisher_operations": [],
            "resolved_tools": [],
            "approval_policy": "read_only",
            "model_policy": "balanced",
            "runtime_adapter": "seren_agent",
            "private_output_policy": "private_session_database",
            "secret_keys": [],
            "credentials": [{
                "name": "DIRECT",
                "ref_uri": "org-secret://direct",
                "kind": "api_key",
                "binding": "reference_env"
            }],
            "requirements": [],
            "visibility": "opaque",
            "routing_reason": "test"
        }))
        .unwrap()
    }

    fn managed_secrets_policy_request(
        organization_id: uuid::Uuid,
        deployment_id: uuid::Uuid,
        deployment_revision_id: uuid::Uuid,
    ) -> crate::DelegationPolicyRequestView {
        let timestamp: jiff::Timestamp = "2030-01-01T18:19:00Z".parse().unwrap();
        crate::DelegationPolicyRequestView {
            agent_display_name: "Managed agent".to_string(),
            agent_identity_id: uuid::Uuid::new_v4(),
            agent_kem_fingerprint: "kem-fp".to_string(),
            agent_kem_public: "kem-public".to_string(),
            agent_signing_fingerprint: "sig-fp".to_string(),
            agent_signing_public: "signing-public".to_string(),
            agent_target_kind: crate::DelegationAgentTargetKind::Existing,
            allowed_access_levels: vec![crate::AccessLevel::Read],
            applied_at: None,
            applied_deployment_revision_id: None,
            created_at: timestamp,
            decided_at: Some(timestamp),
            deployment_id: Some(deployment_id),
            deployment_revision_id: Some(deployment_revision_id),
            destination_organization_id: organization_id,
            effective_mapping: vec![mapping("PASSWORD", "password")],
            effective_vault_access: Vec::new(),
            events: Vec::new(),
            expires_at: timestamp,
            grant_expires_at: None,
            nonce: "n".repeat(16),
            participants: Vec::new(),
            policy: crate::DelegationApprovalPolicy {
                allow_cross_organization: None,
                allow_same_principal_across_roles: None,
                stages: Vec::new(),
            },
            progress: crate::DelegationPolicyProgress {
                active_participants: 0,
                approved_participants: 1,
                granted_vaults: 0,
                mapped_fields: 1,
                requested_fields: 1,
                stages: Vec::new(),
            },
            request_id: uuid::Uuid::new_v4(),
            requested_fields: vec![crate::DelegationRequestedField {
                environment_name: "PASSWORD".to_string(),
                field_group: None,
            }],
            requester_identity_id: uuid::Uuid::new_v4(),
            requester_user_id: uuid::Uuid::new_v4(),
            result_id: uuid::Uuid::new_v4(),
            scope_kind: crate::DelegationPolicyScopeKind::SecretFields,
            status: crate::DelegationPolicyRequestStatus::Approved,
            supersedes_request_id: None,
        }
    }

    #[test]
    fn managed_agent_secrets_mapping_replaces_owned_names_and_old_secrets_refs() {
        let current = vec![
            credential("DIRECT", "org-secret://direct"),
            credential("PASSWORD", "org-secret://shadowing-value"),
            credential("OLD_PASSWORD", "seren-secrets://vault/item/old"),
        ];
        let mapping = vec![mapping("PASSWORD", "password")];

        let credentials = compose_managed_agent_secrets_credentials(&current, &mapping).unwrap();

        assert_eq!(credentials.len(), 2);
        assert!(credentials.iter().any(|credential| {
            credential.name == "DIRECT" && credential.ref_uri == "org-secret://direct"
        }));
        assert!(credentials.iter().any(|credential| {
            credential.name == "PASSWORD" && credential.ref_uri == secrets_ref("password")
        }));
    }

    #[test]
    fn managed_agent_secrets_mapping_rejects_invalid_or_duplicate_entries() {
        assert!(
            compose_managed_agent_secrets_credentials(&[], &[mapping("SEREN_TOKEN", "password")],)
                .is_err()
        );
        let mut malformed = mapping("PASSWORD", "password");
        malformed.ref_uri = "seren-secrets://vault/item/password".to_string();
        assert!(compose_managed_agent_secrets_credentials(&[], &[malformed]).is_err());
        assert!(
            compose_managed_agent_secrets_credentials(
                &[],
                &[
                    mapping("PASSWORD", "password"),
                    mapping("PASSWORD", "other"),
                ],
            )
            .is_err()
        );
        assert!(
            compose_managed_agent_secrets_credentials(&[], &[mapping("lowercase", "password")])
                .is_ok()
        );
    }

    #[test]
    fn managed_agent_secrets_mapping_matches_runtime_name_and_uri_rules() {
        for name in [
            "PATH",
            "tmp",
            "SEREN_API_KEY",
            "aws_access_key_id",
            "KUBERNETES_SERVICE_HOST",
            "redis_service_port",
        ] {
            assert!(!valid_environment_name(name), "{name}");
        }
        assert!(valid_environment_name("slack_bot_token"));

        let valid = secrets_ref("password");
        assert!(valid_seren_secrets_reference(&valid));
        for invalid in [
            "seren-secrets://vault/item/password".to_string(),
            format!("{valid}/extra"),
            format!("{valid}?raw=1"),
            format!("{valid}#fragment"),
        ] {
            assert!(!valid_seren_secrets_reference(&invalid), "{invalid}");
        }
    }

    #[test]
    fn managed_agent_secrets_mapping_requires_exact_requested_fields() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let mut request =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        request
            .requested_fields
            .push(crate::DelegationRequestedField {
                environment_name: "USERNAME".to_string(),
                field_group: None,
            });

        let error = managed_agent_secrets_application(organization_id, &detail, &request)
            .expect_err("partial mapping must be rejected");
        assert!(error.0.contains("exact requested fields"));
    }

    #[test]
    fn managed_agent_secrets_application_uses_the_status_specific_deadline() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let mut request =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        request.expires_at = "2020-01-01T00:00:00Z".parse().unwrap();
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_err());

        request.status = crate::DelegationPolicyRequestStatus::Applied;
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_ok());

        request.grant_expires_at = Some("2021-01-01T00:00:00Z".parse().unwrap());
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_err());
    }

    #[test]
    fn managed_agent_secrets_application_binds_the_approved_revision_and_mapping() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        let ManagedAgentSecretsApplication::Update(update) =
            managed_agent_secrets_application(organization_id, &detail, &request).unwrap()
        else {
            panic!("approved setup must produce an update");
        };

        assert_eq!(update.agent_identity_id, Some(request.agent_identity_id));
        assert_eq!(update.secret_resolution_result_id, Some(request.result_id));
        assert_eq!(update.expected_active_revision_id, Some(revision_id));
        let credentials = update.credentials.unwrap();
        assert_eq!(credentials.len(), 2);
        assert!(credentials.iter().any(|credential| {
            credential.name == "PASSWORD" && credential.ref_uri == secrets_ref("password")
        }));
    }

    #[test]
    fn managed_agent_secrets_application_rejects_stale_and_false_applied_bindings() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let mut detail = managed_detail(deployment_id, revision_id);
        let request =
            managed_secrets_policy_request(organization_id, deployment_id, uuid::Uuid::new_v4());
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_err());

        detail.secret_resolution_result_id = Some(request.result_id);
        detail.agent_identity_id = Some(request.agent_identity_id);
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_err());
    }

    #[test]
    fn managed_agent_secrets_application_recognizes_an_exact_applied_binding() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let mut detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let ManagedAgentSecretsApplication::Update(update) =
            managed_agent_secrets_application(organization_id, &detail, &request).unwrap()
        else {
            panic!("approved setup must produce an update");
        };
        detail.credentials = update.credentials.unwrap();
        detail.agent_identity_id = Some(request.agent_identity_id);
        detail.secret_resolution_result_id = Some(request.result_id);
        detail.active_revision_id = Some(uuid::Uuid::new_v4());

        assert!(matches!(
            managed_agent_secrets_application(organization_id, &detail, &request),
            Ok(ManagedAgentSecretsApplication::AlreadyApplied)
        ));
    }

    #[test]
    fn managed_agent_secrets_application_rejects_wrong_org_and_identity() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let mut detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        assert!(
            managed_agent_secrets_application(uuid::Uuid::new_v4(), &detail, &request).is_err()
        );
        detail.agent_identity_id = Some(uuid::Uuid::new_v4());
        assert!(managed_agent_secrets_application(organization_id, &detail, &request).is_err());
    }

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
        assert_eq!(
            payload.approval_decisions.unwrap()[0].decision,
            crate::CloudRunApprovalDecisionValue::Reject
        );
    }

    #[test]
    fn build_cloud_approval_resume_request_rejects_missing_or_duplicate_ids() {
        let malformed_checkpoint = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": " checkpoint-123 ",
            "pending_approvals": [{ "id": "approval-a" }]
        });
        assert!(build_cloud_approval_resume_request(&malformed_checkpoint, "reject").is_err());

        let missing_list = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": "checkpoint-123"
        });
        assert!(build_cloud_approval_resume_request(&missing_list, "reject").is_err());

        let missing = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": "checkpoint-123",
            "pending_approvals": [{ "tool": "send_message" }]
        });
        assert!(build_cloud_approval_resume_request(&missing, "reject").is_err());

        let malformed = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": "checkpoint-123",
            "pending_approvals": [{ "id": " approval-a " }]
        });
        assert!(build_cloud_approval_resume_request(&malformed, "reject").is_err());

        let duplicate = serde_json::json!({
            "status": "awaiting_approval",
            "checkpoint_id": "checkpoint-123",
            "pending_approvals": [{ "id": "approval-a" }, { "id": "approval-a" }]
        });
        assert!(build_cloud_approval_resume_request(&duplicate, "approve").is_err());
    }

    #[test]
    fn approval_resume_identity_must_match_the_suspended_run() {
        let run_id = uuid::Uuid::new_v4();
        validate_cloud_approval_resume_identity(&run_id, "execution-1", &run_id, "execution-1")
            .expect("matching identity should pass");
        assert!(
            validate_cloud_approval_resume_identity(
                &run_id,
                "execution-1",
                &uuid::Uuid::new_v4(),
                "execution-1",
            )
            .is_err()
        );
        assert!(
            validate_cloud_approval_resume_identity(
                &run_id,
                "execution-1",
                &run_id,
                "execution-2",
            )
            .is_err()
        );
    }
}
