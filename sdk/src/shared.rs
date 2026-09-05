use crate::ManagedSecretsApplyTarget;
use thiserror::Error;

pub const MANAGED_AGENT_SECRETS_REDIRECT_ORIGIN: &str = "https://passwords.serendb.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudDeploymentLifecycleAction {
    Start,
    Stop,
}

#[derive(Debug, Error)]
pub enum CloudDeploymentLifecycleError {
    #[error("failed to resolve the cloud deployment before changing its lifecycle: {0}")]
    Lookup(#[source] Box<crate::Error<()>>),
    #[error(
        "cannot select a lifecycle endpoint because deployment metadata identifies unsupported managed publisher '{publisher}'"
    )]
    UnsupportedManagedPublisher { publisher: String },
    #[error(
        "cannot select a lifecycle endpoint because the deployment has an active managed revision but no managed-agent metadata"
    )]
    AmbiguousDeploymentType,
    #[error("cloud deployment lifecycle mutation failed: {0}")]
    Mutation(#[source] Box<crate::Error<()>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudDeploymentLifecycleRoute {
    SerenAgent,
    SerenCloud,
}

/// `managed_agent` is the authoritative control-plane discriminator: Seren Cloud
/// derives it from the same managed-agent runtime configuration the server uses to
/// reject managed deployments on the generic lifecycle route.
///
/// `active_revision_id` is only a drift guard. A deployment detail that carries a
/// managed revision without managed-agent metadata cannot be classified, so it must
/// not reach either mutation. It does not detect a managed deployment whose metadata
/// the server withheld, because a withheld deployment detail carries neither field.
fn cloud_deployment_lifecycle_route(
    deployment: &crate::CloudDeploymentSummary,
) -> Result<CloudDeploymentLifecycleRoute, CloudDeploymentLifecycleError> {
    match deployment.managed_agent.as_ref() {
        Some(managed_agent) if managed_agent.publisher == "seren-agent" => {
            Ok(CloudDeploymentLifecycleRoute::SerenAgent)
        }
        Some(managed_agent) => Err(CloudDeploymentLifecycleError::UnsupportedManagedPublisher {
            publisher: managed_agent.publisher.clone(),
        }),
        None if deployment.active_revision_id.is_some() => {
            Err(CloudDeploymentLifecycleError::AmbiguousDeploymentType)
        }
        None => Ok(CloudDeploymentLifecycleRoute::SerenCloud),
    }
}

impl crate::Client {
    /// Start or stop a cloud deployment through the lifecycle endpoint that owns it.
    ///
    /// Resolves the deployment once through the read-only Seren Cloud detail
    /// operation, then issues exactly one mutation to the route the deployment
    /// metadata selects. Deployments that cannot be classified fail before any
    /// mutation; the generic route is never used as a probe or a fallback.
    pub async fn dispatch_cloud_deployment_lifecycle(
        &self,
        deployment_id: &uuid::Uuid,
        action: CloudDeploymentLifecycleAction,
    ) -> Result<
        crate::ResponseValue<crate::DataResponseCloudDeploymentActionStatusResponse>,
        CloudDeploymentLifecycleError,
    > {
        let deployment = self
            .seren_cloud_get_deployment(deployment_id)
            .await
            .map_err(|error| CloudDeploymentLifecycleError::Lookup(Box::new(error)))?
            .into_inner()
            .data;
        let route = cloud_deployment_lifecycle_route(&deployment)?;

        match (route, action) {
            (CloudDeploymentLifecycleRoute::SerenAgent, CloudDeploymentLifecycleAction::Start) => {
                self.seren_agent_start_managed_deployment(deployment_id)
                    .await
            }
            (CloudDeploymentLifecycleRoute::SerenAgent, CloudDeploymentLifecycleAction::Stop) => {
                self.seren_agent_stop_managed_deployment(deployment_id)
                    .await
            }
            (CloudDeploymentLifecycleRoute::SerenCloud, CloudDeploymentLifecycleAction::Start) => {
                self.seren_cloud_start(deployment_id).await
            }
            (CloudDeploymentLifecycleRoute::SerenCloud, CloudDeploymentLifecycleAction::Stop) => {
                self.seren_cloud_stop(deployment_id).await
            }
        }
        .map_err(|error| CloudDeploymentLifecycleError::Mutation(Box::new(error)))
    }
}

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

#[derive(Debug, Error)]
pub enum ManagedSecretsSetupBindingError {
    #[error("Failed to load the managed secrets setup binding: {0}")]
    Lookup(#[source] Box<crate::Error<()>>),
    #[error(transparent)]
    InvalidBinding(#[from] ValidationError),
}

/// Resolve the original apply target Core bound to a managed secrets setup.
///
/// Missing or inconsistent bindings stop apply; they never imply a base setup.
pub async fn managed_secrets_apply_target(
    client: &crate::Client,
    setup_id: uuid::Uuid,
    request: &crate::DelegationPolicyRequestView,
) -> Result<ManagedSecretsApplyTarget, ManagedSecretsSetupBindingError> {
    if request.request_id != setup_id {
        return Err(ValidationError::new(
            "The returned secrets setup does not match the selected setup.",
        )
        .into());
    }
    let deployment_id = request.deployment_id.ok_or_else(|| {
        ValidationError::new("The secrets setup is not bound to a managed agent deployment.")
    })?;
    let binding = client
        .managed_agent_secrets_setup_binding(&request.destination_organization_id, &setup_id)
        .await
        .map_err(|error| ManagedSecretsSetupBindingError::Lookup(Box::new(error)))?
        .into_inner()
        .data;
    if binding.setup_id != setup_id || binding.deployment_id != deployment_id {
        return Err(ValidationError::new(
            "Core returned a binding for another setup or deployment.",
        )
        .into());
    }
    Ok(binding.target)
}

pub fn managed_agent_secrets_application(
    target: &ManagedSecretsApplyTarget,
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: &crate::DelegationPolicyRequestView,
) -> Result<ManagedAgentSecretsApplication, ValidationError> {
    if !matches!(target, ManagedSecretsApplyTarget::BaseManifest) {
        return Err(ValidationError::new(
            "This Seren Passwords setup requires its dedicated proposal apply route.",
        ));
    }
    ensure_delegation_setup_applies(organization_id, detail, request)?;
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

/// Reject a managed Passwords setup that binds more than one proposal selector.
///
/// The three selectors are mutually exclusive; Core derives a distinct
/// server-side contract from whichever one is bound, so silently defaulting or
/// accepting several at once would mint the wrong field set.
pub fn ensure_single_managed_secrets_proposal_selector(
    connector_binding_proposal_id: Option<uuid::Uuid>,
    model_credential_proposal_id: Option<uuid::Uuid>,
    publisher_credential_proposal_id: Option<uuid::Uuid>,
) -> Result<(), ValidationError> {
    let selected = usize::from(connector_binding_proposal_id.is_some())
        + usize::from(model_credential_proposal_id.is_some())
        + usize::from(publisher_credential_proposal_id.is_some());
    if selected > 1 {
        return Err(ValidationError::new(
            "At most one managed Passwords proposal selector may be set (connector, model, or publisher).",
        ));
    }
    Ok(())
}

/// Validate that an approved Seren Passwords setup belongs to the current managed agent authority.
fn ensure_delegation_setup_applies(
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: &crate::DelegationPolicyRequestView,
) -> Result<(), ValidationError> {
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
    if detail
        .agent_identity_id
        .is_some_and(|identity_id| identity_id != request.agent_identity_id)
    {
        return Err(ValidationError::new(
            "The setup request names a different Seren Passwords agent identity than the managed agent.",
        ));
    }
    Ok(())
}

/// Project the server-approved Seren Passwords mapping onto the publisher
/// credential apply shape.
///
/// Only the mapping the server returned on the approved delegation is trusted;
/// a caller-invented reference never reaches the apply route. The mapping must
/// cover exactly the environment names the proposal requested.
pub fn managed_publisher_credential_effective_mapping(
    requested_environment_names: &[String],
    request: &crate::DelegationPolicyRequestView,
) -> Result<Vec<crate::ManagedPublisherCredentialEffectiveMapping>, ValidationError> {
    let requested: std::collections::BTreeSet<&str> = requested_environment_names
        .iter()
        .map(String::as_str)
        .collect();
    if requested.len() != requested_environment_names.len() {
        return Err(ValidationError::new(
            "The publisher credential proposal contains duplicate requested environment names.",
        ));
    }
    let policy_requested: std::collections::BTreeSet<&str> = request
        .requested_fields
        .iter()
        .map(|field| field.environment_name.as_str())
        .collect();
    if policy_requested.len() != request.requested_fields.len() || policy_requested != requested {
        return Err(ValidationError::new(
            "The Seren Passwords setup does not request the proposal's exact publisher fields.",
        ));
    }
    let mut mapping = Vec::with_capacity(request.effective_mapping.len());
    let mut seen = std::collections::BTreeSet::new();
    for entry in &request.effective_mapping {
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
        if !seen.insert(entry.environment_name.clone()) {
            return Err(ValidationError::new(format!(
                "The approved mapping contains duplicate environment name '{}'.",
                entry.environment_name
            )));
        }
        mapping.push(crate::ManagedPublisherCredentialEffectiveMapping {
            environment_name: entry.environment_name.clone(),
            ref_uri: ref_uri.to_string(),
            vault_id: entry.vault_id,
            item_id: entry.item_id,
            field: entry.field.clone(),
        });
    }
    let mapped: std::collections::BTreeSet<&str> = mapping
        .iter()
        .map(|entry| entry.environment_name.as_str())
        .collect();
    if mapped != requested {
        return Err(ValidationError::new(
            "The approved Seren Passwords mapping does not cover the exact requested publisher fields.",
        ));
    }
    Ok(mapping)
}

/// The decision a caller must carry out to apply a publisher-credential
/// proposal: either the proposal is already applied (no mutation), or a single
/// proposal-bound apply call must be issued with the server-returned mapping.
#[derive(Debug, Clone)]
pub enum PublisherCredentialProposalApply {
    /// The proposal is already applied at this revision; retrying is a no-op.
    AlreadyApplied {
        applied_revision_id: uuid::Uuid,
        result_id: Option<uuid::Uuid>,
    },
    /// Issue exactly one proposal-bound apply with this request.
    Apply {
        proposal_id: uuid::Uuid,
        idempotency_key: uuid::Uuid,
        request: Box<crate::ApplyPublisherCredentialProposalRequest>,
    },
}

pub fn publisher_credential_proposal_applied_revision(
    reviewed: &crate::ManagedPublisherCredentialProposal,
    request: &crate::ApplyPublisherCredentialProposalRequest,
    applied: &crate::ManagedPublisherCredentialProposal,
) -> Result<uuid::Uuid, ValidationError> {
    if applied.state != crate::ManagedPublisherCredentialProposalState::Applied
        || applied.id != reviewed.id
        || applied.deployment_id != reviewed.deployment_id
        || applied.proposal_fingerprint != reviewed.proposal_fingerprint
        || applied.requirements_fingerprint != reviewed.requirements_fingerprint
        || applied.expected_active_revision_id != reviewed.expected_active_revision_id
        || applied.requested_environment_names != reviewed.requested_environment_names
        || applied.requires_secret_resolution_result != reviewed.requires_secret_resolution_result
        || applied.approval_request_id != reviewed.approval_request_id
        || applied.result_id != request.secret_resolution_result_id
    {
        return Err(ValidationError::new(
            "Core returned a publisher credential proposal that does not match the reviewed apply.",
        ));
    }
    applied.applied_revision_id.ok_or_else(|| {
        ValidationError::new(
            "Core returned an applied publisher credential proposal without an applied revision.",
        )
    })
}

/// Reject a Seren Passwords setup that Core did not bind to this proposal.
///
/// Core records the setup handoff minted for the proposal and reanchors the
/// proposal to the revision that setup bound, so both must agree before the
/// setup's approved mapping can stand in for the proposal's reviewed fields.
fn ensure_setup_bound_to_publisher_credential_proposal(
    request: &crate::DelegationPolicyRequestView,
    proposal: &crate::ManagedPublisherCredentialProposal,
) -> Result<(), ValidationError> {
    if proposal.approval_request_id != Some(request.request_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup is not bound to this publisher credential proposal.",
        ));
    }
    if request.deployment_revision_id != Some(proposal.expected_active_revision_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup does not target the proposal's reviewed revision.",
        ));
    }
    Ok(())
}

fn publisher_credential_proposal_already_applied(
    proposal: &crate::ManagedPublisherCredentialProposal,
) -> Result<PublisherCredentialProposalApply, ValidationError> {
    let applied_revision_id = proposal.applied_revision_id.ok_or_else(|| {
        ValidationError::new(
            "The publisher credential proposal is applied but names no active revision.",
        )
    })?;
    Ok(PublisherCredentialProposalApply::AlreadyApplied {
        applied_revision_id,
        result_id: proposal.result_id,
    })
}

/// Decide whether a publisher-credential proposal needs one apply mutation.
///
/// Core exposes only the deployment's latest proposal, so `proposal_id`
/// pins the apply to the proposal the caller reviewed. Fails closed: a
/// superseded proposal, a proposal bound to a different result, a stale active
/// revision, or a mapping that does not cover the requested fields all error
/// before any mutation. An already-applied proposal reports its existing
/// revision without a Passwords setup, so a retry after a lost response never
/// mutates twice; a setup supplied on that retry must still be the one bound to
/// the proposal.
pub fn publisher_credential_proposal_apply(
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: Option<&crate::DelegationPolicyRequestView>,
    proposal: &crate::ManagedPublisherCredentialProposal,
    proposal_id: uuid::Uuid,
) -> Result<PublisherCredentialProposalApply, ValidationError> {
    if proposal_id != proposal.id {
        return Err(ValidationError::new(
            "The managed agent's current publisher credential proposal is not the proposal selected for apply.",
        ));
    }
    if proposal.deployment_id != detail.deployment_id {
        return Err(ValidationError::new(
            "The publisher credential proposal belongs to another managed agent deployment.",
        ));
    }
    if proposal.state == crate::ManagedPublisherCredentialProposalState::Superseded {
        return Err(ValidationError::new(
            "The publisher credential proposal has been superseded and can no longer be applied.",
        ));
    }

    let apply_request = if proposal.requires_secret_resolution_result {
        if proposal.state == crate::ManagedPublisherCredentialProposalState::Applied {
            if let Some(request) = request {
                ensure_setup_bound_to_publisher_credential_proposal(request, proposal)?;
                if proposal.result_id != Some(request.result_id) {
                    return Err(ValidationError::new(
                        "The publisher credential proposal is bound to a different Seren Passwords result.",
                    ));
                }
            }
            return publisher_credential_proposal_already_applied(proposal);
        }
        let request = request.ok_or_else(|| {
            ValidationError::new(
                "The publisher credential proposal requires an approved Seren Passwords setup.",
            )
        })?;
        ensure_delegation_setup_applies(organization_id, detail, request)?;
        ensure_setup_bound_to_publisher_credential_proposal(request, proposal)?;
        if proposal
            .result_id
            .is_some_and(|result_id| result_id != request.result_id)
        {
            return Err(ValidationError::new(
                "The publisher credential proposal is bound to a different Seren Passwords result.",
            ));
        }
        let effective_mapping = managed_publisher_credential_effective_mapping(
            &proposal.requested_environment_names,
            request,
        )?;
        crate::ApplyPublisherCredentialProposalRequest {
            effective_mapping,
            secret_resolution_result_id: Some(request.result_id),
        }
    } else {
        if request.is_some()
            || !proposal.requested_environment_names.is_empty()
            || proposal.result_id.is_some()
            || proposal.approval_request_id.is_some()
        {
            return Err(ValidationError::new(
                "The publisher credential proposal has an inconsistent result contract.",
            ));
        }
        if proposal.state == crate::ManagedPublisherCredentialProposalState::Applied {
            return publisher_credential_proposal_already_applied(proposal);
        }
        crate::ApplyPublisherCredentialProposalRequest::default()
    };

    let active_revision_id = detail
        .active_revision_id
        .ok_or_else(|| ValidationError::new("The managed agent has no active revision to bind."))?;
    if proposal.expected_active_revision_id != active_revision_id {
        return Err(ValidationError::new(
            "The publisher credential proposal no longer targets the managed agent's active revision.",
        ));
    }

    Ok(PublisherCredentialProposalApply::Apply {
        proposal_id: proposal.id,
        idempotency_key: proposal.id,
        request: Box::new(apply_request),
    })
}

/// The decision a caller must carry out to apply a connector-binding proposal:
/// either the proposal already produced its revision (no mutation), or a single
/// proposal-bound apply call must be issued against the connector's apply route.
///
/// A connector-binding proposal always resolves connector secret references, so
/// an approved Seren Passwords setup is always required for a fresh apply and
/// the apply body only carries the server-resolved `secret_resolution_result_id`.
#[derive(Debug, Clone)]
pub enum ConnectorBindingProposalApply {
    /// The proposal already produced its revision; retrying is a no-op.
    AlreadyApplied {
        applied_revision_id: uuid::Uuid,
        result_id: Option<uuid::Uuid>,
    },
    /// Issue exactly one proposal-bound apply against the connector route.
    Apply {
        connector_ref: String,
        proposal_id: uuid::Uuid,
        idempotency_key: uuid::Uuid,
        request: Box<crate::ApplyConnectorBindingProposalRequest>,
    },
}

/// Whether a connector-binding proposal state means its apply produced a
/// revision that is rolling out or live. Core keeps `applied_revision_id` on a
/// failed rollout, so the revision alone does not prove the apply completed.
fn connector_binding_proposal_rollout_started(
    state: &crate::ManagedConnectorBindingProposalState,
) -> bool {
    matches!(
        state,
        crate::ManagedConnectorBindingProposalState::Applying
            | crate::ManagedConnectorBindingProposalState::Rolling
            | crate::ManagedConnectorBindingProposalState::IngressReady
    )
}

/// Reject a Seren Passwords setup that Core did not bind to this connector
/// proposal.
///
/// Core records the setup handoff minted for the proposal and reanchors the
/// proposal to the revision that setup bound, so both must agree before the
/// setup's approved result can stand in for the proposal's reviewed fields.
fn ensure_setup_bound_to_connector_binding_proposal(
    request: &crate::DelegationPolicyRequestView,
    proposal: &crate::ManagedConnectorBindingProposal,
) -> Result<(), ValidationError> {
    if proposal.approval_request_id != Some(request.request_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup is not bound to this connector-binding proposal.",
        ));
    }
    if request.deployment_revision_id != Some(proposal.expected_active_revision_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup does not target the connector proposal's reviewed revision.",
        ));
    }
    Ok(())
}

/// Validate the connector-binding proposal Core returned from the apply route
/// against the reviewed proposal and the request that was sent.
///
/// Fails closed: Core must echo the same proposal identity, connector, revision,
/// fingerprints, requested fields, and setup binding, bind the result that was
/// sent, report a rollout state, and name the applied revision.
pub fn connector_binding_proposal_applied_revision(
    reviewed: &crate::ManagedConnectorBindingProposal,
    request: &crate::ApplyConnectorBindingProposalRequest,
    applied: &crate::ManagedConnectorBindingProposal,
) -> Result<uuid::Uuid, ValidationError> {
    if !connector_binding_proposal_rollout_started(&applied.state)
        || applied.id != reviewed.id
        || applied.deployment_id != reviewed.deployment_id
        || applied.connector_ref != reviewed.connector_ref
        || applied.proposal_fingerprint != reviewed.proposal_fingerprint
        || applied.requirements_fingerprint != reviewed.requirements_fingerprint
        || applied.expected_active_revision_id != reviewed.expected_active_revision_id
        || applied.requested_environment_names != reviewed.requested_environment_names
        || applied.approval_request_id != reviewed.approval_request_id
        || applied.result_id != Some(request.secret_resolution_result_id)
    {
        return Err(ValidationError::new(
            "Core returned a connector-binding proposal that does not match the reviewed apply.",
        ));
    }
    applied.applied_revision_id.ok_or_else(|| {
        ValidationError::new(
            "Core returned an applied connector-binding proposal without an applied revision.",
        )
    })
}

/// Select an apply mutation or an existing rollout revision for a connector proposal.
///
/// The selected connector and proposal must match Core's response. An approved
/// setup must bind the proposal, reviewed revision, and exact result. Failed or
/// superseded proposals cannot be applied or reported as successful replays.
pub fn connector_binding_proposal_apply(
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: Option<&crate::DelegationPolicyRequestView>,
    proposal: &crate::ManagedConnectorBindingProposal,
    proposal_id: uuid::Uuid,
    connector_ref: &str,
) -> Result<ConnectorBindingProposalApply, ValidationError> {
    if proposal_id != proposal.id {
        return Err(ValidationError::new(
            "The connector's current binding proposal is not the proposal selected for apply.",
        ));
    }
    if proposal.connector_ref != connector_ref {
        return Err(ValidationError::new(
            "The connector binding proposal is not for the connector selected for apply.",
        ));
    }
    if proposal.deployment_id != detail.deployment_id {
        return Err(ValidationError::new(
            "The connector-binding proposal belongs to another managed agent deployment.",
        ));
    }
    match proposal.state {
        crate::ManagedConnectorBindingProposalState::Superseded => {
            return Err(ValidationError::new(
                "The connector-binding proposal has been superseded and can no longer be applied.",
            ));
        }
        crate::ManagedConnectorBindingProposalState::Failed => {
            return Err(ValidationError::new(
                "The connector-binding proposal rollout failed; create a new proposal instead of retrying.",
            ));
        }
        _ => {}
    }

    if connector_binding_proposal_rollout_started(&proposal.state) {
        let applied_revision_id = proposal.applied_revision_id.ok_or_else(|| {
            ValidationError::new(
                "The connector-binding proposal is rolling out but names no applied revision.",
            )
        })?;
        if let Some(request) = request {
            ensure_setup_bound_to_connector_binding_proposal(request, proposal)?;
            if proposal.result_id != Some(request.result_id) {
                return Err(ValidationError::new(
                    "The connector-binding proposal is bound to a different Seren Passwords result.",
                ));
            }
        }
        return Ok(ConnectorBindingProposalApply::AlreadyApplied {
            applied_revision_id,
            result_id: proposal.result_id,
        });
    }
    if proposal.applied_revision_id.is_some() {
        return Err(ValidationError::new(
            "The connector-binding proposal names an applied revision before its rollout started.",
        ));
    }

    let request = request.ok_or_else(|| {
        ValidationError::new(
            "The connector-binding proposal requires an approved Seren Passwords setup.",
        )
    })?;
    ensure_delegation_setup_applies(organization_id, detail, request)?;
    ensure_setup_bound_to_connector_binding_proposal(request, proposal)?;
    if proposal
        .result_id
        .is_some_and(|result_id| result_id != request.result_id)
    {
        return Err(ValidationError::new(
            "The connector-binding proposal is bound to a different Seren Passwords result.",
        ));
    }

    let active_revision_id = detail
        .active_revision_id
        .ok_or_else(|| ValidationError::new("The managed agent has no active revision to bind."))?;
    if proposal.expected_active_revision_id != active_revision_id {
        return Err(ValidationError::new(
            "The connector-binding proposal no longer targets the managed agent's active revision.",
        ));
    }

    Ok(ConnectorBindingProposalApply::Apply {
        connector_ref: proposal.connector_ref.clone(),
        proposal_id: proposal.id,
        idempotency_key: proposal.id,
        request: Box::new(crate::ApplyConnectorBindingProposalRequest {
            secret_resolution_result_id: request.result_id,
        }),
    })
}

/// Project the server-approved Seren Passwords mapping onto the model-credential
/// apply shape.
///
/// Only the mapping the server returned on the approved delegation is trusted; a
/// caller-invented reference never reaches the apply route. The mapping must
/// cover exactly the environment names the proposal requested. Unlike the
/// publisher mapping, the model mapping carries `field_group` through.
pub fn managed_model_credential_effective_mapping(
    requested_environment_names: &[String],
    request: &crate::DelegationPolicyRequestView,
) -> Result<Vec<crate::ManagedModelCredentialEffectiveMapping>, ValidationError> {
    let requested: std::collections::BTreeSet<&str> = requested_environment_names
        .iter()
        .map(String::as_str)
        .collect();
    if requested.len() != requested_environment_names.len() {
        return Err(ValidationError::new(
            "The model credential proposal contains duplicate requested environment names.",
        ));
    }
    let policy_requested: std::collections::BTreeSet<&str> = request
        .requested_fields
        .iter()
        .map(|field| field.environment_name.as_str())
        .collect();
    if policy_requested.len() != request.requested_fields.len() || policy_requested != requested {
        return Err(ValidationError::new(
            "The Seren Passwords setup does not request the proposal's exact model fields.",
        ));
    }
    let mut mapping = Vec::with_capacity(request.effective_mapping.len());
    let mut seen = std::collections::BTreeSet::new();
    for entry in &request.effective_mapping {
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
        if !seen.insert(entry.environment_name.clone()) {
            return Err(ValidationError::new(format!(
                "The approved mapping contains duplicate environment name '{}'.",
                entry.environment_name
            )));
        }
        mapping.push(crate::ManagedModelCredentialEffectiveMapping {
            environment_name: entry.environment_name.clone(),
            ref_uri: ref_uri.to_string(),
            vault_id: entry.vault_id,
            item_id: entry.item_id,
            field: entry.field.clone(),
            field_group: entry.field_group.clone(),
        });
    }
    let mapped: std::collections::BTreeSet<&str> = mapping
        .iter()
        .map(|entry| entry.environment_name.as_str())
        .collect();
    if mapped != requested {
        return Err(ValidationError::new(
            "The approved Seren Passwords mapping does not cover the exact requested model fields.",
        ));
    }
    Ok(mapping)
}

/// The decision a caller must carry out to apply a model-credential proposal:
/// either the proposal is already applied (no mutation), or a single
/// proposal-bound apply call must be issued against the model-credential route.
///
/// Like a publisher-credential proposal, a model-credential proposal may require
/// a managed secrets result (API-key auth) or none (ChatGPT-subscription
/// auth); the apply body carries the reviewed mapping and result only in the
/// former case.
#[derive(Debug, Clone)]
pub enum ModelCredentialProposalApply {
    /// The proposal is already applied at this revision; retrying is a no-op.
    AlreadyApplied {
        applied_revision_id: uuid::Uuid,
        result_id: Option<uuid::Uuid>,
    },
    /// Issue exactly one proposal-bound apply with this request.
    Apply {
        proposal_id: uuid::Uuid,
        idempotency_key: uuid::Uuid,
        request: Box<crate::ApplyModelCredentialProposalRequest>,
    },
}

pub fn model_credential_proposal_applied_revision(
    reviewed: &crate::ManagedModelCredentialProposal,
    request: &crate::ApplyModelCredentialProposalRequest,
    applied: &crate::ManagedModelCredentialProposal,
) -> Result<uuid::Uuid, ValidationError> {
    if applied.state != crate::ManagedModelCredentialProposalState::Applied
        || applied.id != reviewed.id
        || applied.deployment_id != reviewed.deployment_id
        || applied.model_id != reviewed.model_id
        || applied.auth_method != reviewed.auth_method
        || applied.operation != reviewed.operation
        || applied.proposal_fingerprint != reviewed.proposal_fingerprint
        || applied.requirements_fingerprint != reviewed.requirements_fingerprint
        || applied.expected_active_revision_id != reviewed.expected_active_revision_id
        || applied.requested_environment_names != reviewed.requested_environment_names
        || applied.requires_secret_resolution_result != reviewed.requires_secret_resolution_result
        || applied.approval_request_id != reviewed.approval_request_id
        || applied.result_id != request.secret_resolution_result_id
    {
        return Err(ValidationError::new(
            "Core returned a model credential proposal that does not match the reviewed apply.",
        ));
    }
    applied.applied_revision_id.ok_or_else(|| {
        ValidationError::new(
            "Core returned an applied model credential proposal without an applied revision.",
        )
    })
}

/// Reject a Seren Passwords setup that Core did not bind to this model proposal.
fn ensure_setup_bound_to_model_credential_proposal(
    request: &crate::DelegationPolicyRequestView,
    proposal: &crate::ManagedModelCredentialProposal,
) -> Result<(), ValidationError> {
    if proposal.approval_request_id != Some(request.request_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup is not bound to this model credential proposal.",
        ));
    }
    if request.deployment_revision_id != Some(proposal.expected_active_revision_id) {
        return Err(ValidationError::new(
            "The Seren Passwords setup does not target the model proposal's reviewed revision.",
        ));
    }
    Ok(())
}

fn model_credential_proposal_already_applied(
    proposal: &crate::ManagedModelCredentialProposal,
) -> Result<ModelCredentialProposalApply, ValidationError> {
    let applied_revision_id = proposal.applied_revision_id.ok_or_else(|| {
        ValidationError::new(
            "The model credential proposal is applied but names no active revision.",
        )
    })?;
    Ok(ModelCredentialProposalApply::AlreadyApplied {
        applied_revision_id,
        result_id: proposal.result_id,
    })
}

/// Select an apply mutation or an existing revision for a model credential proposal.
///
/// The selected proposal and approved setup must match Core's reviewed binding.
/// Proposals that require no secret result accept no setup or field mapping.
pub fn model_credential_proposal_apply(
    organization_id: uuid::Uuid,
    detail: &crate::ManagedAgentDeploymentDetail,
    request: Option<&crate::DelegationPolicyRequestView>,
    proposal: &crate::ManagedModelCredentialProposal,
    proposal_id: uuid::Uuid,
) -> Result<ModelCredentialProposalApply, ValidationError> {
    if proposal_id != proposal.id {
        return Err(ValidationError::new(
            "The managed agent's current model credential proposal is not the proposal selected for apply.",
        ));
    }
    if proposal.deployment_id != detail.deployment_id {
        return Err(ValidationError::new(
            "The model credential proposal belongs to another managed agent deployment.",
        ));
    }
    if proposal.state == crate::ManagedModelCredentialProposalState::Superseded {
        return Err(ValidationError::new(
            "The model credential proposal has been superseded and can no longer be applied.",
        ));
    }

    let apply_request = if proposal.requires_secret_resolution_result {
        if proposal.state == crate::ManagedModelCredentialProposalState::Applied {
            if let Some(request) = request {
                ensure_setup_bound_to_model_credential_proposal(request, proposal)?;
                if proposal.result_id != Some(request.result_id) {
                    return Err(ValidationError::new(
                        "The model credential proposal is bound to a different Seren Passwords result.",
                    ));
                }
            }
            return model_credential_proposal_already_applied(proposal);
        }
        let request = request.ok_or_else(|| {
            ValidationError::new(
                "The model credential proposal requires an approved Seren Passwords setup.",
            )
        })?;
        ensure_delegation_setup_applies(organization_id, detail, request)?;
        ensure_setup_bound_to_model_credential_proposal(request, proposal)?;
        if proposal
            .result_id
            .is_some_and(|result_id| result_id != request.result_id)
        {
            return Err(ValidationError::new(
                "The model credential proposal is bound to a different Seren Passwords result.",
            ));
        }
        let effective_mapping = managed_model_credential_effective_mapping(
            &proposal.requested_environment_names,
            request,
        )?;
        crate::ApplyModelCredentialProposalRequest {
            effective_mapping,
            secret_resolution_result_id: Some(request.result_id),
        }
    } else {
        if request.is_some()
            || !proposal.requested_environment_names.is_empty()
            || proposal.result_id.is_some()
            || proposal.approval_request_id.is_some()
        {
            return Err(ValidationError::new(
                "The model credential proposal has an inconsistent result contract.",
            ));
        }
        if proposal.state == crate::ManagedModelCredentialProposalState::Applied {
            return model_credential_proposal_already_applied(proposal);
        }
        crate::ApplyModelCredentialProposalRequest::default()
    };

    let active_revision_id = detail
        .active_revision_id
        .ok_or_else(|| ValidationError::new("The managed agent has no active revision to bind."))?;
    if proposal.expected_active_revision_id != active_revision_id {
        return Err(ValidationError::new(
            "The model credential proposal no longer targets the managed agent's active revision.",
        ));
    }

    Ok(ModelCredentialProposalApply::Apply {
        proposal_id: proposal.id,
        idempotency_key: proposal.id,
        request: Box::new(apply_request),
    })
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

    #[tokio::test]
    async fn managed_secrets_binding_resolves_each_original_apply_target() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let request =
            managed_secrets_policy_request(organization_id, deployment_id, uuid::Uuid::new_v4());
        let proposal_id = uuid::Uuid::new_v4();
        for target in [
            serde_json::json!({ "kind": "base_manifest" }),
            serde_json::json!({
                "kind": "connector",
                "connector_ref": "slack",
                "proposal_id": proposal_id,
            }),
            serde_json::json!({ "kind": "model", "proposal_id": proposal_id }),
            serde_json::json!({ "kind": "publisher", "proposal_id": proposal_id }),
        ] {
            let proxy = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!(
                    "/organizations/{organization_id}/managed-agent-secrets/setups/{}",
                    request.request_id,
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "setup_id": request.request_id,
                        "deployment_id": deployment_id,
                        "target": target,
                    },
                })))
                .expect(1)
                .mount(&proxy)
                .await;
            let client = crate::Client::new(&proxy.uri());
            let resolved = managed_secrets_apply_target(&client, request.request_id, &request)
                .await
                .expect("the original setup binding selects the apply route");
            assert_eq!(serde_json::to_value(resolved).unwrap(), target);
            assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn managed_secrets_binding_rejects_missing_or_inconsistent_authority() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let request =
            managed_secrets_policy_request(organization_id, deployment_id, uuid::Uuid::new_v4());
        let valid = serde_json::json!({
            "data": {
                "setup_id": request.request_id,
                "deployment_id": deployment_id,
                "target": { "kind": "base_manifest" },
            },
        });
        let mut wrong_setup = valid.clone();
        wrong_setup["data"]["setup_id"] = serde_json::json!(uuid::Uuid::new_v4());
        let mut wrong_deployment = valid.clone();
        wrong_deployment["data"]["deployment_id"] = serde_json::json!(uuid::Uuid::new_v4());
        let mut unknown_target = valid.clone();
        unknown_target["data"]["target"] = serde_json::json!({ "kind": "unknown" });
        let mut missing_target = valid.clone();
        missing_target["data"]
            .as_object_mut()
            .unwrap()
            .remove("target");
        let mut missing_kind = valid;
        missing_kind["data"]["target"] = serde_json::json!({});
        for response in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_json(wrong_setup),
            ResponseTemplate::new(200).set_body_json(wrong_deployment),
            ResponseTemplate::new(200).set_body_json(unknown_target),
            ResponseTemplate::new(200).set_body_json(missing_target),
            ResponseTemplate::new(200).set_body_json(missing_kind),
        ] {
            let proxy = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(format!(
                    "/organizations/{organization_id}/managed-agent-secrets/setups/{}",
                    request.request_id,
                )))
                .respond_with(response)
                .expect(1)
                .mount(&proxy)
                .await;
            let client = crate::Client::new(&proxy.uri());
            assert!(
                managed_secrets_apply_target(&client, request.request_id, &request)
                    .await
                    .is_err()
            );
            assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn managed_secrets_binding_rejects_unselected_or_unbound_setups_before_lookup() {
        let proxy = wiremock::MockServer::start().await;
        let client = crate::Client::new(&proxy.uri());
        let mut request = managed_secrets_policy_request(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(
            managed_secrets_apply_target(&client, uuid::Uuid::new_v4(), &request)
                .await
                .is_err()
        );
        request.deployment_id = None;
        assert!(
            managed_secrets_apply_target(&client, request.request_id, &request)
                .await
                .is_err()
        );
        assert!(proxy.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn generic_passwords_application_rejects_proposal_targets() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let proposal_id = uuid::Uuid::new_v4();
        for target in [
            ManagedSecretsApplyTarget::Connector {
                connector_ref: "slack".to_string(),
                proposal_id,
            },
            ManagedSecretsApplyTarget::Model { proposal_id },
            ManagedSecretsApplyTarget::Publisher { proposal_id },
        ] {
            assert!(
                managed_agent_secrets_application(&target, organization_id, &detail, &request)
                    .is_err()
            );
        }
    }

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
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let mut request =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        request
            .requested_fields
            .push(crate::DelegationRequestedField {
                environment_name: "USERNAME".to_string(),
                field_group: None,
            });

        let error = managed_agent_secrets_application(&target, organization_id, &detail, &request)
            .expect_err("partial mapping must be rejected");
        assert!(error.0.contains("exact requested fields"));
    }

    #[test]
    fn managed_agent_secrets_application_uses_the_status_specific_deadline() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let mut request =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        request.expires_at = "2020-01-01T00:00:00Z".parse().unwrap();
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_err()
        );

        request.status = crate::DelegationPolicyRequestStatus::Applied;
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_ok()
        );

        request.grant_expires_at = Some("2021-01-01T00:00:00Z".parse().unwrap());
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_err()
        );
    }

    #[test]
    fn managed_agent_secrets_application_binds_the_approved_revision_and_mapping() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        let ManagedAgentSecretsApplication::Update(update) =
            managed_agent_secrets_application(&target, organization_id, &detail, &request).unwrap()
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
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let request =
            managed_secrets_policy_request(organization_id, deployment_id, uuid::Uuid::new_v4());
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_err()
        );

        detail.secret_resolution_result_id = Some(request.result_id);
        detail.agent_identity_id = Some(request.agent_identity_id);
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_err()
        );
    }

    #[test]
    fn managed_agent_secrets_application_recognizes_an_exact_applied_binding() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let mut detail = managed_detail(deployment_id, revision_id);
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let ManagedAgentSecretsApplication::Update(update) =
            managed_agent_secrets_application(&target, organization_id, &detail, &request).unwrap()
        else {
            panic!("approved setup must produce an update");
        };
        detail.credentials = update.credentials.unwrap();
        detail.agent_identity_id = Some(request.agent_identity_id);
        detail.secret_resolution_result_id = Some(request.result_id);
        detail.active_revision_id = Some(uuid::Uuid::new_v4());

        assert!(matches!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request),
            Ok(ManagedAgentSecretsApplication::AlreadyApplied)
        ));
    }

    #[test]
    fn managed_agent_secrets_application_rejects_wrong_org_and_identity() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let mut detail = managed_detail(deployment_id, revision_id);
        let target = ManagedSecretsApplyTarget::BaseManifest;
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        assert!(
            managed_agent_secrets_application(&target, uuid::Uuid::new_v4(), &detail, &request)
                .is_err()
        );
        detail.agent_identity_id = Some(uuid::Uuid::new_v4());
        assert!(
            managed_agent_secrets_application(&target, organization_id, &detail, &request).is_err()
        );
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

    /// Mirrors the Seren Cloud deployment detail response, which omits
    /// `managed_agent` and `active_revision_id` rather than sending nulls.
    fn cloud_deployment_summary(
        managed_publisher: Option<&str>,
        active_revision_id: Option<uuid::Uuid>,
    ) -> crate::CloudDeploymentSummary {
        let mut data = serde_json::json!({
            "id": uuid::Uuid::from_u128(0x9001),
            "organization_id": uuid::Uuid::from_u128(1),
            "user_id": uuid::Uuid::from_u128(2),
            "name": "Lifecycle Route",
            "skill_slug": "lifecycle-route",
            "code_bundle_hash": "bundle-sha",
            "compute_backend": "aws_container",
            "control_generation": 15,
            "created_at": "2026-08-28T12:00:00Z",
            "desired_egress_state": "muted",
            "desired_lifecycle_state": "stopped",
            "mode": "always_on",
            "orchestration_mode": "llm",
            "requirements": {},
            "runtime_kind": "python",
            "status": "stopped",
            "updated_at": "2026-08-28T12:00:00Z",
            "visibility": "open"
        });
        let object = data.as_object_mut().expect("object body");
        if let Some(publisher) = managed_publisher {
            object.insert(
                "managed_agent".to_string(),
                serde_json::json!({
                    "publisher": publisher,
                    "template": "research_monitor",
                    "target_framework": "codex",
                    "runtime_adapter": "seren_agent",
                    "build_target": "python",
                    "tool_presets": [],
                    "allowed_publisher_operations": [],
                    "resolved_tools": [],
                    "approval_policy": "read_only",
                    "model_policy": "balanced",
                    "routing_reason": "route selection fixture"
                }),
            );
        }
        if let Some(revision_id) = active_revision_id {
            object.insert(
                "active_revision_id".to_string(),
                serde_json::json!(revision_id),
            );
        }
        serde_json::from_value(data).expect("deployment summary fixture")
    }

    #[test]
    fn managed_seren_agent_deployments_select_the_seren_agent_route() {
        // Seren Cloud omits active_revision_id from the deployment detail, so the
        // managed-agent publisher has to carry the classification on its own.
        let deployment = cloud_deployment_summary(Some("seren-agent"), None);
        assert_eq!(
            cloud_deployment_lifecycle_route(&deployment).expect("managed route"),
            CloudDeploymentLifecycleRoute::SerenAgent
        );
    }

    #[test]
    fn deployments_without_managed_metadata_select_the_seren_cloud_route() {
        let deployment = cloud_deployment_summary(None, None);
        assert_eq!(
            cloud_deployment_lifecycle_route(&deployment).expect("generic route"),
            CloudDeploymentLifecycleRoute::SerenCloud
        );
    }

    #[test]
    fn unknown_managed_publishers_have_no_lifecycle_route() {
        let deployment = cloud_deployment_summary(Some("another-publisher"), None);
        assert!(matches!(
            cloud_deployment_lifecycle_route(&deployment),
            Err(CloudDeploymentLifecycleError::UnsupportedManagedPublisher { publisher })
                if publisher == "another-publisher"
        ));
    }

    #[test]
    fn managed_revisions_without_managed_metadata_have_no_lifecycle_route() {
        let deployment = cloud_deployment_summary(None, Some(uuid::Uuid::from_u128(3)));
        assert!(matches!(
            cloud_deployment_lifecycle_route(&deployment),
            Err(CloudDeploymentLifecycleError::AmbiguousDeploymentType)
        ));
    }

    fn publisher_proposal(
        deployment_id: uuid::Uuid,
        expected_active_revision_id: uuid::Uuid,
        state: &str,
    ) -> crate::ManagedPublisherCredentialProposal {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "deployment_id": deployment_id,
            "expected_active_revision_id": expected_active_revision_id,
            "proposal_fingerprint": "fp",
            "requirements_fingerprint": "rfp",
            "requested_environment_names": ["PASSWORD"],
            "requires_secret_resolution_result": true,
            "changes": [],
            "state": state,
        }))
        .unwrap()
    }

    #[test]
    fn ensure_single_managed_secrets_proposal_selector_rejects_multiple() {
        let one = Some(uuid::Uuid::new_v4());
        assert!(ensure_single_managed_secrets_proposal_selector(None, None, None).is_ok());
        assert!(ensure_single_managed_secrets_proposal_selector(one, None, None).is_ok());
        assert!(ensure_single_managed_secrets_proposal_selector(None, one, None).is_ok());
        assert!(ensure_single_managed_secrets_proposal_selector(None, None, one).is_ok());
        assert!(ensure_single_managed_secrets_proposal_selector(one, one, None).is_err());
        assert!(ensure_single_managed_secrets_proposal_selector(one, None, one).is_err());
        assert!(ensure_single_managed_secrets_proposal_selector(one, one, one).is_err());
    }

    #[test]
    fn publisher_credential_apply_binds_server_mapping_and_is_deterministic() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        proposal.approval_request_id = Some(request.request_id);

        let PublisherCredentialProposalApply::Apply {
            proposal_id,
            idempotency_key,
            request: apply,
        } = publisher_credential_proposal_apply(
            organization_id,
            &detail,
            Some(&request),
            &proposal,
            proposal.id,
        )
        .expect("awaiting-review proposal must produce an apply")
        else {
            panic!("awaiting-review proposal must produce an apply");
        };

        assert_eq!(proposal_id, proposal.id);
        assert_eq!(apply.secret_resolution_result_id, Some(request.result_id));
        assert_eq!(apply.effective_mapping.len(), 1);
        let entry = &apply.effective_mapping[0];
        assert_eq!(entry.environment_name, "PASSWORD");
        assert_eq!(entry.ref_uri, secrets_ref("password"));
        assert_eq!(idempotency_key, proposal.id);
    }

    #[test]
    fn publisher_credential_apply_rejects_a_proposal_other_than_the_selected_one() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        proposal.approval_request_id = Some(request.request_id);

        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &proposal,
                uuid::Uuid::new_v4(),
            )
            .is_err()
        );
    }

    #[test]
    fn publisher_credential_apply_is_idempotent_when_already_applied() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = publisher_proposal(deployment_id, revision_id, "applied");
        let applied = uuid::Uuid::new_v4();
        proposal.applied_revision_id = Some(applied);
        proposal.result_id = Some(request.result_id);
        proposal.approval_request_id = Some(request.request_id);

        for setup in [Some(&request), None] {
            match publisher_credential_proposal_apply(
                organization_id,
                &detail,
                setup,
                &proposal,
                proposal.id,
            )
            .expect("applied proposal resolves without error")
            {
                PublisherCredentialProposalApply::AlreadyApplied {
                    applied_revision_id,
                    result_id,
                } => {
                    assert_eq!(applied_revision_id, applied);
                    assert_eq!(result_id, Some(request.result_id));
                }
                PublisherCredentialProposalApply::Apply { .. } => {
                    panic!("an applied proposal must not mutate again")
                }
            }
        }

        let mut other_result =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        other_result.request_id = request.request_id;
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&other_result),
                &proposal,
                proposal.id,
            )
            .is_err()
        );

        let mut other_setup =
            managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        other_setup.result_id = request.result_id;
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&other_setup),
                &proposal,
                proposal.id,
            )
            .is_err()
        );
    }

    #[test]
    fn publisher_credential_apply_supports_proposals_without_secret_resolution() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let mut proposal = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        proposal.requires_secret_resolution_result = false;
        proposal.requested_environment_names.clear();

        let PublisherCredentialProposalApply::Apply {
            idempotency_key,
            request,
            ..
        } = publisher_credential_proposal_apply(
            organization_id,
            &detail,
            None,
            &proposal,
            proposal.id,
        )
        .expect("a removal proposal needs no Secrets setup")
        else {
            panic!("an awaiting-review proposal must produce an apply");
        };
        assert!(request.effective_mapping.is_empty());
        assert!(request.secret_resolution_result_id.is_none());
        assert_eq!(idempotency_key, proposal.id);

        let stray = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&stray),
                &proposal,
                proposal.id,
            )
            .is_err()
        );

        let applied_revision_id = uuid::Uuid::new_v4();
        let mut applied = proposal.clone();
        applied.state = crate::ManagedPublisherCredentialProposalState::Applied;
        applied.applied_revision_id = Some(applied_revision_id);
        assert_eq!(
            publisher_credential_proposal_applied_revision(&proposal, &request, &applied)
                .expect("matching response"),
            applied_revision_id
        );
        match publisher_credential_proposal_apply(
            organization_id,
            &detail,
            None,
            &applied,
            applied.id,
        )
        .expect("an applied removal proposal resolves without error")
        {
            PublisherCredentialProposalApply::AlreadyApplied {
                applied_revision_id: reported,
                result_id,
            } => {
                assert_eq!(reported, applied_revision_id);
                assert!(result_id.is_none());
            }
            PublisherCredentialProposalApply::Apply { .. } => {
                panic!("an applied proposal must not mutate again")
            }
        }
    }

    #[test]
    fn publisher_credential_apply_fails_closed() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        let superseded = publisher_proposal(deployment_id, revision_id, "superseded");
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &superseded,
                superseded.id,
            )
            .is_err()
        );

        let mut stale = publisher_proposal(deployment_id, uuid::Uuid::new_v4(), "awaiting_review");
        stale.approval_request_id = Some(request.request_id);
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &stale,
                stale.id,
            )
            .is_err()
        );

        let mut wrong_revision_request =
            managed_secrets_policy_request(organization_id, deployment_id, uuid::Uuid::new_v4());
        wrong_revision_request.effective_mapping = request.effective_mapping.clone();
        wrong_revision_request.requested_fields = request.requested_fields.clone();
        let mut proposal = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        proposal.approval_request_id = Some(wrong_revision_request.request_id);
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&wrong_revision_request),
                &proposal,
                proposal.id,
            )
            .is_err()
        );

        let mut mismatched = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        mismatched.result_id = Some(uuid::Uuid::new_v4());
        mismatched.approval_request_id = Some(request.request_id);
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &mismatched,
                mismatched.id,
            )
            .is_err()
        );

        let other = publisher_proposal(uuid::Uuid::new_v4(), revision_id, "awaiting_review");
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &other,
                other.id,
            )
            .is_err()
        );

        let mut extra = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        extra.approval_request_id = Some(request.request_id);
        extra
            .requested_environment_names
            .push("USERNAME".to_string());
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &extra,
                extra.id,
            )
            .is_err()
        );

        let mut unbound = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        unbound.approval_request_id = Some(request.request_id);
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                None,
                &unbound,
                unbound.id,
            )
            .is_err()
        );

        let proposal = publisher_proposal(deployment_id, revision_id, "awaiting_review");
        assert!(
            publisher_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &proposal,
                proposal.id,
            )
            .is_err()
        );
    }

    fn connector_proposal(
        deployment_id: uuid::Uuid,
        expected_active_revision_id: uuid::Uuid,
        state: &str,
    ) -> crate::ManagedConnectorBindingProposal {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "deployment_id": deployment_id,
            "connector_ref": "slack",
            "expected_active_revision_id": expected_active_revision_id,
            "proposal_fingerprint": "fp",
            "requirements_fingerprint": "rfp",
            "requested_environment_names": ["PASSWORD"],
            "state": state,
        }))
        .unwrap()
    }

    #[test]
    fn connector_binding_apply_binds_setup_result_and_is_deterministic() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = connector_proposal(deployment_id, revision_id, "approved");
        proposal.approval_request_id = Some(request.request_id);

        let ConnectorBindingProposalApply::Apply {
            connector_ref,
            proposal_id,
            idempotency_key,
            request: apply,
        } = connector_binding_proposal_apply(
            organization_id,
            &detail,
            Some(&request),
            &proposal,
            proposal.id,
            "slack",
        )
        .expect("approved connector proposal must produce an apply")
        else {
            panic!("approved connector proposal must produce an apply");
        };

        assert_eq!(connector_ref, "slack");
        assert_eq!(proposal_id, proposal.id);
        assert_eq!(idempotency_key, proposal.id);
        assert_eq!(apply.secret_resolution_result_id, request.result_id);
    }

    #[test]
    fn connector_binding_apply_rejects_another_connector() {
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let proposal = connector_proposal(deployment_id, revision_id, "applying");
        let error = connector_binding_proposal_apply(
            uuid::Uuid::new_v4(),
            &detail,
            None,
            &proposal,
            proposal.id,
            "discord",
        )
        .expect_err("the selected connector must match before apply or replay");
        assert!(error.to_string().contains("connector selected for apply"));
    }

    #[test]
    fn connector_binding_apply_requires_a_setup() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let proposal = connector_proposal(deployment_id, revision_id, "approved");

        assert!(
            connector_binding_proposal_apply(
                organization_id,
                &detail,
                None,
                &proposal,
                proposal.id,
                "slack",
            )
            .is_err()
        );
    }

    #[test]
    fn connector_binding_apply_rejects_unbound_or_superseded_proposals() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        // A setup not bound to this proposal is refused.
        let unbound = connector_proposal(deployment_id, revision_id, "approved");
        assert!(
            connector_binding_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &unbound,
                unbound.id,
                "slack",
            )
            .is_err()
        );

        // A superseded proposal can no longer be applied.
        let mut superseded = connector_proposal(deployment_id, revision_id, "superseded");
        superseded.approval_request_id = Some(request.request_id);
        assert!(
            connector_binding_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &superseded,
                superseded.id,
                "slack",
            )
            .is_err()
        );

        // The selected proposal_id must match the fetched proposal.
        let proposal = connector_proposal(deployment_id, revision_id, "approved");
        assert!(
            connector_binding_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &proposal,
                uuid::Uuid::new_v4(),
                "slack",
            )
            .is_err()
        );
    }

    #[test]
    fn connector_binding_apply_is_idempotent_once_the_rollout_started() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let applied = uuid::Uuid::new_v4();

        for state in ["applying", "rolling", "ingress_ready"] {
            let mut proposal = connector_proposal(deployment_id, revision_id, state);
            proposal.applied_revision_id = Some(applied);
            proposal.result_id = Some(request.result_id);
            proposal.approval_request_id = Some(request.request_id);

            for setup in [Some(&request), None] {
                match connector_binding_proposal_apply(
                    organization_id,
                    &detail,
                    setup,
                    &proposal,
                    proposal.id,
                    "slack",
                )
                .expect("a started connector rollout resolves without error")
                {
                    ConnectorBindingProposalApply::AlreadyApplied {
                        applied_revision_id,
                        result_id,
                    } => {
                        assert_eq!(applied_revision_id, applied);
                        assert_eq!(result_id, Some(request.result_id));
                    }
                    ConnectorBindingProposalApply::Apply { .. } => {
                        panic!("a started connector rollout must not mutate again")
                    }
                }
            }

            let mut other_result =
                managed_secrets_policy_request(organization_id, deployment_id, revision_id);
            other_result.request_id = request.request_id;
            assert!(
                connector_binding_proposal_apply(
                    organization_id,
                    &detail,
                    Some(&other_result),
                    &proposal,
                    proposal.id,
                    "slack",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn connector_binding_apply_rejects_failed_and_unstarted_rollouts() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        // A failed rollout keeps its revision but is never reported as applied.
        let mut failed = connector_proposal(deployment_id, revision_id, "failed");
        failed.applied_revision_id = Some(uuid::Uuid::new_v4());
        failed.result_id = Some(request.result_id);
        failed.approval_request_id = Some(request.request_id);
        for setup in [Some(&request), None] {
            assert!(
                connector_binding_proposal_apply(
                    organization_id,
                    &detail,
                    setup,
                    &failed,
                    failed.id,
                    "slack",
                )
                .is_err()
            );
        }

        // A revision recorded before the rollout state is an inconsistent record.
        let mut unstarted = connector_proposal(deployment_id, revision_id, "approved");
        unstarted.applied_revision_id = Some(uuid::Uuid::new_v4());
        unstarted.approval_request_id = Some(request.request_id);
        assert!(
            connector_binding_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &unstarted,
                unstarted.id,
                "slack",
            )
            .is_err()
        );
    }

    #[test]
    fn connector_binding_applied_revision_requires_a_rollout_state() {
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let setup_id = uuid::Uuid::new_v4();
        let result_id = uuid::Uuid::new_v4();
        let applied_revision_id = uuid::Uuid::new_v4();
        let mut reviewed = connector_proposal(deployment_id, revision_id, "approved");
        reviewed.approval_request_id = Some(setup_id);
        let request = crate::ApplyConnectorBindingProposalRequest {
            secret_resolution_result_id: result_id,
        };

        let mut applied = reviewed.clone();
        applied.state = crate::ManagedConnectorBindingProposalState::Applying;
        applied.applied_revision_id = Some(applied_revision_id);
        applied.result_id = Some(result_id);
        assert_eq!(
            connector_binding_proposal_applied_revision(&reviewed, &request, &applied)
                .expect("a started rollout names its revision"),
            applied_revision_id
        );

        let mut failed = applied.clone();
        failed.state = crate::ManagedConnectorBindingProposalState::Failed;
        assert!(connector_binding_proposal_applied_revision(&reviewed, &request, &failed).is_err());

        let mut unstarted = applied.clone();
        unstarted.state = crate::ManagedConnectorBindingProposalState::Approved;
        assert!(
            connector_binding_proposal_applied_revision(&reviewed, &request, &unstarted).is_err()
        );

        let mut other_setup = applied.clone();
        other_setup.approval_request_id = Some(uuid::Uuid::new_v4());
        assert!(
            connector_binding_proposal_applied_revision(&reviewed, &request, &other_setup).is_err()
        );

        let mut other_result = applied.clone();
        other_result.result_id = Some(uuid::Uuid::new_v4());
        assert!(
            connector_binding_proposal_applied_revision(&reviewed, &request, &other_result)
                .is_err()
        );

        let mut no_revision = applied;
        no_revision.applied_revision_id = None;
        assert!(
            connector_binding_proposal_applied_revision(&reviewed, &request, &no_revision).is_err()
        );
    }
    fn model_proposal(
        deployment_id: uuid::Uuid,
        expected_active_revision_id: uuid::Uuid,
        state: &str,
        auth_method: &str,
        requires_secret: bool,
    ) -> crate::ManagedModelCredentialProposal {
        serde_json::from_value(serde_json::json!({
            "id": uuid::Uuid::new_v4(),
            "deployment_id": deployment_id,
            "model_id": "openai/gpt-5",
            "operation": "configure",
            "auth_method": auth_method,
            "expected_active_revision_id": expected_active_revision_id,
            "proposal_fingerprint": "fp",
            "requirements_fingerprint": "rfp",
            "requested_environment_names": if requires_secret { vec!["PASSWORD"] } else { Vec::<&str>::new() },
            "requires_secret_resolution_result": requires_secret,
            "state": state,
        }))
        .unwrap()
    }

    #[test]
    fn model_credential_apply_binds_server_mapping_for_api_key_auth() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = model_proposal(
            deployment_id,
            revision_id,
            "awaiting_review",
            "api_key",
            true,
        );
        proposal.approval_request_id = Some(request.request_id);

        let ModelCredentialProposalApply::Apply {
            proposal_id,
            idempotency_key,
            request: apply,
        } = model_credential_proposal_apply(
            organization_id,
            &detail,
            Some(&request),
            &proposal,
            proposal.id,
        )
        .expect("api-key model proposal must produce an apply")
        else {
            panic!("api-key model proposal must produce an apply");
        };

        assert_eq!(proposal_id, proposal.id);
        assert_eq!(idempotency_key, proposal.id);
        assert_eq!(apply.secret_resolution_result_id, Some(request.result_id));
        assert_eq!(apply.effective_mapping.len(), 1);
        assert_eq!(apply.effective_mapping[0].environment_name, "PASSWORD");
        assert_eq!(apply.effective_mapping[0].ref_uri, secrets_ref("password"));
    }

    #[test]
    fn model_credential_apply_omits_secret_for_chatgpt_subscription_auth() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let proposal = model_proposal(
            deployment_id,
            revision_id,
            "awaiting_review",
            "chatgpt_subscription",
            false,
        );

        let ModelCredentialProposalApply::Apply { request: apply, .. } =
            model_credential_proposal_apply(organization_id, &detail, None, &proposal, proposal.id)
                .expect("chatgpt-subscription model proposal applies without a Secrets result")
        else {
            panic!("chatgpt-subscription model proposal must produce an apply");
        };

        assert!(apply.secret_resolution_result_id.is_none());
        assert!(apply.effective_mapping.is_empty());
    }

    #[test]
    fn model_credential_apply_requires_a_setup_for_api_key_auth() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let proposal = model_proposal(
            deployment_id,
            revision_id,
            "awaiting_review",
            "api_key",
            true,
        );

        assert!(
            model_credential_proposal_apply(organization_id, &detail, None, &proposal, proposal.id)
                .is_err()
        );
    }

    #[test]
    fn model_credential_apply_rejects_unbound_selected_or_superseded_proposals() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);

        // Setup not bound to this proposal.
        let unbound = model_proposal(
            deployment_id,
            revision_id,
            "awaiting_review",
            "api_key",
            true,
        );
        assert!(
            model_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &unbound,
                unbound.id,
            )
            .is_err()
        );

        // Superseded proposal.
        let mut superseded =
            model_proposal(deployment_id, revision_id, "superseded", "api_key", true);
        superseded.approval_request_id = Some(request.request_id);
        assert!(
            model_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &superseded,
                superseded.id,
            )
            .is_err()
        );

        // Wrong selected proposal_id.
        let proposal = model_proposal(
            deployment_id,
            revision_id,
            "awaiting_review",
            "api_key",
            true,
        );
        assert!(
            model_credential_proposal_apply(
                organization_id,
                &detail,
                Some(&request),
                &proposal,
                uuid::Uuid::new_v4(),
            )
            .is_err()
        );
    }

    #[test]
    fn model_credential_apply_is_idempotent_when_already_applied() {
        let organization_id = uuid::Uuid::new_v4();
        let deployment_id = uuid::Uuid::new_v4();
        let revision_id = uuid::Uuid::new_v4();
        let detail = managed_detail(deployment_id, revision_id);
        let request = managed_secrets_policy_request(organization_id, deployment_id, revision_id);
        let mut proposal = model_proposal(deployment_id, revision_id, "applied", "api_key", true);
        let applied = uuid::Uuid::new_v4();
        proposal.applied_revision_id = Some(applied);
        proposal.result_id = Some(request.result_id);
        proposal.approval_request_id = Some(request.request_id);

        for setup in [Some(&request), None] {
            match model_credential_proposal_apply(
                organization_id,
                &detail,
                setup,
                &proposal,
                proposal.id,
            )
            .expect("applied model proposal resolves without error")
            {
                ModelCredentialProposalApply::AlreadyApplied {
                    applied_revision_id,
                    result_id,
                } => {
                    assert_eq!(applied_revision_id, applied);
                    assert_eq!(result_id, Some(request.result_id));
                }
                ModelCredentialProposalApply::Apply { .. } => {
                    panic!("an applied model proposal must not mutate again")
                }
            }
        }
    }
}
