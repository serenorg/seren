use anyhow::{Context, Result};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use uuid::Uuid;

use crate::commands::memory_gateway::memory_gateway_data;
use crate::{CommandContext, OutputFormat, output};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum KnowledgePrincipalType {
    User,
    Agent,
}

impl KnowledgePrincipalType {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
        }
    }
}

pub struct RecallOptions {
    pub query: String,
    pub created_after: Option<jiff::Timestamp>,
    pub created_before: Option<jiff::Timestamp>,
    pub limit: Option<i64>,
    pub memory_types: Vec<String>,
    pub min_relevance: Option<f64>,
    pub search_mode: Option<String>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
}

pub struct RememberOptions {
    pub content: String,
    pub memory_type: String,
    pub importance: Option<i32>,
    pub lifecycle_status: Option<String>,
    pub metadata: Option<String>,
    pub pin: Option<bool>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
}

pub struct ListOptions {
    pub memory_type: Option<String>,
    pub lifecycle_status: Option<String>,
    pub is_pinned: Option<bool>,
    pub is_consolidated: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
}

pub struct ProcessOptions {
    pub transcript: String,
    pub project_context: Option<String>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub retain_source: bool,
    pub source_external_id: Option<String>,
    pub source_revision: Option<String>,
    pub source_uri: Option<String>,
}

pub struct DeleteBySourceOptions {
    pub source_external_id: Option<String>,
    pub source_uri: Option<String>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
}

pub struct LearnFromErrorOptions {
    pub error_content: String,
    pub fix_content: String,
    pub metadata: Option<String>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
}

pub struct CaptureOptions {
    pub user_prompt: Option<String>,
    pub assistant_response: Option<String>,
    pub project_context: Option<String>,
    pub project_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub retain_source: bool,
    pub source_external_id: String,
    pub source_revision: Option<String>,
    pub source_uri: Option<String>,
    pub agent_platform: String,
    pub external_session_id: Option<String>,
    pub external_parent_session_id: Option<String>,
    pub external_turn_id: Option<String>,
    pub workspace_key: Option<String>,
    pub workspace_uri: Option<String>,
    pub source_metadata: Option<String>,
    pub observed_at: Option<jiff::Timestamp>,
    pub policy_version: String,
}

pub async fn health(detailed: bool, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let result = if detailed {
        client.seren_memory_health_detailed().await
    } else {
        client.seren_memory_health().await
    };
    let response = memory_gateway_data(result, "Failed to get Seren Memory health")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let mut table = table_with_header(["Server", "Status"]);
            table.add_row([response.data.server, response.data.status]);
            println!("{table}");
        }
    }
    Ok(())
}

pub async fn bootstrap(
    project_id: Option<Uuid>,
    org_id: Option<Uuid>,
    token_budget: Option<u64>,
    include_git: Option<bool>,
    include_time: Option<bool>,
    reviewed_only: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_session_bootstrap(&seren::SerenMemorySessionBootstrapParams {
            include_git,
            include_time,
            org_id,
            project_id,
            reviewed_only: Some(reviewed_only),
            token_budget,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to bootstrap Seren Memory")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn recall(options: RecallOptions, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_recall(&seren::SerenMemoryRecallParams {
            created_after: options.created_after,
            created_before: options.created_before,
            limit: options.limit,
            memory_types: (!options.memory_types.is_empty()).then_some(options.memory_types),
            min_relevance: options.min_relevance,
            org_id: options.org_id,
            project_id: options.project_id,
            query: options.query,
            search_mode: options.search_mode,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to recall Seren Memory")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let mut table = table_with_header(["ID", "Type", "Relevance", "Lifecycle"]);
            for memory in response.data.memories {
                table.add_row([
                    memory.id.to_string(),
                    memory.memory_type,
                    format!("{:.3}", memory.relevance_score),
                    memory.lifecycle_status.to_string(),
                ]);
            }
            println!("{table}");
        }
    }
    Ok(())
}

pub async fn search(options: RecallOptions, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_search_memories(&seren::SerenMemoryRecallParams {
            created_after: options.created_after,
            created_before: options.created_before,
            limit: options.limit,
            memory_types: (!options.memory_types.is_empty()).then_some(options.memory_types),
            min_relevance: options.min_relevance,
            org_id: options.org_id,
            project_id: options.project_id,
            query: options.query,
            search_mode: options.search_mode,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to search Seren Memory")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn remember(options: RememberOptions, ctx: &CommandContext) -> Result<()> {
    let lifecycle_status = options
        .lifecycle_status
        .as_deref()
        .map(parse_lifecycle)
        .transpose()?;
    let metadata = options
        .metadata
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .context("Memory metadata must be valid JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_remember(&seren::SerenMemoryRememberParams {
            content: options.content,
            importance: options.importance,
            lifecycle_status,
            memory_type: options.memory_type,
            metadata,
            org_id: options.org_id,
            pin: options.pin,
            project_id: options.project_id,
            session_id: options.session_id,
            skip_conflict_check: None,
            skip_enrichment: None,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to remember Seren Memory")?;

    output::print_json(&response)?;
    Ok(())
}

pub async fn process(options: ProcessOptions, ctx: &CommandContext) -> Result<()> {
    if options.retain_source && options.source_external_id.is_none() {
        anyhow::bail!("--source-external-id is required with --retain-source");
    }
    let retain_source = options.retain_source || options.source_external_id.is_some();
    let result = ctx
        .client()
        .await?
        .seren_memory_process_conversation(&seren::SerenMemoryProcessConversationParams {
            org_id: options.org_id,
            project_context: options.project_context,
            project_id: options.project_id,
            retain_source: Some(retain_source),
            session_id: options.session_id,
            source_external_id: options.source_external_id,
            source_revision: options.source_revision,
            source_uri: options.source_uri,
            transcript: options.transcript,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to process Seren Memory conversation")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn capture(options: CaptureOptions, ctx: &CommandContext) -> Result<()> {
    let source_metadata = options
        .source_metadata
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("--source-metadata must be valid JSON: {error}"))?;
    let params = seren::SerenMemoryCaptureAgentTurnParams {
        agent_platform: options.agent_platform,
        assistant_response: options.assistant_response,
        external_parent_session_id: options.external_parent_session_id,
        external_session_id: options.external_session_id,
        external_turn_id: options.external_turn_id,
        observed_at: options.observed_at,
        org_id: options.org_id,
        policy_version: options.policy_version,
        project_context: options.project_context,
        project_id: options.project_id,
        retain_source: Some(options.retain_source),
        session_id: options.session_id,
        source_external_id: options.source_external_id,
        source_metadata,
        source_revision: options.source_revision,
        source_uri: options.source_uri,
        user_prompt: options.user_prompt,
        workspace_key: options.workspace_key,
        workspace_uri: options.workspace_uri,
    };
    let response = memory_gateway_data(
        ctx.client()
            .await?
            .seren_memory_capture_agent_turn(&params)
            .await,
        "Failed to capture Seren Memory agent turn",
    )?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn list(options: ListOptions, ctx: &CommandContext) -> Result<()> {
    let lifecycle_status = options
        .lifecycle_status
        .as_deref()
        .map(parse_lifecycle)
        .transpose()?;
    let result = ctx
        .client()
        .await?
        .seren_memory_list_memories(
            None,
            options.is_consolidated,
            options.is_pinned,
            lifecycle_status,
            options.limit,
            options.memory_type.as_deref(),
            options.offset,
            options.org_id.as_ref(),
            options.project_id.as_ref(),
        )
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory entries")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let mut table = table_with_header(["ID", "Type", "Lifecycle", "Importance"]);
            for memory in response.data.memories {
                table.add_row([
                    memory.id.to_string(),
                    memory.memory_type,
                    memory.lifecycle_status.to_string(),
                    memory.importance.to_string(),
                ]);
            }
            println!("{table}");
        }
    }
    Ok(())
}

pub async fn export(
    project_id: Option<Uuid>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_export_memories(limit, offset, project_id.as_ref())
        .await;
    let response = memory_gateway_data(result, "Failed to export Seren Memory")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn get(id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx.client().await?.seren_memory_get_memory(&id).await;
    let response = memory_gateway_data(result, "Failed to get Seren Memory entry")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn get_many(ids: Vec<Uuid>, ctx: &CommandContext) -> Result<()> {
    if ids.is_empty() {
        anyhow::bail!("At least one memory ID is required");
    }
    if ids.len() > 25 {
        anyhow::bail!("At most 25 memory IDs may be requested");
    }
    let ids = ids
        .into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let result = ctx
        .client()
        .await?
        .seren_memory_list_memories(
            Some(ids.as_str()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;
    let response = memory_gateway_data(result, "Failed to get Seren Memory entries")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn learn_from_error(options: LearnFromErrorOptions, ctx: &CommandContext) -> Result<()> {
    let metadata = options
        .metadata
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .context("Memory metadata must be valid JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_learn_from_error(&seren::SerenMemoryLearnFromErrorParams {
            error_content: options.error_content,
            fix_content: options.fix_content,
            metadata,
            org_id: options.org_id,
            project_id: options.project_id,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to store Seren Memory error and fix")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn ingest_document(body: String, ctx: &CommandContext) -> Result<()> {
    let request: seren::SerenMemoryIngestDocumentRequest =
        serde_json::from_str(&body).context("Document body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_ingest_document(&request)
        .await;
    let response = memory_gateway_data(result, "Failed to ingest Seren Memory document")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn append(id: Uuid, content: String, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_append_memory(&id, &seren::SerenMemoryAppendMemoryRequest { content })
        .await;
    let response = memory_gateway_data(result, "Failed to append Seren Memory entry")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn revisions(id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_list_memory_revisions(&id)
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory revisions")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn set_status(id: Uuid, lifecycle_status: String, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_set_memory_status(
            &id,
            &seren::SerenMemorySetMemoryStatusRequest {
                lifecycle_status: parse_lifecycle(&lifecycle_status)?,
            },
        )
        .await;
    let response = memory_gateway_data(result, "Failed to set Seren Memory lifecycle status")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn set_review(id: Uuid, review_status: String, ctx: &CommandContext) -> Result<()> {
    let review_status = serde_json::from_value(serde_json::Value::String(review_status.clone()))
        .with_context(|| {
            format!("Invalid review status '{review_status}'. Use unreviewed or reviewed.")
        })?;
    let result = ctx
        .client()
        .await?
        .seren_memory_set_memory_review(
            &id,
            &seren::SerenMemorySetMemoryReviewRequest { review_status },
        )
        .await;
    let response = memory_gateway_data(result, "Failed to set Seren Memory review status")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn sync_status(ctx: &CommandContext) -> Result<()> {
    let result = ctx.client().await?.seren_memory_sync_status().await;
    let response = memory_gateway_data(result, "Failed to get Seren Memory sync status")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn consolidate(project_id: Option<Uuid>, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_consolidate_job(&seren::SerenMemoryConsolidateJobRequest { project_id })
        .await;
    let response = memory_gateway_data(result, "Failed to consolidate Seren Memory")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn reconcile(max_pairs: i64, ctx: &CommandContext) -> Result<()> {
    if !(1..=20).contains(&max_pairs) {
        anyhow::bail!("--max-pairs must be between 1 and 20");
    }
    let result = ctx
        .client()
        .await?
        .seren_memory_reconcile_job(&seren::SerenMemoryReconcileJobRequest {
            max_pairs: Some(max_pairs),
        })
        .await;
    let response = memory_gateway_data(result, "Failed to reconcile Seren Memory")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn timeline(
    id: Uuid,
    as_of: Option<jiff::Timestamp>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_memory_timeline(&id, as_of.as_ref())
        .await;
    let response = memory_gateway_data(result, "Failed to get Seren Memory timeline")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn link(
    source_id: Uuid,
    target_id: Uuid,
    edge_type: String,
    valid_from: Option<jiff::Timestamp>,
    valid_to: Option<jiff::Timestamp>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_link_memories(&seren::SerenMemoryMemoryConnectionRequest {
            edge_type,
            source_id,
            target_id,
            valid_from,
            valid_to,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to connect Seren Memory entries")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn unlink(
    source_id: Uuid,
    target_id: Uuid,
    edge_type: String,
    valid_from: Option<jiff::Timestamp>,
    valid_to: Option<jiff::Timestamp>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_unlink_memories(&seren::SerenMemoryMemoryConnectionRequest {
            edge_type,
            source_id,
            target_id,
            valid_from,
            valid_to,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to disconnect Seren Memory entries")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn forget(id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_forget_memory(&seren::SerenMemoryForgetParams { memory_id: id })
        .await;
    let response = memory_gateway_data(result, "Failed to forget Seren Memory entry")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn delete(id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx.client().await?.seren_memory_delete_memory(&id).await;
    let response = memory_gateway_data(result, "Failed to delete Seren Memory entry")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn delete_by_source(options: DeleteBySourceOptions, ctx: &CommandContext) -> Result<()> {
    let has_external_id = options
        .source_external_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_source_uri = options
        .source_uri
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_external_id && !has_source_uri {
        anyhow::bail!("At least one of --source-external-id or --source-uri is required");
    }

    let result = ctx
        .client()
        .await?
        .seren_memory_delete_memories_by_source(&seren::SerenMemoryDeleteMemoriesBySourceParams {
            org_id: options.org_id,
            project_id: options.project_id,
            source_external_id: options.source_external_id,
            source_uri: options.source_uri,
        })
        .await;
    let response = memory_gateway_data(
        result,
        "Failed to delete Seren Memory sources and derived memories",
    )?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn list_knowledge_domains(ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_list_knowledge_domains()
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory knowledge domains")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn search_knowledge(
    query: String,
    domain_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_search_knowledge(&seren::SerenMemorySearchKnowledgeRequest {
            domain_id,
            query,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to search Seren Memory knowledge")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn open_knowledge_entity(
    entity_id: String,
    domain_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_open_knowledge_entity(&seren::SerenMemoryOpenKnowledgeEntityRequest {
            domain_id,
            entity_id,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to open Seren Memory knowledge entity")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn list_knowledge_operations(
    domain_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_list_knowledge_operations(domain_id.as_ref())
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory knowledge operations")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn invoke_knowledge_operation(
    operation_name: String,
    domain_id: Option<Uuid>,
    parameters: String,
    ctx: &CommandContext,
) -> Result<()> {
    let parameters: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&parameters)
        .context("Knowledge operation parameters must be a valid JSON object")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_invoke_knowledge_operation(
            &operation_name,
            &seren::SerenMemoryInvokeKnowledgeOperationRequest {
                domain_id,
                parameters: serde_json::Value::Object(parameters),
            },
        )
        .await;
    let response =
        memory_gateway_data(result, "Failed to invoke Seren Memory knowledge operation")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn create_knowledge_domain(body: String, ctx: &CommandContext) -> Result<()> {
    let request: seren::SerenMemoryCreateKnowledgeDomainRequest = serde_json::from_str(&body)
        .context("Knowledge domain body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_create_knowledge_domain(&request)
        .await;
    let response = memory_gateway_data(result, "Failed to create Seren Memory knowledge domain")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn update_knowledge_domain(
    domain_id: Uuid,
    body: String,
    ctx: &CommandContext,
) -> Result<()> {
    let request: seren::SerenMemoryUpdateKnowledgeDomainRequest = serde_json::from_str(&body)
        .context("Knowledge domain body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_put_knowledge_domain(&domain_id, &request)
        .await;
    let response = memory_gateway_data(result, "Failed to update Seren Memory knowledge domain")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn list_knowledge_grants(domain_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_list_knowledge_domain_grants(&domain_id)
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory knowledge grants")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn put_knowledge_grant(
    domain_id: Uuid,
    body: String,
    ctx: &CommandContext,
) -> Result<()> {
    let request: seren::SerenMemoryKnowledgeDomainGrantRequest = serde_json::from_str(&body)
        .context("Knowledge grant body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_put_knowledge_domain_grant(&domain_id, &request)
        .await;
    let response = memory_gateway_data(result, "Failed to set Seren Memory knowledge grant")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn delete_knowledge_grant(
    domain_id: Uuid,
    principal_type: KnowledgePrincipalType,
    principal_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_delete_knowledge_domain_grant(
            &domain_id,
            principal_type.as_str(),
            &principal_id,
        )
        .await;
    let response = memory_gateway_data(result, "Failed to delete Seren Memory knowledge grant")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn get_knowledge_model(domain_id: Option<Uuid>, ctx: &CommandContext) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_get_knowledge_model(domain_id.as_ref())
        .await;
    let response = memory_gateway_data(result, "Failed to get Seren Memory knowledge model")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn put_knowledge_model(
    domain_id: Option<Uuid>,
    body: String,
    ctx: &CommandContext,
) -> Result<()> {
    let request: seren::SerenMemoryKnowledgeModel = serde_json::from_str(&body)
        .context("Knowledge model body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_put_knowledge_model(domain_id.as_ref(), &request)
        .await;
    let response = memory_gateway_data(result, "Failed to set Seren Memory knowledge model")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn list_knowledge_records(
    domain_id: Option<Uuid>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_list_knowledge_records(domain_id.as_ref(), limit, offset)
        .await;
    let response = memory_gateway_data(result, "Failed to list Seren Memory knowledge records")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn put_knowledge_record(
    record_key: String,
    domain_id: Option<Uuid>,
    body: String,
    ctx: &CommandContext,
) -> Result<()> {
    let request: seren::SerenMemoryUpsertKnowledgeRecordRequest = serde_json::from_str(&body)
        .context("Knowledge record body must be valid Seren Memory JSON")?;
    let result = ctx
        .client()
        .await?
        .seren_memory_put_knowledge_record(&record_key, domain_id.as_ref(), &request)
        .await;
    let response = memory_gateway_data(result, "Failed to set Seren Memory knowledge record")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn delete_knowledge_record(
    record_key: String,
    domain_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_delete_knowledge_record(&record_key, domain_id.as_ref())
        .await;
    let response = memory_gateway_data(result, "Failed to delete Seren Memory knowledge record")?;
    output::print_json(&response)?;
    Ok(())
}

fn parse_lifecycle(value: &str) -> Result<seren::SerenMemoryMemoryLifecycle> {
    serde_json::from_value(serde_json::Value::String(value.to_string())).with_context(|| {
        format!("Invalid lifecycle status '{value}'. Use active, draft, canonical, or deprecated.")
    })
}

fn table_with_header<const N: usize>(header: [&str; N]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header.map(|label| Cell::new(label).fg(Color::Cyan)));
    table
}
