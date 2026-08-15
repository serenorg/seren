// ABOUTME: Previews and executes explicit, audited Seren Memory workspace merges.
// ABOUTME: Execution requires the state-bound plan hash returned by a fresh preview.

use anyhow::Result;

use crate::commands::memory_gateway::memory_gateway_data;
use crate::{CommandContext, output};

pub async fn preview(
    source_workspace_key: String,
    target_workspace_key: String,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_preview_workspace_merge(&seren::SerenMemoryPreviewWorkspaceMergeRequest {
            source_workspace_key,
            target_workspace_key,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to preview Seren Memory workspace merge")?;
    output::print_json(&response)?;
    Ok(())
}

pub async fn merge(
    source_workspace_key: String,
    target_workspace_key: String,
    plan_hash: String,
    ctx: &CommandContext,
) -> Result<()> {
    let result = ctx
        .client()
        .await?
        .seren_memory_execute_workspace_merge(&seren::SerenMemoryExecuteWorkspaceMergeRequest {
            plan_hash,
            source_workspace_key,
            target_workspace_key,
        })
        .await;
    let response = memory_gateway_data(result, "Failed to execute Seren Memory workspace merge")?;
    output::print_json(&response)?;
    Ok(())
}
