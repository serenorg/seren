use anyhow::Result;
use seren::Client;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .seren_db_list_operations(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list operations: {}", e))?;

    let operations = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&operations)?,
        OutputFormat::Table => output::print_operations_table(&operations.data),
    }

    Ok(())
}

pub async fn get(project_id: &str, operation_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let operation_uuid = Uuid::parse_str(operation_id)
        .map_err(|e| anyhow::anyhow!("Invalid operation ID: {}", e))?;

    let response = client
        .seren_db_get_operation(&project_uuid, &operation_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get operation: {}", e))?;

    let operation = response.into_inner();
    output::print_operation(&operation.data, ctx.format)?;

    Ok(())
}

/// Poll an operation until it reaches a terminal state.
#[allow(dead_code)]
pub async fn poll_operation(
    client: &Client,
    project_id: &Uuid,
    operation_id: &Uuid,
    timeout_secs: u64,
) -> Result<serde_json::Value> {
    let start = std::time::Instant::now();

    loop {
        let response = client
            .seren_db_get_operation(project_id, operation_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get operation {operation_id}: {}", e))?;

        let op = response.into_inner().data;
        let status = op
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_lowercase();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return if status == "completed" {
                Ok(op)
            } else {
                let error_message = op
                    .get("error_message")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                Err(anyhow::anyhow!(
                    "Operation {operation_id} ended with status {}: {}",
                    status,
                    error_message
                ))
            };
        }

        if start.elapsed() > Duration::from_secs(timeout_secs) {
            return Err(anyhow::anyhow!(
                "Operation {operation_id} did not complete within {}s",
                timeout_secs
            ));
        }

        sleep(Duration::from_secs(2)).await;
    }
}
