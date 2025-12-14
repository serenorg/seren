use anyhow::Result;
use seren::Client;
use tokio::time::{Duration, sleep};

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let operations = client
        .operations(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list operations: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&operations)?,
        OutputFormat::Table => output::print_operations_table(&operations),
    }

    Ok(())
}

pub async fn get(project_id: &str, operation_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let operation = client
        .operations(project_id)
        .get(operation_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get operation: {}", e))?;

    output::print_operation(&operation, ctx.format)?;

    Ok(())
}

/// Poll an operation until it reaches a terminal state.
#[allow(dead_code)]
pub async fn poll_operation(
    client: &Client,
    project_id: &str,
    operation_id: &str,
    timeout_secs: u64,
) -> Result<seren::Operation> {
    let start = std::time::Instant::now();

    loop {
        let op = client
            .operations(project_id)
            .get(operation_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get operation {operation_id}: {}", e))?;

        let status = op.status.to_lowercase();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return if status == "completed" {
                Ok(op)
            } else {
                Err(anyhow::anyhow!(
                    "Operation {operation_id} ended with status {}: {}",
                    op.status,
                    op.error_message.unwrap_or_default()
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
