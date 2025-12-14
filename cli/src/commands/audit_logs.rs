use anyhow::Result;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(
    org_id: &str,
    limit: Option<i32>,
    offset: Option<i32>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .audit_logs(org_id)
        .list(limit, offset)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list audit logs: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            output::print_audit_logs_table(&response.logs);
            println!();
            println!(
                "Showing {} of {} total logs (offset: {})",
                response.logs.len(),
                response.total,
                response.offset
            );
        }
    }

    Ok(())
}

pub async fn get(org_id: &str, log_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let log = client
        .audit_logs(org_id)
        .get(log_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get audit log: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&log)?,
        OutputFormat::Table => output::print_audit_logs_table(&[log]),
    }

    Ok(())
}
