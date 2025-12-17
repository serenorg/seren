use anyhow::Result;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(
    org_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_audit_logs(
            &org_uuid, None,   // action
            None,   // action_category
            None,   // actor_id
            None,   // end_date
            limit,  // limit
            offset, // offset
            None,   // resource_id
            None,   // resource_type
            None,   // start_date
            None,   // status
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list audit logs: {}", e))?;

    let audit_logs = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&audit_logs)?,
        OutputFormat::Table => {
            output::print_audit_logs_table(&audit_logs.data.data);
            println!();
            if let Some(pagination) = &audit_logs.pagination {
                println!(
                    "Showing {} logs (offset: {})",
                    audit_logs.data.data.len(),
                    pagination.offset
                );
            } else {
                println!("Showing {} logs", audit_logs.data.data.len());
            }
        }
    }

    Ok(())
}

pub async fn get(org_id: &str, log_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let log_uuid =
        Uuid::parse_str(log_id).map_err(|e| anyhow::anyhow!("Invalid audit log ID: {}", e))?;

    let response = client
        .get_audit_log(&org_uuid, &log_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get audit log: {}", e))?;

    let log = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&log)?,
        OutputFormat::Table => output::print_audit_logs_table(&[log.data]),
    }

    Ok(())
}
