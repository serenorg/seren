use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_sessions()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list sessions: {}", e))?;

    let sessions = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&sessions)?,
        OutputFormat::Table => output::print_sessions_table(&sessions.data),
    }

    Ok(())
}

pub async fn revoke(session_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let session_uuid =
        Uuid::parse_str(session_id).map_err(|e| anyhow::anyhow!("Invalid session ID: {}", e))?;

    client
        .revoke_session(&session_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke session: {}", e))?;

    println!(
        "{}",
        format!("Session {} revoked successfully!", session_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn revoke_others(keep_session_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let session_uuid = Uuid::parse_str(keep_session_id)
        .map_err(|e| anyhow::anyhow!("Invalid session ID: {}", e))?;

    let response = client
        .revoke_other_sessions(&session_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke other sessions: {}", e))?;

    let result = response.into_inner();
    println!(
        "{}",
        format!("Revoked {} other session(s)!", result.data.revoked_count)
            .green()
            .bold()
    );

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {}
    }

    Ok(())
}

pub async fn revoke_all(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .revoke_all_sessions()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke all sessions: {}", e))?;

    let result = response.into_inner();
    println!(
        "{}",
        format!(
            "Revoked {} session(s)! You have been logged out everywhere.",
            result.data.revoked_count
        )
        .green()
        .bold()
    );

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {}
    }

    Ok(())
}
