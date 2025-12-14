use anyhow::Result;
use colored::Colorize;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let sessions = client
        .sessions()
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list sessions: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&sessions)?,
        OutputFormat::Table => output::print_sessions_table(&sessions),
    }

    Ok(())
}

pub async fn revoke(session_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    client
        .sessions()
        .revoke(session_id)
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

    let result = client
        .sessions()
        .revoke_others(keep_session_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke other sessions: {}", e))?;

    println!(
        "{}",
        format!("Revoked {} other session(s)!", result.revoked_count)
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

    let result = client
        .sessions()
        .revoke_all()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke all sessions: {}", e))?;

    println!(
        "{}",
        format!(
            "Revoked {} session(s)! You have been logged out everywhere.",
            result.revoked_count
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
