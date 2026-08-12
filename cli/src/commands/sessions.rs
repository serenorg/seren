use anyhow::{Context, Result};
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
        format!("Refresh session {} revoked successfully!", session_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn revoke_others(keep_session_id: Option<&str>, ctx: &CommandContext) -> Result<()> {
    // Resolve the client first: an expired access token is refreshed here, and
    // that rotation is what writes the current refresh-session ID to disk.
    let client = ctx.client().await?;
    let session_uuid = match keep_session_id {
        Some(keep_session_id) => Uuid::parse_str(keep_session_id)
            .map_err(|e| anyhow::anyhow!("Invalid session ID: {}", e))?,
        // The stored session ID describes the stored OAuth credential, so it
        // only identifies "the current session" when that credential is the one
        // authenticating this request.
        None if ctx.api_key.is_some() => anyhow::bail!(
            "Pass the session ID to keep: an explicit API key does not identify a refresh session.",
        ),
        None => crate::config::Config::load()
            .ok()
            .and_then(|config| config.session_id)
            .context(
                "No current OAuth refresh-session ID is stored. Sign in again with 'seren auth login', or pass the session ID to keep as an argument.",
            )?,
    };

    let response = client
        .revoke_other_sessions(&session_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to revoke other sessions: {}", e))?;

    let result = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Revoked {} other refresh session(s). Existing access tokens remain valid until they expire.",
                result.data.revoked_count
            )
            .green()
            .bold()
        ),
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
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => println!(
            "{}",
            format!(
                "Revoked {} refresh session(s). Existing access tokens remain valid until they expire.",
                result.data.revoked_count
            )
            .green()
            .bold()
        ),
    }

    Ok(())
}
