use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig};

use crate::{OutputFormat, commands::auth::get_bearer_token, output};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let sessions = client
        .sessions()
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list sessions: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&sessions)?,
        OutputFormat::Table => output::print_sessions_table(&sessions),
    }

    Ok(())
}

pub async fn revoke(
    session_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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

pub async fn revoke_others(
    keep_session_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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

    match format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {}
    }

    Ok(())
}

pub async fn revoke_all(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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

    match format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {}
    }

    Ok(())
}
