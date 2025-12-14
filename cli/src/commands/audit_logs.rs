use anyhow::Result;
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
    org_id: &str,
    limit: Option<i32>,
    offset: Option<i32>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let response = client
        .audit_logs(org_id)
        .list(limit, offset)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list audit logs: {}", e))?;

    match format {
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

pub async fn get(
    org_id: &str,
    log_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let log = client
        .audit_logs(org_id)
        .get(log_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get audit log: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&log)?,
        OutputFormat::Table => output::print_audit_logs_table(&[log]),
    }

    Ok(())
}
