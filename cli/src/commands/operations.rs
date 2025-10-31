use anyhow::Result;
use seren::{Client, ClientConfig};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key)?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(
    project_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let operations = client
        .operations(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list operations: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&operations)?,
        OutputFormat::Table => output::print_operations_table(&operations),
    }

    Ok(())
}

pub async fn get(
    project_id: &str,
    operation_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let operation = client
        .operations(project_id)
        .get(operation_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get operation: {}", e))?;

    output::print_operation(&operation, format)?;

    Ok(())
}
