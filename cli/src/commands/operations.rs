use anyhow::Result;
use seren::{Client, ClientConfig};
use tokio::time::{sleep, Duration};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

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
    let client = get_client(api_host, api_key).await?;

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
    let client = get_client(api_host, api_key).await?;

    let operation = client
        .operations(project_id)
        .get(operation_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get operation: {}", e))?;

    output::print_operation(&operation, format)?;

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
