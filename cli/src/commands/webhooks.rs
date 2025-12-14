use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateWebhookRequest, UpdateWebhookRequest};

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
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let webhooks = client
        .webhooks(org_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list webhooks: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&webhooks)?,
        OutputFormat::Table => output::print_webhooks_table(&webhooks),
    }

    Ok(())
}

pub async fn get(
    org_id: &str,
    webhook_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let webhook = client
        .webhooks(org_id)
        .get(webhook_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get webhook: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => output::print_webhooks_table(&[webhook]),
    }

    Ok(())
}

pub async fn create(
    org_id: &str,
    url: &str,
    event_types: Vec<String>,
    is_active: bool,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = CreateWebhookRequest {
        url: url.to_string(),
        event_types,
        is_active: Some(is_active),
    };

    let webhook = client
        .webhooks(org_id)
        .create(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create webhook: {}", e))?;

    println!("{}", "Webhook created successfully!".green().bold());
    println!();
    println!(
        "{}",
        "IMPORTANT: Save the webhook secret below. It will not be shown again!"
            .yellow()
            .bold()
    );
    println!("Secret: {}", webhook.secret.cyan());
    println!();

    match format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => {
            // Print basic info without the secret (already shown above)
            println!("Webhook ID: {}", webhook.id);
            println!("URL: {}", webhook.url);
            println!("Events: {}", webhook.event_types.join(", "));
            println!("Active: {}", webhook.is_active);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn update(
    org_id: &str,
    webhook_id: &str,
    url: Option<String>,
    event_types: Option<Vec<String>>,
    is_active: Option<bool>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = UpdateWebhookRequest {
        url,
        event_types,
        is_active,
    };

    let webhook = client
        .webhooks(org_id)
        .update(webhook_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update webhook: {}", e))?;

    println!("{}", "Webhook updated successfully!".green().bold());
    println!();

    match format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => output::print_webhooks_table(&[webhook]),
    }

    Ok(())
}

pub async fn delete(
    org_id: &str,
    webhook_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    client
        .webhooks(org_id)
        .delete(webhook_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete webhook: {}", e))?;

    println!(
        "{}",
        format!("Webhook {} deleted successfully!", webhook_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn rotate_secret(
    org_id: &str,
    webhook_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let webhook = client
        .webhooks(org_id)
        .rotate_secret(webhook_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rotate webhook secret: {}", e))?;

    println!("{}", "Webhook secret rotated successfully!".green().bold());
    println!();
    println!(
        "{}",
        "IMPORTANT: Save the new webhook secret below. It will not be shown again!"
            .yellow()
            .bold()
    );
    println!("New Secret: {}", webhook.secret.cyan());

    match format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => {}
    }

    Ok(())
}

pub async fn list_deliveries(
    org_id: &str,
    webhook_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let deliveries = client
        .webhooks(org_id)
        .list_deliveries(webhook_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list webhook deliveries: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&deliveries)?,
        OutputFormat::Table => output::print_webhook_deliveries_table(&deliveries),
    }

    Ok(())
}

pub async fn list_event_types(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let event_types = client
        .webhooks("")
        .list_event_types()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list event types: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&event_types)?,
        OutputFormat::Table => {
            println!("{}", "Available Webhook Event Types:".bold());
            for event_type in &event_types {
                println!("  - {}", event_type);
            }
        }
    }

    Ok(())
}
