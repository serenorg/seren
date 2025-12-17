use anyhow::Result;
use colored::Colorize;
use seren::{CreateWebhookRequest, UpdateWebhookRequest};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(org_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_webhooks(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list webhooks: {}", e))?;

    let webhooks = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&webhooks)?,
        OutputFormat::Table => output::print_webhooks_table(&webhooks.data),
    }

    Ok(())
}

pub async fn get(org_id: &str, webhook_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let webhook_uuid =
        Uuid::parse_str(webhook_id).map_err(|e| anyhow::anyhow!("Invalid webhook ID: {}", e))?;

    let response = client
        .get_webhook(&org_uuid, &webhook_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get webhook: {}", e))?;

    let webhook = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => output::print_webhooks_table(&[webhook]),
    }

    Ok(())
}

pub async fn create(
    org_id: &str,
    name: &str,
    url: &str,
    events: Vec<String>,
    project_id: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let project_uuid = project_id
        .map(|id| Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e)))
        .transpose()?;

    let request = CreateWebhookRequest {
        name: name.to_string(),
        url: url.to_string(),
        events,
        project_id: project_uuid,
    };

    let response = client
        .create_webhook(&org_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create webhook: {}", e))?;

    let created = response.into_inner();
    println!("{}", "Webhook created successfully!".green().bold());
    println!();
    println!(
        "{}",
        "IMPORTANT: Save the webhook secret below. It will not be shown again!"
            .yellow()
            .bold()
    );
    println!("Secret: {}", created.secret.cyan());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&created)?,
        OutputFormat::Table => {
            // Print basic info without the secret (already shown above)
            println!("Webhook ID: {}", created.webhook.id);
            println!("Name: {}", created.webhook.name);
            println!("URL: {}", created.webhook.url);
            println!("Events: {}", created.webhook.events.join(", "));
            println!("Enabled: {}", created.webhook.enabled);
        }
    }

    Ok(())
}

pub async fn update(
    org_id: &str,
    webhook_id: &str,
    name: Option<String>,
    url: Option<String>,
    events: Option<Vec<String>>,
    enabled: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let webhook_uuid =
        Uuid::parse_str(webhook_id).map_err(|e| anyhow::anyhow!("Invalid webhook ID: {}", e))?;

    let request = UpdateWebhookRequest {
        name,
        url,
        events,
        enabled,
    };

    let response = client
        .update_webhook(&org_uuid, &webhook_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update webhook: {}", e))?;

    let webhook = response.into_inner();
    println!("{}", "Webhook updated successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&webhook)?,
        OutputFormat::Table => output::print_webhooks_table(&[webhook]),
    }

    Ok(())
}

pub async fn delete(org_id: &str, webhook_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let webhook_uuid =
        Uuid::parse_str(webhook_id).map_err(|e| anyhow::anyhow!("Invalid webhook ID: {}", e))?;

    client
        .delete_webhook(&org_uuid, &webhook_uuid)
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

pub async fn rotate_secret(org_id: &str, webhook_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let webhook_uuid =
        Uuid::parse_str(webhook_id).map_err(|e| anyhow::anyhow!("Invalid webhook ID: {}", e))?;

    let response = client
        .rotate_webhook_secret(&org_uuid, &webhook_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rotate webhook secret: {}", e))?;

    let rotated = response.into_inner();
    println!("{}", "Webhook secret rotated successfully!".green().bold());
    println!();
    println!(
        "{}",
        "IMPORTANT: Save the new webhook secret below. It will not be shown again!"
            .yellow()
            .bold()
    );
    println!("New Secret: {}", rotated.secret.cyan());

    match ctx.format {
        OutputFormat::Json => output::print_json(&rotated)?,
        OutputFormat::Table => {}
    }

    Ok(())
}

pub async fn list_deliveries(org_id: &str, webhook_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let webhook_uuid =
        Uuid::parse_str(webhook_id).map_err(|e| anyhow::anyhow!("Invalid webhook ID: {}", e))?;

    let response = client
        .list_webhook_deliveries(&org_uuid, &webhook_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list webhook deliveries: {}", e))?;

    let deliveries = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&deliveries)?,
        OutputFormat::Table => output::print_webhook_deliveries_table(&deliveries),
    }

    Ok(())
}

pub async fn list_event_types(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_event_types()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list event types: {}", e))?;

    let event_types = response.into_inner();
    match ctx.format {
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
