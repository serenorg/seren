use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .list_ip_allow_list(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list IP allow list: {}", e))?;

    let ips = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&ips)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&ips.data),
    }

    Ok(())
}

pub async fn add(
    project_id: &str,
    ip_address: &str,
    description: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let request = seren::AddIpAllowListRequest {
        ip_address: ip_address.to_string(),
        description,
    };

    let response = client
        .add_ip_to_allow_list(&project_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add IP to allow list: {}", e))?;

    let ip = response.into_inner();
    println!("{}", "✓ IP address added to allow list!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&ip)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&[ip.data]),
    }

    Ok(())
}

pub async fn remove(project_id: &str, ip_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let ip_uuid = Uuid::parse_str(ip_id).map_err(|e| anyhow::anyhow!("Invalid IP ID: {}", e))?;

    client
        .remove_ip_from_allow_list(&project_uuid, &ip_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove IP from allow list: {}", e))?;

    println!(
        "{}",
        format!("✓ IP {} removed from allow list!", ip_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn reset(project_id: &str, ips: &[String], ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let entries: Vec<seren::ResetIpAllowListEntry> = ips
        .iter()
        .map(|ip| seren::ResetIpAllowListEntry {
            ip_address: ip.to_string(),
            description: None,
        })
        .collect();

    let request = seren::ResetIpAllowListRequest { entries };

    let response = client
        .reset_ip_allow_list(&project_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reset IP allow list: {}", e))?;

    let updated = response.into_inner();
    if ips.is_empty() {
        println!(
            "{}",
            "⚠ IP allow list cleared; all computes now accept connections."
                .yellow()
                .bold()
        );
    } else {
        println!("{}", "✓ IP allow list updated successfully!".green().bold());
    }
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&updated)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&updated.data),
    }

    Ok(())
}
