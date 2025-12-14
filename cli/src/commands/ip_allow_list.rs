use anyhow::Result;
use colored::Colorize;
use seren::{AddIpAllowListRequest, ResetIpAllowListEntry, ResetIpAllowListRequest};

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let ips = client
        .ip_allow(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list IP allow list: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&ips)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&ips),
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

    let mut request = AddIpAllowListRequest {
        ip_address: ip_address.to_string(),
        description: None,
    };
    if let Some(desc) = description {
        request.description = Some(desc);
    }

    let ip = client
        .ip_allow(project_id)
        .add(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add IP to allow list: {}", e))?;

    println!("{}", "✓ IP address added to allow list!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&ip)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&[ip]),
    }

    Ok(())
}

pub async fn remove(project_id: &str, ip_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    client
        .ip_allow(project_id)
        .remove(ip_id)
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

    let entries: Vec<ResetIpAllowListEntry> = ips
        .iter()
        .map(|ip| ResetIpAllowListEntry {
            ip_address: ip.to_string(),
            description: None,
        })
        .collect();

    let request = ResetIpAllowListRequest { entries };

    let updated = client
        .ip_allow(project_id)
        .reset(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reset IP allow list: {}", e))?;

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
        OutputFormat::Table => output::print_ip_allow_list_table(&updated),
    }

    Ok(())
}
