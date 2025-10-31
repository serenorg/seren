use anyhow::Result;
use colored::Colorize;
use seren::{
    AddIpAllowListRequest, Client, ClientConfig, ResetIpAllowListEntry, ResetIpAllowListRequest,
};

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

    let ips = client
        .ip_allow(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list IP allow list: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&ips)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&ips),
    }

    Ok(())
}

pub async fn add(
    project_id: &str,
    ip_address: &str,
    description: Option<String>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

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

    match format {
        OutputFormat::Json => output::print_json(&ip)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&[ip]),
    }

    Ok(())
}

pub async fn remove(
    project_id: &str,
    ip_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

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

pub async fn reset(
    project_id: &str,
    ips: &[String],
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

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

    match format {
        OutputFormat::Json => output::print_json(&updated)?,
        OutputFormat::Table => output::print_ip_allow_list_table(&updated),
    }

    Ok(())
}
