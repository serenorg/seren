use anyhow::Result;
use colored::Colorize;
use seren::{AddIpAllowListRequest, Client, ClientConfig};

use crate::{config::Config, output, OutputFormat};

fn get_client(api_host: Option<String>) -> Result<Client> {
    let config = Config::load()?;
    
    let mut client_config = ClientConfig::new(config.api_key);
    
    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }
    
    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(
    project_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let ips = client
        .ip_allow_lists(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list IP allow list: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&ips)?,
        OutputFormat::Table => output::print_ip_allow_lists_table(&ips),
    }

    Ok(())
}

pub async fn add(
    project_id: &str,
    ip_address: &str,
    description: Option<String>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let mut request = AddIpAllowListRequest::new(ip_address);
    if let Some(desc) = description {
        request = request.with_description(desc);
    }
    
    let ip = client
        .ip_allow_lists(project_id)
        .add(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add IP to allow list: {}", e))?;

    println!("{}", "✓ IP address added to allow list!".green().bold());
    println!();
    
    match format {
        OutputFormat::Json => output::print_json(&ip)?,
        OutputFormat::Table => output::print_ip_allow_lists_table(&[ip]),
    }

    Ok(())
}

pub async fn remove(
    project_id: &str,
    ip_id: &str,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    client
        .ip_allow_lists(project_id)
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
