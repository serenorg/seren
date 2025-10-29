use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateProjectRequest};

use crate::{config::Config, output, OutputFormat};

fn get_client(api_host: Option<String>) -> Result<Client> {
    let config = Config::load()?;
    
    let mut client_config = ClientConfig::new(config.api_key);
    
    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }
    
    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    let projects = client
        .projects()
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list projects: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&projects)?,
        OutputFormat::Table => output::print_projects_table(&projects),
    }

    Ok(())
}

pub async fn get(id: &str, format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    let project = client
        .projects()
        .get(id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get project: {}", e))?;

    output::print_project(&project, format)?;

    Ok(())
}

pub async fn create(
    name: &str,
    org_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let request = CreateProjectRequest {
        name: name.to_string(),
        organization_id: org_id.to_string(),
    };

    let project = client
        .projects()
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create project: {}", e))?;

    println!("{}", "✓ Project created successfully!".green().bold());
    println!();
    output::print_project(&project, format)?;

    Ok(())
}

pub async fn delete(id: &str, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    client
        .projects()
        .delete(id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete project: {}", e))?;

    println!("{}", format!("✓ Project {} deleted successfully!", id).green().bold());

    Ok(())
}
