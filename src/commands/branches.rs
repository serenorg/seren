use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateBranchRequest, RenameBranchRequest};

use crate::{config::Config, output, OutputFormat};

fn get_client(api_host: Option<String>) -> Result<Client> {
    let config = Config::load()?;
    
    let mut client_config = ClientConfig::new(config.api_key);
    
    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }
    
    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(project_id: &str, format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    let branches = client
        .branches(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list branches: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&branches)?,
        OutputFormat::Table => output::print_branches_table(&branches),
    }

    Ok(())
}

pub async fn get(
    project_id: &str,
    branch_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let branch = client
        .branches(project_id)
        .get(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch: {}", e))?;

    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn create(
    project_id: &str,
    name: &str,
    parent: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let request = CreateBranchRequest {
        name: name.to_string(),
        parent_branch_id: parent.map(|s| s.to_string()),
    };

    let branch = client
        .branches(project_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create branch: {}", e))?;

    println!("{}", "✓ Branch created successfully!".green().bold());
    println!();
    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn delete(project_id: &str, branch_id: &str, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    client
        .branches(project_id)
        .delete(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete branch: {}", e))?;

    println!("{}", format!("✓ Branch {} deleted successfully!", branch_id).green().bold());

    Ok(())
}

pub async fn rename(
    project_id: &str,
    branch_id: &str,
    name: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let request = RenameBranchRequest {
        name: name.to_string(),
    };

    let branch = client
        .branches(project_id)
        .rename(branch_id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rename branch: {}", e))?;

    println!("{}", "✓ Branch renamed successfully!".green().bold());
    println!();
    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn set_default(project_id: &str, branch_id: &str, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;
    
    client
        .branches(project_id)
        .set_default(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set default branch: {}", e))?;

    println!("{}", format!("✓ Branch {} set as default successfully!", branch_id).green().bold());

    Ok(())
}

pub async fn connection_string(
    project_id: &str,
    branch_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let response = client
        .branches(project_id)
        .connection_string(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get connection string: {}", e))?;

    output::print_connection_string(&response, format)?;

    Ok(())
}
