use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateProjectRequest, UpdateProjectRequest};

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
    region: &str,
    block_public_connections: Option<bool>,
    block_vpc_connections: Option<bool>,
    hipaa: Option<bool>,
    protected_branches_only: Option<bool>,
    compute_unit_min: Option<i32>,
    compute_unit_max: Option<i32>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    let request = CreateProjectRequest {
        name: name.to_string(),
        region: region.to_string(),
        block_public_connections,
        block_vpc_connections,
        hipaa,
        protected_branches_only,
        compute_unit_min,
        compute_unit_max,
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

pub async fn update(
    id: &str,
    name: Option<&str>,
    block_public_connections: Option<bool>,
    block_vpc_connections: Option<bool>,
    hipaa: Option<bool>,
    protected_branches_only: Option<bool>,
    compute_unit_min: Option<i32>,
    compute_unit_max: Option<i32>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    if name.is_none()
        && block_public_connections.is_none()
        && block_vpc_connections.is_none()
        && hipaa.is_none()
        && protected_branches_only.is_none()
        && compute_unit_min.is_none()
        && compute_unit_max.is_none()
    {
        anyhow::bail!("Provide at least one field to update");
    }

    let request = UpdateProjectRequest {
        name: name.map(|value| value.to_string()),
        block_public_connections,
        block_vpc_connections,
        hipaa,
        protected_branches_only,
        compute_unit_min,
        compute_unit_max,
    };

    let project = client
        .projects()
        .update(id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update project: {}", e))?;

    println!("{}", "✓ Project updated successfully!".green().bold());
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

    println!(
        "{}",
        format!("✓ Project {} deleted successfully!", id)
            .green()
            .bold()
    );

    Ok(())
}
