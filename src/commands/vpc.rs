use anyhow::Result;
use colored::Colorize;
use seren::{
    AssignProjectVpcEndpointRequest, Client, ClientConfig, CreateOrganizationVpcEndpointRequest,
};

use crate::{config::Config, output, OutputFormat};

fn get_client(api_host: Option<String>) -> Result<Client> {
    let config = Config::load()?;

    let mut client_config = ClientConfig::new(config.api_key);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn endpoint_list(
    org_id: &str,
    region: Option<String>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    let endpoints = client
        .organization_vpc_endpoints(org_id)
        .list(region.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list VPC endpoints: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&endpoints)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&endpoints),
    }

    Ok(())
}

pub async fn endpoint_create(
    org_id: &str,
    region: &str,
    endpoint_id: &str,
    label: Option<String>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    let request = CreateOrganizationVpcEndpointRequest {
        region: region.to_string(),
        endpoint_id: endpoint_id.to_string(),
        label,
    };

    let endpoint = client
        .organization_vpc_endpoints(org_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to register VPC endpoint: {}", e))?;

    println!("{}", "✓ VPC endpoint registered".green().bold());
    println!();
    match format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint]),
    }

    Ok(())
}

pub async fn endpoint_get(
    org_id: &str,
    endpoint_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    let endpoint = client
        .organization_vpc_endpoints(org_id)
        .get(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch VPC endpoint: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint]),
    }

    Ok(())
}

pub async fn endpoint_remove(
    org_id: &str,
    endpoint_id: &str,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    client
        .organization_vpc_endpoints(org_id)
        .delete(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete VPC endpoint: {}", e))?;

    println!(
        "{}",
        format!("✓ VPC endpoint {} removed", endpoint_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn project_list(
    project_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    let assignments = client
        .project_vpc_endpoints(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list project VPC endpoints: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&assignments)?,
        OutputFormat::Table => output::print_project_vpc_endpoints_table(&assignments),
    }

    Ok(())
}

pub async fn project_assign(
    project_id: &str,
    vpc_endpoint_id: &str,
    label: Option<String>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    let request = AssignProjectVpcEndpointRequest {
        vpc_endpoint_id: vpc_endpoint_id.to_string(),
        label,
    };

    let assignment = client
        .project_vpc_endpoints(project_id)
        .assign(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to assign VPC endpoint: {}", e))?;

    println!("{}", "✓ VPC endpoint assigned to project".green().bold());
    println!();
    match format {
        OutputFormat::Json => output::print_json(&assignment)?,
        OutputFormat::Table => output::print_project_vpc_endpoints_table(&[assignment]),
    }

    Ok(())
}

pub async fn project_remove(
    project_id: &str,
    assignment_id: &str,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;

    client
        .project_vpc_endpoints(project_id)
        .remove(assignment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove project VPC endpoint: {}", e))?;

    println!(
        "{}",
        format!("✓ Removed VPC endpoint assignment {}", assignment_id)
            .green()
            .bold()
    );

    Ok(())
}
