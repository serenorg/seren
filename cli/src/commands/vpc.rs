use anyhow::Result;
use colored::Colorize;
use seren::{AssignProjectVpcEndpointRequest, CreateOrganizationVpcEndpointRequest};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn endpoint_list(
    org_id: &str,
    region: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let endpoints = client
        .organization_vpc_endpoints(org_id)
        .list(region.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list VPC endpoints: {}", e))?;

    match ctx.format {
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
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

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
    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint]),
    }

    Ok(())
}

pub async fn endpoint_get(org_id: &str, endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let endpoint = client
        .organization_vpc_endpoints(org_id)
        .get(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch VPC endpoint: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint]),
    }

    Ok(())
}

pub async fn endpoint_remove(org_id: &str, endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

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

pub async fn project_list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let assignments = client
        .project_vpc_endpoints(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list project VPC endpoints: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&assignments)?,
        OutputFormat::Table => output::print_project_vpc_endpoints_table(&assignments),
    }

    Ok(())
}

pub async fn project_assign(
    project_id: &str,
    vpc_endpoint_id: &str,
    label: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = AssignProjectVpcEndpointRequest {
        vpc_endpoint_id: Uuid::parse_str(vpc_endpoint_id)
            .map_err(|e| anyhow::anyhow!("Invalid VPC endpoint ID: {}", e))?,
        label,
    };

    let assignment = client
        .project_vpc_endpoints(project_id)
        .assign(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to assign VPC endpoint: {}", e))?;

    println!("{}", "✓ VPC endpoint assigned to project".green().bold());
    println!();
    match ctx.format {
        OutputFormat::Json => output::print_json(&assignment)?,
        OutputFormat::Table => output::print_project_vpc_endpoints_table(&[assignment]),
    }

    Ok(())
}

pub async fn project_remove(
    project_id: &str,
    assignment_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

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
