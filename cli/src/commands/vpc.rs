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
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_org_vpc_endpoints(&org_uuid, region.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list VPC endpoints: {}", e))?;

    let endpoints = response.into_inner();
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
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let request = CreateOrganizationVpcEndpointRequest {
        region: region.to_string(),
        endpoint_id: endpoint_id.to_string(),
        label,
    };

    let response = client
        .create_org_vpc_endpoint(&org_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to register VPC endpoint: {}", e))?;

    let endpoint = response.into_inner();
    println!("{}", "VPC endpoint registered".green().bold());
    println!();
    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint.data]),
    }

    Ok(())
}

pub async fn endpoint_get(org_id: &str, endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    let response = client
        .get_org_vpc_endpoint(&org_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch VPC endpoint: {}", e))?;

    let endpoint = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_org_vpc_endpoints_table(&[endpoint.data]),
    }

    Ok(())
}

pub async fn endpoint_remove(org_id: &str, endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    client
        .delete_org_vpc_endpoint(&org_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete VPC endpoint: {}", e))?;

    println!(
        "{}",
        format!("VPC endpoint {} removed", endpoint_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn project_list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .seren_db_list_project_vpc_endpoints(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list project VPC endpoints: {}", e))?;

    let assignments = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&assignments)?,
        OutputFormat::Table => output::print_project_vpc_endpoints_table(&assignments.data),
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let request = AssignProjectVpcEndpointRequest {
        vpc_endpoint_id: Uuid::parse_str(vpc_endpoint_id)
            .map_err(|e| anyhow::anyhow!("Invalid VPC endpoint ID: {}", e))?,
        label,
    };

    let response = client
        .seren_db_assign_project_vpc_endpoint(&project_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to assign VPC endpoint: {}", e))?;

    let assignment = response.into_inner();
    println!("{}", "VPC endpoint assigned to project".green().bold());
    println!();
    match ctx.format {
        OutputFormat::Json => output::print_json(&assignment)?,
        OutputFormat::Table => {
            // Wrap single assignment in an array for the table printer
            let arr = serde_json::Value::Array(vec![assignment.data]);
            output::print_project_vpc_endpoints_table(&arr);
        }
    }

    Ok(())
}

pub async fn project_remove(
    project_id: &str,
    assignment_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let assignment_uuid = Uuid::parse_str(assignment_id)
        .map_err(|e| anyhow::anyhow!("Invalid assignment ID: {}", e))?;

    client
        .seren_db_remove_project_vpc_endpoint(&project_uuid, &assignment_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove project VPC endpoint: {}", e))?;

    println!(
        "{}",
        format!("Removed VPC endpoint assignment {}", assignment_id)
            .green()
            .bold()
    );

    Ok(())
}
