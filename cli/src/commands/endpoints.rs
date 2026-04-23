use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .seren_db_list_endpoints(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list endpoints: {}", e))?;

    let endpoints = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoints)?,
        OutputFormat::Table => output::print_endpoints_table(&endpoints.data),
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    compute_unit: Option<String>,
    autoscaling_min: Option<i32>,
    autoscaling_max: Option<i32>,
    suspend_timeout: Option<i32>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let mut request = seren::CreateEndpointRequest {
        name: Some(name.to_string()),
        compute_unit: compute_unit.clone(),
        autoscaling_min: None,
        autoscaling_max: None,
        pooler_enabled: None,
        pooler_mode: None,
        suspend_timeout_seconds: suspend_timeout,
        endpoint_type: Some(seren::EndpointType::ReadWrite),
    };

    match (autoscaling_min, autoscaling_max) {
        (Some(min), Some(max)) => {
            request.autoscaling_min = Some(min);
            request.autoscaling_max = Some(max);
        }
        (Some(min), None) => {
            request.autoscaling_min = Some(min);
            request.autoscaling_max = Some(min);
        }
        (None, Some(max)) => {
            request.autoscaling_min = Some(1);
            request.autoscaling_max = Some(max);
        }
        (None, None) => {}
    }

    let response = client
        .seren_db_create_endpoint(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create endpoint: {}", e))?;

    let endpoint = response.into_inner();
    println!("{}", "✓ Endpoint created successfully!".green().bold());

    match ctx.format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_create_endpoint_response(&endpoint.data, ctx.format)?,
    }

    Ok(())
}

pub async fn update(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    autoscaling_min: Option<i32>,
    autoscaling_max: Option<i32>,
    suspend_timeout: Option<i32>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    let mut request = seren::UpdateEndpointRequest {
        autoscaling_min: None,
        autoscaling_max: None,
        compute_unit: None,
        pooler_enabled: None,
        pooler_mode: None,
        suspend_timeout_seconds: None,
    };

    if let Some(min) = autoscaling_min {
        request.autoscaling_min = Some(min);
    }

    if let Some(max) = autoscaling_max {
        request.autoscaling_max = Some(max);
    }

    if let Some(timeout) = suspend_timeout {
        request.suspend_timeout_seconds = Some(timeout);
    }

    let response = client
        .seren_db_update_endpoint(&project_uuid, &branch_uuid, &endpoint_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update endpoint: {}", e))?;

    let endpoint = response.into_inner();
    println!("{}", "✓ Endpoint updated successfully!".green().bold());
    println!();
    output::print_endpoint(&endpoint.data, ctx.format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    client
        .seren_db_delete_endpoint(&project_uuid, &branch_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete endpoint: {}", e))?;

    println!(
        "{}",
        format!("✓ Endpoint {} deleted successfully!", endpoint_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn suspend(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    client
        .seren_db_stop_endpoint(&project_uuid, &branch_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to suspend endpoint: {}", e))?;

    println!("{}", "✓ Endpoint suspended successfully!".green().bold());

    Ok(())
}

pub async fn start(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    client
        .seren_db_start_endpoint(&project_uuid, &branch_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start endpoint: {}", e))?;

    println!("{}", "✓ Endpoint started successfully!".green().bold());

    Ok(())
}

pub async fn status(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    let response = client
        .seren_db_get_endpoint_status(&project_uuid, &branch_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get endpoint status: {}", e))?;

    let status_info = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&status_info)?,
        OutputFormat::Table => output::print_endpoint_status(&status_info.data),
    }

    Ok(())
}

pub async fn restart(project_id: &str, endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let endpoint_uuid =
        Uuid::parse_str(endpoint_id).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))?;

    let response = client
        .seren_db_restart_endpoint(&project_uuid, &endpoint_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to restart endpoint: {}", e))?;

    let status_info = response.into_inner();
    println!("{}", "✓ Endpoint restart initiated!".green().bold());

    match ctx.format {
        OutputFormat::Json => output::print_json(&status_info)?,
        OutputFormat::Table => output::print_endpoint_status(&status_info.data),
    }

    Ok(())
}
