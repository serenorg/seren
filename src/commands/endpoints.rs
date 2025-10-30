use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig};

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
    branch_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let endpoints = client
        .endpoints(project_id, branch_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list endpoints: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&endpoints)?,
        OutputFormat::Table => output::print_endpoints_table(&endpoints),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    compute_unit: Option<String>,
    autoscaling_min: Option<i32>,
    autoscaling_max: Option<i32>,
    suspend_timeout: Option<i32>,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let mut request = seren::CreateEndpointRequest::new(name);
    
    if let Some(unit) = compute_unit {
        request = request.with_compute_unit(unit);
    }
    
    if let Some(min) = autoscaling_min {
        let max = autoscaling_max.unwrap_or(min);
        request = request.with_autoscaling(min, max);
    } else if let Some(max) = autoscaling_max {
        request = request.with_autoscaling(1, max);
    }
    
    if let Some(timeout) = suspend_timeout {
        request.suspend_timeout_seconds = Some(timeout);
    }
    
    let endpoint = client
        .endpoints(project_id, branch_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create endpoint: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&endpoint)?,
        OutputFormat::Table => output::print_endpoint(&endpoint, format)?,
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
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let mut request = seren::UpdateEndpointRequest::new();
    
    if let Some(min) = autoscaling_min {
        request = request.autoscaling_min(min);
    }
    
    if let Some(max) = autoscaling_max {
        request = request.autoscaling_max(max);
    }
    
    if let Some(timeout) = suspend_timeout {
        request = request.suspend_timeout(timeout);
    }
    
    let endpoint = client
        .endpoints(project_id, branch_id)
        .update(endpoint_id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update endpoint: {}", e))?;

    println!("{}", "✓ Endpoint updated successfully!".green().bold());
    println!();
    output::print_endpoint(&endpoint, format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    client
        .endpoints(project_id, branch_id)
        .delete(endpoint_id)
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
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let endpoint = client
        .endpoints(project_id, branch_id)
        .suspend(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to suspend endpoint: {}", e))?;

    println!("{}", "✓ Endpoint suspended successfully!".green().bold());
    println!();
    output::print_endpoint(&endpoint, format)?;

    Ok(())
}

pub async fn start(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let endpoint = client
        .endpoints(project_id, branch_id)
        .start(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to start endpoint: {}", e))?;

    println!("{}", "✓ Endpoint started successfully!".green().bold());
    println!();
    output::print_endpoint(&endpoint, format)?;

    Ok(())
}

pub async fn health(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let health = client
        .endpoints(project_id, branch_id)
        .health(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get endpoint health: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&health)?,
        OutputFormat::Table => {
            println!("Endpoint Health Status:");
            println!("  Status: {}", health.status);
            println!("  Replicas: {}", health.replicas);
            println!("  Ready Replicas: {}", health.ready_replicas);
            println!("  Available Replicas: {}", health.available_replicas);
            println!("  Unavailable Replicas: {}", health.unavailable_replicas);
        }
    }

    Ok(())
}

pub async fn metrics(
    project_id: &str,
    branch_id: &str,
    endpoint_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
) -> Result<()> {
    let client = get_client(api_host)?;
    
    let metrics = client
        .endpoints(project_id, branch_id)
        .metrics(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get endpoint metrics: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&metrics)?,
        OutputFormat::Table => {
            println!("Endpoint Resource Metrics:");
            println!("  Pod Count: {}", metrics.pod_count);
            println!("  CPU Request: {} millicores", metrics.cpu_request_millicores);
            println!("  Memory Request: {} bytes ({:.2} MB)", 
                metrics.memory_request_bytes, 
                metrics.memory_request_bytes as f64 / 1024.0 / 1024.0
            );
        }
    }

    Ok(())
}
