use anyhow::Result;
use colored::Colorize;
use seren::{
    Client, ClientConfig, CreateProjectRequest, ProjectConnectionUriQuery, UpdateProjectRequest,
};
use uuid::Uuid;

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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

pub async fn get(
    id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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
    enable_logical_replication: Option<bool>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    // Validate region against supported list (UI/Backend aligned)
    const ALLOWED_REGIONS: &[&str] = &["us-east-1"]; // temporarily restricted for cost control
    if !ALLOWED_REGIONS.contains(&region) {
        let list = ALLOWED_REGIONS.join(", ");
        return Err(anyhow::anyhow!(
            "Unsupported region '{}'. Allowed: {}",
            region,
            list
        ));
    }

    let client = get_client(api_host, api_key).await?;

    let request = CreateProjectRequest {
        name: name.to_string(),
        region: region.to_string(),
        block_public_connections,
        block_vpc_connections,
        hipaa,
        protected_branches_only,
        compute_unit_min,
        compute_unit_max,
        enable_logical_replication,
    };

    let project = client
        .projects()
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create project: {}", e))?;

    println!("{}", "✓ Project created successfully!".green().bold());
    println!();
    output::print_create_project_response(&project, format)?;

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
    enable_logical_replication: Option<bool>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    if name.is_none()
        && block_public_connections.is_none()
        && block_vpc_connections.is_none()
        && hipaa.is_none()
        && protected_branches_only.is_none()
        && compute_unit_min.is_none()
        && compute_unit_max.is_none()
        && enable_logical_replication.is_none()
    {
        anyhow::bail!("Provide at least one field to update");
    }

    // Warn user about enabling logical replication
    if enable_logical_replication == Some(true) {
        println!(
            "{}",
            "Warning: Enabling logical replication will suspend all active endpoints."
                .yellow()
                .bold()
        );
        println!(
            "{}",
            "This action cannot be undone - logical replication cannot be disabled once enabled."
                .yellow()
        );
    }

    let request = UpdateProjectRequest {
        name: name.map(|value| value.to_string()),
        block_public_connections,
        block_vpc_connections,
        hipaa,
        protected_branches_only,
        compute_unit_min,
        compute_unit_max,
        enable_logical_replication,
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

pub async fn delete(id: &str, api_host: Option<String>, api_key: Option<String>) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

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

pub async fn connection_uri(
    id: &str,
    branch_id: Option<&str>,
    endpoint_id: Option<&str>,
    database: Option<&str>,
    role: Option<&str>,
    pooled: bool,
    prisma: bool,
    ssl: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let query = ProjectConnectionUriQuery {
        branch_id: branch_id
            .map(|value| {
                Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))
            })
            .transpose()?,
        endpoint_id: endpoint_id
            .map(|value| {
                Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))
            })
            .transpose()?,
        database_name: database.map(|s| s.to_string()),
        role_name: role.map(|s| s.to_string()),
        pooled: if pooled { Some(true) } else { None },
    };

    let response = client
        .projects()
        .connection_uri(id, query)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch connection URI: {}", e))?;

    output::print_project_connection_uri(&response, pooled, prisma, ssl, format)?;

    Ok(())
}
