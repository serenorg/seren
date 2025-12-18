use anyhow::Result;
use colored::Colorize;
use seren::CreateProjectRequest;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_projects(None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list projects: {}", e))?;

    let projects = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&projects)?,
        OutputFormat::Table => output::print_projects_table(&projects.data),
    }

    Ok(())
}

pub async fn get(id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_id =
        Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .get_project(&project_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get project: {}", e))?;

    let project = response.into_inner();
    output::print_project(&project.data, ctx.format)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
    psql: bool,
    set_context: bool,
    ctx: &CommandContext,
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

    let client = ctx.client().await?;

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

    let response = client
        .create_project(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create project: {}", e))?;

    let project = response.into_inner();
    println!("{}", "✓ Project created successfully!".green().bold());
    println!();
    output::print_create_project_response(&project.data, ctx.format)?;

    // Set context if requested
    if set_context {
        crate::config::set_context_project(&project.data.id.to_string())?;
        println!(
            "{}",
            format!("✓ Set project '{}' as current context", project.data.name).green()
        );
    }

    // Connect via psql if requested
    if psql {
        // Fetch connection URI for the default branch
        match client
            .get_project_connection_uri(
                &project.data.id,
                None, // branch_id
                None, // database_name
                None, // endpoint_id
                None, // pooled
                None, // role_name
            )
            .await
        {
            Ok(uri_response) => {
                let uri_data = uri_response.into_inner();
                println!();
                println!("{}", "Connecting via psql...".cyan());
                let status = std::process::Command::new("psql")
                    .arg(&uri_data.uri)
                    .status();
                match status {
                    Ok(exit_status) if !exit_status.success() => {
                        eprintln!("{}", "psql exited with non-zero status".yellow());
                    }
                    Err(e) => {
                        eprintln!(
                            "{}",
                            format!("Failed to run psql: {}. Is psql installed?", e).red()
                        );
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    format!("Could not get connection URI for psql: {}", e).yellow()
                );
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_id =
        Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

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

    let request = seren::UpdateProjectRequest {
        name: name.map(|value| value.to_string()),
        block_public_connections,
        block_vpc_connections,
        hipaa,
        protected_branches_only,
        compute_unit_min,
        compute_unit_max,
        enable_logical_replication,
        history_retention_seconds: None,
    };

    let response = client
        .update_project(&project_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update project: {}", e))?;

    let project = response.into_inner();
    println!("{}", "✓ Project updated successfully!".green().bold());
    println!();
    output::print_project(&project.data, ctx.format)?;

    Ok(())
}

pub async fn delete(id: &str, skip_confirm: bool, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_id =
        Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    // Get project details for confirmation
    let response = client
        .get_project(&project_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get project: {}", e))?;
    let project = response.into_inner().data;

    if !skip_confirm {
        println!(
            "{}",
            format!(
                "⚠ This action cannot be undone. This will permanently delete the project '{}'.",
                project.name
            )
            .red()
            .bold()
        );
        println!();
        println!(
            "To confirm, type the project name '{}': ",
            project.name.yellow()
        );

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input != project.name {
            println!(
                "{}",
                "Project name does not match. Delete cancelled.".yellow()
            );
            return Ok(());
        }
    }

    client
        .delete_project(&project_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete project: {}", e))?;

    println!(
        "{}",
        format!("✓ Project '{}' deleted successfully!", project.name)
            .green()
            .bold()
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn connection_uri(
    id: &str,
    branch_id: Option<&str>,
    endpoint_id: Option<&str>,
    database: Option<&str>,
    role: Option<&str>,
    pooled: bool,
    ssl: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_id =
        Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let branch_uuid = branch_id
        .map(|value| {
            Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))
        })
        .transpose()?;
    let endpoint_uuid = endpoint_id
        .map(|value| {
            Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))
        })
        .transpose()?;

    let response = client
        .get_project_connection_uri(
            &project_id,
            branch_uuid.as_ref(),
            database,
            endpoint_uuid.as_ref(),
            if pooled { Some(true) } else { None },
            role,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch connection URI: {}", e))?;

    let uri_data = response.into_inner();
    output::print_project_connection_uri(&uri_data, ssl, ctx.format)?;

    Ok(())
}
