use anyhow::Result;
use colored::Colorize;
use seren::CreateDatabaseRequest;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .list_databases(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list databases: {}", e))?;

    let databases = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&databases)?,
        OutputFormat::Table => output::print_databases_table(&databases.data),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    owner: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = CreateDatabaseRequest {
        name: name.to_string(),
        owner_name: owner.map(|s| s.to_string()),
    };

    let response = client
        .create_database(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))?;

    let database = response.into_inner();
    println!("{}", "✓ Database created successfully!".green().bold());
    println!();
    output::print_database(&database.data, ctx.format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    database_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let database_uuid =
        Uuid::parse_str(database_id).map_err(|e| anyhow::anyhow!("Invalid database ID: {}", e))?;

    client
        .delete_database(&project_uuid, &branch_uuid, &database_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete database: {}", e))?;

    println!(
        "{}",
        format!("✓ Database {} deleted successfully!", database_id)
            .green()
            .bold()
    );

    Ok(())
}
