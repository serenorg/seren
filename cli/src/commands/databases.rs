use anyhow::Result;
use colored::Colorize;
use seren::CreateDatabaseRequest;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let databases = client
        .databases(project_id, branch_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list databases: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&databases)?,
        OutputFormat::Table => output::print_databases_table(&databases),
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

    let request = CreateDatabaseRequest {
        name: name.to_string(),
        owner_name: owner.map(|s| s.to_string()),
    };

    let database = client
        .databases(project_id, branch_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))?;

    println!("{}", "✓ Database created successfully!".green().bold());
    println!();
    output::print_database(&database, ctx.format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    database_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    client
        .databases(project_id, branch_id)
        .delete(database_id)
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
