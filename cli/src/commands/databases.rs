use anyhow::Result;
use colored::Colorize;
use comfy_table::{Cell, Color, Table, presets::UTF8_FULL_CONDENSED};
use seren::CreateDatabaseRequest;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn get(
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

    let response = client
        .seren_db_get_database(&project_uuid, &branch_uuid, &database_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get database: {}", e))?;

    let database = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&database)?,
        OutputFormat::Table => {
            let db = &database.data;
            println!("{}: {}", "ID".bold(), db.id);
            println!("{}: {}", "Name".bold(), db.name);
            println!("{}: {}", "Branch ID".bold(), db.branch_id);
            if let Some(owner) = &db.owner_name {
                println!("{}: {}", "Owner".bold(), owner);
            }
            println!("{}: {}", "Created".bold(), db.created_at);
            println!("{}: {}", "Updated".bold(), db.updated_at);
        }
    }

    Ok(())
}

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .seren_db_list_databases(&project_uuid, &branch_uuid)
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
        .seren_db_create_database(&project_uuid, &branch_uuid, &request)
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
        .seren_db_delete_database(&project_uuid, &branch_uuid, &database_uuid)
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

/// List all databases across all projects, or optionally filtered to a specific project
pub async fn list_all(project_id: Option<&str>, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let databases = if let Some(pid) = project_id {
        // List databases for a specific project (across all branches)
        let project_uuid =
            Uuid::parse_str(pid).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
        let resp = client
            .seren_db_list_project_databases(&project_uuid)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list databases: {}", e))?
            .into_inner();
        // The publisher endpoint returns DataResponseValue (untyped), so deserialize
        // into the same typed structure used by list_all_databases.
        let items: Vec<seren::DatabaseWithContext> = serde_json::from_value(resp.data)
            .map_err(|e| anyhow::anyhow!("Failed to parse databases response: {}", e))?;
        seren::DataResponseVecDatabaseWithContext {
            data: items,
            pagination: resp.pagination,
        }
    } else {
        // List all databases across all projects
        client
            .list_all_databases()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list databases: {}", e))?
            .into_inner()
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&databases)?,
        OutputFormat::Table => {
            if databases.data.is_empty() {
                println!("{}", "No databases found.".yellow());
            } else {
                let mut table = Table::new();
                table.load_preset(UTF8_FULL_CONDENSED);
                table.set_header(vec![
                    Cell::new("Project").fg(Color::Cyan),
                    Cell::new("Branch").fg(Color::Cyan),
                    Cell::new("Default").fg(Color::Cyan),
                    Cell::new("Database").fg(Color::Cyan),
                    Cell::new("Owner").fg(Color::Cyan),
                    Cell::new("ID").fg(Color::Cyan),
                ]);

                for db in &databases.data {
                    table.add_row(vec![
                        Cell::new(&db.project_name),
                        Cell::new(&db.branch_name),
                        Cell::new(if db.is_default_branch { "✓" } else { "" }),
                        Cell::new(&db.name).fg(Color::Green),
                        Cell::new(db.owner_name.as_deref().unwrap_or("-")),
                        Cell::new(db.id.to_string()),
                    ]);
                }

                println!("{table}");
                println!();
                println!(
                    "{}",
                    format!("Total: {} database(s)", databases.data.len()).dimmed()
                );
            }
        }
    }

    Ok(())
}
