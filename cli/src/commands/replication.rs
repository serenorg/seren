use anyhow::Result;
use colored::Colorize;
use seren::{
    CreatePublicationRequest, CreateReplicationSlotRequest, UpdateLogicalReplicationRequest,
    UpdatePublicationRequest,
};

use crate::{CommandContext, OutputFormat, output};

// Logical Replication Settings

pub async fn get_settings(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let settings = client
        .replication(project_id)
        .get_settings()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get replication settings: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&settings)?,
        OutputFormat::Table => {
            println!("{}", "Logical Replication Settings".bold());
            println!("  Project ID: {}", settings.project_id);
            println!(
                "  Enabled: {}",
                if settings.logical_replication_enabled {
                    "Yes".green()
                } else {
                    "No".red()
                }
            );
        }
    }

    Ok(())
}

pub async fn enable(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let request = UpdateLogicalReplicationRequest {
        logical_replication_enabled: true,
    };

    let settings = client
        .replication(project_id)
        .update_settings(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to enable logical replication: {}", e))?;

    println!(
        "{}",
        "Logical replication enabled successfully!".green().bold()
    );
    println!();
    println!(
        "{}",
        "Note: This sets wal_level=logical and cannot be disabled.".yellow()
    );

    match ctx.format {
        OutputFormat::Json => output::print_json(&settings)?,
        OutputFormat::Table => {}
    }

    Ok(())
}

// Publications

pub async fn list_publications(
    project_id: &str,
    branch_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let publications = client
        .replication(project_id)
        .list_publications(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list publications: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&publications)?,
        OutputFormat::Table => output::print_publications_table(&publications),
    }

    Ok(())
}

pub async fn create_publication(
    project_id: &str,
    branch_id: &str,
    name: &str,
    table_names: Vec<String>,
    all_tables: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = CreatePublicationRequest {
        name: name.to_string(),
        table_names,
        all_tables,
    };

    let publication = client
        .replication(project_id)
        .create_publication(branch_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create publication: {}", e))?;

    println!("{}", "Publication created successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&publication)?,
        OutputFormat::Table => output::print_publications_table(&[publication]),
    }

    Ok(())
}

pub async fn update_publication(
    project_id: &str,
    branch_id: &str,
    publication_id: &str,
    table_names: Option<Vec<String>>,
    all_tables: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = UpdatePublicationRequest {
        table_names,
        all_tables,
    };

    let publication = client
        .replication(project_id)
        .update_publication(branch_id, publication_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update publication: {}", e))?;

    println!("{}", "Publication updated successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&publication)?,
        OutputFormat::Table => output::print_publications_table(&[publication]),
    }

    Ok(())
}

pub async fn delete_publication(
    project_id: &str,
    branch_id: &str,
    publication_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    client
        .replication(project_id)
        .delete_publication(branch_id, publication_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete publication: {}", e))?;

    println!(
        "{}",
        format!("Publication {} deleted successfully!", publication_id)
            .green()
            .bold()
    );

    Ok(())
}

// Replication Slots

pub async fn list_slots(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let slots = client
        .replication(project_id)
        .list_slots(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list replication slots: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&slots)?,
        OutputFormat::Table => output::print_replication_slots_table(&slots),
    }

    Ok(())
}

pub async fn create_slot(
    project_id: &str,
    branch_id: &str,
    name: &str,
    plugin: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = CreateReplicationSlotRequest {
        name: name.to_string(),
        plugin: plugin.unwrap_or_else(|| "pgoutput".to_string()),
    };

    let slot = client
        .replication(project_id)
        .create_slot(branch_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create replication slot: {}", e))?;

    println!(
        "{}",
        "Replication slot created successfully!".green().bold()
    );
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&slot)?,
        OutputFormat::Table => output::print_replication_slots_table(&[slot]),
    }

    Ok(())
}

pub async fn delete_slot(
    project_id: &str,
    branch_id: &str,
    slot_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    client
        .replication(project_id)
        .delete_slot(branch_id, slot_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete replication slot: {}", e))?;

    println!(
        "{}",
        format!("Replication slot {} deleted successfully!", slot_id)
            .green()
            .bold()
    );

    Ok(())
}
