use anyhow::Result;
use colored::Colorize;
use seren::{
    CreatePublicationRequest, CreateReplicationSlotRequest, UpdateLogicalReplicationRequest,
    UpdatePublicationRequest,
};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

// Logical Replication Settings

pub async fn get_settings(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .get_replication_settings(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get replication settings: {}", e))?;

    let settings = response.into_inner().data;
    match ctx.format {
        OutputFormat::Json => output::print_json(&settings)?,
        OutputFormat::Table => {
            println!("{}", "Logical Replication Settings".bold());
            println!("  Project ID: {}", settings.project_id);
            println!(
                "  Enabled: {}",
                if settings.enabled {
                    "Yes".green()
                } else {
                    "No".red()
                }
            );
            println!("  Publications Count: {}", settings.publications_count);
            println!("  Slots Count: {}", settings.slots_count);
        }
    }

    Ok(())
}

pub async fn enable(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let request = UpdateLogicalReplicationRequest { enabled: true };

    let response = client
        .update_replication_settings(&project_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to enable logical replication: {}", e))?;

    let settings = response.into_inner();
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .list_publications(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list publications: {}", e))?;

    let publications = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&publications)?,
        OutputFormat::Table => output::print_publications_table(&publications.data),
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    // If all_tables is true, use empty tables (means ALL TABLES in API)
    let tables = if all_tables { vec![] } else { table_names };

    let request = CreatePublicationRequest {
        name: name.to_string(),
        tables,
        publish_delete: None,
        publish_insert: None,
        publish_truncate: None,
        publish_update: None,
    };

    let response = client
        .create_publication(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create publication: {}", e))?;

    let publication = response.into_inner();
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let publication_uuid = Uuid::parse_str(publication_id)
        .map_err(|e| anyhow::anyhow!("Invalid publication ID: {}", e))?;

    // Convert all_tables to empty tables vec, or use provided table_names
    let tables = match (all_tables, table_names) {
        (Some(true), _) => Some(vec![]), // ALL TABLES
        (_, Some(names)) => Some(names),
        _ => None,
    };

    let request = UpdatePublicationRequest {
        tables,
        publish_delete: None,
        publish_insert: None,
        publish_truncate: None,
        publish_update: None,
    };

    let response = client
        .update_publication(&project_uuid, &branch_uuid, &publication_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update publication: {}", e))?;

    let publication = response.into_inner();
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let publication_uuid = Uuid::parse_str(publication_id)
        .map_err(|e| anyhow::anyhow!("Invalid publication ID: {}", e))?;

    client
        .delete_publication(&project_uuid, &branch_uuid, &publication_uuid)
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .list_replication_slots(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list replication slots: {}", e))?;

    let slots = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&slots)?,
        OutputFormat::Table => output::print_replication_slots_table(&slots.data),
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = CreateReplicationSlotRequest {
        name: name.to_string(),
        plugin: Some(plugin.unwrap_or_else(|| "pgoutput".to_string())),
        slot_type: None,
    };

    let response = client
        .create_replication_slot(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create replication slot: {}", e))?;

    let slot = response.into_inner();
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let slot_uuid =
        Uuid::parse_str(slot_id).map_err(|e| anyhow::anyhow!("Invalid slot ID: {}", e))?;

    client
        .delete_replication_slot(&project_uuid, &branch_uuid, &slot_uuid)
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
