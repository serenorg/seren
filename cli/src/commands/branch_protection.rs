use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .list_branch_protection_rules(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list branch protection rules: {}", e))?;

    let rules = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&rules)?,
        OutputFormat::Table => output::print_branch_protection_table(&rules.data),
    }

    Ok(())
}

pub async fn get(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .get_branch_protection(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch protection: {}", e))?;

    let rule = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule.data]),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    prevent_deletion: bool,
    prevent_reset: bool,
    require_approval: bool,
    bypass_roles: Vec<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = seren::CreateBranchProtectionRequest {
        prevent_deletion: Some(prevent_deletion),
        prevent_reset: Some(prevent_reset),
        require_approval_for_changes: Some(require_approval),
        allowed_bypass_roles: bypass_roles,
    };

    let response = client
        .create_branch_protection(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create branch protection: {}", e))?;

    let rule = response.into_inner();
    println!(
        "{}",
        "Branch protection rule created successfully!"
            .green()
            .bold()
    );
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule.data]),
    }

    Ok(())
}

pub async fn update(
    project_id: &str,
    branch_id: &str,
    prevent_deletion: Option<bool>,
    prevent_reset: Option<bool>,
    require_approval: Option<bool>,
    bypass_roles: Option<Vec<String>>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = seren::UpdateBranchProtectionRequest {
        prevent_deletion,
        prevent_reset,
        require_approval_for_changes: require_approval,
        allowed_bypass_roles: bypass_roles,
    };

    let response = client
        .update_branch_protection(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update branch protection: {}", e))?;

    let rule = response.into_inner();
    println!(
        "{}",
        "Branch protection rule updated successfully!"
            .green()
            .bold()
    );
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule.data]),
    }

    Ok(())
}

pub async fn delete(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    client
        .delete_branch_protection(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete branch protection: {}", e))?;

    println!(
        "{}",
        format!(
            "Branch protection for branch {} removed successfully!",
            branch_id
        )
        .green()
        .bold()
    );

    Ok(())
}
