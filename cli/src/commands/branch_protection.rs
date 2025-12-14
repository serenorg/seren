use anyhow::Result;
use colored::Colorize;
use seren::{CreateBranchProtectionRequest, UpdateBranchProtectionRequest};

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let rules = client
        .branch_protection(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list branch protection rules: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&rules)?,
        OutputFormat::Table => output::print_branch_protection_table(&rules),
    }

    Ok(())
}

pub async fn get(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let rule = client
        .branch_protection(project_id)
        .get(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch protection: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule]),
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

    let request = CreateBranchProtectionRequest {
        prevent_deletion,
        prevent_reset,
        require_approval_for_changes: require_approval,
        allowed_bypass_roles: bypass_roles,
    };

    let rule = client
        .branch_protection(project_id)
        .create(branch_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create branch protection: {}", e))?;

    println!(
        "{}",
        "Branch protection rule created successfully!"
            .green()
            .bold()
    );
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule]),
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

    let request = UpdateBranchProtectionRequest {
        prevent_deletion,
        prevent_reset,
        require_approval_for_changes: require_approval,
        allowed_bypass_roles: bypass_roles,
    };

    let rule = client
        .branch_protection(project_id)
        .update(branch_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update branch protection: {}", e))?;

    println!(
        "{}",
        "Branch protection rule updated successfully!"
            .green()
            .bold()
    );
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&rule)?,
        OutputFormat::Table => output::print_branch_protection_table(&[rule]),
    }

    Ok(())
}

pub async fn delete(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    client
        .branch_protection(project_id)
        .delete(branch_id)
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
