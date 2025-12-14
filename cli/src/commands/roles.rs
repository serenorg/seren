use anyhow::Result;
use colored::Colorize;
use seren::{CreateRoleRequest, ResetRolePasswordRequest};

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let roles = client
        .roles(project_id, branch_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list roles: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&roles)?,
        OutputFormat::Table => output::print_roles_table(&roles),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = CreateRoleRequest {
        name: name.to_string(),
        description: None,
        permissions: vec![],
    };

    let role = client
        .roles(project_id, branch_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create role: {}", e))?;

    println!("{}", "✓ Role created successfully!".green().bold());
    println!();

    // Show password prominently
    println!(
        "{}",
        "IMPORTANT: Save this password - it cannot be retrieved later!"
            .yellow()
            .bold()
    );
    println!(
        "{}: {}",
        "Password".bold(),
        role.data.password.bright_cyan()
    );
    println!();

    output::print_role_with_password(&role, ctx.format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    role_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    client
        .roles(project_id, branch_id)
        .delete(role_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete role: {}", e))?;

    println!(
        "{}",
        format!("✓ Role {} deleted successfully!", role_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn reset_password(
    project_id: &str,
    branch_id: &str,
    role_id: &str,
    password: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = ResetRolePasswordRequest {
        password: password.to_string(),
    };

    let response = client
        .roles(project_id, branch_id)
        .reset_password(role_id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reset role password: {}", e))?;

    println!("{}", "✓ Password reset successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}: {}", "Role ID".bold(), response.data.role_id);
            println!(
                "{}: {}",
                "New Password".bold(),
                response.data.password.bright_cyan()
            );
        }
    }

    Ok(())
}
