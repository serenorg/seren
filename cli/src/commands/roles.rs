use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .seren_db_list_roles(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list roles: {}", e))?;

    let roles = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&roles)?,
        OutputFormat::Table => output::print_roles_table(&roles.data),
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = seren::CreateRoleRequest {
        name: name.to_string(),
        description: None,
        permissions: vec![],
    };

    let response = client
        .seren_db_create_role(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create role: {}", e))?;

    let role = response.into_inner();
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    client
        .seren_db_delete_role(&project_uuid, &branch_uuid, &role_uuid)
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
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    let request = seren::ResetRolePasswordRequest {
        password: password.to_string(),
    };

    let response = client
        .reset_role_password(&project_uuid, &branch_uuid, &role_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reset role password: {}", e))?;

    let result = response.into_inner();
    println!("{}", "✓ Password reset successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}: {}", "Role ID".bold(), result.data.role_id);
            println!(
                "{}: {}",
                "New Password".bold(),
                result.data.password.bright_cyan()
            );
        }
    }

    Ok(())
}

pub async fn reveal_password(
    project_id: &str,
    branch_id: &str,
    role_name: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .reveal_role_password(&project_uuid, &branch_uuid, role_name)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to reveal role password: {}", e))?;

    let result = response.into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}: {}", "Role".bold(), role_name);
            println!("{}: {}", "Role ID".bold(), result.data.role_id);
            println!(
                "{}: {}",
                "Password".bold(),
                result.data.password.bright_cyan()
            );
        }
    }

    Ok(())
}
