use anyhow::Result;
use colored::Colorize;
use seren::{AssignRoleRequest, CreateRoleRequest, UpdateRoleRequest};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list_roles(org_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_organization_roles(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list roles: {}", e))?;

    let roles = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&roles)?,
        OutputFormat::Table => output::print_rbac_roles_table(&roles.data),
    }

    Ok(())
}

pub async fn get_role(org_id: &str, role_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    let response = client
        .get_role(&org_uuid, &role_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get role: {}", e))?;

    let role = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role.data]),
    }

    Ok(())
}

pub async fn create_role(
    org_id: &str,
    name: &str,
    description: Option<String>,
    permissions: Vec<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let request = CreateRoleRequest {
        name: name.to_string(),
        description,
        permissions,
    };

    let response = client
        .create_organization_role(&org_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create role: {}", e))?;

    let role = response.into_inner();
    println!("{}", "Role created successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role.data]),
    }

    Ok(())
}

pub async fn update_role(
    org_id: &str,
    role_id: &str,
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    let request = UpdateRoleRequest {
        name,
        description,
        permissions,
    };

    let response = client
        .update_role(&org_uuid, &role_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update role: {}", e))?;

    let role = response.into_inner();
    println!("{}", "Role updated successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role.data]),
    }

    Ok(())
}

pub async fn delete_role(org_id: &str, role_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    client
        .delete_organization_role(&org_uuid, &role_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete role: {}", e))?;

    println!(
        "{}",
        format!("Role {} deleted successfully!", role_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn assign_role(
    org_id: &str,
    member_id: &str,
    role_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let member_uuid =
        Uuid::parse_str(member_id).map_err(|e| anyhow::anyhow!("Invalid member ID: {}", e))?;
    let role_uuid =
        Uuid::parse_str(role_id).map_err(|e| anyhow::anyhow!("Invalid role ID: {}", e))?;

    let request = AssignRoleRequest {
        role_id: Some(role_uuid),
        role_name: None,
    };

    client
        .assign_role(&org_uuid, &member_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to assign role: {}", e))?;

    println!(
        "{}",
        format!(
            "Role {} assigned to member {} successfully!",
            role_id, member_id
        )
        .green()
        .bold()
    );

    Ok(())
}

pub async fn list_permissions(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_permissions()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list permissions: {}", e))?;

    let permissions = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&permissions)?,
        OutputFormat::Table => output::print_permissions_table(&permissions),
    }

    Ok(())
}

pub async fn my_permissions(org_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid =
        Uuid::parse_str(org_id).map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .get_my_permissions(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get my permissions: {}", e))?;

    let permissions = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&permissions)?,
        OutputFormat::Table => {
            output::print_list_table(Some("Your Permissions"), "Permission", &permissions)
        }
    }

    Ok(())
}
