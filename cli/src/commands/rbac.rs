use anyhow::Result;
use colored::Colorize;
use seren::{
    AssignOrganizationRoleRequest, Client, ClientConfig, CreateOrganizationRoleRequest,
    UpdateOrganizationRoleRequest,
};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list_roles(
    org_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let roles = client
        .rbac_roles(org_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list roles: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&roles)?,
        OutputFormat::Table => output::print_rbac_roles_table(&roles),
    }

    Ok(())
}

pub async fn get_role(
    org_id: &str,
    role_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let role = client
        .rbac_roles(org_id)
        .get(role_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get role: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role]),
    }

    Ok(())
}

pub async fn create_role(
    org_id: &str,
    name: &str,
    description: Option<String>,
    permissions: Vec<String>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = CreateOrganizationRoleRequest {
        name: name.to_string(),
        description,
        permissions,
    };

    let role = client
        .rbac_roles(org_id)
        .create(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create role: {}", e))?;

    println!("{}", "Role created successfully!".green().bold());
    println!();

    match format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role]),
    }

    Ok(())
}

pub async fn update_role(
    org_id: &str,
    role_id: &str,
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = UpdateOrganizationRoleRequest {
        name,
        description,
        permissions,
    };

    let role = client
        .rbac_roles(org_id)
        .update(role_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update role: {}", e))?;

    println!("{}", "Role updated successfully!".green().bold());
    println!();

    match format {
        OutputFormat::Json => output::print_json(&role)?,
        OutputFormat::Table => output::print_rbac_roles_table(&[role]),
    }

    Ok(())
}

pub async fn delete_role(
    org_id: &str,
    role_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    client
        .rbac_roles(org_id)
        .delete(role_id)
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
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = AssignOrganizationRoleRequest {
        role_id: role_id
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid role ID format"))?,
    };

    client
        .rbac_roles(org_id)
        .assign(member_id, &request)
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

pub async fn list_permissions(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    // Use empty org_id since permissions endpoint is global
    let permissions = client
        .rbac_roles("")
        .list_permissions()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list permissions: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&permissions)?,
        OutputFormat::Table => output::print_permissions_table(&permissions),
    }

    Ok(())
}

pub async fn my_permissions(
    org_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let permissions = client
        .rbac_roles(org_id)
        .my_permissions()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get your permissions: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&permissions)?,
        OutputFormat::Table => {
            println!("{}", "Your Permissions:".bold());
            for perm in &permissions {
                println!("  - {}", perm);
            }
        }
    }

    Ok(())
}
