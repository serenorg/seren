use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateRoleRequest, ResetRolePasswordRequest};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key)?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(
    project_id: &str,
    branch_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let roles = client
        .roles(project_id, branch_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list roles: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&roles)?,
        OutputFormat::Table => output::print_roles_table(&roles),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let request = CreateRoleRequest {
        name: name.to_string(),
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
    println!("{}: {}", "Password".bold(), role.password.bright_cyan());
    println!();

    output::print_role_with_password(&role, format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    role_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

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
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

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

    match format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}: {}", "Role ID".bold(), response.role_id);
            println!(
                "{}: {}",
                "New Password".bold(),
                response.password.bright_cyan()
            );
        }
    }

    Ok(())
}
