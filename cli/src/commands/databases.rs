use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig, CreateDatabaseRequest};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

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
    let client = get_client(api_host, api_key).await?;

    let databases = client
        .databases(project_id, branch_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list databases: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&databases)?,
        OutputFormat::Table => output::print_databases_table(&databases),
    }

    Ok(())
}

pub async fn create(
    project_id: &str,
    branch_id: &str,
    name: &str,
    owner: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let request = CreateDatabaseRequest {
        name: name.to_string(),
        owner_name: owner.map(|s| s.to_string()),
    };

    let database = client
        .databases(project_id, branch_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create database: {}", e))?;

    println!("{}", "✓ Database created successfully!".green().bold());
    println!();
    output::print_database(&database, format)?;

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    database_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    client
        .databases(project_id, branch_id)
        .delete(database_id)
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
