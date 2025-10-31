use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use seren::{
    Client, ClientConfig, CreateBranchRequest, PointInTime, RenameBranchRequest,
    RestoreBranchRequest, RestoreSource, SchemaDiffRequest, SetBranchExpirationRequest,
};
use uuid::Uuid;

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key)?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(project_id: &str, format: OutputFormat, api_host: Option<String>, api_key: Option<String>) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let branches = client
        .branches(project_id)
        .list()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list branches: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&branches)?,
        OutputFormat::Table => output::print_branches_table(&branches),
    }

    Ok(())
}

pub async fn get(
    project_id: &str,
    branch_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let branch = client
        .branches(project_id)
        .get(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch: {}", e))?;

    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn create(
    project_id: &str,
    name: &str,
    parent: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let parent_branch_id = parent
        .map(|value| {
            Uuid::parse_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid parent branch ID: {}", e))
        })
        .transpose()?;

    let request = CreateBranchRequest {
        name: name.to_string(),
        parent_branch_id,
    };

    let branch = client
        .branches(project_id)
        .create(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create branch: {}", e))?;

    println!("{}", "✓ Branch created successfully!".green().bold());
    println!();
    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn delete(project_id: &str, branch_id: &str, api_host: Option<String>, api_key: Option<String>) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    client
        .branches(project_id)
        .delete(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete branch: {}", e))?;

    println!(
        "{}",
        format!("✓ Branch {} deleted successfully!", branch_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn rename(
    project_id: &str,
    branch_id: &str,
    name: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let request = RenameBranchRequest {
        name: name.to_string(),
    };

    let branch = client
        .branches(project_id)
        .rename(branch_id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rename branch: {}", e))?;

    println!("{}", "✓ Branch renamed successfully!".green().bold());
    println!();
    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn set_default(
    project_id: &str,
    branch_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    client
        .branches(project_id)
        .set_default(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set default branch: {}", e))?;

    println!(
        "{}",
        format!("✓ Branch {} set as default successfully!", branch_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn connection_string(
    project_id: &str,
    branch_id: &str,
    pooled: bool,
    prisma: bool,
    ssl: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let response = client
        .branches(project_id)
        .connection_string(branch_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get connection string: {}", e))?;

    output::print_connection_string(&response, pooled, prisma, ssl, format)?;

    Ok(())
}

pub async fn set_expiration(
    project_id: &str,
    branch_id: &str,
    expires_at: Option<&str>,
    no_expiration: bool,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    // Build the request
    let expires_at_value = if no_expiration {
        None
    } else if let Some(exp) = expires_at {
        let parsed = DateTime::parse_from_rfc3339(exp)
            .map_err(|e| anyhow::anyhow!("Invalid expiration timestamp: {}", e))?
            .with_timezone(&Utc);
        Some(parsed)
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --expires-at or --no-expiration"
        ));
    };

    let request = SetBranchExpirationRequest {
        expires_at: expires_at_value,
    };

    let branch = client
        .branches(project_id)
        .set_expiration(branch_id, request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set branch expiration: {}", e))?;

    if no_expiration {
        println!(
            "{}",
            format!("✓ Branch {} expiration removed successfully!", branch_id)
                .green()
                .bold()
        );
    } else {
        println!(
            "{}",
            format!("✓ Branch {} expiration set successfully!", branch_id)
                .green()
                .bold()
        );
    }
    println!();
    output::print_branch(&branch, format)?;

    Ok(())
}

pub async fn schema_diff(
    project_id: &str,
    base_branch_id: &str,
    compare_branch_id: &str,
    database: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let mut request = SchemaDiffRequest::new(base_branch_id, compare_branch_id);
    if let Some(db) = database {
        request = request.with_database(db);
    }

    match client.branches(project_id).schema_diff(request).await {
        Ok(diff) => {
            output::print_schema_diff(&diff, format)?;
            Ok(())
        }
        Err(e) => {
            let message = e.to_string();
            if message.contains("Not implemented")
                || message.contains("Not Implemented")
                || message.contains("501")
            {
                eprintln!(
                    "{}",
                    "⚠ Branch schema diff is not yet available in Seren."
                        .yellow()
                        .bold()
                );
                eprintln!(
                    "This feature requires branch schema introspection and will be added soon."
                );
                std::process::exit(1);
            } else {
                Err(anyhow::anyhow!("Failed to get schema diff: {}", message))
            }
        }
    }
}

pub async fn reset(project_id: &str, branch_id: &str, api_host: Option<String>, api_key: Option<String>) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    match client.branches(project_id).reset(branch_id).await {
        Ok(branch) => {
            println!(
                "{}",
                format!("✓ Branch {} reset to parent successfully!", branch.name)
                    .green()
                    .bold()
            );
            Ok(())
        }
        Err(e) => {
            if e.to_string().contains("Not implemented") || e.to_string().contains("501") {
                eprintln!(
                    "{}",
                    "⚠ Branch reset feature is not yet implemented"
                        .yellow()
                        .bold()
                );
                eprintln!();
                eprintln!("This feature requires SerenDB Write-Ahead Log (WAL) integration.");
                eprintln!("When available, it will reset the branch to its parent's latest state,");
                eprintln!("discarding all local changes.");
                eprintln!();
                eprintln!("Coming soon!");
                std::process::exit(1);
            } else {
                Err(anyhow::anyhow!("Failed to reset branch: {}", e))
            }
        }
    }
}

pub async fn restore(
    project_id: &str,
    branch_id: &str,
    source: &str,
    preserve_under_name: &str,
    timestamp: Option<&str>,
    lsn: Option<&str>,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key)?;

    let parse_timestamp = |ts: &str| -> Result<DateTime<Utc>> {
        Ok(DateTime::parse_from_rfc3339(ts)
            .map_err(|e| anyhow::anyhow!("Invalid timestamp: {}", e))?
            .with_timezone(&Utc))
    };

    let parse_point_in_time = |timestamp: Option<&str>, lsn: Option<&str>| -> Result<Option<PointInTime>> {
        if let Some(ts) = timestamp {
            Ok(Some(PointInTime::Timestamp(parse_timestamp(ts)?)))
        } else if let Some(lsn_value) = lsn {
            Ok(Some(PointInTime::Lsn(lsn_value.to_string())))
        } else {
            Ok(None)
        }
    };

    let restore_source = if source == "^self" {
        let point_in_time = parse_point_in_time(timestamp, lsn)?.ok_or_else(|| {
            anyhow::anyhow!("Restoring from ^self requires either --timestamp or --lsn")
        })?;
        RestoreSource::Self_ { point_in_time }
    } else if source == "^parent" {
        let point_in_time = parse_point_in_time(timestamp, lsn)?;
        RestoreSource::Parent { point_in_time }
    } else {
        let point_in_time = parse_point_in_time(timestamp, lsn)?;
        let source_branch_id = Uuid::parse_str(source)
            .map_err(|e| anyhow::anyhow!("Invalid source branch ID: {}", e))?;
        RestoreSource::Branch {
            point_in_time,
            source_branch_id,
        }
    };

    let request = RestoreBranchRequest {
        source: restore_source,
        preserve_under_name: preserve_under_name.to_string(),
    };

    match client
        .branches(project_id)
        .restore(branch_id, request)
        .await
    {
        Ok(response) => {
            println!("{}", "✓ Branch restored successfully!".green().bold());
            println!();
            println!("Restored branch: {}", response.branch.name);
            println!("Backup branch: {}", response.backup_branch.name);
            Ok(())
        }
        Err(e) => {
            if e.to_string().contains("Not implemented") || e.to_string().contains("501") {
                eprintln!(
                    "{}",
                    "⚠ Branch restore feature is not yet implemented"
                        .yellow()
                        .bold()
                );
                eprintln!();
                eprintln!("This feature requires SerenDB Write-Ahead Log (WAL) integration.");
                eprintln!("When available, it will support point-in-time recovery using timestamps or LSN,");
                eprintln!("with automatic backup branch creation.");
                eprintln!();
                eprintln!("Coming soon!");
                std::process::exit(1);
            } else {
                Err(anyhow::anyhow!("Failed to restore branch: {}", e))
            }
        }
    }
}
