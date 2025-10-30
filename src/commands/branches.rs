use anyhow::Result;
use colored::Colorize;
use seren::{
    Client, ClientConfig, CreateBranchRequest, PointInTime, RenameBranchRequest,
    RestoreBranchRequest, RestoreSource, SchemaDiffRequest, SetBranchExpirationRequest,
};

use crate::{config::Config, output, OutputFormat};

fn get_client(api_host: Option<String>) -> Result<Client> {
    let config = Config::load()?;

    let mut client_config = ClientConfig::new(config.api_key);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list(project_id: &str, format: OutputFormat, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

    let request = CreateBranchRequest {
        name: name.to_string(),
        parent_branch_id: parent.map(|s| s.to_string()),
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

pub async fn delete(project_id: &str, branch_id: &str, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

    // Build the request
    let expires_at_value = if no_expiration {
        None
    } else if let Some(exp) = expires_at {
        Some(exp.to_string())
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
) -> Result<()> {
    let client = get_client(api_host)?;

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

pub async fn reset(project_id: &str, branch_id: &str, api_host: Option<String>) -> Result<()> {
    let client = get_client(api_host)?;

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
) -> Result<()> {
    let client = get_client(api_host)?;

    // Parse restore source
    let restore_source = if source == "^self" {
        // Restore from own history - requires timestamp or LSN
        let point_in_time = if let Some(ts) = timestamp {
            PointInTime::Timestamp {
                timestamp: ts.to_string(),
            }
        } else if let Some(l) = lsn {
            PointInTime::Lsn { lsn: l.to_string() }
        } else {
            return Err(anyhow::anyhow!(
                "Restoring from ^self requires either --timestamp or --lsn"
            ));
        };
        RestoreSource::SelfHistory { point_in_time }
    } else if source == "^parent" {
        // Restore from parent - timestamp/LSN optional
        let point_in_time = if let Some(ts) = timestamp {
            Some(PointInTime::Timestamp {
                timestamp: ts.to_string(),
            })
        } else if let Some(l) = lsn {
            Some(PointInTime::Lsn { lsn: l.to_string() })
        } else {
            None
        };
        RestoreSource::Parent { point_in_time }
    } else {
        // Restore from specific branch - timestamp/LSN optional
        let point_in_time = if let Some(ts) = timestamp {
            Some(PointInTime::Timestamp {
                timestamp: ts.to_string(),
            })
        } else if let Some(l) = lsn {
            Some(PointInTime::Lsn { lsn: l.to_string() })
        } else {
            None
        };
        RestoreSource::Branch {
            source_branch_id: source.to_string(),
            point_in_time,
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
