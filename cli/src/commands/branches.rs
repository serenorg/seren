use anyhow::Result;
use colored::Colorize;
use jiff::Timestamp;
use serde_json::{Map, Value};
use seren::{
    BranchEndpointRequest, CreateBranchRequest, PointInTime, RenameBranchRequest,
    RestoreBranchRequest, RestoreSource, SchemaDiffRequest, SetBranchExpirationRequest,
};
use std::str::FromStr;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

/// Parse a duration string like "1d", "7d", "30d" into a Timestamp
fn parse_duration_to_timestamp(duration_str: &str) -> Result<Timestamp> {
    let duration_str = duration_str.trim().to_lowercase();

    // Parse formats like "1d", "7d", "30d", "24h"
    let (num_str, unit) = if duration_str.ends_with('d') {
        (&duration_str[..duration_str.len() - 1], "d")
    } else if duration_str.ends_with('h') {
        (&duration_str[..duration_str.len() - 1], "h")
    } else {
        return Err(anyhow::anyhow!(
            "Invalid duration format '{}'. Use format like '1d', '7d', '30d', or '24h'",
            duration_str
        ));
    };

    let num: i64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number in duration: {}", num_str))?;

    if num <= 0 {
        return Err(anyhow::anyhow!("Duration must be positive"));
    }

    let seconds = match unit {
        "d" => num * 24 * 60 * 60,
        "h" => num * 60 * 60,
        _ => unreachable!(),
    };

    let now = Timestamp::now();
    let expires_at = now
        .checked_add(jiff::Span::new().seconds(seconds))
        .map_err(|e| anyhow::anyhow!("Duration overflow: {}", e))?;

    Ok(expires_at)
}

pub async fn list(project_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let response = client
        .list_branches(&project_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list branches: {}", e))?;

    let branches = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&branches)?,
        OutputFormat::Table => output::print_branches_table(&branches.data),
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
        .get_branch(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch: {}", e))?;

    let branch = response.into_inner();
    output::print_branch(&branch.data, ctx.format)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    project_id: &str,
    name: &str,
    parent: Option<&str>,
    protected: bool,
    archived: bool,
    init_source: Option<&str>,
    parent_lsn: Option<&str>,
    parent_timestamp: Option<&str>,
    add_endpoint: bool,
    endpoint_type: Option<&str>,
    endpoint_settings: &[String],
    expires_in: Option<&str>,
    _schema_only: bool,
    cu: Option<&str>,
    suspend_timeout: Option<i32>,
    psql: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let parent_branch_id = parent
        .map(|value| {
            Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid parent branch ID: {}", e))
        })
        .transpose()?;

    let parent_timestamp = parent_timestamp
        .map(|value| {
            Timestamp::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid parent timestamp: {}", e))
        })
        .transpose()?;

    // Parse expires_in duration (e.g., "1d", "7d", "30d")
    let _expires_at = expires_in
        .map(|duration_str| {
            parse_duration_to_timestamp(duration_str)
                .map_err(|e| anyhow::anyhow!("Invalid expires-in duration: {}", e))
        })
        .transpose()?;

    let endpoint_settings_value = if endpoint_settings.is_empty() {
        None
    } else {
        let mut map = Map::new();
        for entry in endpoint_settings {
            let (key, value) = entry.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("Invalid endpoint setting '{}'. Use key=value.", entry)
            })?;
            map.insert(key.to_string(), Value::String(value.to_string()));
        }
        Some(Value::Object(map))
    };

    let auto_endpoint = add_endpoint
        || endpoint_type.is_some()
        || endpoint_settings_value.is_some()
        || cu.is_some()
        || suspend_timeout.is_some();
    let mut endpoints = Vec::new();
    if auto_endpoint {
        // Build endpoint settings including cu and suspend_timeout
        let mut settings_map = match endpoint_settings_value {
            Some(Value::Object(map)) => map,
            _ => Map::new(),
        };

        // Parse compute units (e.g., "2" or "0.5-3")
        if let Some(cu_str) = cu {
            if let Some((min, max)) = cu_str.split_once('-') {
                if let (Ok(min_val), Ok(max_val)) = (min.parse::<f64>(), max.parse::<f64>()) {
                    settings_map.insert(
                        "autoscaling_limit_min_cu".to_string(),
                        Value::Number(
                            serde_json::Number::from_f64(min_val)
                                .unwrap_or(serde_json::Number::from(1)),
                        ),
                    );
                    settings_map.insert(
                        "autoscaling_limit_max_cu".to_string(),
                        Value::Number(
                            serde_json::Number::from_f64(max_val)
                                .unwrap_or(serde_json::Number::from(1)),
                        ),
                    );
                }
            } else if let Ok(fixed_val) = cu_str.parse::<f64>() {
                settings_map.insert(
                    "autoscaling_limit_min_cu".to_string(),
                    Value::Number(
                        serde_json::Number::from_f64(fixed_val)
                            .unwrap_or(serde_json::Number::from(1)),
                    ),
                );
                settings_map.insert(
                    "autoscaling_limit_max_cu".to_string(),
                    Value::Number(
                        serde_json::Number::from_f64(fixed_val)
                            .unwrap_or(serde_json::Number::from(1)),
                    ),
                );
            }
        }

        // Add suspend timeout
        if let Some(timeout) = suspend_timeout {
            settings_map.insert(
                "suspend_timeout_seconds".to_string(),
                Value::Number(serde_json::Number::from(timeout)),
            );
        }

        let final_settings = if settings_map.is_empty() {
            None
        } else {
            Some(Value::Object(settings_map))
        };

        endpoints.push(BranchEndpointRequest {
            endpoint_type: endpoint_type
                .map(|s| s.to_string())
                .or_else(|| Some("read_write".to_string())),
            settings: final_settings,
        });
    }

    let request = CreateBranchRequest {
        name: name.to_string(),
        parent_branch_id,
        protected: Some(protected),
        archived: Some(archived),
        init_source: init_source.map(|s| s.to_string()),
        parent_lsn: parent_lsn.map(|s| s.to_string()),
        parent_timestamp,
        add_endpoint: auto_endpoint.then_some(true),
        endpoints,
        expires_at: None,
        schema_only: None,
    };

    let creation_response = client
        .create_branch(&project_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create branch: {}", e))?;

    let creation = creation_response.into_inner().data;

    let branch_response = client
        .get_branch(&project_uuid, &creation.branch.id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch branch details: {}", e))?;

    let branch = branch_response.into_inner().data;

    println!("{}", "✓ Branch created successfully!".green().bold());
    println!();
    output::print_branch(&branch, ctx.format)?;

    let mut connection_uri_for_psql: Option<String> = None;

    if let Some(endpoints) = creation.endpoints.as_ref()
        && !endpoints.is_empty()
    {
        // Store connection URI for potential psql connection
        if let Some(ep) = endpoints.first()
            && let Some(ref uri) = ep.connection_string
        {
            connection_uri_for_psql = Some(uri.clone());
        }
        println!();
        // Convert Vec<EndpointCreated> to Vec<EndpointCreatedResponse> for the output function
        let endpoints_for_output: Vec<seren::EndpointCreatedResponse> = endpoints
            .iter()
            .map(|ep| seren::EndpointCreatedResponse {
                data: ep.clone(),
                pagination: None,
            })
            .collect();
        output::print_created_endpoints(&endpoints_for_output, ctx.format)?;
    }

    // Connect via psql if requested
    if psql {
        if let Some(uri) = connection_uri_for_psql {
            println!();
            println!("{}", "Connecting via psql...".cyan());
            let status = std::process::Command::new("psql").arg(&uri).status();
            match status {
                Ok(exit_status) if !exit_status.success() => {
                    eprintln!("{}", "psql exited with non-zero status".yellow());
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("Failed to run psql: {}. Is psql installed?", e).red()
                    );
                }
                _ => {}
            }
        } else {
            eprintln!(
                "{}",
                "No connection URI available for psql. Was an endpoint created?".yellow()
            );
        }
    }

    Ok(())
}

pub async fn delete(
    project_id: &str,
    branch_id: &str,
    skip_confirm: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    // Get branch details for confirmation message
    let response = client
        .get_branch(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch: {}", e))?;
    let branch = response.into_inner().data;

    if !skip_confirm {
        println!(
            "{}",
            format!(
                "⚠ This will permanently delete the branch '{}'.",
                branch.name
            )
            .yellow()
        );
        println!("Are you sure you want to proceed? [y/N] ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input != "y" && input != "yes" {
            println!("{}", "Delete cancelled.".yellow());
            return Ok(());
        }
    }

    client
        .delete_branch(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete branch: {}", e))?;

    println!(
        "{}",
        format!("✓ Branch '{}' deleted successfully!", branch.name)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn rename(
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

    let request = RenameBranchRequest {
        name: name.to_string(),
    };

    let response = client
        .rename_branch(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rename branch: {}", e))?;

    let branch = response.into_inner().data;
    println!("{}", "✓ Branch renamed successfully!".green().bold());
    println!();
    output::print_branch(&branch, ctx.format)?;

    Ok(())
}

pub async fn set_default(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    client
        .set_default_branch(&project_uuid, &branch_uuid)
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
    ssl: Option<&str>,
    role: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let response = client
        .get_connection_string(
            &project_uuid,
            &branch_uuid,
            if pooled { Some(true) } else { None },
            role,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get connection string: {}", e))?;

    let conn_data = response.into_inner();
    output::print_connection_string(&conn_data.data, ssl, ctx.format)?;

    Ok(())
}

pub async fn set_expiration(
    project_id: &str,
    branch_id: &str,
    expires_at: Option<&str>,
    no_expiration: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    // Build the request
    let expires_at_value = if no_expiration {
        None
    } else if let Some(exp) = expires_at {
        let parsed = Timestamp::from_str(exp)
            .map_err(|e| anyhow::anyhow!("Invalid expiration timestamp: {}", e))?;
        Some(parsed)
    } else {
        return Err(anyhow::anyhow!(
            "Must provide either --expires-at or --no-expiration"
        ));
    };

    let request = SetBranchExpirationRequest {
        expires_at: expires_at_value,
    };

    client
        .set_branch_expiration(&project_uuid, &branch_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set branch expiration: {}", e))?;

    // Fetch the updated branch to display
    let branch_response = client
        .get_branch(&project_uuid, &branch_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get branch: {}", e))?;
    let branch = branch_response.into_inner().data;

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
    output::print_branch(&branch, ctx.format)?;

    Ok(())
}

pub async fn schema_diff(
    project_id: &str,
    base_branch_id: &str,
    compare_branch_id: &str,
    database: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let _client = ctx.client().await?;
    let _project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;

    let mut _request = SchemaDiffRequest::new(base_branch_id, compare_branch_id);
    if let Some(db) = database {
        _request = _request.with_database(db);
    }

    // Schema diff endpoint not yet implemented in the generated client
    // Return a not-implemented message for now
    eprintln!(
        "{}",
        "⚠ Branch schema diff is not yet available in Seren."
            .yellow()
            .bold()
    );
    eprintln!("This feature requires branch schema introspection and will be added soon.");
    std::process::exit(1);
}

pub async fn reset(project_id: &str, branch_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let request = seren::ResetBranchRequest { parent: true };

    match client
        .reset_branch(&project_uuid, &branch_uuid, &request)
        .await
    {
        Ok(response) => {
            let branch = response.into_inner().data;
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
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let project_uuid =
        Uuid::parse_str(project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid =
        Uuid::parse_str(branch_id).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))?;

    let parse_timestamp = |ts: &str| -> Result<Timestamp> {
        Timestamp::from_str(ts).map_err(|e| anyhow::anyhow!("Invalid timestamp: {}", e))
    };

    let parse_point_in_time =
        |timestamp: Option<&str>, lsn: Option<&str>| -> Result<Option<PointInTime>> {
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
        .restore_branch(&project_uuid, &branch_uuid, &request)
        .await
    {
        Ok(response) => {
            let restore_data = response.into_inner();
            println!("{}", "✓ Branch restored successfully!".green().bold());
            println!();
            println!("Restored branch: {}", restore_data.branch.name);
            println!("Backup branch: {}", restore_data.backup_branch.name);
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
                eprintln!(
                    "When available, it will support point-in-time recovery using timestamps or LSN,"
                );
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
