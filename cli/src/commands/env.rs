use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use serde::Serialize;
use seren::{Client, ClientConfig};

use crate::{OutputFormat, commands::auth::get_bearer_token, config::ContextConfig, output};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

fn prompt_input(message: &str) -> Result<String> {
    print!("{}", message);
    io::stdout().flush()?;

    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn write_env_value(env_path: &str, key: &str, value: &str) -> Result<()> {
    let path = Path::new(env_path);
    let mut lines: Vec<String> = if path.exists() {
        let contents = fs::read_to_string(path)?;
        contents.lines().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };

    let key_prefix = format!("{}=", key);
    let mut updated = false;

    for line in &mut lines {
        if line.starts_with(&key_prefix) {
            *line = format!("{}={}", key, value);
            updated = true;
            break;
        }
    }

    if !updated {
        lines.push(format!("{}={}", key, value));
    }

    let new_contents = if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    };

    fs::write(path, new_contents)?;
    Ok(())
}

#[derive(Serialize)]
struct EnvInitResult {
    project_id: String,
    branch_id: String,
    env_path: String,
    key: String,
    pooled: bool,
    prisma: bool,
}

/// Initialize a .env file with a Seren connection string.
#[allow(clippy::too_many_arguments)]
pub async fn init(
    mut project_id: Option<String>,
    mut branch_id: Option<String>,
    env_path: &str,
    key: &str,
    pooled: bool,
    prisma: bool,
    yes: bool,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let context = ContextConfig::load()?;

    if project_id.is_none() {
        project_id = context.project_id.clone();
    }

    // Prompt for project_id if not set and interactive is allowed.
    if project_id.is_none() && !yes {
        let input = prompt_input(
            "Enter project ID (or press Ctrl+C to abort).\nHint: run `seren projects list` to discover IDs.\nProject ID: ",
        )?;
        if !input.is_empty() {
            project_id = Some(input);
        }
    }

    let project_id = project_id.ok_or_else(|| {
        anyhow::anyhow!(
            "Project ID is required. Pass --project-id, set it via `seren set-context set --project-id`, or run without --yes to be prompted."
        )
    })?;

    // Prompt for branch_id if not set and interactive is allowed.
    if branch_id.is_none() && !yes {
        let input = prompt_input(
            "Enter branch ID (or press Ctrl+C to abort).\nHint: run `seren branches list --project-id <PROJECT_ID>` to discover IDs.\nBranch ID: ",
        )?;
        if !input.is_empty() {
            branch_id = Some(input);
        }
    }

    let branch_id = branch_id.ok_or_else(|| {
        anyhow::anyhow!(
            "Branch ID is required. Pass --branch-id or run without --yes to be prompted."
        )
    })?;

    let client = get_client(api_host, api_key).await?;

    let conn = client
        .branches(&project_id)
        .connection_string_with_options(&branch_id, Some(pooled), None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get connection string: {}", e))?;

    // Derive the final connection string using the same formatting logic as print_connection_string.
    // We always apply sslmode=require when writing to .env to be explicit.
    let ssl_mode = Some("require");
    let mut active = conn.data.connection_string.clone();

    let apply_ssl = |s: &str, ssl_mode: &str| -> String {
        if let Some(idx) = s.find('?') {
            let (base, query) = s.split_at(idx);
            let params: Vec<&str> = query[1..]
                .split('&')
                .filter(|p| !p.starts_with("sslmode="))
                .collect();
            let base_str = if params.is_empty() {
                base.to_string()
            } else {
                format!("{}?{}", base, params.join("&"))
            };

            if base_str.contains('?') {
                format!("{}&sslmode={}", base_str, ssl_mode)
            } else {
                format!("{}?sslmode={}", base_str, ssl_mode)
            }
        } else if s.is_empty() {
            s.to_string()
        } else {
            format!("{}?sslmode={}", s, ssl_mode)
        }
    };

    if let Some(mode) = ssl_mode {
        active = apply_ssl(&active, mode);
    }

    let value_to_write = if prisma {
        format!("DATABASE_URL=\"{}\"", active)
    } else {
        active.clone()
    };

    write_env_value(env_path, key, &value_to_write)?;

    let result = EnvInitResult {
        project_id: project_id.clone(),
        branch_id: branch_id.clone(),
        env_path: env_path.to_string(),
        key: key.to_string(),
        pooled,
        prisma,
    };

    match format {
        OutputFormat::Json => {
            output::print_json(&result)?;
        }
        OutputFormat::Table => {
            println!(
                "{}",
                "✓ Wrote Seren connection string to environment file"
                    .green()
                    .bold()
            );

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.set_header(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);

            table.add_row(vec![Cell::new("Project ID"), Cell::new(&result.project_id)]);
            table.add_row(vec![Cell::new("Branch ID"), Cell::new(&result.branch_id)]);
            table.add_row(vec![Cell::new("Env file"), Cell::new(&result.env_path)]);
            table.add_row(vec![Cell::new("Env key"), Cell::new(&result.key)]);
            table.add_row(vec![
                Cell::new("Pooled"),
                Cell::new(if result.pooled { "yes" } else { "no" }),
            ]);
            table.add_row(vec![
                Cell::new("Prisma fmt"),
                Cell::new(if result.prisma { "yes" } else { "no" }),
            ]);

            println!("{table}");
        }
    }

    Ok(())
}
