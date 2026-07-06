use anyhow::{Context, Result};
use uuid::Uuid;

use crate::{CommandContext, config::ContextConfig, output};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    project_id: Option<String>,
    branch_id: Option<String>,
    endpoint_id: Option<String>,
    database: Option<String>,
    role: Option<String>,
    pooled: bool,
    ssl: Option<String>,
    psql_args: Vec<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let context = ContextConfig::load()?;
    let project_id = project_id
        .or(context.project_id)
        .context("Project ID is required. Pass --project-id or set it with `seren set-context set --project-id`.")?;

    let project_uuid =
        Uuid::parse_str(&project_id).map_err(|e| anyhow::anyhow!("Invalid project ID: {}", e))?;
    let branch_uuid = branch_id
        .as_deref()
        .map(|value| {
            Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid branch ID: {}", e))
        })
        .transpose()?;
    let endpoint_uuid = endpoint_id
        .as_deref()
        .map(|value| {
            Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid endpoint ID: {}", e))
        })
        .transpose()?;

    let client = ctx.client().await?;
    let response = client
        .seren_db_connection_uri(
            &project_uuid,
            branch_uuid.as_ref(),
            database.as_deref(),
            endpoint_uuid.as_ref(),
            if pooled { Some(true) } else { None },
            role.as_deref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch connection URI: {}", e))?;

    let mut uri = response.into_inner().data.uri;
    if let Some(ssl_mode) = ssl {
        uri = output::apply_sslmode(&uri, &ssl_mode);
    }

    let status = std::process::Command::new("psql")
        .arg(&uri)
        .args(psql_args)
        .status()
        .context("Failed to run psql. Is psql installed?")?;

    if !status.success() {
        anyhow::bail!("psql exited with non-zero status");
    }

    Ok(())
}
