use anyhow::Result;
use colored::Colorize;

use crate::{OutputFormat, config::ContextConfig, output};

pub async fn set(project_id: Option<String>, org_id: Option<String>) -> Result<()> {
    let mut context = ContextConfig::load()?;

    if let Some(pid) = project_id {
        context.project_id = Some(pid.clone());
        println!(
            "{}",
            format!("✓ Set default project_id to {}", pid)
                .green()
                .bold()
        );
    }

    if let Some(oid) = org_id {
        context.org_id = Some(oid.clone());
        println!(
            "{}",
            format!("✓ Set default org_id to {}", oid).green().bold()
        );
    }

    context.save()?;

    Ok(())
}

pub async fn show(format: OutputFormat) -> Result<()> {
    let context = ContextConfig::load()?;

    match format {
        OutputFormat::Json => output::print_json(&context)?,
        OutputFormat::Table => {
            let rows = [
                (
                    "Project ID",
                    context
                        .project_id
                        .as_deref()
                        .unwrap_or("(not set)")
                        .to_string(),
                ),
                (
                    "Org ID",
                    context.org_id.as_deref().unwrap_or("(not set)").to_string(),
                ),
            ];
            output::print_key_value_table(Some("Current Context"), &rows);
        }
    }

    Ok(())
}

pub async fn clear() -> Result<()> {
    ContextConfig::clear()?;
    println!("{}", "✓ Context cleared".green().bold());
    Ok(())
}
