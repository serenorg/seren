use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use futures_util::TryStreamExt;
use seren::{
    CreateOrganizationCustomSkillRequest, CreateOrganizationCustomSkillRevisionRequest,
    OrganizationCustomSkill, OrganizationCustomSkillFileInput, OrganizationCustomSkillRevision,
    OrganizationCustomSkillRevisionSummary, OrganizationCustomSkillStatus,
    UpdateOrganizationCustomSkillRequest,
};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list(organization_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;

    let response = client
        .list_custom_skills(&org_uuid, None, None)
        .await
        .context("Failed to list custom skills")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => print_skills_table(&body.data),
    }
    Ok(())
}

pub async fn get(organization_id: &str, skill_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;

    let response = client
        .get_custom_skill(&org_uuid, &skill_uuid)
        .await
        .context("Failed to get custom skill")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => print_skill_detail(&body.data),
    }
    Ok(())
}

pub async fn create(
    organization_id: &str,
    slug: &str,
    display_name: &str,
    description: Option<&str>,
    path: &str,
    publish: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let files = collect_skill_files(Path::new(path))?;
    ensure_root_skill_md(&files)?;

    let request = CreateOrganizationCustomSkillRequest {
        slug: slug.to_string(),
        display_name: display_name.to_string(),
        description: description
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        initial_revision: CreateOrganizationCustomSkillRevisionRequest {
            files,
            publish: Some(publish),
        },
    };

    let response = client
        .create_custom_skill(&org_uuid, &request)
        .await
        .context("Failed to create custom skill")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("✓ Created custom skill '{}'", body.data.display_name)
                    .green()
                    .bold()
            );
            println!("  ID: {}", body.data.id);
            println!("  Slug: {}", body.data.slug.cyan());
            if let Some(revision_id) = body
                .data
                .published_revision_id
                .or(body.data.latest_revision_id)
            {
                println!("  Revision: {}", revision_id);
            }
        }
    }

    Ok(())
}

pub async fn update(
    organization_id: &str,
    skill_id: &str,
    display_name: Option<&str>,
    description: Option<&str>,
    clear_description: bool,
    status: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;

    if clear_description {
        anyhow::bail!(
            "--clear-description is not supported yet because the generated SDK cannot send an explicit null description for this endpoint"
        );
    }

    let normalized_status = status
        .map(|value| value.parse::<OrganizationCustomSkillStatus>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid status: {}", e))?;

    let request = UpdateOrganizationCustomSkillRequest {
        display_name: display_name.map(str::to_string),
        description: description.map(str::to_string),
        status: normalized_status,
    };

    let response = client
        .update_custom_skill(&org_uuid, &skill_uuid, &request)
        .await
        .context("Failed to update custom skill")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("✓ Updated custom skill '{}'", body.data.display_name)
                    .green()
                    .bold()
            );
            println!("  Status: {}", body.data.status);
        }
    }

    Ok(())
}

pub async fn list_revisions(
    organization_id: &str,
    skill_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;

    let response = client
        .list_custom_skill_revisions(&org_uuid, &skill_uuid)
        .await
        .context("Failed to list custom skill revisions")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => print_revisions_table(&body.data),
    }
    Ok(())
}

pub async fn get_revision(
    organization_id: &str,
    skill_id: &str,
    revision_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;
    let revision_uuid = parse_uuid(revision_id, "revision ID")?;

    let response = client
        .get_custom_skill_revision(&org_uuid, &skill_uuid, &revision_uuid)
        .await
        .context("Failed to get custom skill revision")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => print_revision_detail(&body.data),
    }
    Ok(())
}

pub async fn create_revision(
    organization_id: &str,
    skill_id: &str,
    path: &str,
    publish: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;
    let files = collect_skill_files(Path::new(path))?;
    ensure_root_skill_md(&files)?;

    let request = CreateOrganizationCustomSkillRevisionRequest {
        files,
        publish: Some(publish),
    };

    let response = client
        .create_custom_skill_revision(&org_uuid, &skill_uuid, &request)
        .await
        .context("Failed to create custom skill revision")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("✓ Created revision {}", body.data.revision_number)
                    .green()
                    .bold()
            );
            println!("  ID: {}", body.data.id);
            println!("  Status: {}", body.data.status);
        }
    }
    Ok(())
}

pub async fn publish_revision(
    organization_id: &str,
    skill_id: &str,
    revision_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;
    let revision_uuid = parse_uuid(revision_id, "revision ID")?;

    let response = client
        .publish_custom_skill_revision(&org_uuid, &skill_uuid, &revision_uuid)
        .await
        .context("Failed to publish custom skill revision")?;

    let body = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&body)?,
        OutputFormat::Table => {
            println!(
                "{}",
                format!("✓ Published revision for '{}'", body.data.display_name)
                    .green()
                    .bold()
            );
            if let Some(revision) = body.data.published_revision {
                println!("  Revision: {}", revision.revision_number);
            }
        }
    }
    Ok(())
}

pub async fn download_bundle(
    organization_id: &str,
    skill_id: &str,
    revision_id: &str,
    output_path: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = parse_uuid(organization_id, "organization ID")?;
    let skill_uuid = parse_uuid(skill_id, "skill ID")?;
    let revision_uuid = parse_uuid(revision_id, "revision ID")?;

    let response = client
        .download_custom_skill_revision_bundle(&org_uuid, &skill_uuid, &revision_uuid)
        .await
        .context("Failed to download custom skill bundle")?;

    let mut stream = response.into_inner().into_inner();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .context("Failed to read custom skill bundle stream")?
    {
        bytes.extend_from_slice(&chunk);
    }

    let path = output_path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("custom-skill-{}.tar.gz", revision_uuid)));

    fs::write(&path, &bytes).with_context(|| format!("Failed to write {}", path.display()))?;
    println!("{} {}", "✓ Wrote bundle to".green().bold(), path.display());
    Ok(())
}

fn print_skills_table(skills: &[OrganizationCustomSkill]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Name").fg(Color::Green),
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Published").fg(Color::Green),
        Cell::new("Latest").fg(Color::Green),
    ]);

    for skill in skills {
        table.add_row(vec![
            Cell::new(&skill.display_name),
            Cell::new(&skill.slug),
            Cell::new(skill.status.to_string()),
            Cell::new(
                skill
                    .published_revision
                    .as_ref()
                    .map(|revision| revision.revision_number.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            ),
            Cell::new(
                skill
                    .latest_revision
                    .as_ref()
                    .map(|revision| revision.revision_number.to_string())
                    .unwrap_or_else(|| "—".to_string()),
            ),
        ]);
    }
    println!("{table}");
}

fn print_skill_detail(skill: &OrganizationCustomSkill) {
    println!("{}", skill.display_name.bold().underline());
    println!("  ID: {}", skill.id);
    println!("  Slug: {}", skill.slug.cyan());
    println!("  Status: {}", skill.status);
    if let Some(description) = &skill.description {
        println!("  Description: {}", description);
    }
    if let Some(revision) = &skill.published_revision {
        println!("  Published revision: {}", revision.revision_number);
    }
    if let Some(revision) = &skill.latest_revision {
        println!("  Latest revision: {}", revision.revision_number);
    }
}

fn print_revisions_table(revisions: &[OrganizationCustomSkillRevisionSummary]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Revision").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Files").fg(Color::Green),
        Cell::new("Bundle Size").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for revision in revisions {
        table.add_row(vec![
            Cell::new(revision.revision_number.to_string()),
            Cell::new(revision.status.to_string()),
            Cell::new(revision.file_count.to_string()),
            Cell::new(revision.bundle_size_bytes.to_string()),
            Cell::new(revision.created_at),
        ]);
    }
    println!("{table}");
}

fn print_revision_detail(revision: &OrganizationCustomSkillRevision) {
    println!(
        "{}",
        format!("Revision {}", revision.revision_number)
            .bold()
            .underline()
    );
    println!("  ID: {}", revision.id);
    println!("  Status: {}", revision.status);
    println!("  Files: {}", revision.files.len());
    println!("  Bundle SHA256: {}", revision.bundle_sha256);
    println!("  Bundle size: {}", revision.bundle_size_bytes);
    if let Some(published_at) = &revision.published_at {
        println!("  Published at: {}", published_at);
    }
    println!();
    println!("{}", "Files".bold());
    for file in &revision.files {
        println!(
            "  - {} ({} bytes, {}, {})",
            file.relative_path,
            file.size_bytes,
            file.content_type,
            if file.is_text { "text" } else { "binary" }
        );
    }
}

fn parse_uuid(value: &str, label: &str) -> Result<Uuid> {
    Uuid::parse_str(value).map_err(|e| anyhow::anyhow!("Invalid {}: {}", label, e))
}

fn collect_skill_files(root: &Path) -> Result<Vec<OrganizationCustomSkillFileInput>> {
    if !root.exists() {
        anyhow::bail!("Path '{}' does not exist", root.display());
    }
    if !root.is_dir() {
        anyhow::bail!("Path '{}' is not a directory", root.display());
    }

    let mut files = Vec::new();
    collect_skill_files_recursive(root, root, &mut files)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(files)
}

fn collect_skill_files_recursive(
    root: &Path,
    current: &Path,
    acc: &mut Vec<OrganizationCustomSkillFileInput>,
) -> Result<()> {
    for entry in fs::read_dir(current)
        .with_context(|| format!("Failed to read directory {}", current.display()))?
    {
        let entry =
            entry.with_context(|| format!("Failed to read entry in {}", current.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_skill_files_recursive(root, &path, acc)?;
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("Failed to compute relative path for {}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes =
            fs::read(&path).with_context(|| format!("Failed to read file {}", path.display()))?;
        let content_base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        acc.push(OrganizationCustomSkillFileInput {
            relative_path: relative,
            content_type: infer_content_type(&path),
            content_base64,
        });
    }
    Ok(())
}

fn ensure_root_skill_md(files: &[OrganizationCustomSkillFileInput]) -> Result<()> {
    if files.iter().any(|file| file.relative_path == "SKILL.md") {
        return Ok(());
    }
    anyhow::bail!("Skill package must include a root SKILL.md file");
}

fn infer_content_type(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_string_lossy().to_ascii_lowercase();
    let content_type = match extension.as_str() {
        "md" => "text/markdown",
        "txt" => "text/plain",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "py" => "text/x-python",
        "js" => "text/javascript",
        "ts" => "text/typescript",
        "tsx" => "text/tsx",
        "jsx" => "text/jsx",
        "rs" => "text/rust",
        "sh" => "text/x-shellscript",
        "sql" => "application/sql",
        _ => return None,
    };
    Some(content_type.to_string())
}
