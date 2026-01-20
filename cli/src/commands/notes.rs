use anyhow::Result;
use colored::Colorize;
use comfy_table::{Cell, Color, Table, presets::UTF8_FULL_CONDENSED};
use seren::{
    AddTagsRequest, AppendToNoteRequest, CreateNoteRequest, NoteFormat, RemoveTagsRequest,
    UpdateNoteRequest,
};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn create(
    title: &str,
    content: &str,
    format: NoteFormat,
    parent_id: Option<&str>,
    tags: Option<Vec<String>>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let parent_uuid = parent_id
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid parent ID: {}", e))?;

    let request = CreateNoteRequest {
        title: title.to_string(),
        content: content.to_string(),
        format: Some(format),
        parent_id: parent_uuid,
        tags,
        idempotency_key: None,
    };

    let response = client
        .create_note(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create note: {}", e))?;

    let note = response.into_inner();
    println!("{}", "Note created successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&note)?,
        OutputFormat::Table => print_note(&note.data),
    }

    Ok(())
}

pub async fn get(note_id: &str, format: NoteFormat, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    let format_str = match format {
        NoteFormat::Markdown => "markdown",
        NoteFormat::Org => "org",
        NoteFormat::Json => "json",
    };

    let response = client
        .get_note(&note_uuid, Some(format_str))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get note: {}", e))?;

    let note = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&note)?,
        OutputFormat::Table => print_note(&note.data),
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn update(
    note_id: &str,
    title: Option<&str>,
    content: Option<&str>,
    format: NoteFormat,
    parent_id: Option<&str>,
    is_archived: Option<bool>,
    is_pinned: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    let parent_uuid = parent_id
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid parent ID: {}", e))?;

    let request = UpdateNoteRequest {
        title: title.map(|s| s.to_string()),
        content: content.map(|s| s.to_string()),
        format: Some(format),
        parent_id: parent_uuid,
        is_archived,
        is_pinned,
        expected_version: None,
    };

    let response = client
        .update_note(&note_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update note: {}", e))?;

    let note = response.into_inner();
    println!("{}", "Note updated successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&note)?,
        OutputFormat::Table => print_note(&note.data),
    }

    Ok(())
}

pub async fn delete(note_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    client
        .delete_note(&note_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete note: {}", e))?;

    println!(
        "{}",
        format!("Note {} deleted successfully!", note_id)
            .green()
            .bold()
    );

    Ok(())
}

pub async fn list(
    parent_id: Option<&str>,
    tag: Option<&str>,
    include_archived: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let parent_uuid = parent_id
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid parent ID: {}", e))?;

    let response = client
        .list_notes(include_archived, limit, offset, parent_uuid.as_ref(), tag)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list notes: {}", e))?;

    let notes = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&notes)?,
        OutputFormat::Table => print_notes_table(&notes.data),
    }

    Ok(())
}

pub async fn search(
    query: &str,
    include_archived: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .search_notes(include_archived, limit, offset, query)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to search notes: {}", e))?;

    let notes = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&notes)?,
        OutputFormat::Table => {
            println!("{}: {}", "Search query".bold(), query);
            println!();
            print_notes_table(&notes.data);
        }
    }

    Ok(())
}

pub async fn append(
    note_id: &str,
    content: &str,
    format: NoteFormat,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    let request = AppendToNoteRequest {
        content: content.to_string(),
        format: Some(format),
        idempotency_key: None,
    };

    let response = client
        .append_to_note(&note_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to append to note: {}", e))?;

    let note = response.into_inner();
    println!("{}", "Content appended successfully!".green().bold());
    println!();

    match ctx.format {
        OutputFormat::Json => output::print_json(&note)?,
        OutputFormat::Table => print_note(&note.data),
    }

    Ok(())
}

pub async fn add_tags(note_id: &str, tags: Vec<String>, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    let request = AddTagsRequest { tags: tags.clone() };

    let response = client
        .add_tags(&note_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add tags: {}", e))?;

    let note = response.into_inner();
    println!(
        "{}",
        format!("Tags added: {}", tags.join(", ")).green().bold()
    );
    println!();
    println!("{}: {:?}", "Current tags".bold(), note.data.tags);

    Ok(())
}

pub async fn remove_tags(note_id: &str, tags: Vec<String>, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let note_uuid =
        Uuid::parse_str(note_id).map_err(|e| anyhow::anyhow!("Invalid note ID: {}", e))?;

    let request = RemoveTagsRequest { tags: tags.clone() };

    let response = client
        .remove_tags(&note_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove tags: {}", e))?;

    let note = response.into_inner();
    println!(
        "{}",
        format!("Tags removed: {}", tags.join(", ")).green().bold()
    );
    println!();
    println!("{}: {:?}", "Remaining tags".bold(), note.data.tags);

    Ok(())
}

pub async fn list_tags(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_tags()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list tags: {}", e))?;

    let tags = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&tags)?,
        OutputFormat::Table => {
            if tags.data.is_empty() {
                println!("{}", "No tags found.".yellow());
            } else {
                println!("{}", "Tags:".bold());
                for tag in &tags.data {
                    println!("  - {}", tag);
                }
                println!();
                println!("{}", format!("Total: {} tag(s)", tags.data.len()).dimmed());
            }
        }
    }

    Ok(())
}

// Helper functions for table output

fn print_note(note: &seren::NoteResponse) {
    println!("{}: {}", "ID".bold(), note.id);
    println!("{}: {}", "Title".bold(), note.title);
    println!("{}: v{}", "Version".bold(), note.version);
    if let Some(parent_id) = &note.parent_id {
        println!("{}: {}", "Parent".bold(), parent_id);
    }
    println!(
        "{}: {}",
        "Pinned".bold(),
        if note.is_pinned { "Yes" } else { "No" }
    );
    println!(
        "{}: {}",
        "Archived".bold(),
        if note.is_archived { "Yes" } else { "No" }
    );
    if !note.tags.is_empty() {
        println!("{}: {}", "Tags".bold(), note.tags.join(", "));
    }
    println!("{}: {}", "Created".bold(), note.created_at);
    println!("{}: {}", "Updated".bold(), note.updated_at);
    println!();
    println!("{}", "Content:".bold());
    println!("{}", "-".repeat(40));
    println!("{}", note.content);
}

fn print_notes_table(notes: &[seren::NoteSummary]) {
    if notes.is_empty() {
        println!("{}", "No notes found.".yellow());
        return;
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec![
        Cell::new("ID").fg(Color::Cyan),
        Cell::new("Title").fg(Color::Cyan),
        Cell::new("Excerpt").fg(Color::Cyan),
        Cell::new("Pin").fg(Color::Cyan),
        Cell::new("Updated").fg(Color::Cyan),
    ]);

    for note in notes {
        let pin_str = if note.is_pinned { "📌" } else { "" };
        let excerpt = if note.excerpt.len() > 30 {
            format!("{}...", &note.excerpt[..27])
        } else {
            note.excerpt.clone()
        };

        table.add_row(vec![
            Cell::new(note.id.to_string().chars().take(8).collect::<String>() + "..."),
            Cell::new(&note.title).fg(Color::Green),
            Cell::new(excerpt),
            Cell::new(pin_str),
            Cell::new(&note.updated_at.to_string()[..10]),
        ]);
    }

    println!("{table}");
    println!();
    println!("{}", format!("Total: {} note(s)", notes.len()).dimmed());
}
