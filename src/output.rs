use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use serde::Serialize;

use crate::OutputFormat;

pub fn print_json<T: Serialize>(data: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    println!("{}", json);
    Ok(())
}

pub fn print_projects_table(projects: &[seren::Project]) {
    if projects.is_empty() {
        println!("No projects found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Organization ID").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for project in projects {
        table.add_row(vec![
            Cell::new(&project.id),
            Cell::new(&project.name),
            Cell::new(&project.organization_id),
            Cell::new(&project.created_at),
        ]);
    }

    println!("{table}");
}

pub fn print_project(project: &seren::Project, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(project)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["ID", &project.id]);
            table.add_row(vec!["Name", &project.name]);
            table.add_row(vec!["Organization ID", &project.organization_id]);
            table.add_row(vec!["Created At", &project.created_at]);
            table.add_row(vec!["Updated At", &project.updated_at]);

            println!("{table}");
        }
    }
    Ok(())
}
