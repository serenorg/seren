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

// Branches
pub fn print_branches_table(branches: &[seren::Branch]) {
    if branches.is_empty() {
        println!("No branches found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Project ID").fg(Color::Green),
        Cell::new("Timeline ID").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for branch in branches {
        table.add_row(vec![
            Cell::new(&branch.id),
            Cell::new(&branch.name),
            Cell::new(&branch.project_id),
            Cell::new(&branch.timeline_id),
            Cell::new(&branch.created_at),
        ]);
    }

    println!("{table}");
}

pub fn print_branch(branch: &seren::Branch, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(branch)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["ID", &branch.id]);
            table.add_row(vec!["Name", &branch.name]);
            table.add_row(vec!["Project ID", &branch.project_id]);
            table.add_row(vec!["Timeline ID", &branch.timeline_id]);
            if let Some(parent) = &branch.parent_branch_id {
                table.add_row(vec!["Parent Branch ID", parent]);
            }
            table.add_row(vec!["Created At", &branch.created_at]);

            println!("{table}");
        }
    }
    Ok(())
}

// Databases
pub fn print_databases_table(databases: &[seren::DatabaseWithOwner]) {
    if databases.is_empty() {
        println!("No databases found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Owner").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for db in databases {
        table.add_row(vec![
            Cell::new(&db.id),
            Cell::new(&db.name),
            Cell::new(db.owner_name.as_deref().unwrap_or("-")),
            Cell::new(&db.created_at),
        ]);
    }

    println!("{table}");
}

pub fn print_database(database: &seren::Database, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(database)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["ID", &database.id]);
            table.add_row(vec!["Name", &database.name]);
            table.add_row(vec!["Branch ID", &database.branch_id]);
            table.add_row(vec!["Created At", &database.created_at]);

            println!("{table}");
        }
    }
    Ok(())
}

// Roles
pub fn print_roles_table(roles: &[seren::Role]) {
    if roles.is_empty() {
        println!("No roles found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Protected").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for role in roles {
        table.add_row(vec![
            Cell::new(&role.id),
            Cell::new(&role.name),
            Cell::new(if role.protected { "Yes" } else { "No" }),
            Cell::new(&role.created_at),
        ]);
    }

    println!("{table}");
}

pub fn print_role_with_password(role: &seren::CreateRoleResponse, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(role)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["ID", &role.id]);
            table.add_row(vec!["Name", &role.name]);
            table.add_row(vec!["Branch ID", &role.branch_id]);
            table.add_row(vec!["Password", &role.password]);
            table.add_row(vec!["Created At", &role.created_at]);

            println!("{table}");
        }
    }
    Ok(())
}

// Endpoints
pub fn print_endpoints_table(endpoints: &[seren::Endpoint]) {
    if endpoints.is_empty() {
        println!("No endpoints found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Compute Unit").fg(Color::Green),
        Cell::new("Connection String").fg(Color::Green),
    ]);

    for endpoint in endpoints {
        table.add_row(vec![
            Cell::new(&endpoint.id),
            Cell::new(&endpoint.name),
            Cell::new(&endpoint.status),
            Cell::new(&endpoint.compute_unit),
            Cell::new(&endpoint.connection_string),
        ]);
    }

    println!("{table}");
}

// Connection String
pub fn print_connection_string(response: &seren::ConnectionStringResponse, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(response)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["Connection String", &response.connection_string]);

            println!("{table}");
        }
    }
    Ok(())
}
