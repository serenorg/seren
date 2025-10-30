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

pub fn print_endpoint(endpoint: &seren::Endpoint, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(endpoint)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
            table.add_row(vec!["ID", &endpoint.id]);
            table.add_row(vec!["Name", &endpoint.name]);
            table.add_row(vec!["Branch ID", &endpoint.branch_id]);
            table.add_row(vec!["Status", &endpoint.status]);
            table.add_row(vec!["Compute Unit", &endpoint.compute_unit]);
            table.add_row(vec!["Autoscaling Min", &endpoint.autoscaling_min.to_string()]);
            table.add_row(vec!["Autoscaling Max", &endpoint.autoscaling_max.to_string()]);
            table.add_row(vec!["Suspend Timeout", &format!("{} seconds", endpoint.suspend_timeout_seconds)]);
            table.add_row(vec!["Connection String", &endpoint.connection_string]);
            table.add_row(vec!["Created At", &endpoint.created_at]);

            println!("{table}");
        }
    }
    Ok(())
}

// Connection String
pub fn print_connection_string(
    response: &seren::ConnectionStringResponse, 
    pooled: bool,
    prisma: bool,
    ssl: Option<&str>,
    format: OutputFormat
) -> anyhow::Result<()> {
    let mut conn_str = response.connection_string.clone();
    
    // Modify connection string based on flags
    if pooled {
        // For pooled connections, change the port to a pooler port (e.g., 6543 for PgBouncer)
        // This is a simplified implementation - in production you'd get this from the backend
        conn_str = conn_str.replace(":5432", ":6543");
    }
    
    // Add or modify SSL mode
    if let Some(ssl_mode) = ssl {
        // Remove existing sslmode if present
        let base_str = if let Some(idx) = conn_str.find('?') {
            let (base, query) = conn_str.split_at(idx);
            let params: Vec<&str> = query[1..].split('&').filter(|p| !p.starts_with("sslmode=")).collect();
            if params.is_empty() {
                base.to_string()
            } else {
                format!("{}?{}", base, params.join("&"))
            }
        } else {
            conn_str.clone()
        };
        
        // Add new sslmode
        conn_str = if base_str.contains('?') {
            format!("{}&sslmode={}", base_str, ssl_mode)
        } else {
            format!("{}?sslmode={}", base_str, ssl_mode)
        };
    }
    
    // Format for Prisma if requested
    if prisma {
        // Prisma format wraps the connection string in quotes and adds schema parameter
        let prisma_str = format!("DATABASE_URL=\"{}\"", conn_str);
        match format {
            OutputFormat::Json => {
                let json_obj = serde_json::json!({
                    "connection_string": conn_str,
                    "prisma_format": prisma_str
                });
                println!("{}", serde_json::to_string_pretty(&json_obj)?);
            }
            OutputFormat::Table => {
                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
                table.add_row(vec!["Prisma Format", &prisma_str]);

                println!("{table}");
            }
        }
    } else {
        match format {
            OutputFormat::Json => {
                let json_obj = serde_json::json!({
                    "connection_string": conn_str
                });
                println!("{}", serde_json::to_string_pretty(&json_obj)?);
            }
            OutputFormat::Table => {
                let mut table = Table::new();
                table
                    .load_preset(UTF8_FULL)
                    .set_content_arrangement(ContentArrangement::Dynamic);

                table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
                table.add_row(vec!["Connection String", &conn_str]);

                println!("{table}");
            }
        }
    }
    Ok(())
}

// Operations
pub fn print_operations_table(operations: &[seren::Operation]) {
    if operations.is_empty() {
        println!("No operations found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Type").fg(Color::Green),
        Cell::new("Resource Type").fg(Color::Green),
        Cell::new("Resource ID").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Progress").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for operation in operations {
        table.add_row(vec![
            Cell::new(&operation.id),
            Cell::new(&operation.operation_type),
            Cell::new(&operation.resource_type),
            Cell::new(&operation.resource_id),
            Cell::new(&operation.status),
            Cell::new(&format!("{}%", operation.progress)),
            Cell::new(&operation.created_at),
        ]);
    }

    println!("{table}");
}

// User
pub fn print_user(user: &seren::User) -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.add_row(vec![Cell::new("Field").fg(Color::Green), Cell::new("Value").fg(Color::Green)]);
    table.add_row(vec!["ID", &user.id]);
    table.add_row(vec!["Email", &user.email]);
    table.add_row(vec!["Name", &user.name]);
    if let Some(avatar) = &user.avatar_url {
        table.add_row(vec!["Avatar URL", avatar]);
    }
    table.add_row(vec!["Status", &user.status]);
    table.add_row(vec!["Created At", &user.created_at]);

    println!("{table}");
    Ok(())
}

// Organizations
pub fn print_organizations_table(organizations: &[seren::Organization]) {
    if organizations.is_empty() {
        println!("No organizations found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for org in organizations {
        table.add_row(vec![
            Cell::new(&org.id),
            Cell::new(&org.name),
            Cell::new(&org.slug),
            Cell::new(&org.created_at),
        ]);
    }

    println!("{table}");
}

// IP Allow Lists
pub fn print_ip_allow_lists_table(ips: &[seren::IpAllowList]) {
    if ips.is_empty() {
        println!("No IP addresses in allow list");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("IP Address").fg(Color::Green),
        Cell::new("Description").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for ip in ips {
        table.add_row(vec![
            Cell::new(&ip.id),
            Cell::new(&ip.ip_address),
            Cell::new(ip.description.as_deref().unwrap_or("-")),
            Cell::new(&ip.created_at),
        ]);
    }

    println!("{table}");
}
