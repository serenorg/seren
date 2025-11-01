use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use serde::Serialize;

use crate::OutputFormat;

pub fn print_json<T: Serialize + ?Sized>(data: &T) -> anyhow::Result<()> {
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
        Cell::new("Region").fg(Color::Green),
        Cell::new("CU Range").fg(Color::Green),
        Cell::new("Public?").fg(Color::Green),
        Cell::new("VPC Only?").fg(Color::Green),
        Cell::new("HIPAA?").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for project in projects {
        let cu_range = format!("{}-{}", project.compute_unit_min, project.compute_unit_max);
        table.add_row(vec![
            Cell::new(project.id.to_string()),
            Cell::new(&project.name),
            Cell::new(&project.region),
            Cell::new(cu_range),
            Cell::new(if project.block_public_connections {
                "No"
            } else {
                "Yes"
            }),
            Cell::new(if project.block_vpc_connections {
                "Yes"
            } else {
                "No"
            }),
            Cell::new(if project.hipaa { "Yes" } else { "No" }),
            Cell::new(project.created_at.to_string()),
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

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(project.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&project.name)]);
            table.add_row(vec![
                Cell::new("Organization ID"),
                Cell::new(project.organization_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Region"), Cell::new(&project.region)]);
            table.add_row(vec![
                Cell::new("Compute Units"),
                Cell::new(format!(
                    "{}-{}",
                    project.compute_unit_min, project.compute_unit_max
                )),
            ]);
            table.add_row(vec![
                Cell::new("Block Public Connections"),
                Cell::new(project.block_public_connections.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Block VPC Connections"),
                Cell::new(project.block_vpc_connections.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("HIPAA"),
                Cell::new(project.hipaa.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Protected Branches Only"),
                Cell::new(project.protected_branches_only.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(project.created_at.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Updated At"),
                Cell::new(project.updated_at.to_string()),
            ]);

            println!("{table}");
        }
    }
    Ok(())
}

pub fn print_create_project_response(
    response: &seren::CreateProjectResponse,
    format: OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(response)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(response.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&response.name)]);
            table.add_row(vec![
                Cell::new("Organization ID"),
                Cell::new(response.organization_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Region"), Cell::new(&response.region)]);
            table.add_row(vec![
                Cell::new("Compute Units"),
                Cell::new(format!(
                    "{}-{}",
                    response.compute_unit_min, response.compute_unit_max
                )),
            ]);
            table.add_row(vec![
                Cell::new("Block Public Connections"),
                Cell::new(response.block_public_connections.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Block VPC Connections"),
                Cell::new(response.block_vpc_connections.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("HIPAA"),
                Cell::new(response.hipaa.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Protected Branches Only"),
                Cell::new(response.protected_branches_only.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(response.created_at.to_string()),
            ]);

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
        Cell::new("Protected").fg(Color::Green),
        Cell::new("Archived").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for branch in branches {
        table.add_row(vec![
            Cell::new(branch.id.to_string()),
            Cell::new(&branch.name),
            Cell::new(branch.project_id.to_string()),
            Cell::new(&branch.timeline_id),
            Cell::new(if branch.protected { "Yes" } else { "No" }),
            Cell::new(if branch.archived { "Yes" } else { "No" }),
            Cell::new(branch.created_at.to_string()),
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

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(branch.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&branch.name)]);
            table.add_row(vec![
                Cell::new("Project ID"),
                Cell::new(branch.project_id.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Timeline ID"),
                Cell::new(&branch.timeline_id),
            ]);
            if let Some(parent) = &branch.parent_branch_id {
                table.add_row(vec![
                    Cell::new("Parent Branch ID"),
                    Cell::new(parent.to_string()),
                ]);
            }
            table.add_row(vec![
                Cell::new("Protected"),
                Cell::new(if branch.protected { "Yes" } else { "No" }),
            ]);
            table.add_row(vec![
                Cell::new("Archived"),
                Cell::new(if branch.archived { "Yes" } else { "No" }),
            ]);
            if let Some(source) = &branch.init_source {
                table.add_row(vec![Cell::new("Init Source"), Cell::new(source)]);
            }
            if let Some(lsn) = &branch.parent_lsn {
                table.add_row(vec![Cell::new("Parent LSN"), Cell::new(lsn)]);
            }
            if let Some(ts) = branch.parent_timestamp {
                table.add_row(vec![
                    Cell::new("Parent Timestamp"),
                    Cell::new(ts.to_string()),
                ]);
            }
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(branch.created_at.to_string()),
            ]);

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
            Cell::new(db.id.to_string()),
            Cell::new(&db.name),
            Cell::new(db.owner_name.as_deref().unwrap_or("-")),
            Cell::new(db.created_at.to_string()),
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

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(database.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&database.name)]);
            table.add_row(vec![
                Cell::new("Branch ID"),
                Cell::new(database.branch_id.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(database.created_at.to_string()),
            ]);

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
            Cell::new(role.id.to_string()),
            Cell::new(&role.name),
            Cell::new(if role.protected { "Yes" } else { "No" }),
            Cell::new(role.created_at.to_string()),
        ]);
    }

    println!("{table}");
}

pub fn print_role_with_password(
    role: &seren::CreateRoleResponse,
    format: OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(role)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(role.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&role.name)]);
            table.add_row(vec![
                Cell::new("Branch ID"),
                Cell::new(role.branch_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Password"), Cell::new(&role.password)]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(role.created_at.to_string()),
            ]);

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
            Cell::new(endpoint.id.to_string()),
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

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(endpoint.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&endpoint.name)]);
            table.add_row(vec![
                Cell::new("Branch ID"),
                Cell::new(endpoint.branch_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Status"), Cell::new(&endpoint.status)]);
            table.add_row(vec![
                Cell::new("Compute Unit"),
                Cell::new(&endpoint.compute_unit),
            ]);
            table.add_row(vec![
                "Autoscaling Min",
                &endpoint.autoscaling_min.to_string(),
            ]);
            table.add_row(vec![
                "Autoscaling Max",
                &endpoint.autoscaling_max.to_string(),
            ]);
            table.add_row(vec![
                "Suspend Timeout",
                &format!("{} seconds", endpoint.suspend_timeout_seconds),
            ]);
            table.add_row(vec![
                Cell::new("Connection String"),
                Cell::new(&endpoint.connection_string),
            ]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(endpoint.created_at.to_string()),
            ]);

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
    format: OutputFormat,
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
            let params: Vec<&str> = query[1..]
                .split('&')
                .filter(|p| !p.starts_with("sslmode="))
                .collect();
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

                table.add_row(vec![
                    Cell::new("Field").fg(Color::Green),
                    Cell::new("Value").fg(Color::Green),
                ]);
                table.add_row(vec![Cell::new("Prisma Format"), Cell::new(&prisma_str)]);

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

                table.add_row(vec![
                    Cell::new("Field").fg(Color::Green),
                    Cell::new("Value").fg(Color::Green),
                ]);
                table.add_row(vec![Cell::new("Connection String"), Cell::new(&conn_str)]);

                println!("{table}");
            }
        }
    }
    Ok(())
}

pub fn print_project_connection_uri(
    response: &seren::ProjectConnectionUriResponse,
    pooled: bool,
    prisma: bool,
    ssl: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let wrapper = seren::ConnectionStringResponse {
        connection_string: response.uri.clone(),
    };
    print_connection_string(&wrapper, pooled, prisma, ssl, format)
}

pub fn print_created_endpoints(
    endpoints: &[seren::CreateEndpointResponse],
    format: OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(endpoints)?,
        OutputFormat::Table => {
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
                    Cell::new(endpoint.id.to_string()),
                    Cell::new(&endpoint.name),
                    Cell::new(&endpoint.status),
                    Cell::new(&endpoint.compute_unit),
                    Cell::new(&endpoint.connection_string),
                ]);
            }

            println!("{}", "Provisioned Endpoints".green().bold());
            println!("{table}");
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
            Cell::new(operation.id.to_string()),
            Cell::new(&operation.operation_type),
            Cell::new(&operation.resource_type),
            Cell::new(operation.resource_id.to_string()),
            Cell::new(&operation.status),
            Cell::new(&format!("{}%", operation.progress)),
            Cell::new(operation.created_at.to_string()),
        ]);
    }

    println!("{table}");
}

pub fn print_operation(operation: &seren::Operation, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(operation)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.add_row(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);
            table.add_row(vec![Cell::new("ID"), Cell::new(operation.id.to_string())]);
            table.add_row(vec![
                Cell::new("Type"),
                Cell::new(&operation.operation_type),
            ]);
            table.add_row(vec![
                Cell::new("Resource Type"),
                Cell::new(&operation.resource_type),
            ]);
            table.add_row(vec![
                Cell::new("Resource ID"),
                Cell::new(operation.resource_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Status"), Cell::new(&operation.status)]);
            table.add_row(vec![
                Cell::new("Progress"),
                Cell::new(format!("{}%", operation.progress)),
            ]);
            table.add_row(vec![
                Cell::new("Created By"),
                Cell::new(operation.created_by.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(operation.created_at.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Updated At"),
                Cell::new(operation.updated_at.to_string()),
            ]);
            if let Some(started_at) = &operation.started_at {
                table.add_row(vec![
                    Cell::new("Started At"),
                    Cell::new(started_at.to_string()),
                ]);
            }
            if let Some(completed_at) = &operation.completed_at {
                table.add_row(vec![
                    Cell::new("Completed At"),
                    Cell::new(completed_at.to_string()),
                ]);
            }
            if let Some(error) = &operation.error_message {
                table.add_row(vec!["Error", error]);
            }
            if let Some(metadata) = &operation.metadata {
                table.add_row(vec!["Metadata", &metadata.to_string()]);
            }

            println!("{table}");
        }
    }

    Ok(())
}

// User
pub fn print_user(user: &seren::User) -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.add_row(vec![
        Cell::new("Field").fg(Color::Green),
        Cell::new("Value").fg(Color::Green),
    ]);
    table.add_row(vec![Cell::new("ID"), Cell::new(user.id.to_string())]);
    table.add_row(vec![Cell::new("Email"), Cell::new(&user.email)]);
    table.add_row(vec![Cell::new("Name"), Cell::new(&user.name)]);
    if let Some(avatar) = &user.avatar_url {
        table.add_row(vec![Cell::new("Avatar URL"), Cell::new(avatar)]);
    }
    table.add_row(vec![
        Cell::new("Status"),
        Cell::new(format!("{:?}", user.status)),
    ]);
    table.add_row(vec![
        Cell::new("Created At"),
        Cell::new(user.created_at.to_string()),
    ]);

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
pub fn print_ip_allow_list_table(ips: &[seren::IpAllowList]) {
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

// VPC Endpoints
pub fn print_org_vpc_endpoints_table(endpoints: &[seren::OrganizationVpcEndpoint]) {
    if endpoints.is_empty() {
        println!("No VPC endpoints configured");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Endpoint ID").fg(Color::Green),
        Cell::new("Region").fg(Color::Green),
        Cell::new("Label").fg(Color::Green),
        Cell::new("State").fg(Color::Green),
        Cell::new("Updated").fg(Color::Green),
    ]);

    for endpoint in endpoints {
        table.add_row(vec![
            Cell::new(&endpoint.id),
            Cell::new(&endpoint.endpoint_id),
            Cell::new(&endpoint.region),
            Cell::new(endpoint.label.as_deref().unwrap_or("-")),
            Cell::new(&endpoint.state),
            Cell::new(&endpoint.updated_at),
        ]);
    }

    println!("{table}");
}

pub fn print_project_vpc_endpoints_table(assignments: &[seren::ProjectVpcEndpointAssignment]) {
    if assignments.is_empty() {
        println!("No project VPC endpoint restrictions");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Assignment ID").fg(Color::Green),
        Cell::new("Endpoint ID").fg(Color::Green),
        Cell::new("Region").fg(Color::Green),
        Cell::new("Assignment Label").fg(Color::Green),
        Cell::new("Endpoint Label").fg(Color::Green),
        Cell::new("Updated").fg(Color::Green),
    ]);

    for assignment in assignments {
        table.add_row(vec![
            Cell::new(assignment.id.to_string()),
            Cell::new(&assignment.endpoint_id),
            Cell::new(&assignment.region),
            Cell::new(assignment.label.as_deref().unwrap_or("-")),
            Cell::new(assignment.endpoint_label.as_deref().unwrap_or("-")),
            Cell::new(assignment.updated_at.to_string()),
        ]);
    }

    println!("{table}");
}

// Schema Diff
pub fn print_schema_diff(diff: &seren::SchemaDiff, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(diff)?,
        OutputFormat::Table => {
            use seren::{SchemaDifference, TableChange};

            println!();
            println!(
                "{}",
                format!(
                    "Schema Diff: {} → {}",
                    diff.base_branch_id, diff.compare_branch_id
                )
                .bold()
            );
            println!();

            if diff.differences.is_empty() {
                println!("{}", "✓ No schema differences found".green());
                return Ok(());
            }

            println!(
                "{}",
                format!("Found {} difference(s):", diff.differences.len()).yellow()
            );
            println!();

            for difference in &diff.differences {
                match difference {
                    SchemaDifference::TableAdded {
                        table_name,
                        schema_name,
                    } => {
                        println!(
                            "{} {}",
                            "+".green().bold(),
                            format!("Table added: {}.{}", schema_name, table_name).green()
                        );
                    }
                    SchemaDifference::TableRemoved {
                        table_name,
                        schema_name,
                    } => {
                        println!(
                            "{} {}",
                            "-".red().bold(),
                            format!("Table removed: {}.{}", schema_name, table_name).red()
                        );
                    }
                    SchemaDifference::TableModified {
                        table_name,
                        schema_name,
                        changes,
                    } => {
                        println!(
                            "{} {}",
                            "~".yellow().bold(),
                            format!("Table modified: {}.{}", schema_name, table_name).yellow()
                        );
                        for change in changes {
                            match change {
                                TableChange::ColumnAdded {
                                    column_name,
                                    data_type,
                                    is_nullable,
                                } => {
                                    let nullable = if *is_nullable { "NULL" } else { "NOT NULL" };
                                    println!(
                                        "  {} Column added: {} {} {}",
                                        "+".green(),
                                        column_name,
                                        data_type,
                                        nullable
                                    );
                                }
                                TableChange::ColumnRemoved {
                                    column_name,
                                    data_type,
                                } => {
                                    println!(
                                        "  {} Column removed: {} {}",
                                        "-".red(),
                                        column_name,
                                        data_type
                                    );
                                }
                                TableChange::ColumnModified {
                                    column_name,
                                    old_type,
                                    new_type,
                                    nullable_changed,
                                } => {
                                    println!("  {} Column modified: {}", "~".yellow(), column_name);
                                    println!("    Type: {} → {}", old_type, new_type);
                                    if let Some(nullable) = nullable_changed {
                                        println!(
                                            "    Nullable: {}",
                                            if *nullable {
                                                "now NULL"
                                            } else {
                                                "now NOT NULL"
                                            }
                                        );
                                    }
                                }
                                TableChange::IndexAdded {
                                    index_name,
                                    is_unique,
                                    columns,
                                } => {
                                    let unique = if *is_unique { "UNIQUE " } else { "" };
                                    println!(
                                        "  {} {}Index added: {} on ({})",
                                        "+".green(),
                                        unique,
                                        index_name,
                                        columns.join(", ")
                                    );
                                }
                                TableChange::IndexRemoved { index_name } => {
                                    println!("  {} Index removed: {}", "-".red(), index_name);
                                }
                                TableChange::ConstraintAdded {
                                    constraint_name,
                                    constraint_type,
                                } => {
                                    println!(
                                        "  {} Constraint added: {} ({})",
                                        "+".green(),
                                        constraint_name,
                                        constraint_type
                                    );
                                }
                                TableChange::ConstraintRemoved {
                                    constraint_name,
                                    constraint_type,
                                } => {
                                    println!(
                                        "  {} Constraint removed: {} ({})",
                                        "-".red(),
                                        constraint_name,
                                        constraint_type
                                    );
                                }
                            }
                        }
                    }
                }
                println!();
            }
        }
    }
    Ok(())
}
