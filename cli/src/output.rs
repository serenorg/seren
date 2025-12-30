use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use serde::Serialize;

use crate::OutputFormat;

/// Apply or replace the `sslmode` query parameter in a PostgreSQL connection string.
pub fn apply_sslmode(dsn: &str, ssl_mode: &str) -> String {
    if let Some(idx) = dsn.find('?') {
        let (base, query) = dsn.split_at(idx);
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
    } else if dsn.is_empty() {
        dsn.to_string()
    } else {
        format!("{}?sslmode={}", dsn, ssl_mode)
    }
}

pub fn print_json<T: Serialize + ?Sized>(data: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    println!("{}", json);
    Ok(())
}

pub fn print_key_value_table(title: Option<&str>, rows: &[(&str, String)]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Field").fg(Color::Green),
        Cell::new("Value").fg(Color::Green),
    ]);

    for (field, value) in rows {
        table.add_row(vec![Cell::new(*field), Cell::new(value)]);
    }

    if let Some(title) = title {
        if !title.is_empty() {
            println!("{}", title.bold());
        }
    }
    println!("{table}");
}

pub fn print_list_table<T: std::fmt::Display>(title: Option<&str>, header: &str, items: &[T]) {
    if items.is_empty() {
        println!("No results found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![Cell::new(header).fg(Color::Green)]);
    for item in items {
        table.add_row(vec![Cell::new(item.to_string())]);
    }

    if let Some(title) = title {
        if !title.is_empty() {
            println!("{}", title.bold());
        }
    }
    println!("{table}");
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
        let cu_range = format!(
            "{}-{} (plan cap {})",
            project.compute_unit_min, project.compute_unit_max, project.compute_unit_max
        );
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
                    "{}-{} (plan cap {})",
                    project.compute_unit_min, project.compute_unit_max, project.compute_unit_max
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
    project: &seren::ProjectCreated,
    format: OutputFormat,
) -> anyhow::Result<()> {
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
            Cell::new(branch.timeline_id),
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
                Cell::new(branch.timeline_id),
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

// Billing: usage summaries
pub fn print_usage_summaries_table(summaries: &[seren::UsageSummary]) {
    if summaries.is_empty() {
        println!("No usage data found for the specified period");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Project").fg(Color::Green),
        Cell::new("Region").fg(Color::Green),
        Cell::new("Period").fg(Color::Green),
        Cell::new("Compute (hrs)").fg(Color::Green),
        Cell::new("Storage (GB)").fg(Color::Green),
        Cell::new("PITR (GB)").fg(Color::Green),
        Cell::new("Compute $").fg(Color::Green),
        Cell::new("Storage $").fg(Color::Green),
        Cell::new("Total $").fg(Color::Green),
    ]);

    let mut grand_total = 0.0f64;

    for summary in summaries {
        let compute_hours_total = summary.compute_hours_small
            + summary.compute_hours_medium
            + summary.compute_hours_large
            + summary.compute_hours_xlarge;

        grand_total += summary.total_cost_usd;

        let project_label = if !summary.project_name.is_empty() {
            summary.project_name.clone()
        } else {
            summary.project_id.to_string()
        };

        let region_label = if summary.project_region.is_empty() {
            "-".to_string()
        } else {
            summary.project_region.clone()
        };

        table.add_row(vec![
            Cell::new(project_label),
            Cell::new(region_label),
            Cell::new(format!("{} → {}", summary.period_start, summary.period_end)),
            Cell::new(format!("{:.2}", compute_hours_total)),
            Cell::new(format!("{:.2}", summary.storage_gb_avg)),
            Cell::new(format!("{:.2}", summary.pitr_gb_avg)),
            Cell::new(format!("{:.2}", summary.compute_cost_usd)),
            Cell::new(format!("{:.2}", summary.storage_cost_usd)),
            Cell::new(format!("{:.2}", summary.total_cost_usd)),
        ]);
    }

    println!("{}", "Usage Summary".bold());
    println!("{table}");
    println!(
        "\n{}",
        format!("Total Cost: ${:.2}", grand_total).green().bold()
    );
}

// Billing: payment methods
pub fn print_payment_methods_table(methods: &[seren::PaymentMethod]) {
    if methods.is_empty() {
        println!("No payment methods found.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Brand").fg(Color::Green),
        Cell::new("Last4").fg(Color::Green),
        Cell::new("Expires").fg(Color::Green),
        Cell::new("Type").fg(Color::Green),
        Cell::new("Default").fg(Color::Green),
    ]);

    for method in methods {
        let brand = method
            .card_brand
            .as_deref()
            .unwrap_or(match method.type_.as_str() {
                "us_bank_account" => "Bank account",
                _ => "Payment method",
            });

        let last4 = method
            .card_last4
            .as_deref()
            .or(method.bank_last4.as_deref())
            .unwrap_or("????");

        let expires = match (method.card_exp_month, method.card_exp_year) {
            (Some(m), Some(y)) => format!("{}/{}", m, y),
            _ => "-".to_string(),
        };

        table.add_row(vec![
            Cell::new(brand),
            Cell::new(last4),
            Cell::new(expires),
            Cell::new(&method.type_),
            Cell::new(if method.is_default { "Yes" } else { "" }),
        ]);
    }

    println!("{}", "Payment Methods".bold());
    println!("{table}");
}

// Billing: health summary
pub fn print_billing_health_table(health: &seren::BillingHealthResponse) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Field").fg(Color::Green),
        Cell::new("Value").fg(Color::Green),
    ]);

    table.add_row(vec![
        Cell::new("Daily aggregation"),
        Cell::new(if health.data.daily_aggregation_ok {
            "OK"
        } else {
            "Attention"
        }),
    ]);
    table.add_row(vec![
        Cell::new("Last daily run"),
        Cell::new(
            health
                .data
                .last_daily_aggregation_run_utc
                .as_deref()
                .unwrap_or("never"),
        ),
    ]);
    table.add_row(vec![
        Cell::new("Has recent daily run"),
        Cell::new(if health.data.has_recent_daily_run {
            "Yes"
        } else {
            "No"
        }),
    ]);
    table.add_row(vec![
        Cell::new("Daily aggregation failures"),
        Cell::new(health.data.daily_aggregation_failures_total.to_string()),
    ]);

    println!("{}", "Billing Health".bold());
    println!("{table}");

    if !health.data.jobs.is_empty() {
        let mut jobs_table = Table::new();
        jobs_table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic);

        jobs_table.set_header(vec![
            Cell::new("Job").fg(Color::Green),
            Cell::new("Failures").fg(Color::Green),
        ]);

        for job in &health.data.jobs {
            jobs_table.add_row(vec![
                Cell::new(&job.job),
                Cell::new(job.failures_total.to_string()),
            ]);
        }

        println!();
        println!("{}", "Job Failures (since last restart)".bold());
        println!("{jobs_table}");
    }
}

fn debug_trim_quotes<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}").trim_matches('"').to_string()
}

fn join_categories(categories: &[String], max: usize) -> String {
    let joined = categories
        .iter()
        .take(max)
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if categories.len() > max {
        format!("{joined}…")
    } else {
        joined
    }
}

pub fn print_publishers_table(publishers: &[seren::PublisherResponse]) {
    if publishers.is_empty() {
        println!("No publishers found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Source").fg(Color::Green),
        Cell::new("Active").fg(Color::Green),
        Cell::new("Verified").fg(Color::Green),
        Cell::new("Resource").fg(Color::Green),
        Cell::new("Categories").fg(Color::Green),
        Cell::new("Base Price").fg(Color::Green),
    ]);

    for publisher in publishers {
        let categories = if publisher.categories.is_empty() {
            "-".to_string()
        } else {
            join_categories(&publisher.categories, 5)
        };

        let base_price = publisher
            .pricing
            .as_ref()
            .and_then(|prices| prices.first())
            .map(|p| {
                let symbol = p.asset_symbol.as_deref().unwrap_or("?");
                format!("{} {}/1000", p.base_price_per_1000_rows, symbol)
            })
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![
            Cell::new(publisher.id.to_string()),
            Cell::new(&publisher.slug),
            Cell::new(&publisher.name),
            Cell::new(debug_trim_quotes(&publisher.source_type)),
            Cell::new(if publisher.is_active { "Yes" } else { "No" }),
            Cell::new(if publisher.is_verified { "Yes" } else { "No" }),
            Cell::new(publisher.resource_name.as_deref().unwrap_or("-")),
            Cell::new(categories),
            Cell::new(base_price),
        ]);
    }

    println!("{}", "Marketplace Publishers".bold());
    println!("{table}");
}

pub fn print_marketplace_publisher(
    publisher: &seren::PublisherResponse,
    format: OutputFormat,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => print_json(publisher)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.set_header(vec![
                Cell::new("Field").fg(Color::Green),
                Cell::new("Value").fg(Color::Green),
            ]);

            table.add_row(vec![Cell::new("ID"), Cell::new(publisher.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&publisher.name)]);
            table.add_row(vec![Cell::new("Slug"), Cell::new(&publisher.slug)]);
            table.add_row(vec![
                Cell::new("Publisher Type"),
                Cell::new(debug_trim_quotes(&publisher.publisher_type)),
            ]);
            table.add_row(vec![
                Cell::new("Source Type"),
                Cell::new(debug_trim_quotes(&publisher.source_type)),
            ]);
            table.add_row(vec![
                Cell::new("Active"),
                Cell::new(if publisher.is_active { "Yes" } else { "No" }),
            ]);
            table.add_row(vec![
                Cell::new("Verified"),
                Cell::new(if publisher.is_verified { "Yes" } else { "No" }),
            ]);
            if let Some(name) = &publisher.resource_name {
                table.add_row(vec![Cell::new("Resource Name"), Cell::new(name)]);
            }
            if let Some(desc) = publisher
                .resource_description
                .as_ref()
                .or(publisher.description.as_ref())
            {
                table.add_row(vec![Cell::new("Description"), Cell::new(desc)]);
            }
            if !publisher.categories.is_empty() {
                table.add_row(vec![
                    Cell::new("Categories"),
                    Cell::new(publisher.categories.join(", ")),
                ]);
            }
            table.add_row(vec![
                Cell::new("Wallet Address"),
                Cell::new(&publisher.wallet_address),
            ]);
            table.add_row(vec![
                Cell::new("Wallet Network"),
                Cell::new(&publisher.wallet_network_id),
            ]);
            table.add_row(vec![
                Cell::new("Total Queries"),
                Cell::new(publisher.total_queries.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Agents Served"),
                Cell::new(publisher.unique_agents_served.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Created"),
                Cell::new(publisher.created_at.to_string()),
            ]);
            table.add_row(vec![
                Cell::new("Updated"),
                Cell::new(publisher.updated_at.to_string()),
            ]);

            println!("{}", "Publisher Details".bold());
            println!("{table}");

            if let Some(pricing) = &publisher.pricing {
                if !pricing.is_empty() {
                    let mut pricing_table = Table::new();
                    pricing_table
                        .load_preset(UTF8_FULL)
                        .set_content_arrangement(ContentArrangement::Dynamic);

                    pricing_table.set_header(vec![
                        Cell::new("Asset").fg(Color::Green),
                        Cell::new("Model").fg(Color::Green),
                        Cell::new("Base/1000").fg(Color::Green),
                        Cell::new("Min Charge").fg(Color::Green),
                        Cell::new("Markup").fg(Color::Green),
                        Cell::new("Prepaid").fg(Color::Green),
                        Cell::new("On-chain").fg(Color::Green),
                    ]);

                    for p in pricing {
                        let asset = p.asset_symbol.as_deref().unwrap_or("Unknown");
                        pricing_table.add_row(vec![
                            Cell::new(asset),
                            Cell::new(debug_trim_quotes(&p.pricing_model)),
                            Cell::new(&p.base_price_per_1000_rows),
                            Cell::new(&p.min_charge),
                            Cell::new(&p.markup_multiplier),
                            Cell::new(if p.prepaid_enabled { "Yes" } else { "No" }),
                            Cell::new(if p.onchain_enabled { "Yes" } else { "No" }),
                        ]);
                    }

                    println!();
                    println!("{}", "Pricing".bold());
                    println!("{pricing_table}");
                }
            }

            if let Some(usage) = &publisher.usage_example {
                println!();
                println!("{}", "Usage Example".bold());
                println!("{}", serde_json::to_string_pretty(usage)?);
            }
        }
    }

    Ok(())
}

pub fn print_database(
    database: &seren::DatabaseCreated,
    format: OutputFormat,
) -> anyhow::Result<()> {
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
pub fn print_roles_table(roles: &[seren::RoleInfo]) {
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
    role: &seren::RoleCreatedResponse,
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
            table.add_row(vec![Cell::new("ID"), Cell::new(role.data.id.to_string())]);
            table.add_row(vec![Cell::new("Name"), Cell::new(&role.data.name)]);
            table.add_row(vec![
                Cell::new("Branch ID"),
                Cell::new(role.data.branch_id.to_string()),
            ]);
            table.add_row(vec![Cell::new("Password"), Cell::new(&role.data.password)]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(role.data.created_at.to_string()),
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
        Cell::new("Connection String (Direct)").fg(Color::Green),
    ]);

    for endpoint in endpoints {
        let conn_str = endpoint
            .connection_string_direct
            .as_deref()
            .or(endpoint.connection_string.as_deref())
            .unwrap_or("");
        table.add_row(vec![
            Cell::new(endpoint.id.to_string()),
            Cell::new(&endpoint.name),
            Cell::new(&endpoint.status),
            Cell::new(&endpoint.compute_unit),
            Cell::new(conn_str),
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
            let conn_str = endpoint
                .connection_string_direct
                .as_deref()
                .or(endpoint.connection_string.as_deref())
                .unwrap_or("");
            table.add_row(vec![Cell::new("Connection String"), Cell::new(conn_str)]);
            table.add_row(vec![
                Cell::new("Created At"),
                Cell::new(endpoint.created_at.to_string()),
            ]);

            println!("{table}");
        }
    }
    Ok(())
}

pub fn print_create_endpoint_response(
    endpoint: &seren::EndpointCreated,
    format: OutputFormat,
) -> anyhow::Result<()> {
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
            let conn_str = endpoint
                .connection_string_direct
                .as_deref()
                .or(endpoint.connection_string.as_deref())
                .unwrap_or("");
            table.add_row(vec![Cell::new("Connection String"), Cell::new(conn_str)]);
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
    response: &seren::ConnectionString,
    ssl: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // Start from the single canonical connection string returned by the API.
    let mut active = response.connection_string.clone();

    // Apply SSL override on the single active DSN.
    if let Some(ssl_mode) = ssl {
        active = apply_sslmode(&active, ssl_mode);
    }

    match format {
        OutputFormat::Json => {
            let json_obj = serde_json::json!({
                "connection_string": active
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
            table.add_row(vec![Cell::new("Connection String"), Cell::new(&active)]);

            println!("{table}");
        }
    }
    Ok(())
}

pub fn print_project_connection_uri(
    response: &seren::ProjectConnectionUriResponse,
    ssl: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let wrapper = seren::ConnectionString {
        connection_string: response.uri.clone(),
    };
    print_connection_string(&wrapper, ssl, format)
}

pub fn print_created_endpoints(
    endpoints: &[seren::EndpointCreatedResponse],
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
                    Cell::new(endpoint.data.id.to_string()),
                    Cell::new(&endpoint.data.name),
                    Cell::new(&endpoint.data.status),
                    Cell::new(&endpoint.data.compute_unit),
                    Cell::new(endpoint.data.connection_string.as_deref().unwrap_or("")),
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
            Cell::new(format!("{}%", operation.progress)),
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
                let metadata_str =
                    serde_json::to_string(&metadata).unwrap_or_else(|_| "<invalid>".to_string());
                table.add_row(vec!["Metadata", &metadata_str]);
            }

            println!("{table}");
        }
    }

    Ok(())
}

// User
pub fn print_user(user: &seren::UserInfoResponse) -> anyhow::Result<()> {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.add_row(vec![
        Cell::new("Field").fg(Color::Green),
        Cell::new("Value").fg(Color::Green),
    ]);
    table.add_row(vec![Cell::new("ID"), Cell::new(user.data.id.to_string())]);
    table.add_row(vec![Cell::new("Email"), Cell::new(&user.data.email)]);
    table.add_row(vec![Cell::new("Name"), Cell::new(&user.data.name)]);
    if let Some(avatar) = &user.data.avatar_url {
        table.add_row(vec![Cell::new("Avatar URL"), Cell::new(avatar)]);
    }
    table.add_row(vec![
        Cell::new("Status"),
        Cell::new(format!("{:?}", user.data.status)),
    ]);
    table.add_row(vec![
        Cell::new("Created At"),
        Cell::new(user.data.created_at.to_string()),
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
            Cell::new(org.id),
            Cell::new(&org.name),
            Cell::new(&org.slug),
            Cell::new(org.created_at),
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
            Cell::new(ip.id),
            Cell::new(&ip.ip_address),
            Cell::new(ip.description.as_deref().unwrap_or("-")),
            Cell::new(ip.created_at),
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
            Cell::new(endpoint.id),
            Cell::new(&endpoint.endpoint_id),
            Cell::new(&endpoint.region),
            Cell::new(endpoint.label.as_deref().unwrap_or("-")),
            Cell::new(&endpoint.state),
            Cell::new(endpoint.updated_at),
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

// Sessions
pub fn print_sessions_table(sessions: &[seren::Session]) {
    if sessions.is_empty() {
        println!("No active sessions found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Current").fg(Color::Green),
        Cell::new("IP Address").fg(Color::Green),
        Cell::new("Last Active").fg(Color::Green),
        Cell::new("Expires").fg(Color::Green),
    ]);

    for session in sessions {
        table.add_row(vec![
            Cell::new(session.id.to_string()),
            Cell::new(if session.is_current { "Yes" } else { "" }),
            Cell::new(session.ip_address.as_deref().unwrap_or("-")),
            Cell::new(session.last_active_at.to_string()),
            Cell::new(session.expires_at.to_string()),
        ]);
    }

    println!("{table}");
}

// Webhooks
pub fn print_webhooks_table(webhooks: &[seren::WebhookInfo]) {
    if webhooks.is_empty() {
        println!("No webhooks configured");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("URL").fg(Color::Green),
        Cell::new("Events").fg(Color::Green),
        Cell::new("Enabled").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for webhook in webhooks {
        table.add_row(vec![
            Cell::new(webhook.id.to_string()),
            Cell::new(&webhook.name),
            Cell::new(&webhook.url),
            Cell::new(webhook.events.join(", ")),
            Cell::new(if webhook.enabled { "Yes" } else { "No" }),
            Cell::new(webhook.created_at.to_string()),
        ]);
    }

    println!("{table}");
}

pub fn print_webhook_deliveries_table(deliveries: &[seren::WebhookDelivery]) {
    if deliveries.is_empty() {
        println!("No webhook deliveries found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Event").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Attempts").fg(Color::Green),
        Cell::new("Delivered").fg(Color::Green),
    ]);

    for delivery in deliveries {
        let is_success = delivery.delivered_at.is_some();
        let status = if is_success {
            format!(
                "{} ({})",
                "Success".green(),
                delivery.response_status.unwrap_or(0)
            )
        } else {
            format!(
                "{} ({})",
                "Failed".red(),
                delivery.response_status.unwrap_or(0)
            )
        };
        table.add_row(vec![
            Cell::new(delivery.id.to_string()),
            Cell::new(&delivery.event_type),
            Cell::new(status),
            Cell::new(delivery.attempt_number.to_string()),
            Cell::new(
                delivery
                    .delivered_at
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]);
    }

    println!("{table}");
}

// Audit Logs
pub fn print_audit_logs_table(logs: &[seren::AuditLog]) {
    if logs.is_empty() {
        println!("No audit logs found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Time").fg(Color::Green),
        Cell::new("Action").fg(Color::Green),
        Cell::new("Resource Type").fg(Color::Green),
        Cell::new("Resource ID").fg(Color::Green),
        Cell::new("Actor ID").fg(Color::Green),
        Cell::new("IP").fg(Color::Green),
    ]);

    for log in logs {
        table.add_row(vec![
            Cell::new(log.created_at.to_string()),
            Cell::new(&log.action),
            Cell::new(&log.resource_type),
            Cell::new(
                log.resource_id
                    .map(|u| u.to_string())
                    .as_deref()
                    .unwrap_or("-"),
            ),
            Cell::new(
                log.actor_id
                    .map(|u| u.to_string())
                    .as_deref()
                    .unwrap_or("-"),
            ),
            Cell::new(log.ip_address.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");
}

// RBAC Roles
pub fn print_rbac_roles_table(roles: &[seren::RbacRole]) {
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
        Cell::new("Description").fg(Color::Green),
        Cell::new("Built-in").fg(Color::Green),
        Cell::new("Permissions").fg(Color::Green),
    ]);

    for role in roles {
        let perms = if role.permissions.len() > 3 {
            format!(
                "{}, ... ({} total)",
                role.permissions[..3].join(", "),
                role.permissions.len()
            )
        } else {
            role.permissions.join(", ")
        };
        table.add_row(vec![
            Cell::new(role.id.to_string()),
            Cell::new(&role.name),
            Cell::new(role.description.as_deref().unwrap_or("-")),
            Cell::new(if role.is_built_in { "Yes" } else { "No" }),
            Cell::new(perms),
        ]);
    }

    println!("{table}");
}

pub fn print_permissions_table(permissions: &[seren::Permission]) {
    if permissions.is_empty() {
        println!("No permissions found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Name").fg(Color::Green),
        Cell::new("Resource").fg(Color::Green),
        Cell::new("Action").fg(Color::Green),
        Cell::new("Description").fg(Color::Green),
    ]);

    for perm in permissions {
        table.add_row(vec![
            Cell::new(&perm.name),
            Cell::new(&perm.resource_type),
            Cell::new(&perm.action),
            Cell::new(perm.description.as_deref().unwrap_or("-")),
        ]);
    }

    println!("{table}");
}

// Branch Protection
pub fn print_branch_protection_table(rules: &[seren::BranchProtection]) {
    if rules.is_empty() {
        println!("No branch protection rules found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Branch ID").fg(Color::Green),
        Cell::new("Prevent Delete").fg(Color::Green),
        Cell::new("Prevent Reset").fg(Color::Green),
        Cell::new("Require Approval").fg(Color::Green),
        Cell::new("Bypass Roles").fg(Color::Green),
    ]);

    for rule in rules {
        table.add_row(vec![
            Cell::new(rule.branch_id.to_string()),
            Cell::new(if rule.prevent_deletion { "Yes" } else { "No" }),
            Cell::new(if rule.prevent_reset { "Yes" } else { "No" }),
            Cell::new(if rule.require_approval_for_changes {
                "Yes"
            } else {
                "No"
            }),
            Cell::new(if rule.allowed_bypass_roles.is_empty() {
                "-".to_string()
            } else {
                rule.allowed_bypass_roles.join(", ")
            }),
        ]);
    }

    println!("{table}");
}

// Logical Replication - Publications
pub fn print_publications_table(publications: &[seren::PublicationInfo]) {
    if publications.is_empty() {
        println!("No publications found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Tables").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for pub_ in publications {
        let tables = if pub_.tables.is_empty() {
            "ALL TABLES".to_string()
        } else {
            pub_.tables.join(", ")
        };
        table.add_row(vec![
            Cell::new(pub_.id.to_string()),
            Cell::new(&pub_.name),
            Cell::new(tables),
            Cell::new(pub_.created_at.to_string()),
        ]);
    }

    println!("{table}");
}

// Logical Replication - Slots
pub fn print_replication_slots_table(slots: &[seren::ReplicationSlotInfo]) {
    if slots.is_empty() {
        println!("No replication slots found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("ID").fg(Color::Green),
        Cell::new("Name").fg(Color::Green),
        Cell::new("Type").fg(Color::Green),
        Cell::new("Plugin").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Created").fg(Color::Green),
    ]);

    for slot in slots {
        table.add_row(vec![
            Cell::new(slot.id.to_string()),
            Cell::new(&slot.name),
            Cell::new(&slot.slot_type),
            Cell::new(&slot.plugin),
            Cell::new(&slot.status),
            Cell::new(slot.created_at.to_string()),
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

pub fn print_endpoint_status(status: &seren::EndpointStatusInfo) {
    let mut rows = vec![
        ("ID", status.id.to_string()),
        ("Status", status.status.to_string()),
        ("K8s Ready", status.k8s_ready.to_string()),
    ];

    if let Some(compute_status) = &status.compute_status {
        rows.push(("Compute Status", compute_status.to_string()));
    }

    print_key_value_table(Some("Endpoint Status"), &rows);
}

pub fn print_replication_settings(settings: &seren::LogicalReplicationSettings) {
    let rows = [
        ("Project ID", settings.project_id.to_string()),
        (
            "Enabled",
            if settings.enabled {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        ),
        (
            "Publications Count",
            settings.publications_count.to_string(),
        ),
        ("Slots Count", settings.slots_count.to_string()),
    ];

    print_key_value_table(Some("Logical Replication Settings"), &rows);
}

pub fn print_agent_balance_summary(summary: &seren::AgentBalanceSummary) {
    let rows = [
        ("Wallet", summary.agent_wallet.to_string()),
        ("Publishers", summary.publishers_used.to_string()),
        ("Queries", summary.total_queries.to_string()),
    ];

    print_key_value_table(Some("Agent Balance Summary"), &rows);

    if summary.totals_by_asset.is_empty() {
        println!("No balances found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Asset").fg(Color::Green),
        Cell::new("Network").fg(Color::Green),
        Cell::new("Balance").fg(Color::Green),
        Cell::new("Reserved").fg(Color::Green),
        Cell::new("Available").fg(Color::Green),
    ]);

    for total in &summary.totals_by_asset {
        let symbol = &total.asset.symbol;
        table.add_row(vec![
            Cell::new(symbol),
            Cell::new(&total.asset.network_name),
            Cell::new(format!("{:.6} {}", total.total_balance, symbol)),
            Cell::new(format!("{:.6} {}", total.total_reserved, symbol)),
            Cell::new(format!("{:.6} {}", total.total_available, symbol)),
        ]);
    }

    println!();
    println!("{}", "Balances by Asset".bold());
    println!("{table}");
}

pub fn print_agent_publisher_balances(balances: &[seren::AgentBalanceResponse]) {
    if balances.is_empty() {
        println!("No balances found for this publisher");
        return;
    }

    let first = &balances[0];

    let mut rows = vec![
        ("Wallet", first.agent_wallet.to_string()),
        ("Publisher", first.publisher_id.to_string()),
    ];
    if let Some(name) = &first.publisher_name {
        rows.push(("Name", name.to_string()));
    }

    print_key_value_table(Some("Agent Publisher Balance"), &rows);

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    table.set_header(vec![
        Cell::new("Asset").fg(Color::Green),
        Cell::new("Network").fg(Color::Green),
        Cell::new("Balance").fg(Color::Green),
        Cell::new("Reserved").fg(Color::Green),
        Cell::new("Available").fg(Color::Green),
        Cell::new("Queries").fg(Color::Green),
    ]);

    for bal in balances {
        let symbol = &bal.asset.symbol;
        table.add_row(vec![
            Cell::new(symbol),
            Cell::new(&bal.asset.network_name),
            Cell::new(format!("{:.6} {}", bal.balance, symbol)),
            Cell::new(format!("{:.6} {}", bal.reserved, symbol)),
            Cell::new(format!("{:.6} {}", bal.available, symbol)),
            Cell::new(bal.total_queries.to_string()),
        ]);
    }

    println!();
    println!("{}", "Balances".bold());
    println!("{table}");
}

pub fn print_invoice(invoice: &seren::Invoice) {
    let rows = [
        ("ID", invoice.id.to_string()),
        ("Number", invoice.invoice_number.to_string()),
        ("Organization", invoice.organization_id.to_string()),
        (
            "Period",
            format!("{} → {}", invoice.period_start, invoice.period_end),
        ),
        ("Status", invoice.status.to_string()),
        ("Subtotal", format!("${:.2}", invoice.subtotal_usd)),
        ("Tax", format!("${:.2}", invoice.tax_usd)),
        ("Total", format!("${:.2}", invoice.total_usd)),
    ];

    print_key_value_table(Some("Invoice Details"), &rows);

    if invoice.line_items.is_empty() {
        return;
    }

    let mut items_table = Table::new();
    items_table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    items_table.set_header(vec![
        Cell::new("Description").fg(Color::Green),
        Cell::new("Type").fg(Color::Green),
        Cell::new("Quantity").fg(Color::Green),
        Cell::new("Unit Price").fg(Color::Green),
        Cell::new("Amount").fg(Color::Green),
    ]);

    for item in &invoice.line_items {
        items_table.add_row(vec![
            Cell::new(&item.description),
            Cell::new(&item.line_type),
            Cell::new(format!("{:.2}", item.quantity)),
            Cell::new(format!("${:.4}", item.unit_price)),
            Cell::new(format!("${:.2}", item.amount_usd)),
        ]);
    }

    println!();
    println!("{}", "Line Items".bold());
    println!("{items_table}");
}

pub fn print_validate_token(result: &seren::ValidateTokenResponse) {
    let rows = [
        ("Endpoint ID", result.endpoint_id.to_string()),
        ("User ID", result.user_id.to_string()),
        ("Balance", format!("${:.4}", result.balance)),
        ("Expires At", result.expires_at.to_string()),
    ];

    print_key_value_table(Some("Token Valid"), &rows);
}

pub fn print_balance(result: &seren::BalanceResponse) {
    let rows = [
        ("Endpoint ID", result.endpoint_id.to_string()),
        ("Balance", format!("${:.4}", result.balance)),
    ];

    print_key_value_table(Some("Endpoint Balance"), &rows);
}
