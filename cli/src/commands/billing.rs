use anyhow::Result;
use colored::Colorize;
use seren::{Client, ClientConfig};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

// Invoice commands

pub async fn generate_invoices(
    year: i32,
    month: u8,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let response = client
        .invoices()
        .generate(year, month)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to generate invoices: {}", e))?;

    println!(
        "{}",
        format!("✓ Generated {} invoices", response.count)
            .green()
            .bold()
    );

    match format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("\nInvoice IDs:");
            for id in &response.invoice_ids {
                println!("  {}", id);
            }
        }
    }

    Ok(())
}

pub async fn get_invoice(
    invoice_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let invoice = client
        .invoices()
        .get(invoice_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get invoice: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&invoice)?,
        OutputFormat::Table => {
            println!("{}", "Invoice Details".bold());
            println!("  ID:              {}", invoice.id);
            println!("  Number:          {}", invoice.invoice_number);
            println!("  Organization:    {}", invoice.organization_id);
            println!("  Period:          {} to {}", invoice.period_start, invoice.period_end);
            println!("  Status:          {}", invoice.status);
            println!("  Subtotal:        ${:.2}", invoice.subtotal_usd);
            println!("  Tax:             ${:.2}", invoice.tax_usd);
            println!("  Total:           ${:.2}", invoice.total_usd.to_string().bold());
            
            if !invoice.line_items.is_empty() {
                println!("\n{}", "Line Items".bold());
                for item in &invoice.line_items {
                    println!("  {} ({})", item.description, item.line_type);
                    println!("    Quantity: {:.2}, Unit Price: ${:.4}, Amount: ${:.2}",
                        item.quantity, item.unit_price, item.amount_usd);
                }
            }
        }
    }

    Ok(())
}

pub async fn issue_invoice(
    invoice_id: &str,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    client
        .invoices()
        .issue(invoice_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to issue invoice: {}", e))?;

    println!(
        "{}",
        format!("✓ Invoice {} issued successfully!", invoice_id)
            .green()
            .bold()
    );

    Ok(())
}

// Usage commands

pub async fn get_usage(
    organization_id: &str,
    start_date: Option<&str>,
    end_date: Option<&str>,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let usage = client
        .usage(organization_id)
        .summary(start_date, end_date)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get usage: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&usage)?,
        OutputFormat::Table => {
            output::print_usage_summaries_table(&usage);
        }
    }

    Ok(())
}

// Agentic billing commands

pub async fn validate_token(
    token: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let response = client
        .billing()
        .validate_token(token)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to validate token: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}", "Token Valid".green().bold());
            println!("  Endpoint ID: {}", response.endpoint_id);
            println!("  Balance:     ${:.4}", response.balance);
            println!("  Expires At:  {}", response.expires_at);
        }
    }

    Ok(())
}

pub async fn get_balance(
    endpoint_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let response = client
        .billing()
        .get_balance(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get balance: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}", "Endpoint Balance".bold());
            println!("  Endpoint ID: {}", response.endpoint_id);
            println!("  Balance:     ${:.4}", response.balance);
        }
    }

    Ok(())
}

pub async fn get_health(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let health = client
        .billing()
        .health()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get billing health: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&health)?,
        OutputFormat::Table => {
            output::print_billing_health_table(&health);
        }
    }

    Ok(())
}
