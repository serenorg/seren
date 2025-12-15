use anyhow::{Context, Result};
use colored::Colorize;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};

use crate::{
    CommandContext, OutputFormat,
    commands::auth::get_bearer_token,
    defaults::{DEFAULT_API_HOST, normalize_api_host},
    output,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct CliPaymentMethod {
    pub id: String,
    #[serde(rename = "type_")]
    pub type_: String,
    pub card_brand: Option<String>,
    pub card_last4: Option<String>,
    pub card_exp_month: Option<i32>,
    pub card_exp_year: Option<i32>,
    pub bank_last4: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct CliAddPaymentMethodResponse {
    id: String,
    message: String,
}

fn resolve_api_host(api_host: Option<&String>) -> String {
    let host = api_host
        .cloned()
        .or_else(|| std::env::var("SEREN_API_HOST").ok())
        .unwrap_or_else(|| DEFAULT_API_HOST.to_string());
    normalize_api_host(&host)
}

// Invoice commands

pub async fn generate_invoices(year: i32, month: u8, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

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

    match ctx.format {
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

pub async fn get_invoice(invoice_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let invoice = client
        .invoices()
        .get(invoice_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get invoice: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&invoice)?,
        OutputFormat::Table => {
            println!("{}", "Invoice Details".bold());
            println!("  ID:              {}", invoice.id);
            println!("  Number:          {}", invoice.invoice_number);
            println!("  Organization:    {}", invoice.organization_id);
            println!(
                "  Period:          {} to {}",
                invoice.period_start, invoice.period_end
            );
            println!("  Status:          {}", invoice.status);
            println!("  Subtotal:        ${:.2}", invoice.subtotal_usd);
            println!("  Tax:             ${:.2}", invoice.tax_usd);
            println!(
                "  Total:           ${:.2}",
                invoice.total_usd.to_string().bold()
            );

            if !invoice.line_items.is_empty() {
                println!("\n{}", "Line Items".bold());
                for item in &invoice.line_items {
                    println!("  {} ({})", item.description, item.line_type);
                    println!(
                        "    Quantity: {:.2}, Unit Price: ${:.4}, Amount: ${:.2}",
                        item.quantity, item.unit_price, item.amount_usd
                    );
                }
            }
        }
    }

    Ok(())
}

pub async fn issue_invoice(invoice_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

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
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let usage = client
        .usage(organization_id)
        .summary(start_date, end_date)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get usage: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&usage)?,
        OutputFormat::Table => {
            output::print_usage_summaries_table(&usage);
        }
    }

    Ok(())
}

// Agentic billing commands

pub async fn validate_token(token: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .billing()
        .validate_token(token)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to validate token: {}", e))?;

    match ctx.format {
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

pub async fn get_balance(endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .billing()
        .get_balance(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get balance: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}", "Endpoint Balance".bold());
            println!("  Endpoint ID: {}", response.endpoint_id);
            println!("  Balance:     ${:.4}", response.balance);
        }
    }

    Ok(())
}

pub async fn get_health(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let health = client
        .billing()
        .health()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get billing health: {}", e))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&health)?,
        OutputFormat::Table => {
            output::print_billing_health_table(&health);
        }
    }

    Ok(())
}

/// List saved payment methods for the authenticated user's primary organization.
pub async fn list_payment_methods(ctx: &CommandContext) -> Result<()> {
    let bearer_token = get_bearer_token(ctx.api_key.clone()).await?;
    let base_url = resolve_api_host(ctx.api_host.as_ref());
    let base_url = base_url.trim_end_matches('/');

    let url = format!("{}/api/billing/payment-methods", base_url);
    let client = HttpClient::new();

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", bearer_token))
        .send()
        .await
        .context("Failed to fetch payment methods")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to list payment methods ({}): {}",
            status,
            body
        ));
    }

    let methods: Vec<CliPaymentMethod> = response
        .json()
        .await
        .context("Failed to parse payment methods response")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&methods)?,
        OutputFormat::Table => output::print_payment_methods_table(&methods),
    }

    Ok(())
}

/// Register an existing Stripe PaymentMethod ID with Seren as a billing method.
pub async fn add_payment_method(
    stripe_payment_method_id: &str,
    set_default: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let bearer_token = get_bearer_token(ctx.api_key.clone()).await?;
    let base_url = resolve_api_host(ctx.api_host.as_ref());
    let base_url = base_url.trim_end_matches('/');

    let url = format!("{}/api/billing/payment-methods", base_url);
    let client = HttpClient::new();

    let body = serde_json::json!({
        "stripe_payment_method_id": stripe_payment_method_id,
        "set_as_default": set_default,
    });

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", bearer_token))
        .json(&body)
        .send()
        .await
        .context("Failed to add payment method")?;

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to add payment method ({}): {}",
            status,
            body_text
        ));
    }

    let result: CliAddPaymentMethodResponse = response
        .json()
        .await
        .context("Failed to parse add payment method response")?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}", "✓ Payment method added successfully".green().bold());
            println!("  ID:      {}", result.id);
            println!("  Message: {}", result.message);
        }
    }

    Ok(())
}

/// Remove a stored payment method by its Seren payment_methods.id value.
pub async fn remove_payment_method(id: &str, ctx: &CommandContext) -> Result<()> {
    let bearer_token = get_bearer_token(ctx.api_key.clone()).await?;
    let base_url = resolve_api_host(ctx.api_host.as_ref());
    let base_url = base_url.trim_end_matches('/');

    let url = format!("{}/api/billing/payment-methods/{}", base_url, id);
    let client = HttpClient::new();

    let response = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", bearer_token))
        .send()
        .await
        .context("Failed to remove payment method")?;

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to remove payment method ({}): {}",
            status,
            body_text
        ));
    }

    if let OutputFormat::Json = ctx.format {
        // No body for 204; return a simple JSON acknowledgement.
        let payload = serde_json::json!({
            "id": id,
            "status": "removed",
        });
        output::print_json(&payload)?;
    } else {
        println!("{}", "✓ Payment method removed successfully".green().bold());
    }

    Ok(())
}
