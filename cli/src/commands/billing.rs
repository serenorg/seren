use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

// Invoice commands

pub async fn generate_invoices(year: i32, month: i32, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let request = seren::GenerateInvoicesRequest { year, month };
    let response = client
        .generate_invoices(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to generate invoices: {}", e))?;

    let result = response.into_inner();
    println!(
        "{}",
        format!("✓ Generated {} invoices", result.data.count)
            .green()
            .bold()
    );

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("\nInvoice IDs:");
            for id in &result.data.invoice_ids {
                println!("  {}", id);
            }
        }
    }

    Ok(())
}

pub async fn get_invoice(invoice_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let invoice_uuid =
        Uuid::parse_str(invoice_id).map_err(|e| anyhow::anyhow!("Invalid invoice ID: {}", e))?;

    let response = client
        .get_invoice(&invoice_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get invoice: {}", e))?;

    let invoice = response.into_inner().data;
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
    let invoice_uuid =
        Uuid::parse_str(invoice_id).map_err(|e| anyhow::anyhow!("Invalid invoice ID: {}", e))?;

    client
        .issue_invoice(&invoice_uuid)
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
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .get_usage_summary(&org_uuid, end_date, start_date)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get usage: {}", e))?;

    let usage = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&usage)?,
        OutputFormat::Table => {
            output::print_usage_summaries_table(&usage.data);
        }
    }

    Ok(())
}

// Agentic billing commands

pub async fn validate_token(token: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let request = seren::ValidateTokenRequest {
        token: token.to_string(),
    };
    let response = client
        .validate_x402_token(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to validate token: {}", e))?;

    let result = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}", "Token Valid".green().bold());
            println!("  Endpoint ID: {}", result.endpoint_id);
            println!("  Balance:     ${:.4}", result.balance);
            println!("  Expires At:  {}", result.expires_at);
        }
    }

    Ok(())
}

pub async fn get_balance(endpoint_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_balance(endpoint_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get balance: {}", e))?;

    let result = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}", "Endpoint Balance".bold());
            println!("  Endpoint ID: {}", result.endpoint_id);
            println!("  Balance:     ${:.4}", result.balance);
        }
    }

    Ok(())
}

pub async fn get_health(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_billing_health()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get billing health: {}", e))?;

    let health = response.into_inner();
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
    let client = ctx.client().await?;

    let response = client
        .list_payment_methods()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list payment methods: {}", e))?;

    let methods = response.into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&methods)?,
        OutputFormat::Table => output::print_payment_methods_table(&methods.data),
    }

    Ok(())
}

/// Register an existing Stripe PaymentMethod ID with Seren as a billing method.
pub async fn add_payment_method(
    stripe_payment_method_id: &str,
    set_default: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let request = seren::AddPaymentMethodRequest {
        stripe_payment_method_id: stripe_payment_method_id.to_string(),
        set_as_default: set_default,
    };

    let response = client
        .add_payment_method(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to add payment method: {}", e))?;

    let result = response.into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}", "✓ Payment method added successfully".green().bold());
            println!("  ID:      {}", result.data.id);
            println!("  Message: {}", result.data.message);
        }
    }

    Ok(())
}

/// Remove a stored payment method by its Seren payment_methods.id value.
pub async fn remove_payment_method(id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let payment_method_id =
        Uuid::parse_str(id).map_err(|e| anyhow::anyhow!("Invalid payment method ID: {}", e))?;

    client
        .delete_payment_method(&payment_method_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove payment method: {}", e))?;

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
