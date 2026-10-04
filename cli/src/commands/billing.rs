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
            output::print_list_table(Some("Invoice IDs"), "Invoice ID", &result.data.invoice_ids)
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
        OutputFormat::Table => output::print_invoice(&invoice),
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

// Agent billing commands

// TODO: These endpoints are internal and not in the public OpenAPI spec.
// They need to be either added to the spec or handled differently.
#[allow(dead_code)]
pub async fn validate_token(_token: &str, _ctx: &CommandContext) -> Result<()> {
    anyhow::bail!("validate_token is not available in the public API")
}

#[allow(dead_code)]
pub async fn get_balance(_endpoint_id: &str, _ctx: &CommandContext) -> Result<()> {
    anyhow::bail!("get_balance is not available in the public API")
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

/// Start hosted payment method setup with the user's allowed return URLs.
pub async fn setup_payment_method(
    success_url: &str,
    cancel_url: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let request = seren::PaymentMethodSetupRequest {
        success_url: success_url.to_string(),
        cancel_url: cancel_url.to_string(),
    };
    let response = match client.setup_payment_method(&request).await {
        Ok(response) => response.into_inner(),
        Err(error) => {
            return Err(super::agent::anyhow_from_seren_error(
                "Failed to start payment method setup",
                error,
            )
            .await);
        }
    };
    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => output::print_key_value_table(
            Some("Payment Method Setup"),
            &[("URL", response.data.url)],
        ),
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
            let rows = [
                ("ID", result.data.id.to_string()),
                ("Message", result.data.message.clone()),
            ];
            output::print_key_value_table(Some("Payment Method Added"), &rows);
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn hosted_payment_setup_sends_the_selected_return_urls() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/billing/payment-methods/setup"))
            .and(body_json(serde_json::json!({
                "success_url": "https://app.example.test/success",
                "cancel_url": "https://app.example.test/cancel",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"url": "https://checkout.stripe.example.test/setup"},
            })))
            .expect(1)
            .mount(&server)
            .await;
        let context = CommandContext::new(
            Some(server.uri()),
            Some("test-key".into()),
            OutputFormat::Json,
        );
        setup_payment_method(
            "https://app.example.test/success",
            "https://app.example.test/cancel",
            &context,
        )
        .await
        .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
