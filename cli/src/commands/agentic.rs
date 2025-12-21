use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, defaults, output};

/// List all active publishers in the marketplace
pub async fn list_publishers(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_marketplace_publishers(
            None, // is_verified
            None, // limit
            None, // offset
            None, // search
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list publishers: {}", e))?;

    let publishers = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&publishers)?,
        OutputFormat::Table => {
            println!("{}", "Marketplace Publishers".bold());
            println!();
            for pub_info in &publishers.data {
                println!("  {} ({})", pub_info.name.bold(), pub_info.slug.dimmed());
                println!("    ID:          {}", pub_info.id);
                if let Some(desc) = &pub_info.description {
                    println!("    Description: {}", desc);
                }
                println!("    Type:        {:?}", pub_info.publisher_type);
                println!(
                    "    Verified:    {}",
                    if pub_info.is_verified {
                        "Yes".green()
                    } else {
                        "No".yellow()
                    }
                );
                if let Some(pricing) = &pub_info.pricing {
                    println!(
                        "    Pricing:     ${:.6}/1000 rows",
                        pricing.base_price_per_1000_rows
                    );
                }
                println!();
            }
            println!("Total: {} publishers", publishers.data.len());
        }
    }

    Ok(())
}

/// Get details about a specific publisher
pub async fn get_publisher(publisher: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    // The API accepts either a slug or UUID as the path parameter
    let response = client
        .get_marketplace_publisher(publisher)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get publisher: {}", e))?;

    let pub_info = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&pub_info)?,
        OutputFormat::Table => {
            let data = &pub_info.data;
            println!("{}", "Publisher Details".bold());
            println!();
            println!("  Name:        {}", data.name.bold());
            println!("  Slug:        {}", data.slug);
            println!("  ID:          {}", data.id);
            if let Some(desc) = &data.description {
                println!("  Description: {}", desc);
            }
            println!("  Type:        {:?}", data.publisher_type);
            println!(
                "  Verified:    {}",
                if data.is_verified {
                    "Yes".green()
                } else {
                    "No".yellow()
                }
            );
            println!(
                "  Active:      {}",
                if data.is_active { "Yes" } else { "No" }
            );
            if let Some(pricing) = &data.pricing {
                println!();
                println!("{}", "Pricing".bold());
                println!(
                    "  Base Price:      ${:.6}/1000 rows",
                    pricing.base_price_per_1000_rows
                );
                println!("  Min Charge:      ${:.6}", pricing.min_charge);
                println!("  Markup:          {:.2}x", pricing.markup_multiplier);
                println!("  Prepaid Enabled: {}", pricing.prepaid_enabled);
                println!("  x402 Enabled:    {}", pricing.x402_enabled);
            }
        }
    }

    Ok(())
}

/// Get agent balance summary across all publishers
pub async fn get_agent_balance(wallet_address: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_agent_balance_summary(wallet_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get agent balance: {}", e))?;

    let balance = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&balance)?,
        OutputFormat::Table => {
            let data = &balance.data;
            println!("{}", "Agent Balance Summary".bold());
            println!();
            println!("  Wallet:         {}", data.agent_wallet);
            println!(
                "  Total Balance:  {}",
                format!("${:.6}", data.total_balance_usdc).green().bold()
            );
            println!("  Total Reserved: ${:.6}", data.total_reserved_usdc);
            println!(
                "  Available:      {}",
                format!("${:.6}", data.total_available_usdc).green()
            );
            println!("  Publishers:     {}", data.publishers_used);
        }
    }

    Ok(())
}

/// Get agent balance for a specific publisher
pub async fn get_agent_publisher_balance(
    wallet_address: &str,
    publisher_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let pub_uuid = Uuid::parse_str(publisher_id)
        .map_err(|e| anyhow::anyhow!("Invalid publisher ID: {}", e))?;

    let response = client
        .get_agent_publisher_balance(wallet_address, &pub_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get publisher balance: {}", e))?;

    let balance = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&balance)?,
        OutputFormat::Table => {
            let data = &balance.data;
            println!("{}", "Agent Publisher Balance".bold());
            println!();
            println!("  Wallet:       {}", data.agent_wallet);
            println!("  Publisher:    {}", data.publisher_id);
            println!(
                "  Balance:      {}",
                format!("${:.6}", data.balance_usdc).green().bold()
            );
            println!("  Reserved:     ${:.6}", data.reserved_usdc);
            println!(
                "  Available:    {}",
                format!("${:.6}", data.available_usdc).green()
            );
        }
    }

    Ok(())
}

/// Get x402 deposit requirements (EIP-712 data for on-chain USDC deposit)
pub async fn get_deposit_requirements(
    publisher: &str,
    amount: &str,
    agent_wallet: &str,
    ctx: &CommandContext,
) -> Result<()> {
    // Resolve publisher ID
    let client = ctx.client().await?;
    let publisher_id = if let Ok(uuid) = Uuid::parse_str(publisher) {
        uuid
    } else {
        let response = client
            .list_marketplace_publishers(None, Some(100), None, Some(publisher))
            .await
            .map_err(|e| anyhow::anyhow!("Failed to search publishers: {}", e))?;

        let publishers = response.into_inner();
        publishers
            .data
            .iter()
            .find(|p| p.slug == publisher)
            .map(|p| p.id)
            .ok_or_else(|| anyhow::anyhow!("Publisher not found: {}", publisher))?
    };

    // Make request to deposit endpoint without payment header to get 402 requirements
    let http_client = reqwest::Client::new();
    let body = serde_json::json!({
        "publisher_id": publisher_id,
        "amount": amount
    });

    let base_url = match ctx.api_host.as_deref() {
        Some(host) => defaults::api_base_url(host),
        None => defaults::api_base_url(defaults::DEFAULT_API_HOST),
    };
    let url = format!("{}/agentic/deposit", base_url);

    let response = http_client
        .post(&url)
        .header("X-AGENT-WALLET", agent_wallet)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get deposit requirements: {}", e))?;

    if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        let requirements: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse requirements: {}", e))?;

        match ctx.format {
            OutputFormat::Json => output::print_json(&requirements)?,
            OutputFormat::Table => {
                println!("{}", "x402 Deposit Requirements".bold());
                println!();
                println!("To complete this deposit, sign the EIP-712 typed data below");
                println!(
                    "and resend the request with the signature in the PAYMENT-SIGNATURE header."
                );
                println!();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&requirements)
                        .unwrap_or_else(|_| "Failed to format".to_string())
                );
            }
        }
        return Ok(());
    }

    if response.status().is_success() {
        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse response: {}", e))?;
        output::print_json(&result)?;
        return Ok(());
    }

    let status = response.status();
    let error_body = response.text().await.unwrap_or_default();
    Err(anyhow::anyhow!(
        "Failed to get deposit requirements: {} - {}",
        status,
        error_body
    ))
}
