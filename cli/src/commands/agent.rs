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
        OutputFormat::Table => output::print_publishers_table(&publishers.data),
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
    output::print_marketplace_publisher(&pub_info.data, ctx.format)?;

    Ok(())
}

/// Get agent balance summary across all publishers
pub async fn get_agent_balance(wallet_address: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_agent_balance_summary(wallet_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get agent balance: {}", e))?;

    let summary = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&summary)?,
        OutputFormat::Table => {
            let data = &summary.data;
            println!("{}", "Agent Balance Summary".bold());
            println!();
            println!("  Wallet:     {}", data.agent_wallet);
            println!("  Publishers: {}", data.publishers_used);
            println!("  Queries:    {}", data.total_queries);
            println!();
            if !data.totals_by_asset.is_empty() {
                println!("{}", "Balances by Asset".bold());
                for total in &data.totals_by_asset {
                    println!(
                        "  {} ({})",
                        total.asset.symbol.bold(),
                        total.asset.network_name
                    );
                    println!(
                        "    Balance:   {}",
                        format!("{:.6} {}", total.total_balance, total.asset.symbol)
                            .green()
                            .bold()
                    );
                    println!(
                        "    Reserved:  {:.6} {}",
                        total.total_reserved, total.asset.symbol
                    );
                    println!(
                        "    Available: {}",
                        format!("{:.6} {}", total.total_available, total.asset.symbol).green()
                    );
                }
            } else {
                println!("  No balances found");
            }
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

    let balances = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&balances)?,
        OutputFormat::Table => {
            println!("{}", "Agent Publisher Balance".bold());
            println!();
            if balances.is_empty() {
                println!("  No balances found for this publisher");
            } else {
                for bal in balances {
                    println!("  Wallet:    {}", bal.agent_wallet);
                    println!("  Publisher: {}", bal.publisher_id);
                    if let Some(name) = &bal.publisher_name {
                        println!("  Name:      {}", name);
                    }
                    println!(
                        "  Asset:     {} ({})",
                        bal.asset.symbol, bal.asset.network_name
                    );
                    println!(
                        "  Balance:   {}",
                        format!("{:.6} {}", bal.balance, bal.asset.symbol)
                            .green()
                            .bold()
                    );
                    println!("  Reserved:  {:.6} {}", bal.reserved, bal.asset.symbol);
                    println!(
                        "  Available: {}",
                        format!("{:.6} {}", bal.available, bal.asset.symbol).green()
                    );
                    println!("  Queries:   {}", bal.total_queries);
                    println!();
                }
            }
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
    let url = format!("{}/agent/deposit", base_url);

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
