use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, defaults, output};

fn first_n_categories(categories: &[String], max: usize) -> String {
    categories
        .iter()
        .take(max)
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

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
                if let Some(resource) = &pub_info.resource_name {
                    println!("    Resource:    {}", resource);
                }
                if let Some(desc) = pub_info
                    .resource_description
                    .as_ref()
                    .or(pub_info.description.as_ref())
                {
                    println!("    Description: {}", desc);
                }
                if !pub_info.categories.is_empty() {
                    println!(
                        "    Categories:  {}{}",
                        first_n_categories(&pub_info.categories, 5),
                        if pub_info.categories.len() > 5 {
                            "…"
                        } else {
                            ""
                        }
                    );
                }
                println!("    Type:        {:?}", pub_info.publisher_type);
                println!("    Source:      {:?}", pub_info.source_type);
                println!(
                    "    Verified:    {}",
                    if pub_info.is_verified {
                        "Yes".green()
                    } else {
                        "No".yellow()
                    }
                );
                if let Some(pricing_list) = &pub_info.pricing {
                    if let Some(first_pricing) = pricing_list.first() {
                        let asset = first_pricing.asset_symbol.as_deref().unwrap_or("?");
                        println!(
                            "    Pricing:     {:.6} {}/1000 rows",
                            first_pricing.base_price_per_1000_rows, asset
                        );
                    }
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
            if let Some(resource) = &data.resource_name {
                println!("  Resource:    {}", resource);
            }
            if let Some(desc) = data
                .resource_description
                .as_ref()
                .or(data.description.as_ref())
            {
                println!("  Description: {}", desc);
            }
            if !data.categories.is_empty() {
                println!(
                    "  Categories:  {}",
                    first_n_categories(&data.categories, 20)
                );
            }
            println!("  Type:        {:?}", data.publisher_type);
            println!("  Source:      {:?}", data.source_type);
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
            println!("  Wallet:      {}", data.wallet_address);
            println!("  Network:     {}", data.wallet_network_id);
            if let Some(usage) = &data.usage_example {
                println!();
                println!("{}", "Usage Example".bold());
                println!(
                    "{}",
                    serde_json::to_string_pretty(usage)
                        .unwrap_or_else(|_| "<invalid json>".to_string())
                );
            }
            if let Some(pricing_list) = &data.pricing {
                if !pricing_list.is_empty() {
                    println!();
                    println!("{}", "Pricing".bold());
                    for pricing in pricing_list {
                        let asset_label = pricing.asset_symbol.as_deref().unwrap_or("Unknown");
                        println!("  {}:", asset_label);
                        println!(
                            "    Base Price:      {:.6} {}/1000 rows",
                            pricing.base_price_per_1000_rows, asset_label
                        );
                        println!(
                            "    Min Charge:      {:.6} {}",
                            pricing.min_charge, asset_label
                        );
                        println!("    Markup:          {:.2}x", pricing.markup_multiplier);
                        println!("    Prepaid Enabled: {}", pricing.prepaid_enabled);
                        println!("    On-chain Enabled: {}", pricing.onchain_enabled);
                    }
                }
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
