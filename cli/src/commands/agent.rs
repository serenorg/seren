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
        OutputFormat::Table => output::print_agent_balance_summary(&summary.data),
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
        OutputFormat::Table => output::print_agent_publisher_balances(&balances),
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

/// Get supported payment protocols and configuration
pub async fn get_supported(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_supported()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get supported protocols: {}", e))?;

    let supported = response.into_inner();
    output::print_json(&supported)?;

    Ok(())
}

/// Create a new publisher in the marketplace
pub async fn create_publisher(
    name: &str,
    slug: &str,
    wallet_address: &str,
    wallet_network_id: &str,
    source_type: Option<&str>,
    description: Option<&str>,
    api_url: Option<&str>,
    project_id: Option<Uuid>,
    branch_id: Option<Uuid>,
    database_name: Option<&str>,
    base_price_per_1000_rows: Option<&str>,
    billing_model: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    // Convert source_type string to enum
    let source_type_enum = source_type.map(|s| match s {
        "serendb" => seren::SourceType::Serendb,
        "api" => seren::SourceType::Api,
        _ => seren::SourceType::Serendb,
    });

    let body = seren::CreatePublisherRequest {
        name: name.to_string(),
        slug: slug.to_string(),
        wallet_address: seren::WalletAddress(wallet_address.to_string()),
        wallet_network_id: wallet_network_id.to_string(),
        source_type: source_type_enum,
        description: description.map(|s| s.to_string()),
        api_url: api_url.map(|s| s.to_string()),
        project_id,
        branch_id,
        database_name: database_name.map(|s| s.to_string()),
        base_price_per_1000_rows: base_price_per_1000_rows.map(|s| s.to_string()),
        billing_model: billing_model.map(|s| s.to_string()),
        categories: vec![],
        logo_url: None,
        accepted_asset_ids: None,
        allowed_passthrough_headers: vec![],
        api_headers: None,
        api_key_header: None,
        api_key_query_param: None,
        auth_type: None,
        cache_ttl_seconds: None,
        gateway_fee_percent: None,
        grace_period_minutes: None,
        hourly_rate: None,
        jwt_access_key: None,
        jwt_algorithm: None,
        jwt_expiration_seconds: None,
        jwt_secret_key: None,
        low_balance_threshold: None,
        markup_multiplier: None,
        minimum_balance: None,
        ownership_tracking_enabled: None,
        price_per_call: None,
        price_per_delete: None,
        price_per_get: None,
        price_per_patch: None,
        price_per_post: None,
        price_per_put: None,
        protected_operations: None,
        publisher_type: None,
        resource_description: None,
        resource_id_response_path: None,
        resource_id_url_pattern: None,
        resource_name: None,
        upstream_api_key: None,
        usage_example: None,
    };

    let response = client
        .create_publisher_api_key(&body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create publisher: {}", e))?;

    let publisher = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&publisher)?,
        OutputFormat::Table => {
            println!("{}", "Publisher created successfully!".green().bold());
            println!();
            output::print_marketplace_publisher(&publisher.data, ctx.format)?;
        }
    }

    Ok(())
}

/// Execute a paid database query using prepaid balance
pub async fn execute_query(
    publisher: &str,
    query: &str,
    database: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    // Resolve publisher to ID
    let publisher_id = if let Ok(uuid) = Uuid::parse_str(publisher) {
        uuid
    } else {
        let response = client
            .get_marketplace_publisher(publisher)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get publisher: {}", e))?;
        response.into_inner().data.id
    };

    let body = seren::QueryRequestBody {
        publisher_id,
        query: query.to_string(),
        database: database.map(|s| s.to_string()),
        asset_id: None,
        request_id: None,
    };

    let response = client
        .execute_query(&body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute query: {}", e))?;

    let result = response.into_inner();
    output::print_json(&result)?;

    Ok(())
}

/// Get prepaid balance summary for authenticated user
pub async fn get_prepaid_balance(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_user_balance_summary()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get prepaid balance: {}", e))?;

    let summary = response.into_inner();
    output::print_json(&summary)?;

    Ok(())
}

/// Create a prepaid deposit (fiat)
pub async fn create_prepaid_deposit(
    publisher: &str,
    amount: f64,
    currency: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    // Resolve publisher to get asset IDs
    let pub_response = client
        .get_marketplace_publisher(publisher)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get publisher: {}", e))?;
    let pub_data = pub_response.into_inner().data;

    // Use the first accepted asset or fail
    let target_asset_id = pub_data
        .accepted_assets
        .as_ref()
        .and_then(|assets| assets.first())
        .map(|asset| asset.id)
        .ok_or_else(|| anyhow::anyhow!("Publisher has no accepted assets"))?;

    let body = seren::CreateUserDepositRequest {
        publisher_id: pub_data.id,
        amount,
        currency: currency.map(|s| s.to_string()),
        target_asset_id,
        provider: None,
    };

    let response = client
        .create_user_deposit(&body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create deposit: {}", e))?;

    let deposit = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&deposit)?,
        OutputFormat::Table => {
            println!("{}", "Prepaid deposit initiated!".green().bold());
            println!();
            println!("Complete the payment using your payment provider (e.g., Stripe).");
            println!();
            output::print_json(&deposit)?;
        }
    }

    Ok(())
}

/// Estimate the cost of a query against a publisher
pub async fn estimate_query_cost(publisher: &str, query: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    // Resolve publisher to ID
    let publisher_id = if let Ok(uuid) = Uuid::parse_str(publisher) {
        uuid
    } else {
        let response = client
            .get_marketplace_publisher(publisher)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get publisher: {}", e))?;
        response.into_inner().data.id
    };

    let body = seren::EstimateRequestBody {
        publisher_id,
        query: query.to_string(),
        asset_id: None,
    };

    let response = client
        .estimate_query(&body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to estimate cost: {}", e))?;

    let estimate = response.into_inner();
    output::print_json(&estimate)?;

    Ok(())
}

/// List all wallets for authenticated user
pub async fn list_wallets(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_wallets()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list wallets: {}", e))?;

    let wallets = response.into_inner();
    output::print_json(&wallets)?;

    Ok(())
}

/// Create a new managed wallet
pub async fn create_wallet(set_as_primary: bool, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let body = seren::CreateManagedWalletRequest {
        set_as_primary: if set_as_primary { Some(true) } else { None },
    };

    let response = client
        .create_managed_wallet(&body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create wallet: {}", e))?;

    let wallet = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&wallet)?,
        OutputFormat::Table => {
            println!("{}", "Managed wallet created successfully!".green().bold());
            println!();
            output::print_json(&wallet)?;
        }
    }

    Ok(())
}

/// Delete a wallet
pub async fn delete_wallet(wallet_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let wallet_uuid =
        Uuid::parse_str(wallet_id).map_err(|e| anyhow::anyhow!("Invalid wallet ID: {}", e))?;

    client
        .delete_wallet(&wallet_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete wallet: {}", e))?;

    println!("{}", "Wallet deleted successfully.".green().bold());

    Ok(())
}

/// Export wallet private key
pub async fn export_wallet_key(wallet_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let wallet_uuid =
        Uuid::parse_str(wallet_id).map_err(|e| anyhow::anyhow!("Invalid wallet ID: {}", e))?;

    let response = client
        .export_wallet_key(&wallet_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to export wallet key: {}", e))?;

    let key = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&key)?,
        OutputFormat::Table => {
            println!(
                "{}",
                "SECURITY WARNING: Store this key securely!".red().bold()
            );
            println!();
            output::print_json(&key)?;
        }
    }

    Ok(())
}

/// Set a wallet as primary
pub async fn set_wallet_primary(wallet_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let wallet_uuid =
        Uuid::parse_str(wallet_id).map_err(|e| anyhow::anyhow!("Invalid wallet ID: {}", e))?;

    let response = client
        .set_wallet_primary(&wallet_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set wallet as primary: {}", e))?;

    let wallet = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&wallet)?,
        OutputFormat::Table => {
            println!("{}", "Wallet set as primary successfully!".green().bold());
            println!();
            output::print_json(&wallet)?;
        }
    }

    Ok(())
}
