use anyhow::Result;
use colored::Colorize;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, defaults, output};

/// List all active publishers in the store
pub async fn list_publishers(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_store_publishers(
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
        .get_store_publisher(publisher)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get publisher: {}", e))?;

    let pub_info = response.into_inner();
    output::print_store_publisher(&pub_info.data, ctx.format)?;

    Ok(())
}

fn truncate_for_cli(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_none() {
        return truncated;
    }
    format!("{truncated}... (truncated)")
}

async fn format_payment_required_response(response: reqwest::Response) -> String {
    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();

    if let Ok(body_json) = serde_json::from_str::<serde_json::Value>(&body_text) {
        let payment_response = body_json
            .get("payment_response")
            .or_else(|| body_json.get("paymentResponse"));
        let accepts = payment_response
            .and_then(|p| p.get("accepts"))
            .and_then(|a| a.as_array());

        if let (Some(_payment_response), Some(accepts)) = (payment_response, accepts)
            && let Some(first) = accepts.first()
        {
            let scheme = first
                .get("scheme")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            if scheme == "prepaid" {
                let extra = first.get("extra").unwrap_or(&serde_json::Value::Null);
                let required = extra
                    .get("requiredAmount")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let available = extra
                    .get("availableBalance")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let deficit = extra.get("deficit").and_then(|v| v.as_str()).unwrap_or("?");

                let top_up = extra.get("topUp").unwrap_or(&serde_json::Value::Null);
                let balance_endpoint = top_up
                    .get("balanceEndpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/agent/wallet/balance");
                let deposit_endpoint = top_up
                    .get("depositEndpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/agent/wallet/deposit");

                return format!(
                    "Payment Required (402): insufficient SerenBucks balance. Required ${required}, available ${available}, deficit ${deficit}. Deposit more via {deposit_endpoint} and check balance via {balance_endpoint}."
                );
            }
        }
    }

    format!(
        "Payment Required (402): {status} - {}",
        truncate_for_cli(&body_text, 1200)
    )
}

async fn anyhow_from_seren_error(context: &str, err: seren::Error<()>) -> anyhow::Error {
    match err {
        seren::Error::UnexpectedResponse(response)
            if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED =>
        {
            anyhow::anyhow!(format_payment_required_response(response).await)
        }
        seren::Error::UnexpectedResponse(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::anyhow!(
                "{context}: unexpected response {status} - {}",
                truncate_for_cli(&body, 1200)
            )
        }
        other => anyhow::anyhow!("{context}: {other}"),
    }
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
            .list_store_publishers(None, Some(100), None, Some(publisher))
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

/// Create a new publisher in the store
#[allow(clippy::too_many_arguments)]
pub async fn create_publisher(
    name: &str,
    slug: &str,
    email: Option<&str>,
    wallet_address: &str,
    wallet_network_id: &str,
    publisher_category: &str,
    database_type: Option<&str>,
    integration_type: Option<&str>,
    description: Option<&str>,
    api_url: Option<&str>,
    mcp_endpoint: Option<&str>,
    project_id: Option<Uuid>,
    branch_id: Option<Uuid>,
    database_name: Option<&str>,
    base_price_per_1000_rows: Option<&str>,
    billing_model: Option<&str>,
    connection_string: Option<&str>,
    upstream_api_key: Option<&str>,
    auth_type: Option<&str>,
    oauth2_token_url: Option<&str>,
    oauth2_client_id: Option<&str>,
    oauth2_client_secret: Option<&str>,
    oauth2_scopes: Vec<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    // Convert publisher_category string to enum
    let publisher_category_enum = {
        let normalized = publisher_category.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "database" => seren::PublisherCategory::Database,
            "integration" => seren::PublisherCategory::Integration,
            "compute" => seren::PublisherCategory::Compute,
            other => {
                return Err(anyhow::anyhow!(
                    "Invalid publisher_category '{}'. Expected one of: database, integration, compute",
                    other
                ));
            }
        }
    };

    // Convert database_type string to enum
    let database_type_enum = match database_type {
        None => None,
        Some(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            let parsed = match normalized.as_str() {
                "serendb" => seren::DatabaseType::Serendb,
                "neon" => seren::DatabaseType::Neon,
                "supabase" => seren::DatabaseType::Supabase,
                "mongodb" => seren::DatabaseType::Mongodb,
                other => {
                    return Err(anyhow::anyhow!(
                        "Invalid database_type '{}'. Expected one of: serendb, neon, supabase, mongodb",
                        other
                    ));
                }
            };
            Some(parsed)
        }
    };

    // Convert integration_type string to enum
    let integration_type_enum = match integration_type {
        None => None,
        Some(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            let parsed = match normalized.as_str() {
                "api" => seren::IntegrationType::Api,
                "mcp" => seren::IntegrationType::Mcp,
                other => {
                    return Err(anyhow::anyhow!(
                        "Invalid integration_type '{}'. Expected one of: api, mcp",
                        other
                    ));
                }
            };
            Some(parsed)
        }
    };

    // Build database_config JSON if connection_string is provided
    let database_config = connection_string.map(|cs| {
        serde_json::json!({
            "connection_string": cs
        })
    });

    let upstream_api_key = upstream_api_key
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let auth_type = match auth_type {
        None => None,
        Some(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Err(anyhow::anyhow!("auth_type must not be empty"));
            }
            match normalized.as_str() {
                "static" | "jwt" | "oauth2_cc" => Some(normalized),
                other => {
                    return Err(anyhow::anyhow!(
                        "Invalid auth_type '{}'. Expected one of: static, jwt, oauth2_cc",
                        other
                    ));
                }
            }
        }
    };

    // MongoDB Atlas Data API publishers require api_url + upstream_api_key.
    if publisher_category_enum == seren::PublisherCategory::Database
        && matches!(database_type_enum, Some(seren::DatabaseType::Mongodb))
    {
        if api_url.is_none() {
            return Err(anyhow::anyhow!(
                "api_url is required for database_type=mongodb (Atlas Data API base URL)"
            ));
        }
        if upstream_api_key.is_none() {
            return Err(anyhow::anyhow!(
                "upstream_api_key is required for database_type=mongodb (Atlas Data API key)"
            ));
        }
    }

    let oauth2_token_url = oauth2_token_url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref url) = oauth2_token_url
        && !url.starts_with("https://")
    {
        return Err(anyhow::anyhow!("oauth2_token_url must use HTTPS"));
    }

    let oauth2_client_id = oauth2_client_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let oauth2_client_secret = oauth2_client_secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut normalized_scopes = Vec::with_capacity(oauth2_scopes.len());
    for (i, scope) in oauth2_scopes.into_iter().enumerate() {
        let trimmed = scope.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("oauth2_scopes[{}] must not be empty", i));
        }
        normalized_scopes.push(trimmed.to_string());
    }

    if auth_type.as_deref() == Some("oauth2_cc")
        && (oauth2_token_url.is_none()
            || oauth2_client_id.is_none()
            || oauth2_client_secret.is_none())
    {
        return Err(anyhow::anyhow!(
            "oauth2_token_url, oauth2_client_id, and oauth2_client_secret are required when auth_type is oauth2_cc"
        ));
    }

    if auth_type.as_deref() != Some("oauth2_cc")
        && (oauth2_token_url.is_some()
            || oauth2_client_id.is_some()
            || oauth2_client_secret.is_some()
            || !normalized_scopes.is_empty())
    {
        return Err(anyhow::anyhow!(
            "oauth2_* fields require auth_type=oauth2_cc"
        ));
    }

    let body = seren::CreatePublisherRequest {
        name: name.to_string(),
        slug: slug.to_string(),
        email: email.map(|s| s.to_string()),
        wallet_address: seren::WalletAddress(wallet_address.to_string()),
        wallet_network_id: wallet_network_id.to_string(),
        publisher_category: publisher_category_enum,
        database_type: database_type_enum,
        integration_type: integration_type_enum,
        compute_type: None,
        description: description.map(|s| s.to_string()),
        api_url: api_url.map(|s| s.to_string()),
        mcp_endpoint: mcp_endpoint.map(|s| s.to_string()),
        project_id,
        branch_id,
        database_name: database_name.map(|s| s.to_string()),
        base_price_per_1000_rows: base_price_per_1000_rows.map(|s| s.to_string()),
        billing_model: billing_model.map(|s| s.to_string()),
        categories: vec![],
        capabilities: vec![],
        use_cases: vec![],
        logo_url: None,
        accepted_asset_ids: None,
        allowed_passthrough_headers: vec![],
        api_headers: None,
        api_key_header: None,
        api_key_query_param: None,
        auth_type,
        oauth2_token_url,
        oauth2_client_id,
        oauth2_client_secret,
        oauth2_scopes: normalized_scopes,
        database_config,
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
        price_per_execution: None,
        price_per_get: None,
        price_per_patch: None,
        price_per_post: None,
        price_per_put: None,
        protected_operations: None,
        endpoints: None,
        undocumented_endpoint_policy: None,
        publisher_type: None,
        resource_description: None,
        resource_id_response_path: None,
        resource_id_url_pattern: None,
        upstream_cost_response_path: None,
        resource_name: None,
        upstream_api_key,
        usage_examples: None,
        request_content_type: None,
        upstream_headers: None,
        token_exchange_url: None,
        token_exchange_method: None,
        token_exchange_mode: None,
        token_cache_ttl_seconds: None,
        token_response_field: None,
        oauth_provider_slug: None,
        requires_user_oauth: Some(false),
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
            output::print_store_publisher(&publisher.data, ctx.format)?;
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

    let body = seren::DatabaseQueryRequest {
        query: query.to_string(),
        database: database.map(|s| s.to_string()),
        params: vec![],
    };

    let response = match client.publisher_root_handler(publisher, &body.into()).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to execute query", e).await),
    };

    let result = response.into_inner();
    output::print_json(&result)?;

    Ok(())
}

/// Get prepaid balance summary for authenticated user
pub async fn get_prepaid_balance(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_wallet_balance()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get SerenBucks balance: {}", e))?;

    let summary = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&summary)?,
        OutputFormat::Table => {
            let data = &summary.data;
            let rows = [
                ("Wallet", data.wallet_address.to_string()),
                ("Total", format!("{} SerenBucks", data.balance_usd)),
                ("Funded", format!("{} SerenBucks", data.funded_balance_usd)),
                (
                    "Promotional",
                    format!("{} SerenBucks", data.promotional_balance_usd),
                ),
            ];
            output::print_key_value_table(Some("SerenBucks Balance"), &rows);
        }
    }

    Ok(())
}

/// Create a prepaid deposit (fiat)
pub async fn create_prepaid_deposit(amount: f64, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    if amount <= 0.0 {
        return Err(anyhow::anyhow!("Amount must be positive"));
    }

    let amount_cents = (amount * 100.0).round() as i64;
    if amount_cents < 500 {
        return Err(anyhow::anyhow!("Minimum deposit is $5.00"));
    }

    let body = seren::DepositRequest {
        amount_cents,
        referral_code: None,
    };

    let response = match client.create_deposit(&body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to create deposit", e).await),
    };

    let deposit = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&deposit)?,
        OutputFormat::Table => {
            let data = &deposit.data;
            let rows = [
                ("Deposit ID", data.deposit_id.to_string()),
                ("Amount", format!("{} SerenBucks", data.amount_usd)),
                ("Bonus", format!("{} SerenBucks", data.bonus_usd)),
                ("Total", format!("{} SerenBucks", data.total_usd)),
            ];
            output::print_key_value_table(Some("SerenBucks Deposit"), &rows);
            println!();
            println!("Open this URL in your browser to complete payment:");
            println!("  {}", data.checkout_url);
            println!();
            println!(
                "SerenBucks will be added to your balance automatically after payment succeeds."
            );
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
            .get_store_publisher(publisher)
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

/// Get wallet transaction history
pub async fn get_transaction_history(
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_transactions(limit, offset)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get transaction history: {}", e))?;

    let history = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&history)?,
        OutputFormat::Table => {
            let data = &history.data;
            println!("{}", "Wallet Transaction History".bold());
            println!(
                "Showing {} of {} transactions",
                data.transactions.len(),
                data.total
            );
            println!();
            if data.transactions.is_empty() {
                println!("No transactions found.");
            } else {
                for tx in &data.transactions {
                    println!(
                        "{} | {} | {} | ${}",
                        tx.created_at,
                        tx.source,
                        tx.description.as_deref().unwrap_or("-"),
                        tx.amount_usd
                    );
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Agent Template Commands
// =============================================================================

/// List available agent templates in the catalog
pub async fn list_templates(
    language: Option<&str>,
    verified_only: Option<bool>,
    search: Option<&str>,
    limit: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_templates(
            language,
            limit,
            None, // max_price
            None, // min_price
            None, // offset
            search,
            None, // sort_by
            verified_only,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list templates: {}", e))?;

    let templates = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&templates)?,
        OutputFormat::Table => {
            println!("{}", "Agent Templates".bold());
            println!();
            if templates.data.is_empty() {
                println!("No templates found.");
            } else {
                for t in &templates.data {
                    let verified = if t.is_verified { "✓" } else { " " };
                    let price_usd = t.price_atomic as f64 / 1_000_000.0;
                    println!(
                        "{} {} ({:?}) - ${:.4} per invocation",
                        verified, t.slug, t.language, price_usd
                    );
                    if let Some(desc) = &t.description {
                        println!("   {}", desc);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Get details about a specific agent template
pub async fn get_template(slug: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .get_template(slug)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get template: {}", e))?;

    let template = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&template)?,
        OutputFormat::Table => {
            let t = &template.data;
            println!("{}", t.name.bold());
            println!();
            let price_usd = t.price_atomic as f64 / 1_000_000.0;
            let rows = [
                ("ID", t.id.to_string()),
                ("Slug", t.slug.clone()),
                ("Language", format!("{:?}", t.language)),
                ("Price", format!("${:.4} per invocation", price_usd)),
                (
                    "Verified",
                    if t.is_verified { "Yes" } else { "No" }.to_string(),
                ),
            ];
            output::print_key_value_table(None, &rows);
            if let Some(desc) = &t.description {
                println!();
                println!("{}", "Description:".bold());
                println!("{}", desc);
            }
        }
    }

    Ok(())
}

/// Publish a new agent template
#[allow(clippy::too_many_arguments)]
pub async fn publish_template(
    name: &str,
    slug: &str,
    code: &str,
    language: &str,
    price: &str,
    description: Option<&str>,
    dependencies: Option<&str>,
    compute_backend: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    // Read code from file
    let code_content = std::fs::read_to_string(code)
        .map_err(|e| anyhow::anyhow!("Failed to read code file '{}': {}", code, e))?;

    // Parse dependencies from comma-separated string
    let deps = dependencies.map(|s| {
        s.split(',')
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>()
    });

    let body = seren::CreateTemplateRequest {
        name: name.to_string(),
        slug: slug.to_string(),
        code: code_content,
        language: language.to_string(),
        price: price.to_string(),
        description: description.map(|s| s.to_string()),
        dependencies: deps,
        compute_backend: compute_backend.map(|s| s.to_string()),
        llm_config: None,
    };

    let response = match client.publish_template(&body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to publish template", e).await),
    };

    let result = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            println!("{}", "Template published successfully!".green().bold());
            println!();
            let t = &result.data;
            let price_usd = t.price_atomic as f64 / 1_000_000.0;
            let rows = [
                ("ID", t.id.to_string()),
                ("Slug", t.slug.clone()),
                ("Name", t.name.clone()),
                ("Language", format!("{:?}", t.language)),
                ("Price", format!("${:.4} per invocation", price_usd)),
            ];
            output::print_key_value_table(None, &rows);
        }
    }

    Ok(())
}

/// Invoke an agent template
pub async fn invoke_template(slug: &str, input: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    // Parse input as JSON
    let input_json: serde_json::Value =
        serde_json::from_str(input).map_err(|e| anyhow::anyhow!("Invalid JSON input: {}", e))?;

    let body = seren::InvokeTemplateRequest { input: input_json };

    let response = match client.invoke_template(slug, &body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to invoke template", e).await),
    };

    let result = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            let data = &result.data;
            println!("{}", "Template Invocation Result".bold());
            println!();

            // Show execution info
            let rows = [
                ("Invocation ID", data.invocation_id.to_string()),
                ("Execution Time", format!("{}ms", data.execution_time_ms)),
            ];
            output::print_key_value_table(Some("Execution"), &rows);

            // Show cost info
            let cost = &data.cost;
            println!();
            let cost_rows = [
                ("Compute Cost", format!("${}", cost.compute_cost)),
                ("LLM Cost", format!("${}", cost.llm_cost)),
                ("Publisher Fee", format!("${}", cost.publisher_fee)),
                ("Total Cost", format!("${}", cost.total)),
            ];
            output::print_key_value_table(Some("Cost"), &cost_rows);

            // Show output
            println!();
            println!("{}", "Output:".bold());
            println!(
                "{}",
                serde_json::to_string_pretty(&data.result)
                    .unwrap_or_else(|_| "Failed to format output".to_string())
            );
        }
    }

    Ok(())
}
