use std::path::Path;

use anyhow::Result;
use base64::Engine;
use colored::Colorize;
use uuid::Uuid;

use crate::money::format_usd_micros_4;
use crate::{CommandContext, OutputFormat, defaults, output};

/// List all active publishers in the store
pub async fn list_publishers(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_store_publishers(
            None, // category
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
                    .unwrap_or("/wallet/balance");
                let deposit_endpoint = top_up
                    .get("depositEndpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/wallet/deposit");

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
            .list_store_publishers(None, None, Some(100), None, Some(publisher))
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
    let url = format!("{}/wallet/deposit", base_url);

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

/// Create a new publisher in an organization
#[allow(clippy::too_many_arguments)]
pub async fn create_publisher(
    organization_id: &Uuid,
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
    upstream_cost_response_path: Option<&str>,
    connection_string: Option<&str>,
    upstream_api_key: Option<&str>,
    database_config_json: Option<&str>,
    auth_type: Option<&str>,
    allowed_passthrough_headers: Vec<String>,
    oauth2_token_url: Option<&str>,
    oauth2_client_id: Option<&str>,
    oauth2_client_secret: Option<&str>,
    oauth2_scopes: Vec<String>,
    use_cases: Option<Vec<String>>,
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

    let database_config_from_json = match database_config_json {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!("database_config_json must not be empty"));
            }

            let parsed: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| anyhow::anyhow!("Invalid database_config_json: {}", e))?;

            if !parsed.is_object() {
                return Err(anyhow::anyhow!(
                    "database_config_json must decode to a JSON object"
                ));
            }

            Some(parsed)
        }
    };

    if connection_string.is_some() && database_config_from_json.is_some() {
        return Err(anyhow::anyhow!(
            "connection_string cannot be combined with database_config_json"
        ));
    }

    let database_config = if let Some(cs) = connection_string {
        Some(serde_json::json!({ "connection_string": cs }))
    } else {
        database_config_from_json
    };

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
                "static" | "jwt" | "oauth2_cc" | "passthrough" => Some(normalized),
                other => {
                    return Err(anyhow::anyhow!(
                        "Invalid auth_type '{}'. Expected one of: static, jwt, oauth2_cc, passthrough",
                        other
                    ));
                }
            }
        }
    };

    let mut allowed_passthrough_headers_normalized =
        Vec::with_capacity(allowed_passthrough_headers.len());
    for (i, header) in allowed_passthrough_headers.into_iter().enumerate() {
        let trimmed = header.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!(
                "allowed_passthrough_headers[{}] must not be empty",
                i
            ));
        }
        allowed_passthrough_headers_normalized.push(trimmed.to_string());
    }

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
        if connection_string.is_some() {
            return Err(anyhow::anyhow!(
                "connection_string is not valid for database_type=mongodb; use api_url + upstream_api_key and optional database_config_json"
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

    let mut normalized_use_cases =
        Vec::with_capacity(use_cases.as_ref().map_or(0, |cases| cases.len()));
    for (i, use_case) in use_cases.unwrap_or_default().into_iter().enumerate() {
        let trimmed = use_case.trim();
        if trimmed.is_empty() {
            return Err(anyhow::anyhow!("use_cases[{}] must not be empty", i));
        }
        normalized_use_cases.push(trimmed.to_string());
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
        use_cases: normalized_use_cases,
        logo_url: None,
        accepted_asset_ids: None,
        allowed_passthrough_headers: allowed_passthrough_headers_normalized,
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
        upstream_cost_response_path: upstream_cost_response_path.map(|s| s.to_string()),
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
        routing: None,
    };

    let response = client
        .create_publisher(organization_id, &body)
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
pub async fn create_prepaid_deposit(amount_cents: i64, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    if amount_cents <= 0 {
        return Err(anyhow::anyhow!("Amount must be positive"));
    }

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
        .estimate_query(publisher, &body)
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
                    let price_usd = format_usd_micros_4(t.price_atomic);
                    println!(
                        "{} {} ({:?}) - ${} per invocation",
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
            let price_usd = format_usd_micros_4(t.price_atomic);
            let rows = [
                ("ID", t.id.to_string()),
                ("Slug", t.slug.clone()),
                ("Language", format!("{:?}", t.language)),
                ("Price", format!("${} per invocation", price_usd)),
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

    let language_norm = language.trim().to_ascii_lowercase();
    let language: seren::TemplateLanguage = language_norm.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid language '{}'. Expected one of: python, typescript, javascript.",
            language
        )
    })?;

    let body = seren::CreateTemplateRequest {
        name: name.to_string(),
        slug: slug.to_string(),
        code: code_content,
        language,
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
            let price_usd = format_usd_micros_4(t.price_atomic);
            let rows = [
                ("ID", t.id.to_string()),
                ("Slug", t.slug.clone()),
                ("Name", t.name.clone()),
                ("Language", format!("{:?}", t.language)),
                ("Price", format!("${} per invocation", price_usd)),
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

/// Run an agent task in the cloud.
pub async fn run_cloud(publisher: &str, message: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!("{}/publishers/{}", ctx.api_base(), publisher);

    // Try to parse message as JSON, fall back to text wrapper
    let message_value: serde_json::Value =
        serde_json::from_str(message).unwrap_or_else(|_| serde_json::json!({"text": message}));

    let response = client
        .post(&url)
        .json(&message_value)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    if !response.status().is_success() && response.status().as_u16() != 202 {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to run agent: {} - {}",
            status,
            body
        ));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// List agent tasks for an organization.
pub async fn list_agent_tasks(
    org_id: &str,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/organizations/{}/agents/tasks?limit={}&offset={}",
        ctx.api_base(),
        org_id,
        limit,
        offset
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to list tasks: {} - {}",
            status,
            body
        ));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// Get details of a specific agent task. With --follow, streams SSE events.
pub async fn get_agent_task(
    org_id: &str,
    task_id: &str,
    follow: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.http_client().await?;

    if follow {
        return follow_agent_task(&client, ctx.api_base(), org_id, task_id).await;
    }

    let url = format!(
        "{}/organizations/{}/agents/tasks/{}",
        ctx.api_base(),
        org_id,
        task_id
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed to get task: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// Follow an agent task via SSE streaming, printing events as they arrive.
async fn follow_agent_task(
    client: &reqwest::Client,
    api_base: String,
    org_id: &str,
    task_id: &str,
) -> Result<()> {
    use futures_util::StreamExt;

    let url = format!(
        "{}/organizations/{}/agents/tasks/{}/stream",
        api_base, org_id, task_id
    );

    eprintln!(
        "{}",
        format!("Following task {task_id}... (Ctrl+C to stop)").dimmed()
    );

    let response = client
        .get(&url)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("SSE connection failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to stream task: {} - {}",
            status,
            body
        ));
    }

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("Stream read error: {}", e))?;
        let normalized = String::from_utf8_lossy(&chunk)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        buffer.push_str(&normalized);

        while let Some(end) = buffer.find("\n\n") {
            let event_block = buffer[..end].to_string();
            buffer = buffer[end + 2..].to_string();

            let mut event_type = String::new();
            let mut data_lines: Vec<String> = Vec::new();

            for line in event_block.lines() {
                if let Some(et) = line.strip_prefix("event:") {
                    event_type = et.trim().to_string();
                } else if let Some(d) = line.strip_prefix("data:") {
                    data_lines.push(d.trim_start().to_string());
                }
            }

            if data_lines.is_empty() {
                continue;
            }

            let data = data_lines.join("\n");
            let is_terminal_event = matches!(
                event_type.as_str(),
                "task.completed" | "task.failed" | "task.canceled" | "task.cancelled"
            );

            if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&data) {
                let is_terminal_status = payload
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|status| {
                        matches!(status, "completed" | "failed" | "canceled" | "cancelled")
                    })
                    .unwrap_or(false);
                let display = if event_type.is_empty() {
                    "event"
                } else {
                    event_type.as_str()
                };

                if is_terminal_event || is_terminal_status {
                    let status = payload
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let status_text = match status {
                        "completed" => format!("Task {status}").green().bold(),
                        "failed" | "canceled" | "cancelled" => {
                            format!("Task {status}").red().bold()
                        }
                        _ => format!("Task {status}").yellow().bold(),
                    };
                    eprintln!("{status_text}");

                    if let Some(output) = payload.get("output") {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(output).unwrap_or_default()
                        );
                    }
                    if let Some(err) = payload.get("error_message").and_then(|v| v.as_str()) {
                        eprintln!("{}: {}", "Error".red().bold(), err);
                    }
                    if let Some(cost) = payload.get("cost_total_atomic").and_then(|v| v.as_i64()) {
                        let cost_usd = format_usd_micros_4(cost);
                        eprintln!("{}", format!("Cost: ${cost_usd}").dimmed());
                    }
                    return Ok(());
                }

                eprintln!(
                    "{} {}",
                    format!("[{display}]").cyan(),
                    serde_json::to_string(&payload).unwrap_or_else(|_| data.clone())
                );
            } else {
                let display = if event_type.is_empty() {
                    "event"
                } else {
                    event_type.as_str()
                };
                eprintln!("{} {}", format!("[{display}]").cyan(), data);
                if is_terminal_event {
                    return Ok(());
                }
            }
        }
    }

    eprintln!("{}", "Stream ended.".dimmed());
    Ok(())
}

fn normalize_local_a2a_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    if let Ok(url) = reqwest::Url::parse(endpoint) {
        let path = url.path().trim_end_matches('/');
        if path.is_empty() || path == "/" {
            return format!("{trimmed}/a2a");
        }
    }
    trimmed.to_string()
}

fn local_a2a_discovery_base(endpoint: &str) -> String {
    let normalized = normalize_local_a2a_endpoint(endpoint);
    normalized
        .strip_suffix("/a2a")
        .unwrap_or(&normalized)
        .to_string()
}

fn build_local_a2a_message(message: &str) -> serde_json::Value {
    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(message) {
        if json_val.get("role").is_some() && json_val.get("parts").is_some() {
            return json_val;
        }
        return serde_json::json!({
            "role": "user",
            "parts": [{"type": "data", "data": json_val}],
            "messageId": Uuid::new_v4().to_string(),
        });
    }

    serde_json::json!({
        "role": "user",
        "parts": [{"type": "text", "text": message}],
        "messageId": Uuid::new_v4().to_string(),
    })
}

fn print_a2a_text_parts(parts: Option<&Vec<serde_json::Value>>) {
    if let Some(parts) = parts {
        for part in parts {
            if part.get("type").and_then(|v| v.as_str()) == Some("text")
                && let Some(text) = part.get("text").and_then(|v| v.as_str())
            {
                println!("{text}");
            }
        }
    }
}

/// Run an agent locally via A2A protocol (direct connection, no billing).
pub async fn run_local(
    endpoint: &str,
    message: &str,
    stream: bool,
    _ctx: &CommandContext,
) -> Result<()> {
    use futures_util::StreamExt;

    let http = reqwest::Client::new();
    let discovery_base = local_a2a_discovery_base(endpoint);
    let card_url = format!("{discovery_base}/.well-known/agent.json");

    eprintln!(
        "{}",
        format!("Resolving agent card from {card_url}...").dimmed()
    );

    let card_resp = http
        .get(&card_url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to resolve agent card: {e}"))?;

    if !card_resp.status().is_success() {
        let status = card_resp.status();
        let body = card_resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to resolve agent card: {} - {}",
            status,
            body
        ));
    }

    let card: serde_json::Value = card_resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Invalid agent card response: {e}"))?;

    let card_name = card
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-agent");
    let card_description = card
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let supports_streaming = card
        .get("capabilities")
        .and_then(|v| v.get("streaming"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let rpc_endpoint = card
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| normalize_local_a2a_endpoint(endpoint));

    eprintln!(
        "{}",
        format!("Connected to {card_name} ({card_description})").dimmed()
    );

    let a2a_message = build_local_a2a_message(message);

    if stream {
        if !supports_streaming {
            return Err(anyhow::anyhow!(
                "Agent does not advertise streaming support; rerun without --stream"
            ));
        }

        eprintln!("{}", "Streaming...".dimmed());
        let stream_url = format!("{}/stream", rpc_endpoint.trim_end_matches('/'));
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "message/stream",
            "params": {"message": a2a_message},
        });

        let response = http
            .post(&stream_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Stream request failed: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Failed to stream local agent: {} - {}",
                status,
                body
            ));
        }

        let mut bytes_stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk_result) = bytes_stream.next().await {
            let chunk = chunk_result.map_err(|e| anyhow::anyhow!("Stream read error: {e}"))?;
            let normalized = String::from_utf8_lossy(&chunk)
                .replace("\r\n", "\n")
                .replace('\r', "\n");
            buffer.push_str(&normalized);

            while let Some(event_end) = buffer.find("\n\n") {
                let event_block = buffer[..event_end].to_string();
                buffer = buffer[event_end + 2..].to_string();

                let mut data_lines: Vec<String> = Vec::new();
                for line in event_block.lines() {
                    if let Some(data) = line.strip_prefix("data:") {
                        data_lines.push(data.trim_start().to_string());
                    }
                }

                if data_lines.is_empty() {
                    continue;
                }

                let data = data_lines.join("\n");
                let payload: serde_json::Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{} unparseable event: {e}", "[stream]".yellow());
                        continue;
                    }
                };

                if let Some(err) = payload.get("error") {
                    let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or_default();
                    let message = err
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown error");
                    return Err(anyhow::anyhow!("A2A stream error {}: {}", code, message));
                }

                let result = payload.get("result").unwrap_or(&payload);

                if let Some(status) = result.get("status") {
                    let state = status
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let final_update = result
                        .get("final")
                        .or_else(|| result.get("final_update"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    eprintln!(
                        "{}",
                        format!("[status] {state} (final={final_update})").cyan()
                    );
                    print_a2a_text_parts(
                        status
                            .get("message")
                            .and_then(|m| m.get("parts"))
                            .and_then(|v| v.as_array()),
                    );

                    if final_update
                        || matches!(state, "completed" | "failed" | "canceled" | "cancelled")
                    {
                        return Ok(());
                    }
                    continue;
                }

                if let Some(artifact_parts) = result
                    .get("artifact")
                    .and_then(|a| a.get("parts"))
                    .and_then(|v| v.as_array())
                {
                    eprintln!("{}", "[artifact]".cyan());
                    print_a2a_text_parts(Some(artifact_parts));
                }
            }
        }

        eprintln!("{}", "Stream ended.".dimmed());
        Ok(())
    } else {
        eprintln!("{}", "Sending message...".dimmed());
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "message/send",
            "params": {"message": a2a_message},
        });

        let response = http
            .post(&rpc_endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Agent call failed: {e}"))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Agent call failed: {} - {}", status, body));
        }

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Invalid A2A response: {e}"))?;

        if let Some(err) = payload.get("error") {
            let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or_default();
            let message = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(anyhow::anyhow!("A2A error {}: {}", code, message));
        }

        let result = payload.get("result").cloned().unwrap_or(payload);
        output::print_json(&result)?;
        Ok(())
    }
}
/// Cancel a running agent task.
pub async fn cancel_agent_task(org_id: &str, task_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/organizations/{}/agents/tasks/{}/cancel",
        ctx.api_base(),
        org_id,
        task_id
    );

    let response = client
        .post(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to cancel task: {} - {}",
            status,
            body
        ));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

// =============================================================================
// Cloud Deployment Commands
// =============================================================================

const SEREN_CLOUD_SLUG: &str = "seren-cloud";
const SEREN_AGENT_SLUG: &str = "seren-agent";

pub struct CloudDeployOptions<'a> {
    pub publisher_slug: Option<&'a str>,
    pub name: Option<&'a str>,
    pub mode: &'a str,
    pub cron_schedule: Option<&'a str>,
    pub compute_backend: Option<&'a str>,
    pub runtime_kind: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
}

const MAX_CLOUD_CODE_BUNDLE_BYTES: usize = 1_000_000;

fn normalize_deploy_publisher_slug(publisher_slug: Option<&str>) -> Result<&'static str> {
    match publisher_slug.unwrap_or(SEREN_CLOUD_SLUG) {
        SEREN_CLOUD_SLUG => Ok(SEREN_CLOUD_SLUG),
        SEREN_AGENT_SLUG => Ok(SEREN_AGENT_SLUG),
        other => Err(anyhow::anyhow!(
            "Invalid deploy publisher '{}'. Use 'seren-cloud' or 'seren-agent'.",
            other
        )),
    }
}

/// Deploy a skill directory to Seren Cloud.
pub async fn cloud_deploy(
    path: &str,
    options: CloudDeployOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let CloudDeployOptions {
        publisher_slug,
        name,
        mode,
        cron_schedule,
        compute_backend,
        runtime_kind,
        config_path,
        env_path,
    } = options;
    let deploy_publisher = normalize_deploy_publisher_slug(publisher_slug)?;

    let skill_dir = Path::new(path);
    if !skill_dir.is_dir() {
        return Err(anyhow::anyhow!("'{}' is not a directory", path));
    }

    let scripts_dir = skill_dir.join("scripts");
    if !scripts_dir.is_dir() {
        return Err(anyhow::anyhow!("No scripts/ directory found in {}", path));
    }

    let runtime_target = resolve_cloud_runtime_target(compute_backend, runtime_kind)?;
    ensure_runtime_entrypoint(&scripts_dir, runtime_target.runtime_kind)?;

    // Derive skill slug from directory name
    let skill_slug = skill_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_lowercase()
        .replace(' ', "-");

    let deploy_name = name.unwrap_or(&skill_slug);

    // Bundle scripts/ as tar.gz
    let code_bundle = bundle_directory(&scripts_dir)?;
    if code_bundle.len() > MAX_CLOUD_CODE_BUNDLE_BYTES {
        return Err(anyhow::anyhow!(
            "Skill bundle is {} bytes, exceeds current cloud limit of {} bytes.",
            code_bundle.len(),
            MAX_CLOUD_CODE_BUNDLE_BYTES
        ));
    }
    let code_bundle_base64 = base64::engine::general_purpose::STANDARD.encode(&code_bundle);

    // Read optional files
    let requirements_txt = {
        let root_req_path = skill_dir.join("requirements.txt");
        let scripts_req_path = scripts_dir.join("requirements.txt");
        if root_req_path.exists() {
            Some(std::fs::read_to_string(&root_req_path)?)
        } else if scripts_req_path.exists() {
            Some(std::fs::read_to_string(&scripts_req_path)?)
        } else {
            None
        }
    };

    let config: Option<serde_json::Value> = if let Some(p) = config_path {
        let content = std::fs::read_to_string(p)?;
        Some(serde_json::from_str(&content)?)
    } else {
        let default_config = skill_dir.join("config.json");
        if default_config.exists() {
            let content = std::fs::read_to_string(&default_config)?;
            Some(serde_json::from_str(&content)?)
        } else {
            None
        }
    };

    let secrets: Option<serde_json::Value> = if let Some(p) = env_path {
        Some(parse_env_file(p)?)
    } else {
        let default_env = skill_dir.join(".env");
        if default_env.exists() {
            Some(parse_env_file(default_env.to_str().unwrap())?)
        } else {
            None
        }
    };

    let api_mode = match mode {
        "always-on" | "always_on" => "always_on",
        "cron" => "cron",
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid mode '{}'. Use 'always-on' or 'cron'.",
                mode
            ));
        }
    };

    if runtime_target.compute_backend == "daytona" && api_mode != "cron" {
        return Err(anyhow::anyhow!(
            "compute_backend 'daytona' currently requires mode 'cron'."
        ));
    }

    let mut body = serde_json::json!({
        "name": deploy_name,
        "skill_slug": skill_slug,
        "mode": api_mode,
        "code_bundle_base64": code_bundle_base64,
    });

    if runtime_target.include_request_fields {
        body["compute_backend"] = serde_json::json!(runtime_target.compute_backend);
        body["runtime_kind"] = serde_json::json!(runtime_target.runtime_kind);
    }

    if let Some(schedule) = cron_schedule {
        body["cron_schedule"] = serde_json::json!(schedule);
    }
    if let Some(req) = requirements_txt {
        body["requirements_txt"] = serde_json::json!(req);
    }
    if let Some(cfg) = config {
        body["config"] = cfg;
    }
    if let Some(sec) = secrets {
        body["secrets"] = sec;
    }

    let client = ctx.http_client().await?;
    let url = format!("{}/publishers/{}/deploy", ctx.api_base(), deploy_publisher);

    println!(
        "{} Deploying {} via {} ({} mode, backend={}, runtime={})...",
        "→".blue(),
        skill_slug.bold(),
        deploy_publisher,
        mode,
        runtime_target.compute_backend,
        runtime_target.runtime_kind
    );

    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    let status = response.status();
    if !status.is_success() && status.as_u16() != 202 {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Deploy failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    if let Some(data) = result.get("data") {
        let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let deploy_status = data.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        println!(
            "{} Deployment created: {} (status: {})",
            "✓".green(),
            id.bold(),
            deploy_status
        );
    } else {
        output::print_json(&result)?;
    }

    Ok(())
}

/// List cloud agent deployments.
pub async fn cloud_list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!("{}/publishers/{}/agents", ctx.api_base(), SEREN_CLOUD_SLUG);

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
        if data.is_empty() {
            println!("No cloud deployments found.");
            return Ok(());
        }
        println!(
            "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10}",
            "ID", "SKILL", "BACKEND", "RUNTIME", "MODE", "STATUS"
        );
        for d in data {
            println!(
                "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10}",
                d.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                d.get("skill_slug").and_then(|v| v.as_str()).unwrap_or("-"),
                d.get("compute_backend")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                d.get("runtime_kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                d.get("mode").and_then(|v| v.as_str()).unwrap_or("-"),
                d.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
            );
        }
    } else {
        output::print_json(&result)?;
    }

    Ok(())
}

/// Get status of a cloud agent deployment.
pub async fn cloud_status(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// Start a stopped always-on cloud agent.
pub async fn cloud_start(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    cloud_action(deployment_id, "start", ctx).await
}

/// Stop a running always-on cloud agent.
pub async fn cloud_stop(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    cloud_action(deployment_id, "stop", ctx).await
}

/// Trigger a one-shot run of a cloud agent.
pub async fn cloud_run(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    cloud_action(deployment_id, "runs", ctx).await
}

/// Destroy a cloud agent deployment.
pub async fn cloud_destroy(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id
    );

    let response = client.delete(&url).send().await?;
    let status = response.status();
    if status.as_u16() == 204 {
        println!("{} Deployment {} destroyed.", "✓".green(), deployment_id);
    } else if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }
    Ok(())
}

/// Get logs from a running cloud agent.
pub async fn cloud_logs(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}/logs",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let logs = response.text().await?;
    println!("{}", logs);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct CloudRunQueryOptions<'a> {
    pub statuses: &'a [String],
    pub compute_backend: Option<&'a str>,
    pub source: Option<&'a str>,
    pub has_artifacts: Option<bool>,
    pub started_after: Option<&'a str>,
    pub started_before: Option<&'a str>,
    pub q: Option<&'a str>,
}

/// Build query parameters for cloud run listing endpoints.
#[allow(clippy::too_many_arguments)]
fn build_cloud_runs_query(
    limit: i64,
    offset: i64,
    statuses: &[String],
    compute_backend: Option<&str>,
    source: Option<&str>,
    has_artifacts: Option<bool>,
    started_after: Option<&str>,
    started_before: Option<&str>,
    q: Option<&str>,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("limit", &limit.to_string());
    serializer.append_pair("offset", &offset.to_string());

    for status in statuses {
        let status = status.trim();
        if !status.is_empty() {
            serializer.append_pair("status", status);
        }
    }
    if let Some(compute_backend) = compute_backend.map(str::trim).filter(|v| !v.is_empty()) {
        serializer.append_pair("compute_backend", compute_backend);
    }
    if let Some(source) = source.map(str::trim).filter(|v| !v.is_empty()) {
        serializer.append_pair("source", source);
    }
    if let Some(has_artifacts) = has_artifacts {
        serializer.append_pair(
            "has_artifacts",
            if has_artifacts { "true" } else { "false" },
        );
    }
    if let Some(started_after) = started_after.map(str::trim).filter(|v| !v.is_empty()) {
        serializer.append_pair("started_after", started_after);
    }
    if let Some(started_before) = started_before.map(str::trim).filter(|v| !v.is_empty()) {
        serializer.append_pair("started_before", started_before);
    }
    if let Some(q) = q.map(str::trim).filter(|v| !v.is_empty()) {
        serializer.append_pair("q", q);
    }

    serializer.finish()
}

pub async fn cloud_runs(
    deployment_id: Uuid,
    limit: i64,
    offset: i64,
    options: CloudRunQueryOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.http_client().await?;
    let query = build_cloud_runs_query(
        limit,
        offset,
        options.statuses,
        options.compute_backend,
        options.source,
        options.has_artifacts,
        options.started_after,
        options.started_before,
        options.q,
    );
    let url = format!(
        "{}/publishers/{}/agents/{}/runs?{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id,
        query,
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
        if data.is_empty() {
            println!("No runs found for deployment {}.", deployment_id);
            return Ok(());
        }
        println!(
            "{:<38} {:<14} {:<10} {:<10} {:<24}",
            "RUN ID", "STATUS", "TIME(ms)", "COST", "STARTED"
        );
        for execution in data {
            println!(
                "{:<38} {:<14} {:<10} {:<10} {:<24}",
                execution.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                execution
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                execution
                    .get("execution_time_ms")
                    .and_then(|v| v.as_i64())
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                execution
                    .get("compute_cost_usd")
                    .and_then(|v| v.as_str())
                    .map(|v| format!("${v}"))
                    .unwrap_or_else(|| "-".to_string()),
                execution
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
            );
        }
    } else {
        output::print_json(&result)?;
    }

    Ok(())
}

/// Get details of a specific run event.
pub async fn cloud_run_get(deployment_id: Uuid, run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}/runs/{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id,
        run_id
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// List all runs across all cloud agent deployments.
pub async fn cloud_all_runs(
    limit: i64,
    offset: i64,
    options: CloudRunQueryOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.http_client().await?;
    let query = build_cloud_runs_query(
        limit,
        offset,
        options.statuses,
        options.compute_backend,
        options.source,
        options.has_artifacts,
        options.started_after,
        options.started_before,
        options.q,
    );
    let url = format!(
        "{}/publishers/{}/runs?{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        query
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
        if data.is_empty() {
            println!("No runs found.");
            return Ok(());
        }
        println!(
            "{:<38} {:<38} {:<14} {:<10} {:<10} {:<24}",
            "RUN ID", "DEPLOYMENT ID", "STATUS", "TIME(ms)", "COST", "STARTED"
        );
        for execution in data {
            println!(
                "{:<38} {:<38} {:<14} {:<10} {:<10} {:<24}",
                execution.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                execution
                    .get("deployment_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                execution
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                execution
                    .get("execution_time_ms")
                    .and_then(|v| v.as_i64())
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                execution
                    .get("compute_cost_usd")
                    .and_then(|v| v.as_str())
                    .map(|v| format!("${v}"))
                    .unwrap_or_else(|| "-".to_string()),
                execution
                    .get("started_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
            );
        }
    } else {
        output::print_json(&result)?;
    }

    Ok(())
}

/// Cancel a queued/running run event.
pub async fn cloud_run_cancel(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}/runs/{}/cancel",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id,
        run_id
    );

    let response = client.post(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

/// Update config and/or secrets for a cloud agent without redeploying.
pub async fn cloud_update_config(
    deployment_id: Uuid,
    config_path: Option<&str>,
    env_path: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    if config_path.is_none() && env_path.is_none() {
        return Err(anyhow::anyhow!(
            "At least one of --config or --env must be provided."
        ));
    }

    let config: Option<serde_json::Value> = if let Some(p) = config_path {
        let content = std::fs::read_to_string(p)
            .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", p, e))?;
        Some(serde_json::from_str(&content)?)
    } else {
        None
    };

    let secrets: Option<serde_json::Value> = if let Some(p) = env_path {
        Some(parse_env_file(p)?)
    } else {
        None
    };

    let mut body = serde_json::Map::new();
    if let Some(cfg) = config {
        body.insert("config".to_string(), cfg);
    }
    if let Some(sec) = secrets {
        body.insert("secrets".to_string(), sec);
    }

    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id
    );

    let response = client
        .patch(&url)
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    println!(
        "{} Config updated for deployment {}.",
        "✓".green(),
        deployment_id
    );
    output::print_json(&result)?;
    Ok(())
}

async fn cloud_action(deployment_id: Uuid, action: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/{}/agents/{}/{}",
        ctx.api_base(),
        SEREN_CLOUD_SLUG,
        deployment_id,
        action
    );

    let response = client.post(&url).send().await?;
    let status = response.status();
    if !status.is_success() && status.as_u16() != 202 {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Failed: {} - {}", status, body));
    }

    let result: serde_json::Value = response.json().await?;
    output::print_json(&result)?;
    Ok(())
}

struct CloudRuntimeTarget {
    compute_backend: &'static str,
    runtime_kind: &'static str,
    include_request_fields: bool,
}

fn resolve_cloud_runtime_target(
    compute_backend: Option<&str>,
    runtime_kind: Option<&str>,
) -> Result<CloudRuntimeTarget> {
    let normalize_backend = |value: &str| -> Result<&'static str> {
        match value {
            "aws_container" => Ok("aws_container"),
            "cloudflare_worker" => Ok("cloudflare_worker"),
            "daytona" => Ok("daytona"),
            other => Err(anyhow::anyhow!(
                "Invalid compute_backend '{}'. Use 'aws_container', 'cloudflare_worker', or 'daytona'.",
                other
            )),
        }
    };

    let normalize_runtime = |value: &str| -> Result<&'static str> {
        match value {
            "python" => Ok("python"),
            "javascript" => Ok("javascript"),
            "typescript" => Ok("typescript"),
            "rust" => Ok("rust"),
            "rust_wasm_adk" => Ok("rust_wasm_adk"),
            other => Err(anyhow::anyhow!(
                "Invalid runtime_kind '{}'. Use 'python', 'javascript', 'typescript', 'rust', or 'rust_wasm_adk'.",
                other
            )),
        }
    };

    let backend = compute_backend.map(normalize_backend).transpose()?;
    let runtime = runtime_kind.map(normalize_runtime).transpose()?;
    let include_request_fields = backend.is_some() || runtime.is_some();

    let (compute_backend, runtime_kind) = match (backend, runtime) {
        (None, None) => ("aws_container", "python"),
        (Some(cb), Some(rk)) => (cb, rk),
        (Some("aws_container"), None) => ("aws_container", "python"),
        (Some("cloudflare_worker"), None) => ("cloudflare_worker", "javascript"),
        (Some("daytona"), None) => ("daytona", "python"),
        (None, Some("python")) => ("aws_container", "python"),
        (None, Some("javascript")) => ("aws_container", "javascript"),
        (None, Some("typescript")) => ("aws_container", "typescript"),
        (None, Some("rust")) => ("cloudflare_worker", "rust"),
        (None, Some("rust_wasm_adk")) => ("cloudflare_worker", "rust_wasm_adk"),
        _ => unreachable!(),
    };

    validate_runtime_target(compute_backend, runtime_kind)?;

    Ok(CloudRuntimeTarget {
        compute_backend,
        runtime_kind,
        include_request_fields,
    })
}

fn validate_runtime_target(compute_backend: &str, runtime_kind: &str) -> Result<()> {
    match (compute_backend, runtime_kind) {
        ("aws_container", "python") => Ok(()),
        ("aws_container", "javascript") => Ok(()),
        ("aws_container", "typescript") => Ok(()),
        ("cloudflare_worker", "python") => Ok(()),
        ("cloudflare_worker", "javascript") => Ok(()),
        ("cloudflare_worker", "typescript") => Ok(()),
        ("cloudflare_worker", "rust") => Ok(()),
        ("cloudflare_worker", "rust_wasm_adk") => Ok(()),
        ("daytona", "python") => Ok(()),
        ("daytona", "javascript") => Ok(()),
        ("daytona", "typescript") => Ok(()),
        _ => Err(anyhow::anyhow!(
            "Invalid backend/runtime combination: {}/{}. Valid pairs are aws_container+(python|javascript|typescript), cloudflare_worker+(python|javascript|typescript|rust|rust_wasm_adk), daytona+(python|javascript|typescript).",
            compute_backend,
            runtime_kind
        )),
    }
}

fn ensure_runtime_entrypoint(scripts_dir: &Path, runtime_kind: &str) -> Result<()> {
    if runtime_kind == "rust" {
        let has_js_entrypoint = find_runtime_entrypoint(scripts_dir, runtime_kind).is_some();
        let has_wasm_artifact = contains_file_with_extension(scripts_dir, "wasm");
        if has_js_entrypoint && has_wasm_artifact {
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "No Rust Worker artifact set found in '{}'. runtime_kind=rust expects JS glue entrypoint (worker.js/index.js) plus at least one .wasm file (workers-rs build output).",
            scripts_dir.display()
        ));
    }

    if find_runtime_entrypoint(scripts_dir, runtime_kind).is_some() {
        return Ok(());
    }

    let expected = match runtime_kind {
        "python" => "agent.py/main.py/index.py (or any .py file)",
        "javascript" => "agent.js/main.js/index.js/worker.js (or any .js/.mjs/.cjs file)",
        "typescript" => "agent.ts/main.ts/index.ts/worker.ts (or any .ts file)",
        "rust" => "worker.js/index.js/dist/worker.js plus at least one .wasm file",
        "rust_wasm_adk" => "worker.js/index.js/dist/worker.js (or any JS/TS source file)",
        other => return Err(anyhow::anyhow!("Unsupported runtime_kind '{}'.", other)),
    };

    Err(anyhow::anyhow!(
        "No entrypoint found in '{}'. Expected one of: {}.",
        scripts_dir.display(),
        expected
    ))
}

fn find_runtime_entrypoint(scripts_dir: &Path, runtime_kind: &str) -> Option<String> {
    let candidates: &[&str] = match runtime_kind {
        "python" => &["agent.py", "main.py", "index.py", "run.py"],
        "javascript" => &[
            "agent.js",
            "main.js",
            "index.js",
            "worker.ts",
            "worker.js",
            "index.ts",
            "index.js",
            "main.ts",
            "main.js",
        ],
        "typescript" => &["agent.ts", "main.ts", "index.ts", "worker.ts"],
        "rust" => &[
            "worker.js",
            "index.js",
            "dist/worker.js",
            "dist/index.js",
            "worker.mjs",
            "index.mjs",
            "dist/worker.mjs",
            "dist/index.mjs",
        ],
        "rust_wasm_adk" => &[
            "worker.js",
            "index.js",
            "dist/worker.js",
            "dist/index.js",
            "worker.ts",
        ],
        _ => &[],
    };

    for candidate in candidates {
        if scripts_dir.join(candidate).is_file() {
            return Some((*candidate).to_string());
        }
    }

    let fallback_exts: &[&str] = match runtime_kind {
        "python" => &["py"],
        "javascript" => &["js", "mjs", "cjs"],
        "typescript" => &["ts"],
        "rust" => &["js", "mjs", "cjs"],
        "rust_wasm_adk" => &["js", "ts", "mjs", "cjs"],
        _ => return None,
    };
    find_file_with_extensions(scripts_dir, fallback_exts)
}

fn find_file_with_extensions(dir: &Path, extensions: &[&str]) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str())
                && extensions
                    .iter()
                    .any(|expected| ext.eq_ignore_ascii_case(expected))
            {
                return path
                    .strip_prefix(dir)
                    .ok()
                    .and_then(|p| p.to_str())
                    .map(|p| p.to_string());
            }
        } else if path.is_dir()
            && let Some(found) = find_file_with_extensions(&path, extensions)
        {
            let dir_name = path.file_name()?.to_str()?;
            return Some(format!("{}/{}", dir_name, found));
        }
    }

    None
}

fn contains_file_with_extension(dir: &Path, extension: &str) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str())
                && ext.eq_ignore_ascii_case(extension)
            {
                return true;
            }
        } else if path.is_dir() && contains_file_with_extension(&path, extension) {
            return true;
        }
    }

    false
}

/// Bundle a directory into a tar.gz archive in memory.
fn bundle_directory(dir: &Path) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::default());
    let mut tar = Builder::new(enc);

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if path.is_file() {
            tar.append_path_with_name(&path, name)?;
        } else if path.is_dir() {
            tar.append_dir_all(name, &path)?;
        }
    }

    let enc = tar.into_inner()?;
    Ok(enc.finish()?)
}

/// Parse a .env file into a JSON object of key-value pairs.
fn parse_env_file(path: &str) -> Result<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    let mut map = serde_json::Map::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"').trim_matches('\'');
            map.insert(
                key.trim().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }
    Ok(serde_json::Value::Object(map))
}
