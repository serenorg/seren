use std::{fs, path::Path};

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
        a2a_endpoint_url: None,
        reserve_max_charge: None,
        unresolved_fallback_charge: None,
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
        .get_transactions(None, None, limit, offset, None)
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

    let body: seren::CreateTemplateRequest = serde_json::from_value(serde_json::json!({
        "name": name,
        "slug": slug,
        "code": code_content,
        "language": language,
        "price": price,
        "description": description,
        "dependencies": deps,
        "computeBackend": compute_backend,
        "settingsSchema": serde_json::Value::Null,
        "llmConfig": serde_json::Value::Null,
    }))
    .map_err(|e| anyhow::anyhow!("Failed to build template request: {}", e))?;

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
    let client = ctx.client().await?;

    // Try to parse message as JSON, fall back to text wrapper
    let message_value: serde_json::Value =
        serde_json::from_str(message).unwrap_or_else(|_| serde_json::json!({"text": message}));

    let body: seren::PublisherRootRequest = message_value.into();
    let response = client
        .publisher_root_handler(publisher, &body)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run agent: {}", e))?
        .into_inner();

    output::print_json(&response)?;
    Ok(())
}

/// List agent tasks for an organization.
pub async fn list_agent_tasks(
    org_id: &str,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let org_uuid: Uuid = org_id
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid organization ID: {}", org_id))?;
    let client = ctx.client().await?;
    let response = client
        .list_tasks(&org_uuid, Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list tasks: {}", e))?
        .into_inner();

    output::print_json(&response)?;
    Ok(())
}

/// Get details of a specific agent task. With --follow, streams SSE events.
pub async fn get_agent_task(
    org_id: &str,
    task_id: &str,
    follow: bool,
    ctx: &CommandContext,
) -> Result<()> {
    if follow {
        // SSE streaming requires raw reqwest client
        let client = ctx.http_client().await?;
        return follow_agent_task(&client, ctx.api_base(), org_id, task_id).await;
    }

    let org_uuid: Uuid = org_id
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid organization ID: {}", org_id))?;
    let task_uuid: Uuid = task_id
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid task ID: {}", task_id))?;
    let client = ctx.client().await?;
    let response = client
        .get_task(&org_uuid, &task_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get task: {}", e))?
        .into_inner();

    output::print_json(&response)?;
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
    let org_uuid: Uuid = org_id
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid organization ID: {}", org_id))?;
    let task_uuid: Uuid = task_id
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid task ID: {}", task_id))?;
    let client = ctx.client().await?;
    let response = client
        .cancel_task(&org_uuid, &task_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to cancel task: {}", e))?
        .into_inner();

    output::print_json(&response)?;
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
    pub environment_id: Option<Uuid>,
    pub mode: &'a str,
    pub cron_schedule: Option<&'a str>,
    pub compute_backend: Option<&'a str>,
    pub runtime_kind: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub orchestration_config_path: Option<&'a str>,
}

pub struct CloudDeployPromptOptions<'a> {
    pub name: &'a str,
    pub agent_slug: Option<&'a str>,
    pub mode: &'a str,
    pub cron_schedule: Option<&'a str>,
    pub compute_backend: Option<&'a str>,
    pub template: Option<&'a str>,
    pub tool_presets: &'a [String],
    pub approval_policy: Option<&'a str>,
    pub model_policy: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub agent_config_path: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub visibility: Option<&'a str>,
}

pub struct ManagedAgentUpdateOptions<'a> {
    pub name: Option<&'a str>,
    pub agent_slug: Option<&'a str>,
    pub cron_schedule: Option<&'a str>,
    pub template: Option<&'a str>,
    pub tool_presets: &'a [String],
    pub approval_policy: Option<&'a str>,
    pub model_policy: Option<&'a str>,
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub agent_config_path: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub visibility: Option<&'a str>,
}

const MAX_CLOUD_CODE_BUNDLE_BYTES: usize = 1_000_000;
const ORCHESTRATION_CONFIG_FIELDS: &[&str] = &[
    "context_budget_tokens",
    "dashboard_config",
    "fallback_models",
    "max_iterations",
    "max_timeout_seconds",
    "max_tool_output_chars",
    "model_config",
    "model_id",
    "orchestration_mode",
    "requirements",
    "system_prompt",
    "tool_definitions",
    "visibility",
];
const MANAGED_AGENT_CONFIG_FIELDS: &[&str] = &[
    "context_budget_tokens",
    "dashboard_config",
    "fallback_models",
    "max_iterations",
    "max_timeout_seconds",
    "max_tool_output_chars",
    "model_config",
    "model_id",
    "prompt",
    "template",
    "tool_presets",
    "approval_policy",
    "model_policy",
    "requirements",
    "visibility",
];

fn normalize_deploy_publisher_slug(publisher_slug: Option<&str>) -> Result<&'static str> {
    match publisher_slug.unwrap_or(SEREN_CLOUD_SLUG) {
        SEREN_CLOUD_SLUG => Ok(SEREN_CLOUD_SLUG),
        other => Err(anyhow::anyhow!(
            "Bundle deployments only support publisher 'seren-cloud'. Managed prompt agents use 'seren-agent', not '{}'.",
            other
        )),
    }
}

fn resolve_skill_dir(path: &str) -> Result<std::path::PathBuf> {
    let resolved = Path::new(path);
    if resolved.is_dir() {
        return Ok(resolved.to_path_buf());
    }

    if resolved.is_file()
        && resolved
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
    {
        return resolved
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow::anyhow!("Could not resolve parent directory for '{}'.", path));
    }

    Err(anyhow::anyhow!(
        "'{}' must be a skill directory or a SKILL.md file",
        path
    ))
}

fn normalize_cloud_skill_slug(value: &str) -> String {
    let mut slug = String::with_capacity(value.len());
    let mut last_was_dash = false;
    for ch in value.trim().chars().flat_map(char::to_lowercase) {
        let next = if ch.is_ascii_alphanumeric() { ch } else { '-' };
        if next == '-' {
            if last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        slug.push(next);
    }

    slug.trim_matches('-').to_string()
}

fn load_orchestration_config(
    skill_dir: Option<&Path>,
    orchestration_config_path: Option<&str>,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let config_path = orchestration_config_path
        .map(|p| Path::new(p).to_path_buf())
        .or_else(|| {
            skill_dir.and_then(|skill_dir| {
                let default_path = skill_dir.join("orchestration.json");
                default_path.exists().then_some(default_path)
            })
        });

    let Some(config_path) = config_path else {
        return Ok(None);
    };

    let contents = fs::read_to_string(&config_path)?;
    let value: serde_json::Value = serde_json::from_str(&contents).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse orchestration config {}: {}",
            config_path.display(),
            e
        )
    })?;

    let serde_json::Value::Object(map) = value else {
        return Err(anyhow::anyhow!(
            "Orchestration config {} must contain a JSON object.",
            config_path.display()
        ));
    };

    Ok(Some(map))
}

fn merge_orchestration_config(
    body: &mut serde_json::Map<String, serde_json::Value>,
    orchestration_config: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let mut unsupported = Vec::new();

    for (key, value) in orchestration_config {
        if ORCHESTRATION_CONFIG_FIELDS.contains(&key.as_str()) {
            body.insert(key, value);
        } else {
            unsupported.push(key);
        }
    }

    if unsupported.is_empty() {
        return Ok(());
    }

    unsupported.sort();
    Err(anyhow::anyhow!(
        "Unsupported orchestration config keys: {}",
        unsupported.join(", ")
    ))
}

fn merge_managed_agent_config(
    body: &mut serde_json::Map<String, serde_json::Value>,
    agent_config: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let mut unsupported = Vec::new();

    for (key, value) in agent_config {
        if MANAGED_AGENT_CONFIG_FIELDS.contains(&key.as_str()) {
            body.insert(key, value);
        } else {
            unsupported.push(key);
        }
    }

    if unsupported.is_empty() {
        return Ok(());
    }

    unsupported.sort();
    Err(anyhow::anyhow!(
        "Unsupported managed agent config keys: {}",
        unsupported.join(", ")
    ))
}

async fn submit_cloud_deploy_request(
    deploy_publisher: &str,
    body: serde_json::Map<String, serde_json::Value>,
    ctx: &CommandContext,
) -> Result<()> {
    let http_client = ctx.http_client().await?;
    let url = format!("{}/publishers/{deploy_publisher}/deploy", ctx.api_base());
    let response = http_client
        .post(&url)
        .json(&serde_json::Value::Object(body))
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
        if let Some(compute_backend) = data.get("compute_backend").and_then(|v| v.as_str()) {
            println!("  Backend: {}", compute_backend);
        }
        if let Some(runtime_kind) = data.get("runtime_kind").and_then(|v| v.as_str()) {
            println!("  Runtime: {}", runtime_kind);
        }
        if let Some(managed_agent) = data.get("managed_agent") {
            if let Some(target_framework) = managed_agent
                .get("target_framework")
                .and_then(|v| v.as_str())
            {
                println!("  Managed Runtime: {}", target_framework);
            }
            if let Some(template) = managed_agent.get("template").and_then(|v| v.as_str()) {
                println!("  Template: {}", template);
            }
            if let Some(tool_presets) = managed_agent
                .get("tool_presets")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
            {
                println!("  Tool Presets: {}", tool_presets);
            }
            if let Some(approval_policy) = managed_agent
                .get("approval_policy")
                .and_then(|v| v.as_str())
            {
                println!("  Approval Policy: {}", approval_policy);
            }
            if let Some(allowed_operations) = managed_agent
                .get("allowed_publisher_operations")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
            {
                println!("  Publisher Ops: {}", allowed_operations);
            }
            if let Some(model_policy) = managed_agent.get("model_policy").and_then(|v| v.as_str()) {
                println!("  Model Policy: {}", model_policy);
            }
            if let Some(routing_reason) =
                managed_agent.get("routing_reason").and_then(|v| v.as_str())
            {
                println!("  Routing: {}", routing_reason);
            }
        }
    } else {
        output::print_json(&result)?;
    }

    Ok(())
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
        environment_id,
        mode,
        cron_schedule,
        compute_backend,
        runtime_kind,
        config_path,
        env_path,
        orchestration_config_path,
    } = options;
    let deploy_publisher = normalize_deploy_publisher_slug(publisher_slug)?;
    let runtime_target = resolve_cloud_runtime_target(compute_backend, runtime_kind)?;

    let skill_dir_buf = resolve_skill_dir(path)?;
    let skill_dir = skill_dir_buf.as_path();

    let scripts_dir = skill_dir.join("scripts");
    if !scripts_dir.is_dir() {
        return Err(anyhow::anyhow!("No scripts/ directory found in {}", path));
    }

    if let Some(runtime_kind) = runtime_target.runtime_kind {
        ensure_runtime_entrypoint(&scripts_dir, runtime_target.compute_backend, runtime_kind)?;
    }

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
    let orchestration_config =
        load_orchestration_config(Some(skill_dir), orchestration_config_path)?;

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

    if runtime_target.compute_backend == Some("daytona") && api_mode != "cron" {
        return Err(anyhow::anyhow!(
            "compute_backend 'daytona' currently requires mode 'cron'."
        ));
    }
    if environment_id.is_some()
        && runtime_target
            .compute_backend
            .is_some_and(|backend| backend != "aws_container")
    {
        return Err(anyhow::anyhow!(
            "--environment-id is only supported with compute_backend 'aws_container'."
        ));
    }

    println!(
        "{} Deploying {} via {} ({} mode, backend={}, runtime={})...",
        "→".blue(),
        skill_slug.bold(),
        deploy_publisher,
        mode,
        runtime_target.compute_backend.unwrap_or("auto"),
        runtime_target.runtime_kind.unwrap_or("auto")
    );

    let mut body = serde_json::Map::new();
    body.insert("name".to_string(), serde_json::json!(deploy_name));
    body.insert("skill_slug".to_string(), serde_json::json!(skill_slug));
    body.insert("mode".to_string(), serde_json::json!(api_mode));
    body.insert(
        "code_bundle_base64".to_string(),
        serde_json::json!(code_bundle_base64),
    );
    if let Some(compute_backend) = runtime_target.compute_backend {
        body.insert(
            "compute_backend".to_string(),
            serde_json::json!(compute_backend),
        );
    }
    if let Some(runtime_kind) = runtime_target.runtime_kind {
        body.insert("runtime_kind".to_string(), serde_json::json!(runtime_kind));
    }
    if let Some(schedule) = cron_schedule {
        body.insert("cron_schedule".to_string(), serde_json::json!(schedule));
    }
    if let Some(environment_id) = environment_id {
        body.insert(
            "environment_id".to_string(),
            serde_json::json!(environment_id),
        );
    }
    if let Some(req) = &requirements_txt {
        body.insert("requirements_txt".to_string(), serde_json::json!(req));
    }
    if let Some(cfg) = &config {
        body.insert("config".to_string(), cfg.clone());
    }
    if let Some(sec) = &secrets {
        body.insert("secrets".to_string(), sec.clone());
    }
    if let Some(orchestration_config) = orchestration_config {
        merge_orchestration_config(&mut body, orchestration_config)?;
    }

    submit_cloud_deploy_request(deploy_publisher, body, ctx).await
}

/// Deploy a managed prompt-based agent through seren-agent.
pub async fn cloud_deploy_prompt(
    options: CloudDeployPromptOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let CloudDeployPromptOptions {
        name,
        agent_slug,
        mode,
        cron_schedule,
        compute_backend,
        template,
        tool_presets,
        approval_policy,
        model_policy,
        config_path,
        env_path,
        agent_config_path,
        prompt,
        model_id,
        visibility,
    } = options;
    let deploy_publisher = SEREN_AGENT_SLUG;
    let runtime_target = resolve_cloud_runtime_target(compute_backend, None)?;
    let agent_config = load_orchestration_config(None, agent_config_path)?;

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

    if runtime_target.compute_backend == Some("daytona") && api_mode != "cron" {
        return Err(anyhow::anyhow!(
            "compute_backend 'daytona' currently requires mode 'cron'."
        ));
    }
    let config: Option<serde_json::Value> = if let Some(p) = config_path {
        let content = fs::read_to_string(p)?;
        Some(serde_json::from_str(&content)?)
    } else {
        None
    };

    let secrets: Option<serde_json::Value> = if let Some(p) = env_path {
        Some(parse_env_file(p)?)
    } else {
        None
    };

    let managed_agent_slug = agent_slug
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| normalize_cloud_skill_slug(name));
    if managed_agent_slug.is_empty() {
        return Err(anyhow::anyhow!(
            "Could not derive a valid agent slug from '{}'. Provide --agent-slug.",
            name
        ));
    }

    println!(
        "{} Deploying managed agent {} via {} ({} mode, backend={})...",
        "→".blue(),
        managed_agent_slug.bold(),
        deploy_publisher,
        mode,
        runtime_target.compute_backend.unwrap_or("auto"),
    );

    let mut body = serde_json::Map::new();
    body.insert("name".to_string(), serde_json::json!(name.trim()));
    body.insert(
        "agent_slug".to_string(),
        serde_json::json!(managed_agent_slug),
    );
    body.insert("mode".to_string(), serde_json::json!(api_mode));

    if let Some(compute_backend) = runtime_target.compute_backend {
        body.insert(
            "compute_backend".to_string(),
            serde_json::json!(compute_backend),
        );
    }
    if let Some(template) = template.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("template".to_string(), serde_json::json!(template));
    }
    if !tool_presets.is_empty() {
        body.insert("tool_presets".to_string(), serde_json::json!(tool_presets));
    }
    if let Some(approval_policy) = approval_policy
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert(
            "approval_policy".to_string(),
            serde_json::json!(approval_policy),
        );
    }
    if let Some(model_policy) = model_policy
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert("model_policy".to_string(), serde_json::json!(model_policy));
    }
    if let Some(schedule) = cron_schedule {
        body.insert("cron_schedule".to_string(), serde_json::json!(schedule));
    }
    if let Some(cfg) = &config {
        body.insert("config".to_string(), cfg.clone());
    }
    if let Some(sec) = &secrets {
        body.insert("secrets".to_string(), sec.clone());
    }
    if let Some(agent_config) = agent_config {
        merge_managed_agent_config(&mut body, agent_config)?;
    }
    if let Some(prompt) = prompt.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("prompt".to_string(), serde_json::json!(prompt));
    }
    if let Some(model_id) = model_id.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("model_id".to_string(), serde_json::json!(model_id));
    }
    if let Some(visibility) = visibility.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("visibility".to_string(), serde_json::json!(visibility));
    }

    if !body.contains_key("prompt") {
        return Err(anyhow::anyhow!(
            "Managed agent deployments require --prompt or an agent config containing prompt."
        ));
    }
    if !body.contains_key("model_id") {
        return Err(anyhow::anyhow!(
            "Managed agent deployments require --model-id or an agent config containing model_id."
        ));
    }

    submit_cloud_deploy_request(deploy_publisher, body, ctx).await
}

/// Get the resolved managed seren-agent deployment detail.
pub async fn managed_agent_get(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let http_client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/seren-agent/deployments/{}/managed",
        ctx.api_base(),
        deployment_id
    );
    let response = http_client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to get managed agent detail: {} - {}",
            status,
            response_text
        ));
    }
    let response_body = serde_json::from_str::<serde_json::Value>(&response_text)
        .map_err(|e| anyhow::anyhow!("Failed to parse response JSON: {}", e))?;
    output::print_json(&response_body)?;
    Ok(())
}

/// Update an existing managed seren-agent deployment.
pub async fn managed_agent_update(
    deployment_id: Uuid,
    options: ManagedAgentUpdateOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let ManagedAgentUpdateOptions {
        name,
        agent_slug,
        cron_schedule,
        template,
        tool_presets,
        approval_policy,
        model_policy,
        config_path,
        env_path,
        agent_config_path,
        prompt,
        model_id,
        visibility,
    } = options;

    let agent_config = load_orchestration_config(None, agent_config_path)?;
    let config: Option<serde_json::Value> = if let Some(p) = config_path {
        let content = fs::read_to_string(p)?;
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
    if let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("name".to_string(), serde_json::json!(name));
    }
    if let Some(agent_slug) = agent_slug.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("agent_slug".to_string(), serde_json::json!(agent_slug));
    }
    if let Some(cron_schedule) = cron_schedule
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert(
            "cron_schedule".to_string(),
            serde_json::json!(cron_schedule),
        );
    }
    if let Some(template) = template.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("template".to_string(), serde_json::json!(template));
    }
    if !tool_presets.is_empty() {
        body.insert("tool_presets".to_string(), serde_json::json!(tool_presets));
    }
    if let Some(approval_policy) = approval_policy
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert(
            "approval_policy".to_string(),
            serde_json::json!(approval_policy),
        );
    }
    if let Some(model_policy) = model_policy
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert("model_policy".to_string(), serde_json::json!(model_policy));
    }
    if let Some(cfg) = &config {
        body.insert("config".to_string(), cfg.clone());
    }
    if let Some(sec) = &secrets {
        body.insert("secrets".to_string(), sec.clone());
    }
    if let Some(agent_config) = agent_config {
        merge_managed_agent_config(&mut body, agent_config)?;
    }
    if let Some(prompt) = prompt.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("prompt".to_string(), serde_json::json!(prompt));
    }
    if let Some(model_id) = model_id.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("model_id".to_string(), serde_json::json!(model_id));
    }
    if let Some(visibility) = visibility.map(str::trim).filter(|value| !value.is_empty()) {
        body.insert("visibility".to_string(), serde_json::json!(visibility));
    }

    if body.is_empty() {
        return Err(anyhow::anyhow!(
            "No managed deployment updates specified. Provide at least one field or --agent-config."
        ));
    }

    let http_client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/seren-agent/deployments/{}/managed",
        ctx.api_base(),
        deployment_id
    );
    let response = http_client
        .patch(&url)
        .json(&serde_json::Value::Object(body))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?;
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to update managed agent deployment: {} - {}",
            status,
            response_text
        ));
    }
    let response_body = serde_json::from_str::<serde_json::Value>(&response_text)
        .map_err(|e| anyhow::anyhow!("Failed to parse response JSON: {}", e))?;
    output::print_json(&response_body)?;
    Ok(())
}

/// List reusable cloud deployment environments.
pub async fn cloud_environment_list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_list_environments()
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    let environments = &response.data;
    if environments.is_empty() {
        println!("No cloud environments found.");
        return Ok(());
    }
    println!(
        "{:<38} {:<24} {:<8} {:<48}",
        "ID", "NAME", "DEFAULT", "IMAGE"
    );
    for env in environments {
        let env_json = serde_json::to_value(env)?;
        println!(
            "{:<38} {:<24} {:<8} {:<48}",
            env_json.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
            env_json.get("name").and_then(|v| v.as_str()).unwrap_or("-"),
            env_json
                .get("is_default")
                .and_then(|v| v.as_bool())
                .map(|v| if v { "yes" } else { "no" })
                .unwrap_or("-"),
            env_json
                .get("docker_image")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
    }

    Ok(())
}

/// Get a single reusable cloud deployment environment.
pub async fn cloud_environment_get(environment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_environment(&environment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

pub struct CloudEnvironmentCreateOptions<'a> {
    pub description: Option<&'a str>,
    pub setup_commands: &'a [String],
    pub is_default: bool,
}

/// Create a reusable cloud deployment environment.
pub async fn cloud_environment_create(
    name: &str,
    docker_image: &str,
    options: CloudEnvironmentCreateOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let setup_commands: Vec<String> = options
        .setup_commands
        .iter()
        .map(|command| command.trim())
        .filter(|command| !command.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let client = ctx.client().await?;
    let request = seren::CreateCloudDeploymentEnvironmentRequest {
        name: name.trim().to_string(),
        docker_image: docker_image.trim().to_string(),
        description: options
            .description
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string),
        setup_commands: if setup_commands.is_empty() {
            None
        } else {
            Some(setup_commands)
        },
        is_default: Some(options.is_default),
    };
    let response = client
        .seren_cloud_create_environment(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Update a reusable cloud deployment environment.
#[allow(clippy::too_many_arguments)]
pub async fn cloud_environment_update(
    environment_id: Uuid,
    name: Option<&str>,
    description: Option<&str>,
    docker_image: Option<&str>,
    setup_commands: &[String],
    clear_setup_commands: bool,
    is_default: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let setup_cmds = if clear_setup_commands {
        Some(vec![])
    } else if !setup_commands.is_empty() {
        Some(
            setup_commands
                .iter()
                .map(|command| command.trim())
                .filter(|command| !command.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        )
    } else {
        None
    };

    let request = seren::UpdateCloudDeploymentEnvironmentRequest {
        name: name.map(|v| v.trim().to_string()),
        description: description.map(|v| v.trim().to_string()),
        docker_image: docker_image.map(|v| v.trim().to_string()),
        setup_commands: setup_cmds,
        is_default,
    };

    if request.name.is_none()
        && request.description.is_none()
        && request.docker_image.is_none()
        && request.setup_commands.is_none()
        && request.is_default.is_none()
    {
        return Err(anyhow::anyhow!(
            "No updates specified. Provide at least one field to update."
        ));
    }

    let client = ctx.client().await?;
    let response = client
        .seren_cloud_update_environment(&environment_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Delete a reusable cloud deployment environment.
pub async fn cloud_environment_delete(environment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    client
        .seren_cloud_delete_environment(&environment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    println!("{} Environment {} deleted.", "✓".green(), environment_id);
    Ok(())
}

/// List cloud agent deployments.
pub async fn cloud_list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_list_deployments()
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    let deployments = &response.data;
    if deployments.is_empty() {
        println!("No cloud deployments found.");
        return Ok(());
    }
    println!(
        "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10}",
        "ID", "SKILL", "BACKEND", "RUNTIME", "MODE", "STATUS"
    );
    for d in deployments {
        let d_json = serde_json::to_value(d)?;
        println!(
            "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10}",
            d_json.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
            d_json
                .get("skill_slug")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            d_json
                .get("compute_backend")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            d_json
                .get("runtime_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
            d_json.get("mode").and_then(|v| v.as_str()).unwrap_or("-"),
            d_json.get("status").and_then(|v| v.as_str()).unwrap_or("-"),
        );
    }

    Ok(())
}

/// Get status of a cloud agent deployment.
pub async fn cloud_status(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_deployment(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Start a stopped always-on cloud agent.
pub async fn cloud_start(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    client
        .seren_cloud_start(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    println!("{} Deployment {} started.", "✓".green(), deployment_id);
    Ok(())
}

/// Stop a running always-on cloud agent.
pub async fn cloud_stop(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    client
        .seren_cloud_stop(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    println!("{} Deployment {} stopped.", "✓".green(), deployment_id);
    Ok(())
}

fn build_cloud_run_payload(
    message: Option<&str>,
    json_body: Option<&str>,
    json_file: Option<&str>,
    run_id: Option<&str>,
    async_run: bool,
) -> Result<Option<serde_json::Value>> {
    if json_body.is_some() && json_file.is_some() {
        return Err(anyhow::anyhow!(
            "Provide only one of --json or --json-file for cloud-run."
        ));
    }

    let mut payload = if let Some(raw_json) = json_body.map(str::trim).filter(|v| !v.is_empty()) {
        Some(
            serde_json::from_str::<serde_json::Value>(raw_json)
                .map_err(|e| anyhow::anyhow!("Invalid --json payload: {}", e))?,
        )
    } else if let Some(json_file) = json_file.map(str::trim).filter(|v| !v.is_empty()) {
        let raw_json = fs::read_to_string(json_file)
            .map_err(|e| anyhow::anyhow!("Failed to read --json-file '{}': {}", json_file, e))?;
        Some(
            serde_json::from_str::<serde_json::Value>(&raw_json).map_err(|e| {
                anyhow::anyhow!("Invalid JSON in --json-file '{}': {}", json_file, e)
            })?,
        )
    } else {
        None
    };

    if let Some(message) = message {
        let message = message.trim();
        if message.is_empty() {
            return Err(anyhow::anyhow!("--message cannot be empty."));
        }

        match payload.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("message".to_string(), serde_json::json!(message));
            }
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "When --message is provided, --json/--json-file must be a JSON object."
                ));
            }
            None => {
                payload = Some(serde_json::json!({ "message": message }));
            }
        }
    }

    if let Some(run_id) = run_id {
        let run_id = run_id.trim();
        if run_id.is_empty() {
            return Err(anyhow::anyhow!("--run-id cannot be empty."));
        }

        match payload.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("run_id".to_string(), serde_json::json!(run_id));
            }
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "When --run-id is provided, --json/--json-file must be a JSON object."
                ));
            }
            None => {
                payload = Some(serde_json::json!({ "run_id": run_id }));
            }
        }
    }

    if async_run {
        match payload.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("async".to_string(), serde_json::json!(true));
            }
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "When --async is provided, --json/--json-file must be a JSON object."
                ));
            }
            None => {
                payload = Some(serde_json::json!({ "async": true }));
            }
        }
    }

    Ok(payload)
}

fn extract_run_identifiers(response_body: &serde_json::Value) -> (Option<String>, Option<String>) {
    let data = response_body.get("data").unwrap_or(response_body);
    let run_id = data
        .get("run_id")
        .or_else(|| data.get("id"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let execution_id = data
        .get("execution_id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    (run_id, execution_id)
}

/// Trigger a one-shot run of a cloud agent.
pub async fn cloud_run(
    deployment_id: Uuid,
    message: Option<&str>,
    json_body: Option<&str>,
    json_file: Option<&str>,
    run_id: Option<&str>,
    async_run: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let payload = build_cloud_run_payload(message, json_body, json_file, run_id, async_run)?;
    let body = payload.unwrap_or(serde_json::json!({}));
    let http_client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/seren-cloud/deployments/{}/runs",
        ctx.api_base(),
        deployment_id
    );
    let response = http_client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    let status = response.status();
    let response_text = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read run response body: {}", e))?;
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to trigger run: {} - {}",
            status,
            response_text
        ));
    }
    let response_body = if response_text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str::<serde_json::Value>(&response_text)
            .unwrap_or_else(|_| serde_json::json!({ "data": response_text }))
    };
    let (run_id, execution_id) = extract_run_identifiers(&response_body);

    match (run_id, execution_id) {
        (Some(run_id), Some(execution_id)) => {
            println!(
                "{} Run accepted for deployment {}.",
                "✓".green(),
                deployment_id
            );
            println!("  Run ID: {}", run_id.bold());
            println!("  Execution ID: {}", execution_id.bold());
            println!(
                "  Check status: seren agent cloud-run-get {} {}",
                deployment_id, run_id
            );
        }
        (Some(run_id), None) => {
            println!(
                "{} Run triggered for deployment {} (run_id: {}).",
                "✓".green(),
                deployment_id,
                run_id.bold()
            );
        }
        _ => {
            println!(
                "{} Run triggered for deployment {}.",
                "✓".green(),
                deployment_id
            );
            if !response_body.is_null() {
                output::print_json(&response_body)?;
            }
        }
    }
    Ok(())
}

/// Get details of a specific run event by run ID (global path).
pub async fn cloud_run_by_id(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_detail(&run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// List artifacts emitted by a run (global path).
pub async fn cloud_run_artifacts(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_artifacts(&run_id, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Cancel a queued/running run event by run ID (global path).
pub async fn cloud_run_cancel_by_id(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_cancel(&run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Stream updates for a run via SSE (global run path).
///
/// Supports explicit stream session reuse (`x-seren-stream-session-id`) and
/// event replay (`Last-Event-ID`) for resumable clients.
pub async fn cloud_run_stream(
    run_id: Uuid,
    session_id: Option<&str>,
    last_event_id: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    use futures_util::StreamExt;

    let client = ctx.http_client().await?;
    let url = format!(
        "{}/publishers/seren-cloud/runs/{}/stream",
        ctx.api_base(),
        run_id
    );

    let mut request = client.get(&url).header("Accept", "text/event-stream");
    if let Some(session_id) = session_id.map(str::trim).filter(|v| !v.is_empty()) {
        request = request.header("x-seren-stream-session-id", session_id);
    }
    if let Some(last_event_id) = last_event_id.map(str::trim).filter(|v| !v.is_empty()) {
        request = request.header("Last-Event-ID", last_event_id);
    }

    let response = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("SSE connection failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to stream run: {} - {}",
            status,
            body
        ));
    }

    if let Some(server_session_id) = response
        .headers()
        .get("x-seren-stream-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        eprintln!(
            "{} {}",
            "Stream session:".dimmed(),
            server_session_id.bold()
        );
        eprintln!(
            "{}",
            format!(
                "Close session: seren agent cloud-run-stream-close {} --session-id {}",
                run_id, server_session_id
            )
            .dimmed()
        );
    }

    eprintln!(
        "{}",
        format!("Streaming run {}... (Ctrl+C to stop)", run_id).dimmed()
    );

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
            let display = if event_type.is_empty() {
                "event"
            } else {
                event_type.as_str()
            };

            let terminal_from_event = matches!(
                event_type.as_str(),
                "done"
                    | "error"
                    | "run.completed"
                    | "run.failed"
                    | "run.cancelled"
                    | "run.canceled"
            );

            if let Ok(payload) = serde_json::from_str::<serde_json::Value>(&data) {
                eprintln!(
                    "{} {}",
                    format!("[{display}]").cyan(),
                    serde_json::to_string(&payload).unwrap_or_else(|_| data.clone())
                );

                let terminal_from_status = payload
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|status| {
                        matches!(status, "completed" | "failed" | "cancelled" | "canceled")
                    })
                    .unwrap_or(false);
                if terminal_from_event || terminal_from_status {
                    return Ok(());
                }
            } else {
                eprintln!("{} {}", format!("[{display}]").cyan(), data);
                if terminal_from_event {
                    return Ok(());
                }
            }
        }
    }

    eprintln!("{}", "Stream ended.".dimmed());
    Ok(())
}

/// Close an active run stream session (global run path).
pub async fn cloud_run_stream_close(
    run_id: Uuid,
    session_id: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err(anyhow::anyhow!("--session-id cannot be empty."));
    }

    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_stream_close(&run_id, session_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// Destroy a cloud agent deployment.
pub async fn cloud_destroy(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    client
        .seren_cloud_delete(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;
    println!("{} Deployment {} destroyed.", "✓".green(), deployment_id);
    Ok(())
}

/// Get logs from a running cloud agent.
pub async fn cloud_logs(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    use futures_util::StreamExt;

    let client = ctx.client().await?;
    let response = client
        .seren_cloud_logs(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    let mut stream = response;
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| anyhow::anyhow!("Stream error: {}", e))?;
        print!("{}", String::from_utf8_lossy(&bytes));
    }
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

pub async fn cloud_runs(
    deployment_id: Uuid,
    limit: i64,
    offset: i64,
    options: CloudRunQueryOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let status_filter = if options.statuses.is_empty() {
        None
    } else {
        Some(options.statuses.join(","))
    };
    let response = client
        .seren_cloud_deployment_runs(
            &deployment_id,
            options.compute_backend,
            options.has_artifacts,
            Some(limit),
            Some(offset),
            options.q,
            options.source,
            options.started_after,
            options.started_before,
            status_filter.as_deref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    let data = serde_json::to_value(&response)?;
    if let Some(runs) = data.get("data").and_then(|d| d.as_array()) {
        if runs.is_empty() {
            println!("No runs found for deployment {}.", deployment_id);
            return Ok(());
        }
        println!(
            "{:<38} {:<14} {:<10} {:<10} {:<24}",
            "RUN ID", "STATUS", "TIME(ms)", "COST", "STARTED"
        );
        for execution in runs {
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
        output::print_json(&response)?;
    }

    Ok(())
}

/// Get details of a specific run event.
pub async fn cloud_run_get(deployment_id: Uuid, run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run(&deployment_id, &run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
    Ok(())
}

/// List all runs across all cloud agent deployments.
pub async fn cloud_all_runs(
    limit: i64,
    offset: i64,
    options: CloudRunQueryOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let status_filter = if options.statuses.is_empty() {
        None
    } else {
        Some(options.statuses.join(","))
    };
    let response = client
        .seren_cloud_runs(
            options.compute_backend,
            options.has_artifacts,
            Some(limit),
            Some(offset),
            options.q,
            options.source,
            options.started_after,
            options.started_before,
            status_filter.as_deref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    let data = serde_json::to_value(&response)?;
    if let Some(runs) = data.get("data").and_then(|d| d.as_array()) {
        if runs.is_empty() {
            println!("No runs found.");
            return Ok(());
        }
        println!(
            "{:<38} {:<38} {:<14} {:<10} {:<10} {:<24}",
            "RUN ID", "DEPLOYMENT ID", "STATUS", "TIME(ms)", "COST", "STARTED"
        );
        for execution in runs {
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
        output::print_json(&response)?;
    }

    Ok(())
}

/// Cancel a queued/running run event.
pub async fn cloud_run_cancel(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_cancel(&deployment_id, &run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    output::print_json(&response)?;
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

    let client = ctx.client().await?;
    let request = seren::UpdateCloudDeploymentRequest {
        config: body.remove("config"),
        secrets: body.remove("secrets"),
    };
    client
        .seren_cloud_update_config(&deployment_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;

    println!(
        "{} Config updated for deployment {}.",
        "✓".green(),
        deployment_id
    );
    Ok(())
}

struct CloudRuntimeTarget {
    compute_backend: Option<&'static str>,
    runtime_kind: Option<&'static str>,
}

fn resolve_cloud_runtime_target(
    compute_backend: Option<&str>,
    runtime_kind: Option<&str>,
) -> Result<CloudRuntimeTarget> {
    let normalize_backend = |value: &str| -> Result<Option<&'static str>> {
        match value {
            "" | "auto" => Ok(None),
            "aws_container" => Ok(Some("aws_container")),
            "cloudflare_worker" => Ok(Some("cloudflare_worker")),
            "daytona" => Ok(Some("daytona")),
            other => Err(anyhow::anyhow!(
                "Invalid compute_backend '{}'. Use 'auto', 'aws_container', 'cloudflare_worker', or 'daytona'.",
                other
            )),
        }
    };

    let normalize_runtime = |value: &str| -> Result<Option<&'static str>> {
        match value {
            "" | "auto" => Ok(None),
            "python" => Ok(Some("python")),
            "javascript" => Ok(Some("javascript")),
            "typescript" => Ok(Some("typescript")),
            "rust" => Ok(Some("rust")),
            "rust_wasm_adk" => Ok(Some("rust_wasm_adk")),
            other => Err(anyhow::anyhow!(
                "Invalid runtime_kind '{}'. Use 'auto', 'python', 'javascript', 'typescript', 'rust', or 'rust_wasm_adk'.",
                other
            )),
        }
    };

    let backend = compute_backend
        .map(normalize_backend)
        .transpose()?
        .flatten();
    let runtime = runtime_kind.map(normalize_runtime).transpose()?.flatten();

    if let (Some(compute_backend), Some(runtime_kind)) = (backend, runtime) {
        validate_runtime_target(compute_backend, runtime_kind)?;
    }

    Ok(CloudRuntimeTarget {
        compute_backend: backend,
        runtime_kind: runtime,
    })
}

fn validate_runtime_target(compute_backend: &str, runtime_kind: &str) -> Result<()> {
    match (compute_backend, runtime_kind) {
        ("aws_container", "python") => Ok(()),
        ("aws_container", "javascript") => Ok(()),
        ("aws_container", "typescript") => Ok(()),
        ("aws_container", "rust") => Ok(()),
        ("aws_container", "rust_wasm_adk") => Ok(()),
        ("cloudflare_worker", "python") => Ok(()),
        ("cloudflare_worker", "javascript") => Ok(()),
        ("cloudflare_worker", "typescript") => Ok(()),
        ("cloudflare_worker", "rust") => Ok(()),
        ("cloudflare_worker", "rust_wasm_adk") => Ok(()),
        ("daytona", "python") => Ok(()),
        ("daytona", "javascript") => Ok(()),
        ("daytona", "typescript") => Ok(()),
        ("daytona", "rust") => Ok(()),
        _ => Err(anyhow::anyhow!(
            "Invalid backend/runtime combination: {}/{}. Valid pairs are aws_container+(python|javascript|typescript|rust|rust_wasm_adk), cloudflare_worker+(python|javascript|typescript|rust|rust_wasm_adk), daytona+(python|javascript|typescript|rust).",
            compute_backend,
            runtime_kind
        )),
    }
}

fn ensure_runtime_entrypoint(
    scripts_dir: &Path,
    compute_backend: Option<&str>,
    runtime_kind: &str,
) -> Result<()> {
    match runtime_kind {
        "rust" => {
            let has_worker_artifact = find_worker_runtime_entrypoint(scripts_dir).is_some()
                && contains_file_with_extension(scripts_dir, "wasm");
            let has_native_entrypoint = find_native_runtime_entrypoint(scripts_dir).is_some();

            match compute_backend {
                Some("cloudflare_worker") => {
                    if has_worker_artifact {
                        return Ok(());
                    }
                    Err(anyhow::anyhow!(
                        "No Rust Worker artifact set found in '{}'. compute_backend=cloudflare_worker with runtime_kind=rust expects JS glue entrypoint (worker.js/index.js) plus at least one .wasm file.",
                        scripts_dir.display()
                    ))
                }
                Some("aws_container") | Some("daytona") => {
                    if has_native_entrypoint {
                        return Ok(());
                    }
                    Err(anyhow::anyhow!(
                        "No native runtime entrypoint found in '{}'. runtime_kind=rust on AWS/Daytona expects a shell script (*.sh) or a precompiled Linux binary such as agent/main/app/worker.",
                        scripts_dir.display()
                    ))
                }
                _ => {
                    if has_worker_artifact || has_native_entrypoint {
                        return Ok(());
                    }
                    Err(anyhow::anyhow!(
                        "No Rust runtime entrypoint found in '{}'. runtime_kind=rust supports either Cloudflare Worker artifacts (worker.js/index.js plus .wasm) or AWS/Daytona native bundles (shell script or precompiled Linux binary).",
                        scripts_dir.display()
                    ))
                }
            }
        }
        "rust_wasm_adk" => match compute_backend {
            Some("cloudflare_worker") => {
                if find_worker_runtime_entrypoint(scripts_dir).is_some() {
                    return Ok(());
                }
                Err(anyhow::anyhow!(
                    "No Worker wrapper entrypoint found in '{}'. compute_backend=cloudflare_worker with runtime_kind=rust_wasm_adk expects worker.js/index.js (or similar JS/TS worker source).",
                    scripts_dir.display()
                ))
            }
            _ => {
                if find_standalone_wasm_entrypoint(scripts_dir).is_some() {
                    return Ok(());
                }
                Err(anyhow::anyhow!(
                    "No standalone WASI module found in '{}'. runtime_kind=rust_wasm_adk on AWS expects a prebuilt .wasm file such as agent.wasm or main.wasm.",
                    scripts_dir.display()
                ))
            }
        },
        _ => {
            if find_runtime_entrypoint(scripts_dir, runtime_kind).is_some() {
                return Ok(());
            }

            let expected = match runtime_kind {
                "python" => "agent.py/main.py/index.py (or any .py file)",
                "javascript" => "agent.js/main.js/index.js/worker.js (or any .js/.mjs/.cjs file)",
                "typescript" => "agent.ts/main.ts/index.ts/worker.ts (or any .ts file)",
                other => return Err(anyhow::anyhow!("Unsupported runtime_kind '{}'.", other)),
            };

            Err(anyhow::anyhow!(
                "No entrypoint found in '{}'. Expected one of: {}.",
                scripts_dir.display(),
                expected
            ))
        }
    }
}

fn find_runtime_entrypoint(scripts_dir: &Path, runtime_kind: &str) -> Option<String> {
    let candidates: &[&str] = match runtime_kind {
        "python" => &["agent.py", "main.py", "index.py", "run.py"],
        "javascript" => &[
            "agent.js",
            "main.js",
            "index.js",
            "worker.js",
            "agent.mjs",
            "main.mjs",
            "index.mjs",
            "worker.mjs",
            "agent.cjs",
            "main.cjs",
            "index.cjs",
            "worker.cjs",
        ],
        "typescript" => &["agent.ts", "main.ts", "index.ts", "worker.ts"],
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
        _ => return None,
    };
    find_file_with_extensions(scripts_dir, fallback_exts)
}

fn find_worker_runtime_entrypoint(scripts_dir: &Path) -> Option<String> {
    let candidates = [
        "worker.js",
        "index.js",
        "main.js",
        "dist/worker.js",
        "dist/index.js",
        "dist/main.js",
        "worker.mjs",
        "index.mjs",
        "main.mjs",
        "dist/worker.mjs",
        "dist/index.mjs",
        "dist/main.mjs",
        "worker.ts",
        "index.ts",
        "main.ts",
        "dist/worker.ts",
        "dist/index.ts",
        "dist/main.ts",
    ];

    for candidate in candidates {
        if scripts_dir.join(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }

    find_file_with_extensions(scripts_dir, &["js", "mjs", "cjs", "ts"])
}

fn find_standalone_wasm_entrypoint(scripts_dir: &Path) -> Option<String> {
    for candidate in ["agent.wasm", "main.wasm", "app.wasm", "worker.wasm"] {
        if scripts_dir.join(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }

    find_file_with_extensions(scripts_dir, &["wasm"])
}

fn find_native_runtime_entrypoint(scripts_dir: &Path) -> Option<String> {
    let candidates = [
        "agent",
        "main",
        "app",
        "worker",
        "run",
        "entrypoint",
        "start",
        "agent.sh",
        "main.sh",
        "run.sh",
        "entrypoint.sh",
        "start.sh",
    ];

    for candidate in candidates {
        if scripts_dir.join(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }

    if let Some(path) = find_file_with_extensions(scripts_dir, &["sh", "bash"]) {
        return Some(path);
    }

    find_extensionless_runtime_file(scripts_dir)
}

fn find_extensionless_runtime_file(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let lower = file_name.to_ascii_lowercase();
            if lower.contains('.')
                || matches!(
                    lower.as_str(),
                    "dockerfile" | "makefile" | "justfile" | "license" | "notice"
                )
                || lower.starts_with("readme")
            {
                continue;
            }
            if matches!(
                lower.as_str(),
                "agent" | "main" | "app" | "worker" | "run" | "entrypoint" | "start"
            ) || path.parent() == Some(dir)
            {
                return path
                    .strip_prefix(dir)
                    .ok()
                    .and_then(|p| p.to_str())
                    .map(|p| p.to_string());
            }
        } else if path.is_dir()
            && let Some(found) = find_extensionless_runtime_file(&path)
        {
            let dir_name = path.file_name()?.to_str()?;
            return Some(format!("{}/{}", dir_name, found));
        }
    }

    None
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
