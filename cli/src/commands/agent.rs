use std::{collections::HashMap, fs, path::Path, str::FromStr};

use anyhow::Result;
use colored::Colorize;
use sha2::{Digest, Sha256};
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

/// Get generated skill.md guidance for a publisher.
pub async fn get_publisher_skill_doc(publisher: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = publisher_skill_doc_url(&ctx.api_base(), publisher)?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "text/markdown")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get publisher skill doc: {}", e))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to get publisher skill doc: {} - {}",
            status,
            truncate_for_cli(&body, 1200)
        ));
    }

    let skill_md = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read publisher skill doc: {}", e))?;
    match ctx.format {
        OutputFormat::Json => output::print_json(&serde_json::json!({
            "publisher": publisher,
            "skill_md": skill_md,
        }))?,
        OutputFormat::Table => println!("{skill_md}"),
    }

    Ok(())
}

/// Get the generated skill.md guidance for the core Seren API.
pub async fn get_seren_api_skill_doc(ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let url = seren_api_skill_doc_url(&ctx.api_base())?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "text/markdown")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get Seren API skill doc: {}", e))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to get Seren API skill doc: {} - {}",
            status,
            truncate_for_cli(&body, 1200)
        ));
    }

    let skill_md = response
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read Seren API skill doc: {}", e))?;
    match ctx.format {
        OutputFormat::Json => output::print_json(&serde_json::json!({
            "skill_md": skill_md,
        }))?,
        OutputFormat::Table => println!("{skill_md}"),
    }

    Ok(())
}

fn publisher_skill_doc_url(api_base_url: &str, publisher: &str) -> Result<reqwest::Url> {
    skill_doc_url(api_base_url, &["publishers", publisher, "skill.md"])
}

fn seren_api_skill_doc_url(api_base_url: &str) -> Result<reqwest::Url> {
    skill_doc_url(api_base_url, &["skill.md"])
}

fn skill_doc_url(api_base_url: &str, segments: &[&str]) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(api_base_url.trim_end_matches('/'))
        .map_err(|e| anyhow::anyhow!("Invalid API base URL '{}': {}", api_base_url, e))?;
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("API base URL cannot be used for path-based requests"))?
        .extend(segments);
    Ok(url)
}

fn truncate_for_cli(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_none() {
        return truncated;
    }
    format!("{truncated}... (truncated)")
}

fn compact_preview_for_cli(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_for_cli(&compact, max_chars)
}

fn build_deployment_name_map(deployments: &[serde_json::Value]) -> HashMap<String, String> {
    deployments
        .iter()
        .filter_map(|deployment| {
            let deployment_id = deployment.get("id").and_then(|value| value.as_str())?;
            let deployment_name = deployment
                .get("name")
                .and_then(|value| value.as_str())
                .or_else(|| {
                    deployment
                        .get("skill_slug")
                        .and_then(|value| value.as_str())
                })
                .unwrap_or(deployment_id);
            Some((deployment_id.to_string(), deployment_name.to_string()))
        })
        .collect()
}

fn enrich_with_deployment_name(
    entries: &[serde_json::Value],
    deployment_names: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    entries
        .iter()
        .map(|entry| {
            let mut entry = entry.clone();
            if let Some(object) = entry.as_object_mut()
                && let Some(deployment_id) =
                    object.get("deployment_id").and_then(|value| value.as_str())
                && let Some(name) = deployment_names.get(deployment_id)
            {
                object.insert(
                    "deployment_name".to_string(),
                    serde_json::Value::String(name.clone()),
                );
            }
            entry
        })
        .collect()
}

fn enrich_data_envelope_with_deployment_names(
    envelope: &serde_json::Value,
    deployment_names: &HashMap<String, String>,
) -> serde_json::Value {
    let mut envelope = envelope.clone();
    if let Some(object) = envelope.as_object_mut()
        && let Some(entries) = object.get("data").and_then(|value| value.as_array())
    {
        object.insert(
            "data".to_string(),
            serde_json::Value::Array(enrich_with_deployment_name(entries, deployment_names)),
        );
    }
    envelope
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
    passthrough_header_rewrite_json: Option<&str>,
    oauth2_token_url: Option<&str>,
    oauth2_client_id: Option<&str>,
    oauth2_client_secret: Option<&str>,
    oauth2_scopes: Vec<String>,
    use_cases: Option<Vec<String>>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;

    let publisher_category_enum =
        seren::parse_publisher_category(publisher_category).map_err(|e| anyhow::anyhow!(e))?;
    let database_type_enum =
        seren::parse_database_type(database_type).map_err(|e| anyhow::anyhow!(e))?;
    let integration_type_enum =
        seren::parse_integration_type(integration_type).map_err(|e| anyhow::anyhow!(e))?;

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

    let auth_type = seren::normalize_auth_type(auth_type).map_err(|e| anyhow::anyhow!(e))?;

    let allowed_passthrough_headers_normalized = seren::normalize_string_list(
        allowed_passthrough_headers.iter().map(String::as_str),
        "allowed_passthrough_headers",
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let passthrough_header_rewrite = match passthrough_header_rewrite_json {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!(
                    "passthrough_header_rewrite_json must not be empty"
                ));
            }
            let parsed: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| anyhow::anyhow!("Invalid passthrough_header_rewrite_json: {}", e))?;
            let object = parsed.as_object().ok_or_else(|| {
                anyhow::anyhow!("passthrough_header_rewrite_json must decode to a JSON object")
            })?;
            if object.is_empty() {
                return Err(anyhow::anyhow!(
                    "passthrough_header_rewrite_json must decode to a non-empty JSON object"
                ));
            }
            Some(parsed)
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
        if connection_string.is_some() {
            return Err(anyhow::anyhow!(
                "connection_string is not valid for database_type=mongodb; use api_url + upstream_api_key and optional database_config_json"
            ));
        }
    }

    let oauth2_token_url = seren::normalize_optional_string(oauth2_token_url, "oauth2_token_url")
        .map_err(|e| anyhow::anyhow!(e))?;
    seren::ensure_https(oauth2_token_url.as_deref(), "oauth2_token_url")
        .map_err(|e| anyhow::anyhow!(e))?;

    let oauth2_client_id = seren::normalize_optional_string(oauth2_client_id, "oauth2_client_id")
        .map_err(|e| anyhow::anyhow!(e))?;
    let oauth2_client_secret =
        seren::normalize_optional_string(oauth2_client_secret, "oauth2_client_secret")
            .map_err(|e| anyhow::anyhow!(e))?;

    let normalized_scopes =
        seren::normalize_string_list(oauth2_scopes.iter().map(String::as_str), "oauth2_scopes")
            .map_err(|e| anyhow::anyhow!(e))?;
    let normalized_use_cases = seren::normalize_string_list(
        use_cases
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str),
        "use_cases",
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    seren::validate_oauth2_create_fields(
        auth_type.as_deref(),
        oauth2_token_url.as_deref(),
        oauth2_client_id.as_deref(),
        oauth2_client_secret.as_deref(),
        !normalized_scopes.is_empty(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

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
        passthrough_header_rewrite,
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

fn format_usd_cents(amount_cents: i64) -> String {
    let sign = if amount_cents < 0 { "-" } else { "" };
    let abs = amount_cents.unsigned_abs();
    format!("{sign}${}.{:02}", abs / 100, abs % 100)
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

fn wallet_transfer_request(
    recipient_email: &str,
    amount_cents: i64,
    memo: Option<&str>,
) -> Result<seren::WalletTransferRequest> {
    if amount_cents <= 0 {
        return Err(anyhow::anyhow!("Amount must be positive"));
    }

    Ok(seren::WalletTransferRequest {
        recipient_email: recipient_email.to_string(),
        amount_cents,
        memo: memo.map(str::to_string),
    })
}

/// Preview a SerenBucks wallet transfer
pub async fn preview_transfer(
    recipient_email: &str,
    amount_cents: i64,
    memo: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = wallet_transfer_request(recipient_email, amount_cents, memo)?;

    let response = match client.preview_wallet_transfer(&body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to preview transfer", e).await),
    };

    let preview = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&preview)?,
        OutputFormat::Table => match &preview.data {
            seren::DataResponseWalletTransferPreviewResponseData::Instant {
                amount_cents,
                balance_after_cents,
                daily_remaining_cents,
                recipient,
                ..
            } => {
                let rows = [
                    ("Kind", "instant".to_string()),
                    ("Recipient", recipient.display_name.clone()),
                    ("Recipient ID", recipient.user_id.to_string()),
                    ("Amount", format_usd_cents(*amount_cents)),
                    ("Balance After", format_usd_cents(*balance_after_cents)),
                    ("Daily Remaining", format_usd_cents(*daily_remaining_cents)),
                ];
                output::print_key_value_table(Some("Transfer Preview"), &rows);
            }
            seren::DataResponseWalletTransferPreviewResponseData::PendingInvite {
                amount_cents,
                balance_after_cents,
                daily_remaining_cents,
                expires_at_estimate,
                recipient_email,
                ..
            } => {
                let rows = [
                    ("Kind", "pending invite".to_string()),
                    ("Recipient Email", recipient_email.clone()),
                    ("Amount", format_usd_cents(*amount_cents)),
                    ("Balance After", format_usd_cents(*balance_after_cents)),
                    ("Daily Remaining", format_usd_cents(*daily_remaining_cents)),
                    ("Expires At", expires_at_estimate.to_string()),
                ];
                output::print_key_value_table(Some("Transfer Preview"), &rows);
            }
        },
    }

    Ok(())
}

/// Execute a SerenBucks wallet transfer
pub async fn send_transfer(
    recipient_email: &str,
    amount_cents: i64,
    memo: Option<&str>,
    idempotency_key: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = wallet_transfer_request(recipient_email, amount_cents, memo)?;
    let idempotency_key = idempotency_key.trim();
    if idempotency_key.is_empty() {
        return Err(anyhow::anyhow!("Idempotency key must not be empty"));
    }

    let response = match client.execute_wallet_transfer(idempotency_key, &body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to send transfer", e).await),
    };

    let transfer = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&transfer)?,
        OutputFormat::Table => match &transfer.data {
            seren::DataResponseWalletTransferExecuteResponseData::Instant {
                balance_after_cents,
                settled_at,
                status,
                transfer_id,
            } => {
                let rows = [
                    ("Kind", "instant".to_string()),
                    ("Transfer ID", transfer_id.to_string()),
                    ("Status", status.clone()),
                    ("Settled At", settled_at.to_string()),
                    ("Balance After", format_usd_cents(*balance_after_cents)),
                    ("Idempotency Key", idempotency_key.to_string()),
                ];
                output::print_key_value_table(Some("Transfer Sent"), &rows);
            }
            seren::DataResponseWalletTransferExecuteResponseData::PendingInvite {
                balance_after_cents,
                expires_at,
                invite_url,
                pending_transfer_id,
                status,
                ..
            } => {
                let rows = [
                    ("Kind", "pending invite".to_string()),
                    ("Pending Transfer ID", pending_transfer_id.to_string()),
                    ("Status", status.clone()),
                    ("Expires At", expires_at.to_string()),
                    ("Balance After", format_usd_cents(*balance_after_cents)),
                    (
                        "Invite URL",
                        invite_url.clone().unwrap_or_else(|| "-".to_string()),
                    ),
                    ("Idempotency Key", idempotency_key.to_string()),
                ];
                output::print_key_value_table(Some("Transfer Invite Created"), &rows);
            }
        },
    }

    Ok(())
}

/// List SerenBucks wallet transfers
pub async fn list_transfers(
    direction: Option<&str>,
    status: Option<&str>,
    cursor: Option<&str>,
    limit: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let direction = direction
        .map(str::parse::<seren::WalletTransferDirection>)
        .transpose()
        .map_err(|_| anyhow::anyhow!("Invalid direction. Use sent, received, or all"))?;

    let response = match client
        .list_wallet_transfers(cursor, direction, limit, status)
        .await
    {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to list transfers", e).await),
    };

    let transfers = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&transfers)?,
        OutputFormat::Table => {
            let data = &transfers.data;
            output::print_wallet_transfers_table(&data.items);
            if let Some(next_cursor) = &data.next_cursor {
                println!("Next cursor: {next_cursor}");
            }
        }
    }

    Ok(())
}

/// Claim a pending SerenBucks transfer invite
pub async fn claim_transfer(token: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let body = seren::WalletTransferClaimRequest {
        token: token.to_string(),
    };

    let response = match client.claim_wallet_transfer(&body).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to claim transfer", e).await),
    };

    let claim = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&claim)?,
        OutputFormat::Table => {
            let data = &claim.data;
            let rows = [
                ("Pending Transfer ID", data.pending_transfer_id.to_string()),
                ("Received", format_usd_cents(data.amount_received_cents)),
                ("Balance After", format_usd_cents(data.balance_after_cents)),
            ];
            output::print_key_value_table(Some("Transfer Claimed"), &rows);
        }
    }

    Ok(())
}

/// Recall a pending outbound SerenBucks transfer
pub async fn recall_transfer(pending_transfer_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = match client.recall_wallet_transfer(&pending_transfer_id).await {
        Ok(response) => response,
        Err(e) => return Err(anyhow_from_seren_error("Failed to recall transfer", e).await),
    };

    let recall = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&recall)?,
        OutputFormat::Table => {
            let data = &recall.data;
            let rows = [
                ("Pending Transfer ID", data.pending_transfer_id.to_string()),
                ("Status", data.status.clone()),
                ("Refunded", format_usd_cents(data.refunded_amount_cents)),
                ("Balance After", format_usd_cents(data.balance_after_cents)),
            ];
            output::print_key_value_table(Some("Transfer Recalled"), &rows);
        }
    }

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
        .get_transactions(None, None, None, None, limit, offset, None)
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
        description: description.map(str::to_string),
        dependencies: deps,
        compute_backend: compute_backend.map(str::to_string),
        settings_schema: None,
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

pub async fn private_models_list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .get_private_models()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list private models: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let rows = response
                .data
                .data
                .iter()
                .map(|model| {
                    let recommended = if model.recommended.unwrap_or(false) {
                        " recommended"
                    } else {
                        ""
                    };
                    let display = model.display_name.as_deref().unwrap_or(&model.id);
                    format!(
                        "{} - {} ({}){}",
                        model.id, display, model.owned_by, recommended
                    )
                })
                .collect::<Vec<_>>();
            output::print_list_table(Some("Private Models"), "Model", &rows);
        }
    }

    Ok(())
}

pub async fn private_models_catalog(region: Option<&str>, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_agent_private_models(region)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list seren-agent private model catalog: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let data = &response.data;
            let summary = [
                ("Source", data.catalog_source.to_string()),
                ("Default Model", data.default_model_id.clone()),
                (
                    "Custom Model IDs",
                    if data.supports_custom_model_id {
                        "yes".to_string()
                    } else {
                        "no".to_string()
                    },
                ),
            ];
            output::print_key_value_table(Some("Private Model Catalog"), &summary);
            if let Some(notice) = &data.notice {
                println!();
                output::print_key_value_table(Some("Notice"), &[("Message", notice.clone())]);
            }
            let rows = data
                .models
                .iter()
                .map(|model| {
                    let recommended = if model.recommended {
                        " recommended"
                    } else {
                        ""
                    };
                    format!("{} - {}{}", model.model_id, model.label, recommended)
                })
                .collect::<Vec<_>>();
            println!();
            output::print_list_table(Some("Models"), "Model", &rows);
        }
    }

    Ok(())
}

pub struct PrivateModelsChatOptions<'a> {
    pub model: Option<&'a str>,
    pub message: Option<&'a str>,
    pub messages_json: Option<&'a str>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<i32>,
    pub top_p: Option<f32>,
    pub top_k: Option<i32>,
    pub response_schema_json: Option<&'a str>,
    pub tools_json: Option<&'a str>,
}

pub async fn private_models_chat(
    options: PrivateModelsChatOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let messages = private_model_messages(options.message, options.messages_json)?;
    let response_schema = options
        .response_schema_json
        .map(|raw| parse_json_object(raw, "response_schema_json"))
        .transpose()?;
    let tools = options
        .tools_json
        .map(|raw| parse_json_object_array(raw, "tools_json"))
        .transpose()?;

    let mut request = serde_json::Map::new();
    request.insert(
        "messages".to_string(),
        serde_json::Value::Array(
            messages
                .into_iter()
                .map(serde_json::Value::Object)
                .collect(),
        ),
    );
    request.insert("stream".to_string(), serde_json::Value::Bool(false));
    if let Some(model) = options.model {
        request.insert(
            "model".to_string(),
            serde_json::Value::String(model.to_string()),
        );
    }
    if let Some(temperature) = options.temperature {
        request.insert("temperature".to_string(), serde_json::json!(temperature));
    }
    if let Some(max_tokens) = options.max_tokens {
        request.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
    }
    if let Some(top_p) = options.top_p {
        request.insert("top_p".to_string(), serde_json::json!(top_p));
    }
    if let Some(top_k) = options.top_k {
        request.insert("top_k".to_string(), serde_json::json!(top_k));
    }
    if let Some(response_schema) = response_schema {
        request.insert(
            "response_schema".to_string(),
            serde_json::Value::Object(response_schema),
        );
    }
    if let Some(tools) = tools {
        request.insert(
            "tools".to_string(),
            serde_json::Value::Array(tools.into_iter().map(serde_json::Value::Object).collect()),
        );
    }
    let request = serde_json::from_value::<seren::PrivateModelsChatCompletionsRequest>(
        serde_json::Value::Object(request),
    )
    .map_err(|e| anyhow::anyhow!("Invalid chat completions request: {}", e))?;

    let client = ctx.client().await?;
    let response = client
        .post_chat_completions(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Private model chat completion failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let data = &response.data;
            let rows = [
                ("Status", data.status.to_string()),
                ("Payment Source", data.payment_source.clone()),
                ("Cost", format!("{} {}", data.cost, data.asset_symbol)),
                ("Execution Time", format!("{}ms", data.execution_time_ms)),
                ("Response Bytes", data.response_bytes.to_string()),
            ];
            output::print_key_value_table(Some("Private Model Response"), &rows);
            println!();
            output::print_json(&data.body)?;
        }
    }

    Ok(())
}

fn private_model_messages(
    message: Option<&str>,
    messages_json: Option<&str>,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    match (message, messages_json) {
        (Some(_), Some(_)) => anyhow::bail!("Use either --message or --messages-json, not both"),
        (Some(message), None) => {
            let mut map = serde_json::Map::new();
            map.insert("role".to_string(), serde_json::json!("user"));
            map.insert("content".to_string(), serde_json::json!(message));
            Ok(vec![map])
        }
        (None, Some(raw)) => parse_json_object_array(raw, "messages_json"),
        (None, None) => anyhow::bail!("Provide --message or --messages-json"),
    }
}

fn parse_json_object(
    raw: &str,
    field_name: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    match serde_json::from_str::<serde_json::Value>(raw)? {
        serde_json::Value::Object(map) => Ok(map),
        _ => anyhow::bail!("{field_name} must be a JSON object"),
    }
}

fn parse_json_object_array(
    raw: &str,
    field_name: &str,
) -> Result<Vec<serde_json::Map<String, serde_json::Value>>> {
    match serde_json::from_str::<serde_json::Value>(raw)? {
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                serde_json::Value::Object(map) => Ok(map),
                _ => anyhow::bail!("{field_name} must contain only JSON objects"),
            })
            .collect(),
        _ => anyhow::bail!("{field_name} must be a JSON array"),
    }
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
    pub cron_timezone: Option<&'a str>,
    pub eval_gate_set_id: Option<Uuid>,
    pub eval_gate_max_age_seconds: Option<i32>,
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
    pub cron_timezone: Option<&'a str>,
    pub eval_gate_set_id: Option<Uuid>,
    pub eval_gate_max_age_seconds: Option<i32>,
    pub compute_backend: Option<&'a str>,
    pub template: Option<&'a str>,
    pub tool_presets: &'a [String],
    pub approval_policy: Option<&'a str>,
    pub model_policy: Option<&'a str>,
    pub allowed_remote_agent_origins: &'a [String],
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub agent_config_path: Option<&'a str>,
    pub capability_policy_json: Option<&'a str>,
    pub capability_policy_path: Option<&'a str>,
    pub prompt: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub visibility: Option<&'a str>,
}

pub struct ManagedAgentUpdateOptions<'a> {
    pub name: Option<&'a str>,
    pub agent_slug: Option<&'a str>,
    pub cron_schedule: Option<&'a str>,
    pub cron_timezone: Option<&'a str>,
    pub eval_gate_set_id: Option<Uuid>,
    pub eval_gate_max_age_seconds: Option<i32>,
    pub clear_eval_gate: bool,
    pub template: Option<&'a str>,
    pub tool_presets: &'a [String],
    pub approval_policy: Option<&'a str>,
    pub model_policy: Option<&'a str>,
    pub allowed_remote_agent_origins: &'a [String],
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub agent_config_path: Option<&'a str>,
    pub capability_policy_json: Option<&'a str>,
    pub capability_policy_path: Option<&'a str>,
    pub clear_capability_policy: bool,
    pub clear_requirements_txt: bool,
    pub prompt: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub visibility: Option<&'a str>,
}

const ORCHESTRATION_CONFIG_FIELDS: &[&str] = &[
    "context_budget_tokens",
    "dashboard_config",
    "external_databases",
    "fallback_models",
    "max_iterations",
    "max_timeout_seconds",
    "max_tool_output_chars",
    "model_config",
    "requirements_txt",
    "model_id",
    "requirements",
    "system_prompt",
    "tool_definitions",
    "visibility",
];
const MANAGED_AGENT_CONFIG_FIELDS: &[&str] = &[
    "bundle",
    "context_budget_tokens",
    "dashboard_config",
    "external_databases",
    "fallback_models",
    "max_iterations",
    "max_timeout_seconds",
    "max_tool_output_chars",
    "capability_policy",
    "memory_policy",
    "model_config",
    "model_id",
    "prompt",
    "template",
    "tool_presets",
    "approval_policy",
    "model_policy",
    "allowed_remote_agent_origins",
    "requirements",
    "requirements_txt",
    "runtime_policy",
    "visibility",
];

fn default_employee_memory_policy_value() -> serde_json::Value {
    serde_json::json!({
        "graph_memory": {
            "enabled": true,
            "store": "seren_managed",
            "write_policy": "on_observation",
            "read_policy": "explicit_tool"
        },
        "semantic_memory": {
            "enabled": false,
            "store": "seren_managed",
            "write_policy": "none",
            "read_policy": "explicit_tool",
            "retention_days": null
        },
        "knowledge": {
            "enabled": true,
            "store": "seren_managed",
            "source": "agent_instructions",
            "read_policy": "explicit_tool",
            "index_policy": "encrypted_scan",
            "chunk_size": null,
            "chunk_overlap": null,
            "top_k": null
        },
        "transcript_retention_days": 30,
        "compaction": {
            "token_threshold": 120000,
            "event_retention_count": 24,
            "overlap_tokens": 1500
        }
    })
}

fn default_employee_capability_policy_value() -> serde_json::Value {
    serde_json::json!({
        "tool_error_recovery": {
            "enabled": true,
            "max_attempts": 3,
            "global_limit": 12,
            "backoff": {
                "kind": "exponential",
                "base_delay_ms": 100,
                "max_delay_ms": 2000
            },
            "allow_tools": [],
            "deny_tools": []
        },
        "browser": {
            "enabled": false,
            "profile": "minimal"
        },
        "audio": {
            "enabled": false,
            "speech_to_text": false,
            "text_to_speech": false,
            "voice_activity_detection": false
        },
        "realtime_sessions": {
            "enabled": false,
            "provider": "openai",
            "voice_activity_detection": true,
            "input_transcription": true,
            "persist_transcripts": true,
            "store_to_memory": true
        }
    })
}

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

fn load_managed_agent_json_override(
    inline_json: Option<&str>,
    file_path: Option<&str>,
    field_name: &str,
) -> Result<Option<serde_json::Value>> {
    match (inline_json, file_path) {
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "Provide either --{field_name} or --{field_name}-file, not both."
        )),
        (Some(value), None) => serde_json::from_str(value)
            .map(Some)
            .map_err(|error| anyhow::anyhow!("Invalid --{field_name} JSON: {error}")),
        (None, Some(path)) => {
            let content = fs::read_to_string(path)?;
            serde_json::from_str(&content)
                .map(Some)
                .map_err(|error| anyhow::anyhow!("Invalid --{field_name}-file JSON: {error}"))
        }
        (None, None) => Ok(None),
    }
}

/// Workload-level fields that the SDK now expects nested under `workload`.
const WORKLOAD_LEVEL_FIELDS: &[&str] = &[
    "deployment_bundle_id",
    "compute_backend",
    "config",
    "external_databases",
    "fallback_models",
    "model_config",
    "model_id",
    "network_policy",
    "publisher_only",
    "requirements",
    "requirements_txt",
    "runtime_kind",
    "secrets",
    "side_effect_policy",
    "system_prompt",
    "tool_definitions",
];

/// Workload limits fields that should be folded into `workload.limits`.
const WORKLOAD_LIMITS_FIELDS: &[&str] = &[
    "context_budget_tokens",
    "max_iterations",
    "max_timeout_seconds",
    "max_tool_calls_per_run",
    "max_tool_output_chars",
];

/// Workload execution fields that distinguish llm-style workloads.
const LLM_EXECUTION_FIELDS: &[&str] = &[
    "bundle",
    "fallback_models",
    "model_config",
    "model_id",
    "system_prompt",
    "tool_definitions",
];

/// Workload execution fields that distinguish deployment-bundle code workloads.
const CODE_EXECUTION_FIELDS: &[&str] = &["deployment_bundle_id", "runtime_kind"];

/// Reshape a flat deploy/update body into the SDK-shaped JSON object.
///
/// The CLI collects flags into a flat `Map<String, Value>`. The SDK contract
/// nests workload-level fields under `workload`, splits the
/// LLM/code execution into a tagged `WorkloadExecution`, bundles `eval_gate_*`
/// into a typed `EvalGate`, and folds resource limits under `workload.limits`.
fn reshape_body_for_sdk(
    body: serde_json::Map<String, serde_json::Value>,
    expect_code_workload: bool,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let mut envelope = body;

    let prompt = envelope.remove("prompt");
    let requirements_txt = envelope.remove("requirements_txt");

    let mut workload = serde_json::Map::new();
    let mut limits = serde_json::Map::new();
    let mut llm_execution = serde_json::Map::new();
    let mut code_execution = serde_json::Map::new();

    for key in WORKLOAD_LIMITS_FIELDS {
        if let Some(value) = envelope.remove(*key) {
            limits.insert((*key).to_string(), value);
        }
    }
    for key in LLM_EXECUTION_FIELDS {
        if let Some(value) = envelope.remove(*key) {
            llm_execution.insert((*key).to_string(), value);
        }
    }
    for key in CODE_EXECUTION_FIELDS {
        if let Some(value) = envelope.remove(*key) {
            code_execution.insert((*key).to_string(), value);
        }
    }
    for key in WORKLOAD_LEVEL_FIELDS {
        if let Some(value) = envelope.remove(*key) {
            // Skip keys that already moved into the execution maps above.
            if LLM_EXECUTION_FIELDS.contains(key) || CODE_EXECUTION_FIELDS.contains(key) {
                continue;
            }
            workload.insert((*key).to_string(), value);
        }
    }

    if let Some(prompt) = prompt {
        if expect_code_workload {
            llm_execution
                .entry("system_prompt".to_string())
                .or_insert(prompt);
        } else {
            let bundle = llm_execution
                .remove("bundle")
                .map(|bundle| bundle_value_with_prompt_override(bundle, prompt.clone()))
                .unwrap_or_else(|| bundle_value_for_prompt(prompt));
            llm_execution.insert("bundle".to_string(), bundle);
        }
    }

    let has_code = !code_execution.is_empty() || expect_code_workload;
    if has_code && !llm_execution.is_empty() {
        anyhow::bail!(
            "A deployment cannot combine code execution fields with LLM execution fields."
        );
    }
    if has_code {
        if let Some(requirements_txt) = requirements_txt {
            code_execution.insert("requirements_txt".to_string(), requirements_txt);
        }
        code_execution.insert(
            "type".to_string(),
            serde_json::Value::String("code".to_string()),
        );
        workload.insert(
            "execution".to_string(),
            serde_json::Value::Object(code_execution),
        );
    } else {
        if let Some(requirements_txt) = requirements_txt {
            llm_execution.insert("requirements_txt".to_string(), requirements_txt);
        }
        let has_llm = !llm_execution.is_empty();
        if has_llm {
            llm_execution.insert(
                "type".to_string(),
                serde_json::Value::String("llm".to_string()),
            );
            workload.insert(
                "execution".to_string(),
                serde_json::Value::Object(llm_execution),
            );
        }
    }
    if !limits.is_empty() {
        workload.insert("limits".to_string(), serde_json::Value::Object(limits));
    }
    if !workload.is_empty() {
        envelope.insert("workload".to_string(), serde_json::Value::Object(workload));
    }

    // Bundle eval_gate_set_id + eval_gate_max_age_seconds into a typed EvalGate.
    let eval_gate_set_id = envelope.remove("eval_gate_set_id");
    let eval_gate_max_age_seconds = envelope.remove("eval_gate_max_age_seconds");
    if let (Some(set_id), Some(max_age_seconds)) = (eval_gate_set_id, eval_gate_max_age_seconds) {
        let mut gate = serde_json::Map::new();
        gate.insert("set_id".to_string(), set_id);
        gate.insert("max_age_seconds".to_string(), max_age_seconds);
        envelope.insert("eval_gate".to_string(), serde_json::Value::Object(gate));
    }

    Ok(envelope)
}

fn bundle_value_for_prompt(prompt: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "instructions": [{
            "kind": "skill",
            "path": "SKILL.md",
            "content": prompt
        }]
    })
}

fn bundle_value_with_prompt_override(
    mut bundle: serde_json::Value,
    prompt: serde_json::Value,
) -> serde_json::Value {
    let Some(instructions) = bundle
        .get_mut("instructions")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return bundle_value_for_prompt(prompt);
    };

    if let Some(instruction) = instructions.iter_mut().find(|instruction| {
        instruction.get("kind").and_then(serde_json::Value::as_str) == Some("skill")
    }) {
        if let Some(object) = instruction.as_object_mut() {
            object.insert("content".to_string(), prompt);
            object.remove("sha256");
        }
    } else {
        instructions.push(serde_json::json!({
            "kind": "skill",
            "path": "SKILL.md",
            "content": prompt
        }));
    }

    bundle
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn put_presigned_deployment_bundle(
    upload_url: &str,
    upload_headers: &HashMap<String, String>,
    bundle: Vec<u8>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let mut request = client.put(upload_url).body(bundle);
    for (name, value) in upload_headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request = request.header(name, value);
    }

    let response = request.send().await.map_err(|e| {
        anyhow::anyhow!("Failed to upload deployment bundle to object storage: {e}")
    })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "Failed to upload deployment bundle to object storage: HTTP {} {}",
            status,
            body
        ));
    }
    Ok(())
}

async fn ensure_cloud_deployment_bundle(client: &seren::Client, bundle: Vec<u8>) -> Result<Uuid> {
    let sha256 = sha256_hex(&bundle);
    let size_bytes = i64::try_from(bundle.len())
        .map_err(|_| anyhow::anyhow!("Deployment bundle is too large."))?;
    let request = seren::CreateCloudDeploymentBundleRequest {
        sha256,
        size_bytes,
        source_kind: seren::CloudDeploymentBundleSourceKind::TarGz,
    };

    let registration = match client.seren_cloud_create_deployment_bundle(&request).await {
        Ok(response) => response.into_inner().data,
        Err(e) => {
            return Err(anyhow_from_seren_error("Failed to register deployment bundle", e).await);
        }
    };

    if registration.upload_required {
        let upload_url = registration.upload_url.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Deployment bundle registration did not return an upload_url.")
        })?;
        put_presigned_deployment_bundle(upload_url, &registration.upload_headers, bundle).await?;
        if let Err(e) = client
            .seren_cloud_complete_deployment_bundle_upload(&registration.deployment_bundle_id)
            .await
        {
            return Err(
                anyhow_from_seren_error("Failed to complete deployment bundle upload", e).await,
            );
        }
    }

    Ok(registration.deployment_bundle_id)
}

async fn submit_cloud_deploy_request(
    deploy_publisher: &str,
    body: serde_json::Map<String, serde_json::Value>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let result = match deploy_publisher {
        SEREN_CLOUD_SLUG => {
            let reshaped = reshape_body_for_sdk(body, true)?;
            let request: seren::CreateCloudDeploymentRequest =
                serde_json::from_value(serde_json::Value::Object(reshaped))
                    .map_err(|e| anyhow::anyhow!("Failed to build cloud deploy request: {}", e))?;
            match client.seren_cloud_deploy(&request).await {
                Ok(response) => response.into_inner(),
                Err(e) => return Err(anyhow_from_seren_error("Deploy failed", e).await),
            }
        }
        SEREN_AGENT_SLUG => {
            let reshaped = reshape_body_for_sdk(body, false)?;
            let request: seren::AgentSpec =
                serde_json::from_value(serde_json::Value::Object(reshaped)).map_err(|e| {
                    anyhow::anyhow!("Failed to build managed deploy request: {}", e)
                })?;
            match client.seren_agent_deploy(&request).await {
                Ok(response) => response.into_inner(),
                Err(e) => return Err(anyhow_from_seren_error("Deploy failed", e).await),
            }
        }
        other => {
            return Err(anyhow::anyhow!("Unsupported deploy publisher '{}'.", other));
        }
    };
    let result = serde_json::to_value(&result)?;
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
        if let Some(eval_gate_set_id) = data.get("eval_gate_set_id").and_then(|v| v.as_str()) {
            println!("  Eval Gate Set: {}", eval_gate_set_id);
        }
        if let Some(eval_gate_max_age_seconds) = data
            .get("eval_gate_max_age_seconds")
            .and_then(|v| v.as_i64())
        {
            println!("  Eval Gate Window: {}s", eval_gate_max_age_seconds);
        }
        if let Some(eval_gate_status) = data.get("eval_gate_status")
            && let Some(state) = eval_gate_status.get("state").and_then(|v| v.as_str())
        {
            println!("  Eval Gate Status: {}", state);
        }
        if let Some(managed_agent) = data.get("managed_agent") {
            let tool_presets = json_string_list(managed_agent, "tool_presets");
            let allowed_publisher_operations =
                json_string_list(managed_agent, "allowed_publisher_operations");
            let allowed_remote_agent_origins =
                json_string_list(managed_agent, "allowed_remote_agent_origins");
            let resolved_tools = json_string_list(managed_agent, "resolved_tools");
            if let Some(target_framework) = managed_agent
                .get("target_framework")
                .and_then(|v| v.as_str())
            {
                println!("  Managed Runtime: {}", target_framework);
            }
            if let Some(template) = managed_agent.get("template").and_then(|v| v.as_str()) {
                println!("  Template: {}", template);
            }
            if !tool_presets.is_empty() {
                println!("  Tool Presets: {}", tool_presets.join(", "));
            }
            if let Some(approval_policy) = managed_agent
                .get("approval_policy")
                .and_then(|v| v.as_str())
            {
                println!("  Approval Policy: {}", approval_policy);
            }
            if !allowed_publisher_operations.is_empty() {
                println!(
                    "  Publisher Ops: {}",
                    allowed_publisher_operations.join(", ")
                );
            }
            if let Some(model_policy) = managed_agent.get("model_policy").and_then(|v| v.as_str()) {
                println!("  Model Policy: {}", model_policy);
            }
            if !allowed_remote_agent_origins.is_empty() {
                println!(
                    "  Remote Agent Origins: {}",
                    allowed_remote_agent_origins.join(", ")
                );
            }
            if !resolved_tools.is_empty() {
                println!("  Resolved Tools: {}", resolved_tools.join(", "));
            }
            let capabilities = managed_capability_summary(
                &tool_presets,
                managed_agent
                    .get("approval_policy")
                    .and_then(|value| value.as_str()),
                &allowed_remote_agent_origins,
            );
            if !capabilities.is_empty() {
                println!("  Capabilities: {}", capabilities.join("; "));
            }
            if let Some(routing_reason) =
                managed_agent.get("routing_reason").and_then(|v| v.as_str())
            {
                println!("  Routing: {}", routing_reason);
            }
            println!("  Next: seren agent managed-get {}", id);
            println!(
                "  Run:  seren agent cloud-run --deployment-id {} --message \"...\"",
                id
            );
        }
    } else {
        output::print_json(&result)?;
    }

    Ok(())
}

fn json_string_list(value: &serde_json::Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|items| items.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn managed_capability_summary(
    tool_presets: &[String],
    approval_policy: Option<&str>,
    allowed_remote_agent_origins: &[String],
) -> Vec<String> {
    let mut capabilities = vec!["Live data via Seren publishers".to_string()];

    if tool_presets
        .iter()
        .any(|preset| preset == "publisher_actions")
    {
        capabilities.push("Write-capable publisher actions".to_string());
    }
    if tool_presets.iter().any(|preset| preset == "database") {
        capabilities.push("Direct SerenDB queries".to_string());
    }
    match approval_policy {
        Some("allow_mutations") => {
            capabilities.push("Mutating publisher and MCP actions allowed".to_string())
        }
        Some("read_only") => {
            capabilities.push("Mutating publisher and MCP actions blocked".to_string())
        }
        _ => {}
    }
    if !allowed_remote_agent_origins.is_empty() {
        capabilities.push(format!(
            "Remote A2A delegation to {} origin{}",
            allowed_remote_agent_origins.len(),
            if allowed_remote_agent_origins.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
    }

    capabilities
}

fn format_optional_string(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            value.trim().to_string()
        }
        Some(serde_json::Value::Array(items)) if !items.is_empty() => items
            .iter()
            .filter_map(|item| item.as_str())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
            .join(", "),
        Some(serde_json::Value::Null) | None => "—".to_string(),
        Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "—".to_string()),
    }
}

fn format_eval_gate_brief(detail: &serde_json::Value) -> String {
    let Some(eval_gate_set_id) = detail.get("eval_gate_set_id").and_then(|v| v.as_str()) else {
        return "—".to_string();
    };
    let short_id = eval_gate_set_id
        .split('-')
        .next()
        .unwrap_or(eval_gate_set_id);
    let max_age = detail
        .get("eval_gate_max_age_seconds")
        .and_then(|v| v.as_i64())
        .map(|value| format!("{value}s"))
        .unwrap_or_else(|| "?".to_string());
    let state = detail
        .get("eval_gate_status")
        .and_then(|status| status.get("state"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    format!("{short_id} / {max_age} / {state}")
}

fn print_cloud_deployment_detail_table(payload: &serde_json::Value) {
    let detail = payload.get("data").unwrap_or(payload);
    output::print_key_value_table(
        Some("Deployment"),
        &[
            ("Deployment ID", format_optional_string(detail.get("id"))),
            ("Name", format_optional_string(detail.get("name"))),
            (
                "Skill Slug",
                format_optional_string(detail.get("skill_slug")),
            ),
            ("Mode", format_optional_string(detail.get("mode"))),
            ("Status", format_optional_string(detail.get("status"))),
            (
                "Backend",
                format_optional_string(detail.get("compute_backend")),
            ),
            (
                "Runtime",
                format_optional_string(detail.get("runtime_kind")),
            ),
            (
                "Deployment Bundle ID",
                format_optional_string(detail.get("deployment_bundle_id")),
            ),
            (
                "Cron Schedule",
                format_optional_string(detail.get("cron_schedule")),
            ),
            (
                "Cron Timezone",
                format_optional_string(detail.get("cron_timezone")),
            ),
            (
                "Eval Gate Set",
                format_optional_string(detail.get("eval_gate_set_id")),
            ),
            (
                "Eval Gate Max Age",
                detail
                    .get("eval_gate_max_age_seconds")
                    .and_then(|v| v.as_i64())
                    .map(|value| format!("{value}s"))
                    .unwrap_or_else(|| "—".to_string()),
            ),
            (
                "Eval Gate Status",
                detail
                    .get("eval_gate_status")
                    .and_then(|status| status.get("state"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "—".to_string()),
            ),
            (
                "Eval Gate Message",
                detail
                    .get("eval_gate_status")
                    .and_then(|status| status.get("message"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "—".to_string()),
            ),
            (
                "Endpoint URL",
                format_optional_string(detail.get("endpoint_url")),
            ),
        ],
    );
}

fn print_cloud_deployment_list_table(deployments: &[serde_json::Value]) {
    if deployments.is_empty() {
        println!("No deployments found.");
        return;
    }
    println!(
        "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10} {:<24}",
        "ID", "SKILL", "BACKEND", "RUNTIME", "MODE", "STATUS", "EVAL GATE"
    );
    for d_json in deployments {
        println!(
            "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10} {:<24}",
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
            format_eval_gate_brief(d_json),
        );
    }
}

fn print_managed_agent_health_table(title: &str, payload: &serde_json::Value) {
    let data = payload.get("data").unwrap_or(payload);
    let summary = data.get("summary").unwrap_or(&serde_json::Value::Null);
    let mut rows = vec![
        ("Status", json_string_field(data, "status")),
        (
            "Deployments",
            json_number_field(summary, "deployment_count"),
        ),
        (
            "Running",
            json_number_field(summary, "running_deployment_count"),
        ),
        (
            "Failed",
            json_number_field(summary, "failed_deployment_count"),
        ),
        (
            "Stopped",
            json_number_field(summary, "stopped_deployment_count"),
        ),
        (
            "Critical Findings",
            json_number_field(summary, "critical_count"),
        ),
        ("Warnings", json_number_field(summary, "warning_count")),
    ];
    if let Some(storage) = data.get("storage") {
        rows.extend([
            ("Storage Configured", json_bool_field(storage, "configured")),
            ("Storage Available", json_bool_field(storage, "available")),
            (
                "Storage Buckets",
                json_number_field(storage, "bucket_count"),
            ),
            (
                "Pending Uploads",
                json_number_field(storage, "pending_upload_count"),
            ),
            (
                "Delete Backlog",
                json_number_field(storage, "delete_failed_count"),
            ),
        ]);
    }
    if let Some(deployment) = data.get("deployment") {
        rows.push((
            "Deployment ID",
            json_string_field(deployment, "deployment_id"),
        ));
        rows.push(("Name", json_string_field(deployment, "name")));
        rows.push(("Agent Slug", json_string_field(deployment, "agent_slug")));
        rows.push(("Deployment Status", json_string_field(deployment, "status")));
    }
    output::print_key_value_table(Some(title), &rows);

    let findings = data
        .get("findings")
        .and_then(|value| value.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if findings.is_empty() {
        println!();
        println!("No health findings.");
        return;
    }

    println!();
    println!("Findings:");
    for finding in findings {
        let severity = finding
            .get("severity")
            .and_then(|value| value.as_str())
            .unwrap_or("info");
        let title = finding
            .get("title")
            .and_then(|value| value.as_str())
            .unwrap_or("Finding");
        let detail = finding
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        println!("- [{severity}] {title}: {detail}");
    }
}

fn print_managed_agent_resources_table(payload: &serde_json::Value) {
    let data = payload.get("data").unwrap_or(payload);
    let deployment = data.get("deployment").unwrap_or(&serde_json::Value::Null);
    let runtime = data.get("runtime").unwrap_or(&serde_json::Value::Null);
    let storage = data.get("storage").unwrap_or(&serde_json::Value::Null);
    let schedule = data.get("schedule").unwrap_or(&serde_json::Value::Null);
    let tools = data.get("tools").unwrap_or(&serde_json::Value::Null);
    let memory = data.get("memory").unwrap_or(&serde_json::Value::Null);
    let capabilities = data.get("capabilities").unwrap_or(&serde_json::Value::Null);
    let connectors = data
        .get("connectors")
        .and_then(|value| value.as_array())
        .map_or(0, Vec::len);
    let rows = vec![
        ("Deployment ID", json_string_field(data, "deployment_id")),
        ("Name", json_string_field(deployment, "name")),
        ("Agent Slug", json_string_field(deployment, "agent_slug")),
        ("Status", json_string_field(deployment, "status")),
        ("Mode", json_string_field(deployment, "mode")),
        (
            "Cron Schedule",
            json_string_field(schedule, "cron_schedule"),
        ),
        (
            "Cron Timezone",
            json_string_field(schedule, "cron_timezone"),
        ),
        ("Runtime", json_string_field(runtime, "runtime_kind")),
        ("Compute", json_string_field(runtime, "compute_backend")),
        ("Model", json_string_field(runtime, "model_id")),
        ("Storage Configured", json_bool_field(storage, "configured")),
        ("Storage Available", json_bool_field(storage, "available")),
        (
            "Storage Buckets",
            json_number_field(storage, "bucket_count"),
        ),
        ("Connectors", connectors.to_string()),
        ("Tool Presets", json_array_join_field(tools, "tool_presets")),
        (
            "Resolved Tools",
            json_array_len_field(tools, "resolved_tools"),
        ),
        (
            "Publisher Ops",
            json_array_len_field(tools, "allowed_publisher_operations"),
        ),
        (
            "Remote Origins",
            json_array_len_field(tools, "allowed_remote_agent_origins"),
        ),
        ("Tool Refs", json_number_field(tools, "tool_ref_count")),
        ("Credentials", json_number_field(tools, "credential_count")),
        ("Guardrails", json_number_field(tools, "guardrail_count")),
        (
            "Memory Policy",
            json_bool_field(memory, "policy_configured"),
        ),
        (
            "Semantic Memory",
            json_bool_field(memory, "semantic_memory_enabled"),
        ),
        ("Browser", json_bool_field(capabilities, "browser_enabled")),
        (
            "Code Execution",
            json_bool_field(capabilities, "code_execution_enabled"),
        ),
    ];
    output::print_key_value_table(Some("Managed Deployment Resources"), &rows);
}

fn print_managed_agent_tools_table(payload: &serde_json::Value) {
    let data = payload.get("data").unwrap_or(payload);
    let rows = vec![
        ("Deployment ID", json_string_field(data, "deployment_id")),
        ("Tool Presets", json_array_join_field(data, "tool_presets")),
        (
            "Approval Policy",
            json_string_field(data, "approval_policy"),
        ),
        (
            "Publisher Ops",
            json_array_len_field(data, "allowed_publisher_operations"),
        ),
        ("Tools", json_array_len_field(data, "tools")),
    ];
    output::print_key_value_table(Some("Managed Deployment Tools"), &rows);

    let tool_rows = data
        .get("tools")
        .and_then(|value| value.as_array())
        .map(|tools| {
            tools
                .iter()
                .map(format_managed_agent_tool)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    output::print_list_table(Some("Tools"), "Tool", &tool_rows);
}

fn print_managed_agent_tool_detail_table(payload: &serde_json::Value) {
    let tool = payload.get("data").unwrap_or(payload);
    let rows = vec![
        ("Name", json_string_field(tool, "name")),
        ("Source", json_string_field(tool, "source")),
        ("Preset", json_string_field(tool, "preset")),
        ("Description", json_string_field(tool, "description")),
        ("Side Effecting", json_bool_field(tool, "side_effecting")),
        (
            "Checkpoint Required",
            json_bool_field(tool, "checkpoint_required"),
        ),
        ("Approval", json_string_field(tool, "approval_type")),
        ("Effective Policy", json_effective_tool_policy_label(tool)),
        (
            "Approval Rules",
            json_number_field(tool, "approval_rule_count"),
        ),
        ("Data Labels", json_array_join_field(tool, "data_labels")),
        (
            "Input Schema",
            if tool
                .get("input_schema")
                .is_some_and(|value| !value.is_null())
            {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        ),
    ];
    output::print_key_value_table(Some("Managed Deployment Tool"), &rows);
}

fn print_managed_agent_tool_groups_table(payload: &serde_json::Value) {
    let data = payload.get("data").unwrap_or(payload);
    let rows = vec![
        ("Deployment ID", json_string_field(data, "deployment_id")),
        ("Implicit", json_bool_field(data, "implicit")),
        ("Groups", json_array_len_field(data, "tool_groups")),
    ];
    output::print_key_value_table(Some("Managed Deployment Tool Groups"), &rows);

    let group_rows = data
        .get("tool_groups")
        .and_then(|value| value.as_array())
        .map(|groups| {
            groups
                .iter()
                .map(format_managed_agent_tool_group)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    output::print_list_table(Some("Tool Groups"), "Group", &group_rows);
}

fn format_managed_agent_tool(tool: &serde_json::Value) -> String {
    let name = json_string_field(tool, "name");
    let source = json_string_field(tool, "source");
    let policy = json_effective_tool_policy_label(tool);
    let mode = if tool
        .get("side_effecting")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        "action"
    } else {
        "read"
    };
    let labels = json_array_join_field(tool, "data_labels");
    let label_suffix = if labels == "-" {
        String::new()
    } else {
        format!(" labels={labels}")
    };
    format!("{name} [{source}] mode={mode} policy={policy}{label_suffix}")
}

fn format_managed_agent_tool_group(group: &serde_json::Value) -> String {
    let label = json_string_field(group, "label");
    let id = json_string_field(group, "id");
    let tool_count = json_number_field(group, "tool_count");
    let policy = json_effective_tool_policy_label(group);
    let mode = if group
        .get("side_effecting")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        "action"
    } else {
        "read"
    };
    let tools = json_array_join_field(group, "tool_names");
    let tool_suffix = if tools == "-" {
        format!("{tool_count} tools")
    } else {
        tools
    };
    format!("{label} ({id}) mode={mode} policy={policy} tools={tool_suffix}")
}

fn json_effective_tool_policy_label(value: &serde_json::Value) -> String {
    let policy = value
        .get("effective_policy")
        .unwrap_or(&serde_json::Value::Null);
    let status = policy.get("status").and_then(|value| value.as_str());
    let conditional = policy
        .get("conditional_status")
        .and_then(|value| value.as_str());
    match (status, conditional) {
        (Some("blocked"), _) => "blocked".to_string(),
        (Some("requires_approval"), _) => "approval required".to_string(),
        (Some("audited"), Some("requires_approval")) => {
            "audited + conditional approval".to_string()
        }
        (Some("audited"), _) => "audited".to_string(),
        (_, Some("requires_approval")) => "conditional approval".to_string(),
        (_, Some("audited")) => "conditional audit".to_string(),
        (Some("allowed"), _) => "allowed".to_string(),
        _ => json_string_field(value, "approval_type"),
    }
}

fn print_managed_agent_activity_table(payload: &serde_json::Value) {
    let data = payload.get("data").unwrap_or(payload);
    let deployment = data.get("deployment").unwrap_or(&serde_json::Value::Null);
    let summary = data.get("summary").unwrap_or(&serde_json::Value::Null);
    let rows = vec![
        ("Deployment ID", json_string_field(data, "deployment_id")),
        ("Name", json_string_field(deployment, "name")),
        ("Agent Slug", json_string_field(deployment, "agent_slug")),
        ("Status", json_string_field(deployment, "status")),
        ("Mode", json_string_field(deployment, "mode")),
        ("Total Runs", json_number_field(summary, "total_run_count")),
        (
            "Completed",
            json_number_field(summary, "completed_run_count"),
        ),
        ("Failed", json_number_field(summary, "failed_run_count")),
        ("Running", json_number_field(summary, "running_run_count")),
        (
            "Awaiting Approval",
            json_number_field(summary, "awaiting_approval_run_count"),
        ),
        (
            "Cancelled",
            json_number_field(summary, "cancelled_run_count"),
        ),
        ("Blocked", json_number_field(summary, "blocked_run_count")),
        ("Artifacts", json_number_field(summary, "artifact_count")),
        (
            "Input Tokens",
            json_number_field(summary, "inference_input_tokens"),
        ),
        (
            "Output Tokens",
            json_number_field(summary, "inference_output_tokens"),
        ),
        (
            "Compute Cost USD",
            json_scalar_field(summary, "compute_cost_usd"),
        ),
        (
            "Inference Cost USD",
            json_scalar_field(summary, "inference_cost_usd"),
        ),
        ("Last Run", json_string_field(summary, "last_run_at")),
    ];
    output::print_key_value_table(Some("Managed Deployment Activity"), &rows);

    let recent_runs = data
        .get("runs")
        .and_then(|value| value.as_array())
        .map(|runs| {
            runs.iter()
                .take(10)
                .map(format_managed_agent_activity_run)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    output::print_list_table(Some("Recent Runs (first 10)"), "Run", &recent_runs);
}

fn format_managed_agent_activity_run(run: &serde_json::Value) -> String {
    let started = json_string_field(run, "started_at");
    let status = json_string_field(run, "status");
    let source = json_string_field(run, "source");
    let run_id = json_string_field(run, "run_id");
    let artifacts = json_number_field(run, "artifact_count");
    let input_tokens = json_number_field(run, "inference_input_tokens");
    let output_tokens = json_number_field(run, "inference_output_tokens");
    format!(
        "{started} {status} source={source} run={run_id} artifacts={artifacts} tokens={input_tokens}/{output_tokens}"
    )
}

fn json_string_field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| "-".to_string())
}

fn json_number_field(value: &serde_json::Value, key: &str) -> String {
    let Some(value) = value.get(key) else {
        return "-".to_string();
    };
    if let Some(number) = value.as_i64() {
        return number.to_string();
    }
    if let Some(number) = value.as_u64() {
        return number.to_string();
    }
    "-".to_string()
}

fn json_scalar_field(value: &serde_json::Value, key: &str) -> String {
    let Some(value) = value.get(key) else {
        return "-".to_string();
    };
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        _ => "-".to_string(),
    }
}

fn json_bool_field(value: &serde_json::Value, key: &str) -> String {
    match value.get(key).and_then(|value| value.as_bool()) {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => "-".to_string(),
    }
}

fn json_array_len_field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|value| value.as_array())
        .map(|items| items.len().to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn json_array_join_field(value: &serde_json::Value, key: &str) -> String {
    let Some(items) = value.get(key).and_then(|value| value.as_array()) else {
        return "-".to_string();
    };
    if items.is_empty() {
        return "-".to_string();
    }
    items
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_managed_agent_detail_table(payload: &serde_json::Value) {
    let detail = payload.get("data").unwrap_or(payload);
    let tool_presets = json_string_list(detail, "tool_presets");
    let publisher_ops = json_string_list(detail, "allowed_publisher_operations");
    let remote_agent_origins = json_string_list(detail, "allowed_remote_agent_origins");
    let resolved_tools = json_string_list(detail, "resolved_tools");
    let fallback_models = json_string_list(detail, "fallback_models");
    let secret_keys = json_string_list(detail, "secret_keys");
    let capabilities = managed_capability_summary(
        &tool_presets,
        detail
            .get("approval_policy")
            .and_then(|value| value.as_str()),
        &remote_agent_origins,
    );

    let rows = vec![
        (
            "Deployment ID",
            format_optional_string(detail.get("deployment_id")),
        ),
        ("Name", format_optional_string(detail.get("name"))),
        (
            "Agent Slug",
            format_optional_string(detail.get("agent_slug")),
        ),
        (
            "Cron Schedule",
            format_optional_string(detail.get("cron_schedule")),
        ),
        (
            "Cron Timezone",
            format_optional_string(detail.get("cron_timezone")),
        ),
        (
            "Eval Gate Set",
            format_optional_string(detail.get("eval_gate_set_id")),
        ),
        (
            "Eval Gate Window",
            match detail
                .get("eval_gate_max_age_seconds")
                .and_then(|value| value.as_i64())
            {
                Some(value) => format!("{}s", value),
                None => "—".to_string(),
            },
        ),
        ("Mode", format_optional_string(detail.get("mode"))),
        ("Status", format_optional_string(detail.get("status"))),
        (
            "Backend",
            format_optional_string(detail.get("compute_backend")),
        ),
        (
            "Runtime",
            format_optional_string(detail.get("runtime_kind")),
        ),
        ("Template", format_optional_string(detail.get("template"))),
        (
            "Approval Policy",
            format_optional_string(detail.get("approval_policy")),
        ),
        (
            "Model Policy",
            format_optional_string(detail.get("model_policy")),
        ),
        (
            "Tool Presets",
            if tool_presets.is_empty() {
                "—".to_string()
            } else {
                tool_presets.join(", ")
            },
        ),
        (
            "Publisher Ops",
            if publisher_ops.is_empty() {
                "—".to_string()
            } else {
                publisher_ops.join(", ")
            },
        ),
        (
            "Remote Agent Origins",
            if remote_agent_origins.is_empty() {
                "—".to_string()
            } else {
                remote_agent_origins.join(", ")
            },
        ),
        (
            "Resolved Tools",
            if resolved_tools.is_empty() {
                "—".to_string()
            } else {
                resolved_tools.join(", ")
            },
        ),
        (
            "Fallback Models",
            if fallback_models.is_empty() {
                "—".to_string()
            } else {
                fallback_models.join(", ")
            },
        ),
        (
            "Secret Keys",
            if secret_keys.is_empty() {
                "—".to_string()
            } else {
                secret_keys.join(", ")
            },
        ),
        (
            "Capabilities",
            if capabilities.is_empty() {
                "—".to_string()
            } else {
                capabilities.join("; ")
            },
        ),
        (
            "Visibility",
            format_optional_string(detail.get("visibility")),
        ),
        (
            "Routing Reason",
            format_optional_string(detail.get("routing_reason")),
        ),
    ];

    output::print_key_value_table(Some("Managed Deployment"), &rows);
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
        cron_timezone,
        eval_gate_set_id,
        eval_gate_max_age_seconds,
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
    let deployment_bundle = bundle_directory(&scripts_dir)?;

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

    let client = ctx.client().await?;
    let deployment_bundle_id = ensure_cloud_deployment_bundle(&client, deployment_bundle).await?;

    let mut body = serde_json::Map::new();
    body.insert("name".to_string(), serde_json::json!(deploy_name));
    body.insert("skill_slug".to_string(), serde_json::json!(skill_slug));
    body.insert("mode".to_string(), serde_json::json!(api_mode));
    body.insert(
        "deployment_bundle_id".to_string(),
        serde_json::json!(deployment_bundle_id),
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
    if let Some(timezone) = cron_timezone {
        body.insert("cron_timezone".to_string(), serde_json::json!(timezone));
    }
    if let Some(eval_gate_set_id) = eval_gate_set_id {
        body.insert(
            "eval_gate_set_id".to_string(),
            serde_json::json!(eval_gate_set_id),
        );
    }
    if let Some(eval_gate_max_age_seconds) = eval_gate_max_age_seconds {
        body.insert(
            "eval_gate_max_age_seconds".to_string(),
            serde_json::json!(eval_gate_max_age_seconds),
        );
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
        cron_timezone,
        eval_gate_set_id,
        eval_gate_max_age_seconds,
        compute_backend,
        template,
        tool_presets,
        approval_policy,
        model_policy,
        allowed_remote_agent_origins,
        config_path,
        env_path,
        agent_config_path,
        capability_policy_json,
        capability_policy_path,
        prompt,
        model_id,
        visibility,
    } = options;
    let deploy_publisher = SEREN_AGENT_SLUG;
    let runtime_target = resolve_cloud_runtime_target(compute_backend, None)?;
    let agent_config = load_orchestration_config(None, agent_config_path)?;
    let capability_policy = load_managed_agent_json_override(
        capability_policy_json,
        capability_policy_path,
        "capability-policy",
    )?;

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
    if !allowed_remote_agent_origins.is_empty() {
        body.insert(
            "allowed_remote_agent_origins".to_string(),
            serde_json::json!(allowed_remote_agent_origins),
        );
    }
    if let Some(schedule) = cron_schedule {
        body.insert("cron_schedule".to_string(), serde_json::json!(schedule));
    }
    if let Some(timezone) = cron_timezone {
        body.insert("cron_timezone".to_string(), serde_json::json!(timezone));
    }
    if let Some(eval_gate_set_id) = eval_gate_set_id {
        body.insert(
            "eval_gate_set_id".to_string(),
            serde_json::json!(eval_gate_set_id),
        );
    }
    if let Some(eval_gate_max_age_seconds) = eval_gate_max_age_seconds {
        body.insert(
            "eval_gate_max_age_seconds".to_string(),
            serde_json::json!(eval_gate_max_age_seconds),
        );
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
    if let Some(capability_policy) = capability_policy {
        body.insert("capability_policy".to_string(), capability_policy);
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
    body.entry("memory_policy".to_string())
        .or_insert_with(default_employee_memory_policy_value);
    body.entry("capability_policy".to_string())
        .or_insert_with(default_employee_capability_policy_value);

    if !body.contains_key("prompt") {
        return Err(anyhow::anyhow!(
            "Managed agent deployments require --prompt or an agent config containing prompt."
        ));
    }
    submit_cloud_deploy_request(deploy_publisher, body, ctx).await
}

/// Inspect seren-agent publisher capabilities.
pub async fn managed_agent_capabilities(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_agent_capabilities()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get seren-agent capabilities: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let data = &response.data;
            let rows = [
                ("Publisher", data.publisher.clone()),
                ("Runtime Provider", data.runtime_provider.clone()),
                ("Runtime API", data.deployment_runtime_api.clone()),
                (
                    "Orchestration Plane",
                    if data.orchestration_plane {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_string(),
                ),
                (
                    "Direct Skill Deploy",
                    if data.supports_direct_skill_deploy {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_string(),
                ),
                (
                    "Orchestrated Deploy",
                    if data.supports_orchestrated_deploy {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_string(),
                ),
                ("Deployment Targets", data.deployment_targets.join(", ")),
            ];
            output::print_key_value_table(Some("Seren Agent Capabilities"), &rows);
        }
    }

    Ok(())
}

/// List deployments through the seren-agent publisher.
pub async fn managed_agent_list(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_agent_list_deployments()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list seren-agent deployments: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&response)?;
            let deployments = value
                .get("data")
                .and_then(|data| data.as_array())
                .cloned()
                .unwrap_or_default();
            print_cloud_deployment_list_table(&deployments);
        }
    }

    Ok(())
}

/// Get health for managed seren-agent deployments.
pub async fn managed_agent_health(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client.seren_agent_health().await {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error("Failed to get managed agent health", err).await);
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_health_table("Managed Agent Health", &value);
        }
    }
    Ok(())
}

/// Run an unsaved managed seren-agent draft once.
pub async fn managed_agent_test_run(body: &str, ctx: &CommandContext) -> Result<()> {
    let request: seren::TestSerenAgentDraftRunRequest =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("Invalid draft JSON: {}", e))?;

    let client = ctx.client().await?;
    let response = client
        .seren_agent_test_run(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run seren-agent draft: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let data = &response.data;
            let rows = [
                ("Status", data.status.to_string()),
                ("Runtime Adapter", data.runtime_adapter.clone()),
                ("Iterations", data.iterations.to_string()),
                ("Tool Calls", data.tool_calls.len().to_string()),
                ("Warnings", data.warnings.len().to_string()),
            ];
            output::print_key_value_table(Some("Seren Agent Draft Run"), &rows);
            if let Some(response) = &data.response {
                println!();
                println!("{}", response);
            } else if let Some(partial) = &data.partial_response {
                println!();
                println!("{}", partial);
            }
            if let Some(error) = &data.error {
                println!();
                println!("Error: {error}");
            }
        }
    }

    Ok(())
}

/// Get health for a managed seren-agent deployment.
pub async fn managed_agent_deployment_health(
    deployment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_get_deployment_health(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to get managed deployment health", err).await,
            );
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_health_table("Managed Deployment Health", &value);
        }
    }
    Ok(())
}

/// Get a managed-agent resource summary for a deployment.
pub async fn managed_agent_deployment_resources(
    deployment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_get_deployment_resources(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to get managed deployment resources", err).await,
            );
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_resources_table(&value);
        }
    }
    Ok(())
}

/// List tools visible to a managed seren-agent deployment.
pub async fn managed_agent_deployment_tools(
    deployment_id: Uuid,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_list_deployment_tools(&deployment_id, q)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to list managed deployment tools", err).await,
            );
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_tools_table(&value);
        }
    }
    Ok(())
}

/// Describe one tool visible to a managed seren-agent deployment.
pub async fn managed_agent_deployment_tool(
    deployment_id: Uuid,
    tool_name: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_describe_deployment_tool(&deployment_id, tool_name)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to describe managed deployment tool", err).await,
            );
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_tool_detail_table(&value);
        }
    }
    Ok(())
}

/// List resolved tool groups for a managed seren-agent deployment.
pub async fn managed_agent_deployment_tool_groups(
    deployment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_list_deployment_tool_groups(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to list managed deployment tool groups",
                err,
            )
            .await);
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_tool_groups_table(&value);
        }
    }
    Ok(())
}

/// Get recent managed-agent activity for a deployment.
pub async fn managed_agent_deployment_activity(
    deployment_id: Uuid,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_get_deployment_activity(&deployment_id, limit, offset)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to get managed deployment activity", err).await,
            );
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_activity_table(&value);
        }
    }
    Ok(())
}

/// Get the resolved managed seren-agent deployment detail.
pub async fn managed_agent_get(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_get_managed_deployment(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error("Failed to get managed agent detail", err).await);
        }
    };
    let payload = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&payload)?;
            print_managed_agent_detail_table(&value);
        }
    }
    Ok(())
}

async fn managed_agent_deployment_summary(
    client: &seren::Client,
    deployment_id: Uuid,
) -> Result<seren::CloudDeploymentSummary> {
    client
        .seren_agent_list_deployments()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list managed agent deployments: {error}"))?
        .into_inner()
        .data
        .into_iter()
        .find(|deployment| deployment.id == deployment_id)
        .ok_or_else(|| anyhow::anyhow!("Managed agent deployment not found: {deployment_id}"))
}

async fn managed_agent_secrets_policy_request(
    client: &seren::Client,
    setup_id: Uuid,
) -> Result<seren::DelegationPolicyRequestView> {
    let response: seren::DataResponseDelegationPolicyRequest =
        crate::commands::passwords::passwords_gateway_data(
            client.delegation_get(&setup_id).await,
            "Failed to load managed agent Seren Passwords setup",
        )?;
    Ok(response.data)
}

fn managed_agent_secrets_status_json(
    request: &seren::DelegationPolicyRequestView,
) -> serde_json::Value {
    let next_step = match request.status {
        seren::DelegationPolicyRequestStatus::Pending
        | seren::DelegationPolicyRequestStatus::PartiallyApproved => {
            "Complete the approval in Seren Passwords, then check this setup again."
        }
        seren::DelegationPolicyRequestStatus::Approved => {
            "Run `seren agent managed-passwords-apply <setup-id>`."
        }
        seren::DelegationPolicyRequestStatus::Applied => {
            "The approved Seren Passwords binding has been applied."
        }
        seren::DelegationPolicyRequestStatus::Declined
        | seren::DelegationPolicyRequestStatus::Expired
        | seren::DelegationPolicyRequestStatus::Cancelled
        | seren::DelegationPolicyRequestStatus::Superseded
        | seren::DelegationPolicyRequestStatus::Conflicted => {
            "Start a new managed agent Seren Passwords setup if access is still required."
        }
    };
    serde_json::json!({
        "status": request.status,
        "setup_id": request.request_id,
        "deployment_id": request.deployment_id,
        "deployment_revision_id": request.deployment_revision_id,
        "result_id": request.result_id,
        "expires_at": request.expires_at,
        "grant_expires_at": request.grant_expires_at,
        "requested_field_count": request.requested_fields.len(),
        "approved_mapping_count": request.effective_mapping.len(),
        "next_step": next_step,
    })
}

pub async fn managed_agent_secrets_setup(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    ctx.require_user_session("Managed agent Seren Passwords setup")
        .await?;
    let client = ctx.client().await?;
    let deployment = managed_agent_deployment_summary(&client, deployment_id).await?;
    if deployment.managed_agent.is_none() {
        anyhow::bail!("Seren Passwords setup is only available for managed agent deployments");
    }
    let setup = match client
        .managed_agent_secrets_setup_initiate(
            &deployment.organization_id,
            &seren::InitiateManagedAgentSecretsSetupRequest {
                deployment_id,
                redirect_origin: seren::MANAGED_AGENT_SECRETS_REDIRECT_ORIGIN.to_string(),
            },
        )
        .await
    {
        Ok(response) => response.into_inner().data,
        Err(error) => {
            return Err(anyhow_from_seren_error(
                "Failed to start managed agent Seren Passwords setup",
                error,
            )
            .await);
        }
    };
    let payload = serde_json::json!({
        "status": "pending",
        "setup_id": setup.setup_id,
        "deployment_id": deployment_id,
        "launch_url": setup.launch_url,
        "expires_at": setup.expires_at,
        "requested_fields": setup.requirements.requested_fields,
    });
    match ctx.format {
        OutputFormat::Json => output::print_json(&payload)?,
        OutputFormat::Table => {
            println!("Setup ID: {}", setup.setup_id);
            println!("Expires: {}", setup.expires_at);
            println!(
                "Requested fields: {}",
                setup.requirements.requested_fields.len()
            );
            println!("Open this URL to approve the exact Passwords field mapping:");
            println!("{}", setup.launch_url);
            println!("Keep this short-lived bearer URL private.");
            println!();
            println!(
                "After approval, run `seren agent managed-passwords-status {}` and then `seren agent managed-passwords-apply {}`.",
                setup.setup_id, setup.setup_id
            );
        }
    }
    Ok(())
}

pub async fn managed_agent_secrets_status(setup_id: Uuid, ctx: &CommandContext) -> Result<()> {
    ctx.require_user_session("Managed agent Seren Passwords setup status")
        .await?;
    let client = ctx.client().await?;
    let request = managed_agent_secrets_policy_request(&client, setup_id).await?;
    output::print_json(&managed_agent_secrets_status_json(&request))?;
    Ok(())
}

pub async fn managed_agent_secrets_apply(setup_id: Uuid, ctx: &CommandContext) -> Result<()> {
    ctx.require_user_session("Managed agent Seren Passwords setup apply")
        .await?;
    let client = ctx.client().await?;
    let request = managed_agent_secrets_policy_request(&client, setup_id).await?;
    let deployment_id = request.deployment_id.ok_or_else(|| {
        anyhow::anyhow!("Seren Passwords setup is not bound to a managed agent deployment")
    })?;
    let deployment = managed_agent_deployment_summary(&client, deployment_id).await?;
    let detail = client
        .seren_agent_get_managed_deployment(&deployment_id)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to load managed agent detail: {error}"))?
        .into_inner()
        .data;
    match seren::managed_agent_secrets_application(deployment.organization_id, &detail, &request)? {
        seren::ManagedAgentSecretsApplication::AlreadyApplied => {
            output::print_json(&serde_json::json!({
                "status": "applied",
                "setup_id": setup_id,
                "deployment_id": deployment_id,
                "result_id": request.result_id,
                "active_revision_id": detail.active_revision_id,
                "already_applied": true,
            }))?;
            return Ok(());
        }
        seren::ManagedAgentSecretsApplication::Update(update) => {
            match client
                .seren_agent_update_managed_deployment(&deployment_id, &update)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    return Err(anyhow_from_seren_error(
                        "Failed to apply managed agent Seren Passwords setup",
                        error,
                    )
                    .await);
                }
            }
        }
    }
    let after = client
        .seren_agent_get_managed_deployment(&deployment_id)
        .await
        .map_err(|error| {
            anyhow::anyhow!("Failed to verify managed agent Seren Passwords setup: {error}")
        })?
        .into_inner()
        .data;
    if !matches!(
        seren::managed_agent_secrets_application(deployment.organization_id, &after, &request),
        Ok(seren::ManagedAgentSecretsApplication::AlreadyApplied)
    ) {
        anyhow::bail!(
            "The managed agent update completed but the Seren Passwords binding could not be verified"
        );
    }
    output::print_json(&serde_json::json!({
        "status": "applied",
        "setup_id": setup_id,
        "deployment_id": deployment_id,
        "result_id": request.result_id,
        "active_revision_id": after.active_revision_id,
        "already_applied": false,
    }))?;
    Ok(())
}

/// List immutable revision snapshots for a managed seren-agent deployment.
pub async fn managed_agent_revisions(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_list_managed_deployment_revisions(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to list managed agent deployment revisions",
                err,
            )
            .await);
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Start a managed seren-agent deployment.
pub async fn managed_agent_start(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    match client
        .seren_agent_start_managed_deployment(&deployment_id)
        .await
    {
        Ok(response) => {
            let _ = response.into_inner();
        }
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to start managed agent deployment", err).await,
            );
        }
    }
    println!(
        "{} Managed deployment {} started.",
        "✓".green(),
        deployment_id
    );
    Ok(())
}

/// Stop a managed seren-agent deployment.
pub async fn managed_agent_stop(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    match client
        .seren_agent_stop_managed_deployment(&deployment_id)
        .await
    {
        Ok(response) => {
            let _ = response.into_inner();
        }
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to stop managed agent deployment", err).await,
            );
        }
    }
    println!(
        "{} Managed deployment {} stopped.",
        "✓".green(),
        deployment_id
    );
    Ok(())
}

/// Delete a managed seren-agent deployment.
pub async fn managed_agent_delete(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    match client
        .seren_agent_delete_managed_deployment(&deployment_id)
        .await
    {
        Ok(response) => {
            let _ = response.into_inner();
        }
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to delete managed agent deployment", err).await,
            );
        }
    }
    println!(
        "{} Managed deployment {} deleted.",
        "✓".green(),
        deployment_id
    );
    Ok(())
}

/// Workload-level keys that, when present in the patch body, force a full
/// `WorkloadSpec` replacement against the current managed deployment.
fn body_touches_workload(body: &serde_json::Map<String, serde_json::Value>) -> bool {
    body.keys().any(|key| {
        WORKLOAD_LEVEL_FIELDS.contains(&key.as_str())
            || WORKLOAD_LIMITS_FIELDS.contains(&key.as_str())
            || LLM_EXECUTION_FIELDS.contains(&key.as_str())
            || CODE_EXECUTION_FIELDS.contains(&key.as_str())
            || key == "prompt"
    })
}

/// Resolve external-database attachments for a managed-agent workload replacement.
///
/// Omitting `external_databases` preserves the deployment's current attachments;
/// an explicit list replaces them, and an explicit empty list clears them.
fn resolve_updated_external_databases(
    body: &serde_json::Map<String, serde_json::Value>,
    current: Vec<seren::ManagedExternalDatabaseAttachment>,
) -> Result<Vec<seren::ManagedExternalDatabaseAttachment>> {
    match body.get("external_databases").cloned() {
        Some(value) => serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("Invalid external_databases payload: {}", e)),
        None => Ok(current),
    }
}

fn require_explicit_replacement_secrets(
    secret_keys: &[String],
    body: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    if !secret_keys.is_empty() && !body.contains_key("secrets") {
        return Err(anyhow::anyhow!(
            "This deployment has existing secrets. Workload-level updates require a full replacement; pass --env or include `secrets` in --agent-config so the new secret bundle is explicit."
        ));
    }
    Ok(())
}

async fn build_replacement_workload_for_managed_agent(
    client: &seren::Client,
    deployment_id: &Uuid,
    body: &serde_json::Map<String, serde_json::Value>,
) -> Result<seren::WorkloadSpec> {
    let detail = match client
        .seren_agent_get_managed_deployment(deployment_id)
        .await
    {
        Ok(response) => response.into_inner().data,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to fetch managed deployment for workload replacement",
                err,
            )
            .await);
        }
    };

    require_explicit_replacement_secrets(&detail.secret_keys, body)?;

    let prompt_override = body
        .get("prompt")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let base_bundle = body
        .get("bundle")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid bundle payload: {}", e))?
        .unwrap_or(detail.bundle);
    let bundle = bundle_with_prompt_override(base_bundle, prompt_override);

    let model_id = body
        .get("model_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .unwrap_or(detail.model_id);

    let model_config = body
        .get("model_config")
        .cloned()
        .unwrap_or(detail.model_config);

    let fallback_models = body
        .get("fallback_models")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid fallback_models payload: {}", e))?
        .or(detail.fallback_models);

    let tool_definitions = body
        .get("tool_definitions")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid tool_definitions payload: {}", e))?
        .or_else(|| (!detail.tool_definitions.is_empty()).then_some(detail.tool_definitions));
    let requirements_txt = match body.get("requirements_txt") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("requirements_txt must be a string or null"))?,
        ),
        None => detail.requirements_txt,
    };

    let config = body.get("config").cloned().or(detail.config);
    let secrets = body.get("secrets").cloned();

    let requirements = match body.get("requirements").cloned() {
        Some(value) => serde_json::from_value(value)
            .map_err(|e| anyhow::anyhow!("Invalid requirements payload: {}", e))?,
        None => detail.requirements,
    };
    let external_databases = resolve_updated_external_databases(body, detail.external_databases)?;

    let max_timeout_seconds = body
        .get("max_timeout_seconds")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or(detail.max_timeout_seconds);
    let context_budget_tokens = body
        .get("context_budget_tokens")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or(detail.context_budget_tokens);
    let max_iterations = body
        .get("max_iterations")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or(detail.max_iterations);
    let max_tool_calls_per_run = body
        .get("max_tool_calls_per_run")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or(detail.max_tool_calls_per_run);
    let max_tool_output_chars = body
        .get("max_tool_output_chars")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or(detail.max_tool_output_chars);

    Ok(seren::WorkloadSpec {
        compute_backend: Some(detail.compute_backend),
        config,
        execution: seren::WorkloadExecution::Llm {
            adapter: Some(detail.runtime_adapter),
            bundle,
            fallback_models,
            llm_connection: detail.llm_connection,
            model_config: Some(model_config),
            model_id: Some(model_id),
            requirements_txt,
            tool_definitions,
        },
        external_databases,
        limits: Some(seren::WorkloadLimits {
            context_budget_tokens,
            max_iterations,
            max_timeout_seconds,
            max_tool_calls_per_run,
            max_tool_output_chars,
        }),
        network_policy: detail.network_policy,
        publisher_only: None,
        requirements: Some(requirements),
        secrets,
        side_effect_policy: detail.side_effect_policy,
    })
}

fn bundle_with_prompt_override(
    mut bundle: seren::AgentBundle,
    prompt_override: Option<String>,
) -> seren::AgentBundle {
    let Some(prompt) = prompt_override else {
        return bundle;
    };

    if let Some(instruction) = bundle
        .instructions
        .iter_mut()
        .find(|instruction| instruction.kind == seren::AgentInstructionKind::Skill)
    {
        instruction.content = prompt;
        instruction.sha256 = None;
    } else {
        bundle.instructions.push(seren::AgentInstructionFile {
            allowed_tools: None,
            content: prompt,
            kind: seren::AgentInstructionKind::Skill,
            path: Some("SKILL.md".to_string()),
            sha256: None,
            skill_name: None,
        });
    }

    bundle
}

fn apply_requirements_txt_clear(
    body: &mut serde_json::Map<String, serde_json::Value>,
    clear_requirements_txt: bool,
) -> Result<()> {
    if clear_requirements_txt && body.contains_key("requirements_txt") {
        return Err(anyhow::anyhow!(
            "Provide either requirements_txt in --agent-config or --clear-requirements-txt, not both."
        ));
    }
    if clear_requirements_txt {
        body.insert("requirements_txt".to_string(), serde_json::Value::Null);
    }
    Ok(())
}

async fn build_managed_agent_update_request(
    client: &seren::Client,
    deployment_id: &Uuid,
    options: ManagedAgentUpdateOptions<'_>,
) -> Result<seren::AgentSpecUpdate> {
    let ManagedAgentUpdateOptions {
        name,
        agent_slug,
        cron_schedule,
        cron_timezone,
        eval_gate_set_id,
        eval_gate_max_age_seconds,
        clear_eval_gate,
        template,
        tool_presets,
        approval_policy,
        model_policy,
        allowed_remote_agent_origins,
        config_path,
        env_path,
        agent_config_path,
        capability_policy_json,
        capability_policy_path,
        clear_capability_policy,
        clear_requirements_txt,
        prompt,
        model_id,
        visibility,
    } = options;

    let agent_config = load_orchestration_config(None, agent_config_path)?;
    let capability_policy = load_managed_agent_json_override(
        capability_policy_json,
        capability_policy_path,
        "capability-policy",
    )?;
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
    if let Some(agent_slug) = agent_slug {
        body.insert(
            "agent_slug".to_string(),
            serde_json::json!(agent_slug.trim()),
        );
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
    if let Some(cron_timezone) = cron_timezone
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        body.insert(
            "cron_timezone".to_string(),
            serde_json::json!(cron_timezone),
        );
    }
    if let Some(eval_gate_set_id) = eval_gate_set_id {
        body.insert(
            "eval_gate_set_id".to_string(),
            serde_json::json!(eval_gate_set_id),
        );
    }
    if let Some(eval_gate_max_age_seconds) = eval_gate_max_age_seconds {
        body.insert(
            "eval_gate_max_age_seconds".to_string(),
            serde_json::json!(eval_gate_max_age_seconds),
        );
    }
    if clear_eval_gate {
        body.insert("clear_eval_gate".to_string(), serde_json::json!(true));
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
    if !allowed_remote_agent_origins.is_empty() {
        body.insert(
            "allowed_remote_agent_origins".to_string(),
            serde_json::json!(allowed_remote_agent_origins),
        );
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
    apply_requirements_txt_clear(&mut body, clear_requirements_txt)?;
    if capability_policy.is_some() && clear_capability_policy {
        return Err(anyhow::anyhow!(
            "Provide either --capability-policy/--capability-policy-file or --clear-capability-policy, not both."
        ));
    }
    if let Some(capability_policy) = capability_policy {
        body.insert("capability_policy".to_string(), capability_policy);
    }
    if clear_capability_policy {
        body.insert(
            "clear_capability_policy".to_string(),
            serde_json::json!(true),
        );
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

    let workload = if body_touches_workload(&body) {
        Some(build_replacement_workload_for_managed_agent(client, deployment_id, &body).await?)
    } else {
        None
    };

    // Strip workload-level fields out of the envelope; they are now embedded
    // in `workload` (or carried implicitly via the existing deployment).
    for key in WORKLOAD_LEVEL_FIELDS
        .iter()
        .chain(WORKLOAD_LIMITS_FIELDS.iter())
        .chain(LLM_EXECUTION_FIELDS.iter())
        .chain(CODE_EXECUTION_FIELDS.iter())
    {
        body.remove(*key);
    }
    body.remove("prompt");

    let eval_gate_set_id = body.remove("eval_gate_set_id");
    let eval_gate_max_age_seconds = body.remove("eval_gate_max_age_seconds");
    if let (Some(set_id), Some(max_age_seconds)) = (eval_gate_set_id, eval_gate_max_age_seconds) {
        let mut gate = serde_json::Map::new();
        gate.insert("set_id".to_string(), set_id);
        gate.insert("max_age_seconds".to_string(), max_age_seconds);
        body.insert("eval_gate".to_string(), serde_json::Value::Object(gate));
    }

    let mut request: seren::AgentSpecUpdate =
        serde_json::from_value(serde_json::Value::Object(body))
            .map_err(|e| anyhow::anyhow!("Failed to build managed update request: {}", e))?;
    request.workload = workload;
    Ok(request)
}

fn build_managed_agent_rollback_request(
    revision_id: Uuid,
    expected_active_revision_id: Option<Uuid>,
    secret_resolution_result_id: Option<Uuid>,
) -> seren::RollbackSerenAgentDeploymentRequest {
    seren::RollbackSerenAgentDeploymentRequest {
        expected_active_revision_id,
        revision_id,
        secret_resolution_result_id,
    }
}

/// Preview an update to an existing managed seren-agent deployment.
pub async fn managed_agent_preview(
    deployment_id: Uuid,
    options: ManagedAgentUpdateOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = build_managed_agent_update_request(&client, &deployment_id, options).await?;
    let response = match client
        .seren_agent_preview_managed_deployment_update(&deployment_id, &body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to preview managed agent deployment update",
                err,
            )
            .await);
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Update an existing managed seren-agent deployment.
pub async fn managed_agent_update(
    deployment_id: Uuid,
    options: ManagedAgentUpdateOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = build_managed_agent_update_request(&client, &deployment_id, options).await?;
    let response = match client
        .seren_agent_update_managed_deployment(&deployment_id, &body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to update managed agent deployment", err).await,
            );
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Preview a rollback to a prior managed seren-agent revision.
pub async fn managed_agent_rollback_preview(
    deployment_id: Uuid,
    revision_id: Uuid,
    expected_active_revision_id: Option<Uuid>,
    secret_resolution_result_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = build_managed_agent_rollback_request(
        revision_id,
        expected_active_revision_id,
        secret_resolution_result_id,
    );
    let response = match client
        .seren_agent_preview_managed_deployment_rollback(&deployment_id, &body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(
                anyhow_from_seren_error("Failed to preview managed agent rollback", err).await,
            );
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Roll back a managed seren-agent deployment to a prior revision.
pub async fn managed_agent_rollback(
    deployment_id: Uuid,
    revision_id: Uuid,
    expected_active_revision_id: Option<Uuid>,
    secret_resolution_result_id: Option<Uuid>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let body = build_managed_agent_rollback_request(
        revision_id,
        expected_active_revision_id,
        secret_resolution_result_id,
    );
    let response = match client
        .seren_agent_rollback_managed_deployment(&deployment_id, &body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to roll back managed agent deployment",
                err,
            )
            .await);
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Preview runtime-policy reconciliation for a managed seren-agent deployment.
pub async fn managed_agent_runtime_policy_reconciliation_preview(
    deployment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_preview_runtime_policy_reconciliation(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to preview managed agent runtime-policy reconciliation",
                err,
            )
            .await);
        }
    };
    output::print_json(&response.into_inner())?;
    Ok(())
}

/// Apply runtime-policy reconciliation for a managed seren-agent deployment.
pub async fn managed_agent_runtime_policy_reconciliation(
    deployment_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = match client
        .seren_agent_apply_runtime_policy_reconciliation(&deployment_id)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err(anyhow_from_seren_error(
                "Failed to apply managed agent runtime-policy reconciliation",
                err,
            )
            .await);
        }
    };
    output::print_json(&response.into_inner())?;
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

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let deployments = &response.data;
            if deployments.is_empty() {
                println!("No cloud deployments found.");
                return Ok(());
            }
            println!(
                "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10} {:<24}",
                "ID", "SKILL", "BACKEND", "RUNTIME", "MODE", "STATUS", "EVAL GATE"
            );
            for d in deployments {
                let d_json = serde_json::to_value(d)?;
                println!(
                    "{:<38} {:<24} {:<18} {:<14} {:<12} {:<10} {:<24}",
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
                    format_eval_gate_brief(&d_json),
                );
            }
        }
    }

    Ok(())
}

/// Get deployment bundle metadata without raw content.
pub async fn cloud_deployment_bundle_get(bundle_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_deployment_bundle(&bundle_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let payload = serde_json::to_value(&response)?;
            let detail = payload.get("data").unwrap_or(&payload);
            let bundle = detail.get("bundle").unwrap_or(detail);
            output::print_key_value_table(
                Some("Deployment Bundle"),
                &[
                    ("Bundle ID", format_optional_string(bundle.get("id"))),
                    (
                        "Organization ID",
                        format_optional_string(bundle.get("organization_id")),
                    ),
                    ("User ID", format_optional_string(bundle.get("user_id"))),
                    ("SHA256", format_optional_string(bundle.get("sha256"))),
                    (
                        "Size Bytes",
                        bundle
                            .get("size_bytes")
                            .and_then(|value| value.as_i64())
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                    ),
                    (
                        "Source Kind",
                        format_optional_string(bundle.get("source_kind")),
                    ),
                    (
                        "Uploaded At",
                        format_optional_string(bundle.get("uploaded_at")),
                    ),
                    (
                        "Deployment References",
                        detail
                            .get("deployment_ids")
                            .and_then(|value| value.as_array())
                            .map(|items| items.len().to_string())
                            .unwrap_or_else(|| "0".to_string()),
                    ),
                ],
            );
        }
    }

    Ok(())
}

/// Show an organization-wide cloud overview with deployment counts, recent runs, and pending approvals.
pub async fn cloud_overview(
    runs_limit: i64,
    approvals_limit: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let deployments_response = client
        .seren_cloud_list_deployments()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load deployments: {}", e))?
        .into_inner();
    let recent_runs_response = client
        .seren_cloud_runs(
            None,
            None,
            None,
            Some(runs_limit),
            Some(0),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load recent runs: {}", e))?
        .into_inner();
    let pending_approvals_response = client
        .seren_cloud_pending_approvals(
            None,
            None,
            Some(approvals_limit),
            Some(0),
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load pending approvals: {}", e))?
        .into_inner();

    let deployments_value = serde_json::to_value(&deployments_response)?;
    let deployments = deployments_value
        .get("data")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let recent_runs_value = serde_json::to_value(&recent_runs_response)?;
    let recent_runs = recent_runs_value
        .get("data")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let pending_approvals_value = serde_json::to_value(&pending_approvals_response)?;
    let pending_approvals = pending_approvals_value
        .get("data")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let deployment_names = build_deployment_name_map(&deployments);
    let recent_runs = enrich_with_deployment_name(&recent_runs, &deployment_names);
    let pending_approvals = enrich_with_deployment_name(&pending_approvals, &deployment_names);

    let summary = serde_json::json!({
        "deployment_count": deployments.len(),
        "running_count": deployments
            .iter()
            .filter(|deployment| deployment.get("status").and_then(|value| value.as_str()) == Some("running"))
            .count(),
        "managed_count": deployments
            .iter()
            .filter(|deployment| !deployment.get("managed_agent").unwrap_or(&serde_json::Value::Null).is_null())
            .count(),
        "cron_count": deployments
            .iter()
            .filter(|deployment| deployment.get("mode").and_then(|value| value.as_str()) == Some("cron"))
            .count(),
        "recent_runs_loaded": recent_runs.len(),
        "pending_approvals_loaded": pending_approvals.len(),
    });

    if matches!(ctx.format, OutputFormat::Json) {
        let payload = serde_json::json!({
            "summary": summary,
            "recent_runs": recent_runs,
            "pending_approvals": pending_approvals,
        });
        output::print_json(&payload)?;
        return Ok(());
    }

    let summary_rows = vec![
        (
            "Deployments",
            summary
                .get("deployment_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "Running",
            summary
                .get("running_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "Managed",
            summary
                .get("managed_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "Cron",
            summary
                .get("cron_count")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "Recent Runs Loaded",
            summary
                .get("recent_runs_loaded")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "Pending Approvals",
            summary
                .get("pending_approvals_loaded")
                .and_then(|value| value.as_u64())
                .unwrap_or(0)
                .to_string(),
        ),
    ];
    output::print_key_value_table(Some("Cloud Overview"), &summary_rows);

    println!();
    println!("Recent Runs");
    print_cloud_run_rows(&recent_runs, true, "No recent runs found.")?;

    println!();
    println!("Pending Approvals");
    let pending_approvals_envelope = serde_json::json!({ "data": pending_approvals });
    print_pending_approval_runs_table(&pending_approvals_envelope, None)?;

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
    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let value = serde_json::to_value(&response)?;
            print_cloud_deployment_detail_table(&value);
        }
    }
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

#[derive(Debug, Clone, Copy, Default)]
pub struct CloudRunOptions<'a> {
    pub message: Option<&'a str>,
    pub json_body: Option<&'a str>,
    pub json_file: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub async_run: bool,
    pub organization: bool,
    pub knowledge_selection_id: Option<Uuid>,
    pub task_label: Option<&'a str>,
}

fn build_cloud_run_payload(options: &CloudRunOptions<'_>) -> Result<Option<serde_json::Value>> {
    let CloudRunOptions {
        message,
        json_body,
        json_file,
        run_id,
        async_run,
        organization,
        knowledge_selection_id,
        task_label,
    } = *options;
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

    if organization {
        let task_label = match task_label {
            Some(value) if value.trim().is_empty() => {
                return Err(anyhow::anyhow!("--task-label cannot be empty."));
            }
            Some(value) => Some(value.trim().to_string()),
            None => None,
        };
        let collaboration = serde_json::json!({
            "invocation_origin": { "kind": "direct" },
            "knowledge_selection": match knowledge_selection_id {
                Some(selection_id) => serde_json::json!({
                    "kind": "organization",
                    "provider": "memory",
                    "selection_id": selection_id,
                }),
                None => serde_json::json!({ "kind": "none" }),
            },
            "knowledge_capture_target": { "kind": "none" },
            "task_label": task_label,
            "output_audience": { "kind": "organization" },
        });
        match payload.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("collaboration".to_string(), collaboration);
            }
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "When --organization is provided, --json/--json-file must be a JSON object."
                ));
            }
            None => {
                payload = Some(serde_json::json!({ "collaboration": collaboration }));
            }
        }
    } else if knowledge_selection_id.is_some() || task_label.is_some() {
        return Err(anyhow::anyhow!(
            "--knowledge-selection-id and --task-label require --organization."
        ));
    }

    Ok(payload)
}

fn parse_optional_json_value(
    flag_name: &str,
    json_body: Option<&str>,
    json_file: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    if json_body.is_some() && json_file.is_some() {
        return Err(anyhow::anyhow!(
            "Provide only one of {flag_name} or {flag_name}-file."
        ));
    }

    if let Some(raw_json) = json_body.map(str::trim).filter(|value| !value.is_empty()) {
        let value = serde_json::from_str::<serde_json::Value>(raw_json)
            .map_err(|e| anyhow::anyhow!("Invalid {flag_name} payload: {e}"))?;
        return Ok(Some(value));
    }

    if let Some(json_file) = json_file.map(str::trim).filter(|value| !value.is_empty()) {
        let raw_json = fs::read_to_string(json_file)
            .map_err(|e| anyhow::anyhow!("Failed to read {flag_name}-file '{}': {e}", json_file))?;
        let value = serde_json::from_str::<serde_json::Value>(&raw_json).map_err(|e| {
            anyhow::anyhow!("Invalid JSON in {flag_name}-file '{}': {e}", json_file)
        })?;
        return Ok(Some(value));
    }

    Ok(None)
}

fn parse_optional_metadata_object(
    json_body: Option<&str>,
    json_file: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    let metadata = parse_optional_json_value("--metadata", json_body, json_file)?;
    match metadata {
        Some(serde_json::Value::Object(_)) => Ok(metadata),
        Some(_) => Err(anyhow::anyhow!(
            "--metadata/--metadata-file must contain a JSON object."
        )),
        None => Ok(None),
    }
}

fn parse_cloud_eval_criteria(
    json_body: Option<&str>,
    json_file: Option<&str>,
) -> Result<seren::CloudEvalCriteria> {
    let criteria = parse_optional_json_value("--criteria", json_body, json_file)?
        .unwrap_or_else(|| serde_json::json!({}));
    if !criteria.is_object() {
        return Err(anyhow::anyhow!(
            "--criteria/--criteria-file must contain a JSON object."
        ));
    }
    serde_json::from_value(criteria)
        .map_err(|e| anyhow::anyhow!("Invalid eval criteria payload: {e}"))
}

fn build_cloud_eval_set_schedule_request(
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
) -> Result<Option<seren::CloudEvalSetScheduleRequest>> {
    seren::build_cloud_eval_set_schedule_request(schedule_cron, schedule_timezone)
        .map_err(|e| anyhow::anyhow!(e))
}

fn resolve_cloud_eval_set_schedule_request(
    eval_set: &seren::CloudEvalSet,
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
    clear_schedule: bool,
) -> Result<Option<seren::CloudEvalSetScheduleRequest>> {
    seren::resolve_cloud_eval_set_schedule_request(
        eval_set,
        schedule_cron,
        schedule_timezone,
        clear_schedule,
    )
    .map_err(|e| anyhow::anyhow!(e))
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

/// Approve all pending approvals for a run and resume it.
pub async fn cloud_run_approve(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    resolve_cloud_run_pending_approvals(run_id, "approve", ctx).await
}

/// Reject all pending approvals for a run and resume it.
pub async fn cloud_run_reject(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    resolve_cloud_run_pending_approvals(run_id, "reject", ctx).await
}

async fn resolve_cloud_run_pending_approvals(
    run_id: Uuid,
    decision: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let run_detail = match client.seren_cloud_run_detail(&run_id).await {
        Ok(response) => response.into_inner(),
        Err(e) => return Err(anyhow_from_seren_error("Failed to load run detail", e).await),
    };
    let deployment_id = run_detail.data.deployment_id;
    let original_execution_id = run_detail.data.execution_id.clone();

    let approval_state = match client.seren_cloud_run_pending_approvals(&run_id).await {
        Ok(response) => response.into_inner(),
        Err(e) => {
            return Err(anyhow_from_seren_error("Failed to load pending approvals", e).await);
        }
    };
    let approval_state_json = serde_json::to_value(&approval_state)?;

    let maybe_body = seren::build_cloud_approval_resume_request(&approval_state_json, decision)
        .map_err(|e| anyhow::anyhow!(e))?;
    if maybe_body.is_none() {
        let payload = serde_json::json!({
            "resolved": false,
            "decision": decision,
            "run_id": run_id,
            "deployment_id": deployment_id,
            "approval_state": approval_state_json,
            "message": "This run is not currently awaiting approval.",
        });
        match ctx.format {
            OutputFormat::Json => output::print_json(&payload)?,
            OutputFormat::Table => {
                println!(
                    "{} Run {} is not currently awaiting approval.",
                    "•".cyan(),
                    run_id
                );
            }
        }
        return Ok(());
    }

    let body = maybe_body.unwrap_or_default();
    let response_body = match client.seren_cloud_run_resume(&run_id, &body).await {
        Ok(response) => response.into_inner(),
        Err(e) => return Err(anyhow_from_seren_error("Failed to resume run", e).await),
    };
    seren::validate_cloud_approval_resume_identity(
        &run_id,
        &original_execution_id,
        &response_body.data.id,
        &response_body.data.execution_id,
    )
    .map_err(|error| anyhow::anyhow!(error))?;

    if matches!(ctx.format, OutputFormat::Json) {
        let payload = serde_json::json!({
            "resolved": true,
            "decision": decision,
            "run_id": run_id,
            "deployment_id": deployment_id,
            "response": response_body,
        });
        output::print_json(&payload)?;
        return Ok(());
    }

    let response_json = serde_json::to_value(&response_body)?;
    let (resumed_run_id, execution_id) = extract_run_identifiers(&response_json);
    let action_label = if decision == "approve" {
        "Approved"
    } else {
        "Rejected"
    };
    match (resumed_run_id, execution_id) {
        (Some(resumed_run_id), Some(execution_id)) => {
            println!(
                "{} {} pending approvals for run {} and resumed deployment {}.",
                "✓".green(),
                action_label,
                run_id,
                deployment_id
            );
            println!("  Run ID: {}", resumed_run_id.bold());
            println!("  Execution ID: {}", execution_id.bold());
            println!(
                "  Check status: seren agent cloud run get --deployment-id {} {}",
                deployment_id, resumed_run_id
            );
        }
        (Some(resumed_run_id), None) => {
            println!(
                "{} {} pending approvals for run {} and resumed deployment {} (run_id: {}).",
                "✓".green(),
                action_label,
                run_id,
                deployment_id,
                resumed_run_id.bold()
            );
        }
        _ => {
            println!(
                "{} {} pending approvals for run {} and resumed deployment {}.",
                "✓".green(),
                action_label,
                run_id,
                deployment_id
            );
            if !response_json.is_null() {
                output::print_json(&response_json)?;
            }
        }
    }

    Ok(())
}

/// Trigger a one-shot run of a cloud agent.
pub async fn cloud_run(
    deployment_id: Uuid,
    options: CloudRunOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let payload = build_cloud_run_payload(&options)?.unwrap_or_else(|| serde_json::json!({}));
    let body: seren::CloudDeploymentRunRequest = serde_json::from_value(payload)
        .map_err(|e| anyhow::anyhow!("Failed to build run payload: {}", e))?;
    let client = ctx.client().await?;
    let response_body = match client.seren_cloud_run(&deployment_id, &body).await {
        Ok(response) => response.into_inner(),
        Err(e) => return Err(anyhow_from_seren_error("Failed to trigger run", e).await),
    };
    let response_json = serde_json::to_value(&response_body)?;
    let (run_id, execution_id) = extract_run_identifiers(&response_json);

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
                "  Check status: seren agent cloud run get --deployment-id {} {}",
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
            if !response_json.is_null() {
                output::print_json(&response_json)?;
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
    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_run_detail_response(&response)?,
    }
    Ok(())
}

/// Compare replay/eval captures for two runs by run ID (global path).
pub async fn cloud_run_compare(
    baseline_run_id: Uuid,
    candidate_run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_compare(&baseline_run_id, &candidate_run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => output::print_cloud_run_replay_comparison(&response.data)?,
    }

    Ok(())
}

fn json_value_has_content(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(raw) => !raw.trim().is_empty(),
        serde_json::Value::Array(entries) => !entries.is_empty(),
        serde_json::Value::Object(entries) => !entries.is_empty(),
        _ => true,
    }
}

fn print_cloud_eval_set_table(
    eval_sets: &[seren::CloudEvalSet],
    pagination: Option<&seren::PaginationMeta>,
) {
    if eval_sets.is_empty() {
        println!("No eval sets found.");
        return;
    }

    println!(
        "{:<38} {:<24} {:<38} {:<24} {:<24}",
        "EVAL SET ID", "NAME", "DEPLOYMENT", "SCHEDULE", "UPDATED"
    );
    for eval_set in eval_sets {
        println!(
            "{:<38} {:<24} {:<38} {:<24} {:<24}",
            eval_set.id,
            truncate_for_cli(&eval_set.name, 24),
            eval_set
                .deployment_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate_for_cli(&format_eval_set_schedule_brief(eval_set), 24),
            eval_set.updated_at,
        );
    }

    if let Some(pagination) = pagination {
        println!(
            "
Showing {} of {} eval sets (offset {}).",
            pagination.count, pagination.total, pagination.offset
        );
    }
}

fn print_cloud_eval_case_table(
    eval_cases: &[seren::CloudEvalCase],
    pagination: Option<&seren::PaginationMeta>,
) {
    if eval_cases.is_empty() {
        println!("No eval cases found.");
        return;
    }

    println!(
        "{:<38} {:<28} {:<14} {:<38} {:<24}",
        "CASE ID", "NAME", "SOURCE", "RUN", "UPDATED"
    );
    for eval_case in eval_cases {
        println!(
            "{:<38} {:<28} {:<14} {:<38} {:<24}",
            eval_case.id,
            eval_case.name,
            eval_case.source_kind,
            eval_case
                .source_run_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            eval_case.updated_at,
        );
    }

    if let Some(pagination) = pagination {
        println!(
            "
Showing {} of {} eval cases (offset {}).",
            pagination.count, pagination.total, pagination.offset
        );
    }
}

fn print_cloud_eval_set_detail(eval_set: &seren::CloudEvalSet) -> Result<()> {
    output::print_key_value_table(
        Some("Eval Set"),
        &[
            ("Eval Set ID", eval_set.id.to_string()),
            ("Name", eval_set.name.clone()),
            (
                "Deployment ID",
                eval_set
                    .deployment_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Description",
                eval_set
                    .description
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Created", eval_set.created_at.to_string()),
            ("Updated", eval_set.updated_at.to_string()),
        ],
    );

    let criteria = eval_set_criteria_json(eval_set);
    if json_value_has_content(&criteria) {
        println!();
        output::print_key_value_table(
            Some("Criteria"),
            &[
                (
                    "Minimum Score",
                    format_eval_run_summary_percent(&criteria, "min_score"),
                ),
                (
                    "Minimum Completion Rate",
                    format_eval_run_summary_percent(&criteria, "min_completion_rate"),
                ),
                (
                    "Maximum Failed Cases",
                    eval_run_summary_count(&criteria, "max_failed_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Errored Cases",
                    eval_run_summary_count(&criteria, "max_errored_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Output Mismatches",
                    eval_run_summary_count(&criteria, "max_output_mismatches")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Status Mismatches",
                    eval_run_summary_count(&criteria, "max_status_mismatches")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Trajectory Mismatches",
                    eval_run_summary_count(&criteria, "max_trajectory_mismatches")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Missing Eval Capture",
                    eval_run_summary_count(&criteria, "max_missing_actual_eval_capture_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Maximum Missing Replay",
                    eval_run_summary_count(&criteria, "max_missing_actual_replay_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Minimum Field Match Rate",
                    format_eval_run_summary_percent(&criteria, "min_field_match_rate"),
                ),
            ],
        );
    }

    let schedule = eval_set_schedule_json(eval_set);
    if json_value_has_content(&schedule) {
        println!();
        output::print_key_value_table(
            Some("Schedule"),
            &[
                (
                    "Cron",
                    eval_run_summary_string(&schedule, "schedule_cron")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Timezone",
                    eval_run_summary_string(&schedule, "schedule_timezone")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Next Run",
                    eval_run_summary_string(&schedule, "schedule_next_run_at")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Last Attempted",
                    eval_run_summary_string(&schedule, "schedule_last_attempted_at")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Last Status",
                    eval_run_summary_string(&schedule, "schedule_last_status")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Last Message",
                    eval_run_summary_string(&schedule, "schedule_last_message")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Last Eval Run ID",
                    eval_run_summary_string(&schedule, "schedule_last_eval_run_id")
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ],
        );
    }

    if json_value_has_content(&eval_set.metadata) {
        println!();
        println!("{}", "Metadata".bold());
        output::print_json(&eval_set.metadata)?;
    }

    Ok(())
}

fn print_cloud_eval_case_detail(eval_case: &seren::CloudEvalCase) -> Result<()> {
    output::print_key_value_table(
        Some("Eval Case"),
        &[
            ("Eval Case ID", eval_case.id.to_string()),
            ("Eval Set ID", eval_case.eval_set_id.to_string()),
            ("Name", eval_case.name.clone()),
            ("Source", eval_case.source_kind.clone()),
            (
                "Source Run ID",
                eval_case
                    .source_run_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Deployment ID",
                eval_case
                    .deployment_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Expected Output SHA256",
                eval_case
                    .expected_output_sha256
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Created", eval_case.created_at.to_string()),
            ("Updated", eval_case.updated_at.to_string()),
        ],
    );

    if let Some(expected_output) = eval_case.expected_output.as_deref()
        && !expected_output.trim().is_empty()
    {
        println!();
        println!("{}", "Expected Output".bold());
        println!("{}", expected_output);
    }

    for (label, value) in [
        ("Invocation Payload", &eval_case.invocation_payload),
        ("Expected Eval Capture", &eval_case.expected_eval_capture),
        ("Expected Replay Events", &eval_case.expected_replay_events),
        ("Metadata", &eval_case.metadata),
    ] {
        if json_value_has_content(value) {
            println!();
            println!("{}", label.bold());
            output::print_json(value)?;
        }
    }

    Ok(())
}

fn eval_set_criteria_json(eval_set: &seren::CloudEvalSet) -> serde_json::Value {
    serde_json::to_value(&eval_set.criteria).unwrap_or(serde_json::Value::Null)
}

fn eval_set_schedule_json(eval_set: &seren::CloudEvalSet) -> serde_json::Value {
    serde_json::to_value(&eval_set.schedule).unwrap_or(serde_json::Value::Null)
}

fn eval_set_schedule_string(eval_set: &seren::CloudEvalSet, key: &str) -> Option<String> {
    seren::eval_set_schedule_string(eval_set, key)
}

fn format_eval_set_schedule_brief(eval_set: &seren::CloudEvalSet) -> String {
    match (
        eval_set_schedule_string(eval_set, "schedule_cron"),
        eval_set_schedule_string(eval_set, "schedule_timezone"),
    ) {
        (Some(schedule_cron), Some(schedule_timezone)) => {
            format!("{schedule_cron} ({schedule_timezone})")
        }
        (Some(schedule_cron), None) => schedule_cron,
        _ => "-".to_string(),
    }
}

fn eval_run_summary_json(eval_run: &seren::CloudEvalRun) -> serde_json::Value {
    serde_json::to_value(&eval_run.summary).unwrap_or(serde_json::Value::Null)
}

fn eval_run_verdict_json(eval_run: &seren::CloudEvalRun) -> serde_json::Value {
    serde_json::to_value(&eval_run.verdict).unwrap_or(serde_json::Value::Null)
}

fn eval_run_summary_number(summary: &serde_json::Value, key: &str) -> Option<f64> {
    summary.as_object()?.get(key)?.as_f64()
}

fn eval_run_summary_count(summary: &serde_json::Value, key: &str) -> Option<i64> {
    summary.as_object()?.get(key)?.as_i64()
}

fn eval_run_summary_string(summary: &serde_json::Value, key: &str) -> Option<String> {
    summary
        .as_object()?
        .get(key)?
        .as_str()
        .map(ToString::to_string)
}

fn format_eval_run_summary_percent(summary: &serde_json::Value, key: &str) -> String {
    eval_run_summary_number(summary, key)
        .map(|value| format!("{:.1}%", value * 100.0))
        .unwrap_or_else(|| "-".to_string())
}

fn format_eval_run_summary_ratio(
    summary: &serde_json::Value,
    mismatch_key: &str,
    checked_key: &str,
) -> String {
    match (
        eval_run_summary_count(summary, mismatch_key),
        eval_run_summary_count(summary, checked_key),
    ) {
        (Some(mismatches), Some(checked)) => format!("{mismatches}/{checked}"),
        _ => "-".to_string(),
    }
}

fn eval_run_verdict_string(verdict: &serde_json::Value, key: &str) -> Option<String> {
    verdict
        .as_object()?
        .get(key)?
        .as_str()
        .map(ToString::to_string)
}

fn print_cloud_eval_run_table(
    eval_runs: &[seren::CloudEvalRun],
    pagination: Option<&seren::PaginationMeta>,
) {
    if eval_runs.is_empty() {
        println!("No eval runs found.");
        return;
    }

    println!(
        "{:<38} {:<12} {:<10} {:<8} {:<10} {:<10} {:<10} {:<24}",
        "EVAL RUN ID", "STATUS", "VERDICT", "SCORE", "PASSED", "FAILED", "ERRORED", "UPDATED"
    );
    for eval_run in eval_runs {
        let summary = eval_run_summary_json(eval_run);
        let verdict = eval_run_verdict_json(eval_run);
        println!(
            "{:<38} {:<12} {:<10} {:<8} {:<10} {:<10} {:<10} {:<24}",
            eval_run.id,
            eval_run.status,
            eval_run_verdict_string(&verdict, "status").unwrap_or_else(|| "-".to_string()),
            format_eval_run_summary_percent(&summary, "score"),
            eval_run.passed_cases,
            eval_run.failed_cases,
            eval_run.errored_cases,
            eval_run.updated_at,
        );
    }

    if let Some(pagination) = pagination {
        println!(
            "
Showing {} of {} eval runs (offset {}).",
            pagination.count, pagination.total, pagination.offset
        );
    }
}

fn print_cloud_eval_case_result_table(
    results: &[seren::CloudEvalCaseResult],
    pagination: Option<&seren::PaginationMeta>,
) {
    if results.is_empty() {
        println!("No eval case results found.");
        return;
    }

    println!(
        "{:<38} {:<38} {:<12} {:<12} {:<12} {:<24}",
        "CASE ID", "RUN ID", "STATUS", "EXPECTED", "ACTUAL", "UPDATED"
    );
    for result in results {
        println!(
            "{:<38} {:<38} {:<12} {:<12} {:<12} {:<24}",
            result.eval_case_id,
            result
                .actual_run_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string()),
            result.status,
            result
                .expected_status
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            result
                .actual_status
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            result.updated_at,
        );
    }

    if let Some(pagination) = pagination {
        println!(
            "
Showing {} of {} eval case results (offset {}).",
            pagination.count, pagination.total, pagination.offset
        );
    }
}

fn print_cloud_eval_run_detail(eval_run: &seren::CloudEvalRun) -> Result<()> {
    output::print_key_value_table(
        Some("Eval Run"),
        &[
            ("Eval Run ID", eval_run.id.to_string()),
            ("Eval Set ID", eval_run.eval_set_id.to_string()),
            (
                "Deployment ID",
                eval_run
                    .deployment_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Status", eval_run.status.clone()),
            (
                "Verdict",
                eval_run_verdict_json(eval_run)
                    .as_object()
                    .and_then(|object| object.get("status"))
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Status Message",
                eval_run
                    .status_message
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Total Cases", eval_run.total_cases.to_string()),
            ("Completed", eval_run.completed_cases.to_string()),
            ("Passed", eval_run.passed_cases.to_string()),
            ("Failed", eval_run.failed_cases.to_string()),
            ("Errored", eval_run.errored_cases.to_string()),
            (
                "Started",
                eval_run
                    .started_at
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Completed",
                eval_run
                    .completed_at
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Created", eval_run.created_at.to_string()),
            ("Updated", eval_run.updated_at.to_string()),
        ],
    );

    let summary = eval_run_summary_json(eval_run);
    let verdict = eval_run_verdict_json(eval_run);
    if json_value_has_content(&summary) {
        println!();
        output::print_key_value_table(
            Some("Summary"),
            &[
                ("Score", format_eval_run_summary_percent(&summary, "score")),
                (
                    "Pass Rate",
                    format_eval_run_summary_percent(&summary, "pass_rate"),
                ),
                (
                    "Completion Rate",
                    format_eval_run_summary_percent(&summary, "completion_rate"),
                ),
                (
                    "Compared Cases",
                    eval_run_summary_count(&summary, "compared_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Output Drift",
                    format_eval_run_summary_ratio(
                        &summary,
                        "output_mismatches",
                        "output_checked_cases",
                    ),
                ),
                (
                    "Status Drift",
                    format_eval_run_summary_ratio(
                        &summary,
                        "status_mismatches",
                        "status_checked_cases",
                    ),
                ),
                (
                    "Trajectory Drift",
                    format_eval_run_summary_ratio(
                        &summary,
                        "trajectory_mismatches",
                        "trajectory_checked_cases",
                    ),
                ),
                (
                    "Missing Eval Capture",
                    eval_run_summary_count(&summary, "missing_actual_eval_capture_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Missing Replay",
                    eval_run_summary_count(&summary, "missing_actual_replay_cases")
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Field Drift",
                    format_eval_run_summary_ratio(
                        &summary,
                        "field_mismatches",
                        "field_comparisons",
                    ),
                ),
                (
                    "Field Match Rate",
                    format_eval_run_summary_percent(&summary, "field_match_rate"),
                ),
                (
                    "First Failed Case",
                    eval_run_summary_string(&summary, "first_failed_case_id")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "First Errored Case",
                    eval_run_summary_string(&summary, "first_errored_case_id")
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ],
        );

        if let Some(failure_examples) = summary
            .as_object()
            .and_then(|object| object.get("failure_examples"))
            && json_value_has_content(failure_examples)
        {
            println!();
            println!("{}", "Failure Examples".bold());
            output::print_json(failure_examples)?;
        }
    }

    if json_value_has_content(&verdict) {
        println!();
        output::print_key_value_table(
            Some("Verdict"),
            &[
                (
                    "Status",
                    eval_run_verdict_string(&verdict, "status").unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Evaluated At",
                    eval_run_verdict_string(&verdict, "evaluated_at")
                        .unwrap_or_else(|| "-".to_string()),
                ),
                (
                    "Failing Checks",
                    verdict
                        .as_object()
                        .and_then(|object| object.get("failing_checks"))
                        .and_then(|value| value.as_array())
                        .map(|value| value.len().to_string())
                        .unwrap_or_else(|| "0".to_string()),
                ),
            ],
        );

        if let Some(criteria) = verdict
            .as_object()
            .and_then(|object| object.get("criteria"))
            && json_value_has_content(criteria)
        {
            println!();
            println!("{}", "Verdict Criteria Snapshot".bold());
            output::print_json(criteria)?;
        }
        if let Some(failing_checks) = verdict
            .as_object()
            .and_then(|object| object.get("failing_checks"))
            && json_value_has_content(failing_checks)
        {
            println!();
            println!("{}", "Failing Checks".bold());
            output::print_json(failing_checks)?;
        }
    }

    if json_value_has_content(&eval_run.metadata) {
        println!();
        println!("{}", "Metadata".bold());
        output::print_json(&eval_run.metadata)?;
    }

    Ok(())
}

fn print_cloud_eval_case_result_detail(result: &seren::CloudEvalCaseResult) -> Result<()> {
    output::print_key_value_table(
        Some("Eval Case Result"),
        &[
            ("Eval Run ID", result.eval_run_id.to_string()),
            ("Eval Set ID", result.eval_set_id.to_string()),
            ("Eval Case ID", result.eval_case_id.to_string()),
            (
                "Deployment ID",
                result
                    .deployment_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Actual Run ID",
                result
                    .actual_run_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Status", result.status.clone()),
            (
                "Status Message",
                result
                    .status_message
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Expected Status",
                result
                    .expected_status
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Actual Status",
                result
                    .actual_status
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Expected Output SHA256",
                result
                    .expected_output_sha256
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Actual Output SHA256",
                result
                    .actual_output_sha256
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Started",
                result
                    .started_at
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "Completed",
                result
                    .completed_at
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Updated", result.updated_at.to_string()),
        ],
    );

    for (label, value) in [
        ("Expected Eval Capture", &result.expected_eval_capture),
        ("Actual Eval Capture", &result.actual_eval_capture),
        ("Expected Replay Events", &result.expected_replay_events),
        ("Actual Replay Events", &result.actual_replay_events),
        ("Comparison", &result.comparison),
        ("Metadata", &result.metadata),
    ] {
        if json_value_has_content(value) {
            println!();
            println!("{}", label.bold());
            output::print_json(value)?;
        }
    }

    Ok(())
}

/// List durable eval sets for seren-cloud runs.
pub async fn cloud_eval_sets(
    deployment_id: Option<Uuid>,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_eval_sets(deployment_id.as_ref(), Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_cloud_eval_set_table(&response.data, response.pagination.as_ref())
        }
    }

    Ok(())
}

/// Create a durable eval set for seren-cloud runs.
#[allow(clippy::too_many_arguments)]
pub async fn cloud_eval_set_create(
    name: &str,
    deployment_id: Option<Uuid>,
    description: Option<&str>,
    criteria_json: Option<&str>,
    criteria_file: Option<&str>,
    metadata_json: Option<&str>,
    metadata_file: Option<&str>,
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let criteria = parse_cloud_eval_criteria(criteria_json, criteria_file)?;
    let metadata = parse_optional_metadata_object(metadata_json, metadata_file)?
        .unwrap_or_else(|| serde_json::json!({}));
    let schedule = build_cloud_eval_set_schedule_request(schedule_cron, schedule_timezone)?;
    let request = seren::CreateCloudEvalSetRequest {
        criteria: Some(criteria),
        deployment_id,
        description: description.map(ToOwned::to_owned),
        metadata: Some(metadata),
        name: name.to_string(),
        schedule,
    };
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_create_eval_set(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_set_detail(&response.data)?,
    }

    Ok(())
}

/// Get a single eval set.
pub async fn cloud_eval_set_get(eval_set_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_eval_set(&eval_set_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_set_detail(&response.data)?,
    }

    Ok(())
}

/// Replace a single eval set.
#[allow(clippy::too_many_arguments)]
pub async fn cloud_eval_set_update(
    eval_set_id: Uuid,
    name: Option<&str>,
    deployment_id: Option<Uuid>,
    clear_deployment: bool,
    description: Option<&str>,
    criteria_json: Option<&str>,
    criteria_file: Option<&str>,
    metadata_json: Option<&str>,
    metadata_file: Option<&str>,
    schedule_cron: Option<&str>,
    schedule_timezone: Option<&str>,
    clear_schedule: bool,
    ctx: &CommandContext,
) -> Result<()> {
    if clear_deployment && deployment_id.is_some() {
        return Err(anyhow::anyhow!(
            "Do not combine --clear-deployment with --deployment-id.",
        ));
    }

    let client = ctx.client().await?;
    let current = client
        .seren_cloud_get_eval_set(&eval_set_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load current eval set: {}", e))?
        .into_inner()
        .data;

    let criteria = if criteria_json.is_some() || criteria_file.is_some() {
        parse_cloud_eval_criteria(criteria_json, criteria_file)?
    } else {
        current.criteria.clone()
    };
    let metadata = if metadata_json.is_some() || metadata_file.is_some() {
        parse_optional_metadata_object(metadata_json, metadata_file)?
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        current.metadata.clone()
    };
    let schedule = resolve_cloud_eval_set_schedule_request(
        &current,
        schedule_cron,
        schedule_timezone,
        clear_schedule,
    )?;
    let request = seren::UpdateCloudEvalSetRequest {
        name: name
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| current.name.clone()),
        description: match description {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => current.description.clone(),
        },
        deployment_id: if clear_deployment {
            None
        } else {
            deployment_id.or(current.deployment_id)
        },
        criteria: Some(criteria),
        metadata: Some(metadata),
        schedule,
    };
    let response = client
        .seren_cloud_update_eval_set(&eval_set_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_set_detail(&response.data)?,
    }

    Ok(())
}

/// List eval cases within a set.
pub async fn cloud_eval_cases(
    eval_set_id: Uuid,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_eval_cases(&eval_set_id, Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_cloud_eval_case_table(&response.data, response.pagination.as_ref())
        }
    }

    Ok(())
}

/// Get a single eval case.
pub async fn cloud_eval_case_get(
    eval_set_id: Uuid,
    case_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_eval_case(&eval_set_id, &case_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_case_detail(&response.data)?,
    }

    Ok(())
}

/// Promote a terminal run into a durable eval case.
pub async fn cloud_eval_case_from_run(
    eval_set_id: Uuid,
    run_id: Uuid,
    name: Option<&str>,
    metadata_json: Option<&str>,
    metadata_file: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let metadata = parse_optional_metadata_object(metadata_json, metadata_file)?;
    let request = seren::PromoteRunToCloudEvalCaseRequest {
        metadata,
        name: name.map(ToOwned::to_owned),
    };
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_promote_run_to_eval_case(&eval_set_id, &run_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_case_detail(&response.data)?,
    }

    Ok(())
}

pub async fn cloud_eval_run_create(
    eval_set_id: Uuid,
    deployment_id: Option<Uuid>,
    metadata_json: Option<&str>,
    metadata_file: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let metadata = parse_optional_metadata_object(metadata_json, metadata_file)?;
    let request = seren::CreateCloudEvalRunRequest {
        deployment_id,
        metadata,
    };
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_eval_set(&eval_set_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_run_detail(&response.data)?,
    }

    Ok(())
}

pub async fn cloud_eval_runs(
    eval_set_id: Uuid,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_eval_runs(&eval_set_id, Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_cloud_eval_run_table(&response.data, response.pagination.as_ref())
        }
    }

    Ok(())
}

pub async fn cloud_eval_run_get(
    eval_set_id: Uuid,
    eval_run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_eval_run(&eval_set_id, &eval_run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_run_detail(&response.data)?,
    }

    Ok(())
}

pub async fn cloud_eval_run_results(
    eval_set_id: Uuid,
    eval_run_id: Uuid,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_eval_run_results(&eval_set_id, &eval_run_id, Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_cloud_eval_case_result_table(&response.data, response.pagination.as_ref())
        }
    }

    Ok(())
}

pub async fn cloud_eval_result_get(
    eval_set_id: Uuid,
    eval_run_id: Uuid,
    case_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_eval_case_result(&eval_set_id, &eval_run_id, &case_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_eval_case_result_detail(&response.data)?,
    }

    Ok(())
}

/// List artifacts emitted by a run (global path).
pub async fn cloud_run_artifacts(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_artifacts(&run_id, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list run artifacts: {}", e))?
        .into_inner();
    print_cloud_run_artifacts_response(&response, ctx)?;
    Ok(())
}

/// List artifacts emitted by a deployment-scoped run.
pub async fn cloud_deployment_run_artifacts(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_artifacts(&deployment_id, &run_id, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list deployment run artifacts: {}", e))?
        .into_inner();
    print_cloud_run_artifacts_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_run_artifacts_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let Some(artifacts) = envelope.get("data").and_then(serde_json::Value::as_array) else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = artifacts
        .iter()
        .map(format_cloud_run_artifact)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Run Artifacts"), "Artifact", &rows);
    Ok(())
}

fn format_cloud_run_artifact(artifact: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(id) = artifact.get("id").and_then(serde_json::Value::as_str) {
        parts.push(format!("id={id}"));
    }
    if let Some(artifact_type) = artifact
        .get("artifact_type")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("type={artifact_type}"));
    }
    if let Some(title) = artifact
        .get("title")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("title={}", compact_preview_for_cli(title, 80)));
    }
    if let Some(url) = artifact
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("url={}", compact_preview_for_cli(url, 120)));
    }
    if let Some(created_at) = artifact
        .get("created_at")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("created={created_at}"));
    }
    parts.join(" ")
}

pub async fn cloud_run_audit(
    run_id: Uuid,
    action: Option<&str>,
    limit: i64,
    offset: i64,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_audit(&run_id, action, Some(limit), Some(offset), q)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list run audit entries: {}", e))?
        .into_inner();
    print_cloud_audit_entries_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_run_evals(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_evals(&run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list run evals: {}", e))?
        .into_inner();
    print_cloud_run_evals_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_deployment_run_evals(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_evals(&deployment_id, &run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list deployment run evals: {}", e))?
        .into_inner();
    print_cloud_run_evals_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_run_evals_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let data = envelope.get("data").unwrap_or(&envelope);
    if !data.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    output::print_key_value_table(Some("Run Evals"), &cloud_run_evals_rows(data));
    Ok(())
}

fn cloud_run_evals_rows(data: &serde_json::Value) -> Vec<(&'static str, String)> {
    let source_count = data
        .get("source_eval_cases")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let result_count = data
        .get("actual_eval_case_results")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    let mut rows = Vec::new();
    push_json_row(&mut rows, "Run ID", data.get("run_id"));
    rows.push(("Source Eval Cases", source_count.to_string()));
    rows.push(("Actual Eval Results", result_count.to_string()));
    if let Some(first_case) = data
        .get("source_eval_cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| cases.first())
    {
        push_json_row(&mut rows, "First Source Case", first_case.get("id"));
        push_json_row(&mut rows, "First Source Name", first_case.get("name"));
    }
    if let Some(first_result) = data
        .get("actual_eval_case_results")
        .and_then(serde_json::Value::as_array)
        .and_then(|results| results.first())
    {
        push_json_row(
            &mut rows,
            "First Result Case",
            first_result.get("eval_case_id"),
        );
        push_json_row(&mut rows, "First Result Status", first_result.get("status"));
    }
    rows
}

pub async fn cloud_run_events(
    run_id: Uuid,
    item_id: Option<&str>,
    kind: Option<&str>,
    limit: i64,
    offset: i64,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_events(&run_id, item_id, kind, Some(limit), Some(offset), q)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list run events: {}", e))?
        .into_inner();
    print_cloud_run_events_response(&response, ctx)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cloud_deployment_run_events(
    deployment_id: Uuid,
    run_id: Uuid,
    item_id: Option<&str>,
    kind: Option<&str>,
    limit: i64,
    offset: i64,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_events(
            &deployment_id,
            &run_id,
            item_id,
            kind,
            Some(limit),
            Some(offset),
            q,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list deployment run events: {}", e))?
        .into_inner();
    print_cloud_run_events_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_run_events_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let Some(events) = envelope.get("data").and_then(serde_json::Value::as_array) else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = events
        .iter()
        .map(format_cloud_run_output_event)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Run Events"), "Event", &rows);
    Ok(())
}

fn format_cloud_run_output_event(envelope: &serde_json::Value) -> String {
    let sequence = json_scalar_field(envelope, "sequence_number");
    let kind = json_string_field(envelope, "kind");
    let event_type = json_string_field(envelope, "event_type");
    let item_id = json_string_field(envelope, "item_id");
    let event = envelope.get("event").unwrap_or(&serde_json::Value::Null);
    let code = json_string_field(event, "code");
    let retryable = json_bool_field(event, "retryable");
    let tool = json_string_field(event, "name");
    let event_id = json_string_field(event, "id");
    let status = json_string_field(event, "status");
    let summary = summarize_cloud_run_output_event(event);

    let mut parts = Vec::new();
    if sequence != "-" {
        parts.push(format!("#{sequence}"));
    }
    parts.push(if kind != "-" {
        kind
    } else if event_type != "-" {
        event_type
    } else {
        "event".to_string()
    });
    if status != "-" {
        parts.push(format!("status={status}"));
    }
    if event_id != "-" {
        parts.push(format!("id={event_id}"));
    } else if item_id != "-" {
        parts.push(format!("item={item_id}"));
    }
    if tool != "-" {
        parts.push(format!("tool={tool}"));
    }
    if code != "-" {
        parts.push(format!("code={code}"));
    }
    if retryable == "yes" {
        parts.push("retryable=yes".to_string());
    }
    if !summary.is_empty() {
        parts.push(format!("summary={}", truncate_for_cli(&summary, 180)));
    }

    parts.join(" ")
}

fn summarize_cloud_run_output_event(event: &serde_json::Value) -> String {
    for key in ["message", "text", "content", "reason"] {
        if let Some(value) = event.get(key).and_then(json_value_to_string) {
            return value;
        }
    }

    if let Some(details) = event.get("details").and_then(json_value_to_string) {
        return details;
    }

    String::new()
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

fn parse_conversation_message_order(
    value: Option<&str>,
) -> Result<Option<seren::ConversationMessageOrder>> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("asc") => Ok(Some(seren::ConversationMessageOrder::Asc)),
        Some("desc") => Ok(Some(seren::ConversationMessageOrder::Desc)),
        Some(other) => Err(anyhow::anyhow!(
            "Invalid --order '{}'. Expected asc or desc.",
            other
        )),
        None => Ok(None),
    }
}

pub async fn cloud_conversations(
    deployment_id: Uuid,
    limit: i64,
    cursor: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_list_conversations(
            &deployment_id,
            cursor.map(str::trim).filter(|value| !value.is_empty()),
            Some(limit),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list conversations: {}", e))?
        .into_inner();
    print_cloud_conversations_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_conversation_messages(
    deployment_id: Uuid,
    conversation_id: &str,
    limit: i64,
    cursor: Option<&str>,
    order: Option<&str>,
    include_run: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let conversation_id = conversation_id.trim();
    if conversation_id.is_empty() {
        return Err(anyhow::anyhow!("conversation_id cannot be empty."));
    }

    let order = parse_conversation_message_order(order)?;
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_conversation_messages(
            &deployment_id,
            conversation_id,
            cursor.map(str::trim).filter(|value| !value.is_empty()),
            include_run,
            Some(limit),
            order,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list conversation messages: {}", e))?
        .into_inner();
    print_cloud_conversation_messages_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_conversations_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let data = envelope.get("data").unwrap_or(&envelope);
    let Some(conversations) = data
        .get("conversations")
        .and_then(serde_json::Value::as_array)
    else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = conversations
        .iter()
        .map(format_cloud_conversation)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Conversations"), "Conversation", &rows);
    print_next_cursor_hint(data);
    Ok(())
}

fn print_cloud_conversation_messages_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let data = envelope.get("data").unwrap_or(&envelope);
    let Some(messages) = data.get("messages").and_then(serde_json::Value::as_array) else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = messages
        .iter()
        .map(format_cloud_conversation_message)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Conversation Messages"), "Message", &rows);
    print_next_cursor_hint(data);
    Ok(())
}

fn print_next_cursor_hint(data: &serde_json::Value) {
    let has_more = data
        .get("has_more")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !has_more {
        return;
    }
    if let Some(cursor) = data
        .get("next_cursor")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        println!();
        println!("Next cursor: {cursor}");
    }
}

fn format_cloud_conversation(conversation: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(conversation_id) = conversation
        .get("conversation_id")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("id={conversation_id}"));
    }
    if let Some(title) = conversation
        .get("title")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("title={}", compact_preview_for_cli(title, 80)));
    }
    if let Some(count) = conversation
        .get("message_count")
        .and_then(json_value_to_string)
    {
        parts.push(format!("messages={count}"));
    }
    if let Some(source) = conversation
        .get("last_source")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("source={source}"));
    }
    if let Some(last_activity) = conversation
        .get("last_activity_at")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("last={last_activity}"));
    }
    parts.join(" ")
}

fn format_cloud_conversation_message(message: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(created_at) = message
        .get("created_at")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(created_at.to_string());
    }
    if let Some(role) = message.get("role").and_then(serde_json::Value::as_str) {
        parts.push(format!("role={role}"));
    }
    if let Some(source) = message.get("source").and_then(serde_json::Value::as_str) {
        parts.push(format!("source={source}"));
    }
    if let Some(run_id) = message
        .get("run_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            message
                .get("run_summary")
                .and_then(|summary| summary.get("run_id"))
                .and_then(serde_json::Value::as_str)
        })
    {
        parts.push(format!("run={run_id}"));
    }
    if let Some(status) = message
        .get("run_summary")
        .and_then(|summary| summary.get("status"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            message
                .get("run")
                .and_then(|run| run.get("status"))
                .and_then(serde_json::Value::as_str)
        })
    {
        parts.push(format!("status={status}"));
    }
    if let Some(events) = message.get("events").and_then(serde_json::Value::as_array)
        && !events.is_empty()
    {
        parts.push(format!("events={}", events.len()));
    }
    if let Some(content) = message
        .get("content")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("content={}", compact_preview_for_cli(content, 180)));
    }
    parts.join(" ")
}

pub async fn cloud_deployment_run_state(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_state(&deployment_id, &run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load run state: {}", e))?
        .into_inner();
    print_cloud_run_state_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_run_state(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_state(&run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load run state: {}", e))?
        .into_inner();
    print_cloud_run_state_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_run_state_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let state = envelope.get("data").unwrap_or(&envelope);
    if !state.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    let rows = cloud_run_state_rows(state);
    output::print_key_value_table(Some("Run State"), &rows);
    Ok(())
}

fn cloud_run_state_rows(state: &serde_json::Value) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    push_json_row(&mut rows, "Run ID", state.get("run_id"));
    push_json_row(&mut rows, "Deployment ID", state.get("deployment_id"));
    push_json_row(&mut rows, "Status", state.get("status"));
    push_json_row(&mut rows, "Phase", state.get("phase"));
    push_json_row(&mut rows, "Current Step", state.get("current_step"));
    push_json_row(&mut rows, "Current Tool", state.get("current_tool"));
    push_json_row(
        &mut rows,
        "Pending Approvals",
        state.get("pending_approval_count"),
    );
    push_json_row(&mut rows, "Checkpoint ID", state.get("checkpoint_id"));
    push_json_row(&mut rows, "Latest Sequence", state.get("latest_sequence"));
    push_json_row(&mut rows, "Latest Event", state.get("latest_event_kind"));
    push_json_row(&mut rows, "Terminal", state.get("terminal"));
    push_json_row(&mut rows, "Status Message", state.get("status_message"));
    push_json_row(&mut rows, "Started", state.get("started_at"));
    push_json_row(&mut rows, "Updated", state.get("updated_at"));
    rows
}

pub async fn cloud_agent_schedules(
    deployment_id: Uuid,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_list_agent_schedules(&deployment_id, Some(limit), Some(offset))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list agent schedules: {}", e))?
        .into_inner();
    print_cloud_agent_schedules_response(&response, ctx)?;
    Ok(())
}

pub struct CloudAgentScheduleCreateOptions<'a> {
    pub deployment_id: Uuid,
    pub schedule_key: Option<&'a str>,
    pub message: Option<&'a str>,
    pub payload_json: Option<&'a str>,
    pub payload_file: Option<&'a str>,
    pub conversation_id: Option<&'a str>,
    pub run_at: Option<&'a str>,
    pub delay_seconds: Option<i64>,
    pub cron: Option<&'a str>,
    pub timezone: Option<&'a str>,
    pub max_attempts: Option<i32>,
}

pub async fn cloud_agent_schedule_create(
    options: CloudAgentScheduleCreateOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    let payload =
        parse_optional_json_value("--payload", options.payload_json, options.payload_file)?;
    let run_at = options
        .run_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(jiff::Timestamp::from_str)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid --run-at timestamp: {}", e))?;
    let request = seren::CloudDeploymentAgentScheduleRequest {
        conversation_id: options
            .conversation_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        cron: options
            .cron
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        delay_seconds: options.delay_seconds,
        max_attempts: options.max_attempts,
        message: options
            .message
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        payload,
        run_at,
        schedule_key: options
            .schedule_key
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        timezone: options
            .timezone
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
    };

    let client = ctx.client().await?;
    let response = client
        .seren_cloud_create_agent_schedule(&options.deployment_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create agent schedule: {}", e))?
        .into_inner();
    print_cloud_agent_schedule_response(&response, "Agent Schedule", ctx)?;
    Ok(())
}

pub async fn cloud_agent_schedule_cancel(
    deployment_id: Uuid,
    schedule_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_cancel_agent_schedule(&deployment_id, &schedule_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to cancel agent schedule: {}", e))?
        .into_inner();
    print_cloud_agent_schedule_response(&response, "Cancelled Agent Schedule", ctx)?;
    Ok(())
}

fn print_cloud_agent_schedules_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let Some(schedules) = envelope.get("data").and_then(serde_json::Value::as_array) else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = schedules
        .iter()
        .map(format_cloud_agent_schedule)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Agent Schedules"), "Schedule", &rows);
    Ok(())
}

fn print_cloud_agent_schedule_response<T: serde::Serialize>(
    response: &T,
    title: &'static str,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let schedule = envelope.get("data").unwrap_or(&envelope);
    if !schedule.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    let rows = cloud_agent_schedule_rows(schedule);
    output::print_key_value_table(Some(title), &rows);
    Ok(())
}

fn format_cloud_agent_schedule(schedule: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(id) = schedule.get("id").and_then(serde_json::Value::as_str) {
        parts.push(format!("id={id}"));
    }
    if let Some(key) = schedule
        .get("schedule_key")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("key={key}"));
    }
    if let Some(kind) = schedule
        .get("schedule_kind")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("kind={kind}"));
    }
    if let Some(status) = schedule.get("status").and_then(serde_json::Value::as_str) {
        parts.push(format!("status={status}"));
    }
    if let Some(next_run_at) = schedule
        .get("next_run_at")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("next={next_run_at}"));
    }
    if let Some(cron) = schedule
        .get("cron_schedule")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("cron={cron}"));
    }
    if let Some(timezone) = schedule
        .get("cron_timezone")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("tz={timezone}"));
    }
    let attempts = json_number_field(schedule, "attempts");
    let max_attempts = json_number_field(schedule, "max_attempts");
    if attempts != "-" || max_attempts != "-" {
        parts.push(format!("attempts={attempts}/{max_attempts}"));
    }
    if let Some(last_error) = schedule
        .get("last_error")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!(
            "error={}",
            compact_preview_for_cli(last_error, 100)
        ));
    }
    parts.join(" ")
}

fn cloud_agent_schedule_rows(schedule: &serde_json::Value) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    push_json_row(&mut rows, "Schedule ID", schedule.get("id"));
    push_json_row(&mut rows, "Deployment ID", schedule.get("deployment_id"));
    push_json_row(&mut rows, "Schedule Key", schedule.get("schedule_key"));
    push_json_row(&mut rows, "Kind", schedule.get("schedule_kind"));
    push_json_row(&mut rows, "Status", schedule.get("status"));
    push_json_row(&mut rows, "Next Run", schedule.get("next_run_at"));
    push_json_row(&mut rows, "Cron", schedule.get("cron_schedule"));
    push_json_row(&mut rows, "Timezone", schedule.get("cron_timezone"));
    push_json_row(&mut rows, "Attempts", schedule.get("attempts"));
    push_json_row(&mut rows, "Max Attempts", schedule.get("max_attempts"));
    push_json_row(&mut rows, "Last Run", schedule.get("last_run_at"));
    push_json_row(
        &mut rows,
        "Last Run Event",
        schedule.get("last_run_event_id"),
    );
    push_json_row(&mut rows, "Last Error", schedule.get("last_error"));
    push_json_row(&mut rows, "Created", schedule.get("created_at"));
    push_json_row(&mut rows, "Updated", schedule.get("updated_at"));
    rows
}

/// Stream updates for a run via SSE (global run path).
///
/// Supports event replay (`Last-Event-ID`) for resumable clients.
pub async fn cloud_run_stream(
    run_id: Uuid,
    last_event_id: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let url = format!(
        "{}/publishers/seren-cloud/runs/{}/stream",
        ctx.api_base(),
        run_id
    );
    cloud_run_stream_url(&url, run_id, last_event_id, ctx).await
}

/// Stream updates for a deployment-scoped run via SSE.
///
/// Uses raw HTTP so callers can pass SSE resume headers that are not exposed by
/// the generated stream method.
pub async fn cloud_deployment_run_stream(
    deployment_id: Uuid,
    run_id: Uuid,
    last_event_id: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let url = format!(
        "{}/publishers/seren-cloud/deployments/{}/runs/{}/stream",
        ctx.api_base(),
        deployment_id,
        run_id
    );
    cloud_run_stream_url(&url, run_id, last_event_id, ctx).await
}

async fn cloud_run_stream_url(
    url: &str,
    run_id: Uuid,
    last_event_id: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    use futures_util::StreamExt;

    let client = ctx.http_client().await?;

    let mut request = client.get(url).header("Accept", "text/event-stream");
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

pub async fn cloud_audit_list(
    action: Option<&str>,
    limit: i64,
    offset: i64,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_list_audit_entries(action, Some(limit), Some(offset), q)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list cloud audit entries: {}", e))?
        .into_inner();
    print_cloud_audit_entries_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_audit_get(entry_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_audit_entry(&entry_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get cloud audit entry: {}", e))?
        .into_inner();
    print_cloud_audit_entry_response(&response, ctx)?;
    Ok(())
}

pub async fn cloud_audit_verify(limit: Option<i64>, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_verify_audit(limit)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify cloud audit chain: {}", e))?
        .into_inner();
    print_cloud_audit_verify_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_audit_entries_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let Some(entries) = envelope.get("data").and_then(serde_json::Value::as_array) else {
        output::print_json(response)?;
        return Ok(());
    };

    let rows = entries
        .iter()
        .map(format_cloud_audit_entry)
        .collect::<Vec<_>>();
    output::print_list_table(Some("Cloud Audit Entries"), "Entry", &rows);
    Ok(())
}

fn print_cloud_audit_entry_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let entry = envelope.get("data").unwrap_or(&envelope);
    if !entry.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    output::print_key_value_table(Some("Cloud Audit Entry"), &cloud_audit_entry_rows(entry));
    Ok(())
}

fn print_cloud_audit_verify_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let result = envelope.get("data").unwrap_or(&envelope);
    if !result.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    output::print_key_value_table(
        Some("Cloud Audit Verification"),
        &cloud_audit_verify_rows(result),
    );
    Ok(())
}

fn format_cloud_audit_entry(entry: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(sequence) = entry.get("sequence_number").and_then(json_value_to_string) {
        parts.push(format!("#{sequence}"));
    }
    if let Some(action) = entry.get("action").and_then(serde_json::Value::as_str) {
        parts.push(format!("action={action}"));
    }
    if let Some(actor) = entry.get("actor").and_then(serde_json::Value::as_str) {
        parts.push(format!("actor={actor}"));
    }
    if let Some(id) = entry.get("id").and_then(serde_json::Value::as_str) {
        parts.push(format!("id={id}"));
    }
    if let Some(invocation_id) = entry
        .get("invocation_id")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("invocation={invocation_id}"));
    }
    if let Some(publisher_id) = entry
        .get("publisher_id")
        .and_then(serde_json::Value::as_str)
    {
        parts.push(format!("publisher={publisher_id}"));
    }
    if let Some(created_at) = entry.get("created_at").and_then(serde_json::Value::as_str) {
        parts.push(format!("created={created_at}"));
    }
    parts.join(" ")
}

fn cloud_audit_entry_rows(entry: &serde_json::Value) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    push_json_row(&mut rows, "Entry ID", entry.get("id"));
    push_json_row(&mut rows, "Sequence", entry.get("sequence_number"));
    push_json_row(&mut rows, "Action", entry.get("action"));
    push_json_row(&mut rows, "Actor", entry.get("actor"));
    push_json_row(&mut rows, "Invocation ID", entry.get("invocation_id"));
    push_json_row(&mut rows, "Publisher ID", entry.get("publisher_id"));
    push_json_row(&mut rows, "Created", entry.get("created_at"));
    rows
}

fn cloud_audit_verify_rows(result: &serde_json::Value) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    push_json_row(&mut rows, "Verified", result.get("verified"));
    push_json_row(&mut rows, "Entries Checked", result.get("entries_checked"));
    push_json_row(
        &mut rows,
        "First Invalid Sequence",
        result.get("first_invalid_sequence"),
    );
    push_json_row(&mut rows, "Error", result.get("error"));
    rows
}

pub async fn cloud_deployment_spend(deployment_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_get_deployment_spend(&deployment_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get deployment spend: {}", e))?
        .into_inner();
    print_cloud_deployment_spend_response(&response, ctx)?;
    Ok(())
}

fn print_cloud_deployment_spend_response<T: serde::Serialize>(
    response: &T,
    ctx: &CommandContext,
) -> Result<()> {
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(response)?;
        return Ok(());
    }

    let envelope = serde_json::to_value(response)?;
    let spend = envelope.get("data").unwrap_or(&envelope);
    if !spend.is_object() {
        output::print_json(response)?;
        return Ok(());
    }

    output::print_key_value_table(
        Some("Deployment Spend"),
        &cloud_deployment_spend_rows(spend),
    );
    Ok(())
}

fn cloud_deployment_spend_rows(spend: &serde_json::Value) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    push_json_row(&mut rows, "Total Cost USD", spend.get("total_cost_usd"));
    push_json_row(&mut rows, "Compute Cost USD", spend.get("compute_cost_usd"));
    push_json_row(
        &mut rows,
        "Inference Cost USD",
        spend.get("inference_cost_usd"),
    );
    push_json_row(&mut rows, "Run Count", spend.get("run_count"));
    push_json_row(&mut rows, "First Event", spend.get("first_event_at"));
    push_json_row(&mut rows, "Last Event", spend.get("last_event_at"));
    rows
}

pub async fn cloud_deployment_audit(
    deployment_id: Uuid,
    action: Option<&str>,
    limit: i64,
    offset: i64,
    q: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_audit(&deployment_id, action, Some(limit), Some(offset), q)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list deployment audit entries: {}", e))?
        .into_inner();
    print_cloud_audit_entries_response(&response, ctx)?;
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
            None,
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

    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(&response)?;
        return Ok(());
    }

    let data = serde_json::to_value(&response)?;
    if let Some(runs) = data.get("data").and_then(|d| d.as_array()) {
        print_cloud_run_rows(
            runs,
            false,
            &format!("No runs found for deployment {}.", deployment_id),
        )?;
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
    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_cloud_run_detail_response(&response)?,
    }
    Ok(())
}

fn print_cloud_run_detail_response<T: serde::Serialize>(response: &T) -> Result<()> {
    let envelope = serde_json::to_value(response)?;
    let run = envelope.get("data").unwrap_or(&envelope);
    let Some(run_obj) = run.as_object() else {
        output::print_json(response)?;
        return Ok(());
    };

    let mut summary = Vec::new();
    push_json_row(&mut summary, "Run ID", run_obj.get("id"));
    push_json_row(&mut summary, "Deployment ID", run_obj.get("deployment_id"));
    push_json_row(&mut summary, "Status", run_obj.get("status"));
    push_json_row(
        &mut summary,
        "Status Message",
        run_obj.get("status_message"),
    );
    push_json_row(&mut summary, "Stop Reason", run_obj.get("stop_reason"));
    push_json_row(&mut summary, "Execution ID", run_obj.get("execution_id"));
    push_json_row(&mut summary, "Backend", run_obj.get("compute_backend"));
    push_json_row(&mut summary, "Source", run_obj.get("source"));
    push_json_row(&mut summary, "Started", run_obj.get("started_at"));
    push_json_row(&mut summary, "Completed", run_obj.get("completed_at"));
    push_json_row(
        &mut summary,
        "Duration (ms)",
        run_obj.get("execution_time_ms"),
    );
    push_json_row(
        &mut summary,
        "Billed (ms)",
        run_obj.get("billed_duration_ms"),
    );
    push_json_row(
        &mut summary,
        "Compute Cost (USD)",
        run_obj.get("compute_cost_usd"),
    );
    push_json_row(
        &mut summary,
        "Input Tokens",
        run_obj.get("inference_input_tokens"),
    );
    push_json_row(
        &mut summary,
        "Output Tokens",
        run_obj.get("inference_output_tokens"),
    );
    push_json_row(
        &mut summary,
        "Inference Cost (USD)",
        run_obj.get("inference_cost_usd"),
    );
    push_json_row(&mut summary, "Session ID", run_obj.get("session_id"));
    push_json_row(&mut summary, "Session URL", run_obj.get("session_url"));
    push_json_row(
        &mut summary,
        "Conversation ID",
        run_obj.get("conversation_id"),
    );

    output::print_key_value_table(Some("Run Summary"), &summary);

    let trace_rows = metadata_section_rows(
        run_obj,
        "trace_context",
        &[
            ("Request ID", "request_id"),
            ("Phase", "phase"),
            ("Job", "job_name"),
            ("Script", "script_name"),
            ("Sandbox", "sandbox_id"),
            ("Orchestrator Run", "orchestrator_run_id"),
            ("Wakeup ID", "managed_wakeup_request_id"),
            ("Wakeup Source", "managed_wakeup_source"),
            ("Wakeup Reason", "managed_wakeup_reason"),
        ],
    );
    if !trace_rows.is_empty() {
        println!();
        output::print_key_value_table(Some("Trace Context"), &trace_rows);
    }

    let provenance_rows = metadata_section_rows(
        run_obj,
        "provenance",
        &[
            ("Output Bytes", "output_bytes"),
            ("Event Count", "output_events_count"),
            ("Event Bytes", "output_events_bytes"),
            ("Output SHA256", "output_sha256"),
            ("Events SHA256", "output_events_sha256"),
            ("Kinds", "output_events_kind_counts"),
        ],
    );
    if !provenance_rows.is_empty() {
        println!();
        output::print_key_value_table(Some("Output Capture"), &provenance_rows);
    }

    let eval_capture_rows = metadata_section_rows(
        run_obj,
        "eval_capture",
        &[
            ("Event Count", "event_count"),
            ("Trajectory", "trajectory"),
            ("Tool Calls", "tool_call_sequence"),
            ("Workflow States", "workflow_states"),
            ("Text Segments", "text_segment_count"),
            ("Thinking Segments", "thinking_segment_count"),
            ("Tool Results", "tool_result_count"),
            ("Tool Result Errors", "tool_result_error_count"),
            ("Errors", "error_count"),
            ("Final Text SHA256", "final_text_sha256"),
            ("Final Text Bytes", "final_text_bytes"),
        ],
    );
    if !eval_capture_rows.is_empty() {
        println!();
        output::print_key_value_table(Some("Eval Capture"), &eval_capture_rows);
    }

    Ok(())
}

fn metadata_section_rows(
    run: &serde_json::Map<String, serde_json::Value>,
    section: &str,
    fields: &[(&'static str, &'static str)],
) -> Vec<(&'static str, String)> {
    let Some(section_obj) = run
        .get("metadata")
        .and_then(|value| value.get(section))
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };

    let mut rows = Vec::new();
    for (label, key) in fields {
        if let Some(value) = section_obj.get(*key).and_then(json_value_to_string) {
            rows.push((*label, value));
        }
    }
    rows
}

fn push_json_row(
    rows: &mut Vec<(&'static str, String)>,
    label: &'static str,
    value: Option<&serde_json::Value>,
) {
    if let Some(value) = value.and_then(json_value_to_string) {
        rows.push((label, value));
    }
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::Bool(flag) => Some(flag.to_string()),
        serde_json::Value::Array(items) => {
            let rendered = items
                .iter()
                .filter_map(json_value_to_string)
                .collect::<Vec<_>>()
                .join(", ");
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
        serde_json::Value::Object(object) => {
            let rendered = object
                .iter()
                .filter_map(|(key, value)| {
                    json_value_to_string(value).map(|value| format!("{key}={value}"))
                })
                .collect::<Vec<_>>()
                .join(", ");
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
    }
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
    let deployments_value = serde_json::to_value(
        client
            .seren_cloud_list_deployments()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load deployments: {}", e))?
            .into_inner(),
    )?;
    let deployment_names = build_deployment_name_map(
        &deployments_value
            .get("data")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default(),
    );
    let response = client
        .seren_cloud_runs(
            options.compute_backend,
            None,
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

    let enriched_response = enrich_data_envelope_with_deployment_names(
        &serde_json::to_value(&response)?,
        &deployment_names,
    );
    if matches!(ctx.format, OutputFormat::Json) {
        output::print_json(&enriched_response)?;
        return Ok(());
    }

    if let Some(runs) = enriched_response.get("data").and_then(|d| d.as_array()) {
        print_cloud_run_rows(runs, true, "No runs found.")?;
    } else {
        output::print_json(&enriched_response)?;
    }

    Ok(())
}

pub async fn cloud_pending_approvals(limit: i64, offset: i64, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let deployments_value = serde_json::to_value(
        client
            .seren_cloud_list_deployments()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load deployments: {}", e))?
            .into_inner(),
    )?;
    let deployment_names = build_deployment_name_map(
        &deployments_value
            .get("data")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default(),
    );
    let response = client
        .seren_cloud_pending_approvals(
            None,
            None,
            Some(limit),
            Some(offset),
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();
    let enriched_response = enrich_data_envelope_with_deployment_names(
        &serde_json::to_value(&response)?,
        &deployment_names,
    );

    match ctx.format {
        OutputFormat::Json => output::print_json(&enriched_response)?,
        OutputFormat::Table => print_pending_approval_runs_table(&enriched_response, None)?,
    }

    Ok(())
}

pub async fn cloud_deployment_pending_approvals(
    deployment_id: Uuid,
    limit: i64,
    offset: i64,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_pending_approvals(
            &deployment_id,
            None,
            None,
            Some(limit),
            Some(offset),
            None,
            None,
            None,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_pending_approval_runs_table(&response, Some(deployment_id))?,
    }

    Ok(())
}

pub async fn cloud_run_pending_approvals(run_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_run_pending_approvals(&run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_run_pending_approvals_response(&response)?,
    }

    Ok(())
}

pub async fn cloud_deployment_run_pending_approvals(
    deployment_id: Uuid,
    run_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .seren_cloud_deployment_run_pending_approvals(&deployment_id, &run_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_run_pending_approvals_response(&response)?,
    }

    Ok(())
}

fn print_pending_approval_runs_table<T: serde::Serialize>(
    response: &T,
    deployment_scope: Option<Uuid>,
) -> Result<()> {
    let envelope = serde_json::to_value(response)?;
    let Some(runs) = envelope.get("data").and_then(|value| value.as_array()) else {
        output::print_json(response)?;
        return Ok(());
    };

    if runs.is_empty() {
        match deployment_scope {
            Some(deployment_id) => {
                println!(
                    "No pending approvals found for deployment {}.",
                    deployment_id
                );
            }
            None => println!("No pending approvals found."),
        }
        return Ok(());
    }

    println!(
        "{:<38} {:<38} {:<18} {:<8} {:<28}",
        "RUN ID", "DEPLOYMENT", "STATUS", "COUNT", "TOOLS"
    );
    for run in runs {
        let approvals = run
            .get("pending_approvals")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        let tools = approvals
            .iter()
            .filter_map(|approval| approval.get("tool").and_then(|value| value.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<38} {:<38} {:<18} {:<8} {:<28}",
            run.get("run_id")
                .and_then(|value| value.as_str())
                .unwrap_or("-"),
            run.get("deployment_name")
                .and_then(|value| value.as_str())
                .or_else(|| run.get("deployment_id").and_then(|value| value.as_str()))
                .unwrap_or("-"),
            run.get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("-"),
            approvals.len(),
            truncate_for_cli(&tools, 28),
        );
    }

    Ok(())
}

fn print_cloud_run_rows(
    runs: &[serde_json::Value],
    include_deployment: bool,
    empty_message: &str,
) -> Result<()> {
    if runs.is_empty() {
        println!("{empty_message}");
        return Ok(());
    }

    if include_deployment {
        println!(
            "{:<38} {:<38} {:<14} {:<10} {:<10} {:<24}",
            "RUN ID", "DEPLOYMENT", "STATUS", "TIME(ms)", "COST", "STARTED"
        );
        for execution in runs {
            println!(
                "{:<38} {:<38} {:<14} {:<10} {:<10} {:<24}",
                execution.get("id").and_then(|v| v.as_str()).unwrap_or("-"),
                execution
                    .get("deployment_name")
                    .and_then(|v| v.as_str())
                    .or_else(|| execution.get("deployment_id").and_then(|v| v.as_str()))
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
    }

    Ok(())
}

fn print_run_pending_approvals_response<T: serde::Serialize>(response: &T) -> Result<()> {
    let envelope = serde_json::to_value(response)?;
    let data = envelope.get("data").unwrap_or(&envelope);
    let Some(run_obj) = data.as_object() else {
        output::print_json(response)?;
        return Ok(());
    };

    let mut summary = Vec::new();
    push_json_row(&mut summary, "Run ID", run_obj.get("run_id"));
    push_json_row(&mut summary, "Status", run_obj.get("status"));
    output::print_key_value_table(Some("Pending Approval State"), &summary);

    let approvals = run_obj
        .get("pending_approvals")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    if approvals.is_empty() {
        println!();
        println!("No pending approvals.");
        return Ok(());
    }

    println!();
    println!(
        "{:<38} {:<24} {:<20} {:<32}",
        "APPROVAL ID", "TOOL", "CALL ID", "REASON"
    );
    for approval in approvals {
        println!(
            "{:<38} {:<24} {:<20} {:<32}",
            approval
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("-"),
            approval
                .get("tool")
                .and_then(|value| value.as_str())
                .unwrap_or("-"),
            approval
                .get("function_call_id")
                .and_then(|value| value.as_str())
                .unwrap_or("-"),
            truncate_for_cli(
                approval
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("-"),
                32,
            ),
        );
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

pub struct CloudUpdateConfigOptions<'a> {
    pub config_path: Option<&'a str>,
    pub env_path: Option<&'a str>,
    pub alert_policy_path: Option<&'a str>,
    pub clear_alert_policy: bool,
    pub network_policy_path: Option<&'a str>,
    pub clear_network_policy: bool,
    pub eval_gate_set_id: Option<Uuid>,
    pub eval_gate_max_age_seconds: Option<i32>,
    pub clear_eval_gate: bool,
}

/// Update config and/or secrets for a cloud agent without redeploying.
pub async fn cloud_update_config(
    deployment_id: Uuid,
    options: CloudUpdateConfigOptions<'_>,
    ctx: &CommandContext,
) -> Result<()> {
    if options.config_path.is_none()
        && options.env_path.is_none()
        && options.alert_policy_path.is_none()
        && !options.clear_alert_policy
        && options.network_policy_path.is_none()
        && !options.clear_network_policy
        && options.eval_gate_set_id.is_none()
        && options.eval_gate_max_age_seconds.is_none()
        && !options.clear_eval_gate
    {
        return Err(anyhow::anyhow!(
            "Provide at least one of --config, --env, --alert-policy, --clear-alert-policy, --network-policy, --clear-network-policy, --eval-gate-set-id, --eval-gate-max-age-seconds, or --clear-eval-gate."
        ));
    }

    if options.config_path.is_some()
        || options.env_path.is_some()
        || options.network_policy_path.is_some()
        || options.clear_network_policy
    {
        return Err(anyhow::anyhow!(
            "config, secrets, and network_policy are workload-level fields and cannot be changed through this cloud settings helper. Redeploy the cloud agent with the new bundle and config, or use the managed-agent update path for managed seren-agent deployments.",
        ));
    }

    let alert_policy = options
        .alert_policy_path
        .map(parse_json_file)
        .transpose()?
        .map(serde_json::from_value::<seren::CloudDeploymentAlertPolicy>)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid alert policy: {}", e))?;
    let eval_gate = match (
        options.eval_gate_set_id,
        options.eval_gate_max_age_seconds,
        options.clear_eval_gate,
    ) {
        (Some(set_id), Some(max_age_seconds), false) => Some(seren::EvalGate {
            block_on_failure: None,
            drift_baseline: None,
            max_age_seconds,
            schedule: None,
            set_id,
        }),
        (None, None, _) => None,
        (Some(_), None, false) => {
            return Err(anyhow::anyhow!(
                "--eval-gate-max-age-seconds is required with --eval-gate-set-id."
            ));
        }
        (None, Some(_), false) => {
            return Err(anyhow::anyhow!(
                "--eval-gate-set-id is required with --eval-gate-max-age-seconds."
            ));
        }
        (Some(_), _, true) | (_, Some(_), true) => {
            return Err(anyhow::anyhow!(
                "Provide either --clear-eval-gate or --eval-gate-set-id plus --eval-gate-max-age-seconds, not both."
            ));
        }
    };

    let client = ctx.client().await?;
    let request = seren::UpdateCloudDeploymentRequest {
        alert_policy,
        clear_alert_policy: Some(options.clear_alert_policy),
        clear_dashboard_config: None,
        clear_eval_gate: Some(options.clear_eval_gate),
        dashboard_config: None,
        eval_gate,
        visibility: None,
    };
    client
        .seren_cloud_update_config(&deployment_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed: {}", e))?;

    println!(
        "{} Deployment settings updated for {}.",
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

fn parse_json_file(path: &str) -> Result<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read JSON file '{}': {}", path, e))?;
    serde_json::from_str(&content).map_err(|e| anyhow::anyhow!("Invalid JSON in '{}': {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_run_payload_selects_organization_context() {
        let knowledge_selection_id = Uuid::new_v4();
        let payload = build_cloud_run_payload(&CloudRunOptions {
            message: Some("Review the launch plan"),
            organization: true,
            knowledge_selection_id: Some(knowledge_selection_id),
            task_label: Some("product.launch"),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            payload["collaboration"]["invocation_origin"]["kind"],
            "direct"
        );
        assert_eq!(
            payload["collaboration"]["knowledge_selection"],
            serde_json::json!({
                "kind": "organization",
                "provider": "memory",
                "selection_id": knowledge_selection_id,
            })
        );
        assert_eq!(
            payload["collaboration"]["knowledge_capture_target"]["kind"],
            "none"
        );
        assert_eq!(payload["collaboration"]["task_label"], "product.launch");
        assert_eq!(
            payload["collaboration"]["output_audience"]["kind"],
            "organization"
        );
        assert_eq!(payload["message"], "Review the launch plan");
    }

    #[test]
    fn cloud_run_payload_requires_organization_for_shared_context() {
        let error = build_cloud_run_payload(&CloudRunOptions {
            knowledge_selection_id: Some(Uuid::new_v4()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(error.to_string().contains("require --organization"));
    }

    #[test]
    fn cloud_run_payload_keeps_individual_runs_implicit() {
        let payload = build_cloud_run_payload(&CloudRunOptions {
            message: Some("Hello"),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert!(payload.get("collaboration").is_none());
    }

    #[test]
    fn merge_managed_agent_config_accepts_runtime_policy() {
        let mut body = serde_json::Map::new();
        let runtime_policy = serde_json::json!({
            "network": {
                "default": "deny",
                "egress_rules": [{
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                    "enforcement": "enforce"
                }]
            }
        });
        let agent_config =
            serde_json::Map::from_iter([("runtime_policy".to_string(), runtime_policy.clone())]);

        merge_managed_agent_config(&mut body, agent_config).unwrap();

        assert_eq!(body.get("runtime_policy"), Some(&runtime_policy));
    }

    #[test]
    fn merge_managed_agent_config_accepts_requirements_txt() {
        let mut body = serde_json::Map::new();
        let requirements_txt = serde_json::json!("httpx==0.28.1");
        let agent_config = serde_json::Map::from_iter([(
            "requirements_txt".to_string(),
            requirements_txt.clone(),
        )]);

        merge_managed_agent_config(&mut body, agent_config).unwrap();

        assert_eq!(body.get("requirements_txt"), Some(&requirements_txt));
    }

    #[test]
    fn clear_requirements_txt_conflicts_with_replacement_content() {
        let mut body = serde_json::Map::from_iter([(
            "requirements_txt".to_string(),
            serde_json::json!("httpx==0.28.1"),
        )]);

        let error = apply_requirements_txt_clear(&mut body, true)
            .expect_err("requirements content and clearing must be mutually exclusive");

        assert!(error.to_string().contains("--clear-requirements-txt"));
    }

    #[test]
    fn workload_replacement_requires_existing_secrets_to_be_explicit() {
        let secret_keys = vec!["DATABASE_URL".to_string()];
        let mut body = serde_json::Map::new();
        assert!(require_explicit_replacement_secrets(&secret_keys, &body).is_err());

        body.insert("secrets".to_string(), serde_json::json!({}));
        assert!(require_explicit_replacement_secrets(&secret_keys, &body).is_ok());
    }

    #[test]
    fn managed_agent_rollback_request_preserves_security_preconditions() {
        let revision_id = Uuid::new_v4();
        let expected_active_revision_id = Uuid::new_v4();
        let secret_resolution_result_id = Uuid::new_v4();

        let request = build_managed_agent_rollback_request(
            revision_id,
            Some(expected_active_revision_id),
            Some(secret_resolution_result_id),
        );

        assert_eq!(request.revision_id, revision_id);
        assert_eq!(
            request.expected_active_revision_id,
            Some(expected_active_revision_id)
        );
        assert_eq!(
            request.secret_resolution_result_id,
            Some(secret_resolution_result_id)
        );
    }

    #[test]
    fn build_deployment_name_map_prefers_name_then_skill_slug() {
        let deployments = vec![
            serde_json::json!({
                "id": "dep-1",
                "name": "Ops Router",
                "skill_slug": "ops-router"
            }),
            serde_json::json!({
                "id": "dep-2",
                "skill_slug": "btc-watcher"
            }),
        ];

        let map = build_deployment_name_map(&deployments);
        assert_eq!(map.get("dep-1").map(String::as_str), Some("Ops Router"));
        assert_eq!(map.get("dep-2").map(String::as_str), Some("btc-watcher"));
    }

    #[test]
    fn enrich_data_envelope_with_deployment_names_adds_deployment_name_field() {
        let deployment_names = HashMap::from([("dep-123".to_string(), "BTC Watcher".to_string())]);
        let envelope = serde_json::json!({
            "data": [
                {
                    "id": "run-1",
                    "deployment_id": "dep-123",
                    "status": "running"
                }
            ]
        });

        let enriched = enrich_data_envelope_with_deployment_names(&envelope, &deployment_names);
        let first = &enriched["data"][0];
        assert_eq!(first["deployment_name"], "BTC Watcher");
        assert_eq!(first["deployment_id"], "dep-123");
    }

    #[test]
    fn publisher_skill_doc_url_builds_seren_cloud_path() {
        let url = publisher_skill_doc_url("https://api.serendb.com", "seren-cloud").unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.serendb.com/publishers/seren-cloud/skill.md"
        );
    }

    #[test]
    fn seren_api_skill_doc_url_builds_root_path() {
        let url = seren_api_skill_doc_url("https://api.serendb.com").unwrap();
        assert_eq!(url.as_str(), "https://api.serendb.com/skill.md");
    }

    #[test]
    fn build_cloud_approval_resume_payload_returns_none_without_pending_approvals() {
        let approval_state = serde_json::json!({
            "data": {
                "status": "completed",
                "pending_approvals": []
            }
        });

        let payload =
            seren::build_cloud_approval_resume_request(&approval_state, "approve").unwrap();
        assert!(payload.is_none());
    }

    #[test]
    fn build_cloud_approval_resume_payload_includes_checkpoint_and_decisions() {
        let approval_state = serde_json::json!({
            "data": {
                "status": "awaiting_approval",
                "checkpoint_id": "chk_123",
                "pending_approvals": [
                    { "id": "approval-1", "tool": "shell" },
                    { "id": "approval-2", "tool": "browser" }
                ]
            }
        });

        let payload = seren::build_cloud_approval_resume_request(&approval_state, "reject")
            .unwrap()
            .unwrap();
        assert_eq!(payload.resume_checkpoint_id.as_deref(), Some("chk_123"));
        let approval_decisions = payload.approval_decisions.unwrap();
        assert_eq!(approval_decisions[0].id, "approval-1");
        assert_eq!(
            approval_decisions[0].decision,
            seren::CloudRunApprovalDecisionValue::Reject
        );
        assert_eq!(approval_decisions[1].id, "approval-2");
    }

    #[test]
    fn cloud_run_output_event_formatter_shows_tool_result_error_code() {
        let envelope = serde_json::json!({
            "sequence_number": 4,
            "event_type": "response.output_item.done",
            "kind": "tool_call_completed",
            "item_id": "call_123",
            "event": {
                "type": "tool_result",
                "id": "call_123",
                "content": "Provider rate limit exceeded",
                "is_error": true,
                "code": "tool_rate_limited",
                "retryable": true
            }
        });

        let row = format_cloud_run_output_event(&envelope);
        assert!(row.contains("#4"));
        assert!(row.contains("tool_call_completed"));
        assert!(row.contains("id=call_123"));
        assert!(row.contains("code=tool_rate_limited"));
        assert!(row.contains("retryable=yes"));
        assert!(row.contains("summary=Provider rate limit exceeded"));
    }

    #[test]
    fn cloud_run_output_event_formatter_shows_text_preview() {
        let envelope = serde_json::json!({
            "sequence_number": 1,
            "event_type": "response.output_text.done",
            "kind": "text",
            "event": {
                "type": "text",
                "text": "hello from the employee"
            }
        });

        let row = format_cloud_run_output_event(&envelope);
        assert!(row.contains("#1"));
        assert!(row.contains("text"));
        assert!(row.contains("summary=hello from the employee"));
    }

    #[test]
    fn cloud_run_state_rows_include_live_progress_fields() {
        let state = serde_json::json!({
            "run_id": "run-1",
            "deployment_id": "dep-1",
            "status": "awaiting_approval",
            "phase": "waiting",
            "current_step": "approval",
            "current_tool": "send_email",
            "pending_approval_count": 2,
            "checkpoint_id": "chk-1",
            "latest_sequence": 7,
            "latest_event_kind": "approval_wait",
            "terminal": false,
            "started_at": "2026-07-06T00:00:00Z",
            "updated_at": "2026-07-06T00:00:05Z"
        });

        let rows = cloud_run_state_rows(&state);
        assert!(rows.contains(&("Run ID", "run-1".to_string())));
        assert!(rows.contains(&("Status", "awaiting_approval".to_string())));
        assert!(rows.contains(&("Current Tool", "send_email".to_string())));
        assert!(rows.contains(&("Pending Approvals", "2".to_string())));
        assert!(rows.contains(&("Checkpoint ID", "chk-1".to_string())));
        assert!(rows.contains(&("Latest Sequence", "7".to_string())));
    }

    #[test]
    fn cloud_conversation_formatter_shows_count_source_and_title() {
        let conversation = serde_json::json!({
            "conversation_id": "thread-1",
            "title": "Research notes",
            "message_count": 5,
            "last_source": "interactive_session",
            "last_activity_at": "2026-07-06T00:00:00Z"
        });

        let row = format_cloud_conversation(&conversation);
        assert!(row.contains("id=thread-1"));
        assert!(row.contains("title=Research notes"));
        assert!(row.contains("messages=5"));
        assert!(row.contains("source=interactive_session"));
        assert!(row.contains("last=2026-07-06T00:00:00Z"));
    }

    #[test]
    fn cloud_conversation_message_formatter_shows_run_status_and_preview() {
        let message = serde_json::json!({
            "created_at": "2026-07-06T00:00:05Z",
            "role": "assistant",
            "source": "interactive_session",
            "run_id": "11111111-1111-4111-8111-111111111111",
            "run_summary": {
                "status": "completed"
            },
            "events": [
                { "kind": "text" },
                { "kind": "done" }
            ],
            "content": "Hello\n\nfrom the employee"
        });

        let row = format_cloud_conversation_message(&message);
        assert!(row.contains("2026-07-06T00:00:05Z"));
        assert!(row.contains("role=assistant"));
        assert!(row.contains("source=interactive_session"));
        assert!(row.contains("run=11111111-1111-4111-8111-111111111111"));
        assert!(row.contains("status=completed"));
        assert!(row.contains("events=2"));
        assert!(row.contains("content=Hello from the employee"));
    }

    #[test]
    fn cloud_agent_schedule_formatter_shows_status_and_timing() {
        let schedule = serde_json::json!({
            "id": "sched-1",
            "schedule_key": "daily-report",
            "schedule_kind": "cron",
            "status": "active",
            "next_run_at": "2026-07-07T00:00:00Z",
            "cron_schedule": "0 0 * * *",
            "cron_timezone": "UTC",
            "attempts": 1,
            "max_attempts": 3
        });

        let row = format_cloud_agent_schedule(&schedule);
        assert!(row.contains("id=sched-1"));
        assert!(row.contains("key=daily-report"));
        assert!(row.contains("kind=cron"));
        assert!(row.contains("status=active"));
        assert!(row.contains("next=2026-07-07T00:00:00Z"));
        assert!(row.contains("cron=0 0 * * *"));
        assert!(row.contains("tz=UTC"));
        assert!(row.contains("attempts=1/3"));
    }

    #[test]
    fn cloud_agent_schedule_rows_include_last_error() {
        let schedule = serde_json::json!({
            "id": "sched-1",
            "deployment_id": "dep-1",
            "schedule_key": "daily-report",
            "schedule_kind": "cron",
            "status": "failed_terminal",
            "next_run_at": "2026-07-07T00:00:00Z",
            "attempts": 3,
            "max_attempts": 3,
            "last_error": "provider error"
        });

        let rows = cloud_agent_schedule_rows(&schedule);
        assert!(rows.contains(&("Schedule ID", "sched-1".to_string())));
        assert!(rows.contains(&("Schedule Key", "daily-report".to_string())));
        assert!(rows.contains(&("Status", "failed_terminal".to_string())));
        assert!(rows.contains(&("Last Error", "provider error".to_string())));
    }

    #[test]
    fn cloud_run_artifact_formatter_shows_declared_metadata() {
        let artifact = serde_json::json!({
            "id": "artifact-1",
            "artifact_type": "screenshot",
            "title": "Home page screenshot",
            "url": "https://example.com/artifacts/1",
            "created_at": "2026-07-06T00:00:00Z"
        });

        let row = format_cloud_run_artifact(&artifact);
        assert!(row.contains("id=artifact-1"));
        assert!(row.contains("type=screenshot"));
        assert!(row.contains("title=Home page screenshot"));
        assert!(row.contains("url=https://example.com/artifacts/1"));
        assert!(row.contains("created=2026-07-06T00:00:00Z"));
    }

    #[test]
    fn cloud_run_evals_rows_show_counts_and_first_links() {
        let data = serde_json::json!({
            "run_id": "run-1",
            "source_eval_cases": [
                { "id": "case-1", "name": "Homepage loads" }
            ],
            "actual_eval_case_results": [
                { "eval_case_id": "case-1", "status": "passed" }
            ]
        });

        let rows = cloud_run_evals_rows(&data);
        assert!(rows.contains(&("Run ID", "run-1".to_string())));
        assert!(rows.contains(&("Source Eval Cases", "1".to_string())));
        assert!(rows.contains(&("Actual Eval Results", "1".to_string())));
        assert!(rows.contains(&("First Source Case", "case-1".to_string())));
        assert!(rows.contains(&("First Source Name", "Homepage loads".to_string())));
        assert!(rows.contains(&("First Result Case", "case-1".to_string())));
        assert!(rows.contains(&("First Result Status", "passed".to_string())));
    }

    #[test]
    fn cloud_deployment_spend_rows_show_costs_and_window() {
        let spend = serde_json::json!({
            "total_cost_usd": "12.34",
            "compute_cost_usd": "3.21",
            "inference_cost_usd": "9.13",
            "run_count": 42,
            "first_event_at": "2026-07-01T00:00:00Z",
            "last_event_at": "2026-07-06T00:00:00Z"
        });

        let rows = cloud_deployment_spend_rows(&spend);
        assert!(rows.contains(&("Total Cost USD", "12.34".to_string())));
        assert!(rows.contains(&("Compute Cost USD", "3.21".to_string())));
        assert!(rows.contains(&("Inference Cost USD", "9.13".to_string())));
        assert!(rows.contains(&("Run Count", "42".to_string())));
        assert!(rows.contains(&("First Event", "2026-07-01T00:00:00Z".to_string())));
        assert!(rows.contains(&("Last Event", "2026-07-06T00:00:00Z".to_string())));
    }

    #[test]
    fn cloud_audit_entry_formatter_uses_top_level_metadata() {
        let entry = serde_json::json!({
            "id": "entry-1",
            "sequence_number": 42,
            "action": "run.created",
            "actor": "system",
            "invocation_id": "11111111-1111-4111-8111-111111111111",
            "publisher_id": "22222222-2222-4222-8222-222222222222",
            "created_at": "2026-07-06T00:00:00Z",
            "details": { "ignored": true }
        });

        let row = format_cloud_audit_entry(&entry);
        assert!(row.contains("#42"));
        assert!(row.contains("action=run.created"));
        assert!(row.contains("actor=system"));
        assert!(row.contains("id=entry-1"));
        assert!(row.contains("invocation=11111111-1111-4111-8111-111111111111"));
        assert!(row.contains("publisher=22222222-2222-4222-8222-222222222222"));
        assert!(row.contains("created=2026-07-06T00:00:00Z"));
        assert!(!row.contains("ignored"));
    }

    #[test]
    fn cloud_audit_entry_rows_omit_details_and_hashes() {
        let entry = serde_json::json!({
            "id": "entry-1",
            "sequence_number": 42,
            "action": "run.created",
            "actor": "system",
            "created_at": "2026-07-06T00:00:00Z",
            "details": { "ignored": true },
            "entry_hash": "abc"
        });

        let rows = cloud_audit_entry_rows(&entry);
        assert!(rows.contains(&("Entry ID", "entry-1".to_string())));
        assert!(rows.contains(&("Sequence", "42".to_string())));
        assert!(rows.contains(&("Action", "run.created".to_string())));
        assert!(rows.contains(&("Actor", "system".to_string())));
        assert!(rows.contains(&("Created", "2026-07-06T00:00:00Z".to_string())));
        assert!(!rows.iter().any(|(label, _)| *label == "Details"));
        assert!(!rows.iter().any(|(label, _)| *label == "Entry Hash"));
    }

    #[test]
    fn cloud_audit_verify_rows_show_integrity_result() {
        let result = serde_json::json!({
            "verified": false,
            "entries_checked": 100,
            "first_invalid_sequence": 42,
            "error": "hash mismatch"
        });

        let rows = cloud_audit_verify_rows(&result);
        assert!(rows.contains(&("Verified", "false".to_string())));
        assert!(rows.contains(&("Entries Checked", "100".to_string())));
        assert!(rows.contains(&("First Invalid Sequence", "42".to_string())));
        assert!(rows.contains(&("Error", "hash mismatch".to_string())));
    }

    #[test]
    fn resolve_updated_external_databases_preserves_clears_and_replaces() {
        let current: Vec<seren::ManagedExternalDatabaseAttachment> =
            serde_json::from_value(serde_json::json!([{
                "project_id": "24dc59b5-52f8-4a95-bff3-d0b8bab84423",
                "branch_id": "4be7f967-fd9c-4587-bb7d-b45ee4eb2c8f",
                "database": "chief_lending_officer_borrower_sourcing",
                "access": "read_only"
            }]))
            .unwrap();

        // An absent key preserves the current attachments.
        let preserved =
            resolve_updated_external_databases(&serde_json::Map::new(), current.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&preserved).unwrap(),
            serde_json::to_value(&current).unwrap(),
        );

        // An explicit empty list clears the attachments.
        let cleared_body =
            serde_json::Map::from_iter([("external_databases".to_string(), serde_json::json!([]))]);
        assert!(
            resolve_updated_external_databases(&cleared_body, current.clone())
                .unwrap()
                .is_empty()
        );

        // An explicit list replaces the attachments.
        let replace_body = serde_json::Map::from_iter([(
            "external_databases".to_string(),
            serde_json::json!([{
                "project_id": "3dbd443a-86f6-4120-9b56-b8f61a021838",
                "branch_id": "5c1bcdc5-875d-4528-90c0-65d86780e4c1",
                "database": "bat_sales_coach",
                "access": "read_write"
            }]),
        )]);
        let replaced = resolve_updated_external_databases(&replace_body, current.clone()).unwrap();
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced[0].database, "bat_sales_coach");

        // A malformed payload is a clear error, not a silent preserve.
        let invalid_body = serde_json::Map::from_iter([(
            "external_databases".to_string(),
            serde_json::json!("not-an-array"),
        )]);
        assert!(resolve_updated_external_databases(&invalid_body, current).is_err());
    }

    #[test]
    fn reshape_managed_prompt_uses_bundle_execution() {
        let body = serde_json::Map::from_iter([
            ("name".to_string(), serde_json::json!("Research Agent")),
            ("mode".to_string(), serde_json::json!("always_on")),
            ("prompt".to_string(), serde_json::json!("watch the price")),
            (
                "external_databases".to_string(),
                serde_json::json!([{
                    "project_id": "24dc59b5-52f8-4a95-bff3-d0b8bab84423",
                    "branch_id": "4be7f967-fd9c-4587-bb7d-b45ee4eb2c8f",
                    "database": "chief_lending_officer_borrower_sourcing",
                    "access": "read_only"
                }]),
            ),
        ]);

        let reshaped = reshape_body_for_sdk(body, false).unwrap();
        let request: seren::AgentSpec =
            serde_json::from_value(serde_json::Value::Object(reshaped)).unwrap();

        assert_eq!(request.workload.external_databases.len(), 1);
        assert_eq!(
            request.workload.external_databases[0].database,
            "chief_lending_officer_borrower_sourcing"
        );
        match request.workload.execution {
            seren::WorkloadExecution::Llm { bundle, .. } => {
                assert_eq!(bundle.instructions.len(), 1);
                assert_eq!(bundle.instructions[0].content, "watch the price");
                assert_eq!(
                    bundle.instructions[0].kind,
                    seren::AgentInstructionKind::Skill
                );
            }
            other => panic!("expected llm workload, got {other:?}"),
        }
    }

    #[test]
    fn reshape_managed_requirements_stays_with_llm_execution() {
        let body = serde_json::Map::from_iter([
            ("name".to_string(), serde_json::json!("Research Agent")),
            ("mode".to_string(), serde_json::json!("always_on")),
            ("prompt".to_string(), serde_json::json!("watch the price")),
            (
                "requirements_txt".to_string(),
                serde_json::json!("httpx==0.28.1"),
            ),
        ]);

        let reshaped = reshape_body_for_sdk(body, false).unwrap();
        let request: seren::AgentSpec =
            serde_json::from_value(serde_json::Value::Object(reshaped)).unwrap();

        match request.workload.execution {
            seren::WorkloadExecution::Llm {
                requirements_txt, ..
            } => assert_eq!(requirements_txt.as_deref(), Some("httpx==0.28.1")),
            other => panic!("expected llm workload, got {other:?}"),
        }
    }

    #[test]
    fn reshape_rejects_mixed_execution_fields() {
        let body = serde_json::Map::from_iter([
            (
                "deployment_bundle_id".to_string(),
                serde_json::json!(Uuid::new_v4()),
            ),
            (
                "tool_definitions".to_string(),
                serde_json::json!([{"name": "lookup", "description": "Look up a record."}]),
            ),
        ]);

        let error = reshape_body_for_sdk(body, false).unwrap_err();

        assert!(error.to_string().contains("cannot combine"));
    }

    #[test]
    fn bundle_prompt_override_preserves_assets_and_clears_sha() {
        let bundle = seren::AgentBundle {
            assets: vec![seren::AgentAssetFile {
                content_base64: "Zm9v".to_string(),
                content_type: None,
                path: "notes.txt".to_string(),
                purpose: None,
                sha256: Some("asset-sha".to_string()),
            }],
            instructions: vec![seren::AgentInstructionFile {
                allowed_tools: None,
                content: "old prompt".to_string(),
                kind: seren::AgentInstructionKind::Skill,
                path: Some("SKILL.md".to_string()),
                sha256: Some("old-sha".to_string()),
                skill_name: None,
            }],
        };

        let bundle = bundle_with_prompt_override(bundle, Some("new prompt".to_string()));

        assert_eq!(bundle.assets.len(), 1);
        assert_eq!(bundle.instructions.len(), 1);
        assert_eq!(bundle.instructions[0].content, "new prompt");
        assert!(bundle.instructions[0].sha256.is_none());
    }

    #[test]
    fn bundle_prompt_override_preserves_non_skill_instructions() {
        let bundle = seren::AgentBundle {
            assets: vec![],
            instructions: vec![
                seren::AgentInstructionFile {
                    allowed_tools: None,
                    content: "be careful".to_string(),
                    kind: seren::AgentInstructionKind::Identity,
                    path: Some("IDENTITY.md".to_string()),
                    sha256: Some("identity-sha".to_string()),
                    skill_name: None,
                },
                seren::AgentInstructionFile {
                    allowed_tools: None,
                    content: "old prompt".to_string(),
                    kind: seren::AgentInstructionKind::Skill,
                    path: Some("SKILL.md".to_string()),
                    sha256: Some("old-sha".to_string()),
                    skill_name: None,
                },
                seren::AgentInstructionFile {
                    allowed_tools: None,
                    content: "tail logs".to_string(),
                    kind: seren::AgentInstructionKind::Tools,
                    path: Some("TOOLS.md".to_string()),
                    sha256: Some("tools-sha".to_string()),
                    skill_name: None,
                },
            ],
        };

        let bundle = bundle_with_prompt_override(bundle, Some("new prompt".to_string()));

        assert_eq!(bundle.instructions.len(), 3);
        let identity = bundle
            .instructions
            .iter()
            .find(|i| i.kind == seren::AgentInstructionKind::Identity)
            .expect("identity instruction preserved");
        assert_eq!(identity.content, "be careful");
        assert_eq!(identity.sha256.as_deref(), Some("identity-sha"));
        let tools = bundle
            .instructions
            .iter()
            .find(|i| i.kind == seren::AgentInstructionKind::Tools)
            .expect("tools instruction preserved");
        assert_eq!(tools.content, "tail logs");
        assert_eq!(tools.sha256.as_deref(), Some("tools-sha"));
        let skill = bundle
            .instructions
            .iter()
            .find(|i| i.kind == seren::AgentInstructionKind::Skill)
            .expect("skill instruction present");
        assert_eq!(skill.content, "new prompt");
        assert!(skill.sha256.is_none());
    }
}
