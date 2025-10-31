use anyhow::{Context, Result};
use colored::Colorize;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

use crate::config::Config;
use crate::defaults::{DEFAULT_API_HOST, DEFAULT_CLIENT_ID, DEFAULT_OAUTH_HOST};
use crate::output;
use crate::OutputFormat;

pub async fn login() -> Result<()> {
    println!("{}", "Seren CLI Authentication".bold().green());
    println!();
    println!("Choose authentication method:");
    println!("  1) Browser login (OAuth) - Recommended");
    println!("  2) API key");
    println!();
    print!("Selection [1]: ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    if choice.is_empty() || choice == "1" {
        login_oauth().await
    } else if choice == "2" {
        login_api_key().await
    } else {
        anyhow::bail!("Invalid selection")
    }
}

async fn login_oauth() -> Result<()> {
    println!();
    println!("{}", "Starting OAuth login flow...".bold());
    println!();

    // Get OAuth host from runtime env var or use compile-time default
    let oauth_host =
        std::env::var("SEREN_OAUTH_HOST").unwrap_or_else(|_| DEFAULT_OAUTH_HOST.to_string());
    let api_host = std::env::var("SEREN_API_HOST").unwrap_or_else(|_| DEFAULT_API_HOST.to_string());

    // Start local server to receive OAuth callback
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;
    let redirect_url = format!("http://127.0.0.1:{}/callback", local_addr.port());

    // Set up OAuth client
    let client = BasicClient::new(
        ClientId::new(DEFAULT_CLIENT_ID.to_string()),
        None,
        AuthUrl::new(format!("{}/api/auth/authorize", oauth_host))?,
        Some(TokenUrl::new(format!("{}/api/auth/token", oauth_host))?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.clone())?);

    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate authorization URL
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Opening browser for authentication...");
    println!("If the browser doesn't open, visit:");
    println!("{}", auth_url.to_string().cyan());
    println!();

    // Try to open browser
    if let Err(e) = open::that(auth_url.to_string()) {
        eprintln!("Warning: Could not open browser: {}", e);
    }

    println!("Waiting for authentication...");

    // Wait for callback
    let (code, state) = receive_callback(listener)?;

    // Verify CSRF token
    if state.secret() != csrf_token.secret() {
        anyhow::bail!("CSRF token mismatch");
    }

    println!("Exchanging authorization code for tokens...");

    // Exchange code for token
    let token_result = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    let access_token = token_result.access_token().secret().to_string();
    let refresh_token = token_result
        .refresh_token()
        .map(|t| t.secret().to_string())
        .unwrap_or_default();

    // Calculate expiration timestamp
    let expires_at = token_result
        .expires_in()
        .map(|duration| chrono::Utc::now().timestamp() + duration.as_secs() as i64)
        .unwrap_or_else(|| chrono::Utc::now().timestamp() + 900); // Default 15 minutes

    // Verify token works by calling /me endpoint
    println!("Verifying authentication...");
    verify_token(&access_token, &api_host).await?;

    // Save credentials
    let config = Config::from_oauth(access_token, refresh_token, expires_at);
    config.save()?;

    println!();
    println!("{}", "✓ Successfully authenticated!".green().bold());
    println!();
    println!("Try running: seren projects list");

    Ok(())
}

async fn login_api_key() -> Result<()> {
    println!();
    println!("To authenticate, you need an API key from your Seren account.");
    println!("You can create one at: https://app.seren.com/settings/api-keys");
    println!();

    // Use rpassword for hidden input
    let api_key = rpassword::prompt_password("Enter your API key (seren_...): ")?;
    let api_key = api_key.trim().to_string();

    // Validate API key format
    if !api_key.starts_with("seren_") {
        anyhow::bail!("Invalid API key format. API keys should start with 'seren_'");
    }

    // Verify the API key by making a test request to the API
    println!("Verifying API key...");
    let api_host = std::env::var("SEREN_API_HOST").unwrap_or_else(|_| DEFAULT_API_HOST.to_string());
    verify_token(&api_key, &api_host).await?;

    let config = Config::from_api_key(api_key);
    config.save()?;

    println!();
    println!("{}", "✓ Successfully authenticated!".green().bold());
    println!();
    println!("Try running: seren projects list");

    Ok(())
}

async fn verify_token(token: &str, api_host: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/auth/me", api_host);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("Failed to verify token")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Token verification failed ({}): {}", status, body);
    }

    Ok(())
}

fn receive_callback(listener: TcpListener) -> Result<(String, CsrfToken)> {
    // Set timeout on the listener
    listener
        .set_nonblocking(false)
        .context("Failed to set blocking mode")?;

    let (mut stream, _) = listener.accept().context("Failed to accept connection")?;

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("Failed to read request")?;

    // Parse the callback URL from request line
    let redirect_url = request_line
        .split_whitespace()
        .nth(1)
        .context("Invalid HTTP request")?;

    let url = Url::parse(&format!("http://localhost{}", redirect_url))?;

    // Extract code and state from query parameters
    let mut code = None;
    let mut state = None;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            _ => {}
        }
    }

    let code = code.context("No authorization code in callback")?;
    let state = state.context("No state in callback")?;

    // Send success response to browser
    let response = "HTTP/1.1 200 OK\r\n\r\n\
        <html><body>\
        <h1>Authentication Successful!</h1>\
        <p>You can close this window and return to the terminal.</p>\
        </body></html>";

    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    Ok((code, CsrfToken::new(state)))
}

pub async fn status() -> Result<()> {
    match Config::load() {
        Ok(config) => {
            println!("{}", "✓ Authenticated".green().bold());

            if let Some(api_key) = &config.api_key {
                let masked_key = mask_api_key(api_key);
                println!("Auth Type: API Key");
                println!("API Key: {}", masked_key);
            } else if config.access_token.is_some() {
                println!("Auth Type: OAuth");
                if let Some(expires_at) = config.expires_at {
                    let expires = chrono::DateTime::from_timestamp(expires_at, 0)
                        .unwrap_or_else(|| chrono::Utc::now());
                    let now = chrono::Utc::now();

                    if expires > now {
                        let duration = expires - now;
                        println!("Token expires in: {} minutes", duration.num_minutes());
                    } else {
                        println!("{}", "Token expired".yellow());
                    }
                }
            }

            if let Ok(path) = Config::config_path() {
                println!("Config: {}", path.display());
            }
        }
        Err(_) => {
            println!("{}", "✗ Not authenticated".red().bold());
            println!("Run 'seren auth login' to authenticate");
        }
    }

    Ok(())
}

pub async fn logout() -> Result<()> {
    Config::delete()?;
    println!("{}", "✓ Successfully logged out".green().bold());
    Ok(())
}

fn mask_api_key(key: &str) -> String {
    if key.len() <= 12 {
        return "*".repeat(key.len());
    }

    let prefix = &key[..7]; // "seren_"
    let suffix = &key[key.len() - 4..];
    format!("{}...{}", prefix, suffix)
}

pub async fn me(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let bearer_token = get_bearer_token(api_key)?;

    let mut client_config = seren::ClientConfig::new(bearer_token);
    if let Some(base_url) = api_host {
        client_config = client_config.with_base_url(base_url);
    }

    let client = seren::Client::new(client_config)?;
    let user = client.me().await?;

    match format {
        OutputFormat::Json => output::print_json(&user)?,
        OutputFormat::Table => output::print_user(&user)?,
    }

    Ok(())
}

pub async fn organizations(
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let bearer_token = get_bearer_token(api_key)?;

    let mut client_config = seren::ClientConfig::new(bearer_token);
    if let Some(base_url) = api_host {
        client_config = client_config.with_base_url(base_url);
    }

    let client = seren::Client::new(client_config)?;
    let orgs = client.organizations().await?;

    match format {
        OutputFormat::Json => output::print_json(&orgs)?,
        OutputFormat::Table => output::print_organizations_table(&orgs),
    }

    Ok(())
}

/// Helper to get bearer token with priority: CLI flag > env var > config file
pub fn get_bearer_token(api_key_override: Option<String>) -> Result<String> {
    // Priority 1: --api-key flag or SEREN_API_KEY env var (handled by clap)
    if let Some(key) = api_key_override {
        return Ok(key);
    }

    // Priority 2: Stored credentials
    let config = Config::load()?;

    config
        .get_bearer_token()
        .map(|s| s.to_string())
        .context("No valid authentication token found")
}
