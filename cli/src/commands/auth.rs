use anyhow::{Context, Result};
use colored::Colorize;
use jiff::Timestamp;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl, basic::BasicClient,
};
use serde::Deserialize;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;

use crate::OutputFormat;
use crate::config::Config;
use crate::defaults::{DEFAULT_API_HOST, DEFAULT_CLIENT_ID, DEFAULT_OAUTH_HOST, api_base_url};
use crate::output;

const ACCESS_TOKEN_DEFAULT_TTL_SECS: i64 = 900; // 15 minutes
const TOKEN_REFRESH_SKEW_SECONDS: i64 = 60;

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
    let client_id =
        std::env::var("SEREN_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    let client = BasicClient::new(ClientId::new(client_id.clone()))
        .set_auth_uri(AuthUrl::new(format!(
            "{}/api/oauth2/authorize",
            oauth_host
        ))?)
        .set_token_uri(TokenUrl::new(format!("{}/api/oauth2/token", oauth_host))?)
        .set_auth_type(AuthType::RequestBody)
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

    // Avoid following redirects during token exchange.
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build OAuth HTTP client")?;

    // Exchange code for token
    let token_result = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await?;

    let access_token = token_result.access_token().secret().to_string();
    let refresh_token = token_result
        .refresh_token()
        .map(|t| t.secret().to_string())
        .unwrap_or_default();

    if refresh_token.is_empty() {
        anyhow::bail!("OAuth response did not include a refresh token; please contact support");
    }

    // Calculate expiration timestamp
    let expires_at = token_result
        .expires_in()
        .map(|duration| Timestamp::now().as_second() + duration.as_secs() as i64)
        .unwrap_or_else(|| Timestamp::now().as_second() + ACCESS_TOKEN_DEFAULT_TTL_SECS);

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
    let url = format!("{}/auth/me", api_base_url(api_host));

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("Failed to verify token")?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("Token verification failed with status {}", status);
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
                    let expires =
                        Timestamp::from_second(expires_at).unwrap_or_else(|_| Timestamp::now());
                    let now = Timestamp::now();

                    if expires > now {
                        let duration = expires.duration_since(now);
                        let minutes = duration.as_secs() / 60;
                        println!("Token expires in: {} minutes", minutes);
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
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = seren::ClientConfig::new(bearer_token);
    let host = api_host.unwrap_or_else(|| DEFAULT_API_HOST.to_string());
    client_config = client_config.with_base_url(api_base_url(&host));

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
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = seren::ClientConfig::new(bearer_token);
    let host = api_host.unwrap_or_else(|| DEFAULT_API_HOST.to_string());
    client_config = client_config.with_base_url(api_base_url(&host));

    let client = seren::Client::new(client_config)?;
    let orgs = client.organizations().await?;

    match format {
        OutputFormat::Json => output::print_json(&orgs)?,
        OutputFormat::Table => output::print_organizations_table(&orgs),
    }

    Ok(())
}

/// Helper to get bearer token with priority: CLI flag > env var > config file
pub async fn get_bearer_token(api_key_override: Option<String>) -> Result<String> {
    // Priority 1: --api-key flag or SEREN_API_KEY env var (handled by clap)
    if let Some(key) = api_key_override {
        return Ok(key);
    }

    // Priority 2: Stored credentials
    let mut config = Config::load()?;
    maybe_refresh_oauth_token(&mut config).await?;

    config
        .get_bearer_token()
        .map(|s| s.to_string())
        .context("No valid authentication token found")
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    expires_in: i64,
    refresh_token: Option<String>,
}

async fn maybe_refresh_oauth_token(config: &mut Config) -> Result<()> {
    let Some(expires_at) = config.expires_at else {
        return Ok(());
    };

    let Some(refresh_token) = config
        .refresh_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .cloned()
    else {
        return Ok(());
    };

    let now = Timestamp::now().as_second();
    if expires_at - TOKEN_REFRESH_SKEW_SECONDS > now {
        return Ok(());
    }

    let oauth_host =
        std::env::var("SEREN_OAUTH_HOST").unwrap_or_else(|_| DEFAULT_OAUTH_HOST.to_string());
    let client_id =
        std::env::var("SEREN_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    let refreshed = request_token_refresh(&oauth_host, &client_id, &refresh_token).await?;

    let expires_at = Timestamp::now().as_second() + refreshed.expires_in;
    let refresh_token = refreshed
        .refresh_token
        .ok_or_else(|| anyhow::anyhow!("Refresh response missing new refresh_token"))?;

    config.access_token = Some(refreshed.access_token);
    config.refresh_token = Some(refresh_token);
    config.expires_at = Some(expires_at);
    config.save_silent()?;

    Ok(())
}

async fn request_token_refresh(
    oauth_host: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<OAuthTokenResponse> {
    let base = oauth_host.trim_end_matches('/');
    let token_url = format!("{}/api/oauth2/token", base);

    let client = reqwest::Client::new();
    let response = client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await
        .context("Failed to contact OAuth token endpoint")?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("Token refresh failed with status {}", status);
    }

    response
        .json::<OAuthTokenResponse>()
        .await
        .context("Failed to parse OAuth token response")
}
