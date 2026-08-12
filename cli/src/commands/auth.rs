use anyhow::{Context, Result};
use colored::Colorize;
use jiff::Timestamp;
use oauth2::{
    AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, basic::BasicClient,
};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use url::Url;

use crate::OutputFormat;
use crate::config::Config;
use crate::defaults::{
    DEFAULT_API_HOST, DEFAULT_CLIENT_ID, DEFAULT_OAUTH_HOST, api_base_url, runtime_api_host,
};
use crate::output;

const ACCESS_TOKEN_DEFAULT_TTL_SECS: i64 = 900; // 15 minutes
const TOKEN_REFRESH_SKEW_SECONDS: i64 = 60;

/// Resolve the OAuth host, dropping a trailing slash so generated SDK
/// operations do not build `host//oauth2/token`.
fn oauth_host() -> String {
    std::env::var("SEREN_OAUTH_HOST")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_OAUTH_HOST.to_string())
}

/// Absolute expiry for a freshly issued access token.
///
/// A non-positive lifetime would make every subsequent command refresh again,
/// so fall back to the documented default instead of trusting it.
fn access_token_expires_at(expires_in: i64) -> i64 {
    let ttl = if expires_in > 0 {
        expires_in
    } else {
        ACCESS_TOKEN_DEFAULT_TTL_SECS
    };
    Timestamp::now().as_second() + ttl
}

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
    let oauth_host = oauth_host();
    let api_host = runtime_api_host();

    // Start local server to receive OAuth callback
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;
    let redirect_url = format!("http://127.0.0.1:{}/callback", local_addr.port());

    // Set up OAuth client
    let client_id =
        std::env::var("SEREN_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    // Only the authorization URL is built here; the code exchange below goes
    // through the generated SDK so the response's session ID is retained.
    let client = BasicClient::new(ClientId::new(client_id.clone()))
        .set_auth_uri(AuthUrl::new(format!("{}/oauth2/authorize", oauth_host))?)
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

    // Exchange code through the typed API contract so session metadata is retained.
    let token_result = seren::Client::new_with_client(&oauth_host, http_client)
        .token(&seren::TokenRequest {
            client_id: Some(client_id),
            code: Some(code),
            code_verifier: Some(pkce_verifier.secret().to_string()),
            grant_type: "authorization_code".to_string(),
            redirect_uri: Some(redirect_url),
            refresh_token: None,
        })
        .await
        .map_err(|e| anyhow::anyhow!("OAuth token exchange failed: {}", e))?
        .into_inner();

    let access_token = token_result.access_token;
    let refresh_token = token_result.refresh_token.unwrap_or_default();

    if refresh_token.is_empty() {
        anyhow::bail!("OAuth response did not include a refresh token; please contact support");
    }

    // Calculate expiration timestamp
    let expires_at = access_token_expires_at(token_result.expires_in);

    // Verify token works by calling /me endpoint
    println!("Verifying authentication...");
    verify_token(&access_token, &api_host).await?;

    // Save credentials
    let config = Config::from_oauth(
        access_token,
        refresh_token,
        expires_at,
        token_result.session_id,
    );
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
    let api_host = runtime_api_host();
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
            if let Some(session_id) = config.session_id {
                println!("Session ID: {}", session_id);
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

    let client = seren::Client::from_config(&client_config)?;
    let response = client
        .get_current_user()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get user info: {}", e))?;
    let user = response.into_inner();

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

    let client = seren::Client::from_config(&client_config)?;
    let response = client
        .list_organizations()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list organizations: {}", e))?;
    let orgs = response.into_inner();

    match format {
        OutputFormat::Json => output::print_json(&orgs)?,
        OutputFormat::Table => output::print_organizations_table(&orgs.data),
    }

    Ok(())
}

pub async fn organization_memberships(ctx: &crate::CommandContext) -> Result<()> {
    let memberships = ctx
        .client()
        .await?
        .list_current_user_organization_memberships()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list organization memberships: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&memberships)?,
        OutputFormat::Table => output::print_organization_memberships_table(&memberships.data),
    }
    Ok(())
}

pub async fn update_profile(
    name: Option<String>,
    avatar_url: Option<String>,
    ctx: &crate::CommandContext,
) -> Result<()> {
    if name.is_none() && avatar_url.is_none() {
        anyhow::bail!("At least one of --name or --avatar-url is required");
    }

    let request = seren::UpdateProfileRequest { name, avatar_url };
    let response = ctx
        .client()
        .await?
        .update_current_user_profile(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update profile: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!("{}", response.data.message.green().bold());
            println!("Name: {}", response.data.user.name);
            println!("Email: {}", response.data.user.email);
            if let Some(avatar_url) = response.data.user.avatar_url {
                println!("Avatar URL: {}", avatar_url);
            }
        }
    }
    Ok(())
}

pub async fn upload_avatar(path: &Path, ctx: &crate::CommandContext) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Avatar path must have a UTF-8 file name")?;
    let file = std::fs::read(path)
        .with_context(|| format!("Failed to read avatar image {}", path.display()))?;
    let response = ctx
        .client()
        .await?
        .upload_current_user_avatar(file_name, file)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to upload avatar: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!("Avatar uploaded: {}", response.data.avatar_url),
    }
    Ok(())
}

pub async fn download_avatar(
    path: &Path,
    user_id: Option<uuid::Uuid>,
    ctx: &crate::CommandContext,
) -> Result<()> {
    use futures_util::TryStreamExt;

    let client = ctx.client().await?;
    let response = match &user_id {
        Some(user_id) => client.get_user_avatar(user_id).await,
        None => client.get_current_user_avatar().await,
    }
    .map_err(|e| anyhow::anyhow!("Failed to download avatar: {}", e))?;
    let chunks: Vec<_> = response
        .into_inner_stream()
        .try_collect()
        .await
        .context("Failed to read avatar response")?;
    let bytes: Vec<u8> = chunks.into_iter().flatten().collect();
    std::fs::write(path, &bytes)
        .with_context(|| format!("Failed to write avatar image {}", path.display()))?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&serde_json::json!({
            "path": path,
            "bytes": bytes.len(),
            "user_id": user_id,
        }))?,
        OutputFormat::Table => println!("Avatar written to {}", path.display()),
    }
    Ok(())
}

pub async fn recovery_email_status(ctx: &crate::CommandContext) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .get_account_security()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read account security state: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            println!(
                "Recovery email: {}",
                response
                    .data
                    .recovery_email
                    .as_deref()
                    .unwrap_or("not configured")
            );
            if let Some(pending) = response.data.pending_recovery_email.as_deref() {
                println!("Pending verification: {}", pending);
            }
        }
    }
    Ok(())
}

pub async fn set_recovery_email(email: &str, ctx: &crate::CommandContext) -> Result<()> {
    let current_password = rpassword::prompt_password("Current password: ")?;
    let request = seren::SetRecoveryEmailRequest {
        recovery_email: email.to_string().into(),
        current_password,
    };
    let response = ctx
        .client()
        .await?
        .set_recovery_email(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set recovery email: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!("{}", response.data.message),
    }
    Ok(())
}

pub async fn remove_recovery_email(ctx: &crate::CommandContext) -> Result<()> {
    let current_password = rpassword::prompt_password("Current password: ")?;
    let request = seren::RemoveRecoveryEmailRequest { current_password };
    let response = ctx
        .client()
        .await?
        .remove_recovery_email(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remove recovery email: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!("{}", response.data.message),
    }
    Ok(())
}

pub async fn verify_recovery_email(token: &str, ctx: &crate::CommandContext) -> Result<()> {
    let request = seren::VerifyRecoveryEmailRequest {
        token: token.to_string(),
    };
    let response = seren::Client::new(&ctx.api_base())
        .verify_recovery_email(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify recovery email: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => println!("{}", response.data.message),
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

    let oauth_host = oauth_host();
    let client_id =
        std::env::var("SEREN_CLIENT_ID").unwrap_or_else(|_| DEFAULT_CLIENT_ID.to_string());

    let refreshed = request_token_refresh(&oauth_host, &client_id, &refresh_token).await?;

    let expires_at = access_token_expires_at(refreshed.expires_in);
    let refresh_token = refreshed.refresh_token.unwrap_or(refresh_token);

    config.access_token = Some(refreshed.access_token);
    config.refresh_token = Some(refresh_token);
    config.expires_at = Some(expires_at);
    config.session_id = refreshed.session_id.or(config.session_id);
    config.save_silent()?;

    Ok(())
}

async fn request_token_refresh(
    oauth_host: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<seren::TokenResponse> {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build OAuth HTTP client")?;
    seren::Client::new_with_client(oauth_host, http_client)
        .token(&seren::TokenRequest {
            client_id: Some(client_id.to_string()),
            code: None,
            code_verifier: None,
            grant_type: "refresh_token".to_string(),
            redirect_uri: None,
            refresh_token: Some(refresh_token.to_string()),
        })
        .await
        .map(|response| response.into_inner())
        .map_err(|error| anyhow::anyhow!("Token refresh failed: {}", error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_expiry_uses_the_reported_lifetime() {
        let before = Timestamp::now().as_second();
        let expires_at = access_token_expires_at(3600);
        assert!((expires_at - before - 3600).abs() <= 1, "{expires_at}");
    }

    #[test]
    fn access_token_expiry_falls_back_when_lifetime_is_not_positive() {
        // A zero or negative lifetime would otherwise mark the token expired on
        // arrival and make every later command refresh again.
        for reported in [0, -1, i64::MIN + 1] {
            let before = Timestamp::now().as_second();
            let expires_at = access_token_expires_at(reported);
            assert!(
                (expires_at - before - ACCESS_TOKEN_DEFAULT_TTL_SECS).abs() <= 1,
                "expires_in {reported} produced {expires_at}",
            );
        }
    }
}
