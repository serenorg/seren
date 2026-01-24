//! OAuth commands for managing BYOC (Bring Your Own Credentials) publisher connections.
//!
//! These commands allow users to connect their own accounts to OAuth-enabled publishers
//! like Attio, Neon, etc.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use crate::CommandContext;

/// OAuth provider information
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct OAuthProvider {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub authorization_url: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
}

/// User's OAuth connection
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct OAuthConnection {
    pub id: String,
    pub provider_id: String,
    pub provider_slug: String,
    pub provider_name: String,
    pub provider_logo_url: Option<String>,
    pub provider_user_id: Option<String>,
    pub provider_email: Option<String>,
    pub scopes: Vec<String>,
    pub is_valid: bool,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

/// Response from authorization initiation
#[derive(Debug, Deserialize)]
struct AuthorizeResponse {
    authorization_url: String,
    state: String,
}

/// List available OAuth providers
pub async fn list_providers(ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let api_base = ctx.api_base();

    let response = client
        .get(format!("{}/api/oauth/providers", api_base))
        .send()
        .await
        .context("Failed to list OAuth providers")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to list OAuth providers: {} - {}", status, body);
    }

    let providers: Vec<OAuthProvider> = response.json().await?;

    if providers.is_empty() {
        println!("No OAuth providers available.");
        return Ok(());
    }

    println!("{}", "Available OAuth Providers".bold().underline());
    println!();

    for provider in providers {
        let status = if provider.is_active {
            "active".green()
        } else {
            "inactive".yellow()
        };

        println!("  {} ({})", provider.name.bold(), provider.slug.cyan());
        println!("    Status: {}", status);
        if !provider.scopes.is_empty() {
            println!("    Scopes: {}", provider.scopes.join(", "));
        }
        println!();
    }

    println!(
        "Use {} to connect your account.",
        "seren oauth connect <provider_slug>".cyan()
    );

    Ok(())
}

/// List user's OAuth connections
pub async fn list_connections(ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let api_base = ctx.api_base();

    let response = client
        .get(format!("{}/api/oauth/connections", api_base))
        .send()
        .await
        .context("Failed to list OAuth connections")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to list OAuth connections: {} - {}", status, body);
    }

    let connections: Vec<OAuthConnection> = response.json().await?;

    if connections.is_empty() {
        println!("No OAuth connections found.");
        println!();
        println!(
            "Use {} to see available providers.",
            "seren oauth providers".cyan()
        );
        return Ok(());
    }

    println!("{}", "Your OAuth Connections".bold().underline());
    println!();

    for conn in connections {
        let status = if conn.is_valid {
            "valid".green()
        } else {
            "expired/invalid".red()
        };

        println!(
            "  {} ({})",
            conn.provider_name.bold(),
            conn.provider_slug.cyan()
        );
        println!("    Status: {}", status);
        if let Some(email) = &conn.provider_email {
            println!("    Email: {}", email);
        }
        if let Some(user_id) = &conn.provider_user_id {
            println!("    User ID: {}", user_id);
        }
        if !conn.scopes.is_empty() {
            println!("    Scopes: {}", conn.scopes.join(", "));
        }
        println!("    Connected: {}", conn.created_at);
        if let Some(last_used) = &conn.last_used_at {
            println!("    Last used: {}", last_used);
        }
        println!();
    }

    Ok(())
}

/// Initiate OAuth flow to connect to a provider
pub async fn connect(provider_slug: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let api_base = ctx.api_base();

    println!("{}", "Starting OAuth connection flow...".bold());
    println!();

    // Start local server to receive OAuth callback
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;
    let redirect_url = format!("http://127.0.0.1:{}/callback", local_addr.port());

    // Request authorization URL from the API
    let response = client
        .get(format!(
            "{}/api/oauth/{}/authorize?redirect_uri={}",
            api_base,
            provider_slug,
            urlencoding::encode(&redirect_url)
        ))
        .send()
        .await
        .context("Failed to initiate OAuth flow")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.as_u16() == 404 {
            anyhow::bail!(
                "OAuth provider '{}' not found. Use 'seren oauth providers' to see available providers.",
                provider_slug
            );
        }
        anyhow::bail!("Failed to initiate OAuth flow: {} - {}", status, body);
    }

    let auth_response: AuthorizeResponse = response.json().await?;

    println!("Opening browser for {} authorization...", provider_slug);
    println!("If the browser doesn't open, visit:");
    println!("{}", auth_response.authorization_url.cyan());
    println!();

    // Try to open browser
    if let Err(e) = open::that(&auth_response.authorization_url) {
        eprintln!("Warning: Could not open browser: {}", e);
    }

    println!("Waiting for authorization...");

    // Wait for callback
    let (code, state, error) = receive_oauth_callback(listener)?;

    // Check for errors
    if let Some(err) = error {
        anyhow::bail!("OAuth authorization failed: {}", err);
    }

    // Verify state matches
    if state != auth_response.state {
        anyhow::bail!("OAuth state mismatch - possible CSRF attack");
    }

    let _code = code.ok_or_else(|| anyhow::anyhow!("No authorization code received"))?;

    println!("Completing authorization...");

    // The callback is handled server-side, but we need to inform the user
    // The server should have already exchanged the code when the callback was received
    // We just need to verify the connection was established

    // Poll for connection status
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let response = client
        .get(format!("{}/api/oauth/connections", api_base))
        .send()
        .await
        .context("Failed to verify connection")?;

    if response.status().is_success() {
        let connections: Vec<OAuthConnection> = response.json().await?;
        if connections
            .iter()
            .any(|c| c.provider_slug == provider_slug && c.is_valid)
        {
            println!();
            println!(
                "{}",
                format!("✓ Successfully connected to {}!", provider_slug)
                    .green()
                    .bold()
            );
            println!();
            println!("You can now use publishers that require this OAuth connection.");
            return Ok(());
        }
    }

    // If we get here, the callback should have been processed by the server
    // The actual token exchange happens in the browser callback
    println!();
    println!(
        "{}",
        format!("✓ Authorization completed for {}!", provider_slug)
            .green()
            .bold()
    );
    println!();
    println!(
        "Use {} to verify your connection.",
        "seren oauth connections".cyan()
    );

    Ok(())
}

/// Disconnect/revoke an OAuth connection
pub async fn disconnect(provider_slug: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.http_client().await?;
    let api_base = ctx.api_base();

    println!("Disconnecting from {}...", provider_slug);

    let response = client
        .delete(format!(
            "{}/api/oauth/connections/{}",
            api_base, provider_slug
        ))
        .send()
        .await
        .context("Failed to disconnect OAuth connection")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.as_u16() == 404 {
            anyhow::bail!("No connection found for provider '{}'", provider_slug);
        }
        anyhow::bail!("Failed to disconnect: {} - {}", status, body);
    }

    println!();
    println!(
        "{}",
        format!("✓ Disconnected from {}", provider_slug)
            .green()
            .bold()
    );

    Ok(())
}

/// Receive OAuth callback on local server
fn receive_oauth_callback(
    listener: TcpListener,
) -> Result<(Option<String>, String, Option<String>)> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Parse the request to extract code, state, and error
    let mut code = None;
    let mut state = String::new();
    let mut error = None;

    if let Some(path_start) = request_line.find(' ') {
        if let Some(path_end) = request_line[path_start + 1..].find(' ') {
            let path = &request_line[path_start + 1..path_start + 1 + path_end];
            if let Some(query_start) = path.find('?') {
                let query = &path[query_start + 1..];
                for param in query.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "code" => code = Some(urlencoding::decode(value)?.into_owned()),
                            "state" => state = urlencoding::decode(value)?.into_owned(),
                            "error" => error = Some(urlencoding::decode(value)?.into_owned()),
                            "error_description" => {
                                if error.is_some() {
                                    let desc = urlencoding::decode(value)?.into_owned();
                                    error = Some(format!("{}: {}", error.unwrap(), desc));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Send response to browser
    let response_body = if error.is_some() {
        r#"<!DOCTYPE html>
<html>
<head><title>OAuth Error</title></head>
<body style="font-family: system-ui; text-align: center; padding: 50px;">
<h1 style="color: #e74c3c;">Authorization Failed</h1>
<p>Please return to the terminal for details.</p>
<p>You can close this window.</p>
</body>
</html>"#
    } else {
        r#"<!DOCTYPE html>
<html>
<head><title>OAuth Success</title></head>
<body style="font-family: system-ui; text-align: center; padding: 50px;">
<h1 style="color: #27ae60;">Authorization Successful!</h1>
<p>You can close this window and return to the terminal.</p>
</body>
</html>"#
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    Ok((code, state, error))
}
