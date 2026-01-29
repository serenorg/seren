//! OAuth commands for managing BYOC (Bring Your Own Credentials) publisher connections.
//!
//! These commands allow users to connect their own accounts to OAuth-enabled publishers
//! like Attio, Neon, etc.

use anyhow::{Context, Result};
use colored::Colorize;
use seren::{ConnectionsResponse, ProvidersResponse};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use crate::CommandContext;

#[derive(Debug)]
struct LocalOAuthCallback {
    success: Option<bool>,
    provider: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// List available OAuth providers
pub async fn list_providers(ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let response = client
        .list_providers()
        .await
        .context("Failed to list OAuth providers")?;

    let ProvidersResponse { providers } = response.into_inner();

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
    let client = ctx.client().await?;

    let response = client
        .list_connections()
        .await
        .context("Failed to list OAuth connections")?;

    let ConnectionsResponse { connections } = response.into_inner();

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
    // The initiate_oauth endpoint returns a 302 redirect to the provider's authorization URL.
    // We need to read the Location header rather than follow the redirect, so we use the
    // raw HTTP client with redirects disabled instead of the SDK client.
    let client = ctx.http_client_no_redirect().await?;
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
            "{}/oauth/{}/authorize?redirect_uri={}",
            api_base,
            provider_slug,
            urlencoding::encode(&redirect_url)
        ))
        .send()
        .await
        .context("Failed to initiate OAuth flow")?;

    if !response.status().is_redirection() {
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

    let authorization_url = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("OAuth authorize response missing Location header"))?;

    println!("Opening browser for {} authorization...", provider_slug);
    println!("If the browser doesn't open, visit:");
    println!("{}", authorization_url.cyan());
    println!();

    // Try to open browser
    if let Err(e) = open::that(&authorization_url) {
        eprintln!("Warning: Could not open browser: {}", e);
    }

    println!("Waiting for authorization...");

    // Wait for callback
    let callback = receive_oauth_callback(listener)?;

    // Check for errors
    if let Some(err) = callback.error {
        if let Some(desc) = callback.error_description {
            anyhow::bail!("OAuth authorization failed: {err}: {desc}");
        }
        anyhow::bail!("OAuth authorization failed: {err}");
    }

    if callback.success != Some(true) {
        anyhow::bail!("OAuth authorization did not complete successfully.");
    }

    if let Some(provider) = callback.provider.as_deref()
        && provider != provider_slug
    {
        eprintln!(
            "Warning: OAuth completed for provider '{}', expected '{}'",
            provider, provider_slug
        );
    }

    println!("Authorization complete. Verifying connection...");

    // Poll for connection status using the SDK client
    let sdk_client = ctx.client().await?;
    for _ in 0..5 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        if let Ok(response) = sdk_client.list_connections().await {
            let ConnectionsResponse { connections } = response.into_inner();
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
    }

    // If we get here, the callback should have been processed by the server
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
    let client = ctx.client().await?;

    println!("Disconnecting from {}...", provider_slug);

    client.revoke_connection(provider_slug).await.map_err(|e| {
        if let seren::Error::ErrorResponse(ref resp) = e {
            if resp.status() == 404 {
                return anyhow::anyhow!("No connection found for provider '{}'", provider_slug);
            }
        }
        anyhow::anyhow!("Failed to disconnect: {}", e)
    })?;

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
fn receive_oauth_callback(listener: TcpListener) -> Result<LocalOAuthCallback> {
    let (mut stream, _) = listener.accept()?;
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Parse the request to extract success/error info from query params.
    let mut success = None;
    let mut provider = None;
    let mut error = None;
    let mut error_description = None;

    if let Some(path_start) = request_line.find(' ') {
        if let Some(path_end) = request_line[path_start + 1..].find(' ') {
            let path = &request_line[path_start + 1..path_start + 1 + path_end];
            if let Some(query_start) = path.find('?') {
                let query = &path[query_start + 1..];
                for param in query.split('&') {
                    if let Some((key, value)) = param.split_once('=') {
                        match key {
                            "success" => {
                                let v = urlencoding::decode(value)?.into_owned();
                                success = Some(v == "true" || v == "1");
                            }
                            "provider" => provider = Some(urlencoding::decode(value)?.into_owned()),
                            "error" => error = Some(urlencoding::decode(value)?.into_owned()),
                            "error_description" => {
                                error_description = Some(urlencoding::decode(value)?.into_owned());
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

    Ok(LocalOAuthCallback {
        success,
        provider,
        error,
        error_description,
    })
}
