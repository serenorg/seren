//! OAuth commands for managing BYOC (Bring Your Own Credentials) publisher connections.
//!
//! These commands allow users to connect their own accounts to OAuth-enabled publishers
//! like Attio, Neon, etc.

use anyhow::{Context, Result};
use colored::Colorize;
use seren::{ConnectionsResponse, ProvidersResponse, UserOAuthConnectionResponse};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use uuid::Uuid;

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
        println!("    Connection ID: {}", conn.id);
        println!("    Status: {}", status);
        println!(
            "    Default: {}",
            if conn.is_default { "yes" } else { "no" }
        );
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

/// Select the default OAuth connection for its provider
pub async fn set_default(connection_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .set_default_connection(&connection_id)
        .await
        .context("Failed to set default OAuth connection")?
        .into_inner();
    let connection = response.connection;
    let identity = connection
        .provider_email
        .as_deref()
        .or(connection.provider_user_id.as_deref())
        .unwrap_or("unknown account");

    println!(
        "Default {} connection: {} ({})",
        connection.provider_name, identity, connection.id
    );
    Ok(())
}

/// Initiate OAuth flow to connect to a provider
pub async fn connect(provider_slug: &str, ctx: &CommandContext) -> Result<()> {
    let sdk_client = ctx.client().await?;

    eprintln!("{}", "Starting OAuth connection flow...".bold());
    eprintln!();

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let local_addr = listener.local_addr()?;
    let redirect_url = format!("http://127.0.0.1:{}/callback", local_addr.port());
    let consent = sdk_client
        .initiate_oauth(provider_slug, &redirect_url, Some("application/json"))
        .await
        .context("Failed to initiate OAuth flow")?
        .into_inner()
        .data;
    let authorization_url = consent.authorization_url;
    let consent_state = consent.state;

    eprintln!("Opening browser for {} authorization...", provider_slug);
    eprintln!("If the browser doesn't open, visit:");
    eprintln!("{}", authorization_url.cyan());
    eprintln!();

    // Try to open browser
    if let Err(e) = open::that(&authorization_url) {
        eprintln!("Warning: Could not open browser: {}", e);
    }

    eprintln!("Waiting for authorization...");

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
        anyhow::bail!("OAuth completed for provider '{provider}', expected '{provider_slug}'.");
    }

    let result = resolve_consent_connection(&sdk_client, provider_slug, &consent_state).await?;
    match ctx.format {
        crate::OutputFormat::Json => crate::output::print_json(&result)?,
        crate::OutputFormat::Table => {
            println!(
                "Successfully connected to {} (connection {}).",
                result.provider, result.connection_id
            );
        }
    }
    Ok(())
}

/// Read only the connection produced by this consent attempt. An earlier connection for the same provider cannot confirm it.
async fn resolve_consent_connection(
    client: &seren::Client,
    provider: &str,
    state: &str,
) -> Result<seren::OAuthConnectionResultResponse> {
    let result = client
        .get_connection_result(state)
        .await
        .context("Failed to read the connection produced by this OAuth consent attempt")?
        .into_inner()
        .data;
    if result.provider != provider {
        anyhow::bail!(
            "OAuth consent returned provider '{}', expected '{provider}'.",
            result.provider
        );
    }
    Ok(seren::OAuthConnectionResultResponse {
        provider: result.provider,
        connection_id: result.connection_id,
    })
}

/// Disconnect/revoke an OAuth connection
pub async fn disconnect(connection: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;

    let connection_id = match Uuid::parse_str(connection) {
        Ok(connection_id) => connection_id,
        Err(_) => {
            let response = client
                .list_connections()
                .await
                .context("Failed to list OAuth connections")?;
            let ConnectionsResponse { connections } = response.into_inner();
            resolve_connection_id_for_disconnect(&connections, connection)?
        }
    };

    println!("Disconnecting OAuth connection {}...", connection_id);

    client
        .revoke_connection_by_id(&connection_id)
        .await
        .map_err(|e| {
            let not_found = match &e {
                seren::Error::ErrorResponse(resp) => resp.status() == 404,
                seren::Error::UnexpectedResponse(resp) => resp.status() == 404,
                _ => false,
            };
            if not_found {
                return anyhow::anyhow!("No OAuth connection found for '{}'", connection);
            }
            anyhow::anyhow!("Failed to disconnect: {}", e)
        })?;

    println!();
    println!(
        "{}",
        format!("✓ Disconnected OAuth connection {}", connection_id)
            .green()
            .bold()
    );

    Ok(())
}

fn resolve_connection_id_for_disconnect(
    connections: &[UserOAuthConnectionResponse],
    provider_slug: &str,
) -> Result<Uuid> {
    let matches = connections
        .iter()
        .filter(|connection| connection.provider_slug == provider_slug)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => anyhow::bail!("No connection found for provider '{}'", provider_slug),
        [connection] => Ok(connection.id),
        _ => {
            let mut details = String::new();
            for connection in matches {
                let account = connection
                    .provider_email
                    .as_deref()
                    .or(connection.provider_user_id.as_deref())
                    .unwrap_or("unknown account");
                details.push_str(&format!("\n  {} ({})", connection.id, account));
            }
            anyhow::bail!(
                "Multiple connections found for provider '{}'. Disconnect by connection ID:{}\nUse 'seren oauth connections' to inspect connections.",
                provider_slug,
                details
            );
        }
    }
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

    if let Some(path_start) = request_line.find(' ')
        && let Some(path_end) = request_line[path_start + 1..].find(' ')
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consent_completion_reads_only_the_exact_attempts_connection() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let connection_id = Uuid::from_u128(24);
        Mock::given(method("GET"))
            .and(path("/oauth/results/this-consent-attempt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"data": {"provider": "google", "connection_id": connection_id}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let client = seren::Client::new(&server.uri());
        let result = resolve_consent_connection(&client, "google", "this-consent-attempt")
            .await
            .unwrap();
        assert_eq!(result.connection_id, connection_id);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn consent_completion_rejects_a_different_provider() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth/results/this-consent-attempt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": {"provider": "microsoft", "connection_id": Uuid::from_u128(24)}})))
            .expect(1)
            .mount(&server)
            .await;
        let client = seren::Client::new(&server.uri());
        assert!(
            resolve_consent_connection(&client, "google", "this-consent-attempt")
                .await
                .unwrap_err()
                .to_string()
                .contains("expected 'google'")
        );
    }

    fn test_connection(
        id: &str,
        provider_slug: &str,
        account: &str,
    ) -> UserOAuthConnectionResponse {
        UserOAuthConnectionResponse {
            id: Uuid::parse_str(id).expect("valid connection id"),
            provider_id: Uuid::parse_str("99999999-9999-4999-8999-999999999999")
                .expect("valid provider id"),
            provider_slug: provider_slug.to_string(),
            provider_name: provider_slug.to_string(),
            provider_logo_url: None,
            provider_user_id: None,
            provider_email: Some(account.to_string()),
            scopes: Vec::new(),
            is_valid: true,
            is_default: false,
            expires_at: None,
            last_used_at: None,
            created_at: jiff::Timestamp::from_second(0).expect("valid timestamp"),
        }
    }

    #[test]
    fn resolve_connection_id_for_disconnect_rejects_multiple_provider_matches() {
        let connections = vec![
            test_connection(
                "11111111-1111-4111-8111-111111111111",
                "google",
                "first@example.com",
            ),
            test_connection(
                "22222222-2222-4222-8222-222222222222",
                "google",
                "second@example.com",
            ),
        ];

        let err = resolve_connection_id_for_disconnect(&connections, "google")
            .expect_err("multiple provider matches should be ambiguous");
        let message = err.to_string();

        assert!(message.contains("Multiple connections found for provider 'google'"));
        assert!(message.contains("11111111-1111-4111-8111-111111111111"));
        assert!(message.contains("22222222-2222-4222-8222-222222222222"));
    }
}
