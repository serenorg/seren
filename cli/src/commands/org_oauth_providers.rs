//! Organization OAuth provider management commands.
//!
//! These commands allow organization admins to create, list, update, and delete
//! OAuth provider configurations for BYOC (Bring Your Own Credentials) authentication.

use anyhow::{Context, Result};
use colored::Colorize;
use seren::{CreateOAuthProviderRequest, UpdateOAuthProviderRequest};
use uuid::Uuid;

use crate::CommandContext;

/// List OAuth providers for an organization
pub async fn list(organization_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_org_oauth_providers(&org_uuid)
        .await
        .context("Failed to list OAuth providers")?;

    let providers = response.into_inner().data;

    if providers.is_empty() {
        println!("No OAuth providers configured for this organization.");
        println!();
        println!(
            "Use {} to create one.",
            "seren org-oauth-providers create".cyan()
        );
        return Ok(());
    }

    println!("{}", "Organization OAuth Providers".bold().underline());
    println!();

    for provider in providers {
        let status = if provider.is_active {
            "active".green()
        } else {
            "inactive".yellow()
        };

        println!("  {} ({})", provider.name.bold(), provider.slug.cyan());
        println!("    ID: {}", provider.id);
        println!("    Status: {}", status);
        if let Some(desc) = &provider.description {
            println!("    Description: {}", desc);
        }
        println!("    Authorization URL: {}", provider.authorization_url);
        println!("    Token URL: {}", provider.token_url);
        println!("    Client ID: {}", provider.client_id);
        if !provider.scopes.is_empty() {
            println!("    Scopes: {}", provider.scopes.join(", "));
        }
        println!("    PKCE Required: {}", provider.pkce_required);
        println!(
            "    Token Auth Method: {}",
            provider.token_endpoint_auth_method
        );
        println!();
    }

    Ok(())
}

/// Get a specific OAuth provider
pub async fn get(organization_id: &str, provider_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let provider_uuid =
        Uuid::parse_str(provider_id).map_err(|e| anyhow::anyhow!("Invalid provider ID: {}", e))?;

    let response = client
        .get_org_oauth_provider(&org_uuid, &provider_uuid)
        .await
        .context("Failed to get OAuth provider")?;

    let provider = response.into_inner().data;

    println!("{}", "OAuth Provider Details".bold().underline());
    println!();
    println!("  Name: {}", provider.name.bold());
    println!("  Slug: {}", provider.slug.cyan());
    println!("  ID: {}", provider.id);
    println!(
        "  Status: {}",
        if provider.is_active {
            "active".green()
        } else {
            "inactive".yellow()
        }
    );
    if let Some(desc) = &provider.description {
        println!("  Description: {}", desc);
    }
    if let Some(logo) = &provider.logo_url {
        println!("  Logo URL: {}", logo);
    }
    println!();
    println!("{}", "OAuth Configuration".bold());
    println!("  Authorization URL: {}", provider.authorization_url);
    println!("  Token URL: {}", provider.token_url);
    if let Some(userinfo) = &provider.userinfo_url {
        println!("  Userinfo URL: {}", userinfo);
    }
    if let Some(revocation) = &provider.revocation_url {
        println!("  Revocation URL: {}", revocation);
    }
    println!("  Client ID: {}", provider.client_id);
    println!("  Scopes: {}", provider.scopes.join(", "));
    println!("  PKCE Required: {}", provider.pkce_required);
    println!(
        "  Token Auth Method: {}",
        provider.token_endpoint_auth_method
    );
    println!();
    println!("{}", "Timestamps".bold());
    println!("  Created: {}", provider.created_at);
    println!("  Updated: {}", provider.updated_at);

    Ok(())
}

/// Create a new OAuth provider
#[allow(clippy::too_many_arguments)]
pub async fn create(
    organization_id: &str,
    slug: &str,
    name: &str,
    authorization_url: &str,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    description: Option<&str>,
    logo_url: Option<&str>,
    userinfo_url: Option<&str>,
    revocation_url: Option<&str>,
    scopes: &[String],
    pkce_required: bool,
    token_endpoint_auth_method: Option<&str>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let request = CreateOAuthProviderRequest {
        userinfo_method: None,
        userinfo_id_path: None,
        userinfo_email_path: None,
        revocation_auth: None,
        slug: slug.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        logo_url: logo_url.map(String::from),
        authorization_url: authorization_url.to_string(),
        token_url: token_url.to_string(),
        userinfo_url: userinfo_url.map(String::from),
        revocation_url: revocation_url.map(String::from),
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        scopes: scopes.to_vec(),
        custom_auth_params: None,
        pkce_required: Some(pkce_required),
        token_endpoint_auth_method: token_endpoint_auth_method.map(|s| s.parse()).transpose()?,
    };

    let response = client
        .create_org_oauth_provider(&org_uuid, &request)
        .await
        .context("Failed to create OAuth provider")?;

    let provider = response.into_inner().data;

    println!(
        "{}",
        format!("✓ Created OAuth provider '{}'", provider.name)
            .green()
            .bold()
    );
    println!();
    println!("  ID: {}", provider.id);
    println!("  Slug: {}", provider.slug.cyan());

    Ok(())
}

/// Update an OAuth provider
#[allow(clippy::too_many_arguments)]
pub async fn update(
    organization_id: &str,
    provider_id: &str,
    name: Option<&str>,
    description: Option<Option<&str>>,
    logo_url: Option<Option<&str>>,
    authorization_url: Option<&str>,
    token_url: Option<&str>,
    userinfo_url: Option<Option<&str>>,
    revocation_url: Option<Option<&str>>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    scopes: Option<&[String]>,
    pkce_required: Option<bool>,
    token_endpoint_auth_method: Option<&str>,
    is_active: Option<bool>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let provider_uuid =
        Uuid::parse_str(provider_id).map_err(|e| anyhow::anyhow!("Invalid provider ID: {}", e))?;

    let request = UpdateOAuthProviderRequest {
        userinfo_method: None,
        userinfo_id_path: None,
        userinfo_email_path: None,
        revocation_auth: None,
        slug: None, // Slug cannot be changed after creation
        name: name.map(String::from),
        description: description.map(|value| value.map(String::from)),
        logo_url: logo_url.map(|value| value.map(String::from)),
        authorization_url: authorization_url.map(String::from),
        token_url: token_url.map(String::from),
        userinfo_url: userinfo_url.map(|value| value.map(String::from)),
        revocation_url: revocation_url.map(|value| value.map(String::from)),
        client_id: client_id.map(String::from),
        client_secret: client_secret.map(String::from),
        scopes: scopes.map(|s| s.to_vec()),
        custom_auth_params: None,
        pkce_required,
        token_endpoint_auth_method: token_endpoint_auth_method.map(|s| s.parse()).transpose()?,
        is_active,
        organization_id: None,
    };

    let response = client
        .update_org_oauth_provider(&org_uuid, &provider_uuid, &request)
        .await
        .context("Failed to update OAuth provider")?;

    let provider = response.into_inner().data;

    println!(
        "{}",
        format!("✓ Updated OAuth provider '{}'", provider.name)
            .green()
            .bold()
    );

    Ok(())
}

/// Delete an OAuth provider
pub async fn delete(organization_id: &str, provider_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let provider_uuid =
        Uuid::parse_str(provider_id).map_err(|e| anyhow::anyhow!("Invalid provider ID: {}", e))?;

    client
        .delete_org_oauth_provider(&org_uuid, &provider_uuid)
        .await
        .context("Failed to delete OAuth provider")?;

    println!(
        "{}",
        format!("✓ Deleted OAuth provider {}", provider_id)
            .green()
            .bold()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    #[tokio::test]
    async fn oauth_provider_update_sends_clear_omit_empty_and_false_values() {
        for (nullable, expected) in [
            (
                None,
                json!({"is_active": false, "pkce_required": false, "scopes": []}),
            ),
            (
                Some(None),
                json!({"description": null, "logo_url": null, "userinfo_url": null,
                "revocation_url": null, "is_active": false, "pkce_required": false, "scopes": []}),
            ),
            (
                Some(Some("")),
                json!({"description": "", "logo_url": "", "userinfo_url": "",
                "revocation_url": "", "is_active": false, "pkce_required": false, "scopes": []}),
            ),
            (
                Some(Some("value")),
                json!({"description": "value", "logo_url": "value", "userinfo_url": "value",
                "revocation_url": "value", "is_active": false, "pkce_required": false, "scopes": []}),
            ),
        ] {
            let proxy = MockServer::start().await;
            let organization_id = Uuid::from_u128(1);
            let provider_id = Uuid::from_u128(2);
            Mock::given(method("PATCH"))
                .and(path(format!(
                    "/organizations/{organization_id}/oauth/providers/{provider_id}"
                )))
                .and(header("authorization", "Bearer test-key"))
                .and(body_json(expected.clone()))
                .respond_with(ResponseTemplate::new(409))
                .expect(1)
                .mount(&proxy)
                .await;
            let ctx = CommandContext::new(
                Some(proxy.uri()),
                Some("test-key".into()),
                crate::OutputFormat::Json,
            );
            let result = update(
                &organization_id.to_string(),
                &provider_id.to_string(),
                None,
                nullable,
                nullable,
                None,
                None,
                nullable,
                nullable,
                None,
                None,
                Some(&[]),
                Some(false),
                None,
                Some(false),
                &ctx,
            )
            .await;
            assert!(
                result.is_err(),
                "the loopback server refuses after inspecting the patch"
            );
            let received = proxy.received_requests().await.unwrap();
            assert_eq!(received.len(), 1);
            assert_eq!(
                received[0].body_json::<serde_json::Value>().unwrap(),
                expected
            );
        }
    }
}
