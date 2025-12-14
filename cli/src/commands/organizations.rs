use anyhow::Result;
use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use seren::{Client, ClientConfig, CreateOrganizationInviteRequest};

use crate::{commands::auth::get_bearer_token, output, OutputFormat};

async fn get_client(api_host: Option<String>, api_key: Option<String>) -> Result<Client> {
    let bearer_token = get_bearer_token(api_key).await?;

    let mut client_config = ClientConfig::new(bearer_token);

    if let Some(host) = api_host {
        client_config = client_config.with_base_url(host);
    }

    Client::new(client_config).map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
}

pub async fn list_members(
    organization_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let members = client
        .organization_members(organization_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list members: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&members)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.set_header(vec![
                Cell::new("Email").fg(Color::Green),
                Cell::new("Name").fg(Color::Green),
                Cell::new("Role").fg(Color::Green),
                Cell::new("Joined").fg(Color::Green),
            ]);

            for member in members {
                table.add_row(vec![
                    Cell::new(member.email),
                    Cell::new(member.name.unwrap_or_else(|| "—".to_string())),
                    Cell::new(member.role),
                    Cell::new(member.created_at),
                ]);
            }

            println!("{table}");
        }
    }

    Ok(())
}

pub async fn list_invites(
    organization_id: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let invites = client
        .organization_invites(organization_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list invites: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&invites)?,
        OutputFormat::Table => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic);

            table.set_header(vec![
                Cell::new("Email").fg(Color::Green),
                Cell::new("Role").fg(Color::Green),
                Cell::new("Expires").fg(Color::Green),
                Cell::new("Status").fg(Color::Green),
            ]);

            for invite in invites {
                let is_accepted = invite.data.accepted_at.is_some();
                let is_revoked = invite.data.revoked_at.is_some();
                let is_expired = !is_accepted && !is_revoked; // UI computes actual expiry time; CLI keeps it simple.

                let status = if is_accepted {
                    "accepted"
                } else if is_revoked {
                    "revoked"
                } else if is_expired {
                    "pending"
                } else {
                    "pending"
                };

                table.add_row(vec![
                    Cell::new(&invite.data.email),
                    Cell::new(&invite.data.role),
                    Cell::new(&invite.data.expires_at),
                    Cell::new(status),
                ]);
            }

            println!("{table}");
        }
    }

    Ok(())
}

pub async fn create_invite(
    organization_id: &str,
    email: &str,
    role: &str,
    format: OutputFormat,
    api_host: Option<String>,
    api_key: Option<String>,
) -> Result<()> {
    let client = get_client(api_host, api_key).await?;

    let payload = CreateOrganizationInviteRequest {
        email: email.to_string(),
        role: Some(role.to_string()),
    };

    let invite = client
        .create_organization_invite(organization_id, &payload)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create invite: {}", e))?;

    match format {
        OutputFormat::Json => output::print_json(&invite)?,
        OutputFormat::Table => {
            println!("✓ Invite created");
            println!("  Email:   {}", invite.data.email);
            println!("  Role:    {}", invite.data.role);
            println!("  Expires: {}", invite.data.expires_at);
        }
    }

    Ok(())
}
