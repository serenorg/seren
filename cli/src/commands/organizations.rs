use anyhow::Result;
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use seren::CreateOrganizationInviteRequest;
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub async fn list_members(organization_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_members(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list members: {}", e))?;

    let members = response.into_inner();
    match ctx.format {
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

            for member in &members.data {
                table.add_row(vec![
                    Cell::new(&member.email),
                    Cell::new(member.name.as_deref().unwrap_or("—")),
                    Cell::new(&member.role),
                    Cell::new(member.created_at.to_string()),
                ]);
            }

            println!("{table}");
        }
    }

    Ok(())
}

pub async fn list_invites(organization_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .list_invites(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list invites: {}", e))?;

    let invites = response.into_inner();
    match ctx.format {
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

            for invite in &invites.data {
                let is_accepted = invite.accepted_at.is_some();
                let is_revoked = invite.revoked_at.is_some();
                let is_expired = !is_accepted && !is_revoked; // UI computes actual expiry time; CLI keeps it simple.

                let status = if is_accepted {
                    "accepted"
                } else if is_revoked {
                    "revoked"
                } else if is_expired {
                    "expired"
                } else {
                    "pending"
                };

                table.add_row(vec![
                    Cell::new(&invite.email),
                    Cell::new(&invite.role),
                    Cell::new(&invite.expires_at),
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
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let payload = CreateOrganizationInviteRequest {
        email: email.to_string(),
        role: Some(role.to_string()),
    };

    let response = client
        .create_invite(&org_uuid, &payload)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create invite: {}", e))?;

    let invite = response.into_inner();
    match ctx.format {
        OutputFormat::Json => output::print_json(&invite)?,
        OutputFormat::Table => {
            println!("✓ Invite created");
            println!("  Email:   {}", invite.email);
            println!("  Role:    {}", invite.role);
            println!("  Expires: {}", invite.expires_at);
        }
    }

    Ok(())
}
