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
            let data = &invite.data;
            println!("✓ Invite created");
            println!("  Email:   {}", data.email);
            println!("  Role:    {}", data.role);
            println!("  Expires: {}", data.expires_at);
        }
    }

    Ok(())
}

pub async fn private_models_policy_get(organization_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;

    let response = client
        .get_private_models_policy(&org_uuid)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get private-model policy: {}", e))?
        .into_inner();

    print_private_models_policy_response(&response, ctx.format)
}

pub async fn private_models_policy_update(
    organization_id: &str,
    body: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let org_uuid = Uuid::parse_str(organization_id)
        .map_err(|e| anyhow::anyhow!("Invalid organization ID: {}", e))?;
    let request: seren::UpdateOrganizationPrivateModelsPolicyRequest =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("Invalid policy JSON: {}", e))?;

    let response = client
        .update_private_models_policy(&org_uuid, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to update private-model policy: {}", e))?
        .into_inner();

    print_private_models_policy_response(&response, ctx.format)
}

fn print_private_models_policy_response(
    response: &seren::DataResponseOrganizationPrivateModelsPolicy,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Json => output::print_json(response)?,
        OutputFormat::Table => {
            let policy = &response.data;
            let rows = [
                ("Organization ID", policy.organization_id.to_string()),
                ("Mode", policy.mode.to_string()),
                (
                    "Deployment ID",
                    option_to_string(policy.deployment_id.as_ref()),
                ),
                (
                    "Deployment Name",
                    policy
                        .deployment_name
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                ),
                ("Model ID", option_to_string(policy.model_id.as_ref())),
                (
                    "Disable Seren Models",
                    option_to_string(policy.disable_seren_models.as_ref()),
                ),
                (
                    "Disable External Providers",
                    option_to_string(policy.disable_external_model_providers.as_ref()),
                ),
                (
                    "Disable Local Agents",
                    option_to_string(policy.disable_local_agents.as_ref()),
                ),
                (
                    "Allow Seren Agent",
                    option_to_string(policy.allow_seren_agent.as_ref()),
                ),
                (
                    "Allow Cloud Agent Launch",
                    option_to_string(policy.allow_cloud_agent_launch.as_ref()),
                ),
                ("Updated At", policy.updated_at.to_string()),
            ];
            output::print_key_value_table(Some("Private Model Policy"), &rows);
        }
    }

    Ok(())
}

fn option_to_string<T: std::fmt::Display>(value: Option<&T>) -> String {
    value
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_string())
}
