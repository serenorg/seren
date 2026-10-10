//! Owner-facing managed agent operations. Runtime-only record writes and browser relay APIs belong to the deployed runtime.

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum TemplateProvider {
    Google,
    Microsoft,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackRating {
    Great,
    Okay,
    NotQuite,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Approve,
    Decline,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    ApiKey,
    SignIn,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
    Applied,
    Reverted,
    Failed,
}

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum InboxDecision {
    Approve,
    AllowAlways,
    Deny,
}

#[derive(Subcommand)]
pub enum ManagedAction {
    /// Create a managed deployment from a published template using a connected account
    ManagedDeployTemplate {
        template: String,
        #[arg(long, value_enum)]
        provider: TemplateProvider,
        #[arg(long)]
        connection_id: Uuid,
        /// IANA time zone for the managed deployment's schedule
        #[arg(long)]
        timezone: String,
    },
    /// Read aggregate work hours and skill count for a published template
    ManagedTemplateStats { template: String },
    /// Replace a managed agent's connected mail and files account
    ManagedRebind {
        deployment_id: Uuid,
        #[arg(long)]
        connection_id: Uuid,
    },
    /// Read the managed agent's latest greeting, highlights, ideas, and check-in settings
    ManagedState { deployment_id: Uuid },
    /// Enable or disable weekly check-in email
    ManagedCheckins {
        deployment_id: Uuid,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        enabled: bool,
    },
    /// List completed work and its feedback
    ManagedWork {
        deployment_id: Uuid,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=50))]
        limit: Option<u32>,
    },
    /// Create a feedback record for one work revision
    ManagedFeedback {
        deployment_id: Uuid,
        work_id: Uuid,
        #[arg(long, value_enum)]
        rating: FeedbackRating,
        #[arg(long)]
        comment: Option<String>,
        /// Reuse this key when retrying a feedback submission
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Review publisher access requests or decide one request
    ManagedAccess {
        #[command(subcommand)]
        action: AccessAction,
    },
    /// Manage approved publisher account and API-key access
    ManagedGrants {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Inspect or revoke standing approvals for publisher actions
    ManagedAllowances {
        #[command(subcommand)]
        action: AllowanceAction,
    },
    /// Inspect a managed agent's live browser sign-in handoff
    ManagedHandoff {
        #[command(subcommand)]
        action: HandoffAction,
    },
    /// Review a managed agent's proposed changes to its skills or owner notes
    ManagedProposals {
        #[command(subcommand)]
        action: ProposalAction,
    },
    /// Publish a managed template release using a key scoped to managed-agent-template:publish
    ManagedPublishTemplateRelease {
        organization_id: Uuid,
        template: String,
        /// PublishManagedAgentTemplateReleaseRequest JSON file
        #[arg(long)]
        request: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AccessAction {
    List {
        deployment_id: Uuid,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: Option<u32>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Approval returns the browser consent action needed to finish granting access
    Decide {
        deployment_id: Uuid,
        request_id: Uuid,
        #[arg(long, value_enum)]
        decision: AccessDecision,
        #[arg(long)]
        redirect_origin: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum GrantAction {
    List {
        deployment_id: Uuid,
    },
    /// Start browser consent; requires an interactive OAuth user session
    Add {
        deployment_id: Uuid,
        #[arg(long)]
        publisher: String,
        #[arg(long, value_enum)]
        kind: GrantKind,
        #[arg(long)]
        connection_id: Option<Uuid>,
        #[arg(long)]
        redirect_origin: String,
    },
    Revoke {
        deployment_id: Uuid,
        grant_id: Uuid,
        /// Return origin when revocation needs fresh Passwords consent
        #[arg(long)]
        redirect_origin: Option<String>,
    },
    /// Confirm a completed signed sign-in consent; requires an interactive OAuth user session
    Confirm {
        deployment_id: Uuid,
        grant_id: Uuid,
        #[arg(long)]
        consent_id: Uuid,
    },
}

#[derive(Subcommand)]
pub enum AllowanceAction {
    List {
        deployment_id: Uuid,
    },
    Revoke {
        deployment_id: Uuid,
        allowance_id: Uuid,
    },
}

#[derive(Subcommand)]
pub enum HandoffAction {
    /// Read the active sign-in window, which expires within ten minutes
    Active { deployment_id: Uuid },
    /// Issue a one-use viewer WebSocket ticket, valid for 60 seconds
    Ticket {
        deployment_id: Uuid,
        handoff_id: Uuid,
    },
}

#[derive(Subcommand)]
pub enum ProposalAction {
    List {
        deployment_id: Uuid,
        #[arg(long, value_enum)]
        status: Option<ProposalStatus>,
    },
    Approve {
        deployment_id: Uuid,
        proposal_id: Uuid,
    },
    Reject {
        deployment_id: Uuid,
        proposal_id: Uuid,
    },
    /// Undo the latest applied proposal if its revision is still active
    Undo {
        deployment_id: Uuid,
        proposal_id: Uuid,
    },
}

#[derive(Subcommand)]
pub enum InboxAction {
    List {
        #[arg(long)]
        deployment_id: Option<Uuid>,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..=100))]
        limit: Option<i64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Decide exactly one inbox entry; email sends require each exact message's approval
    Decide {
        entry_id: String,
        #[arg(long, value_enum)]
        decision: InboxDecision,
        #[arg(long)]
        comment: Option<String>,
        /// ActionLease JSON file that bounds an allow-always approval; it must grant only the held operation
        #[arg(long)]
        lease: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum WalletAction {
    /// Read automatic reload settings
    ReloadSettings,
    /// Enable automatic reload with an amount and monthly spending cap
    EnableReload {
        #[arg(long, value_parser = clap::value_parser!(i32).range(1..))]
        amount_cents: i32,
        #[arg(long, value_parser = clap::value_parser!(i32).range(1..))]
        monthly_cap_cents: i32,
    },
    /// Disable automatic reload while preserving the saved amount and cap
    DisableReload,
    /// Claim the signup bonus
    SignupBonus,
    /// Claim the payment method bonus after saving a card
    PaymentMethodBonus,
}

fn bounded_limit(limit: Option<u32>, maximum: u32) -> Result<Option<std::num::NonZeroU32>> {
    limit
        .map(|limit| {
            if limit > maximum {
                anyhow::bail!("List limit must be between 1 and {maximum}.");
            }
            std::num::NonZeroU32::new(limit)
                .ok_or_else(|| anyhow::anyhow!("List limit must be greater than zero."))
        })
        .transpose()
}

fn typed_request<T: DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).context("Invalid request")
}

fn request_file<T: DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("Invalid request in {}", path.display()))
}

fn access_request(
    decision: AccessDecision,
    redirect_origin: Option<String>,
) -> Result<seren::DecidePublisherAccess> {
    if matches!(decision, AccessDecision::Decline) && redirect_origin.is_some() {
        anyhow::bail!("--redirect-origin applies only to an approve decision.");
    }
    let mut body = json!({"decision": decision});
    if matches!(decision, AccessDecision::Approve) {
        body["redirect_origin"] = json!(redirect_origin);
    }
    typed_request(body)
}

fn grant_request(
    kind: GrantKind,
    publisher: String,
    connection_id: Option<Uuid>,
    redirect_origin: String,
) -> Result<seren::AddManagedAgentPublisherGrant> {
    if matches!(kind, GrantKind::ApiKey) && connection_id.is_some() {
        anyhow::bail!("--connection-id applies only to a sign-in grant.");
    }
    let mut body =
        json!({"kind": kind, "publisher_slug": publisher, "redirect_origin": redirect_origin});
    if matches!(kind, GrantKind::SignIn) {
        body["oauth_connection_id"] = json!(connection_id);
    }
    typed_request(body)
}

fn inbox_request(
    decision: InboxDecision,
    comment: Option<String>,
    lease: Option<seren::ActionLease>,
) -> Result<seren::ApprovalInboxDecisionRequest> {
    if lease.is_some() && !matches!(decision, InboxDecision::AllowAlways) {
        anyhow::bail!("--lease applies only to an allow-always decision.");
    }
    typed_request(json!({"decision": decision, "comment": comment, "lease": lease}))
}

fn reload_request(
    enabled: bool,
    amount_cents: Option<i32>,
    monthly_cap_cents: Option<i32>,
) -> Result<seren::UpdateWalletAutoReloadSettings> {
    if enabled
        && !matches!((amount_cents, monthly_cap_cents), (Some(amount), Some(cap)) if amount > 0 && cap >= amount)
    {
        anyhow::bail!("The monthly cap must be at least the positive reload amount.");
    }
    if !enabled && (amount_cents.is_some() || monthly_cap_cents.is_some()) {
        anyhow::bail!("Disabling automatic reload accepts no amount or monthly cap.");
    }
    Ok(seren::UpdateWalletAutoReloadSettings {
        enabled,
        amount_cents,
        monthly_cap_cents,
    })
}

fn template_publication_timeout(rollout: Option<bool>) -> Option<u64> {
    (rollout == Some(true)).then_some(600)
}

pub(crate) fn print_response<T: Serialize>(payload: &T, ctx: &CommandContext) -> Result<()> {
    match ctx.format {
        OutputFormat::Json => output::print_json(payload),
        OutputFormat::Table => {
            let value = serde_json::to_value(payload)?;
            print_value(value.get("data").unwrap_or(&value));
            Ok(())
        }
    }
}

fn print_value(value: &Value) {
    match value {
        Value::Array(items) if items.is_empty() => println!("No results found"),
        Value::Array(items) => {
            for item in items {
                print_value(item);
            }
        }
        Value::Object(fields) => {
            let rows: Vec<(&str, String)> = fields
                .iter()
                .map(|(key, value)| {
                    let text = match value {
                        Value::String(text) => text.clone(),
                        Value::Null => "-".to_string(),
                        _ => serde_json::to_string_pretty(value).expect("JSON value serializes"),
                    };
                    (key.as_str(), text)
                })
                .collect();
            output::print_key_value_table(None, &rows);
        }
        _ => println!("{value}"),
    }
}

pub async fn execute(action: ManagedAction, ctx: &CommandContext) -> Result<()> {
    // These operations use the caller's owner credential. Core enforces ownership and rejects runtime/work-context credentials.
    let client = ctx.client().await?;
    macro_rules! respond {
        ($call:expr) => {{
            let response = match $call.await {
                Ok(response) => response,
                Err(error) => {
                    return Err(super::agent::anyhow_from_seren_error(
                        "Managed agent request failed",
                        error,
                    )
                    .await);
                }
            };
            print_response(&response.into_inner(), ctx)?;
        }};
    }
    match action {
        ManagedAction::ManagedDeployTemplate {
            template,
            provider,
            connection_id,
            timezone,
        } => {
            let request: seren::CreateManagedAgentTemplateDeploymentRequest = typed_request(
                json!({"provider": provider, "oauth_connection_id": connection_id, "timezone": timezone}),
            )?;
            respond!(
                client.seren_agent_create_managed_agent_template_deployment(&template, &request)
            );
        }
        ManagedAction::ManagedTemplateStats { template } => {
            respond!(client.seren_agent_get_managed_agent_template_stats(&template))
        }
        ManagedAction::ManagedRebind {
            deployment_id,
            connection_id,
        } => {
            respond!(client.seren_agent_rebind_managed_agent_connection(
                &deployment_id,
                &seren::RebindManagedAgentConnectionRequest {
                    oauth_connection_id: connection_id
                }
            ));
        }
        ManagedAction::ManagedState { deployment_id } => {
            respond!(client.seren_agent_get_managed_agent_state(&deployment_id))
        }
        ManagedAction::ManagedCheckins {
            deployment_id,
            enabled,
        } => respond!(client.seren_agent_update_managed_agent_checkins(
            &deployment_id,
            &seren::ManagedAgentCheckinsRequest { enabled }
        )),
        ManagedAction::ManagedWork {
            deployment_id,
            limit,
        } => respond!(
            client.seren_agent_list_managed_agent_work(&deployment_id, bounded_limit(limit, 50)?)
        ),
        ManagedAction::ManagedFeedback {
            deployment_id,
            work_id,
            rating,
            comment,
            idempotency_key,
        } => {
            let request: seren::ManagedAgentFeedbackRequest =
                typed_request(json!({"rating": rating, "comment": comment}))?;
            respond!(client.seren_agent_create_managed_agent_work_feedback(
                &deployment_id,
                &work_id,
                idempotency_key.as_deref(),
                &request
            ));
        }
        ManagedAction::ManagedAccess { action } => match action {
            AccessAction::List {
                deployment_id,
                limit,
                cursor,
            } => respond!(
                client.seren_agent_list_managed_agent_publisher_access_requests(
                    &deployment_id,
                    cursor.as_deref(),
                    bounded_limit(limit, 100)?
                )
            ),
            AccessAction::Decide {
                deployment_id,
                request_id,
                decision,
                redirect_origin,
            } => {
                let request = access_request(decision, redirect_origin)?;
                respond!(
                    client.seren_agent_decide_managed_agent_publisher_access_request(
                        &deployment_id,
                        &request_id,
                        &request
                    )
                );
            }
        },
        ManagedAction::ManagedGrants { action } => match action {
            GrantAction::List { deployment_id } => {
                respond!(client.seren_agent_list_managed_agent_publisher_grants(&deployment_id))
            }
            GrantAction::Add {
                deployment_id,
                publisher,
                kind,
                connection_id,
                redirect_origin,
            } => {
                let request = grant_request(kind, publisher, connection_id, redirect_origin)?;
                ctx.require_user_session("Adding publisher access").await?;
                respond!(
                    client.seren_agent_add_managed_agent_publisher_grant(&deployment_id, &request)
                );
            }
            GrantAction::Revoke {
                deployment_id,
                grant_id,
                redirect_origin,
            } => {
                let request = seren::RevokeManagedAgentPublisherGrant { redirect_origin };
                respond!(client.seren_agent_revoke_managed_agent_publisher_grant(
                    &deployment_id,
                    &grant_id,
                    &request
                ));
            }
            GrantAction::Confirm {
                deployment_id,
                grant_id,
                consent_id,
            } => {
                ctx.require_user_session("Confirming publisher sign-in consent")
                    .await?;
                respond!(client.seren_agent_confirm_managed_agent_publisher_consent(
                    &deployment_id,
                    &grant_id,
                    &seren::ConfirmPublisherConnectionGrant { consent_id }
                ));
            }
        },
        ManagedAction::ManagedAllowances { action } => match action {
            AllowanceAction::List { deployment_id } => {
                respond!(client.seren_agent_list_managed_publisher_allowances(&deployment_id))
            }
            AllowanceAction::Revoke {
                deployment_id,
                allowance_id,
            } => respond!(
                client
                    .seren_agent_revoke_managed_publisher_allowance(&deployment_id, &allowance_id)
            ),
        },
        ManagedAction::ManagedHandoff { action } => match action {
            HandoffAction::Active { deployment_id } => respond!(
                client.seren_agent_get_active_managed_agent_browser_handoff(&deployment_id)
            ),
            HandoffAction::Ticket {
                deployment_id,
                handoff_id,
            } => respond!(
                client.seren_agent_create_managed_agent_browser_handoff_ticket(
                    &deployment_id,
                    &handoff_id
                )
            ),
        },
        ManagedAction::ManagedProposals { action } => match action {
            ProposalAction::List {
                deployment_id,
                status,
            } => {
                let status: Option<seren::ManagedAgentProposalStatus> = status
                    .map(|status| typed_request(json!(status)))
                    .transpose()?;
                respond!(
                    client.seren_agent_list_managed_agent_skill_change_proposals(
                        &deployment_id,
                        status
                    )
                );
            }
            ProposalAction::Approve {
                deployment_id,
                proposal_id,
            } => respond!(
                client.seren_agent_approve_managed_agent_skill_change_proposal(
                    &deployment_id,
                    &proposal_id
                )
            ),
            ProposalAction::Reject {
                deployment_id,
                proposal_id,
            } => respond!(
                client.seren_agent_reject_managed_agent_skill_change_proposal(
                    &deployment_id,
                    &proposal_id
                )
            ),
            ProposalAction::Undo {
                deployment_id,
                proposal_id,
            } => respond!(client.seren_agent_undo_managed_agent_skill_change_proposal(
                &deployment_id,
                &proposal_id
            )),
        },
        ManagedAction::ManagedPublishTemplateRelease {
            organization_id,
            template,
            request,
        } => {
            let request: seren::PublishManagedAgentTemplateReleaseRequest = request_file(&request)?;
            let client = if let Some(timeout) = template_publication_timeout(request.rollout) {
                let bearer_token = super::auth::get_bearer_token(ctx.api_key.clone()).await?;
                seren::Client::from_config(
                    &seren::ClientConfig::new(bearer_token)
                        .with_base_url(ctx.api_base())
                        .with_timeout(timeout),
                )?
            } else {
                client
            };
            respond!(client.publish_managed_agent_template_release(
                &organization_id,
                &template,
                &request
            ));
        }
    }
    Ok(())
}

pub async fn execute_inbox(action: InboxAction, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    macro_rules! respond {
        ($call:expr) => {{
            let response = match $call.await {
                Ok(response) => response,
                Err(error) => {
                    return Err(super::agent::anyhow_from_seren_error(
                        "Approval inbox request failed",
                        error,
                    )
                    .await);
                }
            };
            print_response(&response.into_inner(), ctx)?;
        }};
    }
    match action {
        InboxAction::List {
            deployment_id,
            limit,
            cursor,
        } => respond!(client.seren_cloud_approval_inbox_list(
            cursor.as_deref(),
            deployment_id.as_ref(),
            limit
        )),
        InboxAction::Decide {
            entry_id,
            decision,
            comment,
            lease,
        } => {
            let lease = lease
                .as_ref()
                .map(request_file::<seren::ActionLease>)
                .transpose()?;
            let request = inbox_request(decision, comment, lease)?;
            respond!(client.seren_cloud_approval_inbox_decide(&entry_id, &request));
        }
    }
    Ok(())
}

pub async fn execute_wallet(action: WalletAction, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    macro_rules! respond {
        ($call:expr) => {{
            let response = match $call.await {
                Ok(response) => response,
                Err(error) => {
                    return Err(super::agent::anyhow_from_seren_error(
                        "Wallet request failed",
                        error,
                    )
                    .await);
                }
            };
            print_response(&response.into_inner(), ctx)?;
        }};
    }
    match action {
        WalletAction::ReloadSettings => respond!(client.get_reload_settings()),
        WalletAction::EnableReload {
            amount_cents,
            monthly_cap_cents,
        } => {
            let request = reload_request(true, Some(amount_cents), Some(monthly_cap_cents))?;
            respond!(client.update_reload_settings(&request));
        }
        WalletAction::DisableReload => {
            let request = reload_request(false, None, None)?;
            respond!(client.update_reload_settings(&request));
        }
        WalletAction::SignupBonus => respond!(client.claim_signup_bonus()),
        WalletAction::PaymentMethodBonus => respond!(client.claim_payment_method_bonus()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct ManagedCli {
        #[command(subcommand)]
        action: ManagedAction,
    }

    #[test]
    fn managed_commands_parse_owner_actions_and_bound_page_sizes() {
        let id = "11111111-1111-4111-8111-111111111111";
        let cli = ManagedCli::try_parse_from([
            "agent",
            "managed-deploy-template",
            "camilla",
            "--provider",
            "google",
            "--connection-id",
            id,
            "--timezone",
            "America/New_York",
        ])
        .unwrap();
        assert!(matches!(
            cli.action,
            ManagedAction::ManagedDeployTemplate {
                provider: TemplateProvider::Google,
                ..
            }
        ));
        assert!(
            ManagedCli::try_parse_from(["agent", "managed-work", id, "--limit", "51"]).is_err()
        );
        assert!(ManagedCli::try_parse_from(["agent", "managed-checkins", id]).is_err());
        let cli =
            ManagedCli::try_parse_from(["agent", "managed-checkins", id, "--enabled", "false"])
                .unwrap();
        assert!(matches!(
            cli.action,
            ManagedAction::ManagedCheckins { enabled: false, .. }
        ));
        // Runtime-only capabilities are absent from the owner surface.
        assert!(ManagedCli::try_parse_from(["agent", "managed-handoff", "create", id]).is_err());
        assert!(ManagedCli::try_parse_from(["agent", "managed-proposals", "create", id]).is_err());
    }

    #[test]
    fn only_requested_rollouts_override_the_publication_timeout() {
        assert_eq!(template_publication_timeout(None), None);
        assert_eq!(template_publication_timeout(Some(false)), None);
        assert_eq!(template_publication_timeout(Some(true)), Some(600));
    }

    #[tokio::test]
    async fn template_publication_forwards_rollout_selection_and_authentication() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for rollout in [None, Some(false), Some(true)] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let mut request = json!({
                "display_name": "Release test",
                "source_bundle_id": Uuid::new_v4(),
                "source_commit_sha": "a".repeat(40),
                "deploy_defaults": {
                    "mode": "cron", "cron_schedule": "0 9 * * *",
                    "model_policy": "balanced", "max_runtime_seconds": 300,
                    "browser": {"display": "headless", "max_session_seconds": 60},
                    "network_egress": [], "script_publisher_grants": []
                }
            });
            if let Some(rollout) = rollout {
                request["rollout"] = json!(rollout);
            }
            let mut response = json!({"data": {
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true,
                "providers": ["google", "microsoft"]
            }});
            if rollout == Some(true) {
                response["data"]["rollout"] = json!({
                    "template_slug": "release-test", "template_revision": 8,
                    "deployments": [{"deployment_id": Uuid::new_v4(), "outcome": "hire_incomplete"}]
                });
            }
            Mock::given(method("POST"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/release-test/releases"
                )))
                .and(header("Authorization", "Bearer seren_test_key"))
                .and(body_json(request.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let fixture = tempfile::tempdir().unwrap();
            let request_path = fixture.path().join("release.json");
            fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
            let context = CommandContext::new(
                Some(server.uri()),
                Some("seren_test_key".into()),
                OutputFormat::Json,
            );
            execute(
                ManagedAction::ManagedPublishTemplateRelease {
                    organization_id,
                    template: "release-test".into(),
                    request: request_path,
                },
                &context,
            )
            .await
            .unwrap();
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[test]
    fn owner_access_decisions_keep_the_selected_operation() {
        let request = access_request(
            AccessDecision::Approve,
            Some("https://app.example.test".into()),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"decision": "approve", "redirect_origin": "https://app.example.test"})
        );
        let request = access_request(AccessDecision::Decline, None).unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"decision": "decline"})
        );
        assert!(
            access_request(
                AccessDecision::Decline,
                Some("https://app.example.test".into())
            )
            .is_err()
        );
    }

    #[test]
    fn grant_requests_accept_only_sign_in_connection_ids() {
        let id = Uuid::new_v4();
        assert!(
            grant_request(
                GrantKind::ApiKey,
                "canva".into(),
                Some(id),
                "https://app.example.test".into()
            )
            .is_err()
        );
        let request = grant_request(
            GrantKind::SignIn,
            "google-drive".into(),
            Some(id),
            "https://app.example.test".into(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap()["oauth_connection_id"],
            json!(id)
        );
    }

    #[test]
    fn inbox_decisions_preserve_exact_entry_semantics() {
        let request = inbox_request(
            InboxDecision::AllowAlways,
            Some("approved scope".into()),
            None,
        )
        .unwrap();
        let body = serde_json::to_value(request).unwrap();
        assert_eq!(body["decision"], "allow_always");
        assert_eq!(body["comment"], "approved scope");
        let lease =
            typed_request(json!({"action": "send", "capability": {"kind": "all"}})).unwrap();
        assert!(inbox_request(InboxDecision::Approve, None, Some(lease)).is_err());
    }

    #[test]
    fn reload_configuration_checks_the_spending_cap_and_disable_shape() {
        assert!(reload_request(true, Some(1000), Some(999)).is_err());
        assert!(reload_request(true, None, Some(1000)).is_err());
        assert!(reload_request(false, Some(1000), None).is_err());
        let disabled = reload_request(false, None, None).unwrap();
        assert!(!disabled.enabled);
        assert!(disabled.amount_cents.is_none());
        let enabled = reload_request(true, Some(1000), Some(2000)).unwrap();
        assert_eq!(enabled.monthly_cap_cents, Some(2000));
    }

    #[tokio::test]
    async fn inbox_decision_sends_only_the_selected_entry_with_its_lease() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let entry = "tool:run-1:call-2";
        let lease = json!({"action": "calendar.create", "capability": {"kind": "specific", "actions": ["calendar.create"]}, "use_budget": 3});
        Mock::given(method("POST"))
            .and(path(format!("/publishers/seren-cloud/inbox/approvals/{entry}/decide")))
            .and(body_json(json!({"decision": "allow_always", "comment": "three matching actions", "lease": lease})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"entry_id": entry, "decision_state": "approved"}})))
            .expect(1)
            .mount(&server)
            .await;
        let fixture = tempfile::tempdir().unwrap();
        let lease_path = fixture.path().join("lease.json");
        fs::write(&lease_path, serde_json::to_vec(&lease).unwrap()).unwrap();
        let context = CommandContext::new(
            Some(server.uri()),
            Some("test-key".into()),
            OutputFormat::Json,
        );
        execute_inbox(
            InboxAction::Decide {
                entry_id: entry.into(),
                decision: InboxDecision::AllowAlways,
                comment: Some("three matching actions".into()),
                lease: Some(lease_path),
            },
            &context,
        )
        .await
        .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn grant_creation_with_api_key_is_rejected_before_mutation() {
        let server = wiremock::MockServer::start().await;
        let context = CommandContext::new(
            Some(server.uri()),
            Some("seren_test_key".into()),
            OutputFormat::Json,
        );
        let error = execute(
            ManagedAction::ManagedGrants {
                action: GrantAction::Add {
                    deployment_id: Uuid::new_v4(),
                    publisher: "canva".into(),
                    kind: GrantKind::ApiKey,
                    connection_id: None,
                    redirect_origin: "https://app.example.test".into(),
                },
            },
            &context,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("interactive OAuth user session"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
