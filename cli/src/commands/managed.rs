//! Owner-facing managed agent operations. Runtime-only record writes and browser relay APIs belong to the deployed runtime.

use std::{
    fs,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ReleaseSourceProduct {
    #[value(alias = "github_actions")]
    GithubActions,
    Gitlab,
    Circleci,
}

impl From<ReleaseSourceProduct> for seren::ReleaseCiProduct {
    fn from(product: ReleaseSourceProduct) -> Self {
        match product {
            ReleaseSourceProduct::GithubActions => Self::GithubActions,
            ReleaseSourceProduct::Gitlab => Self::Gitlab,
            ReleaseSourceProduct::Circleci => Self::Circleci,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum HeldReleaseStatusFilter {
    Pending,
    Approved,
    Refused,
    Replaced,
    Lapsed,
    Cancelled,
}

impl From<HeldReleaseStatusFilter> for seren::HeldReleaseStatus {
    fn from(status: HeldReleaseStatusFilter) -> Self {
        match status {
            HeldReleaseStatusFilter::Pending => Self::Pending,
            HeldReleaseStatusFilter::Approved => Self::Approved,
            HeldReleaseStatusFilter::Refused => Self::Refused,
            HeldReleaseStatusFilter::Replaced => Self::Replaced,
            HeldReleaseStatusFilter::Lapsed => Self::Lapsed,
            HeldReleaseStatusFilter::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(Subcommand)]
pub enum ManagedAction {
    /// Create a managed deployment from a published template
    ManagedDeployTemplate {
        template: String,
        /// Mail provider; sent only when --connection-id is supplied
        #[arg(long, value_enum)]
        provider: Option<TemplateProvider>,
        /// Mail connection; omit both flags for sign-in-only or unlinked mail-read hires
        #[arg(long, requires = "provider")]
        connection_id: Option<Uuid>,
        /// IANA time zone for the managed deployment's schedule
        #[arg(long)]
        timezone: String,
    },
    /// Read aggregate work hours and skill count for a published template
    ManagedTemplateStats { template: String },
    /// List the runs of an Employee your organization publishes, newest first
    ManagedTemplateRuns {
        template: String,
        /// Only runs that ended this way, such as `completed` or `script_failed`
        #[arg(long)]
        ending: Option<String>,
        /// Only runs started at or after this RFC 3339 time
        #[arg(long)]
        since: Option<String>,
        /// Only runs started before this RFC 3339 time
        #[arg(long)]
        until: Option<String>,
        /// Only runs of this Employer number, or `yours` for your organization's runs
        #[arg(long)]
        employer: Option<String>,
        /// Only runs of this release
        #[arg(long)]
        release: Option<i64>,
        /// Maximum runs to return, 20 by default
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..=100))]
        limit: Option<i64>,
        /// Runs to skip
        #[arg(long, value_parser = clap::value_parser!(i64).range(0..))]
        offset: Option<i64>,
    },
    /// Read one run's timeline of an Employee your organization publishes
    ManagedTemplateRun {
        template: String,
        /// Run code, such as `R-7F3K`
        run_code: String,
        /// Print new steps every 5 seconds until the run ends
        #[arg(long)]
        follow: bool,
    },
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
    /// List the publishing organization's Employee templates, including pending and rejected entries
    ManagedTemplates { organization_id: Uuid },
    /// Read or edit an Employee template's catalog profile
    ManagedTemplateProfile {
        #[command(subcommand)]
        action: TemplateProfileAction,
    },
    /// Set the Owner's listing preference; approval and activation are also required for new hires
    ManagedTemplateListing {
        organization_id: Uuid,
        template: String,
        #[arg(long, action = clap::ArgAction::Set, required = true)]
        listed: bool,
    },
    /// Resubmit a rejected Employee template for review
    ManagedTemplateReview {
        organization_id: Uuid,
        template: String,
    },
    /// Publish a managed template release using a key scoped to managed-agent-template:publish
    ManagedPublishTemplateRelease {
        organization_id: Uuid,
        template: String,
        /// PublishManagedAgentTemplateReleaseRequest JSON file
        #[arg(long)]
        request: PathBuf,
    },
    /// Get a short-lived release pass for an organization
    ManagedReleasePass { organization_id: Uuid },
    /// Package an Employee folder, upload its bundle, and release it with a release pass
    ManagedRelease {
        organization_id: Uuid,
        folder: PathBuf,
        /// Release settings JSON file (defaults to `<folder>/seren-release.json`)
        #[arg(long)]
        settings: Option<PathBuf>,
        /// Full commit SHA (40 or 64 hex characters); defaults to `git -C <folder> rev-parse HEAD`
        #[arg(long)]
        commit: Option<String>,
    },
    /// List, approve, edit, or revoke Employee release sources
    ManagedReleaseSources {
        organization_id: Uuid,
        #[command(subcommand)]
        action: ReleaseSourceAction,
    },
    /// List, approve, or refuse held Employee releases
    ManagedHeldReleases {
        organization_id: Uuid,
        #[command(subcommand)]
        action: HeldReleaseAction,
    },
}

#[derive(Subcommand)]
pub enum ReleaseSourceAction {
    /// List approved release sources for the organization
    List,
    /// Approve a CI repository and branch as a signed-run release source; requires browser login
    Approve {
        /// CI product that signs release runs
        #[arg(long, value_enum)]
        product: ReleaseSourceProduct,
        /// Repository as named by the CI product (`owner/name`, GitLab project path, or `host/org/repo`)
        #[arg(long)]
        repository: String,
        /// Branch name, not a `refs/` path
        #[arg(long)]
        branch: String,
        /// CI environment required on the run, if any
        #[arg(long)]
        environment: Option<String>,
        /// Token issuer URL (optional for GitLab, required for CircleCI)
        #[arg(long)]
        issuer: Option<String>,
        /// Human-readable label for this release source
        #[arg(long)]
        label: String,
        /// Employee template slug this source may release (repeat for multiple)
        #[arg(long = "template", value_name = "SLUG", required = true)]
        templates: Vec<String>,
    },
    /// Create a short-lived organization release key (1 to 30 days); requires browser login
    CreateKey {
        /// Human-readable label for this release key
        #[arg(long)]
        label: String,
        /// Lifetime in days, from 1 to 30
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..=30))]
        days: i64,
        /// Employee template slug this key may release (repeat for multiple)
        #[arg(long = "template", value_name = "SLUG", required = true)]
        templates: Vec<String>,
    },
    /// Edit an approved release source; requires browser login
    Edit {
        release_source_id: Uuid,
        /// Replace the release source label
        #[arg(long)]
        label: Option<String>,
        /// Replace the branch for a signed-run source
        #[arg(long)]
        branch: Option<String>,
        /// Set or replace the required CI environment for a signed-run source
        #[arg(long)]
        environment: Option<String>,
        /// Remove the CI environment requirement from a signed-run source
        #[arg(long, conflicts_with = "environment")]
        clear_environment: bool,
        /// Replace the Employee template slugs this source may release (repeat for multiple)
        #[arg(long = "template", value_name = "SLUG")]
        templates: Vec<String>,
    },
    /// Revoke an approved release source; requires browser login
    Revoke { release_source_id: Uuid },
}

#[derive(Subcommand)]
pub enum HeldReleaseAction {
    /// List held releases for the organization (pending by default)
    List {
        /// Filter by held release status
        #[arg(long, value_enum)]
        status: Option<HeldReleaseStatusFilter>,
    },
    /// Approve a held release after reviewing its changes
    Approve {
        held_release_id: Uuid,
        /// Fingerprint of the reviewed changes; omitted to fetch, show, and approve current changes
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Refuse a held release with an explanation
    Refuse {
        held_release_id: Uuid,
        /// Reason for refusing the release (1 to 2000 characters)
        #[arg(long)]
        note: String,
    },
}

#[derive(Subcommand)]
pub enum TemplateProfileAction {
    Get {
        organization_id: Uuid,
        template: String,
    },
    /// Change only supplied fields; null clears text and an empty list clears that list.
    ///
    /// Set `display_name` to rename the Employee. A rename costs $1.00 in
    /// SerenBucks from your wallet, and the old name is retired: no Owner can
    /// choose it again.
    Update {
        organization_id: Uuid,
        template: String,
        /// PutManagedAgentTemplateProfile JSON file; `display_name` renames for $1.00
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

const TEMPLATE_ROLLOUT_TIMEOUT_SECS: u64 = 600;
const RELEASE_KEY_STORE_ONCE_NOTICE: &str = "Store it now. Seren will not show it again.";
const DEFAULT_RELEASE_SETTINGS_FILE: &str = "seren-release.json";
const CONSOLE_PUBLISHED_EMPLOYEES_URL: &str = "https://console.serendb.com/published-employees";

fn default_release_listed() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedReleaseSettings {
    slug: String,
    display_name: String,
    deploy_defaults: seren::ManagedAgentTemplateDeployDefaults,
    #[serde(default)]
    rollout: bool,
    #[serde(default = "default_release_listed")]
    listed: bool,
    #[serde(default)]
    release_note: Option<String>,
}

fn resolve_release_settings_path(folder: &Path, settings: Option<&Path>) -> PathBuf {
    settings
        .map(Path::to_path_buf)
        .unwrap_or_else(|| folder.join(DEFAULT_RELEASE_SETTINGS_FILE))
}

fn load_release_settings(path: &Path) -> Result<ManagedReleaseSettings> {
    let bytes = fs::read(path)
        .with_context(|| format!("Failed to read release settings {}", path.display()))?;
    let parsed: ManagedReleaseSettings = serde_json::from_slice(&bytes)
        .with_context(|| format!("Invalid release settings in {}", path.display()))?;
    if parsed.slug.trim().is_empty() {
        anyhow::bail!(
            "Release settings `slug` in {} must not be empty.",
            path.display()
        );
    }
    if parsed.display_name.trim().is_empty() {
        anyhow::bail!(
            "Release settings `display_name` in {} must not be empty.",
            path.display()
        );
    }
    Ok(parsed)
}

fn parse_release_note(
    note: Option<String>,
) -> Result<Option<seren::PublishManagedAgentTemplateReleaseRequestReleaseNote>> {
    note.map(|value| {
        if value.trim().is_empty() {
            anyhow::bail!("Release settings `release_note` must be 1 to 2000 characters.");
        }
        value.parse().map_err(|_| {
            anyhow::anyhow!("Release settings `release_note` must be 1 to 2000 characters.")
        })
    })
    .transpose()
}

fn validate_commit_sha(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let sha = trimmed.to_ascii_lowercase();
    if (sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(sha)
    } else {
        anyhow::bail!("Commit SHA must be 40 or 64 hexadecimal characters (got `{trimmed}`).")
    }
}

async fn resolve_release_commit_sha(folder: &Path, commit: Option<String>) -> Result<String> {
    if let Some(commit) = commit {
        return validate_commit_sha(&commit);
    }
    let output = tokio::process::Command::new("git")
        .arg("-C")
        .arg(folder)
        .args(["rev-parse", "HEAD"])
        .output()
        .await
        .with_context(|| {
            format!(
                "Failed to run `git -C {} rev-parse HEAD`. Pass --commit <sha> to set the commit SHA explicitly.",
                folder.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            anyhow::bail!(
                "Could not determine commit SHA from `{}` (`git rev-parse HEAD` exited with {}). Pass --commit <sha> to set it explicitly.",
                folder.display(),
                output.status
            );
        }
        anyhow::bail!(
            "Could not determine commit SHA from `{}`: {detail}. Pass --commit <sha> to set it explicitly.",
            folder.display()
        );
    }
    let stdout = String::from_utf8(output.stdout)
        .context("`git rev-parse HEAD` returned non-UTF-8 output")?;
    validate_commit_sha(&stdout)
}

fn client_with_bearer(
    api_base: &str,
    bearer_token: &str,
    timeout_secs: Option<u64>,
) -> Result<seren::Client> {
    let mut config = seren::ClientConfig::new(bearer_token).with_base_url(api_base);
    if let Some(timeout_secs) = timeout_secs {
        config = config.with_timeout(timeout_secs);
    }
    seren::Client::from_config(&config)
        .map_err(|error| anyhow::anyhow!("Failed to create API client: {error}"))
}

fn parse_held_release_conflict(body: &str) -> Option<Value> {
    let payload: Value = serde_json::from_str(body).ok()?;
    if payload.get("error").and_then(Value::as_str) != Some("managed_agent_release_held") {
        return None;
    }
    Some(payload.get("details").cloned().unwrap_or_else(|| json!({})))
}

fn refusal_error_from_body(
    context: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> anyhow::Error {
    if let Ok(payload) = serde_json::from_str::<Value>(body)
        && let Some(message) = payload
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    {
        return anyhow::anyhow!("{message}");
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        anyhow::anyhow!("{context}: unexpected response {status}")
    } else {
        anyhow::anyhow!("{context}: unexpected response {status} - {trimmed}")
    }
}

fn held_outcome_reason_label(details: &Value) -> String {
    match details
        .get("reason")
        .cloned()
        .and_then(|value| serde_json::from_value::<seren::HeldReleaseReason>(value).ok())
    {
        Some(seren::HeldReleaseReason::FirstRelease) => "first release".to_string(),
        Some(seren::HeldReleaseReason::AccessChange) => "access change".to_string(),
        Some(seren::HeldReleaseReason::Other(other)) => other,
        None => details
            .get("reason")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("review required")
            .to_string(),
    }
}

fn held_access_change_sentences(details: &Value) -> Vec<String> {
    let Some(comparison_value) = details.get("comparison").filter(|value| !value.is_null()) else {
        return Vec::new();
    };
    if let Ok(comparison) =
        serde_json::from_value::<seren::TemplateRevisionComparison>(comparison_value.clone())
    {
        return comparison
            .access_changes
            .iter()
            .map(describe_access_change)
            .collect();
    }
    comparison_value
        .get("access_changes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    serde_json::from_value::<seren::TemplateAccessChange>(item.clone())
                        .map(|change| describe_access_change(&change))
                        .unwrap_or_else(|_| {
                            item.get("change")
                                .and_then(Value::as_str)
                                .map(|name| format!("Access change: {name}."))
                                .unwrap_or_else(|| item.to_string())
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn write_managed_release_published(
    release: &seren::ManagedAgentTemplateRelease,
    format: OutputFormat,
    stdout: &mut impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let mut payload = serde_json::Map::new();
            payload.insert("outcome".to_string(), json!("published"));
            if let Value::Object(fields) = serde_json::to_value(release)? {
                for (key, value) in fields {
                    if key != "outcome" {
                        payload.insert(key, value);
                    }
                }
            }
            writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&Value::Object(payload))?
            )?;
        }
        OutputFormat::Table => {
            writeln!(
                stdout,
                "Published {} revision {}.",
                release.slug, release.revision
            )?;
            if let Some(changes) = release.access_changes.as_deref() {
                for change in changes {
                    writeln!(stdout, "- {}", describe_access_change(change))?;
                }
            }
        }
    }
    Ok(())
}

fn write_managed_release_held(
    organization_id: Uuid,
    details: &Value,
    format: OutputFormat,
    stdout: &mut impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            let mut payload = serde_json::Map::new();
            payload.insert("outcome".to_string(), json!("held"));
            if let Value::Object(fields) = details {
                for (key, value) in fields {
                    if key != "outcome" {
                        payload.insert(key.clone(), value.clone());
                    }
                }
            }
            writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&Value::Object(payload))?
            )?;
        }
        OutputFormat::Table => {
            writeln!(
                stdout,
                "Held for approval: {}.",
                held_outcome_reason_label(details)
            )?;
            for sentence in held_access_change_sentences(details) {
                writeln!(stdout, "- {sentence}")?;
            }
            if let Some(held_release_id) = details
                .get("held_release_id")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                writeln!(
                    stdout,
                    "Approve it: seren agent managed-held-releases {organization_id} approve {held_release_id}"
                )?;
            } else {
                writeln!(
                    stdout,
                    "Review pending holds: seren agent managed-held-releases {organization_id} list"
                )?;
            }
            writeln!(
                stdout,
                "Or in the Console: {CONSOLE_PUBLISHED_EMPLOYEES_URL}"
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn managed_release_with_env(
    organization_id: Uuid,
    folder: &Path,
    settings: Option<&Path>,
    commit: Option<String>,
    ctx: &CommandContext,
    env: &dyn Fn(&str) -> Option<String>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<()> {
    if !folder.is_dir() {
        anyhow::bail!("'{}' is not a directory", folder.display());
    }
    let settings_path = resolve_release_settings_path(folder, settings);
    let release_settings = load_release_settings(&settings_path)?;
    let release_note = parse_release_note(release_settings.release_note)?;
    let source_commit_sha = resolve_release_commit_sha(folder, commit).await?;
    let draft =
        super::agent_dev::package_agent_bundle_excluding(folder, Some(settings_path.as_path()))?;
    let (serialized, _) = super::agent::managed_bundle_upload(&draft)?;

    let pass_answer = super::release_pass::release_pass_with_env(ctx, organization_id, env).await?;
    writeln!(stderr, "Using {} proof.", pass_answer.proof_label)?;

    let api_base = ctx.api_base();
    let upload_client = client_with_bearer(&api_base, pass_answer.pass(), None)?;
    let source_bundle_id = super::agent::ensure_cloud_deployment_bundle(
        &upload_client,
        serialized,
        seren::CloudDeploymentBundleSourceKind::AgentBundle,
    )
    .await?;

    let request = seren::PublishManagedAgentTemplateReleaseRequest {
        capabilities: Vec::new(),
        deploy_defaults: release_settings.deploy_defaults,
        display_name: release_settings.display_name,
        listed: release_settings.listed,
        release_note,
        rollout: Some(release_settings.rollout),
        skill_slugs: Vec::new(),
        source_bundle_id,
        source_commit_sha,
    };
    let publish_client = if let Some(timeout) = template_publication_timeout(request.rollout) {
        client_with_bearer(&api_base, pass_answer.pass(), Some(timeout))?
    } else {
        upload_client
    };

    match publish_client
        .publish_managed_agent_template_release(&organization_id, &release_settings.slug, &request)
        .await
    {
        Ok(response) => {
            let release = response.into_inner().data;
            write_managed_release_published(&release, ctx.format, stdout)
        }
        Err(seren::Error::UnexpectedResponse(response))
            if response.status() == reqwest::StatusCode::CONFLICT =>
        {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if let Some(details) = parse_held_release_conflict(&body) {
                return write_managed_release_held(organization_id, &details, ctx.format, stdout);
            }
            Err(refusal_error_from_body(
                "Failed to publish Employee release",
                status,
                &body,
            ))
        }
        Err(error) => Err(super::release_pass::refusal_error(
            "Failed to publish Employee release",
            error,
        )
        .await),
    }
}

fn template_publication_timeout(rollout: Option<bool>) -> Option<u64> {
    (rollout == Some(true)).then_some(TEMPLATE_ROLLOUT_TIMEOUT_SECS)
}

async fn client_with_timeout(ctx: &CommandContext, timeout_secs: u64) -> Result<seren::Client> {
    let bearer_token = super::auth::get_bearer_token(ctx.api_key.clone()).await?;
    seren::Client::from_config(
        &seren::ClientConfig::new(bearer_token)
            .with_base_url(ctx.api_base())
            .with_timeout(timeout_secs),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create API client: {e}"))
}

fn edit_release_source_request(
    label: Option<String>,
    branch: Option<String>,
    environment: Option<String>,
    clear_environment: bool,
    templates: Vec<String>,
) -> Result<seren::UpdateManagedAgentReleaseSourceRequest> {
    if clear_environment && environment.is_some() {
        anyhow::bail!("--clear-environment cannot be combined with --environment.");
    }
    let environment = if clear_environment {
        Some(None)
    } else {
        environment.map(Some)
    };
    let templates = (!templates.is_empty()).then_some(templates);
    if label.is_none() && branch.is_none() && environment.is_none() && templates.is_none() {
        anyhow::bail!(
            "Specify at least one of --label, --branch, --environment, --clear-environment, or --template."
        );
    }
    Ok(seren::UpdateManagedAgentReleaseSourceRequest {
        label,
        branch,
        environment,
        templates,
    })
}

fn owner_connection_label(value: &str) -> &str {
    match value {
        "mail_and_files" => "mail and files",
        "mail_read" => "mail read",
        "sign_in_only" => "sign-in only",
        other => other,
    }
}

fn network_protocol_label(protocol: seren::AgentNetworkProtocol) -> &'static str {
    match protocol {
        seren::AgentNetworkProtocol::Tcp => "TCP",
        seren::AgentNetworkProtocol::Rest => "REST",
        seren::AgentNetworkProtocol::Sse => "SSE",
        seren::AgentNetworkProtocol::Websocket => "WebSocket",
    }
}

fn deployment_mode_label(mode: seren::CloudDeploymentMode) -> &'static str {
    match mode {
        seren::CloudDeploymentMode::AlwaysOn => "always-on",
        seren::CloudDeploymentMode::Cron => "cron",
        seren::CloudDeploymentMode::Job => "job",
    }
}

fn model_policy_label(policy: seren::ManagedAgentModelPolicy) -> &'static str {
    match policy {
        seren::ManagedAgentModelPolicy::Fast => "fast",
        seren::ManagedAgentModelPolicy::Balanced => "balanced",
        seren::ManagedAgentModelPolicy::Deep => "deep",
    }
}

fn owner_model_fallback_label(fallback: &seren::ManagedOwnerModelFallback) -> String {
    let provider = match fallback.provider {
        seren::ManagedOwnerModelFallbackProvider::SerenPrivateModels => "Seren Private Models",
    };
    if fallback.fallback_models.is_empty() {
        format!("{provider} {}", fallback.model_id)
    } else {
        format!(
            "{provider} {} (then {})",
            fallback.model_id,
            fallback.fallback_models.join(", ")
        )
    }
}

fn llm_connection_label(connection: Option<&seren::ManagedAgentTemplateLlmConnection>) -> String {
    match connection {
        None => "default Seren Private Model".to_string(),
        Some(seren::ManagedAgentTemplateLlmConnection::SerenPrivateModels {
            model_id: None,
            fallback_models,
        }) if fallback_models.is_empty() => "default Seren Private Model".to_string(),
        Some(seren::ManagedAgentTemplateLlmConnection::SerenPrivateModels {
            model_id: None,
            fallback_models,
        }) => format!(
            "default Seren Private Model (fallback: {})",
            fallback_models.join(", ")
        ),
        Some(seren::ManagedAgentTemplateLlmConnection::SerenPrivateModels {
            model_id: Some(model_id),
            fallback_models,
        }) if fallback_models.is_empty() => format!("Seren Private Models ({model_id})"),
        Some(seren::ManagedAgentTemplateLlmConnection::SerenPrivateModels {
            model_id: Some(model_id),
            fallback_models,
        }) => format!(
            "Seren Private Models ({model_id}; fallback: {})",
            fallback_models.join(", ")
        ),
        Some(seren::ManagedAgentTemplateLlmConnection::Codex { model_id, fallback }) => format!(
            "Codex ({model_id}; fallback: {})",
            owner_model_fallback_label(fallback)
        ),
        Some(seren::ManagedAgentTemplateLlmConnection::ProviderKeys { model_id, fallback }) => {
            format!(
                "provider keys ({model_id}; fallback: {})",
                owner_model_fallback_label(fallback)
            )
        }
        Some(seren::ManagedAgentTemplateLlmConnection::SerenModels { model_id }) => {
            format!("Seren Models ({model_id})")
        }
    }
}

fn guarded_purchase_rule_label(rule: &seren::GuardedPurchaseRule) -> String {
    let form_fields = if rule.form_fields.is_some() {
        " with form fields"
    } else {
        ""
    };
    format!(
        "{} {}{} ({}{form_fields})",
        rule.method, rule.host, rule.path_pattern, rule.checkout
    )
}

fn guarded_submission_rule_label(rule: &seren::GuardedSubmissionRule) -> String {
    let ops = match rule.graphql_operation_names.as_deref() {
        Some(names) if !names.is_empty() => format!(" (GraphQL: {})", names.join(", ")),
        _ => String::new(),
    };
    format!("{} {}{}{ops}", rule.method, rule.host, rule.path_pattern)
}

fn format_rule_list(items: Vec<String>) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn cardano_signing_label(cfg: &seren::ManagedAgentTemplateCardanoSigning) -> String {
    format!(
        "builder {}, debt_asset {}, payout_assets [{}], lender_scripts [{}], swap_scripts [{}], venue_scripts [{}], mint_policies [{}], max_borrow_ratio_bps {}, max_loan_rate_bps {}, max_lend_rate_bps {}",
        cfg.builder_script,
        cfg.debt_asset,
        cfg.payout_assets.join(", "),
        cfg.lender_scripts.join(", "),
        cfg.swap_scripts.join(", "),
        cfg.venue_scripts.join(", "),
        cfg.mint_policies.join(", "),
        cfg.max_borrow_ratio_bps,
        cfg.max_loan_rate_bps,
        cfg.max_lend_rate_bps,
    )
}

fn browser_defaults_label(browser: &seren::ManagedAgentTemplateBrowserDefaults) -> String {
    let display = match browser.display {
        seren::BrowserDisplay::Headless => "headless",
        seren::BrowserDisplay::Headed => "headed",
    };
    let mut parts = vec![
        display.to_string(),
        format!("max session {}s", browser.max_session_seconds),
    ];
    if let Some(links) = browser.links {
        let links_label = match links {
            seren::BrowserLinks::Any => "any HTTPS link",
            seren::BrowserLinks::SentOnly => "conversation links only",
        };
        parts.push(links_label.to_string());
    }
    if browser.public_web == Some(true) {
        parts.push("public web reader enabled".to_string());
    }
    parts.join(", ")
}

fn runtime_class_label(class: Option<seren::ManagedAgentTemplateRuntimeClass>) -> &'static str {
    match class {
        None => "default",
        Some(seren::ManagedAgentTemplateRuntimeClass::Gvisor) => "gvisor",
        Some(seren::ManagedAgentTemplateRuntimeClass::Kata) => "kata",
    }
}

fn native_tools_label(tools: &[seren::AgentNativeToolSet]) -> String {
    if tools.is_empty() {
        "none".to_string()
    } else {
        tools
            .iter()
            .map(|tool| match tool {
                seren::AgentNativeToolSet::Onepassword => "1Password",
                seren::AgentNativeToolSet::SerenSupport => "Seren Support",
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn describe_access_change(change: &seren::TemplateAccessChange) -> String {
    match change {
        seren::TemplateAccessChange::OwnerConnectionChanged { before, after } => format!(
            "Employer account connection changed from {} to {}.",
            owner_connection_label(before),
            owner_connection_label(after)
        ),
        seren::TemplateAccessChange::PublisherGrantAdded { grant } => {
            let operation = grant
                .operation_id
                .as_deref()
                .map(|id| format!(" [{id}]"))
                .unwrap_or_default();
            let approval = if grant.require_approval {
                " (requires approval)"
            } else {
                ""
            };
            format!(
                "Added script access to {} {} {}{operation}{approval}.",
                grant.publisher_slug, grant.method, grant.path
            )
        }
        seren::TemplateAccessChange::PublisherGrantRemoved { grant } => {
            let operation = grant
                .operation_id
                .as_deref()
                .map(|id| format!(" [{id}]"))
                .unwrap_or_default();
            format!(
                "Removed script access to {} {} {}{operation}.",
                grant.publisher_slug, grant.method, grant.path
            )
        }
        seren::TemplateAccessChange::PublisherGrantChanged { before, after } => {
            let operation = after
                .operation_id
                .as_deref()
                .map(|id| format!(" [{id}]"))
                .unwrap_or_default();
            format!(
                "Changed script access approval for {} {} {}{operation} from {} to {}.",
                after.publisher_slug,
                after.method,
                after.path,
                if before.require_approval {
                    "approval required"
                } else {
                    "no approval required"
                },
                if after.require_approval {
                    "approval required"
                } else {
                    "no approval required"
                }
            )
        }
        seren::TemplateAccessChange::NetworkHostAdded { rule } => format!(
            "Added outbound network host {}:{} ({}).",
            rule.host,
            rule.port,
            network_protocol_label(rule.protocol)
        ),
        seren::TemplateAccessChange::NetworkHostRemoved { rule } => format!(
            "Removed outbound network host {}:{} ({}).",
            rule.host,
            rule.port,
            network_protocol_label(rule.protocol)
        ),
        seren::TemplateAccessChange::GuardedPurchasesChanged { before, after } => format!(
            "Changed guarded purchase rules from {} to {}.",
            format_rule_list(before.iter().map(guarded_purchase_rule_label).collect()),
            format_rule_list(after.iter().map(guarded_purchase_rule_label).collect()),
        ),
        seren::TemplateAccessChange::GuardedSubmissionsChanged { before, after } => format!(
            "Changed guarded submission rules from {} to {}.",
            format_rule_list(before.iter().map(guarded_submission_rule_label).collect()),
            format_rule_list(after.iter().map(guarded_submission_rule_label).collect()),
        ),
        seren::TemplateAccessChange::CardanoSigningChanged { before, after } => {
            match (before.as_ref(), after.as_ref()) {
                (None, Some(after)) => format!(
                    "Enabled Cardano transaction signing ({}).",
                    cardano_signing_label(after)
                ),
                (Some(before), None) => format!(
                    "Disabled Cardano transaction signing (was {}).",
                    cardano_signing_label(before)
                ),
                (Some(before), Some(after)) => format!(
                    "Changed Cardano transaction signing from {} to {}.",
                    cardano_signing_label(before),
                    cardano_signing_label(after)
                ),
                (None, None) => "Changed Cardano transaction signing rules.".to_string(),
            }
        }
        seren::TemplateAccessChange::WorkloadEgressChanged { before, after } => format!(
            "Changed workload network egress from {} to {}.",
            if *before { "enabled" } else { "disabled" },
            if *after { "enabled" } else { "disabled" }
        ),
        seren::TemplateAccessChange::ScriptModelKeyChanged { before, after } => format!(
            "Changed script model key access from {} to {}.",
            if *before { "enabled" } else { "disabled" },
            if *after { "enabled" } else { "disabled" }
        ),
        seren::TemplateAccessChange::PackagesChanged { added, removed } => {
            let mut parts = Vec::new();
            if !added.is_empty() {
                parts.push(format!("added {}", added.join(", ")));
            }
            if !removed.is_empty() {
                parts.push(format!("removed {}", removed.join(", ")));
            }
            if parts.is_empty() {
                "Changed Python package requirements.".to_string()
            } else {
                format!("Changed Python packages: {}.", parts.join("; "))
            }
        }
        seren::TemplateAccessChange::ModeChanged { before, after } => format!(
            "Changed deployment mode from {} to {}.",
            deployment_mode_label(*before),
            deployment_mode_label(*after)
        ),
        seren::TemplateAccessChange::ModelPolicyChanged { before, after } => format!(
            "Changed model policy from {} to {}.",
            model_policy_label(*before),
            model_policy_label(*after)
        ),
        seren::TemplateAccessChange::ModelConnectionChanged { before, after } => format!(
            "Changed model connection from {} to {}.",
            llm_connection_label(before.as_ref()),
            llm_connection_label(after.as_ref())
        ),
        seren::TemplateAccessChange::BrowserChanged { before, after } => format!(
            "Changed browser settings from {} to {}.",
            browser_defaults_label(before),
            browser_defaults_label(after)
        ),
        seren::TemplateAccessChange::RuntimeClassChanged { before, after } => format!(
            "Changed runtime class from {} to {}.",
            runtime_class_label(*before),
            runtime_class_label(*after)
        ),
        seren::TemplateAccessChange::NativeToolsChanged { before, after } => format!(
            "Changed native tools from {} to {}.",
            native_tools_label(before),
            native_tools_label(after)
        ),
        seren::TemplateAccessChange::MaxRuntimeChanged {
            before_seconds,
            after_seconds,
        } => format!("Changed maximum runtime from {before_seconds}s to {after_seconds}s."),
        seren::TemplateAccessChange::CronScheduleChanged { before, after } => {
            format!("Changed schedule from `{before}` to `{after}`.")
        }
        seren::TemplateAccessChange::SkillSpecificationChanged { path, file_change } => {
            let verb = match file_change {
                seren::TemplateFileChange::Added => "added",
                seren::TemplateFileChange::Changed => "changed",
                seren::TemplateFileChange::Removed => "removed",
                seren::TemplateFileChange::Other(other) => other.as_str(),
            };
            format!("Skill specification `{path}` was {verb}.")
        }
        seren::TemplateAccessChange::SkillToolsChanged {
            path,
            before,
            after,
        } => {
            let format_tools = |tools: Option<&Vec<String>>| match tools {
                None => "unrestricted".to_string(),
                Some(list) if list.is_empty() => "none".to_string(),
                Some(list) => list.join(", "),
            };
            format!(
                "Changed allowed tools in `{path}` from {} to {}.",
                format_tools(before.as_ref()),
                format_tools(after.as_ref())
            )
        }
    }
}

fn comparison_change_sentences(comparison: &seren::TemplateRevisionComparison) -> Vec<String> {
    let mut sentences: Vec<String> = comparison
        .access_changes
        .iter()
        .map(describe_access_change)
        .collect();
    if !comparison.content_changes.added.is_empty() {
        sentences.push(format!(
            "Added files: {}.",
            comparison.content_changes.added.join(", ")
        ));
    }
    if !comparison.content_changes.changed.is_empty() {
        sentences.push(format!(
            "Changed files: {}.",
            comparison.content_changes.changed.join(", ")
        ));
    }
    if !comparison.content_changes.removed.is_empty() {
        sentences.push(format!(
            "Removed files: {}.",
            comparison.content_changes.removed.join(", ")
        ));
    }
    sentences
}

fn held_release_reason_label(reason: &seren::HeldReleaseReason) -> String {
    match reason {
        seren::HeldReleaseReason::FirstRelease => "First release".to_string(),
        seren::HeldReleaseReason::AccessChange => "Access change".to_string(),
        seren::HeldReleaseReason::Other(other) => other.clone(),
    }
}

fn held_release_status_label(status: seren::HeldReleaseStatus) -> &'static str {
    match status {
        seren::HeldReleaseStatus::Pending => "pending",
        seren::HeldReleaseStatus::Approved => "approved",
        seren::HeldReleaseStatus::Refused => "refused",
        seren::HeldReleaseStatus::Replaced => "replaced",
        seren::HeldReleaseStatus::Lapsed => "lapsed",
        seren::HeldReleaseStatus::Cancelled => "cancelled",
    }
}

fn held_release_change_sentences(hold: &seren::HeldReleaseSummary) -> Vec<String> {
    if let Some(comparison) = hold.comparison.as_ref() {
        let sentences = comparison_change_sentences(comparison);
        if !sentences.is_empty() {
            return sentences;
        }
    }
    match &hold.reason {
        seren::HeldReleaseReason::FirstRelease => {
            vec!["First release of this Employee (no previous revision to compare).".to_string()]
        }
        seren::HeldReleaseReason::AccessChange => {
            vec!["No itemized changes reported.".to_string()]
        }
        seren::HeldReleaseReason::Other(other) => {
            vec![format!("Held for review ({other}).")]
        }
    }
}

fn format_release_run(run: &seren::ReleaseRun) -> String {
    let mut parts = vec![format!("{} {}", run.product, run.repository)];
    if !run.commit.is_empty() {
        let short_commit: String = run.commit.chars().take(12).collect();
        parts.push(format!("commit {short_commit}"));
    }
    if !run.run_id.is_empty() {
        parts.push(format!("run {}", run.run_id));
    }
    parts.join(", ")
}

fn held_release_table_rows(hold: &seren::HeldReleaseSummary) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("id", hold.id.to_string()),
        ("employee", hold.slug.clone()),
        ("status", held_release_status_label(hold.status).to_string()),
        ("reason", held_release_reason_label(&hold.reason)),
        ("source", hold.source_label.clone()),
    ];
    if let Some(run) = hold.run.as_ref() {
        rows.push(("run", format_release_run(run)));
    }
    rows.push(("created_at", hold.created_at.to_string()));
    rows.push(("changes", held_release_change_sentences(hold).join("\n")));
    rows.push(("changes_fingerprint", hold.changes_fingerprint.clone()));
    if let Some(decided_at) = hold.decided_at {
        rows.push(("decided_at", decided_at.to_string()));
    }
    if let Some(decided_by) = hold.decided_by_user_id {
        rows.push(("decided_by_user_id", decided_by.to_string()));
    }
    if let Some(note) = hold.note.as_ref() {
        rows.push(("note", note.clone()));
    }
    rows
}

fn write_create_key_output<T: Serialize>(
    payload: &T,
    format: OutputFormat,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<()> {
    match format {
        OutputFormat::Json => {
            writeln!(stdout, "{}", serde_json::to_string_pretty(payload)?)?;
            writeln!(stderr, "{RELEASE_KEY_STORE_ONCE_NOTICE}")?;
        }
        OutputFormat::Table => {
            let value = serde_json::to_value(payload)?;
            let data = value.get("data").unwrap_or(&value);
            if let Value::Object(fields) = data {
                let mut table = comfy_table::Table::new();
                table
                    .load_style(comfy_table::presets::UTF8_FULL)
                    .set_content_arrangement(comfy_table::ContentArrangement::Dynamic);
                table.set_header(vec![
                    comfy_table::Cell::new("Field").fg(comfy_table::Color::Green),
                    comfy_table::Cell::new("Value").fg(comfy_table::Color::Green),
                ]);
                for (key, val) in fields {
                    let text = match val {
                        Value::String(text) => text.clone(),
                        Value::Null => "-".to_string(),
                        _ => serde_json::to_string_pretty(val)?,
                    };
                    table.add_row(vec![
                        comfy_table::Cell::new(key),
                        comfy_table::Cell::new(text),
                    ]);
                }
                output::keep_id_columns_whole(&mut table);
                writeln!(stdout, "{table}")?;
            } else {
                writeln!(stdout, "{data}")?;
            }
            writeln!(stdout, "{RELEASE_KEY_STORE_ONCE_NOTICE}")?;
        }
    }
    Ok(())
}

fn held_release_review_text(hold: &seren::HeldReleaseSummary) -> String {
    let sentences = held_release_change_sentences(hold);
    let mut lines = vec![format!(
        "Held release {} for {} ({}):",
        hold.id,
        hold.slug,
        held_release_reason_label(&hold.reason)
    )];
    for sentence in sentences {
        lines.push(format!("- {sentence}"));
    }
    lines.push(format!("Fingerprint: {}", hold.changes_fingerprint));
    lines.join("\n")
}

struct ApprovalPrompt<'a, R, W> {
    interactive: bool,
    reader: &'a mut R,
    out: &'a mut W,
}

fn confirm_held_release_approval<R: BufRead, W: Write>(
    organization_id: Uuid,
    hold: &seren::HeldReleaseSummary,
    prompt: &mut ApprovalPrompt<'_, R, W>,
) -> Result<()> {
    writeln!(prompt.out, "{}", held_release_review_text(hold))?;
    if !prompt.interactive {
        anyhow::bail!(
            "Cannot approve held release {} without --fingerprint on a non-interactive terminal. Review the changes above and re-run: seren agent managed-held-releases {organization_id} approve {} --fingerprint {}",
            hold.id,
            hold.id,
            hold.changes_fingerprint
        );
    }
    write!(prompt.out, "Type 'yes' to approve these changes: ")?;
    prompt.out.flush()?;
    let mut response = String::new();
    prompt.reader.read_line(&mut response)?;
    if response.trim() != "yes" {
        anyhow::bail!("Held release approval cancelled.");
    }
    Ok(())
}

async fn approve_held_release<R: BufRead, W: Write>(
    client: &seren::Client,
    organization_id: Uuid,
    held_release_id: Uuid,
    fingerprint: Option<String>,
    ctx: &CommandContext,
    prompt: &mut ApprovalPrompt<'_, R, W>,
) -> Result<()> {
    let changes_fingerprint = match fingerprint {
        Some(fingerprint) => fingerprint,
        None => {
            let holds = match client
                .list_managed_agent_held_releases(
                    &organization_id,
                    Some(seren::HeldReleaseStatus::Pending),
                )
                .await
            {
                Ok(response) => response.into_inner().data,
                Err(error) => {
                    return Err(super::agent::anyhow_from_seren_error(
                        "Managed agent request failed",
                        error,
                    )
                    .await);
                }
            };
            let hold = holds
                .into_iter()
                .find(|hold| hold.id == held_release_id)
                .ok_or_else(|| {
                    anyhow::anyhow!("No pending held release found with ID {held_release_id}.")
                })?;
            confirm_held_release_approval(organization_id, &hold, prompt)?;
            hold.changes_fingerprint
        }
    };
    let approve_client = client_with_timeout(ctx, TEMPLATE_ROLLOUT_TIMEOUT_SECS).await?;
    let response = match approve_client
        .approve_managed_agent_held_release(
            &organization_id,
            &held_release_id,
            &seren::ApproveHeldReleaseRequest {
                changes_fingerprint,
            },
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Err(format_held_release_approval_error(
                organization_id,
                held_release_id,
                error,
            )
            .await);
        }
    };
    print_response(&response.into_inner(), ctx)
}

fn format_held_release_changed_conflict(
    organization_id: Uuid,
    held_release_id: Uuid,
    body: &str,
) -> Option<String> {
    let payload: Value = serde_json::from_str(body).ok()?;
    if payload.get("error").and_then(Value::as_str) != Some("managed_agent_held_release_changed") {
        return None;
    }
    let message = payload
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("This held release has changed. Review the current changes before approving.");
    let details = payload.get("details");
    let comparison: Option<seren::TemplateRevisionComparison> = details
        .and_then(|details| details.get("comparison"))
        .filter(|value| !value.is_null())
        .and_then(|value| serde_json::from_value(value.clone()).ok());
    let new_fingerprint = details
        .and_then(|details| details.get("changes_fingerprint"))
        .and_then(Value::as_str);

    let mut lines = vec![message.to_string()];
    if let Some(comparison) = comparison.as_ref() {
        let sentences = comparison_change_sentences(comparison);
        if !sentences.is_empty() {
            lines.push("Current changes:".to_string());
            for sentence in sentences {
                lines.push(format!("- {sentence}"));
            }
        }
    } else {
        lines.push(format!(
            "Review the updated release with: seren agent managed-held-releases {organization_id} list"
        ));
    }
    if let Some(fingerprint) = new_fingerprint {
        lines.push(format!("New fingerprint: {fingerprint}"));
        lines.push(format!(
            "To approve after reviewing, run: seren agent managed-held-releases {organization_id} approve {held_release_id} --fingerprint {fingerprint}"
        ));
    }
    Some(lines.join("\n"))
}

async fn format_held_release_approval_error(
    organization_id: Uuid,
    held_release_id: Uuid,
    error: seren::Error<()>,
) -> anyhow::Error {
    match error {
        seren::Error::UnexpectedResponse(response)
            if response.status() == reqwest::StatusCode::CONFLICT =>
        {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            if let Some(formatted) =
                format_held_release_changed_conflict(organization_id, held_release_id, &body)
            {
                return anyhow::anyhow!(formatted);
            }
            anyhow::anyhow!("Managed agent request failed: unexpected response {status} - {body}")
        }
        other => super::agent::anyhow_from_seren_error("Managed agent request failed", other).await,
    }
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

/// Seconds between reads of a followed run.
const RUN_FOLLOW_INTERVAL_SECS: u64 = 5;
/// Maximum steps per timeline response.
const RUN_TIMELINE_PAGE_STEPS: usize = 500;

/// Follow a timeline by printing new steps, then the ended run.
async fn print_run_timeline(
    client: &seren::Client,
    template: &str,
    run_code: &str,
    follow: bool,
    ctx: &CommandContext,
) -> Result<()> {
    let mut after = None;
    loop {
        let timeline = match client
            .seren_agent_get_template_run(template, run_code, after)
            .await
        {
            Ok(response) => response.into_inner().data,
            Err(error) => {
                return Err(super::agent::anyhow_from_seren_error(
                    "Managed agent request failed",
                    error,
                )
                .await);
            }
        };
        let ended = timeline.run.ended_at.is_some();
        if after.is_none() {
            print_response(&json!({ "data": timeline }), ctx)?;
        } else {
            if !timeline.steps.is_empty() {
                print_response(&json!({ "data": timeline.steps }), ctx)?;
            }
            if ended {
                print_response(&json!({ "data": timeline.run }), ctx)?;
            }
        }
        if !follow || ended {
            return Ok(());
        }
        let full_page = timeline.steps.len() >= RUN_TIMELINE_PAGE_STEPS;
        after = timeline.next_after.or(after).or(Some(0));
        if !full_page {
            tokio::time::sleep(std::time::Duration::from_secs(RUN_FOLLOW_INTERVAL_SECS)).await;
        }
    }
}

pub async fn execute(action: ManagedAction, ctx: &CommandContext) -> Result<()> {
    if let ManagedAction::ManagedReleasePass { organization_id } = action {
        return super::release_pass::execute(organization_id, ctx).await;
    }
    if let ManagedAction::ManagedRelease {
        organization_id,
        folder,
        settings,
        commit,
    } = action
    {
        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        return managed_release_with_env(
            organization_id,
            &folder,
            settings.as_deref(),
            commit,
            ctx,
            &|name| std::env::var(name).ok(),
            &mut stdout,
            &mut stderr,
        )
        .await;
    }
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
            let mut body = json!({"timezone": timezone});
            match (provider, connection_id) {
                (Some(provider), Some(connection_id)) => {
                    body["provider"] = json!(provider);
                    body["oauth_connection_id"] = json!(connection_id);
                }
                (_, None) => {}
                (None, Some(_)) => anyhow::bail!("provider is required with connection-id"),
            }
            let request: seren::CreateManagedAgentTemplateDeploymentRequest = typed_request(body)?;
            respond!(
                client.seren_agent_create_managed_agent_template_deployment(&template, &request)
            );
        }
        ManagedAction::ManagedTemplateStats { template } => {
            respond!(client.seren_agent_get_managed_agent_template_stats(&template))
        }
        ManagedAction::ManagedTemplateRuns {
            template,
            ending,
            since,
            until,
            employer,
            release,
            limit,
            offset,
        } => respond!(client.seren_agent_list_template_runs(
            &template,
            employer.as_deref(),
            ending.as_deref(),
            limit,
            offset,
            release,
            since.as_deref(),
            until.as_deref(),
        )),
        ManagedAction::ManagedTemplateRun {
            template,
            run_code,
            follow,
        } => {
            tokio::select! {
                result = print_run_timeline(&client, &template, &run_code, follow, ctx) => result?,
                _ = tokio::signal::ctrl_c() => {}
            }
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
                let request = seren::RevokeManagedAgentPublisherGrant {
                    redirect_origin,
                    update: None,
                };
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
        ManagedAction::ManagedTemplates { organization_id } => {
            respond!(client.list_organization_managed_agent_templates(&organization_id));
        }
        ManagedAction::ManagedTemplateProfile { action } => match action {
            TemplateProfileAction::Get {
                organization_id,
                template,
            } => {
                respond!(client.get_managed_agent_template_profile(&organization_id, &template));
            }
            TemplateProfileAction::Update {
                organization_id,
                template,
                request,
            } => {
                let request: seren::PutManagedAgentTemplateProfile = request_file(&request)?;
                respond!(client.put_managed_agent_template_profile(
                    &organization_id,
                    &template,
                    &request
                ));
            }
        },
        ManagedAction::ManagedTemplateListing {
            organization_id,
            template,
            listed,
        } => {
            respond!(client.put_managed_agent_template_listing(
                &organization_id,
                &template,
                &seren::PutManagedAgentTemplateListing { listed }
            ));
        }
        ManagedAction::ManagedTemplateReview {
            organization_id,
            template,
        } => {
            respond!(client.request_managed_agent_template_review(&organization_id, &template));
        }
        ManagedAction::ManagedPublishTemplateRelease {
            organization_id,
            template,
            request,
        } => {
            let request: seren::PublishManagedAgentTemplateReleaseRequest = request_file(&request)?;
            let client = if let Some(timeout) = template_publication_timeout(request.rollout) {
                client_with_timeout(ctx, timeout).await?
            } else {
                client
            };
            respond!(client.publish_managed_agent_template_release(
                &organization_id,
                &template,
                &request
            ));
        }
        ManagedAction::ManagedReleasePass { .. } | ManagedAction::ManagedRelease { .. } => {
            unreachable!("handled above")
        }
        ManagedAction::ManagedReleaseSources {
            organization_id,
            action,
        } => match action {
            ReleaseSourceAction::List => {
                respond!(client.list_managed_agent_release_sources(&organization_id));
            }
            ReleaseSourceAction::Approve {
                product,
                repository,
                branch,
                environment,
                issuer,
                label,
                templates,
            } => {
                ctx.require_user_session("Approving a release source")
                    .await?;
                let request = seren::CreateManagedAgentReleaseSourceRequest::SignedRun {
                    label,
                    ci_product: product.into(),
                    issuer,
                    repository,
                    branch,
                    environment,
                    templates,
                };
                respond!(client.create_managed_agent_release_source(&organization_id, &request));
            }
            ReleaseSourceAction::CreateKey {
                label,
                days,
                templates,
            } => {
                ctx.require_user_session("Creating a release key").await?;
                let request = seren::CreateManagedAgentReleaseSourceRequest::ReleaseKey {
                    label,
                    expires_in_days: days,
                    templates,
                };
                let response = match client
                    .create_managed_agent_release_source(&organization_id, &request)
                    .await
                {
                    Ok(response) => response.into_inner(),
                    Err(error) => {
                        return Err(super::agent::anyhow_from_seren_error(
                            "Managed agent request failed",
                            error,
                        )
                        .await);
                    }
                };
                let mut stdout = std::io::stdout().lock();
                let mut stderr = std::io::stderr().lock();
                write_create_key_output(&response, ctx.format, &mut stdout, &mut stderr)?;
            }
            ReleaseSourceAction::Edit {
                release_source_id,
                label,
                branch,
                environment,
                clear_environment,
                templates,
            } => {
                let request = edit_release_source_request(
                    label,
                    branch,
                    environment,
                    clear_environment,
                    templates,
                )?;
                ctx.require_user_session("Editing a release source").await?;
                respond!(client.update_managed_agent_release_source(
                    &organization_id,
                    &release_source_id,
                    &request
                ));
            }
            ReleaseSourceAction::Revoke { release_source_id } => {
                ctx.require_user_session("Revoking a release source")
                    .await?;
                respond!(
                    client
                        .revoke_managed_agent_release_source(&organization_id, &release_source_id)
                );
            }
        },
        ManagedAction::ManagedHeldReleases {
            organization_id,
            action,
        } => match action {
            HeldReleaseAction::List { status } => {
                let response = match client
                    .list_managed_agent_held_releases(&organization_id, status.map(Into::into))
                    .await
                {
                    Ok(response) => response.into_inner(),
                    Err(error) => {
                        return Err(super::agent::anyhow_from_seren_error(
                            "Managed agent request failed",
                            error,
                        )
                        .await);
                    }
                };
                match ctx.format {
                    OutputFormat::Json => output::print_json(&response)?,
                    OutputFormat::Table => {
                        if response.data.is_empty() {
                            println!("No results found");
                        } else {
                            for hold in &response.data {
                                let rows = held_release_table_rows(hold);
                                output::print_key_value_table(None, &rows);
                            }
                        }
                    }
                }
            }
            HeldReleaseAction::Approve {
                held_release_id,
                fingerprint,
            } => {
                let interactive = std::io::stdin().is_terminal();
                let mut stdin = std::io::stdin().lock();
                match ctx.format {
                    OutputFormat::Json => {
                        let mut stderr = std::io::stderr().lock();
                        let mut prompt = ApprovalPrompt {
                            interactive,
                            reader: &mut stdin,
                            out: &mut stderr,
                        };
                        approve_held_release(
                            &client,
                            organization_id,
                            held_release_id,
                            fingerprint,
                            ctx,
                            &mut prompt,
                        )
                        .await?;
                    }
                    OutputFormat::Table => {
                        let mut stdout = std::io::stdout().lock();
                        let mut prompt = ApprovalPrompt {
                            interactive,
                            reader: &mut stdin,
                            out: &mut stdout,
                        };
                        approve_held_release(
                            &client,
                            organization_id,
                            held_release_id,
                            fingerprint,
                            ctx,
                            &mut prompt,
                        )
                        .await?;
                    }
                }
            }
            HeldReleaseAction::Refuse {
                held_release_id,
                note,
            } => {
                let note = note
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Note must be 1 to 2000 characters."))?;
                respond!(client.refuse_managed_agent_held_release(
                    &organization_id,
                    &held_release_id,
                    &seren::RefuseHeldReleaseRequest { note }
                ));
            }
        },
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
                provider: Some(TemplateProvider::Google),
                connection_id: Some(_),
                ..
            }
        ));
        let cli = ManagedCli::try_parse_from([
            "agent",
            "managed-deploy-template",
            "bella",
            "--timezone",
            "UTC",
        ])
        .unwrap();
        assert!(matches!(
            cli.action,
            ManagedAction::ManagedDeployTemplate {
                provider: None,
                connection_id: None,
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
    fn template_deployment_requires_a_provider_for_a_mail_connection() {
        for flags in [
            vec!["--connection-id", "11111111-1111-4111-8111-111111111111"],
            vec![
                "--provider",
                "unknown",
                "--connection-id",
                "11111111-1111-4111-8111-111111111111",
            ],
        ] {
            let mut args = vec![
                "agent",
                "managed-deploy-template",
                "bella",
                "--timezone",
                "UTC",
            ];
            args.extend(flags);
            assert!(ManagedCli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn template_deployment_keeps_existing_provider_only_commands() {
        for provider in ["google", "microsoft"] {
            let cli = ManagedCli::try_parse_from([
                "agent",
                "managed-deploy-template",
                "vera-hale",
                "--provider",
                provider,
                "--timezone",
                "UTC",
            ])
            .unwrap();
            assert!(matches!(
                cli.action,
                ManagedAction::ManagedDeployTemplate {
                    provider: Some(_),
                    connection_id: None,
                    ..
                }
            ));
        }
    }

    #[test]
    fn only_requested_rollouts_override_the_publication_timeout() {
        assert_eq!(template_publication_timeout(None), None);
        assert_eq!(template_publication_timeout(Some(false)), None);
        assert_eq!(template_publication_timeout(Some(true)), Some(600));
    }

    #[tokio::test]
    async fn template_deployment_forwards_only_the_selected_mail_connection() {
        use wiremock::matchers::{body_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (provider, connection_id) in [
            (None, None),
            (Some(TemplateProvider::Google), None),
            (Some(TemplateProvider::Microsoft), None),
            (Some(TemplateProvider::Google), Some(Uuid::new_v4())),
            (Some(TemplateProvider::Microsoft), Some(Uuid::new_v4())),
        ] {
            let server = MockServer::start().await;
            let mut request = json!({"timezone": "UTC"});
            if let Some(id) = connection_id {
                request["provider"] = json!(provider);
                request["oauth_connection_id"] = json!(id);
            }
            Mock::given(method("POST"))
                .and(path(
                    "/publishers/seren-agent/templates/researcher/deployments",
                ))
                .and(body_json(request))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "data": {
                        "deployment_id": Uuid::new_v4(),
                        "hire_id": Uuid::new_v4(),
                        "created": true,
                        "bonus": {"status": "ineligible"},
                        "spend_limits": {"model_paid_by_owner":false,"per_task_atomic":2000000,"per_day_atomic":10000000,"day_timezone":"UTC","defaults":{"per_task_atomic":2000000,"per_day_atomic":10000000},"run_kinds":[{"key":"run","name":"Run","charge":"fee","triggers":["hire_cron","schedule","chat","webhook","api"],"amount":{"atomic":300000,"usd":"$0.30"},"expected_cost_atomic":300000}]},
                        "run_kinds": [{
                            "key": "run", "name": "Run", "charge": "fee",
                            "triggers": ["hire_cron", "schedule", "chat", "webhook", "api"],
                            "amount": {"atomic": 300000, "usd": "$0.30"},
                            "expected_cost_atomic": 300000
                        }]
                    }
                })))
                .expect(1)
                .mount(&server)
                .await;
            let context = CommandContext::new(
                Some(server.uri()),
                Some("test-key".into()),
                OutputFormat::Json,
            );
            execute(
                ManagedAction::ManagedDeployTemplate {
                    template: "researcher".into(),
                    provider,
                    connection_id,
                    timezone: "UTC".into(),
                },
                &context,
            )
            .await
            .expect("template deployment request succeeds");
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn template_publication_forwards_rollout_selection_and_authentication() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for rollout in [None, Some(false), Some(true)] {
            for listed in [None, Some(false), Some(true)] {
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
                if let Some(listed) = listed {
                    request["listed"] = json!(listed);
                }
                let mut expected_request = request.clone();
                expected_request["listed"] = json!(listed.unwrap_or(true));
                let mut response = json!({"data": {
                    "slug": "release-test", "revision": 7, "created": false,
                    "revision_added": false, "active": true, "listed": false, "review_state": "pending",
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
                    .and(body_json(expected_request))
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
    }

    #[test]
    fn template_catalog_commands_require_explicit_listing_choice() {
        let id = "11111111-1111-4111-8111-111111111111";
        assert!(
            ManagedCli::try_parse_from(["agent", "managed-template-listing", id, "example"])
                .is_err()
        );
        let parsed = ManagedCli::try_parse_from([
            "agent",
            "managed-template-listing",
            id,
            "example",
            "--listed",
            "false",
        ])
        .unwrap();
        assert!(matches!(
            parsed.action,
            ManagedAction::ManagedTemplateListing { listed: false, .. }
        ));
        assert!(ManagedCli::try_parse_from(["agent", "managed-templates", id]).is_ok());
        assert!(
            ManagedCli::try_parse_from(["agent", "managed-template-review", id, "example"]).is_ok()
        );
        assert!(
            ManagedCli::try_parse_from(["agent", "managed-template-profile", "get", id, "example"])
                .is_ok()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-template-profile",
                "update",
                id,
                "example",
                "--request",
                "profile.json"
            ])
            .is_ok()
        );
    }

    #[tokio::test]
    async fn template_catalog_commands_preserve_profile_presence_and_listing_state() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let organization_id = Uuid::from_u128(42);
        let ctx = CommandContext::new(
            Some(server.uri()),
            Some("seren_test_key".into()),
            OutputFormat::Json,
        );
        let template = json!({"slug": "example", "display_name": "Example", "active": true, "listed": false, "current_revision": 3, "review_state": "pending"});
        let profile = json!({"capabilities": [], "skill_slugs": [], "example_tasks": [], "works_in": [], "pronouns": "they/them"});
        let prefix = format!("/organizations/{organization_id}/templates");
        for (verb, route, request, response) in [
            (
                "GET",
                prefix.clone(),
                None,
                json!({"data": [template.clone()]}),
            ),
            (
                "GET",
                format!("{prefix}/example/profile"),
                None,
                json!({"data": profile.clone()}),
            ),
            (
                "PUT",
                format!("{prefix}/example/profile"),
                Some(json!({"job_title": null, "example_tasks": [], "pronouns": "they/them"})),
                json!({"data": profile}),
            ),
            (
                "PUT",
                format!("{prefix}/example/listing"),
                Some(json!({"listed": false})),
                json!({"data": template.clone()}),
            ),
            (
                "POST",
                format!("{prefix}/example/reviews"),
                None,
                json!({"data": template}),
            ),
        ] {
            let mut mock = Mock::given(method(verb))
                .and(path(route))
                .and(header("Authorization", "Bearer seren_test_key"));
            if let Some(request) = request {
                mock = mock.and(body_json(request));
            }
            mock.respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
        }
        let dir = tempfile::tempdir().unwrap();
        let request = dir.path().join("profile.json");
        fs::write(
            &request,
            br#"{"job_title":null,"example_tasks":[],"pronouns":"they/them"}"#,
        )
        .unwrap();
        for action in [
            ManagedAction::ManagedTemplates { organization_id },
            ManagedAction::ManagedTemplateProfile {
                action: TemplateProfileAction::Get {
                    organization_id,
                    template: "example".into(),
                },
            },
            ManagedAction::ManagedTemplateProfile {
                action: TemplateProfileAction::Update {
                    organization_id,
                    template: "example".into(),
                    request,
                },
            },
            ManagedAction::ManagedTemplateListing {
                organization_id,
                template: "example".into(),
                listed: false,
            },
            ManagedAction::ManagedTemplateReview {
                organization_id,
                template: "example".into(),
            },
        ] {
            execute(action, &ctx).await.unwrap();
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
        server.verify().await;
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

    #[tokio::test]
    async fn release_source_and_held_release_commands_cover_wire_and_session_rules() {
        use wiremock::matchers::{body_json, header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let org_id = Uuid::from_u128(701);
        let source_id = Uuid::from_u128(702);
        let key_source_id = Uuid::from_u128(703);
        let approver_id = Uuid::from_u128(704);
        let held_id = Uuid::from_u128(705);
        let org_str = org_id.to_string();
        let source_str = source_id.to_string();
        let held_str = held_id.to_string();
        let fp_old = "a".repeat(64);
        let fp_new = "b".repeat(64);
        let timestamp = "2026-11-25T09:00:00Z";
        let expires_at = "2026-12-09T09:00:00Z";

        // Parse checks for flags, ranges, and conflicts.
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-release-sources",
                &org_str,
                "approve",
                "--product",
                "github-actions",
                "--repository",
                "example/employees",
                "--branch",
                "main",
                "--environment",
                "production",
                "--label",
                "Main CI",
                "--template",
                "analyst",
                "--template",
                "reviewer",
            ])
            .is_ok()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-release-sources",
                &org_str,
                "approve",
                "--product",
                "github_actions",
                "--repository",
                "example/employees",
                "--branch",
                "main",
                "--label",
                "Main CI",
                "--template",
                "analyst",
            ])
            .is_ok()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-release-sources",
                &org_str,
                "create-key",
                "--label",
                "Temp key",
                "--days",
                "0",
                "--template",
                "analyst",
            ])
            .is_err()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-release-sources",
                &org_str,
                "create-key",
                "--label",
                "Temp key",
                "--days",
                "31",
                "--template",
                "analyst",
            ])
            .is_err()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-release-sources",
                &org_str,
                "edit",
                &source_str,
                "--environment",
                "prod",
                "--clear-environment",
            ])
            .is_err()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-held-releases",
                &org_str,
                "approve",
                &held_str,
            ])
            .is_ok()
        );
        assert!(
            ManagedCli::try_parse_from([
                "agent",
                "managed-held-releases",
                &org_str,
                "refuse",
                &held_str,
                "--note",
                "Needs security review",
            ])
            .is_ok()
        );

        // Source write actions must refuse API keys before issuing any HTTP request.
        let server = MockServer::start().await;
        let api_key_ctx = CommandContext::new(
            Some(server.uri()),
            Some("seren_test_key".into()),
            OutputFormat::Json,
        );
        for action in [
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Approve {
                    product: ReleaseSourceProduct::GithubActions,
                    repository: "example/employees".into(),
                    branch: "main".into(),
                    environment: None,
                    issuer: None,
                    label: "Main CI".into(),
                    templates: vec!["analyst".into()],
                },
            },
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::CreateKey {
                    label: "Temp key".into(),
                    days: 14,
                    templates: vec!["analyst".into()],
                },
            },
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Edit {
                    release_source_id: source_id,
                    label: Some("Renamed".into()),
                    branch: None,
                    environment: None,
                    clear_environment: false,
                    templates: vec![],
                },
            },
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Revoke {
                    release_source_id: source_id,
                },
            },
        ] {
            let error = execute(action, &api_key_ctx).await.unwrap_err();
            assert!(
                error.to_string().contains("interactive OAuth user session"),
                "unexpected error: {error}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());

        // Empty edit and empty refusal note fail locally before HTTP.
        let session_ctx = CommandContext::new(
            Some(server.uri()),
            Some("oauth-session-token".into()),
            OutputFormat::Table,
        );
        assert!(
            execute(
                ManagedAction::ManagedReleaseSources {
                    organization_id: org_id,
                    action: ReleaseSourceAction::Edit {
                        release_source_id: source_id,
                        label: None,
                        branch: None,
                        environment: None,
                        clear_environment: false,
                        templates: vec![],
                    },
                },
                &session_ctx,
            )
            .await
            .is_err()
        );
        assert!(
            execute(
                ManagedAction::ManagedHeldReleases {
                    organization_id: org_id,
                    action: HeldReleaseAction::Refuse {
                        held_release_id: held_id,
                        note: String::new(),
                    },
                },
                &session_ctx,
            )
            .await
            .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());

        let signed_run_source = json!({
            "id": source_id,
            "organization_id": org_id,
            "kind": "signed_run",
            "label": "Main CI",
            "approved_by_user_id": approver_id,
            "ci_product": "github_actions",
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": "example/employees",
            "branch": "main",
            "environment": "production",
            "templates": ["analyst"],
            "created_at": timestamp,
            "updated_at": timestamp
        });
        let created_key_source = json!({
            "id": key_source_id,
            "organization_id": org_id,
            "kind": "release_key",
            "label": "Fallback key",
            "approved_by_user_id": approver_id,
            "key_prefix": "serenrk_0123",
            "expires_at": expires_at,
            "templates": ["analyst"],
            "created_at": timestamp,
            "updated_at": timestamp,
            "release_key": "serenrk_synthetic_once_value"
        });
        let mut cleared_env_source = signed_run_source.clone();
        cleared_env_source
            .as_object_mut()
            .unwrap()
            .remove("environment");
        let mut revoked_source = signed_run_source.clone();
        revoked_source["revoked_at"] = json!(timestamp);
        revoked_source["revoked_by_user_id"] = json!(approver_id);

        let comparison_old = json!({
            "kind": "access",
            "access_changes": [
                {
                    "change": "network_host_added",
                    "rule": { "host": "api.example.com", "port": 443, "protocol": "rest" }
                }
            ],
            "content_changes": { "added": ["SKILL.md"], "changed": [], "removed": [] }
        });
        let comparison_new = json!({
            "kind": "access",
            "access_changes": [
                {
                    "change": "network_host_added",
                    "rule": { "host": "data.example.com", "port": 443, "protocol": "rest" }
                }
            ],
            "content_changes": { "added": [], "changed": ["TOOLS.md"], "removed": [] }
        });
        let held_summary_wire = json!({
            "id": held_id,
            "slug": "analyst",
            "reason": "access_change",
            "comparison": comparison_old,
            "changes_fingerprint": fp_old,
            "source_label": "Main CI",
            "status": "pending",
            "created_at": timestamp
        });
        let held_summary: seren::HeldReleaseSummary =
            serde_json::from_value(held_summary_wire.clone()).unwrap();
        let rows = held_release_table_rows(&held_summary);
        assert!(rows.iter().any(|(k, v)| *k == "changes"
            && v.contains("Added outbound network host api.example.com:443 (REST).")));
        assert!(
            rows.iter()
                .any(|(k, v)| *k == "changes_fingerprint" && v == &fp_old)
        );

        // Mount mocks for full source & held-release lifecycle.
        Mock::given(method("GET"))
            .and(path(format!("/organizations/{org_id}/release-sources")))
            .and(header("Authorization", "Bearer seren_test_key"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": [signed_run_source]})),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/organizations/{org_id}/release-sources")))
            .and(header("Authorization", "Bearer oauth-session-token"))
            .and(body_json(json!({
                "kind": "signed_run",
                "label": "Main CI",
                "ci_product": "github_actions",
                "repository": "example/employees",
                "branch": "main",
                "environment": "production",
                "templates": ["analyst"]
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": signed_run_source})),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/organizations/{org_id}/release-sources")))
            .and(header("Authorization", "Bearer oauth-session-token"))
            .and(body_json(json!({
                "kind": "release_key",
                "label": "Fallback key",
                "expires_in_days": 14,
                "templates": ["analyst"]
            })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": created_key_source})),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path(format!(
                "/organizations/{org_id}/release-sources/{source_id}"
            )))
            .and(header("Authorization", "Bearer oauth-session-token"))
            .and(body_json(json!({"environment": null})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": cleared_env_source})),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(format!(
                "/organizations/{org_id}/release-sources/{source_id}"
            )))
            .and(header("Authorization", "Bearer oauth-session-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": revoked_source})))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/organizations/{org_id}/held-releases")))
            .and(wiremock::matchers::query_param_is_missing("status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": [held_summary_wire]})),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/organizations/{org_id}/held-releases")))
            .and(query_param("status", "pending"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"data": [held_summary_wire]})),
            )
            .expect(4)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{org_id}/held-releases/{held_id}/approve"
            )))
            .and(body_json(json!({"changes_fingerprint": fp_old})))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": "managed_agent_held_release_changed",
                "message": "This held release has changed. Review the current changes before approving.",
                "details": {
                    "comparison": comparison_new,
                    "changes_fingerprint": fp_new
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{org_id}/held-releases/{held_id}/approve"
            )))
            .and(body_json(json!({"changes_fingerprint": fp_new})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "slug": "analyst",
                    "revision": 4,
                    "created": false,
                    "revision_added": true,
                    "active": true,
                    "listed": true,
                    "review_state": "approved",
                    "providers": []
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{org_id}/held-releases/{held_id}/refuse"
            )))
            .and(body_json(json!({"note": "Wait for review"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "id": held_id, "status": "refused" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Verify detailed access-change sentences expose fallbacks, guarded hosts/paths/ops, and Cardano scripts/assets/limits.
        let fallback_change: seren::TemplateAccessChange = serde_json::from_value(json!({
            "change": "model_connection_changed",
            "before": {
                "provider": "codex",
                "model_id": "gpt-5",
                "fallback": { "provider": "seren_private_models", "model_id": "model-a" }
            },
            "after": {
                "provider": "codex",
                "model_id": "gpt-5",
                "fallback": { "provider": "seren_private_models", "model_id": "model-b", "fallback_models": ["model-c"] }
            }
        }))
        .unwrap();
        let fallback_text = describe_access_change(&fallback_change);
        assert!(
            fallback_text.contains("model-a")
                && fallback_text.contains("model-b")
                && fallback_text.contains("model-c"),
            "{fallback_text}"
        );

        let guarded_purchase_change: seren::TemplateAccessChange = serde_json::from_value(json!({
            "change": "guarded_purchases_changed",
            "before": [],
            "after": [{ "checkout": "best_buy", "host": "shop.example.com", "method": "POST", "path_pattern": "/orders/*/submit" }]
        }))
        .unwrap();
        let purchase_text = describe_access_change(&guarded_purchase_change);
        assert!(
            purchase_text.contains("shop.example.com/orders/*/submit")
                && purchase_text.contains("best_buy"),
            "{purchase_text}"
        );

        let guarded_submission_change: seren::TemplateAccessChange = serde_json::from_value(json!({
            "change": "guarded_submissions_changed",
            "before": [],
            "after": [{ "host": "forms.example.com", "method": "POST", "path_pattern": "/graphql", "graphql_operation_names": ["SubmitTax"] }]
        }))
        .unwrap();
        let submission_text = describe_access_change(&guarded_submission_change);
        assert!(
            submission_text.contains("forms.example.com/graphql")
                && submission_text.contains("SubmitTax"),
            "{submission_text}"
        );

        let cardano_change: seren::TemplateAccessChange = serde_json::from_value(json!({
            "change": "cardano_signing_changed",
            "before": {
                "builder_script": "scripts/build.py",
                "debt_asset": "a".repeat(56),
                "lender_scripts": ["script1old"],
                "max_borrow_ratio_bps": 5000,
                "max_lend_rate_bps": 1000,
                "max_loan_rate_bps": 1200,
                "mint_policies": ["script1mint1"],
                "payout_assets": ["lovelace"],
                "swap_scripts": ["script1swap1"],
                "venue_scripts": ["script1venue1"]
            },
            "after": {
                "builder_script": "scripts/build_v2.py",
                "debt_asset": "b".repeat(56),
                "lender_scripts": ["script1new"],
                "max_borrow_ratio_bps": 6500,
                "max_lend_rate_bps": 1000,
                "max_loan_rate_bps": 1500,
                "mint_policies": ["script1mint2"],
                "payout_assets": ["lovelace"],
                "swap_scripts": ["script1swap2"],
                "venue_scripts": ["script1venue2"]
            }
        }))
        .unwrap();
        let cardano_text = describe_access_change(&cardano_change);
        assert!(
            cardano_text.contains("scripts/build.py")
                && cardano_text.contains("scripts/build_v2.py")
                && cardano_text.contains("script1old")
                && cardano_text.contains("script1new")
                && cardano_text.contains("6500"),
            "{cardano_text}"
        );

        // Verify create-key output places the show-once notice on stdout in table mode and stderr in JSON mode.
        let created_key_envelope = json!({"data": created_key_source});
        let (mut table_out, mut table_err) = (Vec::new(), Vec::new());
        write_create_key_output(
            &created_key_envelope,
            OutputFormat::Table,
            &mut table_out,
            &mut table_err,
        )
        .unwrap();
        let table_stdout = String::from_utf8(table_out).unwrap();
        assert!(table_stdout.contains("serenrk_synthetic_once_value"));
        assert!(table_stdout.contains(RELEASE_KEY_STORE_ONCE_NOTICE));
        assert!(table_err.is_empty());

        let (mut json_out, mut json_err) = (Vec::new(), Vec::new());
        write_create_key_output(
            &created_key_envelope,
            OutputFormat::Json,
            &mut json_out,
            &mut json_err,
        )
        .unwrap();
        let parsed_json: Value = serde_json::from_slice(&json_out).unwrap();
        assert_eq!(
            parsed_json["data"]["release_key"],
            "serenrk_synthetic_once_value"
        );
        assert!(
            String::from_utf8(json_err)
                .unwrap()
                .contains(RELEASE_KEY_STORE_ONCE_NOTICE)
        );

        // Listing sources works with an unrestricted personal API key.
        execute(
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::List,
            },
            &api_key_ctx,
        )
        .await
        .unwrap();

        // Source writes succeed with a user session token.
        execute(
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Approve {
                    product: ReleaseSourceProduct::GithubActions,
                    repository: "example/employees".into(),
                    branch: "main".into(),
                    environment: Some("production".into()),
                    issuer: None,
                    label: "Main CI".into(),
                    templates: vec!["analyst".into()],
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        execute(
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::CreateKey {
                    label: "Fallback key".into(),
                    days: 14,
                    templates: vec!["analyst".into()],
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        execute(
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Edit {
                    release_source_id: source_id,
                    label: None,
                    branch: None,
                    environment: None,
                    clear_environment: true,
                    templates: vec![],
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        execute(
            ManagedAction::ManagedReleaseSources {
                organization_id: org_id,
                action: ReleaseSourceAction::Revoke {
                    release_source_id: source_id,
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        // Held release list omits `status` by default and forwards explicit `--status`.
        execute(
            ManagedAction::ManagedHeldReleases {
                organization_id: org_id,
                action: HeldReleaseAction::List { status: None },
            },
            &session_ctx,
        )
        .await
        .unwrap();
        execute(
            ManagedAction::ManagedHeldReleases {
                organization_id: org_id,
                action: HeldReleaseAction::List {
                    status: Some(HeldReleaseStatusFilter::Pending),
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        // Without --fingerprint on a non-interactive terminal, approve shows the changes and refuses without posting.
        let session_client = session_ctx.client().await.unwrap();
        let mut non_tty_out = Vec::new();
        let mut non_tty_in = std::io::Cursor::new(b"yes\n");
        let mut non_tty_prompt = ApprovalPrompt {
            interactive: false,
            reader: &mut non_tty_in,
            out: &mut non_tty_out,
        };
        let non_tty_err = approve_held_release(
            &session_client,
            org_id,
            held_id,
            None,
            &session_ctx,
            &mut non_tty_prompt,
        )
        .await
        .unwrap_err();
        assert!(
            non_tty_err.to_string().contains("--fingerprint"),
            "{non_tty_err}"
        );
        assert!(
            String::from_utf8(non_tty_out)
                .unwrap()
                .contains("Added outbound network host api.example.com:443 (REST).")
        );

        // Declining interactive confirmation cancels without posting approve.
        let mut cancel_out = Vec::new();
        let mut cancel_in = std::io::Cursor::new(b"no\n");
        let mut cancel_prompt = ApprovalPrompt {
            interactive: true,
            reader: &mut cancel_in,
            out: &mut cancel_out,
        };
        let cancel_err = approve_held_release(
            &session_client,
            org_id,
            held_id,
            None,
            &session_ctx,
            &mut cancel_prompt,
        )
        .await
        .unwrap_err();
        assert!(cancel_err.to_string().contains("cancelled"), "{cancel_err}");

        // Confirming interactive review posts the shown fingerprint and surfaces 409 managed_agent_held_release_changed.
        let mut confirm_out = Vec::new();
        let mut confirm_in = std::io::Cursor::new(b"yes\n");
        let mut confirm_prompt = ApprovalPrompt {
            interactive: true,
            reader: &mut confirm_in,
            out: &mut confirm_out,
        };
        let conflict = approve_held_release(
            &session_client,
            org_id,
            held_id,
            None,
            &session_ctx,
            &mut confirm_prompt,
        )
        .await
        .unwrap_err();
        let conflict_text = conflict.to_string();
        assert!(
            conflict_text.contains("Added outbound network host data.example.com:443 (REST)."),
            "missing updated change sentence: {conflict_text}"
        );
        assert!(
            conflict_text.contains(&fp_new),
            "missing updated fingerprint: {conflict_text}"
        );

        // Explicit --fingerprint approves directly without needing a prompt.
        execute(
            ManagedAction::ManagedHeldReleases {
                organization_id: org_id,
                action: HeldReleaseAction::Approve {
                    held_release_id: held_id,
                    fingerprint: Some(fp_new),
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        execute(
            ManagedAction::ManagedHeldReleases {
                organization_id: org_id,
                action: HeldReleaseAction::Refuse {
                    held_release_id: held_id,
                    note: "Wait for review".into(),
                },
            },
            &session_ctx,
        )
        .await
        .unwrap();

        server.verify().await;
    }

    #[tokio::test]
    async fn releasing_a_folder_ends_published_or_held() {
        use std::collections::HashMap;
        use std::process::Command;

        use sha2::{Digest, Sha256};
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let org_id = Uuid::from_u128(801);
        let source_id = Uuid::from_u128(802);
        let bundle_id = Uuid::from_u128(803);
        let held_id = Uuid::from_u128(804);
        let org_str = org_id.to_string();
        let fingerprint = "c".repeat(64);
        let explicit_commit = "b".repeat(40);
        let release_key = "serenrk_synthetic_release_key";
        let release_pass_token = "serenpass_synthetic_release_pass";
        let unused_api_key = "seren_unused_personal_api_key";

        // Parse checks for `managed-release` arguments.
        let parsed = ManagedCli::try_parse_from([
            "agent",
            "managed-release",
            &org_str,
            "./employee",
            "--settings",
            "./custom-release.json",
            "--commit",
            &explicit_commit,
        ])
        .unwrap();
        assert!(matches!(
            parsed.action,
            ManagedAction::ManagedRelease {
                organization_id,
                folder,
                settings: Some(settings),
                commit: Some(commit),
            } if organization_id == org_id
                && folder == Path::new("./employee")
                && settings == Path::new("./custom-release.json")
                && commit == explicit_commit
        ));

        // Build a synthetic Employee folder initialized as a git repository.
        let fixture = tempfile::tempdir().unwrap();
        let folder = fixture.path().join("analyst");
        fs::create_dir_all(&folder).unwrap();
        fs::write(
            folder.join("SKILL.md"),
            "---\nname: analyst\ndescription: Synthetic analyst employee\n---\n\n# Analyst\n",
        )
        .unwrap();
        let deploy_defaults = json!({
            "mode": "cron",
            "cron_schedule": "0 9 * * *",
            "model_policy": "balanced",
            "max_runtime_seconds": 300,
            "browser": {"display": "headless", "max_session_seconds": 60},
            "network_egress": [],
            "script_publisher_grants": []
        });
        let settings_json = json!({
            "slug": "analyst",
            "display_name": "Analyst",
            "deploy_defaults": deploy_defaults,
            "release_note": "Add quarterly report summary."
        });
        fs::write(
            folder.join("seren-release.json"),
            serde_json::to_vec_pretty(&settings_json).unwrap(),
        )
        .unwrap();

        for args in [
            vec!["init"],
            vec!["config", "user.name", "Test User"],
            vec!["config", "user.email", "test@example.com"],
            vec!["add", "."],
            vec!["-c", "commit.gpgsign=false", "commit", "-m", "initial"],
        ] {
            let status = Command::new("git")
                .arg("-C")
                .arg(&folder)
                .args(&args)
                .status()
                .expect("git is available for tests");
            assert!(status.success(), "git {args:?} failed with {status}");
        }
        let git_head = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&folder)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        assert_eq!(git_head.len(), 40);

        // Build expected bundle from a folder with only SKILL.md (no seren-release.json)
        // so the test proves the release settings file is excluded from the packaged bundle.
        let expected_only_dir = tempfile::tempdir().unwrap();
        fs::write(
            expected_only_dir.path().join("SKILL.md"),
            "---\nname: analyst\ndescription: Synthetic analyst employee\n---\n\n# Analyst\n",
        )
        .unwrap();
        let expected_draft =
            super::super::agent_dev::package_agent_bundle(expected_only_dir.path()).unwrap();
        assert!(expected_draft.bundle.assets.is_empty());
        let (expected_bundle_bytes, _) =
            super::super::agent::managed_bundle_upload(&expected_draft).unwrap();
        let expected_bundle_sha = hex::encode(Sha256::digest(&expected_bundle_bytes));
        let expected_bundle_size = i64::try_from(expected_bundle_bytes.len()).unwrap();

        // Also verify an external settings symlink inside `<folder>` is excluded before symlink escape checks.
        #[cfg(unix)]
        {
            let symlink_dir = tempfile::tempdir().unwrap();
            let linked_folder = symlink_dir.path().join("employee");
            fs::create_dir_all(&linked_folder).unwrap();
            fs::write(
                linked_folder.join("SKILL.md"),
                "---\nname: analyst\ndescription: Synthetic analyst employee\n---\n\n# Analyst\n",
            )
            .unwrap();
            let external_settings = symlink_dir.path().join("external-release.json");
            fs::write(
                &external_settings,
                serde_json::to_vec_pretty(&settings_json).unwrap(),
            )
            .unwrap();
            let symlink_settings = linked_folder.join("seren-release.json");
            std::os::unix::fs::symlink(&external_settings, &symlink_settings).unwrap();
            let symlink_draft = super::super::agent_dev::package_agent_bundle_excluding(
                &linked_folder,
                Some(symlink_settings.as_path()),
            )
            .unwrap();
            let (symlink_bytes, _) =
                super::super::agent::managed_bundle_upload(&symlink_draft).unwrap();
            assert_eq!(symlink_bytes, expected_bundle_bytes);
            assert!(symlink_draft.bundle.assets.is_empty());
        }

        let env = HashMap::from([("SEREN_RELEASE_KEY", release_key.to_string())]);
        let env_lookup = |name: &str| env.get(name).cloned();

        // Unknown settings field and malformed commit SHA fail locally before any HTTP call.
        let untouched_server = MockServer::start().await;
        let bad_settings_path = fixture.path().join("bad-release.json");
        fs::write(
            &bad_settings_path,
            serde_json::to_vec(&json!({
                "slug": "analyst",
                "display_name": "Analyst",
                "deploy_defaults": deploy_defaults,
                "unexpected_key": true
            }))
            .unwrap(),
        )
        .unwrap();
        let untouched_ctx = CommandContext::new(
            Some(untouched_server.uri()),
            Some(unused_api_key.into()),
            OutputFormat::Table,
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let unknown_err = managed_release_with_env(
            org_id,
            &folder,
            Some(&bad_settings_path),
            None,
            &untouched_ctx,
            &env_lookup,
            &mut out,
            &mut err,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{unknown_err:#}").contains("unknown field"),
            "expected deny_unknown_fields error, got: {unknown_err:#}"
        );
        let bad_commit_err = managed_release_with_env(
            org_id,
            &folder,
            None,
            Some("abc1234".into()),
            &untouched_ctx,
            &env_lookup,
            &mut out,
            &mut err,
        )
        .await
        .unwrap_err();
        assert!(
            bad_commit_err.to_string().contains("40 or 64"),
            "unexpected commit error: {bad_commit_err}"
        );
        assert!(
            untouched_server
                .received_requests()
                .await
                .unwrap()
                .is_empty()
        );

        // 1. Published (200): release key obtains pass without Authorization;
        //    bundle register, upload complete, and release all authenticate with the pass,
        //    never the release key or personal API key.
        let publish_server = MockServer::start().await;
        let pass_route = format!("/organizations/{org_id}/release-passes");
        let release_route = format!("/organizations/{org_id}/templates/analyst/releases");
        let bundle_register_route = "/publishers/seren-cloud/deployment-bundles";
        let bundle_complete_route =
            format!("/publishers/seren-cloud/deployment-bundles/{bundle_id}/complete");
        let presigned_upload_route = "/object-storage/upload-bundle";

        Mock::given(method("POST"))
            .and(path(&pass_route))
            .and(body_json(json!({
                "proof": "release_key",
                "key": release_key,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": release_pass_token,
                    "expires_at": "2026-11-25T18:00:00Z",
                    "release_source_id": source_id,
                    "templates": ["analyst"]
                }
            })))
            .expect(1)
            .mount(&publish_server)
            .await;

        Mock::given(method("POST"))
            .and(path(bundle_register_route))
            .and(header(
                "Authorization",
                format!("Bearer {release_pass_token}"),
            ))
            .and(body_json(json!({
                "sha256": expected_bundle_sha,
                "size_bytes": expected_bundle_size,
                "source_kind": "agent_bundle"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "deployment_bundle_id": bundle_id,
                    "sha256": expected_bundle_sha,
                    "size_bytes": expected_bundle_size,
                    "source_kind": "agent_bundle",
                    "upload_required": true,
                    "upload_url": format!("{}{}", publish_server.uri(), presigned_upload_route),
                    "upload_headers": {"x-amz-meta-test": "1"}
                }
            })))
            .expect(1)
            .mount(&publish_server)
            .await;

        Mock::given(method("PUT"))
            .and(path(presigned_upload_route))
            .and(header("x-amz-meta-test", "1"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&publish_server)
            .await;

        Mock::given(method("POST"))
            .and(path(&bundle_complete_route))
            .and(header(
                "Authorization",
                format!("Bearer {release_pass_token}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "id": bundle_id,
                    "organization_id": org_id,
                    "user_id": Uuid::from_u128(805),
                    "sha256": expected_bundle_sha,
                    "size_bytes": expected_bundle_size,
                    "source_kind": "agent_bundle",
                    "created_at": "2026-11-25T17:00:00Z",
                    "updated_at": "2026-11-25T17:00:00Z",
                    "uploaded_at": "2026-11-25T17:00:00Z"
                }
            })))
            .expect(1)
            .mount(&publish_server)
            .await;

        Mock::given(method("POST"))
            .and(path(&release_route))
            .and(header(
                "Authorization",
                format!("Bearer {release_pass_token}"),
            ))
            .and(body_json(json!({
                "display_name": "Analyst",
                "source_bundle_id": bundle_id,
                "source_commit_sha": git_head,
                "deploy_defaults": deploy_defaults,
                "listed": true,
                "rollout": false,
                "release_note": "Add quarterly report summary."
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "slug": "analyst",
                    "revision": 3,
                    "created": false,
                    "revision_added": true,
                    "active": true,
                    "listed": true,
                    "review_state": "approved",
                    "providers": ["google"],
                    "access_changes": [
                        {
                            "change": "network_host_added",
                            "rule": { "host": "api.example.com", "port": 443, "protocol": "rest" }
                        }
                    ]
                }
            })))
            .expect(1)
            .mount(&publish_server)
            .await;

        let publish_ctx = CommandContext::new(
            Some(publish_server.uri()),
            Some(unused_api_key.into()),
            OutputFormat::Table,
        );
        let (mut pub_out, mut pub_err) = (Vec::new(), Vec::new());
        managed_release_with_env(
            org_id,
            &folder,
            None,
            None,
            &publish_ctx,
            &env_lookup,
            &mut pub_out,
            &mut pub_err,
        )
        .await
        .unwrap();
        let pub_stdout = String::from_utf8(pub_out).unwrap();
        let pub_stderr = String::from_utf8(pub_err).unwrap();
        assert!(
            pub_stdout.contains("Published analyst revision 3."),
            "unexpected published output: {pub_stdout}"
        );
        assert!(
            pub_stdout.contains("Added outbound network host api.example.com:443 (REST)."),
            "missing access change on published output: {pub_stdout}"
        );
        assert_eq!(pub_stderr, "Using release key proof.\n");
        assert!(!pub_stdout.contains(release_key) && !pub_stdout.contains(release_pass_token));
        assert!(!pub_stderr.contains(release_key) && !pub_stderr.contains(release_pass_token));

        let received = publish_server.received_requests().await.unwrap();
        assert_eq!(received.len(), 5);
        assert!(
            !received[0].headers.contains_key("authorization"),
            "release-passes request must not send Authorization"
        );
        let uploaded_put = received
            .iter()
            .find(|req| req.method.as_str() == "PUT")
            .expect("presigned upload PUT request");
        assert_eq!(uploaded_put.body, expected_bundle_bytes);
        let uploaded_bundle: seren::AgentBundle =
            serde_json::from_slice(&uploaded_put.body).expect("uploaded bundle is valid JSON");
        assert!(
            !uploaded_bundle
                .assets
                .iter()
                .any(|asset| asset.path == "seren-release.json"),
            "release settings file must not be packaged into bundle assets: {:?}",
            uploaded_bundle.assets
        );
        for req in &received {
            if let Some(auth) = req.headers.get("authorization") {
                let auth_str = auth.to_str().unwrap();
                assert_eq!(auth_str, format!("Bearer {release_pass_token}"));
                assert!(!auth_str.contains(release_key));
                assert!(!auth_str.contains(unused_api_key));
            }
        }
        publish_server.verify().await;

        // Also check `-o json` formatting for published releases.
        let mut pub_json_out = Vec::new();
        let sample_release: seren::ManagedAgentTemplateRelease = serde_json::from_value(json!({
            "slug": "analyst",
            "revision": 3,
            "created": false,
            "revision_added": true,
            "active": true,
            "listed": true,
            "review_state": "approved",
            "providers": ["google"]
        }))
        .unwrap();
        write_managed_release_published(&sample_release, OutputFormat::Json, &mut pub_json_out)
            .unwrap();
        let pub_json: Value = serde_json::from_slice(&pub_json_out).unwrap();
        assert_eq!(pub_json["outcome"], "published");
        assert_eq!(pub_json["slug"], "analyst");
        assert_eq!(pub_json["revision"], 3);

        // 2. Held (409 managed_agent_release_held): exits Ok(()), prints reason, changes,
        //    CLI approve command and Console URL in table mode, and `{"outcome":"held", ...}` in JSON mode.
        let held_details = json!({
            "held_release_id": held_id,
            "reason": "access_change",
            "comparison": {
                "kind": "access",
                "access_changes": [
                    {
                        "change": "network_host_added",
                        "rule": { "host": "data.example.com", "port": 443, "protocol": "rest" }
                    }
                ],
                "content_changes": { "added": [], "changed": ["SKILL.md"], "removed": [] }
            },
            "changes_fingerprint": fingerprint,
            "approve_path": format!("/organizations/{org_id}/held-releases/{held_id}/approve")
        });

        for format in [OutputFormat::Table, OutputFormat::Json] {
            let held_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(&pass_route))
                .and(body_json(json!({
                    "proof": "release_key",
                    "key": release_key,
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": {
                        "pass": release_pass_token,
                        "expires_at": "2026-11-25T18:00:00Z",
                        "release_source_id": source_id,
                        "templates": ["analyst"]
                    }
                })))
                .expect(1)
                .mount(&held_server)
                .await;

            Mock::given(method("POST"))
                .and(path(bundle_register_route))
                .and(header(
                    "Authorization",
                    format!("Bearer {release_pass_token}"),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": {
                        "deployment_bundle_id": bundle_id,
                        "sha256": expected_bundle_sha,
                        "size_bytes": expected_bundle_size,
                        "source_kind": "agent_bundle",
                        "upload_required": false,
                        "upload_headers": {}
                    }
                })))
                .expect(1)
                .mount(&held_server)
                .await;

            Mock::given(method("POST"))
                .and(path(&release_route))
                .and(header(
                    "Authorization",
                    format!("Bearer {release_pass_token}"),
                ))
                .and(body_json(json!({
                    "display_name": "Analyst",
                    "source_bundle_id": bundle_id,
                    "source_commit_sha": explicit_commit,
                    "deploy_defaults": deploy_defaults,
                    "listed": true,
                    "rollout": false,
                    "release_note": "Add quarterly report summary."
                })))
                .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                    "error": "managed_agent_release_held",
                    "message": "This release changes what the Employee can reach, so it waits for an Owner or Admin to approve it.",
                    "details": held_details
                })))
                .expect(1)
                .mount(&held_server)
                .await;

            let held_ctx =
                CommandContext::new(Some(held_server.uri()), Some(unused_api_key.into()), format);
            let (mut held_out, mut held_err) = (Vec::new(), Vec::new());
            managed_release_with_env(
                org_id,
                &folder,
                None,
                Some(explicit_commit.clone()),
                &held_ctx,
                &env_lookup,
                &mut held_out,
                &mut held_err,
            )
            .await
            .unwrap();
            let held_stdout = String::from_utf8(held_out).unwrap();
            match format {
                OutputFormat::Table => {
                    assert!(
                        held_stdout.contains("Held for approval: access change."),
                        "unexpected held output: {held_stdout}"
                    );
                    assert!(
                        held_stdout
                            .contains("Added outbound network host data.example.com:443 (REST)."),
                        "missing held access change: {held_stdout}"
                    );
                    assert!(
                        held_stdout.contains(&format!(
                            "Approve it: seren agent managed-held-releases {org_id} approve {held_id}"
                        )),
                        "missing CLI approval command: {held_stdout}"
                    );
                    assert!(
                        held_stdout.contains(CONSOLE_PUBLISHED_EMPLOYEES_URL),
                        "missing Console page URL: {held_stdout}"
                    );
                }
                OutputFormat::Json => {
                    let parsed: Value = serde_json::from_str(&held_stdout).unwrap();
                    assert_eq!(parsed["outcome"], "held");
                    assert_eq!(parsed["held_release_id"], held_id.to_string());
                    assert_eq!(parsed["reason"], "access_change");
                    assert_eq!(parsed["changes_fingerprint"], fingerprint);
                    assert_eq!(
                        parsed["approve_path"],
                        format!("/organizations/{org_id}/held-releases/{held_id}/approve")
                    );
                }
            }
            held_server.verify().await;
        }

        // 3. Refused (non-held 409 or 403): returns Err with the server's message.
        let refused_server = MockServer::start().await;
        let refusal_message = "This release source may not release analyst.";
        Mock::given(method("POST"))
            .and(path(&pass_route))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "pass": release_pass_token,
                    "expires_at": "2026-11-25T18:00:00Z",
                    "release_source_id": source_id,
                    "templates": ["other"]
                }
            })))
            .expect(1)
            .mount(&refused_server)
            .await;
        Mock::given(method("POST"))
            .and(path(bundle_register_route))
            .and(header(
                "Authorization",
                format!("Bearer {release_pass_token}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "deployment_bundle_id": bundle_id,
                    "sha256": expected_bundle_sha,
                    "size_bytes": expected_bundle_size,
                    "source_kind": "agent_bundle",
                    "upload_required": false,
                    "upload_headers": {}
                }
            })))
            .expect(1)
            .mount(&refused_server)
            .await;
        Mock::given(method("POST"))
            .and(path(&release_route))
            .and(header(
                "Authorization",
                format!("Bearer {release_pass_token}"),
            ))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "error": "release_source_template_not_allowed",
                "message": refusal_message
            })))
            .expect(1)
            .mount(&refused_server)
            .await;

        let refused_ctx = CommandContext::new(
            Some(refused_server.uri()),
            Some(unused_api_key.into()),
            OutputFormat::Table,
        );
        let (mut ref_out, mut ref_err) = (Vec::new(), Vec::new());
        let refused_err = managed_release_with_env(
            org_id,
            &folder,
            None,
            Some(explicit_commit),
            &refused_ctx,
            &env_lookup,
            &mut ref_out,
            &mut ref_err,
        )
        .await
        .unwrap_err();
        assert_eq!(refused_err.to_string(), refusal_message);
        refused_server.verify().await;
    }
}
