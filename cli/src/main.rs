use clap::{ArgAction, Parser, Subcommand};
use uuid::Uuid;

use seren_cli::commands;
use seren_cli::money::UsdCents;
use seren_cli::{CommandContext, OutputFormat, config, defaults};

#[derive(Parser)]
#[command(name = "seren")]
#[command(about = "CLI tool for Seren database management", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json or table)
    #[arg(long, short = 'o', global = true, default_value = "table")]
    format: OutputFormat,

    /// API base URL
    #[arg(long = "api-base", global = true, env = "SEREN_API_BASE")]
    api_host: Option<String>,

    /// API key for authentication (overrides stored credentials)
    #[arg(long, global = true, env = "SEREN_API_KEY")]
    api_key: Option<String>,

    /// Profile name to select per-profile credentials and context.
    ///
    /// Precedence (highest first): --profile, SEREN_PROFILE, "default".
    /// Profile-scoped state lives under `~/.config/seren/profiles/<name>/`.
    #[arg(long, global = true, env = "SEREN_PROFILE")]
    profile: Option<String>,

    /// Pretty-print API request/response envelopes for debugging.
    ///
    /// Currently parsed but not wired through the request pipeline; the flag
    /// is reserved so consumers can adopt it before envelope logging lands.
    #[arg(long, global = true, hide = true)]
    debug_envelopes: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with Seren
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Get current user information
    Me,
    /// List organizations
    Organizations,
    /// Manage organizations (members, invites)
    Orgs {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Manage files through the Seren Storage publisher
    Storage {
        #[command(subcommand)]
        action: StorageAction,
    },
    /// Administer organization object storage
    #[command(name = "object-storage")]
    ObjectStorage {
        /// Organization ID, or default for the active organization
        #[arg(long, default_value = "default")]
        org_id: String,

        #[command(subcommand)]
        action: ObjectStorageAction,
    },
    /// Manage projects
    Projects {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Manage branches
    Branches {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: BranchAction,
    },
    /// Manage databases
    Databases {
        /// Project ID
        #[arg(long)]
        project_id: String,

        /// Branch ID
        #[arg(long)]
        branch_id: String,

        #[command(subcommand)]
        action: DatabaseAction,
    },
    /// Manage databases across projects
    #[command(name = "database")]
    Database {
        #[command(subcommand)]
        action: GlobalDatabaseAction,
    },
    /// Manage roles
    Roles {
        /// Project ID
        #[arg(long)]
        project_id: String,

        /// Branch ID
        #[arg(long)]
        branch_id: String,

        #[command(subcommand)]
        action: RoleAction,
    },
    /// Manage endpoints
    Endpoints {
        /// Project ID
        #[arg(long)]
        project_id: String,

        /// Branch ID
        #[arg(long)]
        branch_id: String,

        #[command(subcommand)]
        action: EndpointAction,
    },
    /// Manage operations
    Operations {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: OperationAction,
    },
    /// Manage IP allow lists
    IpAllowList {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: IpAllowListAction,
    },
    /// Manage CLI context (default project and org)
    SetContext {
        #[command(subcommand)]
        action: ContextAction,
    },
    /// Manage environment files and connection strings
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Connect to a database with psql
    Psql {
        /// Project ID (defaults to CLI context if not provided)
        #[arg(long)]
        project_id: Option<String>,

        /// Branch ID to connect to
        #[arg(long)]
        branch_id: Option<String>,

        /// Endpoint ID override
        #[arg(long)]
        endpoint_id: Option<String>,

        /// Database name override
        #[arg(long)]
        database: Option<String>,

        /// Role name override
        #[arg(long)]
        role: Option<String>,

        /// Request pooled connection string
        #[arg(long, action = ArgAction::SetTrue)]
        pooled: bool,

        /// Override SSL mode (require, prefer, disable)
        #[arg(long)]
        ssl: Option<String>,

        /// Arguments passed to psql after `--`
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        psql_args: Vec<String>,
    },
    /// Manage VPC endpoints
    Vpc {
        #[command(subcommand)]
        action: VpcAction,
    },
    /// Manage billing and invoices
    Billing {
        #[command(subcommand)]
        action: BillingAction,
    },
    /// Manage user sessions
    Sessions {
        #[command(subcommand)]
        action: SessionAction,
    },
    /// Manage Seren Passwords vault entries
    Passwords {
        /// Read the Seren Passwords master password from stdin.
        #[arg(long)]
        master_password_stdin: bool,

        /// Read the Seren Passwords master password from a file.
        #[arg(long)]
        master_password_file: Option<std::path::PathBuf>,

        #[command(subcommand)]
        action: PasswordsAction,
    },
    /// Manage webhooks for an organization
    Webhooks {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: WebhookAction,
    },
    /// View audit logs for an organization
    AuditLogs {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: AuditLogAction,
    },
    /// Manage RBAC roles for an organization
    Rbac {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: RbacAction,
    },
    /// Manage branch protection rules
    BranchProtection {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: BranchProtectionAction,
    },
    /// Manage logical replication
    Replication {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: ReplicationAction,
    },
    /// Agent commerce and x402 payment commands
    Agent {
        #[command(subcommand)]
        action: Box<AgentAction>,
    },
    /// Discover, install, and manage AI agent skills
    Skills {
        #[command(subcommand)]
        action: SkillsAction,
    },
    /// Manage OAuth connections for BYOC publishers
    Oauth {
        #[command(subcommand)]
        action: OAuthAction,
    },
    /// Start the Seren MCP server
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
}

#[derive(Subcommand)]
enum SkillsAction {
    /// List all available skills
    List {
        /// Force refresh from GitHub (ignore cache)
        #[arg(long)]
        refresh: bool,
    },
    /// Search skills by name or description
    Search {
        /// Search query
        query: String,
    },
    /// Show details about a specific skill
    Show {
        /// Skill slug (e.g., coinbase-grid-trader)
        slug: String,
    },
    /// Install a skill (or all skills with --all)
    Add {
        /// Skill slug to install
        slug: Option<String>,
        /// Install all available skills
        #[arg(long)]
        all: bool,
        /// Auto-confirm agent directory installation
        #[arg(long, short)]
        yes: bool,
    },
    /// List locally installed skills
    Installed,
    /// Remove an installed skill
    Remove {
        /// Skill slug to remove
        slug: String,
    },
    /// Update installed skill(s) to latest version
    Update {
        /// Skill slug to update (omit to update all)
        slug: Option<String>,
        /// Auto-confirm agent directory installation
        #[arg(long, short)]
        yes: bool,
    },
    /// Initialize a new skill template
    Init {
        /// Skill name (creates directory)
        name: Option<String>,
        /// Directory to create skill in
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum PasswordsAction {
    /// List password vaults available to the current account
    Vaults {
        #[command(subcommand)]
        action: Box<PasswordVaultAction>,
    },
    /// Create encrypted password items
    Items {
        #[command(subcommand)]
        action: Box<PasswordItemAction>,
    },
    /// List, download, and delete item attachments
    Attachments {
        #[command(subcommand)]
        action: PasswordAttachmentAction,
    },
    /// Provision and manage AI-agent identities for vault access
    Agent {
        #[command(subcommand)]
        action: PasswordAgentAction,
    },
    /// Inspect Seren Passwords audit events
    Audit {
        #[command(subcommand)]
        action: PasswordAuditAction,
    },
    /// Manage password approval requests
    Approvals {
        #[command(subcommand)]
        action: PasswordApprovalAction,
    },
    /// Inspect and revoke vault memberships
    Memberships {
        #[command(subcommand)]
        action: PasswordMembershipAction,
    },
    /// Create, redeem, and complete vault invitations
    Invitations {
        #[command(subcommand)]
        action: PasswordInvitationAction,
    },
    /// Generate a strong password or passphrase locally without storing it.
    GeneratePassword {
        /// Generator mode: random, passphrase, or hex.
        #[arg(long, default_value = "random", value_parser = ["random", "passphrase", "hex"])]
        mode: String,
        /// Random or hex length. Random defaults to 20; hex defaults to 32.
        #[arg(long)]
        length: Option<u32>,
        /// Exclude uppercase letters in random mode.
        #[arg(long = "no-upper", default_value_t = true, action = ArgAction::SetFalse)]
        upper: bool,
        /// Exclude lowercase letters in random mode.
        #[arg(long = "no-lower", default_value_t = true, action = ArgAction::SetFalse)]
        lower: bool,
        /// Exclude digits in random mode.
        #[arg(long = "no-digits", default_value_t = true, action = ArgAction::SetFalse)]
        digits: bool,
        /// Exclude symbols in random mode.
        #[arg(long = "no-symbols", default_value_t = true, action = ArgAction::SetFalse)]
        symbols: bool,
        /// Word count for passphrase mode.
        #[arg(long, default_value_t = 5)]
        word_count: u32,
        /// Word separator for passphrase mode.
        #[arg(long, default_value_t = '-')]
        separator: char,
        /// Do not capitalize passphrase words.
        #[arg(long = "no-capitalize-first", default_value_t = true, action = ArgAction::SetFalse)]
        capitalize_first: bool,
    },
    /// Inspect and revoke live item shares
    Shares {
        #[command(subcommand)]
        action: PasswordShareAction,
    },
    /// Export decrypted vault items and attachments to a plaintext JSON file.
    Export {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Destination JSON file. The file must not already exist.
        #[arg(long)]
        output: std::path::PathBuf,
        /// Exclude attachments from the export.
        #[arg(long)]
        exclude_attachments: bool,
    },
    /// Import plaintext JSON items and attachments into a vault.
    Import {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Source JSON file produced by `passwords export`.
        #[arg(long)]
        input: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum PasswordVaultAction {
    /// List vaults and decrypted vault names
    List,
    /// Create a new encrypted user vault
    Create {
        /// Vault name
        #[arg(long)]
        name: String,
        /// Vault description
        #[arg(long)]
        description: Option<String>,
        /// Approval policy for reads
        #[arg(long, value_enum)]
        requires_approval: Option<PasswordVaultApprovalModeArg>,
    },
    /// Update encrypted vault display metadata. Requires admin membership.
    Update {
        /// Vault id to update
        vault_id: Uuid,
        /// New vault name
        #[arg(long)]
        name: Option<String>,
        /// New vault description
        #[arg(long)]
        description: Option<String>,
    },
    /// Soft-archive a vault. Requires admin membership.
    Archive {
        /// Vault id to archive
        vault_id: Uuid,
    },
    /// Rotate a vault key. Requires admin membership.
    Rotate {
        #[command(subcommand)]
        action: PasswordVaultRotateAction,
    },
}

#[derive(Subcommand)]
enum PasswordVaultRotateAction {
    /// Start a two-phase rotation and print the rotation token
    Initiate {
        /// Vault id to rotate
        vault_id: Uuid,
    },
    /// Complete a rotation, starting one first when no token is supplied
    Complete {
        /// Vault id to rotate
        vault_id: Uuid,
        /// Existing rotation token from `rotate initiate`
        #[arg(long)]
        rotation_token: Option<Uuid>,
    },
    /// Cancel an in-progress rotation
    Cancel {
        /// Vault id to cancel
        vault_id: Uuid,
        /// Rotation token from `rotate initiate`
        rotation_token: Uuid,
    },
}

#[derive(Subcommand)]
enum PasswordAgentAction {
    /// Provision a new agent identity and grant it vault access
    Provision {
        /// Vault id to grant, or "all" for every vault you can access
        #[arg(long)]
        vault: String,
        /// Access level to grant the agent
        #[arg(long, value_enum, default_value_t = AgentAccessArg::Write)]
        access: AgentAccessArg,
        /// Human-readable name for the agent identity
        #[arg(long, default_value = "seren-cli agent")]
        name: String,
        /// Days until the minted agent API key expires. Omit for a non-expiring
        /// key (a warning is printed); expiry bounds the lifetime of a leaked key.
        #[arg(long)]
        expires_in_days: Option<u32>,
    },
    /// List the agent identities you have provisioned and their vault grants
    List,
    /// Revoke every active agent identity you own
    Freeze,
    /// Revoke an agent's vault membership (with --vault) or the whole identity
    Revoke {
        /// Agent identity id to revoke
        agent_id: Uuid,
        /// Revoke only this vault membership; omit to revoke the whole identity
        #[arg(long)]
        vault: Option<Uuid>,
    },
}

#[derive(Subcommand)]
enum PasswordAuditAction {
    /// List password-vault audit events visible to your account
    List {
        /// Filter by exact audit action
        #[arg(long)]
        action: Option<String>,
        /// Filter by actor identity id
        #[arg(long)]
        actor_identity_id: Option<Uuid>,
        /// Filter by target kind
        #[arg(long)]
        target_kind: Option<String>,
        /// Filter by target id
        #[arg(long)]
        target_id: Option<Uuid>,
        /// Start timestamp, for example 2030-01-01T00:00:00Z
        #[arg(long)]
        from: Option<String>,
        /// End timestamp, for example 2030-01-01T23:59:59Z
        #[arg(long)]
        to: Option<String>,
        /// Maximum audit entries to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Verify the password-vault audit hash chain
    Verify,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum PasswordApprovalTargetKindArg {
    Vault,
    Item,
}

impl From<PasswordApprovalTargetKindArg> for seren::ApprovalTargetKind {
    fn from(value: PasswordApprovalTargetKindArg) -> Self {
        match value {
            PasswordApprovalTargetKindArg::Vault => seren::ApprovalTargetKind::Vault,
            PasswordApprovalTargetKindArg::Item => seren::ApprovalTargetKind::Item,
        }
    }
}

#[derive(Subcommand)]
enum PasswordApprovalAction {
    /// Request approval for a vault or item target
    Request {
        /// Target kind to request approval for
        #[arg(long, value_enum)]
        target_kind: PasswordApprovalTargetKindArg,
        /// Target vault or item id
        #[arg(long)]
        target_id: Uuid,
        /// Seconds before the request expires
        #[arg(long, value_parser = clap::value_parser!(i32).range(1..=3600))]
        timeout_seconds: Option<i32>,
    },
    /// List pending approvals visible to your account
    List,
    /// Fetch one approval request
    Get {
        /// Approval request id
        approval_id: Uuid,
    },
    /// Approve a pending approval request
    Approve {
        /// Approval request id
        approval_id: Uuid,
    },
    /// Deny a pending approval request
    Deny {
        /// Approval request id
        approval_id: Uuid,
    },
}

#[derive(Subcommand)]
enum PasswordMembershipAction {
    /// List active memberships for a vault
    List {
        /// Vault id
        vault_id: Uuid,
    },
    /// Grant an identity access to a vault. Requires admin membership.
    Grant {
        /// Vault id
        vault_id: Uuid,
        /// Identity id to grant
        identity_id: Uuid,
        /// Access level to grant
        #[arg(long, value_enum, default_value_t = PasswordAccessArg::Write)]
        access: PasswordAccessArg,
    },
    /// Revoke an identity's vault membership. Requires admin membership.
    Revoke {
        /// Vault id
        vault_id: Uuid,
        /// Identity id to revoke from the vault
        identity_id: Uuid,
    },
}

#[derive(Subcommand)]
enum PasswordInvitationAction {
    /// Create an invitation token for a vault
    Create {
        /// Vault id
        vault_id: Uuid,
        /// Invitee email address
        #[arg(long)]
        email: String,
        /// Access level to grant once completed
        #[arg(long, value_enum, default_value_t = PasswordAccessArg::Read)]
        access: PasswordAccessArg,
        /// Hours until expiration. Omit for server default.
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..=8760))]
        expires_in_hours: Option<i64>,
    },
    /// List pending invitations for this identity, or invitations for a vault
    List {
        /// Vault id. When omitted, lists pending redeemed invitations.
        #[arg(long)]
        vault_id: Option<Uuid>,
    },
    /// Redeem an invitation token as the current identity
    Redeem {
        /// Invitation token
        token: String,
    },
    /// Complete a redeemed invitation by granting the redeemer vault access
    Complete {
        /// Vault id
        vault_id: Uuid,
        /// Invitation id
        invitation_id: Uuid,
    },
}

#[derive(Subcommand)]
enum PasswordShareAction {
    /// List live shares you have sent
    Outbound {
        /// Filter by vault id
        #[arg(long)]
        vault_id: Option<Uuid>,
    },
    /// List live shares you have received
    Received,
    /// Revoke a live share you sent
    Revoke {
        /// Share id
        share_id: Uuid,
    },
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum AgentAccessArg {
    Read,
    Write,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum PasswordAccessArg {
    Read,
    Write,
    Admin,
}

impl From<PasswordAccessArg> for seren::AccessLevel {
    fn from(value: PasswordAccessArg) -> Self {
        match value {
            PasswordAccessArg::Read => seren::AccessLevel::Read,
            PasswordAccessArg::Write => seren::AccessLevel::Write,
            PasswordAccessArg::Admin => seren::AccessLevel::Admin,
        }
    }
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum PasswordVaultApprovalModeArg {
    Never,
    SensitiveOnly,
    Always,
}

impl From<PasswordVaultApprovalModeArg> for seren::VaultApprovalMode {
    fn from(value: PasswordVaultApprovalModeArg) -> Self {
        match value {
            PasswordVaultApprovalModeArg::Never => seren::VaultApprovalMode::Never,
            PasswordVaultApprovalModeArg::SensitiveOnly => seren::VaultApprovalMode::SensitiveOnly,
            PasswordVaultApprovalModeArg::Always => seren::VaultApprovalMode::Always,
        }
    }
}

#[derive(Subcommand)]
enum PasswordItemAction {
    /// Create a login item
    #[command(name = "create-login")]
    Login {
        /// Destination vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item title
        #[arg(long)]
        title: String,
        /// Login username
        #[arg(long, default_value = "")]
        username: String,
        /// Login password. Prefer --password-stdin to avoid shell history.
        #[arg(long, hide = true)]
        password: Option<String>,
        /// Read the login password from stdin
        #[arg(long)]
        password_stdin: bool,
        /// Associated login URL. Repeat or comma-separate.
        #[arg(long = "url", value_delimiter = ',')]
        urls: Vec<String>,
        /// Plain-text notes to encrypt into the item body
        #[arg(long)]
        notes: Option<String>,
        /// Tag. Repeat or comma-separate.
        #[arg(long = "tag", value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark the item as sensitive for server-side approval policy
        #[arg(long)]
        sensitive: bool,
    },
    /// Create an API credential item
    #[command(name = "create-api-key")]
    ApiKey {
        /// Destination vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item title
        #[arg(long)]
        title: String,
        /// API key value. Prefer --key-stdin to avoid shell history.
        #[arg(long, hide = true)]
        key: Option<String>,
        /// Read the API key from stdin
        #[arg(long)]
        key_stdin: bool,
        /// Credential kind: api_key, oauth2_token, basic, mtls, aws_sig_v4, gcp_service_account
        #[arg(long, default_value = "api_key")]
        credential_kind: String,
        /// Plain-text notes to encrypt into the item body
        #[arg(long)]
        notes: Option<String>,
        /// Tag. Repeat or comma-separate.
        #[arg(long = "tag", value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark the item as sensitive for server-side approval policy
        #[arg(long)]
        sensitive: bool,
    },
    /// Create a secure note item
    #[command(name = "create-note")]
    Note {
        /// Destination vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item title
        #[arg(long)]
        title: String,
        /// Note body. Prefer --body-stdin for multi-line input.
        #[arg(long)]
        body: Option<String>,
        /// Read note body from stdin
        #[arg(long)]
        body_stdin: bool,
        /// Tag. Repeat or comma-separate.
        #[arg(long = "tag", value_delimiter = ',')]
        tags: Vec<String>,
        /// Mark the item as sensitive for server-side approval policy
        #[arg(long)]
        sensitive: bool,
    },
    /// List items in a vault
    List {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
    },
    /// Get and decrypt a single item
    Get {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item id
        #[arg(long)]
        item_id: Uuid,
        /// Reveal decrypted secret content (off by default)
        #[arg(long)]
        reveal: bool,
    },
    /// Soft-delete (trash) an item
    Delete {
        #[arg(long)]
        vault_id: Option<Uuid>,
        #[arg(long)]
        item_id: Uuid,
    },
    /// Restore a trashed item
    Restore {
        #[arg(long)]
        vault_id: Option<Uuid>,
        #[arg(long)]
        item_id: Uuid,
    },
    /// Duplicate an item into another vault
    Duplicate {
        /// Source vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        #[arg(long)]
        item_id: Uuid,
        /// Destination vault id
        #[arg(long)]
        target_vault_id: Uuid,
    },
    /// Move an item into another vault
    Move {
        /// Source vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        #[arg(long)]
        item_id: Uuid,
        /// Destination vault id
        #[arg(long)]
        target_vault_id: Uuid,
    },
    /// Update fields on an existing item (only provided fields change)
    Update {
        #[arg(long)]
        vault_id: Option<Uuid>,
        #[arg(long)]
        item_id: Uuid,
        #[arg(long)]
        title: Option<String>,
        /// Replace tags. Repeat or comma-separate. Omit to keep existing tags.
        #[arg(long = "tag", value_delimiter = ',')]
        tags: Option<Vec<String>>,
        /// Set sensitivity (true/false). Omit to keep existing.
        #[arg(long)]
        sensitive: Option<bool>,
        #[arg(long, hide = true)]
        password: Option<String>,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        username: Option<String>,
        #[arg(long = "url", value_delimiter = ',')]
        urls: Option<Vec<String>>,
        #[arg(long, hide = true)]
        key: Option<String>,
        #[arg(long)]
        key_stdin: bool,
        #[arg(long)]
        credential_kind: Option<String>,
        #[arg(long)]
        body: Option<String>,
        #[arg(long)]
        body_stdin: bool,
        #[arg(long)]
        notes: Option<String>,
    },
}

#[derive(Subcommand)]
enum PasswordAttachmentAction {
    /// Encrypt and upload a file attachment to an item
    Upload {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item id
        #[arg(long)]
        item_id: Uuid,
        /// File path to upload
        #[arg(long)]
        path: std::path::PathBuf,
        /// Stored filename. Defaults to the file name from --path.
        #[arg(long)]
        filename: Option<String>,
        /// Stored content type. Defaults to application/octet-stream.
        #[arg(long)]
        content_type: Option<String>,
    },
    /// List decrypted attachment metadata for an item
    List {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item id
        #[arg(long)]
        item_id: Uuid,
    },
    /// Download and decrypt one attachment
    Download {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item id
        #[arg(long)]
        item_id: Uuid,
        /// Attachment id
        #[arg(long)]
        attachment_id: Uuid,
        /// Destination file path
        #[arg(long)]
        output: std::path::PathBuf,
    },
    /// Delete one attachment
    Delete {
        /// Vault id. Required when the account has multiple vaults.
        #[arg(long)]
        vault_id: Option<Uuid>,
        /// Item id
        #[arg(long)]
        item_id: Uuid,
        /// Attachment id
        #[arg(long)]
        attachment_id: Uuid,
    },
}

#[derive(Subcommand)]
enum OAuthAction {
    /// List available OAuth providers
    Providers,
    /// List your OAuth connections
    Connections,
    /// Connect to an OAuth provider
    Connect {
        /// Provider slug (e.g., "attio", "neon")
        provider_slug: String,
    },
    /// Disconnect an OAuth connection
    Disconnect {
        /// Connection ID, or provider slug if only one matching connection exists
        connection: String,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum AgentAction {
    /// List publishers in the store
    ListPublishers,
    /// Get details about a specific publisher
    GetPublisher {
        /// Publisher ID (UUID) or slug
        publisher: String,
    },
    /// Get generated skill.md guidance for a publisher
    #[command(name = "publisher-skill-doc", visible_alias = "skill-doc")]
    PublisherSkillDoc {
        /// Publisher ID (UUID) or slug
        publisher: String,
    },
    /// Get generated skill.md guidance for the core Seren API
    #[command(name = "api-skill-doc", visible_alias = "seren-skill-doc")]
    ApiSkillDoc,
    /// Get x402 deposit requirements (EIP-712 data for on-chain USDC deposit)
    GetDepositRequirements {
        /// Publisher ID (UUID) or slug
        publisher: String,
        /// Amount to deposit in USDC (e.g., "10.50")
        amount: String,
        /// Agent wallet address (0x...)
        agent_wallet: String,
    },
    /// Get supported payment protocols and configuration
    GetSupported,
    /// Create a new publisher in the store
    CreatePublisher {
        /// Organization ID (UUID) that owns this publisher
        #[arg(long)]
        organization_id: Uuid,
        /// Publisher name
        #[arg(long)]
        name: String,
        /// URL-friendly slug (unique identifier)
        #[arg(long)]
        slug: String,
        /// Contact email for notifications and support
        #[arg(long)]
        email: Option<String>,
        /// Wallet address for receiving payments (0x...)
        #[arg(long)]
        wallet_address: String,
        /// Network ID for the wallet (e.g., "base-sepolia", "base-mainnet")
        #[arg(long)]
        wallet_network_id: String,
        /// Publisher category: "database", "integration", or "compute"
        #[arg(long)]
        publisher_category: String,
        /// Database type: "serendb", "neon", "supabase", or "mongodb" (for database category)
        #[arg(long)]
        database_type: Option<String>,
        /// Integration type: "api" or "mcp" (for integration category)
        #[arg(long)]
        integration_type: Option<String>,
        /// Publisher description
        #[arg(long)]
        description: Option<String>,
        /// API URL for API-type publishers (also used for MongoDB Atlas Data API publishers)
        #[arg(long)]
        api_url: Option<String>,
        /// MCP server endpoint URL for MCP-type publishers
        #[arg(long)]
        mcp_endpoint: Option<String>,
        /// Project ID for SerenDB publishers
        #[arg(long)]
        project_id: Option<Uuid>,
        /// Branch ID for SerenDB publishers
        #[arg(long)]
        branch_id: Option<Uuid>,
        /// Database name for SerenDB publishers
        #[arg(long)]
        database_name: Option<String>,
        /// Base price per 1000 rows (e.g., "0.001")
        #[arg(long)]
        base_price_per_1000_rows: Option<String>,
        /// Billing model (x402_per_request, prepaid_credits, x402_passthrough, pay_per_use)
        #[arg(long)]
        billing_model: Option<String>,
        /// Dot-separated path to upstream cost in response body (required for pay_per_use billing).
        /// Example: "usage.cost" extracts the cost from {"usage": {"cost": 0.0023}}
        #[arg(long)]
        upstream_cost_response_path: Option<String>,
        /// Database connection string (e.g., "postgresql://user:pass@host/db") - for external SQL databases (Neon/Supabase)
        #[arg(long)]
        connection_string: Option<String>,
        /// Upstream API key (encrypted). Required for MongoDB Atlas Data API publishers.
        #[arg(long)]
        upstream_api_key: Option<String>,
        /// Generic database provider config JSON (advanced).
        /// Neon/Supabase example: '{"connection_string":"postgresql://..."}'
        /// MongoDB Atlas example: '{"default_data_source":"MyCluster","max_limit":200,"read_only":true}'
        #[arg(long)]
        database_config_json: Option<String>,
        /// Upstream auth mode: "static", "jwt", "oauth2_cc", or "passthrough" (default: static)
        #[arg(long)]
        auth_type: Option<String>,
        /// Whitelist of agent-provided headers allowed to pass through to upstream.
        /// Only relevant for auth_type="passthrough".
        #[arg(long = "allowed-passthrough-header", value_delimiter = ',')]
        allowed_passthrough_headers: Vec<String>,
        /// OAuth2 token endpoint URL for Client Credentials flow (required when auth_type=oauth2_cc)
        #[arg(long)]
        oauth2_token_url: Option<String>,
        /// OAuth2 client ID for Client Credentials flow (required when auth_type=oauth2_cc)
        #[arg(long)]
        oauth2_client_id: Option<String>,
        /// OAuth2 client secret for Client Credentials flow (required when auth_type=oauth2_cc)
        #[arg(long)]
        oauth2_client_secret: Option<String>,
        /// OAuth2 scopes for Client Credentials flow (comma-separated)
        #[arg(long = "oauth2-scope", value_delimiter = ',')]
        oauth2_scopes: Option<Vec<String>>,
        /// Human-readable use cases for this publisher (comma-separated)
        #[arg(long = "use-case", value_delimiter = ',')]
        use_cases: Option<Vec<String>>,
    },
    /// Execute a paid database query using your SerenBucks balance
    ExecuteQuery {
        /// Publisher ID (UUID) or slug
        #[arg(long)]
        publisher: String,
        /// Query payload to execute (SQL string for SQL publishers, JSON string for MongoDB publishers)
        #[arg(long)]
        query: String,
        /// Database name (optional, uses publisher default)
        #[arg(long)]
        database: Option<String>,
    },
    /// Get your SerenBucks balance
    GetPrepaidBalance,
    /// Deposit SerenBucks (fiat via Stripe)
    CreatePrepaidDeposit {
        /// Amount in USD to deposit (e.g., 10.00)
        #[arg(long)]
        amount: UsdCents,
    },
    /// Estimate the cost of a query against a publisher
    EstimateQueryCost {
        /// Publisher ID (UUID) or slug
        #[arg(long)]
        publisher: String,
        /// Query payload to estimate (SQL string for SQL publishers, JSON string for MongoDB publishers)
        #[arg(long)]
        query: String,
    },
    /// Get wallet transaction history (deposits, charges, refunds)
    GetTransactionHistory {
        /// Maximum number of transactions to return (default 50, max 100)
        #[arg(long)]
        limit: Option<i64>,
        /// Offset for pagination
        #[arg(long)]
        offset: Option<i64>,
    },
    /// Preview a SerenBucks transfer before sending
    PreviewTransfer {
        /// Recipient email address
        #[arg(long)]
        recipient_email: String,
        /// Amount in USD to send (e.g., 10.00)
        #[arg(long)]
        amount: UsdCents,
        /// Optional memo shown to the recipient
        #[arg(long)]
        memo: Option<String>,
    },
    /// Send SerenBucks to another email address
    SendTransfer {
        /// Recipient email address
        #[arg(long)]
        recipient_email: String,
        /// Amount in USD to send (e.g., 10.00)
        #[arg(long)]
        amount: UsdCents,
        /// Optional memo shown to the recipient
        #[arg(long)]
        memo: Option<String>,
        /// Idempotency key for safe retries. Reuse the same key when retrying.
        #[arg(long)]
        idempotency_key: String,
    },
    /// List SerenBucks transfers
    ListTransfers {
        /// Direction filter: sent, received, or all
        #[arg(long)]
        direction: Option<String>,
        /// Status filter, such as settled, pending, claimed, recalled, or expired
        #[arg(long)]
        status: Option<String>,
        /// Cursor from a previous response
        #[arg(long)]
        cursor: Option<String>,
        /// Maximum number of transfers to return (default 50)
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Claim a pending SerenBucks transfer invite
    ClaimTransfer {
        /// Raw invite token from the claim link
        #[arg(long)]
        token: String,
    },
    /// Recall a pending outbound SerenBucks transfer
    RecallTransfer {
        /// Pending transfer ID
        #[arg(long)]
        pending_transfer_id: Uuid,
    },

    // =========================================================================
    // Agent Template Commands
    // =========================================================================
    /// List available agent templates in the catalog
    ListTemplates {
        /// Filter by programming language (python, typescript, javascript)
        #[arg(long)]
        language: Option<String>,
        /// Filter to verified templates only
        #[arg(long)]
        verified_only: Option<bool>,
        /// Search templates by name or description
        #[arg(long)]
        search: Option<String>,
        /// Maximum number of templates to return
        #[arg(long)]
        limit: Option<i64>,
    },
    /// Get details about a specific agent template
    GetTemplate {
        /// Template slug (e.g., "web-researcher")
        slug: String,
    },
    /// Publish a new agent template
    PublishTemplate {
        /// Template display name
        #[arg(long)]
        name: String,
        /// URL-friendly slug (unique identifier)
        #[arg(long)]
        slug: String,
        /// Path to the code file
        #[arg(long)]
        code: String,
        /// Programming language (python, typescript, javascript)
        #[arg(long)]
        language: String,
        /// Price per invocation in USD (e.g., "0.05")
        #[arg(long)]
        price: String,
        /// Description of what the template does
        #[arg(long)]
        description: Option<String>,
        /// Dependencies (e.g., "openai>=1.0.0,requests")
        #[arg(long)]
        dependencies: Option<String>,
        /// Preferred compute backend (e.g., "daytona", "modal")
        #[arg(long)]
        compute_backend: Option<String>,
    },
    /// Invoke an agent template (requires SerenBucks balance)
    InvokeTemplate {
        /// Template slug (e.g., "web-researcher")
        #[arg(long)]
        slug: String,
        /// Input JSON to pass to the template
        #[arg(long)]
        input: String,
    },
    /// Run an agent task via the unified publisher proxy
    RunCloud {
        /// Publisher slug of the agent to invoke
        #[arg(long)]
        publisher: String,
        /// Input message (text or JSON)
        #[arg(long)]
        message: String,
    },
    /// Run an agent locally via A2A protocol (direct connection, no billing)
    RunLocal {
        /// A2A agent endpoint URL (e.g., http://localhost:8000)
        #[arg(long)]
        endpoint: String,
        /// Input message (text or JSON)
        #[arg(long)]
        message: String,
        /// Use streaming mode (SSE) instead of blocking
        #[arg(long, short = 's')]
        stream: bool,
    },
    // =========================================================================
    // Cloud Deployment Commands
    // =========================================================================
    /// Package a directory of instruction files and deploy it as a dev-namespace
    /// agent. Streams logs until Ctrl-C, then deletes the deployment.
    Dev {
        /// Directory containing SKILL.md and optional companion instruction files.
        path: String,
        /// Optional display name (defaults to the directory name).
        #[arg(long)]
        name: Option<String>,
        /// Optional agent slug; the result is always prefixed with `dev-`.
        #[arg(long)]
        agent_slug: Option<String>,
        /// Build and print the AgentSpec draft without contacting the API.
        #[arg(long)]
        dry_run: bool,
    },
    /// Deploy a skill to Seren Cloud
    Deploy {
        /// Path to a skill directory or SKILL.md (must contain scripts/)
        path: String,
        /// Deployment publisher slug (`seren-cloud` for direct bundle/runtime deploys)
        #[arg(long, default_value = "seren-cloud")]
        publisher: String,
        /// Deployment name
        #[arg(long)]
        name: Option<String>,
        /// Optional reusable execution environment ID (AWS container backend only)
        #[arg(long)]
        environment_id: Option<Uuid>,
        /// Deployment mode: "always-on" or "cron"
        #[arg(long, default_value = "always-on")]
        mode: String,
        /// Cron schedule expression (required if mode is "cron")
        #[arg(long)]
        cron_schedule: Option<String>,
        /// Cron timezone as an IANA name (defaults to UTC)
        #[arg(long)]
        cron_timezone: Option<String>,
        /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
        #[arg(long)]
        eval_gate_set_id: Option<Uuid>,
        /// Freshness window in seconds for the eval gate (required with --eval-gate-set-id)
        #[arg(long)]
        eval_gate_max_age_seconds: Option<i32>,
        /// Optional compute backend override (auto, aws_container, cloudflare_worker, or daytona). Omit for AWS-first auto-routing.
        #[arg(long)]
        compute_backend: Option<String>,
        /// Optional runtime override (auto, python, javascript, typescript, rust, rust_wasm_adk). Omit to infer from the bundle. `rust` covers native Linux binaries and shell scripts; `rust_wasm_adk` covers standalone WASI .wasm modules on AWS.
        #[arg(long)]
        runtime_kind: Option<String>,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
        /// Path to an orchestration JSON file (defaults to <skill>/orchestration.json if present)
        #[arg(long)]
        orchestration_config: Option<String>,
    },
    /// Deploy a managed prompt-based agent through seren-agent
    DeployPrompt {
        /// Deployment display name
        #[arg(long)]
        name: String,
        /// Optional agent slug override (defaults to a slugified form of --name)
        #[arg(long)]
        agent_slug: Option<String>,
        /// Deployment mode: "always-on" or "cron"
        #[arg(long, default_value = "always-on")]
        mode: String,
        /// Cron schedule expression (required if mode is "cron")
        #[arg(long)]
        cron_schedule: Option<String>,
        /// Cron timezone as an IANA name (defaults to UTC)
        #[arg(long)]
        cron_timezone: Option<String>,
        /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
        #[arg(long)]
        eval_gate_set_id: Option<Uuid>,
        /// Freshness window in seconds for the eval gate (required with --eval-gate-set-id)
        #[arg(long)]
        eval_gate_max_age_seconds: Option<i32>,
        /// Optional compute backend override (auto, aws_container, cloudflare_worker, or daytona). Omit for AWS-first managed routing.
        #[arg(long)]
        compute_backend: Option<String>,
        /// Agent style. Use research_monitor for read-oriented live-data work or workflow_agent for action-oriented workflows.
        #[arg(long, visible_alias = "agent-style")]
        template: Option<String>,
        /// Capability list. Use live_data for publisher-backed data access, publisher_actions for write-capable publisher actions, and database for direct SerenDB queries.
        #[arg(
            long = "tool-preset",
            visible_alias = "capability",
            value_delimiter = ','
        )]
        tool_presets: Vec<String>,
        /// Access mode (read_only or allow_mutations).
        #[arg(long, visible_alias = "access-mode")]
        approval_policy: Option<String>,
        /// Performance profile (fast, balanced, or deep).
        #[arg(long, visible_alias = "performance-profile")]
        model_policy: Option<String>,
        /// Allow remote A2A delegation to these hostnames or origins. Repeat or use commas.
        #[arg(long = "allow-remote-agent-origin", value_delimiter = ',')]
        allowed_remote_agent_origins: Vec<String>,
        /// Agent prompt written in plain language. Required unless provided by --agent-config.
        #[arg(long)]
        prompt: Option<String>,
        /// Optional model ID. Omit to use the platform default.
        #[arg(long = "model-id")]
        model_id: Option<String>,
        /// Optional visibility mode (open or opaque)
        #[arg(long)]
        visibility: Option<String>,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
        /// Path to a managed agent JSON config for advanced tuning
        #[arg(long)]
        agent_config: Option<String>,
        /// JSON capability_policy override for managed runtime capabilities
        #[arg(long)]
        capability_policy: Option<String>,
        /// Path to a JSON capability_policy override
        #[arg(long)]
        capability_policy_file: Option<String>,
    },
    /// Use seren-private-models and related seren-agent model discovery
    PrivateModels {
        #[command(subcommand)]
        action: PrivateModelsAction,
    },
    /// Inspect seren-agent publisher capabilities
    ManagedCapabilities,
    /// List deployments through the seren-agent publisher
    ManagedList,
    /// Get health for managed seren-agent deployments
    ManagedHealth,
    /// Run an unsaved seren-agent managed draft once
    ManagedTestRun {
        /// JSON body matching AgentSpec
        #[arg(long)]
        body: String,
    },
    /// Get the resolved managed seren-agent deployment detail
    ManagedGet {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Get a managed-agent resource summary for a deployment
    ManagedDeploymentResources {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// List tools visible to a managed seren-agent deployment
    ManagedDeploymentTools {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Optional case-insensitive search over tool names, descriptions, and sources
        #[arg(long)]
        q: Option<String>,
    },
    /// Describe one tool visible to a managed seren-agent deployment
    ManagedDeploymentTool {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Tool name
        tool_name: String,
    },
    /// List resolved tool groups for a managed seren-agent deployment
    ManagedDeploymentToolGroups {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Get recent managed-agent activity for a deployment
    ManagedDeploymentActivity {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Max run activity entries to return
        #[arg(long, default_value_t = 20)]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Get health for a managed seren-agent deployment
    ManagedDeploymentHealth {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// List immutable revision snapshots for a managed seren-agent deployment
    ManagedRevisions {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Start a managed seren-agent deployment
    ManagedStart {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Stop a managed seren-agent deployment
    ManagedStop {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Delete a managed seren-agent deployment
    ManagedDelete {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Preview rolling a managed seren-agent deployment back to a prior revision
    ManagedRollbackPreview {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Revision ID (UUID)
        revision_id: Uuid,
    },
    /// Roll a managed seren-agent deployment back to a prior revision
    ManagedRollback {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Revision ID (UUID)
        revision_id: Uuid,
    },
    /// Preview an update to an existing managed seren-agent deployment
    ManagedPreview {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Updated display name
        #[arg(long)]
        name: Option<String>,
        /// Updated stable agent slug
        #[arg(long)]
        agent_slug: Option<String>,
        /// Updated cron schedule (cron deployments only)
        #[arg(long)]
        cron_schedule: Option<String>,
        /// Updated cron timezone (cron deployments only)
        #[arg(long)]
        cron_timezone: Option<String>,
        /// Updated eval set ID that gates execution
        #[arg(long)]
        eval_gate_set_id: Option<Uuid>,
        /// Updated eval gate freshness window in seconds
        #[arg(long)]
        eval_gate_max_age_seconds: Option<i32>,
        /// Clear the eval gate entirely
        #[arg(long)]
        clear_eval_gate: bool,
        /// Agent style override
        #[arg(long, visible_alias = "agent-style")]
        template: Option<String>,
        /// Capability list
        #[arg(
            long = "tool-preset",
            visible_alias = "capability",
            value_delimiter = ','
        )]
        tool_presets: Vec<String>,
        /// Access mode (read_only or allow_mutations)
        #[arg(long, visible_alias = "access-mode")]
        approval_policy: Option<String>,
        /// Performance profile (fast, balanced, or deep)
        #[arg(long, visible_alias = "performance-profile")]
        model_policy: Option<String>,
        /// Allow remote A2A delegation to these hostnames or origins. Repeat or use commas.
        #[arg(long = "allow-remote-agent-origin", value_delimiter = ',')]
        allowed_remote_agent_origins: Vec<String>,
        /// Updated agent prompt
        #[arg(long)]
        prompt: Option<String>,
        /// Updated model ID
        #[arg(long = "model-id")]
        model_id: Option<String>,
        /// Optional visibility mode (open or opaque)
        #[arg(long)]
        visibility: Option<String>,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
        /// Path to a managed agent JSON config for advanced tuning
        #[arg(long)]
        agent_config: Option<String>,
        /// JSON capability_policy override for managed runtime capabilities
        #[arg(long)]
        capability_policy: Option<String>,
        /// Path to a JSON capability_policy override
        #[arg(long)]
        capability_policy_file: Option<String>,
        /// Clear the capability policy entirely
        #[arg(long)]
        clear_capability_policy: bool,
    },
    /// Update an existing managed seren-agent deployment
    ManagedUpdate {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Updated display name
        #[arg(long)]
        name: Option<String>,
        /// Updated stable agent slug
        #[arg(long)]
        agent_slug: Option<String>,
        /// Updated cron schedule (cron deployments only)
        #[arg(long)]
        cron_schedule: Option<String>,
        /// Updated cron timezone (cron deployments only)
        #[arg(long)]
        cron_timezone: Option<String>,
        /// Updated eval set ID that gates execution
        #[arg(long)]
        eval_gate_set_id: Option<Uuid>,
        /// Updated eval gate freshness window in seconds
        #[arg(long)]
        eval_gate_max_age_seconds: Option<i32>,
        /// Clear the eval gate entirely
        #[arg(long)]
        clear_eval_gate: bool,
        /// Agent style override
        #[arg(long, visible_alias = "agent-style")]
        template: Option<String>,
        /// Capability list
        #[arg(
            long = "tool-preset",
            visible_alias = "capability",
            value_delimiter = ','
        )]
        tool_presets: Vec<String>,
        /// Access mode (read_only or allow_mutations)
        #[arg(long, visible_alias = "access-mode")]
        approval_policy: Option<String>,
        /// Performance profile (fast, balanced, or deep)
        #[arg(long, visible_alias = "performance-profile")]
        model_policy: Option<String>,
        /// Allow remote A2A delegation to these hostnames or origins. Repeat or use commas.
        #[arg(long = "allow-remote-agent-origin", value_delimiter = ',')]
        allowed_remote_agent_origins: Vec<String>,
        /// Updated agent prompt
        #[arg(long)]
        prompt: Option<String>,
        /// Updated model ID
        #[arg(long = "model-id")]
        model_id: Option<String>,
        /// Optional visibility mode (open or opaque)
        #[arg(long)]
        visibility: Option<String>,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
        /// Path to a managed agent JSON config for advanced tuning
        #[arg(long)]
        agent_config: Option<String>,
        /// JSON capability_policy override for managed runtime capabilities
        #[arg(long)]
        capability_policy: Option<String>,
        /// Path to a JSON capability_policy override
        #[arg(long)]
        capability_policy_file: Option<String>,
        /// Clear the capability policy entirely
        #[arg(long)]
        clear_capability_policy: bool,
    },
    /// Manage cloud deployments, environments, runs, approvals, and evals
    Cloud {
        #[command(subcommand)]
        action: Box<AgentCloudAction>,
    },
    // =========================================================================
    // Agent Task Commands
    // =========================================================================
    /// List agent tasks for an organization
    TasksList {
        /// Organization ID
        #[arg(long)]
        org_id: String,
        /// Maximum tasks to return
        #[arg(long, default_value = "20")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Get details of a specific agent task
    TasksGet {
        /// Organization ID
        #[arg(long)]
        org_id: String,
        /// Task ID (UUID)
        task_id: String,
        /// Follow task progress via SSE stream (like tail -f)
        #[arg(long, short = 'f')]
        follow: bool,
    },
    /// Cancel a running agent task
    TasksCancel {
        /// Organization ID
        #[arg(long)]
        org_id: String,
        /// Task ID (UUID)
        task_id: String,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the local stdio MCP server
    #[command(name = "start")]
    Start,
    /// Start the streamable HTTP MCP server with static bearer auth
    #[command(name = "start:http")]
    StartHttp,
    /// Start the hosted MCP server with OAuth 2.1
    #[command(name = "start:server", alias = "start:oauth")]
    StartServer,
}

#[derive(Subcommand)]
enum PrivateModelsAction {
    /// List models from the seren-private-models publisher
    List,
    /// List the seren-agent private model catalog
    Catalog {
        /// Optional private model region for live discovery
        #[arg(long)]
        region: Option<String>,
    },
    /// Send one chat completion request to seren-private-models
    Chat {
        /// Model ID to use
        #[arg(long)]
        model: Option<String>,
        /// User message. Mutually exclusive with --messages-json
        #[arg(long)]
        message: Option<String>,
        /// Full OpenAI-compatible messages JSON array
        #[arg(long)]
        messages_json: Option<String>,
        /// Sampling temperature
        #[arg(long)]
        temperature: Option<f32>,
        /// Maximum output tokens
        #[arg(long)]
        max_tokens: Option<i32>,
        /// Top-p sampling value
        #[arg(long)]
        top_p: Option<f32>,
        /// Top-k sampling value
        #[arg(long)]
        top_k: Option<i32>,
        /// JSON object schema for structured responses
        #[arg(long)]
        response_schema_json: Option<String>,
        /// JSON array of tool definitions
        #[arg(long)]
        tools_json: Option<String>,
    },
}

#[derive(Subcommand)]
enum AgentCloudAction {
    /// Manage cloud deployments
    Deployment {
        #[command(subcommand)]
        action: CloudDeploymentAction,
    },
    /// Inspect tamper-evident cloud audit logs
    Audit {
        #[command(subcommand)]
        action: CloudAuditAction,
    },
    /// Manage reusable cloud deployment environments
    Environment {
        #[command(subcommand)]
        action: CloudEnvironmentAction,
    },
    /// Show organization-wide cloud deployment counts, recent runs, and pending approvals
    Overview {
        /// Maximum recent runs to include
        #[arg(long, default_value = "8")]
        runs_limit: i64,
        /// Maximum pending-approval runs to include
        #[arg(long, default_value = "8")]
        approvals_limit: i64,
    },
    /// Manage individual cloud runs
    Run {
        #[command(subcommand)]
        action: CloudRunAction,
    },
    /// Inspect durable employee conversations for a deployment
    Conversation {
        #[command(subcommand)]
        action: CloudConversationAction,
    },
    /// Manage agent-owned future run schedules
    Schedule {
        #[command(subcommand)]
        action: CloudScheduleAction,
    },
    /// List run activity across one deployment or the whole organization
    Runs {
        #[command(subcommand)]
        action: CloudRunsAction,
    },
    /// List pending approval queues globally or for a deployment
    Approvals {
        #[command(subcommand)]
        action: CloudApprovalsAction,
    },
    /// Manage cloud eval sets, cases, runs, and results
    Eval {
        #[command(subcommand)]
        action: CloudEvalAction,
    },
}

#[derive(Subcommand)]
enum CloudDeploymentAction {
    /// List cloud agent deployments
    List,
    /// Inspect uploaded deployment bundle metadata
    Bundle {
        #[command(subcommand)]
        action: CloudDeploymentBundleAction,
    },
    /// Get status of a cloud agent deployment
    Status {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Start a stopped always-on cloud agent
    Start {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Stop a running always-on cloud agent
    Stop {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Get deployment spend summary
    Spend {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// List audit entries scoped to a deployment
    Audit {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Filter by exact audit action
        #[arg(long)]
        action: Option<String>,
        /// Maximum audit entries to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
        /// Case-insensitive search query
        #[arg(long)]
        q: Option<String>,
    },
    /// Destroy a cloud agent deployment
    Destroy {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Update config and/or secrets for a cloud agent without redeploying
    UpdateConfig {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
        /// Path to alert_policy JSON
        #[arg(long)]
        alert_policy: Option<String>,
        /// Remove the deployment alert policy
        #[arg(long, default_value_t = false)]
        clear_alert_policy: bool,
        /// Path to network_policy JSON
        #[arg(long)]
        network_policy: Option<String>,
        /// Remove the deployment network policy
        #[arg(long, default_value_t = false)]
        clear_network_policy: bool,
        /// Optional eval set ID that must have a fresh passing verdict before runs are allowed
        #[arg(long)]
        eval_gate_set_id: Option<Uuid>,
        /// Freshness window in seconds for the eval gate (required with --eval-gate-set-id)
        #[arg(long)]
        eval_gate_max_age_seconds: Option<i32>,
        /// Remove the eval gate from the deployment
        #[arg(long, default_value_t = false)]
        clear_eval_gate: bool,
    },
}

#[derive(Subcommand)]
enum CloudDeploymentBundleAction {
    /// Get deployment bundle metadata without downloading raw content
    Get {
        /// Deployment bundle ID (UUID)
        bundle_id: Uuid,
    },
}

#[derive(Subcommand)]
enum CloudAuditAction {
    /// List tamper-evident audit entries
    List {
        /// Filter by exact audit action
        #[arg(long)]
        action: Option<String>,
        /// Maximum audit entries to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
        /// Case-insensitive search query
        #[arg(long)]
        q: Option<String>,
    },
    /// Get one audit entry
    Get {
        /// Audit entry ID (UUID)
        entry_id: Uuid,
    },
    /// Verify the audit hash chain
    Verify {
        /// Maximum audit entries to verify
        #[arg(long)]
        limit: Option<i64>,
    },
}

#[derive(Subcommand)]
enum CloudEnvironmentAction {
    /// List reusable cloud deployment environments
    List,
    /// Get a reusable cloud deployment environment
    Get {
        /// Environment ID (UUID)
        environment_id: Uuid,
    },
    /// Create a reusable cloud deployment environment
    Create {
        /// Environment display name
        #[arg(long)]
        name: String,
        /// Docker image reference
        #[arg(long)]
        docker_image: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Setup command to run before agent start (repeatable)
        #[arg(long = "setup-command")]
        setup_commands: Vec<String>,
        /// Mark as default environment for the organization
        #[arg(long, default_value_t = false)]
        is_default: bool,
    },
    /// Update a reusable cloud deployment environment
    Update {
        /// Environment ID (UUID)
        environment_id: Uuid,
        /// New environment name
        #[arg(long)]
        name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// New Docker image reference
        #[arg(long)]
        docker_image: Option<String>,
        /// Setup command list replacement (repeatable)
        #[arg(long = "setup-command")]
        setup_commands: Vec<String>,
        /// Clear setup commands to an empty list
        #[arg(long)]
        clear_setup_commands: bool,
        /// Set/unset default environment
        #[arg(long)]
        is_default: Option<bool>,
    },
    /// Delete a reusable cloud deployment environment
    Delete {
        /// Environment ID (UUID)
        environment_id: Uuid,
    },
}

#[derive(Subcommand)]
enum CloudRunAction {
    /// Trigger a one-shot run for a cloud deployment
    Start {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Optional run message payload (recommended for llm orchestrated deployments)
        #[arg(long)]
        message: Option<String>,
        /// Optional raw JSON request body to forward to the deployment
        #[arg(long = "json")]
        json_body: Option<String>,
        /// Optional path to a JSON file to forward as the request body
        #[arg(long = "json-file")]
        json_file: Option<String>,
        /// Optional run identifier (useful for resumable orchestrations)
        #[arg(long)]
        run_id: Option<String>,
        /// Request async execution for always_on deployments (returns run_id + execution_id)
        #[arg(long = "async")]
        async_run: bool,
    },
    /// Get details of a run by ID; provide --deployment-id to use deployment-scoped lookup
    Get {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// Compare replay/eval captures for two runs by run ID
    Compare {
        /// Baseline run event ID (UUID)
        baseline_run_id: Uuid,
        /// Candidate run event ID (UUID)
        candidate_run_id: Uuid,
    },
    /// List artifacts emitted by a run
    Artifacts {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// List audit entries scoped to a run
    Audit {
        /// Run event ID (UUID)
        run_id: Uuid,
        /// Filter by exact audit action
        #[arg(long)]
        action: Option<String>,
        /// Maximum audit entries to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
        /// Case-insensitive search query
        #[arg(long)]
        q: Option<String>,
    },
    /// List eval records linked to a run
    Evals {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// List structured output events emitted by a run
    Events {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
        /// Filter by tool/output item ID
        #[arg(long)]
        item_id: Option<String>,
        /// Filter by event kind
        #[arg(long)]
        kind: Option<String>,
        /// Maximum events to return
        #[arg(long, default_value = "100")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
        /// Case-insensitive search query
        #[arg(long)]
        q: Option<String>,
    },
    /// Stream run events over SSE, with optional Last-Event-ID resume
    Stream {
        /// Deployment ID (UUID) for deployment-scoped stream path
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
        /// Optional Last-Event-ID header for SSE replay/resume
        #[arg(long)]
        last_event_id: Option<String>,
    },
    /// Get the current live state for a run; provide --deployment-id for deployment-scoped lookup
    State {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// Get the latest pending approvals for a run; optionally scope by deployment
    PendingApprovals {
        /// Deployment ID (UUID) for deployment-scoped lookup
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// Approve all current pending approvals for a run and resume it
    Approve {
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// Reject all current pending approvals for a run and resume it
    Reject {
        /// Run event ID (UUID)
        run_id: Uuid,
    },
    /// Cancel a queued/running run; provide --deployment-id for deployment-scoped cancellation
    Cancel {
        /// Deployment ID (UUID) for deployment-scoped cancellation
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Run event ID (UUID)
        run_id: Uuid,
    },
}

#[derive(Subcommand)]
enum CloudConversationAction {
    /// List durable conversations for a cloud agent deployment
    List {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Maximum conversations to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Opaque keyset cursor returned by a previous page
        #[arg(long)]
        cursor: Option<String>,
    },
    /// List messages for one durable conversation
    Messages {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Durable conversation ID
        conversation_id: String,
        /// Maximum messages to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Opaque keyset cursor returned by a previous page
        #[arg(long)]
        cursor: Option<String>,
        /// Message page order: asc or desc
        #[arg(long)]
        order: Option<String>,
        /// Include full run records for run-backed messages
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        include_run: Option<bool>,
    },
}

#[derive(Subcommand)]
enum CloudScheduleAction {
    /// List agent-owned future run schedules for a deployment
    List {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Maximum schedules to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Create or update an agent-owned future run schedule
    Create {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Stable idempotency key for this schedule
        #[arg(long)]
        schedule_key: Option<String>,
        /// User-facing message payload for the future run
        #[arg(long)]
        message: Option<String>,
        /// Optional JSON payload for the future run
        #[arg(long = "payload")]
        payload_json: Option<String>,
        /// Path to an optional JSON payload file
        #[arg(long = "payload-file")]
        payload_file: Option<String>,
        /// Durable conversation ID to continue when the schedule fires
        #[arg(long)]
        conversation_id: Option<String>,
        /// RFC3339 timestamp for a one-shot future run
        #[arg(long)]
        run_at: Option<String>,
        /// Relative delay in seconds for a one-shot future run
        #[arg(long)]
        delay_seconds: Option<i64>,
        /// Cron expression for a recurring future run
        #[arg(long)]
        cron: Option<String>,
        /// Timezone for cron schedules
        #[arg(long)]
        timezone: Option<String>,
        /// Maximum worker retry attempts
        #[arg(long)]
        max_attempts: Option<i32>,
    },
    /// Cancel an active agent-owned future run schedule
    Cancel {
        /// Deployment ID (UUID)
        #[arg(long)]
        deployment_id: Uuid,
        /// Schedule ID (UUID)
        schedule_id: Uuid,
    },
}

#[derive(Subcommand)]
enum CloudRunsAction {
    /// List run activity across one deployment or the whole organization
    List {
        /// Deployment ID (UUID) to scope results to one deployment
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Maximum runs to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
        /// Filter by run status (repeat or comma-separate)
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        status: Vec<String>,
        /// Filter by compute backend (aws_container, cloudflare_worker, daytona)
        #[arg(long)]
        compute_backend: Option<String>,
        /// Filter by run source (api, cli, scheduler, ui, system, unknown)
        #[arg(long)]
        source: Option<String>,
        /// Only include runs that emitted artifacts
        #[arg(long)]
        has_artifacts: bool,
        /// Filter runs with started_at >= RFC3339 timestamp
        #[arg(long)]
        started_after: Option<String>,
        /// Filter runs with started_at <= RFC3339 timestamp
        #[arg(long)]
        started_before: Option<String>,
        /// Search query across execution ID/status/output/metadata
        #[arg(long)]
        q: Option<String>,
    },
}

#[derive(Subcommand)]
enum CloudApprovalsAction {
    /// List runs currently awaiting approval globally or for a deployment
    List {
        /// Deployment ID (UUID) to scope results to one deployment
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Maximum runs to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
}

#[derive(Subcommand)]
enum CloudEvalAction {
    /// Manage durable eval sets
    Set {
        #[command(subcommand)]
        action: CloudEvalSetAction,
    },
    /// Manage eval cases within a set
    Case {
        #[command(subcommand)]
        action: CloudEvalCaseAction,
    },
    /// Manage eval runs within a set
    Run {
        #[command(subcommand)]
        action: CloudEvalRunAction,
    },
    /// Fetch a single per-case result from an eval run
    Result {
        #[command(subcommand)]
        action: CloudEvalResultAction,
    },
}

#[derive(Subcommand)]
enum CloudEvalSetAction {
    /// List durable eval sets for seren-cloud runs
    List {
        /// Optional deployment scope (UUID)
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Maximum eval sets to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Create a durable eval set for seren-cloud runs
    Create {
        /// Eval set name
        #[arg(long)]
        name: String,
        /// Optional deployment scope (UUID)
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Optional eval criteria JSON object
        #[arg(long = "criteria")]
        criteria_json: Option<String>,
        /// Optional path to an eval criteria JSON file
        #[arg(long = "criteria-file")]
        criteria_file: Option<String>,
        /// Optional metadata JSON object
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON file
        #[arg(long = "metadata-file")]
        metadata_file: Option<String>,
        /// Optional cron schedule for automatically running the eval set
        #[arg(long = "schedule-cron")]
        schedule_cron: Option<String>,
        /// Optional timezone for the scheduled eval cron expression
        #[arg(long = "schedule-timezone")]
        schedule_timezone: Option<String>,
    },
    /// Get a single eval set
    Get {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
    },
    /// Update an eval set
    Update {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Updated eval set name
        #[arg(long)]
        name: Option<String>,
        /// Updated deployment scope (UUID)
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Remove deployment scoping from the eval set
        #[arg(long)]
        clear_deployment: bool,
        /// Updated description (pass empty string to clear)
        #[arg(long)]
        description: Option<String>,
        /// Updated eval criteria JSON object
        #[arg(long = "criteria")]
        criteria_json: Option<String>,
        /// Optional path to an eval criteria JSON file
        #[arg(long = "criteria-file")]
        criteria_file: Option<String>,
        /// Updated metadata JSON object
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON file
        #[arg(long = "metadata-file")]
        metadata_file: Option<String>,
        /// Updated cron schedule for automatically running the eval set
        #[arg(long = "schedule-cron")]
        schedule_cron: Option<String>,
        /// Updated timezone for the scheduled eval cron expression
        #[arg(long = "schedule-timezone")]
        schedule_timezone: Option<String>,
        /// Disable scheduled execution for this eval set
        #[arg(long)]
        clear_schedule: bool,
    },
}

#[derive(Subcommand)]
enum CloudEvalCaseAction {
    /// List eval cases within a set
    List {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Maximum eval cases to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Get a single eval case within a set
    Get {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Eval case ID (UUID)
        case_id: Uuid,
    },
    /// Promote a terminal run into a durable eval case
    FromRun {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Source run ID (UUID)
        run_id: Uuid,
        /// Optional eval case name override
        #[arg(long)]
        name: Option<String>,
        /// Optional metadata JSON object merged onto the generated case metadata
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON file
        #[arg(long = "metadata-file")]
        metadata_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum CloudEvalRunAction {
    /// Execute an eval set against a deployment
    Create {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Optional deployment override (required when the eval set is not deployment-scoped)
        #[arg(long)]
        deployment_id: Option<Uuid>,
        /// Optional metadata JSON object
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON file
        #[arg(long = "metadata-file")]
        metadata_file: Option<String>,
    },
    /// List eval runs within a set
    List {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Maximum eval runs to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
    /// Get a single eval run within a set
    Get {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Eval run ID (UUID)
        eval_run_id: Uuid,
    },
    /// List per-case results for an eval run
    Results {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Eval run ID (UUID)
        eval_run_id: Uuid,
        /// Maximum case results to return
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: i64,
    },
}

#[derive(Subcommand)]
enum CloudEvalResultAction {
    /// Get a single per-case result from an eval run
    Get {
        /// Eval set ID (UUID)
        eval_set_id: Uuid,
        /// Eval run ID (UUID)
        eval_run_id: Uuid,
        /// Eval case ID (UUID)
        case_id: Uuid,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Login to Seren (via OAuth or API key)
    Login,
    /// Show authentication status
    Status,
    /// Logout and remove stored credentials
    Logout,
}

#[derive(Subcommand)]
enum OrgAction {
    /// List members in an organization
    Members {
        /// Organization ID
        #[arg(long)]
        org_id: String,
    },
    /// List invites for an organization
    Invites {
        /// Organization ID
        #[arg(long)]
        org_id: String,
    },
    /// Create an invite for an organization
    Invite {
        /// Organization ID
        #[arg(long)]
        org_id: String,
        /// Email address to invite
        #[arg(long)]
        email: String,
        /// Role for the invited member (owner, admin, or member)
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Manage OAuth provider configurations (BYOC)
    Oauth {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: Box<OrgOauthAction>,
    },
    /// Manage organization custom skills
    Skills {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: Box<OrgSkillsAction>,
    },
    /// Manage organization private-model policy
    PrivateModelsPolicy {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: PrivateModelsPolicyAction,
    },
}

#[derive(Subcommand)]
enum ObjectStorageAction {
    /// Manage object storage buckets
    Buckets {
        #[command(subcommand)]
        action: ObjectStorageBucketAction,
    },
    /// Manage objects in a bucket
    Objects {
        /// Object storage bucket slug
        #[arg(long)]
        bucket: Option<String>,

        #[command(subcommand)]
        action: ObjectStorageObjectAction,
    },
}

#[derive(Subcommand)]
enum StorageAction {
    /// Check Seren Storage service health
    Health,
    /// Browse Seren Storage buckets
    Buckets {
        #[command(subcommand)]
        action: StorageBucketAction,
    },
    /// Manage objects through Seren Storage
    Objects {
        /// Seren Storage bucket slug
        #[arg(long)]
        bucket: Option<String>,

        #[command(subcommand)]
        action: ObjectStorageObjectAction,
    },
}

#[derive(Subcommand)]
enum StorageBucketAction {
    /// List buckets available to the authenticated organization
    List,
}

#[derive(Subcommand)]
enum ObjectStorageBucketAction {
    /// List buckets
    List,
    /// Create a bucket
    Create {
        /// Bucket slug
        #[arg(long)]
        slug: String,
        /// Optional display name
        #[arg(long)]
        display_name: Option<String>,
        /// Optional metadata JSON object
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON object file
        #[arg(long = "metadata-file")]
        metadata_file: Option<std::path::PathBuf>,
    },
    /// Delete an empty bucket
    Delete {
        /// Bucket slug
        #[arg(long)]
        bucket: String,
    },
}

#[derive(Subcommand)]
enum ObjectStorageObjectAction {
    /// List uploaded objects
    List {
        /// Bucket slug, optionally followed by a key prefix as bucket/prefix
        target: Option<String>,
        /// Optional key prefix filter
        #[arg(long)]
        prefix: Option<String>,
        /// Maximum number of objects to return
        #[arg(long)]
        limit: Option<i64>,
        /// Offset for pagination
        #[arg(long)]
        offset: Option<i64>,
    },
    /// Upload a local file
    #[command(visible_alias = "put")]
    Upload {
        /// Bucket/key target. When provided, --bucket and --key are optional.
        target: Option<String>,
        /// Object key to store
        #[arg(long)]
        key: Option<String>,
        /// Local file path
        #[arg(long)]
        path: std::path::PathBuf,
        /// Content type. Defaults to application/octet-stream.
        #[arg(long)]
        content_type: Option<String>,
        /// Optional metadata JSON object
        #[arg(long = "metadata")]
        metadata_json: Option<String>,
        /// Optional path to a metadata JSON object file
        #[arg(long = "metadata-file")]
        metadata_file: Option<std::path::PathBuf>,
    },
    /// Download an object by key
    #[command(visible_alias = "get")]
    Download {
        /// Bucket/key target. When provided, --bucket and --key are optional.
        target: Option<String>,
        /// Object key to download
        #[arg(long)]
        key: Option<String>,
        /// Destination file path. The file must not already exist.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Retry confirmation for a pending upload
    Confirm {
        /// Object ID returned by the upload create step
        #[arg(long)]
        object_id: Uuid,
        /// Optional expected SHA-256 hex digest
        #[arg(long)]
        sha256: Option<String>,
        /// Optional expected byte length
        #[arg(long)]
        byte_length: Option<i64>,
        /// Optional object ETag returned by the presigned PUT
        #[arg(long)]
        etag: Option<String>,
    },
    /// Delete an object by ID or bucket/key target
    Delete {
        /// Object ID
        #[arg(long)]
        object_id: Option<Uuid>,
        /// Bucket/key target. When provided, --bucket and --object-id are optional.
        target: Option<String>,
    },
}

#[derive(Subcommand)]
enum PrivateModelsPolicyAction {
    /// Get the private-model policy
    Get,
    /// Update the private-model policy from a JSON request body
    Update {
        /// JSON body matching UpdateOrganizationPrivateModelsPolicyRequest
        #[arg(long)]
        body: String,
    },
}

#[derive(Subcommand)]
enum OrgOauthAction {
    /// List OAuth providers for the organization
    List,
    /// Get details about a specific OAuth provider
    Get {
        /// OAuth provider ID (UUID)
        provider_id: String,
    },
    /// Create a new OAuth provider configuration
    Create {
        /// URL-friendly slug (unique identifier)
        #[arg(long)]
        slug: String,
        /// Display name for the provider
        #[arg(long)]
        name: String,
        /// OAuth authorization URL
        #[arg(long)]
        authorization_url: String,
        /// OAuth token URL
        #[arg(long)]
        token_url: String,
        /// OAuth client ID
        #[arg(long)]
        client_id: String,
        /// OAuth client secret
        #[arg(long)]
        client_secret: String,
        /// Description of the provider
        #[arg(long)]
        description: Option<String>,
        /// Logo URL
        #[arg(long)]
        logo_url: Option<String>,
        /// Userinfo URL (for fetching user details after auth)
        #[arg(long)]
        userinfo_url: Option<String>,
        /// Token revocation URL
        #[arg(long)]
        revocation_url: Option<String>,
        /// OAuth scopes (comma-separated or multiple --scope flags)
        #[arg(long = "scope", value_delimiter = ',')]
        scopes: Vec<String>,
        /// Require PKCE for authorization
        #[arg(long, default_value_t = true)]
        pkce_required: bool,
        /// Token endpoint auth method (client_secret_basic, client_secret_post)
        #[arg(long)]
        token_endpoint_auth_method: Option<String>,
    },
    /// Update an OAuth provider configuration
    Update {
        /// OAuth provider ID (UUID)
        provider_id: String,
        /// New display name
        #[arg(long)]
        name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// New logo URL
        #[arg(long)]
        logo_url: Option<String>,
        /// New authorization URL
        #[arg(long)]
        authorization_url: Option<String>,
        /// New token URL
        #[arg(long)]
        token_url: Option<String>,
        /// New userinfo URL
        #[arg(long)]
        userinfo_url: Option<String>,
        /// New revocation URL
        #[arg(long)]
        revocation_url: Option<String>,
        /// New client ID
        #[arg(long)]
        client_id: Option<String>,
        /// New client secret
        #[arg(long)]
        client_secret: Option<String>,
        /// New scopes (replaces existing)
        #[arg(long = "scope", value_delimiter = ',')]
        scopes: Option<Vec<String>>,
        /// Require PKCE
        #[arg(long)]
        pkce_required: Option<bool>,
        /// Token endpoint auth method
        #[arg(long)]
        token_endpoint_auth_method: Option<String>,
        /// Enable or disable the provider
        #[arg(long)]
        is_active: Option<bool>,
    },
    /// Delete an OAuth provider configuration
    Delete {
        /// OAuth provider ID (UUID)
        provider_id: String,
    },
}

#[derive(Subcommand)]
enum OrgSkillsAction {
    /// List custom skills for the organization
    List,
    /// Get one custom skill by ID
    Get {
        /// Custom skill ID (UUID)
        skill_id: String,
    },
    /// Create a new custom skill from a local directory
    Create {
        /// URL-safe skill slug
        #[arg(long)]
        slug: String,
        /// Display name
        #[arg(long)]
        display_name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Path to the local skill directory containing SKILL.md
        #[arg(long)]
        path: String,
        /// Publish the initial revision immediately
        #[arg(long, default_value_t = true)]
        publish: bool,
    },
    /// Update skill metadata
    Update {
        /// Custom skill ID (UUID)
        skill_id: String,
        /// New display name
        #[arg(long)]
        display_name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// Clear the description
        #[arg(long, default_value_t = false)]
        clear_description: bool,
        /// New status (active or archived)
        #[arg(long)]
        status: Option<String>,
    },
    /// List revisions for a custom skill
    Revisions {
        /// Custom skill ID (UUID)
        skill_id: String,
    },
    /// Get one revision by ID
    RevisionGet {
        /// Custom skill ID (UUID)
        skill_id: String,
        /// Revision ID (UUID)
        revision_id: String,
    },
    /// Upload a new revision from a local directory
    RevisionCreate {
        /// Custom skill ID (UUID)
        skill_id: String,
        /// Path to the local skill directory containing SKILL.md
        #[arg(long)]
        path: String,
        /// Publish the revision immediately
        #[arg(long, default_value_t = false)]
        publish: bool,
    },
    /// Publish an existing revision
    Publish {
        /// Custom skill ID (UUID)
        skill_id: String,
        /// Revision ID (UUID)
        revision_id: String,
    },
    /// Download a revision bundle
    DownloadBundle {
        /// Custom skill ID (UUID)
        skill_id: String,
        /// Revision ID (UUID)
        revision_id: String,
        /// Output path for the tar.gz bundle
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProjectAction {
    /// List all projects
    List,
    /// Get a specific project
    Get {
        /// Project ID
        id: String,
    },
    /// Create a new project
    Create {
        /// Project name
        #[arg(long)]
        name: String,

        /// Region identifier (e.g. aws-us-east-1)
        #[arg(long)]
        region: String,

        /// Organization ID
        #[arg(long)]
        org_id: Option<String>,

        /// Block public connections to the project
        #[arg(long)]
        block_public_connections: Option<bool>,

        /// Block connections from unapproved VPC endpoints
        #[arg(long)]
        block_vpc_connections: Option<bool>,

        /// Enable HIPAA controls
        #[arg(long)]
        hipaa: Option<bool>,

        /// Apply IP allow list only to protected branches
        #[arg(long)]
        protected_branches_only: Option<bool>,

        /// Minimum compute units for default sizing
        #[arg(long)]
        compute_unit_min: Option<i32>,

        /// Maximum compute units for default sizing
        #[arg(long)]
        compute_unit_max: Option<i32>,

        /// Enable logical replication (sets wal_level=logical). Cannot be disabled once enabled.
        #[arg(long)]
        enable_logical_replication: Option<bool>,

        /// Connect to the new project via psql after creation
        #[arg(long, action = ArgAction::SetTrue)]
        psql: bool,

        /// Set the new project as the current context
        #[arg(long, action = ArgAction::SetTrue)]
        set_context: bool,
    },
    /// Retrieve a project-level connection URI
    ConnectionUri {
        /// Project ID
        id: String,

        /// Branch ID override
        #[arg(long)]
        branch_id: Option<String>,

        /// Endpoint ID override
        #[arg(long)]
        endpoint_id: Option<String>,

        /// Database name override
        #[arg(long)]
        database: Option<String>,

        /// Role name override
        #[arg(long)]
        role: Option<String>,

        /// Request pooled connection string
        #[arg(long, action = ArgAction::SetTrue)]
        pooled: bool,

        /// Override SSL mode (require, prefer, disable)
        #[arg(long)]
        ssl: Option<String>,
    },
    /// Update a project
    Update {
        /// Project ID
        id: String,

        /// New project name
        #[arg(long)]
        name: Option<String>,

        /// Block public connections
        #[arg(long)]
        block_public_connections: Option<bool>,

        /// Block VPC connections
        #[arg(long)]
        block_vpc_connections: Option<bool>,

        /// Enable HIPAA controls
        #[arg(long)]
        hipaa: Option<bool>,

        /// Set protected branches requirement for IP allow list
        #[arg(long)]
        protected_branches_only: Option<bool>,

        /// Minimum compute units
        #[arg(long)]
        compute_unit_min: Option<i32>,

        /// Maximum compute units
        #[arg(long)]
        compute_unit_max: Option<i32>,

        /// Enable logical replication (sets wal_level=logical). Cannot be disabled once enabled.
        #[arg(long)]
        enable_logical_replication: Option<bool>,
    },
    /// Delete a project
    Delete {
        /// Project ID
        id: String,

        /// Skip confirmation prompt (use with caution)
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum BranchAction {
    /// List all branches
    List,
    /// Get a specific branch
    Get {
        /// Branch ID
        id: String,
    },
    /// Create a new branch
    Create {
        /// Branch name
        #[arg(long)]
        name: String,

        /// Parent branch ID (optional)
        #[arg(long)]
        parent: Option<String>,

        /// Mark branch as protected
        #[arg(long, action = ArgAction::SetTrue)]
        protected: bool,

        /// Mark branch as archived
        #[arg(long, action = ArgAction::SetTrue)]
        archived: bool,

        /// Initial data source identifier
        #[arg(long)]
        init_source: Option<String>,

        /// Parent branch LSN for PITR
        #[arg(long)]
        parent_lsn: Option<String>,

        /// Parent branch timestamp for PITR (RFC3339)
        #[arg(long)]
        parent_timestamp: Option<String>,

        /// Do not create a compute endpoint for this branch.
        /// By default, new branches get an endpoint automatically.
        #[arg(long, action = ArgAction::SetTrue)]
        no_compute: bool,

        /// Endpoint type for auto-provisioned endpoint (default read_write)
        #[arg(long, conflicts_with = "no_compute")]
        endpoint_type: Option<String>,

        /// Endpoint settings in key=value form
        #[arg(long = "endpoint-setting", value_name = "KEY=VALUE", num_args = 0.., conflicts_with = "no_compute")]
        endpoint_settings: Vec<String>,

        /// Auto-delete branch after specified duration.
        /// Examples: "1d" (1 day), "7d" (7 days), "30d" (30 days)
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,

        /// Create branch with schema only (no data).
        /// Copies only the database schema, not the data.
        #[arg(long, action = ArgAction::SetTrue)]
        schema_only: bool,

        /// Compute units for the endpoint. Can be a fixed size (e.g., "2") or
        /// a range (e.g., "0.5-3") for autoscaling.
        #[arg(long, conflicts_with = "no_compute")]
        cu: Option<String>,

        /// Suspend timeout in seconds. Duration of inactivity after which the
        /// endpoint is suspended. Use 0 for default, -1 for never.
        #[arg(long, conflicts_with = "no_compute")]
        suspend_timeout: Option<i32>,

        /// Connect to the new branch via psql after creation
        #[arg(long, action = ArgAction::SetTrue)]
        psql: bool,
    },
    /// Delete a branch
    Delete {
        /// Branch ID
        id: String,

        /// Skip confirmation prompt (use with caution)
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Rename a branch
    Rename {
        /// Branch ID
        id: String,

        /// New branch name
        #[arg(long)]
        name: String,
    },
    /// Set a branch as the default branch
    SetDefault {
        /// Branch ID
        id: String,
    },
    /// Get connection string for a branch
    ConnectionString {
        /// Branch ID
        id: String,

        /// PostgreSQL role/username to embed in the connection string (default: serendb_owner)
        #[arg(long)]
        role: Option<String>,

        /// Use pooled connection (PgBouncer)
        #[arg(long)]
        pooled: bool,

        /// SSL mode (require, prefer, disable)
        #[arg(long)]
        ssl: Option<String>,
    },
    /// Set branch expiration
    SetExpiration {
        /// Branch ID
        id: String,

        /// Expiration date in RFC3339 format (e.g., "2025-12-31T23:59:59Z")
        #[arg(long)]
        expires_at: Option<String>,

        /// Remove expiration
        #[arg(long)]
        no_expiration: bool,
    },
    /// Compare schemas between two branches
    SchemaDiff {
        /// Base branch ID to compare from
        #[arg(long)]
        base_branch_id: String,

        /// Compare branch ID to compare to
        #[arg(long)]
        compare_branch_id: String,

        /// Database name (defaults to 'postgres')
        #[arg(long)]
        database: Option<String>,
    },
    /// Reset a branch to its parent's latest state
    Reset {
        /// Branch ID to reset
        id: String,
    },
    /// Restore a branch to a point in time
    Restore {
        /// Branch ID to restore
        id: String,

        /// Source to restore from (^self, ^parent, or branch ID)
        #[arg(long)]
        source: String,

        /// Name for the backup branch created during restore
        #[arg(long)]
        preserve_under_name: String,

        /// Point-in-time timestamp (RFC3339 format)
        #[arg(long)]
        timestamp: Option<String>,

        /// Log Sequence Number (LSN) for point-in-time recovery
        #[arg(long)]
        lsn: Option<String>,
    },
}

#[derive(Subcommand)]
enum DatabaseAction {
    /// List all databases
    List,
    /// Get a specific database
    Get {
        /// Database ID
        id: String,
    },
    /// Create a new database
    Create {
        /// Database name
        #[arg(long)]
        name: String,

        /// Owner role name (optional)
        #[arg(long)]
        owner: Option<String>,
    },
    /// Delete a database
    Delete {
        /// Database ID
        id: String,
    },
}

#[derive(Subcommand)]
enum GlobalDatabaseAction {
    /// List databases across projects
    List {
        /// Optional project ID to filter databases to a specific project
        #[arg(long)]
        project_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum RoleAction {
    /// List all roles
    List,
    /// Create a new role
    Create {
        /// Role name
        #[arg(long)]
        name: String,
    },
    /// Delete a role
    Delete {
        /// Role ID
        id: String,
    },
    /// Reset role password
    ResetPassword {
        /// Role ID
        #[arg(long)]
        id: String,
    },
    /// Reveal the current password for a role
    RevealPassword {
        /// Role name
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum EndpointAction {
    /// List all endpoints
    List,
    /// Create a new endpoint
    Create {
        /// Endpoint name
        #[arg(long)]
        name: String,

        /// Compute unit (small, medium, large, xlarge, 2xlarge, 4xlarge)
        #[arg(long, value_parser = ["small", "medium", "large", "xlarge", "2xlarge", "4xlarge"])]
        compute_unit: Option<String>,

        /// Minimum autoscaling compute units
        #[arg(long)]
        autoscaling_min: Option<i32>,

        /// Maximum autoscaling compute units
        #[arg(long)]
        autoscaling_max: Option<i32>,

        /// Suspend timeout in seconds
        #[arg(long)]
        suspend_timeout: Option<i32>,
    },
    /// Update an endpoint
    Update {
        /// Endpoint ID
        id: String,

        /// Minimum autoscaling compute units
        #[arg(long)]
        autoscaling_min: Option<i32>,

        /// Maximum autoscaling compute units
        #[arg(long)]
        autoscaling_max: Option<i32>,

        /// Suspend timeout in seconds
        #[arg(long)]
        suspend_timeout: Option<i32>,
    },
    /// Delete an endpoint
    Delete {
        /// Endpoint ID
        id: String,
    },
    /// Suspend an endpoint
    Suspend {
        /// Endpoint ID
        id: String,
    },
    /// Start an endpoint
    Start {
        /// Endpoint ID
        id: String,
    },
    /// Restart an endpoint (rolling restart via Kubernetes)
    Restart {
        /// Endpoint ID
        id: String,
    },
    /// Get endpoint health status
    Health {
        /// Endpoint ID
        id: String,
    },
    /// Get endpoint resource metrics
    Metrics {
        /// Endpoint ID
        id: String,
    },
}

#[derive(Subcommand)]
enum OperationAction {
    /// List all operations for a project
    List,
    /// Get a specific operation by ID
    Get {
        /// Operation ID
        id: String,
    },
}

#[derive(Subcommand)]
enum IpAllowListAction {
    /// List IP allow list entries
    List,
    /// Add IP to allow list
    Add {
        /// IP address or CIDR range
        #[arg(long)]
        ip_address: String,

        /// Optional description
        #[arg(long)]
        description: Option<String>,
    },
    /// Remove IP from allow list
    Remove {
        /// IP allow list entry ID
        id: String,
    },
    /// Replace entire IP allow list (omit IPs to clear)
    Reset {
        /// IP addresses or CIDR ranges to allow after reset
        #[arg(value_name = "IP", num_args = 0..)]
        ips: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ContextAction {
    /// Set default project or organization
    Set {
        /// Default project ID
        #[arg(long)]
        project_id: Option<String>,

        /// Default organization ID
        #[arg(long)]
        org_id: Option<String>,
    },
    /// Show current context
    Show,
    /// Clear context
    Clear,
}

#[derive(Subcommand)]
enum EnvAction {
    /// Initialize a .env file with a Seren connection string
    Init {
        /// Project ID (defaults to CLI context if not provided)
        #[arg(long)]
        project_id: Option<String>,

        /// Branch ID to use for the connection
        #[arg(long)]
        branch_id: Option<String>,

        /// Path to the .env file
        #[arg(long, default_value = ".env")]
        env: String,

        /// Environment key to write
        #[arg(long, default_value = "DATABASE_URL")]
        key: String,

        /// Request a pooled connection string
        #[arg(long, action = ArgAction::SetTrue)]
        pooled: bool,

        /// Non-interactive mode (do not prompt; error instead)
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum VpcAction {
    /// Manage organization VPC endpoints
    Endpoint {
        /// Organization ID
        #[arg(long)]
        org_id: String,

        #[command(subcommand)]
        action: VpcEndpointAction,
    },
    /// Manage project VPC endpoint assignments
    Project {
        /// Project ID
        #[arg(long)]
        project_id: String,

        #[command(subcommand)]
        action: VpcProjectAction,
    },
}

#[derive(Subcommand)]
enum VpcEndpointAction {
    /// List VPC endpoints for an organization
    List {
        /// Optional region filter
        #[arg(long)]
        region: Option<String>,
    },
    /// Register a VPC endpoint for an organization
    Add {
        /// Region identifier
        #[arg(long)]
        region: String,

        /// Cloud provider VPC endpoint identifier
        #[arg(long)]
        endpoint_id: String,

        /// Optional label to help identify the endpoint
        #[arg(long)]
        label: Option<String>,
    },
    /// Show details for a VPC endpoint
    Get {
        /// Organization VPC endpoint ID
        endpoint_id: String,
    },
    /// Remove a VPC endpoint from the organization
    Remove {
        /// Organization VPC endpoint ID
        endpoint_id: String,
    },
}

#[derive(Subcommand)]
enum VpcProjectAction {
    /// List project VPC endpoint restrictions
    List,
    /// Restrict project access to a specific VPC endpoint
    Assign {
        /// Organization VPC endpoint ID to assign
        #[arg(long)]
        vpc_endpoint_id: String,

        /// Optional label for the assignment
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a VPC endpoint assignment from the project
    Remove {
        /// Assignment ID
        assignment_id: String,
    },
}

#[derive(Subcommand)]
enum BillingAction {
    /// Generate monthly invoices for all organizations
    GenerateInvoices {
        /// Year (e.g., 2025)
        #[arg(long)]
        year: i32,

        /// Month (1-12)
        #[arg(long)]
        month: i32,
    },
    /// Get invoice details
    GetInvoice {
        /// Invoice ID
        invoice_id: String,
    },
    /// Issue a draft invoice
    IssueInvoice {
        /// Invoice ID
        invoice_id: String,
    },
    /// Get usage summary for an organization
    GetUsage {
        /// Organization ID
        #[arg(long)]
        organization_id: String,

        /// Start date (YYYY-MM-DD)
        #[arg(long)]
        start_date: Option<String>,

        /// End date (YYYY-MM-DD)
        #[arg(long)]
        end_date: Option<String>,
    },
    /// List payment methods for the authenticated user's primary organization
    ListPaymentMethods,
    /// Add a payment method using a Stripe PaymentMethod ID
    AddPaymentMethod {
        /// Stripe PaymentMethod ID (pm_...)
        stripe_payment_method_id: String,

        /// Set this payment method as the default
        #[arg(long, default_value_t = true)]
        default: bool,
    },
    /// Validate an agent endpoint token
    ValidateToken {
        /// Token to validate
        token: String,
    },
    /// Get endpoint balance
    GetBalance {
        /// Endpoint ID
        endpoint_id: String,
    },
    /// Remove a stored payment method
    RemovePaymentMethod {
        /// Seren payment method ID (UUID)
        id: String,
    },
    /// Get billing pipeline health
    Health,
}

#[derive(Subcommand)]
enum SessionAction {
    /// List all active sessions
    List,
    /// Revoke a specific session
    Revoke {
        /// Session ID to revoke
        session_id: String,
    },
    /// Revoke all other sessions (keep current)
    RevokeOthers {
        /// Session ID to keep (usually your current session)
        keep_session_id: String,
    },
    /// Revoke all sessions (logout everywhere)
    RevokeAll,
}

#[derive(Subcommand)]
enum WebhookAction {
    /// List all webhooks
    List,
    /// Get a specific webhook
    Get {
        /// Webhook ID
        webhook_id: String,
    },
    /// Create a new webhook
    Create {
        /// Name of the webhook
        #[arg(long)]
        name: String,

        /// Webhook URL to receive events
        #[arg(long)]
        url: String,

        /// Event types to subscribe to (comma-separated or multiple --event flags)
        #[arg(long = "event", value_delimiter = ',')]
        events: Vec<String>,

        /// Project ID to scope webhook to (optional)
        #[arg(long)]
        project_id: Option<String>,
    },
    /// Update a webhook
    Update {
        /// Webhook ID
        webhook_id: String,

        /// New webhook name
        #[arg(long)]
        name: Option<String>,

        /// New webhook URL
        #[arg(long)]
        url: Option<String>,

        /// New event types (replaces existing)
        #[arg(long = "event", value_delimiter = ',')]
        events: Option<Vec<String>>,

        /// Enable or disable the webhook
        #[arg(long)]
        enabled: Option<bool>,
    },
    /// Delete a webhook
    Delete {
        /// Webhook ID
        webhook_id: String,
    },
    /// Rotate webhook secret
    RotateSecret {
        /// Webhook ID
        webhook_id: String,
    },
    /// List webhook deliveries
    Deliveries {
        /// Webhook ID
        webhook_id: String,
    },
    /// List available event types
    EventTypes,
}

#[derive(Subcommand)]
enum AuditLogAction {
    /// List audit logs
    List {
        /// Maximum number of logs to return
        #[arg(long, default_value_t = 50)]
        limit: i64,

        /// Offset for pagination
        #[arg(long, default_value_t = 0)]
        offset: i64,
    },
    /// Get a specific audit log entry
    Get {
        /// Audit log ID
        log_id: String,
    },
}

#[derive(Subcommand)]
enum RbacAction {
    /// List all roles in the organization
    ListRoles,
    /// Get a specific role
    GetRole {
        /// Role ID
        role_id: String,
    },
    /// Create a new role
    CreateRole {
        /// Role name
        #[arg(long)]
        name: String,

        /// Role description
        #[arg(long)]
        description: Option<String>,

        /// Permissions to grant (comma-separated or multiple --permission flags)
        #[arg(long = "permission", value_delimiter = ',')]
        permissions: Vec<String>,
    },
    /// Update a role
    UpdateRole {
        /// Role ID
        role_id: String,

        /// New role name
        #[arg(long)]
        name: Option<String>,

        /// New description
        #[arg(long)]
        description: Option<String>,

        /// New permissions (replaces existing)
        #[arg(long = "permission", value_delimiter = ',')]
        permissions: Option<Vec<String>>,
    },
    /// Delete a role
    DeleteRole {
        /// Role ID
        role_id: String,
    },
    /// Assign a role to an organization member
    AssignRole {
        /// Member ID
        #[arg(long)]
        member_id: String,

        /// Role ID to assign
        #[arg(long)]
        role_id: String,
    },
    /// List all available permissions
    ListPermissions,
    /// List your permissions in the organization
    MyPermissions,
}

#[derive(Subcommand)]
enum BranchProtectionAction {
    /// List all branch protection rules for a project
    List,
    /// Get branch protection for a specific branch
    Get {
        /// Branch ID
        branch_id: String,
    },
    /// Create branch protection for a branch
    Create {
        /// Branch ID
        branch_id: String,

        /// Prevent branch deletion
        #[arg(long, default_value_t = true)]
        prevent_deletion: bool,

        /// Prevent branch reset
        #[arg(long, default_value_t = true)]
        prevent_reset: bool,

        /// Require approval for changes
        #[arg(long)]
        require_approval: bool,

        /// Roles that can bypass protection (comma-separated)
        #[arg(long = "bypass-role", value_delimiter = ',')]
        bypass_roles: Vec<String>,
    },
    /// Update branch protection
    Update {
        /// Branch ID
        branch_id: String,

        /// Prevent branch deletion
        #[arg(long)]
        prevent_deletion: Option<bool>,

        /// Prevent branch reset
        #[arg(long)]
        prevent_reset: Option<bool>,

        /// Require approval for changes
        #[arg(long)]
        require_approval: Option<bool>,

        /// Roles that can bypass protection (replaces existing)
        #[arg(long = "bypass-role", value_delimiter = ',')]
        bypass_roles: Option<Vec<String>>,
    },
    /// Remove branch protection
    Delete {
        /// Branch ID
        branch_id: String,
    },
}

#[derive(Subcommand)]
enum ReplicationAction {
    /// Get logical replication settings for a project
    Settings,
    /// Enable logical replication (sets wal_level=logical, cannot be disabled)
    Enable,
    /// List publications for a branch
    ListPublications {
        /// Branch ID
        #[arg(long)]
        branch_id: String,
    },
    /// Create a publication
    CreatePublication {
        /// Branch ID
        #[arg(long)]
        branch_id: String,

        /// Publication name
        #[arg(long)]
        name: String,

        /// Tables to include (comma-separated)
        #[arg(long = "table", value_delimiter = ',')]
        tables: Vec<String>,

        /// Publish all tables
        #[arg(long)]
        all_tables: bool,
    },
    /// Update a publication
    UpdatePublication {
        /// Branch ID
        #[arg(long)]
        branch_id: String,

        /// Publication ID
        #[arg(long)]
        publication_id: String,

        /// Tables to include (replaces existing)
        #[arg(long = "table", value_delimiter = ',')]
        tables: Option<Vec<String>>,

        /// Publish all tables
        #[arg(long)]
        all_tables: Option<bool>,
    },
    /// Delete a publication
    DeletePublication {
        /// Branch ID
        #[arg(long)]
        branch_id: String,

        /// Publication ID
        #[arg(long)]
        publication_id: String,
    },
    /// List replication slots for a branch
    ListSlots {
        /// Branch ID
        #[arg(long)]
        branch_id: String,
    },
    /// Create a replication slot
    CreateSlot {
        /// Branch ID
        #[arg(long)]
        branch_id: String,

        /// Slot name
        #[arg(long)]
        name: String,

        /// Output plugin (default: pgoutput)
        #[arg(long)]
        plugin: Option<String>,
    },
    /// Delete a replication slot
    DeleteSlot {
        /// Branch ID
        #[arg(long)]
        branch_id: String,

        /// Slot ID
        #[arg(long)]
        slot_id: String,
    },
}

async fn execute_agent_cloud_action(
    action: AgentCloudAction,
    ctx: &CommandContext,
) -> anyhow::Result<()> {
    match action {
        AgentCloudAction::Deployment { action } => match action {
            CloudDeploymentAction::List => commands::agent::cloud_list(ctx).await?,
            CloudDeploymentAction::Bundle { action } => match action {
                CloudDeploymentBundleAction::Get { bundle_id } => {
                    commands::agent::cloud_deployment_bundle_get(bundle_id, ctx).await?
                }
            },
            CloudDeploymentAction::Status { deployment_id } => {
                commands::agent::cloud_status(deployment_id, ctx).await?
            }
            CloudDeploymentAction::Start { deployment_id } => {
                commands::agent::cloud_start(deployment_id, ctx).await?
            }
            CloudDeploymentAction::Stop { deployment_id } => {
                commands::agent::cloud_stop(deployment_id, ctx).await?
            }
            CloudDeploymentAction::Spend { deployment_id } => {
                commands::agent::cloud_deployment_spend(deployment_id, ctx).await?
            }
            CloudDeploymentAction::Audit {
                deployment_id,
                action,
                limit,
                offset,
                q,
            } => {
                commands::agent::cloud_deployment_audit(
                    deployment_id,
                    action.as_deref(),
                    limit,
                    offset,
                    q.as_deref(),
                    ctx,
                )
                .await?
            }
            CloudDeploymentAction::Destroy { deployment_id } => {
                commands::agent::cloud_destroy(deployment_id, ctx).await?
            }
            CloudDeploymentAction::UpdateConfig {
                deployment_id,
                config,
                env_file,
                alert_policy,
                clear_alert_policy,
                network_policy,
                clear_network_policy,
                eval_gate_set_id,
                eval_gate_max_age_seconds,
                clear_eval_gate,
            } => {
                commands::agent::cloud_update_config(
                    deployment_id,
                    commands::agent::CloudUpdateConfigOptions {
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                        alert_policy_path: alert_policy.as_deref(),
                        clear_alert_policy,
                        network_policy_path: network_policy.as_deref(),
                        clear_network_policy,
                        eval_gate_set_id,
                        eval_gate_max_age_seconds,
                        clear_eval_gate,
                    },
                    ctx,
                )
                .await?
            }
        },
        AgentCloudAction::Audit { action } => match action {
            CloudAuditAction::List {
                action,
                limit,
                offset,
                q,
            } => {
                commands::agent::cloud_audit_list(
                    action.as_deref(),
                    limit,
                    offset,
                    q.as_deref(),
                    ctx,
                )
                .await?
            }
            CloudAuditAction::Get { entry_id } => {
                commands::agent::cloud_audit_get(entry_id, ctx).await?
            }
            CloudAuditAction::Verify { limit } => {
                commands::agent::cloud_audit_verify(limit, ctx).await?
            }
        },
        AgentCloudAction::Environment { action } => match action {
            CloudEnvironmentAction::List => commands::agent::cloud_environment_list(ctx).await?,
            CloudEnvironmentAction::Get { environment_id } => {
                commands::agent::cloud_environment_get(environment_id, ctx).await?
            }
            CloudEnvironmentAction::Create {
                name,
                docker_image,
                description,
                setup_commands,
                is_default,
            } => {
                commands::agent::cloud_environment_create(
                    &name,
                    &docker_image,
                    commands::agent::CloudEnvironmentCreateOptions {
                        description: description.as_deref(),
                        setup_commands: &setup_commands,
                        is_default,
                    },
                    ctx,
                )
                .await?
            }
            CloudEnvironmentAction::Update {
                environment_id,
                name,
                description,
                docker_image,
                setup_commands,
                clear_setup_commands,
                is_default,
            } => {
                commands::agent::cloud_environment_update(
                    environment_id,
                    name.as_deref(),
                    description.as_deref(),
                    docker_image.as_deref(),
                    &setup_commands,
                    clear_setup_commands,
                    is_default,
                    ctx,
                )
                .await?
            }
            CloudEnvironmentAction::Delete { environment_id } => {
                commands::agent::cloud_environment_delete(environment_id, ctx).await?
            }
        },
        AgentCloudAction::Overview {
            runs_limit,
            approvals_limit,
        } => commands::agent::cloud_overview(runs_limit, approvals_limit, ctx).await?,
        AgentCloudAction::Run { action } => match action {
            CloudRunAction::Start {
                deployment_id,
                message,
                json_body,
                json_file,
                run_id,
                async_run,
            } => {
                commands::agent::cloud_run(
                    deployment_id,
                    message.as_deref(),
                    json_body.as_deref(),
                    json_file.as_deref(),
                    run_id.as_deref(),
                    async_run,
                    ctx,
                )
                .await?
            }
            CloudRunAction::Get {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_run_get(deployment_id, run_id, ctx).await?
                } else {
                    commands::agent::cloud_run_by_id(run_id, ctx).await?
                }
            }
            CloudRunAction::Compare {
                baseline_run_id,
                candidate_run_id,
            } => commands::agent::cloud_run_compare(baseline_run_id, candidate_run_id, ctx).await?,
            CloudRunAction::Artifacts {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_artifacts(deployment_id, run_id, ctx)
                        .await?
                } else {
                    commands::agent::cloud_run_artifacts(run_id, ctx).await?
                }
            }
            CloudRunAction::Audit {
                run_id,
                action,
                limit,
                offset,
                q,
            } => {
                commands::agent::cloud_run_audit(
                    run_id,
                    action.as_deref(),
                    limit,
                    offset,
                    q.as_deref(),
                    ctx,
                )
                .await?
            }
            CloudRunAction::Evals {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_evals(deployment_id, run_id, ctx).await?
                } else {
                    commands::agent::cloud_run_evals(run_id, ctx).await?
                }
            }
            CloudRunAction::Events {
                deployment_id,
                run_id,
                item_id,
                kind,
                limit,
                offset,
                q,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_events(
                        deployment_id,
                        run_id,
                        item_id.as_deref(),
                        kind.as_deref(),
                        limit,
                        offset,
                        q.as_deref(),
                        ctx,
                    )
                    .await?
                } else {
                    commands::agent::cloud_run_events(
                        run_id,
                        item_id.as_deref(),
                        kind.as_deref(),
                        limit,
                        offset,
                        q.as_deref(),
                        ctx,
                    )
                    .await?
                }
            }
            CloudRunAction::Stream {
                deployment_id,
                run_id,
                last_event_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_stream(
                        deployment_id,
                        run_id,
                        last_event_id.as_deref(),
                        ctx,
                    )
                    .await?
                } else {
                    commands::agent::cloud_run_stream(run_id, last_event_id.as_deref(), ctx).await?
                }
            }
            CloudRunAction::State {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_state(deployment_id, run_id, ctx).await?
                } else {
                    commands::agent::cloud_run_state(run_id, ctx).await?
                }
            }
            CloudRunAction::PendingApprovals {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_run_pending_approvals(
                        deployment_id,
                        run_id,
                        ctx,
                    )
                    .await?
                } else {
                    commands::agent::cloud_run_pending_approvals(run_id, ctx).await?
                }
            }
            CloudRunAction::Approve { run_id } => {
                commands::agent::cloud_run_approve(run_id, ctx).await?
            }
            CloudRunAction::Reject { run_id } => {
                commands::agent::cloud_run_reject(run_id, ctx).await?
            }
            CloudRunAction::Cancel {
                deployment_id,
                run_id,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_run_cancel(deployment_id, run_id, ctx).await?
                } else {
                    commands::agent::cloud_run_cancel_by_id(run_id, ctx).await?
                }
            }
        },
        AgentCloudAction::Conversation { action } => match action {
            CloudConversationAction::List {
                deployment_id,
                limit,
                cursor,
            } => {
                commands::agent::cloud_conversations(deployment_id, limit, cursor.as_deref(), ctx)
                    .await?
            }
            CloudConversationAction::Messages {
                deployment_id,
                conversation_id,
                limit,
                cursor,
                order,
                include_run,
            } => {
                commands::agent::cloud_conversation_messages(
                    deployment_id,
                    &conversation_id,
                    limit,
                    cursor.as_deref(),
                    order.as_deref(),
                    include_run,
                    ctx,
                )
                .await?
            }
        },
        AgentCloudAction::Schedule { action } => match action {
            CloudScheduleAction::List {
                deployment_id,
                limit,
                offset,
            } => commands::agent::cloud_agent_schedules(deployment_id, limit, offset, ctx).await?,
            CloudScheduleAction::Create {
                deployment_id,
                schedule_key,
                message,
                payload_json,
                payload_file,
                conversation_id,
                run_at,
                delay_seconds,
                cron,
                timezone,
                max_attempts,
            } => {
                let options = commands::agent::CloudAgentScheduleCreateOptions {
                    deployment_id,
                    schedule_key: schedule_key.as_deref(),
                    message: message.as_deref(),
                    payload_json: payload_json.as_deref(),
                    payload_file: payload_file.as_deref(),
                    conversation_id: conversation_id.as_deref(),
                    run_at: run_at.as_deref(),
                    delay_seconds,
                    cron: cron.as_deref(),
                    timezone: timezone.as_deref(),
                    max_attempts,
                };
                commands::agent::cloud_agent_schedule_create(options, ctx).await?
            }
            CloudScheduleAction::Cancel {
                deployment_id,
                schedule_id,
            } => {
                commands::agent::cloud_agent_schedule_cancel(deployment_id, schedule_id, ctx)
                    .await?
            }
        },
        AgentCloudAction::Runs { action } => match action {
            CloudRunsAction::List {
                deployment_id,
                limit,
                offset,
                status,
                compute_backend,
                source,
                has_artifacts,
                started_after,
                started_before,
                q,
            } => {
                let options = commands::agent::CloudRunQueryOptions {
                    statuses: &status,
                    compute_backend: compute_backend.as_deref(),
                    source: source.as_deref(),
                    has_artifacts: if has_artifacts { Some(true) } else { None },
                    started_after: started_after.as_deref(),
                    started_before: started_before.as_deref(),
                    q: q.as_deref(),
                };
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_runs(deployment_id, limit, offset, options, ctx).await?
                } else {
                    commands::agent::cloud_all_runs(limit, offset, options, ctx).await?
                }
            }
        },
        AgentCloudAction::Approvals { action } => match action {
            CloudApprovalsAction::List {
                deployment_id,
                limit,
                offset,
            } => {
                if let Some(deployment_id) = deployment_id {
                    commands::agent::cloud_deployment_pending_approvals(
                        deployment_id,
                        limit,
                        offset,
                        ctx,
                    )
                    .await?
                } else {
                    commands::agent::cloud_pending_approvals(limit, offset, ctx).await?
                }
            }
        },
        AgentCloudAction::Eval { action } => match action {
            CloudEvalAction::Set { action } => match action {
                CloudEvalSetAction::List {
                    deployment_id,
                    limit,
                    offset,
                } => commands::agent::cloud_eval_sets(deployment_id, limit, offset, ctx).await?,
                CloudEvalSetAction::Create {
                    name,
                    deployment_id,
                    description,
                    criteria_json,
                    criteria_file,
                    metadata_json,
                    metadata_file,
                    schedule_cron,
                    schedule_timezone,
                } => {
                    commands::agent::cloud_eval_set_create(
                        &name,
                        deployment_id,
                        description.as_deref(),
                        criteria_json.as_deref(),
                        criteria_file.as_deref(),
                        metadata_json.as_deref(),
                        metadata_file.as_deref(),
                        schedule_cron.as_deref(),
                        schedule_timezone.as_deref(),
                        ctx,
                    )
                    .await?
                }
                CloudEvalSetAction::Get { eval_set_id } => {
                    commands::agent::cloud_eval_set_get(eval_set_id, ctx).await?
                }
                CloudEvalSetAction::Update {
                    eval_set_id,
                    name,
                    deployment_id,
                    clear_deployment,
                    description,
                    criteria_json,
                    criteria_file,
                    metadata_json,
                    metadata_file,
                    schedule_cron,
                    schedule_timezone,
                    clear_schedule,
                } => {
                    commands::agent::cloud_eval_set_update(
                        eval_set_id,
                        name.as_deref(),
                        deployment_id,
                        clear_deployment,
                        description.as_deref(),
                        criteria_json.as_deref(),
                        criteria_file.as_deref(),
                        metadata_json.as_deref(),
                        metadata_file.as_deref(),
                        schedule_cron.as_deref(),
                        schedule_timezone.as_deref(),
                        clear_schedule,
                        ctx,
                    )
                    .await?
                }
            },
            CloudEvalAction::Case { action } => match action {
                CloudEvalCaseAction::List {
                    eval_set_id,
                    limit,
                    offset,
                } => commands::agent::cloud_eval_cases(eval_set_id, limit, offset, ctx).await?,
                CloudEvalCaseAction::Get {
                    eval_set_id,
                    case_id,
                } => commands::agent::cloud_eval_case_get(eval_set_id, case_id, ctx).await?,
                CloudEvalCaseAction::FromRun {
                    eval_set_id,
                    run_id,
                    name,
                    metadata_json,
                    metadata_file,
                } => {
                    commands::agent::cloud_eval_case_from_run(
                        eval_set_id,
                        run_id,
                        name.as_deref(),
                        metadata_json.as_deref(),
                        metadata_file.as_deref(),
                        ctx,
                    )
                    .await?
                }
            },
            CloudEvalAction::Run { action } => match action {
                CloudEvalRunAction::Create {
                    eval_set_id,
                    deployment_id,
                    metadata_json,
                    metadata_file,
                } => {
                    commands::agent::cloud_eval_run_create(
                        eval_set_id,
                        deployment_id,
                        metadata_json.as_deref(),
                        metadata_file.as_deref(),
                        ctx,
                    )
                    .await?
                }
                CloudEvalRunAction::List {
                    eval_set_id,
                    limit,
                    offset,
                } => commands::agent::cloud_eval_runs(eval_set_id, limit, offset, ctx).await?,
                CloudEvalRunAction::Get {
                    eval_set_id,
                    eval_run_id,
                } => commands::agent::cloud_eval_run_get(eval_set_id, eval_run_id, ctx).await?,
                CloudEvalRunAction::Results {
                    eval_set_id,
                    eval_run_id,
                    limit,
                    offset,
                } => {
                    commands::agent::cloud_eval_run_results(
                        eval_set_id,
                        eval_run_id,
                        limit,
                        offset,
                        ctx,
                    )
                    .await?
                }
            },
            CloudEvalAction::Result { action } => match action {
                CloudEvalResultAction::Get {
                    eval_set_id,
                    eval_run_id,
                    case_id,
                } => {
                    commands::agent::cloud_eval_result_get(eval_set_id, eval_run_id, case_id, ctx)
                        .await?
                }
            },
        },
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve the active profile before any config or context is read.
    config::set_active_profile(cli.profile.clone());

    let api_host = cli
        .api_host
        .clone()
        .or_else(defaults::env_api_host_override);

    // `--debug-envelopes` is a global flag; capture it for later use.
    let _debug_envelopes = cli.debug_envelopes;

    // Create shared command context for all commands
    let ctx = CommandContext::new(api_host.clone(), cli.api_key.clone(), cli.format);

    match cli.command {
        Commands::Auth { action } => match action {
            AuthAction::Login => commands::auth::login().await?,
            AuthAction::Status => commands::auth::status().await?,
            AuthAction::Logout => commands::auth::logout().await?,
        },
        Commands::Me => {
            commands::auth::me(cli.format, api_host.clone(), cli.api_key.clone()).await?
        }
        Commands::Organizations => {
            commands::auth::organizations(cli.format, api_host.clone(), cli.api_key.clone()).await?
        }
        Commands::Orgs { action } => match action {
            OrgAction::Members { org_id } => {
                commands::organizations::list_members(&org_id, &ctx).await?
            }
            OrgAction::Invites { org_id } => {
                commands::organizations::list_invites(&org_id, &ctx).await?
            }
            OrgAction::Invite {
                org_id,
                email,
                role,
            } => commands::organizations::create_invite(&org_id, &email, &role, &ctx).await?,
            OrgAction::Oauth { org_id, action } => match *action {
                OrgOauthAction::List => commands::org_oauth_providers::list(&org_id, &ctx).await?,
                OrgOauthAction::Get { provider_id } => {
                    commands::org_oauth_providers::get(&org_id, &provider_id, &ctx).await?
                }
                OrgOauthAction::Create {
                    slug,
                    name,
                    authorization_url,
                    token_url,
                    client_id,
                    client_secret,
                    description,
                    logo_url,
                    userinfo_url,
                    revocation_url,
                    scopes,
                    pkce_required,
                    token_endpoint_auth_method,
                } => {
                    commands::org_oauth_providers::create(
                        &org_id,
                        &slug,
                        &name,
                        &authorization_url,
                        &token_url,
                        &client_id,
                        &client_secret,
                        description.as_deref(),
                        logo_url.as_deref(),
                        userinfo_url.as_deref(),
                        revocation_url.as_deref(),
                        &scopes,
                        pkce_required,
                        token_endpoint_auth_method.as_deref(),
                        &ctx,
                    )
                    .await?
                }
                OrgOauthAction::Update {
                    provider_id,
                    name,
                    description,
                    logo_url,
                    authorization_url,
                    token_url,
                    userinfo_url,
                    revocation_url,
                    client_id,
                    client_secret,
                    scopes,
                    pkce_required,
                    token_endpoint_auth_method,
                    is_active,
                } => {
                    commands::org_oauth_providers::update(
                        &org_id,
                        &provider_id,
                        name.as_deref(),
                        description.as_deref(),
                        logo_url.as_deref(),
                        authorization_url.as_deref(),
                        token_url.as_deref(),
                        userinfo_url.as_deref(),
                        revocation_url.as_deref(),
                        client_id.as_deref(),
                        client_secret.as_deref(),
                        scopes.as_deref(),
                        pkce_required,
                        token_endpoint_auth_method.as_deref(),
                        is_active,
                        &ctx,
                    )
                    .await?
                }
                OrgOauthAction::Delete { provider_id } => {
                    commands::org_oauth_providers::delete(&org_id, &provider_id, &ctx).await?
                }
            },
            OrgAction::Skills { org_id, action } => match *action {
                OrgSkillsAction::List => commands::org_skills::list(&org_id, &ctx).await?,
                OrgSkillsAction::Get { skill_id } => {
                    commands::org_skills::get(&org_id, &skill_id, &ctx).await?
                }
                OrgSkillsAction::Create {
                    slug,
                    display_name,
                    description,
                    path,
                    publish,
                } => {
                    commands::org_skills::create(
                        &org_id,
                        &slug,
                        &display_name,
                        description.as_deref(),
                        &path,
                        publish,
                        &ctx,
                    )
                    .await?
                }
                OrgSkillsAction::Update {
                    skill_id,
                    display_name,
                    description,
                    clear_description,
                    status,
                } => {
                    commands::org_skills::update(
                        &org_id,
                        &skill_id,
                        display_name.as_deref(),
                        description.as_deref(),
                        clear_description,
                        status.as_deref(),
                        &ctx,
                    )
                    .await?
                }
                OrgSkillsAction::Revisions { skill_id } => {
                    commands::org_skills::list_revisions(&org_id, &skill_id, &ctx).await?
                }
                OrgSkillsAction::RevisionGet {
                    skill_id,
                    revision_id,
                } => {
                    commands::org_skills::get_revision(&org_id, &skill_id, &revision_id, &ctx)
                        .await?
                }
                OrgSkillsAction::RevisionCreate {
                    skill_id,
                    path,
                    publish,
                } => {
                    commands::org_skills::create_revision(&org_id, &skill_id, &path, publish, &ctx)
                        .await?
                }
                OrgSkillsAction::Publish {
                    skill_id,
                    revision_id,
                } => {
                    commands::org_skills::publish_revision(&org_id, &skill_id, &revision_id, &ctx)
                        .await?
                }
                OrgSkillsAction::DownloadBundle {
                    skill_id,
                    revision_id,
                    output,
                } => {
                    commands::org_skills::download_bundle(
                        &org_id,
                        &skill_id,
                        &revision_id,
                        output.as_deref(),
                        &ctx,
                    )
                    .await?
                }
            },
            OrgAction::PrivateModelsPolicy { org_id, action } => match action {
                PrivateModelsPolicyAction::Get => {
                    commands::organizations::private_models_policy_get(&org_id, &ctx).await?
                }
                PrivateModelsPolicyAction::Update { body } => {
                    commands::organizations::private_models_policy_update(&org_id, &body, &ctx)
                        .await?
                }
            },
        },
        Commands::Psql {
            project_id,
            branch_id,
            endpoint_id,
            database,
            role,
            pooled,
            ssl,
            psql_args,
        } => {
            commands::psql::run(
                project_id,
                branch_id,
                endpoint_id,
                database,
                role,
                pooled,
                ssl,
                psql_args,
                &ctx,
            )
            .await?
        }
        Commands::Storage { action } => match action {
            StorageAction::Health => commands::storage::health(&ctx).await?,
            StorageAction::Buckets { action } => match action {
                StorageBucketAction::List => commands::storage::list_buckets(&ctx).await?,
            },
            StorageAction::Objects { bucket, action } => match action {
                ObjectStorageObjectAction::List {
                    target,
                    prefix,
                    limit,
                    offset,
                } => {
                    let (bucket, prefix) = commands::object_storage::resolve_bucket_prefix(
                        bucket.as_deref(),
                        target.as_deref(),
                        prefix.as_deref(),
                    )?;
                    commands::storage::list_objects(&bucket, prefix, limit, offset, &ctx).await?
                }
                ObjectStorageObjectAction::Upload {
                    target,
                    key,
                    path,
                    content_type,
                    metadata_json,
                    metadata_file,
                } => {
                    let (bucket, key) = commands::object_storage::resolve_bucket_key(
                        bucket.as_deref(),
                        target.as_deref(),
                        key.as_deref(),
                    )?;
                    commands::storage::upload_object(
                        &bucket,
                        commands::object_storage::UploadObjectOptions {
                            object_key: key,
                            path,
                            content_type,
                            metadata_json,
                            metadata_file,
                        },
                        &ctx,
                    )
                    .await?
                }
                ObjectStorageObjectAction::Download {
                    target,
                    key,
                    output,
                } => {
                    let (bucket, key) = commands::object_storage::resolve_bucket_key(
                        bucket.as_deref(),
                        target.as_deref(),
                        key.as_deref(),
                    )?;
                    let output = commands::storage::resolve_download_output(&key, output)?;
                    commands::storage::download_object(&bucket, &key, output, &ctx).await?
                }
                ObjectStorageObjectAction::Confirm {
                    object_id,
                    sha256,
                    byte_length,
                    etag,
                } => {
                    let bucket = commands::object_storage::resolve_bucket_for_object_id(
                        bucket.as_deref(),
                        None,
                    )?;
                    commands::storage::confirm_object(
                        &bucket,
                        object_id,
                        sha256,
                        byte_length,
                        etag,
                        &ctx,
                    )
                    .await?
                }
                ObjectStorageObjectAction::Delete { object_id, target } => {
                    if let Some(object_id) = object_id {
                        let bucket = commands::object_storage::resolve_bucket_for_object_id(
                            bucket.as_deref(),
                            target.as_deref(),
                        )?;
                        commands::storage::delete_object(&bucket, object_id, &ctx).await?
                    } else {
                        let (bucket, key) = commands::object_storage::resolve_bucket_key(
                            bucket.as_deref(),
                            target.as_deref(),
                            None,
                        )?;
                        commands::storage::delete_object_by_key(&bucket, &key, &ctx).await?
                    }
                }
            },
        },
        Commands::ObjectStorage { org_id, action } => match action {
            ObjectStorageAction::Buckets { action } => match action {
                ObjectStorageBucketAction::List => {
                    commands::object_storage::list_buckets(&org_id, &ctx).await?
                }
                ObjectStorageBucketAction::Create {
                    slug,
                    display_name,
                    metadata_json,
                    metadata_file,
                } => {
                    commands::object_storage::create_bucket(
                        &org_id,
                        slug,
                        display_name,
                        metadata_json,
                        metadata_file,
                        &ctx,
                    )
                    .await?
                }
                ObjectStorageBucketAction::Delete { bucket } => {
                    commands::object_storage::delete_bucket(&org_id, &bucket, &ctx).await?
                }
            },
            ObjectStorageAction::Objects { bucket, action } => match action {
                ObjectStorageObjectAction::List {
                    target,
                    prefix,
                    limit,
                    offset,
                } => {
                    let (bucket, prefix) = commands::object_storage::resolve_bucket_prefix(
                        bucket.as_deref(),
                        target.as_deref(),
                        prefix.as_deref(),
                    )?;
                    commands::object_storage::list_objects(
                        &org_id, &bucket, prefix, limit, offset, &ctx,
                    )
                    .await?
                }
                ObjectStorageObjectAction::Upload {
                    target,
                    key,
                    path,
                    content_type,
                    metadata_json,
                    metadata_file,
                } => {
                    let (bucket, key) = commands::object_storage::resolve_bucket_key(
                        bucket.as_deref(),
                        target.as_deref(),
                        key.as_deref(),
                    )?;
                    commands::object_storage::upload_object(
                        &org_id,
                        &bucket,
                        commands::object_storage::UploadObjectOptions {
                            object_key: key,
                            path,
                            content_type,
                            metadata_json,
                            metadata_file,
                        },
                        &ctx,
                    )
                    .await?
                }
                ObjectStorageObjectAction::Download {
                    target,
                    key,
                    output,
                } => {
                    let (bucket, key) = commands::object_storage::resolve_bucket_key(
                        bucket.as_deref(),
                        target.as_deref(),
                        key.as_deref(),
                    )?;
                    let output = commands::object_storage::resolve_download_output(&key, output)?;
                    commands::object_storage::download_object(&org_id, &bucket, &key, output, &ctx)
                        .await?
                }
                ObjectStorageObjectAction::Confirm {
                    object_id,
                    sha256,
                    byte_length,
                    etag,
                } => {
                    let bucket = commands::object_storage::resolve_bucket_for_object_id(
                        bucket.as_deref(),
                        None,
                    )?;
                    commands::object_storage::confirm_object(
                        &org_id,
                        &bucket,
                        object_id,
                        sha256,
                        byte_length,
                        etag,
                        &ctx,
                    )
                    .await?
                }
                ObjectStorageObjectAction::Delete { object_id, target } => {
                    if let Some(object_id) = object_id {
                        let bucket = commands::object_storage::resolve_bucket_for_object_id(
                            bucket.as_deref(),
                            target.as_deref(),
                        )?;
                        commands::object_storage::delete_object(&org_id, &bucket, object_id, &ctx)
                            .await?
                    } else {
                        let (bucket, key) = commands::object_storage::resolve_bucket_key(
                            bucket.as_deref(),
                            target.as_deref(),
                            None,
                        )?;
                        commands::object_storage::delete_object_by_key(&org_id, &bucket, &key, &ctx)
                            .await?
                    }
                }
            },
        },
        Commands::Projects { action } => match action {
            ProjectAction::List => commands::projects::list(&ctx).await?,
            ProjectAction::Get { id } => commands::projects::get(&id, &ctx).await?,
            ProjectAction::Create {
                name,
                region,
                block_public_connections,
                block_vpc_connections,
                hipaa,
                protected_branches_only,
                compute_unit_min,
                compute_unit_max,
                enable_logical_replication,
                psql,
                set_context,
                ..
            } => {
                commands::projects::create(
                    &name,
                    &region,
                    block_public_connections,
                    block_vpc_connections,
                    hipaa,
                    protected_branches_only,
                    compute_unit_min,
                    compute_unit_max,
                    enable_logical_replication,
                    psql,
                    set_context,
                    &ctx,
                )
                .await?
            }
            ProjectAction::Update {
                id,
                name,
                block_public_connections,
                block_vpc_connections,
                hipaa,
                protected_branches_only,
                compute_unit_min,
                compute_unit_max,
                enable_logical_replication,
            } => {
                commands::projects::update(
                    &id,
                    name.as_deref(),
                    block_public_connections,
                    block_vpc_connections,
                    hipaa,
                    protected_branches_only,
                    compute_unit_min,
                    compute_unit_max,
                    enable_logical_replication,
                    &ctx,
                )
                .await?
            }
            ProjectAction::ConnectionUri {
                id,
                branch_id,
                endpoint_id,
                database,
                role,
                pooled,
                ssl,
            } => {
                commands::projects::connection_uri(
                    &id,
                    branch_id.as_deref(),
                    endpoint_id.as_deref(),
                    database.as_deref(),
                    role.as_deref(),
                    pooled,
                    ssl.as_deref(),
                    &ctx,
                )
                .await?
            }
            ProjectAction::Delete { id, yes } => commands::projects::delete(&id, yes, &ctx).await?,
        },
        Commands::Branches { project_id, action } => match action {
            BranchAction::List => commands::branches::list(&project_id, &ctx).await?,
            BranchAction::Get { id } => commands::branches::get(&project_id, &id, &ctx).await?,
            BranchAction::Create {
                name,
                parent,
                protected,
                archived,
                init_source,
                parent_lsn,
                parent_timestamp,
                no_compute,
                endpoint_type,
                endpoint_settings,
                expires_in,
                schema_only,
                cu,
                suspend_timeout,
                psql,
            } => {
                // Invert: --no-compute means add_endpoint=false, default is true
                let add_endpoint = !no_compute;
                commands::branches::create(
                    &project_id,
                    &name,
                    parent.as_deref(),
                    protected,
                    archived,
                    init_source.as_deref(),
                    parent_lsn.as_deref(),
                    parent_timestamp.as_deref(),
                    add_endpoint,
                    endpoint_type.as_deref(),
                    &endpoint_settings,
                    expires_in.as_deref(),
                    schema_only,
                    cu.as_deref(),
                    suspend_timeout,
                    psql,
                    &ctx,
                )
                .await?
            }
            BranchAction::Delete { id, yes } => {
                commands::branches::delete(&project_id, &id, yes, &ctx).await?
            }
            BranchAction::Rename { id, name } => {
                commands::branches::rename(&project_id, &id, &name, &ctx).await?
            }
            BranchAction::SetDefault { id } => {
                commands::branches::set_default(&project_id, &id, &ctx).await?
            }
            BranchAction::ConnectionString {
                id,
                role,
                pooled,
                ssl,
            } => {
                commands::branches::connection_string(
                    &project_id,
                    &id,
                    pooled,
                    ssl.as_deref(),
                    role.as_deref(),
                    &ctx,
                )
                .await?
            }
            BranchAction::SetExpiration {
                id,
                expires_at,
                no_expiration,
            } => {
                commands::branches::set_expiration(
                    &project_id,
                    &id,
                    expires_at.as_deref(),
                    no_expiration,
                    &ctx,
                )
                .await?
            }
            BranchAction::SchemaDiff {
                base_branch_id,
                compare_branch_id,
                database,
            } => {
                commands::branches::schema_diff(
                    &project_id,
                    &base_branch_id,
                    &compare_branch_id,
                    database.as_deref(),
                    &ctx,
                )
                .await?
            }
            BranchAction::Reset { id } => commands::branches::reset(&project_id, &id, &ctx).await?,
            BranchAction::Restore {
                id,
                source,
                preserve_under_name,
                timestamp,
                lsn,
            } => {
                commands::branches::restore(
                    &project_id,
                    &id,
                    &source,
                    &preserve_under_name,
                    timestamp.as_deref(),
                    lsn.as_deref(),
                    &ctx,
                )
                .await?
            }
        },
        Commands::Databases {
            project_id,
            branch_id,
            action,
        } => match action {
            DatabaseAction::List => {
                commands::databases::list(&project_id, &branch_id, &ctx).await?
            }
            DatabaseAction::Create { name, owner } => {
                commands::databases::create(&project_id, &branch_id, &name, owner.as_deref(), &ctx)
                    .await?
            }
            DatabaseAction::Get { id } => {
                commands::databases::get(&project_id, &branch_id, &id, &ctx).await?
            }
            DatabaseAction::Delete { id } => {
                commands::databases::delete(&project_id, &branch_id, &id, &ctx).await?
            }
        },
        Commands::Database { action } => match action {
            GlobalDatabaseAction::List { project_id } => {
                commands::databases::list_all(project_id.as_deref(), &ctx).await?
            }
        },
        Commands::Roles {
            project_id,
            branch_id,
            action,
        } => match action {
            RoleAction::List => commands::roles::list(&project_id, &branch_id, &ctx).await?,
            RoleAction::Create { name } => {
                commands::roles::create(&project_id, &branch_id, &name, &ctx).await?
            }
            RoleAction::Delete { id } => {
                commands::roles::delete(&project_id, &branch_id, &id, &ctx).await?
            }
            RoleAction::ResetPassword { id } => {
                commands::roles::reset_password(&project_id, &branch_id, &id, &ctx).await?
            }
            RoleAction::RevealPassword { name } => {
                commands::roles::reveal_password(&project_id, &branch_id, &name, &ctx).await?
            }
        },
        Commands::Endpoints {
            project_id,
            branch_id,
            action,
        } => match action {
            EndpointAction::List => {
                commands::endpoints::list(&project_id, &branch_id, &ctx).await?
            }
            EndpointAction::Create {
                name,
                compute_unit,
                autoscaling_min,
                autoscaling_max,
                suspend_timeout,
            } => {
                commands::endpoints::create(
                    &project_id,
                    &branch_id,
                    &name,
                    compute_unit,
                    autoscaling_min,
                    autoscaling_max,
                    suspend_timeout,
                    &ctx,
                )
                .await?
            }
            EndpointAction::Update {
                id,
                autoscaling_min,
                autoscaling_max,
                suspend_timeout,
            } => {
                commands::endpoints::update(
                    &project_id,
                    &branch_id,
                    &id,
                    autoscaling_min,
                    autoscaling_max,
                    suspend_timeout,
                    &ctx,
                )
                .await?
            }
            EndpointAction::Delete { id } => {
                commands::endpoints::delete(&project_id, &branch_id, &id, &ctx).await?
            }
            EndpointAction::Suspend { id } => {
                commands::endpoints::suspend(&project_id, &branch_id, &id, &ctx).await?
            }
            EndpointAction::Start { id } => {
                commands::endpoints::start(&project_id, &branch_id, &id, &ctx).await?
            }
            EndpointAction::Restart { id } => {
                commands::endpoints::restart(&project_id, &id, &ctx).await?
            }
            EndpointAction::Health { id } => {
                commands::endpoints::status(&project_id, &branch_id, &id, &ctx).await?
            }
            EndpointAction::Metrics { id } => {
                commands::endpoints::status(&project_id, &branch_id, &id, &ctx).await?
            }
        },
        Commands::Operations { project_id, action } => match action {
            OperationAction::List => commands::operations::list(&project_id, &ctx).await?,
            OperationAction::Get { id } => {
                commands::operations::get(&project_id, &id, &ctx).await?
            }
        },
        Commands::IpAllowList { project_id, action } => match action {
            IpAllowListAction::List => commands::ip_allow_list::list(&project_id, &ctx).await?,
            IpAllowListAction::Add {
                ip_address,
                description,
            } => {
                commands::ip_allow_list::add(&project_id, &ip_address, description.clone(), &ctx)
                    .await?
            }
            IpAllowListAction::Remove { id } => {
                commands::ip_allow_list::remove(&project_id, &id, &ctx).await?
            }
            IpAllowListAction::Reset { ips } => {
                commands::ip_allow_list::reset(&project_id, &ips, &ctx).await?
            }
        },
        Commands::SetContext { action } => match action {
            ContextAction::Set { project_id, org_id } => {
                commands::context::set(project_id, org_id).await?
            }
            ContextAction::Show => commands::context::show(cli.format).await?,
            ContextAction::Clear => commands::context::clear().await?,
        },
        Commands::Vpc { action } => match action {
            VpcAction::Endpoint { org_id, action } => match action {
                VpcEndpointAction::List { region } => {
                    commands::vpc::endpoint_list(&org_id, region, &ctx).await?
                }
                VpcEndpointAction::Add {
                    region,
                    endpoint_id,
                    label,
                } => {
                    commands::vpc::endpoint_create(&org_id, &region, &endpoint_id, label, &ctx)
                        .await?
                }
                VpcEndpointAction::Get { endpoint_id } => {
                    commands::vpc::endpoint_get(&org_id, &endpoint_id, &ctx).await?
                }
                VpcEndpointAction::Remove { endpoint_id } => {
                    commands::vpc::endpoint_remove(&org_id, &endpoint_id, &ctx).await?
                }
            },
            VpcAction::Project { project_id, action } => match action {
                VpcProjectAction::List => commands::vpc::project_list(&project_id, &ctx).await?,
                VpcProjectAction::Assign {
                    vpc_endpoint_id,
                    label,
                } => {
                    commands::vpc::project_assign(&project_id, &vpc_endpoint_id, label, &ctx)
                        .await?
                }
                VpcProjectAction::Remove { assignment_id } => {
                    commands::vpc::project_remove(&project_id, &assignment_id, &ctx).await?
                }
            },
        },
        Commands::Env { action } => match action {
            EnvAction::Init {
                project_id,
                branch_id,
                env,
                key,
                pooled,
                yes,
            } => commands::env::init(project_id, branch_id, &env, &key, pooled, yes, &ctx).await?,
        },
        Commands::Billing { action } => match action {
            BillingAction::GenerateInvoices { year, month } => {
                commands::billing::generate_invoices(year, month, &ctx).await?
            }
            BillingAction::GetInvoice { invoice_id } => {
                commands::billing::get_invoice(&invoice_id, &ctx).await?
            }
            BillingAction::IssueInvoice { invoice_id } => {
                commands::billing::issue_invoice(&invoice_id, &ctx).await?
            }
            BillingAction::GetUsage {
                organization_id,
                start_date,
                end_date,
            } => {
                commands::billing::get_usage(
                    &organization_id,
                    start_date.as_deref(),
                    end_date.as_deref(),
                    &ctx,
                )
                .await?
            }
            BillingAction::ValidateToken { token } => {
                commands::billing::validate_token(&token, &ctx).await?
            }
            BillingAction::GetBalance { endpoint_id } => {
                commands::billing::get_balance(&endpoint_id, &ctx).await?
            }
            BillingAction::ListPaymentMethods => {
                commands::billing::list_payment_methods(&ctx).await?
            }
            BillingAction::AddPaymentMethod {
                stripe_payment_method_id,
                default,
            } => {
                commands::billing::add_payment_method(&stripe_payment_method_id, default, &ctx)
                    .await?
            }
            BillingAction::RemovePaymentMethod { id } => {
                commands::billing::remove_payment_method(&id, &ctx).await?
            }
            BillingAction::Health => commands::billing::get_health(&ctx).await?,
        },
        Commands::Sessions { action } => match action {
            SessionAction::List => commands::sessions::list(&ctx).await?,
            SessionAction::Revoke { session_id } => {
                commands::sessions::revoke(&session_id, &ctx).await?
            }
            SessionAction::RevokeOthers { keep_session_id } => {
                commands::sessions::revoke_others(&keep_session_id, &ctx).await?
            }
            SessionAction::RevokeAll => commands::sessions::revoke_all(&ctx).await?,
        },
        Commands::Passwords {
            master_password_stdin,
            master_password_file,
            action,
        } => match action {
            PasswordsAction::Vaults { action } => match *action {
                PasswordVaultAction::List => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::list_vaults(options, &ctx).await?
                }
                PasswordVaultAction::Create {
                    name,
                    description,
                    requires_approval,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::create_vault(
                        commands::passwords::VaultCreateOptions {
                            master_password: options.master_password,
                            name,
                            description,
                            requires_approval: requires_approval.map(Into::into),
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordVaultAction::Update {
                    vault_id,
                    name,
                    description,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::update_vault(
                        commands::passwords::VaultUpdateOptions {
                            master_password: options.master_password,
                            vault_id,
                            name,
                            description,
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordVaultAction::Archive { vault_id } => {
                    commands::passwords::archive_vault(vault_id, &ctx).await?
                }
                PasswordVaultAction::Rotate { action } => match action {
                    PasswordVaultRotateAction::Initiate { vault_id } => {
                        commands::passwords::vault_rotation_initiate(vault_id, &ctx).await?
                    }
                    PasswordVaultRotateAction::Complete {
                        vault_id,
                        rotation_token,
                    } => {
                        let options = commands::passwords::PasswordsOptions::from_input(
                            master_password_stdin,
                            master_password_file.as_deref(),
                        )?;
                        commands::passwords::vault_rotation_complete(
                            commands::passwords::VaultRotationCompleteOptions {
                                master_password: options.master_password,
                                vault_id,
                                rotation_token,
                            },
                            &ctx,
                        )
                        .await?
                    }
                    PasswordVaultRotateAction::Cancel {
                        vault_id,
                        rotation_token,
                    } => {
                        commands::passwords::vault_rotation_cancel(
                            commands::passwords::VaultRotationCancelOptions {
                                vault_id,
                                rotation_token,
                            },
                            &ctx,
                        )
                        .await?
                    }
                },
            },
            PasswordsAction::Items { action } => {
                // A single stdin stream has no framing to split the master
                // password from an item secret, so reject reading both from it.
                let leaf_reads_stdin = match action.as_ref() {
                    PasswordItemAction::Login { password_stdin, .. } => *password_stdin,
                    PasswordItemAction::ApiKey { key_stdin, .. } => *key_stdin,
                    PasswordItemAction::Note { body_stdin, .. } => *body_stdin,
                    PasswordItemAction::Update {
                        password_stdin,
                        key_stdin,
                        body_stdin,
                        ..
                    } => *password_stdin || *key_stdin || *body_stdin,
                    _ => false,
                };
                if master_password_stdin && leaf_reads_stdin {
                    anyhow::bail!(
                        "cannot read the master password and an item secret from stdin at once; use --master-password-file with --password-stdin, --key-stdin, or --body-stdin"
                    );
                }
                let options = commands::passwords::PasswordsOptions::from_input(
                    master_password_stdin,
                    master_password_file.as_deref(),
                )?;
                match *action {
                    PasswordItemAction::Login {
                        vault_id,
                        title,
                        username,
                        password,
                        password_stdin,
                        urls,
                        notes,
                        tags,
                        sensitive,
                    } => {
                        commands::passwords::create_login(
                            options,
                            commands::passwords::LoginCreateOptions {
                                vault_id,
                                title,
                                username,
                                password,
                                password_stdin,
                                urls,
                                notes,
                                tags,
                                sensitive,
                            },
                            &ctx,
                        )
                        .await?
                    }
                    PasswordItemAction::ApiKey {
                        vault_id,
                        title,
                        key,
                        key_stdin,
                        credential_kind,
                        notes,
                        tags,
                        sensitive,
                    } => {
                        commands::passwords::create_api_credential(
                            options,
                            commands::passwords::ApiCredentialCreateOptions {
                                vault_id,
                                title,
                                key,
                                key_stdin,
                                credential_kind,
                                notes,
                                tags,
                                sensitive,
                            },
                            &ctx,
                        )
                        .await?
                    }
                    PasswordItemAction::Note {
                        vault_id,
                        title,
                        body,
                        body_stdin,
                        tags,
                        sensitive,
                    } => {
                        commands::passwords::create_secure_note(
                            options,
                            commands::passwords::SecureNoteCreateOptions {
                                vault_id,
                                title,
                                body,
                                body_stdin,
                                tags,
                                sensitive,
                            },
                            &ctx,
                        )
                        .await?
                    }
                    PasswordItemAction::List { vault_id } => {
                        commands::passwords::list_items(options, vault_id, &ctx).await?
                    }
                    PasswordItemAction::Get {
                        vault_id,
                        item_id,
                        reveal,
                    } => {
                        commands::passwords::get_item(options, vault_id, item_id, reveal, &ctx)
                            .await?
                    }
                    PasswordItemAction::Delete { vault_id, item_id } => {
                        commands::passwords::delete_item(options, vault_id, item_id, &ctx).await?
                    }
                    PasswordItemAction::Restore { vault_id, item_id } => {
                        commands::passwords::restore_item(options, vault_id, item_id, &ctx).await?
                    }
                    PasswordItemAction::Duplicate {
                        vault_id,
                        item_id,
                        target_vault_id,
                    } => {
                        commands::passwords::copy_item(
                            options,
                            vault_id,
                            item_id,
                            target_vault_id,
                            &ctx,
                        )
                        .await?
                    }
                    PasswordItemAction::Move {
                        vault_id,
                        item_id,
                        target_vault_id,
                    } => {
                        commands::passwords::move_item(
                            options,
                            vault_id,
                            item_id,
                            target_vault_id,
                            &ctx,
                        )
                        .await?
                    }
                    PasswordItemAction::Update {
                        vault_id,
                        item_id,
                        title,
                        tags,
                        sensitive,
                        password,
                        password_stdin,
                        username,
                        urls,
                        key,
                        key_stdin,
                        credential_kind,
                        body,
                        body_stdin,
                        notes,
                    } => {
                        commands::passwords::update_item(
                            options,
                            commands::passwords::ItemUpdateOptions {
                                vault_id,
                                item_id,
                                title,
                                tags,
                                sensitive,
                                password,
                                password_stdin,
                                username,
                                urls,
                                key,
                                key_stdin,
                                credential_kind,
                                body,
                                body_stdin,
                                notes,
                            },
                            &ctx,
                        )
                        .await?
                    }
                }
            }
            PasswordsAction::Attachments { action } => {
                let options = commands::passwords::PasswordsOptions::from_input(
                    master_password_stdin,
                    master_password_file.as_deref(),
                )?;
                match action {
                    PasswordAttachmentAction::Upload {
                        vault_id,
                        item_id,
                        path,
                        filename,
                        content_type,
                    } => {
                        commands::passwords::attachment_upload(
                            options,
                            vault_id,
                            item_id,
                            path,
                            filename,
                            content_type,
                            &ctx,
                        )
                        .await?
                    }
                    PasswordAttachmentAction::List { vault_id, item_id } => {
                        commands::passwords::attachment_list(options, vault_id, item_id, &ctx)
                            .await?
                    }
                    PasswordAttachmentAction::Download {
                        vault_id,
                        item_id,
                        attachment_id,
                        output,
                    } => {
                        commands::passwords::attachment_download(
                            options,
                            vault_id,
                            item_id,
                            attachment_id,
                            output,
                            &ctx,
                        )
                        .await?
                    }
                    PasswordAttachmentAction::Delete {
                        vault_id,
                        item_id,
                        attachment_id,
                    } => {
                        commands::passwords::attachment_delete(
                            options,
                            vault_id,
                            item_id,
                            attachment_id,
                            &ctx,
                        )
                        .await?
                    }
                }
            }
            PasswordsAction::Agent { action } => match action {
                PasswordAgentAction::Provision {
                    vault,
                    access,
                    name,
                    expires_in_days,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    let access = match access {
                        AgentAccessArg::Read => "read",
                        AgentAccessArg::Write => "write",
                    };
                    commands::passwords::agent_provision(
                        options,
                        commands::passwords::AgentProvisionOptions {
                            vault,
                            access: access.to_string(),
                            name,
                            expires_in_days,
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordAgentAction::List => commands::passwords::agent_list(&ctx).await?,
                PasswordAgentAction::Freeze => commands::passwords::agent_freeze(&ctx).await?,
                PasswordAgentAction::Revoke { agent_id, vault } => {
                    commands::passwords::agent_revoke(agent_id, vault, &ctx).await?
                }
            },
            PasswordsAction::Audit { action } => match action {
                PasswordAuditAction::List {
                    action,
                    actor_identity_id,
                    target_kind,
                    target_id,
                    from,
                    to,
                    limit,
                    offset,
                } => {
                    commands::passwords::audit_list(
                        commands::passwords::PasswordAuditListOptions {
                            action,
                            actor_identity_id,
                            target_kind,
                            target_id,
                            from,
                            to,
                            limit,
                            offset,
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordAuditAction::Verify => commands::passwords::audit_verify(&ctx).await?,
            },
            PasswordsAction::Approvals { action } => match action {
                PasswordApprovalAction::Request {
                    target_kind,
                    target_id,
                    timeout_seconds,
                } => {
                    commands::passwords::approval_request(
                        target_kind.into(),
                        target_id,
                        timeout_seconds,
                        &ctx,
                    )
                    .await?
                }
                PasswordApprovalAction::List => commands::passwords::approval_list(&ctx).await?,
                PasswordApprovalAction::Get { approval_id } => {
                    commands::passwords::approval_get(approval_id, &ctx).await?
                }
                PasswordApprovalAction::Approve { approval_id } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::approval_approve(options, approval_id, &ctx).await?
                }
                PasswordApprovalAction::Deny { approval_id } => {
                    commands::passwords::approval_deny(approval_id, &ctx).await?
                }
            },
            PasswordsAction::Memberships { action } => match action {
                PasswordMembershipAction::List { vault_id } => {
                    commands::passwords::membership_list(vault_id, &ctx).await?
                }
                PasswordMembershipAction::Grant {
                    vault_id,
                    identity_id,
                    access,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::membership_grant(
                        commands::passwords::MembershipGrantOptions {
                            master_password: options.master_password,
                            vault_id,
                            identity_id,
                            access_level: access.into(),
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordMembershipAction::Revoke {
                    vault_id,
                    identity_id,
                } => commands::passwords::membership_revoke(vault_id, identity_id, &ctx).await?,
            },
            PasswordsAction::Invitations { action } => match action {
                PasswordInvitationAction::Create {
                    vault_id,
                    email,
                    access,
                    expires_in_hours,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::invitation_create(
                        commands::passwords::InvitationCreateOptions {
                            master_password: options.master_password,
                            vault_id,
                            email,
                            access_level: access.into(),
                            expires_in_hours,
                        },
                        &ctx,
                    )
                    .await?
                }
                PasswordInvitationAction::List { vault_id } => {
                    commands::passwords::invitation_list(vault_id, &ctx).await?
                }
                PasswordInvitationAction::Redeem { token } => {
                    commands::passwords::invitation_redeem(token, &ctx).await?
                }
                PasswordInvitationAction::Complete {
                    vault_id,
                    invitation_id,
                } => {
                    let options = commands::passwords::PasswordsOptions::from_input(
                        master_password_stdin,
                        master_password_file.as_deref(),
                    )?;
                    commands::passwords::invitation_complete(
                        commands::passwords::InvitationCompleteOptions {
                            master_password: options.master_password,
                            vault_id,
                            invitation_id,
                        },
                        &ctx,
                    )
                    .await?
                }
            },
            PasswordsAction::GeneratePassword {
                mode,
                length,
                upper,
                lower,
                digits,
                symbols,
                word_count,
                separator,
                capitalize_first,
            } => commands::passwords::generate_password(
                commands::passwords::PasswordGenerateOptions {
                    mode,
                    length,
                    upper,
                    lower,
                    digits,
                    symbols,
                    word_count,
                    separator,
                    capitalize_first,
                },
                &ctx,
            )?,
            PasswordsAction::Shares { action } => match action {
                PasswordShareAction::Outbound { vault_id } => {
                    commands::passwords::share_list_outbound(vault_id, &ctx).await?
                }
                PasswordShareAction::Received => {
                    commands::passwords::share_list_received(&ctx).await?
                }
                PasswordShareAction::Revoke { share_id } => {
                    commands::passwords::share_revoke(share_id, &ctx).await?
                }
            },
            PasswordsAction::Export {
                vault_id,
                output,
                exclude_attachments,
            } => {
                let options = commands::passwords::PasswordsOptions::from_input(
                    master_password_stdin,
                    master_password_file.as_deref(),
                )?;
                commands::passwords::export_vault(
                    options,
                    vault_id,
                    output,
                    exclude_attachments,
                    &ctx,
                )
                .await?
            }
            PasswordsAction::Import { vault_id, input } => {
                let options = commands::passwords::PasswordsOptions::from_input(
                    master_password_stdin,
                    master_password_file.as_deref(),
                )?;
                commands::passwords::import_vault(options, vault_id, input, &ctx).await?
            }
        },
        Commands::Webhooks { org_id, action } => match action {
            WebhookAction::List => commands::webhooks::list(&org_id, &ctx).await?,
            WebhookAction::Get { webhook_id } => {
                commands::webhooks::get(&org_id, &webhook_id, &ctx).await?
            }
            WebhookAction::Create {
                name,
                url,
                events,
                project_id,
            } => {
                commands::webhooks::create(
                    &org_id,
                    &name,
                    &url,
                    events,
                    project_id.as_deref(),
                    &ctx,
                )
                .await?
            }
            WebhookAction::Update {
                webhook_id,
                name,
                url,
                events,
                enabled,
            } => {
                commands::webhooks::update(&org_id, &webhook_id, name, url, events, enabled, &ctx)
                    .await?
            }
            WebhookAction::Delete { webhook_id } => {
                commands::webhooks::delete(&org_id, &webhook_id, &ctx).await?
            }
            WebhookAction::RotateSecret { webhook_id } => {
                commands::webhooks::rotate_secret(&org_id, &webhook_id, &ctx).await?
            }
            WebhookAction::Deliveries { webhook_id } => {
                commands::webhooks::list_deliveries(&org_id, &webhook_id, &ctx).await?
            }
            WebhookAction::EventTypes => commands::webhooks::list_event_types(&ctx).await?,
        },
        Commands::AuditLogs { org_id, action } => match action {
            AuditLogAction::List { limit, offset } => {
                commands::audit_logs::list(&org_id, Some(limit), Some(offset), &ctx).await?
            }
            AuditLogAction::Get { log_id } => {
                commands::audit_logs::get(&org_id, &log_id, &ctx).await?
            }
        },
        Commands::Rbac { org_id, action } => match action {
            RbacAction::ListRoles => commands::rbac::list_roles(&org_id, &ctx).await?,
            RbacAction::GetRole { role_id } => {
                commands::rbac::get_role(&org_id, &role_id, &ctx).await?
            }
            RbacAction::CreateRole {
                name,
                description,
                permissions,
            } => {
                commands::rbac::create_role(&org_id, &name, description, permissions, &ctx).await?
            }
            RbacAction::UpdateRole {
                role_id,
                name,
                description,
                permissions,
            } => {
                commands::rbac::update_role(&org_id, &role_id, name, description, permissions, &ctx)
                    .await?
            }
            RbacAction::DeleteRole { role_id } => {
                commands::rbac::delete_role(&org_id, &role_id, &ctx).await?
            }
            RbacAction::AssignRole { member_id, role_id } => {
                commands::rbac::assign_role(&org_id, &member_id, &role_id, &ctx).await?
            }
            RbacAction::ListPermissions => commands::rbac::list_permissions(&ctx).await?,
            RbacAction::MyPermissions => commands::rbac::my_permissions(&org_id, &ctx).await?,
        },
        Commands::BranchProtection { project_id, action } => match action {
            BranchProtectionAction::List => {
                commands::branch_protection::list(&project_id, &ctx).await?
            }
            BranchProtectionAction::Get { branch_id } => {
                commands::branch_protection::get(&project_id, &branch_id, &ctx).await?
            }
            BranchProtectionAction::Create {
                branch_id,
                prevent_deletion,
                prevent_reset,
                require_approval,
                bypass_roles,
            } => {
                commands::branch_protection::create(
                    &project_id,
                    &branch_id,
                    prevent_deletion,
                    prevent_reset,
                    require_approval,
                    bypass_roles,
                    &ctx,
                )
                .await?
            }
            BranchProtectionAction::Update {
                branch_id,
                prevent_deletion,
                prevent_reset,
                require_approval,
                bypass_roles,
            } => {
                commands::branch_protection::update(
                    &project_id,
                    &branch_id,
                    prevent_deletion,
                    prevent_reset,
                    require_approval,
                    bypass_roles,
                    &ctx,
                )
                .await?
            }
            BranchProtectionAction::Delete { branch_id } => {
                commands::branch_protection::delete(&project_id, &branch_id, &ctx).await?
            }
        },
        Commands::Replication { project_id, action } => match action {
            ReplicationAction::Settings => {
                commands::replication::get_settings(&project_id, &ctx).await?
            }
            ReplicationAction::Enable => commands::replication::enable(&project_id, &ctx).await?,
            ReplicationAction::ListPublications { branch_id } => {
                commands::replication::list_publications(&project_id, &branch_id, &ctx).await?
            }
            ReplicationAction::CreatePublication {
                branch_id,
                name,
                tables,
                all_tables,
            } => {
                commands::replication::create_publication(
                    &project_id,
                    &branch_id,
                    &name,
                    tables,
                    all_tables,
                    &ctx,
                )
                .await?
            }
            ReplicationAction::UpdatePublication {
                branch_id,
                publication_id,
                tables,
                all_tables,
            } => {
                commands::replication::update_publication(
                    &project_id,
                    &branch_id,
                    &publication_id,
                    tables,
                    all_tables,
                    &ctx,
                )
                .await?
            }
            ReplicationAction::DeletePublication {
                branch_id,
                publication_id,
            } => {
                commands::replication::delete_publication(
                    &project_id,
                    &branch_id,
                    &publication_id,
                    &ctx,
                )
                .await?
            }
            ReplicationAction::ListSlots { branch_id } => {
                commands::replication::list_slots(&project_id, &branch_id, &ctx).await?
            }
            ReplicationAction::CreateSlot {
                branch_id,
                name,
                plugin,
            } => {
                commands::replication::create_slot(&project_id, &branch_id, &name, plugin, &ctx)
                    .await?
            }
            ReplicationAction::DeleteSlot { branch_id, slot_id } => {
                commands::replication::delete_slot(&project_id, &branch_id, &slot_id, &ctx).await?
            }
        },
        Commands::Mcp { action } => match action {
            McpAction::Start => seren_mcp::run(seren_mcp::McpMode::Stdio).await?,
            McpAction::StartHttp => seren_mcp::run(seren_mcp::McpMode::Http).await?,
            McpAction::StartServer => seren_mcp::run(seren_mcp::McpMode::Server).await?,
        },
        Commands::Agent { action } => match *action {
            AgentAction::ListPublishers => commands::agent::list_publishers(&ctx).await?,
            AgentAction::GetPublisher { publisher } => {
                commands::agent::get_publisher(&publisher, &ctx).await?
            }
            AgentAction::PublisherSkillDoc { publisher } => {
                commands::agent::get_publisher_skill_doc(&publisher, &ctx).await?
            }
            AgentAction::ApiSkillDoc => commands::agent::get_seren_api_skill_doc(&ctx).await?,
            AgentAction::GetDepositRequirements {
                publisher,
                amount,
                agent_wallet,
            } => {
                commands::agent::get_deposit_requirements(&publisher, &amount, &agent_wallet, &ctx)
                    .await?
            }
            AgentAction::GetSupported => commands::agent::get_supported(&ctx).await?,
            AgentAction::CreatePublisher {
                organization_id,
                name,
                slug,
                email,
                wallet_address,
                wallet_network_id,
                publisher_category,
                database_type,
                integration_type,
                description,
                api_url,
                mcp_endpoint,
                project_id,
                branch_id,
                database_name,
                base_price_per_1000_rows,
                billing_model,
                upstream_cost_response_path,
                connection_string,
                upstream_api_key,
                database_config_json,
                auth_type,
                allowed_passthrough_headers,
                oauth2_token_url,
                oauth2_client_id,
                oauth2_client_secret,
                oauth2_scopes,
                use_cases,
            } => {
                commands::agent::create_publisher(
                    &organization_id,
                    &name,
                    &slug,
                    email.as_deref(),
                    &wallet_address,
                    &wallet_network_id,
                    &publisher_category,
                    database_type.as_deref(),
                    integration_type.as_deref(),
                    description.as_deref(),
                    api_url.as_deref(),
                    mcp_endpoint.as_deref(),
                    project_id,
                    branch_id,
                    database_name.as_deref(),
                    base_price_per_1000_rows.as_deref(),
                    billing_model.as_deref(),
                    upstream_cost_response_path.as_deref(),
                    connection_string.as_deref(),
                    upstream_api_key.as_deref(),
                    database_config_json.as_deref(),
                    auth_type.as_deref(),
                    allowed_passthrough_headers,
                    oauth2_token_url.as_deref(),
                    oauth2_client_id.as_deref(),
                    oauth2_client_secret.as_deref(),
                    oauth2_scopes.unwrap_or_default(),
                    use_cases,
                    &ctx,
                )
                .await?
            }
            AgentAction::ExecuteQuery {
                publisher,
                query,
                database,
            } => {
                commands::agent::execute_query(&publisher, &query, database.as_deref(), &ctx)
                    .await?
            }
            AgentAction::GetPrepaidBalance => commands::agent::get_prepaid_balance(&ctx).await?,
            AgentAction::CreatePrepaidDeposit { amount } => {
                commands::agent::create_prepaid_deposit(amount.0, &ctx).await?
            }
            AgentAction::EstimateQueryCost { publisher, query } => {
                commands::agent::estimate_query_cost(&publisher, &query, &ctx).await?
            }
            AgentAction::GetTransactionHistory { limit, offset } => {
                commands::agent::get_transaction_history(limit, offset, &ctx).await?
            }
            AgentAction::PreviewTransfer {
                recipient_email,
                amount,
                memo,
            } => {
                commands::agent::preview_transfer(&recipient_email, amount.0, memo.as_deref(), &ctx)
                    .await?
            }
            AgentAction::SendTransfer {
                recipient_email,
                amount,
                memo,
                idempotency_key,
            } => {
                commands::agent::send_transfer(
                    &recipient_email,
                    amount.0,
                    memo.as_deref(),
                    &idempotency_key,
                    &ctx,
                )
                .await?
            }
            AgentAction::ListTransfers {
                direction,
                status,
                cursor,
                limit,
            } => {
                commands::agent::list_transfers(
                    direction.as_deref(),
                    status.as_deref(),
                    cursor.as_deref(),
                    limit,
                    &ctx,
                )
                .await?
            }
            AgentAction::ClaimTransfer { token } => {
                commands::agent::claim_transfer(&token, &ctx).await?
            }
            AgentAction::RecallTransfer {
                pending_transfer_id,
            } => commands::agent::recall_transfer(pending_transfer_id, &ctx).await?,
            // Template commands
            AgentAction::ListTemplates {
                language,
                verified_only,
                search,
                limit,
            } => {
                commands::agent::list_templates(
                    language.as_deref(),
                    verified_only,
                    search.as_deref(),
                    limit,
                    &ctx,
                )
                .await?
            }
            AgentAction::GetTemplate { slug } => commands::agent::get_template(&slug, &ctx).await?,
            AgentAction::PublishTemplate {
                name,
                slug,
                code,
                language,
                price,
                description,
                dependencies,
                compute_backend,
            } => {
                commands::agent::publish_template(
                    &name,
                    &slug,
                    &code,
                    &language,
                    &price,
                    description.as_deref(),
                    dependencies.as_deref(),
                    compute_backend.as_deref(),
                    &ctx,
                )
                .await?
            }
            AgentAction::InvokeTemplate { slug, input } => {
                commands::agent::invoke_template(&slug, &input, &ctx).await?
            }
            AgentAction::RunCloud { publisher, message } => {
                commands::agent::run_cloud(&publisher, &message, &ctx).await?
            }
            AgentAction::RunLocal {
                endpoint,
                message,
                stream,
            } => commands::agent::run_local(&endpoint, &message, stream, &ctx).await?,
            AgentAction::Dev {
                path,
                name,
                agent_slug,
                dry_run,
            } => {
                commands::agent_dev::dev_agent_run(
                    commands::agent_dev::DevAgentOptions {
                        directory: std::path::PathBuf::from(path),
                        name,
                        agent_slug,
                        // `dev_agent_run` populates this from the auth context
                        // when None so the CLI does not have to.
                        user_discriminator: None,
                        dry_run,
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::Deploy {
                path,
                publisher,
                name,
                environment_id,
                mode,
                cron_schedule,
                cron_timezone,
                eval_gate_set_id,
                eval_gate_max_age_seconds,
                compute_backend,
                runtime_kind,
                config,
                env_file,
                orchestration_config,
            } => {
                commands::agent::cloud_deploy(
                    &path,
                    commands::agent::CloudDeployOptions {
                        publisher_slug: Some(&publisher),
                        name: name.as_deref(),
                        environment_id,
                        mode: &mode,
                        cron_schedule: cron_schedule.as_deref(),
                        cron_timezone: cron_timezone.as_deref(),
                        eval_gate_set_id,
                        eval_gate_max_age_seconds,
                        compute_backend: compute_backend.as_deref(),
                        runtime_kind: runtime_kind.as_deref(),
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                        orchestration_config_path: orchestration_config.as_deref(),
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::DeployPrompt {
                name,
                agent_slug,
                mode,
                cron_schedule,
                cron_timezone,
                eval_gate_set_id,
                eval_gate_max_age_seconds,
                compute_backend,
                template,
                tool_presets,
                approval_policy,
                model_policy,
                allowed_remote_agent_origins,
                prompt,
                model_id,
                visibility,
                config,
                env_file,
                agent_config,
                capability_policy,
                capability_policy_file,
            } => {
                commands::agent::cloud_deploy_prompt(
                    commands::agent::CloudDeployPromptOptions {
                        name: &name,
                        agent_slug: agent_slug.as_deref(),
                        mode: &mode,
                        cron_schedule: cron_schedule.as_deref(),
                        cron_timezone: cron_timezone.as_deref(),
                        eval_gate_set_id,
                        eval_gate_max_age_seconds,
                        compute_backend: compute_backend.as_deref(),
                        template: template.as_deref(),
                        tool_presets: &tool_presets,
                        approval_policy: approval_policy.as_deref(),
                        model_policy: model_policy.as_deref(),
                        allowed_remote_agent_origins: &allowed_remote_agent_origins,
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                        agent_config_path: agent_config.as_deref(),
                        capability_policy_json: capability_policy.as_deref(),
                        capability_policy_path: capability_policy_file.as_deref(),
                        prompt: prompt.as_deref(),
                        model_id: model_id.as_deref(),
                        visibility: visibility.as_deref(),
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::PrivateModels { action } => match action {
                PrivateModelsAction::List => commands::agent::private_models_list(&ctx).await?,
                PrivateModelsAction::Catalog { region } => {
                    commands::agent::private_models_catalog(region.as_deref(), &ctx).await?
                }
                PrivateModelsAction::Chat {
                    model,
                    message,
                    messages_json,
                    temperature,
                    max_tokens,
                    top_p,
                    top_k,
                    response_schema_json,
                    tools_json,
                } => {
                    commands::agent::private_models_chat(
                        commands::agent::PrivateModelsChatOptions {
                            model: model.as_deref(),
                            message: message.as_deref(),
                            messages_json: messages_json.as_deref(),
                            temperature,
                            max_tokens,
                            top_p,
                            top_k,
                            response_schema_json: response_schema_json.as_deref(),
                            tools_json: tools_json.as_deref(),
                        },
                        &ctx,
                    )
                    .await?
                }
            },
            AgentAction::ManagedCapabilities => {
                commands::agent::managed_agent_capabilities(&ctx).await?
            }
            AgentAction::ManagedList => commands::agent::managed_agent_list(&ctx).await?,
            AgentAction::ManagedHealth => commands::agent::managed_agent_health(&ctx).await?,
            AgentAction::ManagedTestRun { body } => {
                commands::agent::managed_agent_test_run(&body, &ctx).await?
            }
            AgentAction::ManagedGet { deployment_id } => {
                commands::agent::managed_agent_get(deployment_id, &ctx).await?
            }
            AgentAction::ManagedDeploymentResources { deployment_id } => {
                commands::agent::managed_agent_deployment_resources(deployment_id, &ctx).await?
            }
            AgentAction::ManagedDeploymentTools { deployment_id, q } => {
                commands::agent::managed_agent_deployment_tools(deployment_id, q.as_deref(), &ctx)
                    .await?
            }
            AgentAction::ManagedDeploymentTool {
                deployment_id,
                tool_name,
            } => {
                commands::agent::managed_agent_deployment_tool(
                    deployment_id,
                    tool_name.as_str(),
                    &ctx,
                )
                .await?
            }
            AgentAction::ManagedDeploymentToolGroups { deployment_id } => {
                commands::agent::managed_agent_deployment_tool_groups(deployment_id, &ctx).await?
            }
            AgentAction::ManagedDeploymentActivity {
                deployment_id,
                limit,
                offset,
            } => {
                commands::agent::managed_agent_deployment_activity(
                    deployment_id,
                    Some(limit),
                    Some(offset),
                    &ctx,
                )
                .await?
            }
            AgentAction::ManagedDeploymentHealth { deployment_id } => {
                commands::agent::managed_agent_deployment_health(deployment_id, &ctx).await?
            }
            AgentAction::ManagedRevisions { deployment_id } => {
                commands::agent::managed_agent_revisions(deployment_id, &ctx).await?
            }
            AgentAction::ManagedStart { deployment_id } => {
                commands::agent::managed_agent_start(deployment_id, &ctx).await?
            }
            AgentAction::ManagedStop { deployment_id } => {
                commands::agent::managed_agent_stop(deployment_id, &ctx).await?
            }
            AgentAction::ManagedDelete { deployment_id } => {
                commands::agent::managed_agent_delete(deployment_id, &ctx).await?
            }
            AgentAction::ManagedRollbackPreview {
                deployment_id,
                revision_id,
            } => {
                commands::agent::managed_agent_rollback_preview(deployment_id, revision_id, &ctx)
                    .await?
            }
            AgentAction::ManagedRollback {
                deployment_id,
                revision_id,
            } => commands::agent::managed_agent_rollback(deployment_id, revision_id, &ctx).await?,
            AgentAction::ManagedPreview {
                deployment_id,
                name,
                agent_slug,
                cron_schedule,
                cron_timezone,
                eval_gate_set_id,
                eval_gate_max_age_seconds,
                clear_eval_gate,
                template,
                tool_presets,
                approval_policy,
                model_policy,
                allowed_remote_agent_origins,
                prompt,
                model_id,
                visibility,
                config,
                env_file,
                agent_config,
                capability_policy,
                capability_policy_file,
                clear_capability_policy,
            } => {
                commands::agent::managed_agent_preview(
                    deployment_id,
                    commands::agent::ManagedAgentUpdateOptions {
                        name: name.as_deref(),
                        agent_slug: agent_slug.as_deref(),
                        cron_schedule: cron_schedule.as_deref(),
                        cron_timezone: cron_timezone.as_deref(),
                        eval_gate_set_id,
                        eval_gate_max_age_seconds,
                        clear_eval_gate,
                        template: template.as_deref(),
                        tool_presets: &tool_presets,
                        approval_policy: approval_policy.as_deref(),
                        model_policy: model_policy.as_deref(),
                        allowed_remote_agent_origins: &allowed_remote_agent_origins,
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                        agent_config_path: agent_config.as_deref(),
                        capability_policy_json: capability_policy.as_deref(),
                        capability_policy_path: capability_policy_file.as_deref(),
                        clear_capability_policy,
                        prompt: prompt.as_deref(),
                        model_id: model_id.as_deref(),
                        visibility: visibility.as_deref(),
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::ManagedUpdate {
                deployment_id,
                name,
                agent_slug,
                cron_schedule,
                cron_timezone,
                eval_gate_set_id,
                eval_gate_max_age_seconds,
                clear_eval_gate,
                template,
                tool_presets,
                approval_policy,
                model_policy,
                allowed_remote_agent_origins,
                prompt,
                model_id,
                visibility,
                config,
                env_file,
                agent_config,
                capability_policy,
                capability_policy_file,
                clear_capability_policy,
            } => {
                commands::agent::managed_agent_update(
                    deployment_id,
                    commands::agent::ManagedAgentUpdateOptions {
                        name: name.as_deref(),
                        agent_slug: agent_slug.as_deref(),
                        cron_schedule: cron_schedule.as_deref(),
                        cron_timezone: cron_timezone.as_deref(),
                        eval_gate_set_id,
                        eval_gate_max_age_seconds,
                        clear_eval_gate,
                        template: template.as_deref(),
                        tool_presets: &tool_presets,
                        approval_policy: approval_policy.as_deref(),
                        model_policy: model_policy.as_deref(),
                        allowed_remote_agent_origins: &allowed_remote_agent_origins,
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                        agent_config_path: agent_config.as_deref(),
                        capability_policy_json: capability_policy.as_deref(),
                        capability_policy_path: capability_policy_file.as_deref(),
                        clear_capability_policy,
                        prompt: prompt.as_deref(),
                        model_id: model_id.as_deref(),
                        visibility: visibility.as_deref(),
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::Cloud { action } => execute_agent_cloud_action(*action, &ctx).await?,
            AgentAction::TasksList {
                org_id,
                limit,
                offset,
            } => commands::agent::list_agent_tasks(&org_id, limit, offset, &ctx).await?,
            AgentAction::TasksGet {
                org_id,
                task_id,
                follow,
            } => commands::agent::get_agent_task(&org_id, &task_id, follow, &ctx).await?,
            AgentAction::TasksCancel { org_id, task_id } => {
                commands::agent::cancel_agent_task(&org_id, &task_id, &ctx).await?
            }
        },
        Commands::Skills { action } => match action {
            SkillsAction::List { refresh } => commands::skills::list(refresh, &ctx).await?,
            SkillsAction::Search { query } => commands::skills::search(&query, &ctx).await?,
            SkillsAction::Show { slug } => commands::skills::show(&slug, &ctx).await?,
            SkillsAction::Add { slug, all, yes } => {
                commands::skills::add(slug.as_deref(), all, yes).await?
            }
            SkillsAction::Installed => commands::skills::installed(&ctx).await?,
            SkillsAction::Remove { slug } => commands::skills::remove(&slug).await?,
            SkillsAction::Update { slug, yes } => {
                commands::skills::update(slug.as_deref(), yes).await?
            }
            SkillsAction::Init { name, path } => {
                commands::skills::init(name.as_deref(), path.as_deref())?
            }
        },
        Commands::Oauth { action } => match action {
            OAuthAction::Providers => commands::oauth::list_providers(&ctx).await?,
            OAuthAction::Connections => commands::oauth::list_connections(&ctx).await?,
            OAuthAction::Connect { provider_slug } => {
                commands::oauth::connect(&provider_slug, &ctx).await?
            }
            OAuthAction::Disconnect { connection } => {
                commands::oauth::disconnect(&connection, &ctx).await?
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cli_with_large_stack(args: Vec<&'static str>) -> Cli {
        std::thread::Builder::new()
            .name("cli-parse-test".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(args).expect("cli parse should succeed"))
            .expect("failed to spawn parser thread")
            .join()
            .expect("parser thread panicked")
    }

    fn try_parse_cli_with_large_stack(args: Vec<&'static str>) -> Result<Cli, clap::Error> {
        std::thread::Builder::new()
            .name("cli-try-parse-test".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(args))
            .expect("failed to spawn parser thread")
            .join()
            .expect("parser thread panicked")
    }

    #[test]
    fn agent_publisher_skill_doc_accepts_primary_name_and_alias() {
        let primary = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "publisher-skill-doc",
            "seren-agent",
        ]);
        match primary.command {
            Commands::Agent { action } => match *action {
                AgentAction::PublisherSkillDoc { publisher } => {
                    assert_eq!(publisher, "seren-agent");
                }
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let alias = parse_cli_with_large_stack(vec!["seren", "agent", "skill-doc", "seren-db"]);
        match alias.command {
            Commands::Agent { action } => match *action {
                AgentAction::PublisherSkillDoc { publisher } => {
                    assert_eq!(publisher, "seren-db");
                }
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn agent_api_skill_doc_accepts_primary_name_and_alias() {
        for name in ["api-skill-doc", "seren-skill-doc"] {
            let cli = parse_cli_with_large_stack(vec!["seren", "agent", name]);
            match cli.command {
                Commands::Agent { action } => match *action {
                    AgentAction::ApiSkillDoc => {}
                    _ => panic!("unexpected agent action parsed for {name}"),
                },
                _ => panic!("unexpected command parsed for {name}"),
            }
        }
    }

    #[test]
    fn role_reset_password_accepts_no_password_flag() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "roles",
            "--project-id",
            "11111111-1111-1111-1111-111111111111",
            "--branch-id",
            "22222222-2222-2222-2222-222222222222",
            "reset-password",
            "--id",
            "33333333-3333-3333-3333-333333333333",
        ]);

        match cli.command {
            Commands::Roles {
                action: RoleAction::ResetPassword { .. },
                ..
            } => {}
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_overview_accepts_custom_limits() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "overview",
            "--runs-limit",
            "12",
            "--approvals-limit",
            "6",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Overview {
                        runs_limit,
                        approvals_limit,
                    } => {
                        assert_eq!(runs_limit, 12);
                        assert_eq!(approvals_limit, 6);
                    }
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn database_list_accepts_grouped_command() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "database",
            "list",
            "--project-id",
            "11111111-1111-1111-1111-111111111111",
        ]);

        match cli.command {
            Commands::Database { action } => match action {
                GlobalDatabaseAction::List { project_id } => {
                    assert_eq!(
                        project_id.as_deref(),
                        Some("11111111-1111-1111-1111-111111111111")
                    );
                }
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_runs_list_accepts_grouped_command() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "runs",
            "list",
            "--deployment-id",
            "11111111-1111-1111-1111-111111111111",
            "--limit",
            "10",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Runs { action } => match action {
                        CloudRunsAction::List {
                            deployment_id,
                            limit,
                            ..
                        } => {
                            assert_eq!(
                                deployment_id,
                                Some(
                                    Uuid::parse_str("11111111-1111-1111-1111-111111111111")
                                        .unwrap()
                                )
                            );
                            assert_eq!(limit, 10);
                        }
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_run_approve_accepts_grouped_command() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "run",
            "approve",
            "11111111-1111-1111-1111-111111111111",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Run { action } => match action {
                        CloudRunAction::Approve { run_id } => {
                            assert_eq!(
                                run_id,
                                Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
                            );
                        }
                        _ => panic!("unexpected run action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_run_get_accepts_optional_deployment_scope() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "run",
            "get",
            "--deployment-id",
            "33333333-3333-3333-3333-333333333333",
            "22222222-2222-2222-2222-222222222222",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Run { action } => match action {
                        CloudRunAction::Get {
                            deployment_id,
                            run_id,
                        } => {
                            assert_eq!(
                                deployment_id,
                                Some(
                                    Uuid::parse_str("33333333-3333-3333-3333-333333333333")
                                        .unwrap()
                                )
                            );
                            assert_eq!(
                                run_id,
                                Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
                            );
                        }
                        _ => panic!("unexpected run action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_audit_list_accepts_filters() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "audit",
            "list",
            "--action",
            "run.completed",
            "--limit",
            "25",
            "--q",
            "deploy",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Audit { action } => match action {
                        CloudAuditAction::List {
                            action, limit, q, ..
                        } => {
                            assert_eq!(action.as_deref(), Some("run.completed"));
                            assert_eq!(limit, 25);
                            assert_eq!(q.as_deref(), Some("deploy"));
                        }
                        _ => panic!("unexpected audit action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_run_stream_accepts_deployment_scope_and_resume_cursor() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "run",
            "stream",
            "--deployment-id",
            "33333333-3333-3333-3333-333333333333",
            "22222222-2222-2222-2222-222222222222",
            "--last-event-id",
            "42",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Run { action } => match action {
                        CloudRunAction::Stream {
                            deployment_id,
                            run_id,
                            last_event_id,
                        } => {
                            assert_eq!(
                                deployment_id,
                                Some(
                                    Uuid::parse_str("33333333-3333-3333-3333-333333333333")
                                        .unwrap()
                                )
                            );
                            assert_eq!(
                                run_id,
                                Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
                            );
                            assert_eq!(last_event_id.as_deref(), Some("42"));
                        }
                        _ => panic!("unexpected run action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_run_state_accepts_deployment_scope() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "run",
            "state",
            "--deployment-id",
            "33333333-3333-3333-3333-333333333333",
            "22222222-2222-2222-2222-222222222222",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Run { action } => match action {
                        CloudRunAction::State {
                            deployment_id,
                            run_id,
                        } => {
                            assert_eq!(
                                deployment_id,
                                Some(
                                    Uuid::parse_str("33333333-3333-3333-3333-333333333333")
                                        .unwrap()
                                )
                            );
                            assert_eq!(
                                run_id,
                                Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
                            );
                        }
                        _ => panic!("unexpected run action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_conversation_messages_accepts_paging_options() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "conversation",
            "messages",
            "--deployment-id",
            "33333333-3333-3333-3333-333333333333",
            "thread-1",
            "--limit",
            "25",
            "--cursor",
            "cursor-1",
            "--order",
            "asc",
            "--include-run",
            "false",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Conversation { action } => match action {
                        CloudConversationAction::Messages {
                            deployment_id,
                            conversation_id,
                            limit,
                            cursor,
                            order,
                            include_run,
                        } => {
                            assert_eq!(
                                deployment_id,
                                Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
                            );
                            assert_eq!(conversation_id, "thread-1");
                            assert_eq!(limit, 25);
                            assert_eq!(cursor.as_deref(), Some("cursor-1"));
                            assert_eq!(order.as_deref(), Some("asc"));
                            assert_eq!(include_run, Some(false));
                        }
                        _ => panic!("unexpected conversation action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn cloud_schedule_create_accepts_future_run_options() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "cloud",
            "schedule",
            "create",
            "--deployment-id",
            "33333333-3333-3333-3333-333333333333",
            "--schedule-key",
            "daily-summary",
            "--message",
            "Summarize yesterday",
            "--cron",
            "0 9 * * *",
            "--timezone",
            "UTC",
            "--conversation-id",
            "thread-1",
            "--max-attempts",
            "3",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::Cloud { action } => match *action {
                    AgentCloudAction::Schedule { action } => match action {
                        CloudScheduleAction::Create {
                            deployment_id,
                            schedule_key,
                            message,
                            cron,
                            timezone,
                            conversation_id,
                            max_attempts,
                            ..
                        } => {
                            assert_eq!(
                                deployment_id,
                                Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
                            );
                            assert_eq!(schedule_key.as_deref(), Some("daily-summary"));
                            assert_eq!(message.as_deref(), Some("Summarize yesterday"));
                            assert_eq!(cron.as_deref(), Some("0 9 * * *"));
                            assert_eq!(timezone.as_deref(), Some("UTC"));
                            assert_eq!(conversation_id.as_deref(), Some("thread-1"));
                            assert_eq!(max_attempts, Some(3));
                        }
                        _ => panic!("unexpected schedule action parsed"),
                    },
                    _ => panic!("unexpected cloud action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn private_models_chat_accepts_simple_message() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "private-models",
            "chat",
            "--model",
            "anthropic.claude-3-5-sonnet",
            "--message",
            "hello",
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::PrivateModels { action } => match action {
                    PrivateModelsAction::Chat { model, message, .. } => {
                        assert_eq!(model.as_deref(), Some("anthropic.claude-3-5-sonnet"));
                        assert_eq!(message.as_deref(), Some("hello"));
                    }
                    _ => panic!("unexpected private models action parsed"),
                },
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn managed_test_run_accepts_body() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "managed-test-run",
            "--body",
            r#"{"name":"Draft","mode":"always_on","prompt":"hello"}"#,
        ]);

        match cli.command {
            Commands::Agent { action, .. } => match *action {
                AgentAction::ManagedTestRun { body } => {
                    assert_eq!(
                        body,
                        r#"{"name":"Draft","mode":"always_on","prompt":"hello"}"#
                    );
                }
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn managed_lifecycle_commands_accept_deployment_id() {
        for command in ["managed-start", "managed-stop", "managed-delete"] {
            let cli = parse_cli_with_large_stack(vec![
                "seren",
                "agent",
                command,
                "11111111-1111-1111-1111-111111111111",
            ]);

            match cli.command {
                Commands::Agent { action, .. } => match *action {
                    AgentAction::ManagedStart { deployment_id }
                    | AgentAction::ManagedStop { deployment_id }
                    | AgentAction::ManagedDelete { deployment_id } => {
                        assert_eq!(
                            deployment_id,
                            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
                        );
                    }
                    _ => panic!("unexpected agent action parsed"),
                },
                _ => panic!("unexpected command parsed"),
            }
        }
    }

    #[test]
    fn managed_tool_catalog_commands_accept_deployment_id() {
        let deployment_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();

        let tools = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "managed-deployment-tools",
            "11111111-1111-1111-1111-111111111111",
            "--q",
            "web",
        ]);
        match tools.command {
            Commands::Agent { action } => match *action {
                AgentAction::ManagedDeploymentTools {
                    deployment_id: parsed_id,
                    q,
                } => {
                    assert_eq!(parsed_id, deployment_id);
                    assert_eq!(q.as_deref(), Some("web"));
                }
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let tool = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "managed-deployment-tool",
            "11111111-1111-1111-1111-111111111111",
            "seren_publishers_get",
        ]);
        match tool.command {
            Commands::Agent { action } => match *action {
                AgentAction::ManagedDeploymentTool {
                    deployment_id: parsed_id,
                    tool_name,
                } => {
                    assert_eq!(parsed_id, deployment_id);
                    assert_eq!(tool_name, "seren_publishers_get");
                }
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let groups = parse_cli_with_large_stack(vec![
            "seren",
            "agent",
            "managed-deployment-tool-groups",
            "11111111-1111-1111-1111-111111111111",
        ]);
        match groups.command {
            Commands::Agent { action } => match *action {
                AgentAction::ManagedDeploymentToolGroups {
                    deployment_id: parsed_id,
                } => assert_eq!(parsed_id, deployment_id),
                _ => panic!("unexpected agent action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn org_private_models_policy_update_accepts_body() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "orgs",
            "private-models-policy",
            "--org-id",
            "11111111-1111-1111-1111-111111111111",
            "update",
            "--body",
            r#"{"mode":"standard"}"#,
        ]);

        match cli.command {
            Commands::Orgs { action } => match action {
                OrgAction::PrivateModelsPolicy { org_id, action } => {
                    assert_eq!(org_id, "11111111-1111-1111-1111-111111111111");
                    match action {
                        PrivateModelsPolicyAction::Update { body } => {
                            assert_eq!(body, r#"{"mode":"standard"}"#);
                        }
                        _ => panic!("unexpected policy action parsed"),
                    }
                }
                _ => panic!("unexpected org action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_create_login_accepts_safe_secret_input_flags() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "items",
            "create-login",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--title",
            "Example",
            "--username",
            "alice",
            "--password-stdin",
            "--url",
            "https://example.com",
            "--tag",
            "prod,api",
            "--sensitive",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Items { action, .. } => match *action {
                    PasswordItemAction::Login {
                        vault_id,
                        title,
                        username,
                        password_stdin,
                        urls,
                        tags,
                        sensitive,
                        ..
                    } => {
                        assert_eq!(
                            vault_id,
                            Some(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
                        );
                        assert_eq!(title, "Example");
                        assert_eq!(username, "alice");
                        assert!(password_stdin);
                        assert_eq!(urls, vec!["https://example.com"]);
                        assert_eq!(tags, vec!["prod", "api"]);
                        assert!(sensitive);
                    }
                    _ => panic!("unexpected passwords item action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_accepts_master_password_stdin_flag() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "--master-password-stdin",
            "vaults",
            "list",
        ]);

        match cli.command {
            Commands::Passwords {
                master_password_stdin,
                master_password_file,
                action,
            } => {
                assert!(master_password_stdin);
                assert!(master_password_file.is_none());
                match action {
                    PasswordsAction::Vaults { action } => match *action {
                        PasswordVaultAction::List => {}
                        _ => panic!("unexpected passwords vault action parsed"),
                    },
                    _ => panic!("unexpected passwords action parsed"),
                }
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_accepts_master_password_file_flag() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "--master-password-file",
            "/tmp/seren-passwords-master",
            "items",
            "list",
        ]);

        match cli.command {
            Commands::Passwords {
                master_password_stdin,
                master_password_file,
                action,
            } => {
                assert!(!master_password_stdin);
                assert_eq!(
                    master_password_file,
                    Some(std::path::PathBuf::from("/tmp/seren-passwords-master"))
                );
                match action {
                    PasswordsAction::Items { action } => match *action {
                        PasswordItemAction::List { vault_id } => assert!(vault_id.is_none()),
                        _ => panic!("unexpected passwords item action parsed"),
                    },
                    _ => panic!("unexpected passwords action parsed"),
                }
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_get_item_parses_reveal_flag() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "items",
            "get",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--item-id",
            "22222222-2222-2222-2222-222222222222",
            "--reveal",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Items { action, .. } => match *action {
                    PasswordItemAction::Get {
                        vault_id,
                        item_id,
                        reveal,
                    } => {
                        assert_eq!(
                            vault_id,
                            Some(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap())
                        );
                        assert_eq!(
                            item_id,
                            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
                        );
                        assert!(reveal);
                    }
                    _ => panic!("unexpected passwords item action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_attachment_commands_parse() {
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let item_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let attachment_id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let upload = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "attachments",
            "upload",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--item-id",
            "22222222-2222-2222-2222-222222222222",
            "--path",
            "attachment.bin",
            "--filename",
            "report.pdf",
            "--content-type",
            "application/pdf",
        ]);
        match upload.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Attachments { action } => match action {
                    PasswordAttachmentAction::Upload {
                        vault_id: parsed_vault,
                        item_id: parsed_item,
                        path,
                        filename,
                        content_type,
                    } => {
                        assert_eq!(parsed_vault, Some(vault_id));
                        assert_eq!(parsed_item, item_id);
                        assert_eq!(path, std::path::PathBuf::from("attachment.bin"));
                        assert_eq!(filename.as_deref(), Some("report.pdf"));
                        assert_eq!(content_type.as_deref(), Some("application/pdf"));
                    }
                    _ => panic!("unexpected passwords attachment action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let download = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "attachments",
            "download",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--item-id",
            "22222222-2222-2222-2222-222222222222",
            "--attachment-id",
            "33333333-3333-3333-3333-333333333333",
            "--output",
            "attachment.bin",
        ]);
        match download.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Attachments { action } => match action {
                    PasswordAttachmentAction::Download {
                        vault_id: parsed_vault,
                        item_id: parsed_item,
                        attachment_id: parsed_attachment,
                        output,
                    } => {
                        assert_eq!(parsed_vault, Some(vault_id));
                        assert_eq!(parsed_item, item_id);
                        assert_eq!(parsed_attachment, attachment_id);
                        assert_eq!(output, std::path::PathBuf::from("attachment.bin"));
                    }
                    _ => panic!("unexpected passwords attachment action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_update_item_parses_partial_fields() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "items",
            "update",
            "--item-id",
            "22222222-2222-2222-2222-222222222222",
            "--title",
            "New Title",
            "--tag",
            "a,b",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Items { action, .. } => match *action {
                    PasswordItemAction::Update {
                        item_id,
                        title,
                        tags,
                        sensitive,
                        ..
                    } => {
                        assert_eq!(
                            item_id,
                            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
                        );
                        assert_eq!(title, Some("New Title".to_string()));
                        assert_eq!(tags, Some(vec!["a".to_string(), "b".to_string()]));
                        assert_eq!(sensitive, None);
                    }
                    _ => panic!("unexpected passwords item action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_agent_provision_parses_flags() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "agent",
            "provision",
            "--vault",
            "all",
            "--access",
            "read",
            "--name",
            "ci-bot",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Agent { action, .. } => match action {
                    PasswordAgentAction::Provision {
                        vault,
                        access,
                        name,
                        expires_in_days,
                    } => {
                        assert_eq!(vault, "all");
                        assert_eq!(access, AgentAccessArg::Read);
                        assert_eq!(name, "ci-bot");
                        assert_eq!(expires_in_days, None);
                    }
                    _ => panic!("unexpected passwords agent action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_agent_freeze_parses() {
        let cli = parse_cli_with_large_stack(vec!["seren", "passwords", "agent", "freeze"]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Agent { action, .. } => match action {
                    PasswordAgentAction::Freeze => {}
                    _ => panic!("unexpected passwords agent action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_audit_commands_parse() {
        let actor = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let target = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "audit",
            "list",
            "--action",
            "identity.agent.freeze",
            "--actor-identity-id",
            "11111111-1111-1111-1111-111111111111",
            "--target-kind",
            "identity",
            "--target-id",
            "22222222-2222-2222-2222-222222222222",
            "--from",
            "2030-01-01T00:00:00Z",
            "--to",
            "2030-01-01T23:59:59Z",
            "--limit",
            "10",
            "--offset",
            "5",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Audit { action, .. } => match action {
                    PasswordAuditAction::List {
                        action,
                        actor_identity_id,
                        target_kind,
                        target_id,
                        from,
                        to,
                        limit,
                        offset,
                    } => {
                        assert_eq!(action.as_deref(), Some("identity.agent.freeze"));
                        assert_eq!(actor_identity_id, Some(actor));
                        assert_eq!(target_kind.as_deref(), Some("identity"));
                        assert_eq!(target_id, Some(target));
                        assert_eq!(from.as_deref(), Some("2030-01-01T00:00:00Z"));
                        assert_eq!(to.as_deref(), Some("2030-01-01T23:59:59Z"));
                        assert_eq!(limit, 10);
                        assert_eq!(offset, 5);
                    }
                    _ => panic!("unexpected passwords audit action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec!["seren", "passwords", "audit", "verify"]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Audit { action, .. } => match action {
                    PasswordAuditAction::Verify => {}
                    _ => panic!("unexpected passwords audit action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_approval_commands_parse() {
        let target = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "approvals",
            "request",
            "--target-kind",
            "item",
            "--target-id",
            "22222222-2222-2222-2222-222222222222",
            "--timeout-seconds",
            "60",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Approvals { action } => match action {
                    PasswordApprovalAction::Request {
                        target_kind,
                        target_id,
                        timeout_seconds,
                    } => {
                        assert_eq!(target_kind, PasswordApprovalTargetKindArg::Item);
                        assert_eq!(target_id, target);
                        assert_eq!(timeout_seconds, Some(60));
                    }
                    _ => panic!("unexpected passwords approval action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let too_short = try_parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "approvals",
            "request",
            "--target-kind",
            "item",
            "--target-id",
            "22222222-2222-2222-2222-222222222222",
            "--timeout-seconds",
            "0",
        ]);
        assert!(too_short.is_err());

        let too_long = try_parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "approvals",
            "request",
            "--target-kind",
            "item",
            "--target-id",
            "22222222-2222-2222-2222-222222222222",
            "--timeout-seconds",
            "3601",
        ]);
        assert!(too_long.is_err());

        let approval_id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "approvals",
            "deny",
            "33333333-3333-3333-3333-333333333333",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Approvals { action } => match action {
                    PasswordApprovalAction::Deny {
                        approval_id: parsed,
                    } => {
                        assert_eq!(parsed, approval_id);
                    }
                    _ => panic!("unexpected passwords approval action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "approvals",
            "approve",
            "33333333-3333-3333-3333-333333333333",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Approvals { action } => match action {
                    PasswordApprovalAction::Approve {
                        approval_id: parsed,
                    } => {
                        assert_eq!(parsed, approval_id);
                    }
                    _ => panic!("unexpected passwords approval action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_membership_and_vault_admin_commands_parse() {
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let identity_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "memberships",
            "revoke",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Memberships { action } => match action {
                    PasswordMembershipAction::Revoke {
                        vault_id: parsed_vault,
                        identity_id: parsed_identity,
                    } => {
                        assert_eq!(parsed_vault, vault_id);
                        assert_eq!(parsed_identity, identity_id);
                    }
                    _ => panic!("unexpected passwords membership action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "memberships",
            "grant",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "--access",
            "admin",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Memberships { action } => match action {
                    PasswordMembershipAction::Grant {
                        vault_id: parsed_vault,
                        identity_id: parsed_identity,
                        access,
                    } => {
                        assert_eq!(parsed_vault, vault_id);
                        assert_eq!(parsed_identity, identity_id);
                        assert_eq!(access, PasswordAccessArg::Admin);
                    }
                    _ => panic!("unexpected passwords membership action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "vaults",
            "archive",
            "11111111-1111-1111-1111-111111111111",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Vaults { action } => match *action {
                    PasswordVaultAction::Archive {
                        vault_id: parsed_vault,
                    } => assert_eq!(parsed_vault, vault_id),
                    _ => panic!("unexpected passwords vault action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "vaults",
            "create",
            "--name",
            "Shared Ops",
            "--description",
            "Operational credentials",
            "--requires-approval",
            "always",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Vaults { action } => match *action {
                    PasswordVaultAction::Create {
                        name,
                        description,
                        requires_approval,
                    } => {
                        assert_eq!(name, "Shared Ops");
                        assert_eq!(description.as_deref(), Some("Operational credentials"));
                        assert_eq!(
                            requires_approval,
                            Some(PasswordVaultApprovalModeArg::Always)
                        );
                    }
                    _ => panic!("unexpected passwords vault action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let rotation_token = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "vaults",
            "rotate",
            "complete",
            "11111111-1111-1111-1111-111111111111",
            "--rotation-token",
            "33333333-3333-3333-3333-333333333333",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Vaults { action } => match *action {
                    PasswordVaultAction::Rotate { action } => match action {
                        PasswordVaultRotateAction::Complete {
                            vault_id: parsed_vault,
                            rotation_token: parsed_token,
                        } => {
                            assert_eq!(parsed_vault, vault_id);
                            assert_eq!(parsed_token, Some(rotation_token));
                        }
                        _ => panic!("unexpected passwords vault rotate action parsed"),
                    },
                    _ => panic!("unexpected passwords vault action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_vault_update_command_parse() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
                let cli = Cli::parse_from([
                    "seren",
                    "passwords",
                    "vaults",
                    "update",
                    "11111111-1111-1111-1111-111111111111",
                    "--name",
                    "Shared Ops",
                    "--description",
                    "Operational credentials",
                ]);
                match cli.command {
                    Commands::Passwords { action, .. } => match action {
                        PasswordsAction::Vaults { action } => match *action {
                            PasswordVaultAction::Update {
                                vault_id: parsed_vault,
                                name,
                                description,
                            } => {
                                assert_eq!(parsed_vault, vault_id);
                                assert_eq!(name.as_deref(), Some("Shared Ops"));
                                assert_eq!(description.as_deref(), Some("Operational credentials"));
                            }
                            _ => panic!("unexpected passwords vault action parsed"),
                        },
                        _ => panic!("unexpected passwords action parsed"),
                    },
                    _ => panic!("unexpected command parsed"),
                }
            })
            .expect("spawn parse test thread")
            .join()
            .expect("parse test thread");
    }

    #[test]
    fn passwords_invitation_commands_parse() {
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let invitation_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "invitations",
            "create",
            "11111111-1111-1111-1111-111111111111",
            "--email",
            "ops@example.com",
            "--access",
            "write",
            "--expires-in-hours",
            "24",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Invitations { action } => match action {
                    PasswordInvitationAction::Create {
                        vault_id: parsed_vault,
                        email,
                        access,
                        expires_in_hours,
                    } => {
                        assert_eq!(parsed_vault, vault_id);
                        assert_eq!(email, "ops@example.com");
                        assert_eq!(access, PasswordAccessArg::Write);
                        assert_eq!(expires_in_hours, Some(24));
                    }
                    _ => panic!("unexpected passwords invitation action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let too_short = try_parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "invitations",
            "create",
            "11111111-1111-1111-1111-111111111111",
            "--email",
            "ops@example.com",
            "--expires-in-hours",
            "0",
        ]);
        assert!(too_short.is_err());

        let too_long = try_parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "invitations",
            "create",
            "11111111-1111-1111-1111-111111111111",
            "--email",
            "ops@example.com",
            "--expires-in-hours",
            "8761",
        ]);
        assert!(too_long.is_err());

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "invitations",
            "complete",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Invitations { action } => match action {
                    PasswordInvitationAction::Complete {
                        vault_id: parsed_vault,
                        invitation_id: parsed_invitation,
                    } => {
                        assert_eq!(parsed_vault, vault_id);
                        assert_eq!(parsed_invitation, invitation_id);
                    }
                    _ => panic!("unexpected passwords invitation action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_generate_password_command_parses() {
        let random = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "generate-password",
            "--length",
            "24",
            "--no-symbols",
        ]);
        match random.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::GeneratePassword {
                    mode,
                    length,
                    symbols,
                    ..
                } => {
                    assert_eq!(mode, "random");
                    assert_eq!(length, Some(24));
                    assert!(!symbols);
                }
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let passphrase = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "generate-password",
            "--mode",
            "passphrase",
            "--word-count",
            "4",
            "--separator",
            "_",
            "--no-capitalize-first",
        ]);
        match passphrase.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::GeneratePassword {
                    mode,
                    word_count,
                    separator,
                    capitalize_first,
                    ..
                } => {
                    assert_eq!(mode, "passphrase");
                    assert_eq!(word_count, 4);
                    assert_eq!(separator, '_');
                    assert!(!capitalize_first);
                }
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_share_commands_parse() {
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "shares",
            "outbound",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Shares { action } => match action {
                    PasswordShareAction::Outbound {
                        vault_id: parsed_vault,
                    } => assert_eq!(parsed_vault, Some(vault_id)),
                    _ => panic!("unexpected passwords share action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let share_id = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "shares",
            "revoke",
            "33333333-3333-3333-3333-333333333333",
        ]);
        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Shares { action } => match action {
                    PasswordShareAction::Revoke { share_id: parsed } => {
                        assert_eq!(parsed, share_id);
                    }
                    _ => panic!("unexpected passwords share action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_import_export_commands_parse() {
        let vault_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let export = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "export",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--output",
            "vault-export.json",
        ]);
        match export.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Export {
                    vault_id: parsed_vault,
                    output,
                    exclude_attachments,
                } => {
                    assert_eq!(parsed_vault, Some(vault_id));
                    assert_eq!(output, std::path::PathBuf::from("vault-export.json"));
                    assert!(!exclude_attachments);
                }
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let import = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "import",
            "--vault-id",
            "11111111-1111-1111-1111-111111111111",
            "--input",
            "vault-export.json",
        ]);
        match import.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Import {
                    vault_id: parsed_vault,
                    input,
                } => {
                    assert_eq!(parsed_vault, Some(vault_id));
                    assert_eq!(input, std::path::PathBuf::from("vault-export.json"));
                }
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_item_transfer_commands_parse() {
        let item_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let source = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let target = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "items",
            "duplicate",
            "--vault-id",
            "22222222-2222-2222-2222-222222222222",
            "--item-id",
            "11111111-1111-1111-1111-111111111111",
            "--target-vault-id",
            "33333333-3333-3333-3333-333333333333",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Items { action, .. } => match *action {
                    PasswordItemAction::Duplicate {
                        vault_id,
                        item_id: parsed_item,
                        target_vault_id,
                    } => {
                        assert_eq!(vault_id, Some(source));
                        assert_eq!(parsed_item, item_id);
                        assert_eq!(target_vault_id, target);
                    }
                    _ => panic!("unexpected passwords item action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "items",
            "move",
            "--vault-id",
            "22222222-2222-2222-2222-222222222222",
            "--item-id",
            "11111111-1111-1111-1111-111111111111",
            "--target-vault-id",
            "33333333-3333-3333-3333-333333333333",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Items { action, .. } => match *action {
                    PasswordItemAction::Move {
                        vault_id,
                        item_id: parsed_item,
                        target_vault_id,
                    } => {
                        assert_eq!(vault_id, Some(source));
                        assert_eq!(parsed_item, item_id);
                        assert_eq!(target_vault_id, target);
                    }
                    _ => panic!("unexpected passwords item action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn passwords_agent_revoke_parses_membership_scope() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "passwords",
            "agent",
            "revoke",
            "33333333-3333-3333-3333-333333333333",
            "--vault",
            "44444444-4444-4444-4444-444444444444",
        ]);

        match cli.command {
            Commands::Passwords { action, .. } => match action {
                PasswordsAction::Agent { action, .. } => match action {
                    PasswordAgentAction::Revoke { agent_id, vault } => {
                        assert_eq!(
                            agent_id,
                            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
                        );
                        assert_eq!(
                            vault,
                            Some(Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap())
                        );
                    }
                    _ => panic!("unexpected passwords agent action parsed"),
                },
                _ => panic!("unexpected passwords action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn object_storage_bucket_create_parses_metadata() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "object-storage",
            "--org-id",
            "default",
            "buckets",
            "create",
            "--slug",
            "employee-files",
            "--display-name",
            "Employee files",
            "--metadata",
            r#"{"team":"ops"}"#,
        ]);

        match cli.command {
            Commands::ObjectStorage { org_id, action } => {
                assert_eq!(org_id, "default");
                match action {
                    ObjectStorageAction::Buckets { action } => match action {
                        ObjectStorageBucketAction::Create {
                            slug,
                            display_name,
                            metadata_json,
                            metadata_file,
                        } => {
                            assert_eq!(slug, "employee-files");
                            assert_eq!(display_name.as_deref(), Some("Employee files"));
                            assert_eq!(metadata_json.as_deref(), Some(r#"{"team":"ops"}"#));
                            assert!(metadata_file.is_none());
                        }
                        _ => panic!("unexpected object storage bucket action parsed"),
                    },
                    _ => panic!("unexpected object storage action parsed"),
                }
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn seren_storage_publisher_commands_parse() {
        let health = parse_cli_with_large_stack(vec!["seren", "storage", "health"]);
        assert!(matches!(
            health.command,
            Commands::Storage {
                action: StorageAction::Health
            }
        ));

        let buckets = parse_cli_with_large_stack(vec!["seren", "storage", "buckets", "list"]);
        assert!(matches!(
            buckets.command,
            Commands::Storage {
                action: StorageAction::Buckets {
                    action: StorageBucketAction::List
                }
            }
        ));
    }

    #[test]
    fn object_storage_object_upload_download_parse() {
        let upload = parse_cli_with_large_stack(vec![
            "seren",
            "object-storage",
            "objects",
            "--bucket",
            "employee-files",
            "upload",
            "--key",
            "notes/report.txt",
            "--path",
            "report.txt",
            "--content-type",
            "text/plain",
        ]);

        match upload.command {
            Commands::ObjectStorage { org_id, action } => {
                assert_eq!(org_id, "default");
                match action {
                    ObjectStorageAction::Objects { bucket, action } => {
                        assert_eq!(bucket.as_deref(), Some("employee-files"));
                        match action {
                            ObjectStorageObjectAction::Upload {
                                target,
                                key,
                                path,
                                content_type,
                                metadata_json,
                                metadata_file,
                            } => {
                                assert!(target.is_none());
                                assert_eq!(key.as_deref(), Some("notes/report.txt"));
                                assert_eq!(path, std::path::PathBuf::from("report.txt"));
                                assert_eq!(content_type.as_deref(), Some("text/plain"));
                                assert!(metadata_json.is_none());
                                assert!(metadata_file.is_none());
                            }
                            _ => panic!("unexpected object storage object action parsed"),
                        }
                    }
                    _ => panic!("unexpected object storage action parsed"),
                }
            }
            _ => panic!("unexpected command parsed"),
        }

        let download = parse_cli_with_large_stack(vec![
            "seren",
            "storage",
            "objects",
            "--bucket",
            "employee-files",
            "download",
            "--key",
            "notes/report.txt",
            "--output",
            "report-copy.txt",
        ]);

        match download.command {
            Commands::Storage { action } => match action {
                StorageAction::Objects { bucket, action } => {
                    assert_eq!(bucket.as_deref(), Some("employee-files"));
                    match action {
                        ObjectStorageObjectAction::Download {
                            target,
                            key,
                            output,
                        } => {
                            assert!(target.is_none());
                            assert_eq!(key.as_deref(), Some("notes/report.txt"));
                            assert_eq!(output, Some(std::path::PathBuf::from("report-copy.txt")));
                        }
                        _ => panic!("unexpected Seren Storage object action parsed"),
                    }
                }
                _ => panic!("unexpected Seren Storage action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let confirm = parse_cli_with_large_stack(vec![
            "seren",
            "storage",
            "objects",
            "--bucket",
            "employee-files",
            "confirm",
            "--object-id",
            "11111111-1111-1111-1111-111111111111",
            "--sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "--byte-length",
            "42",
            "--etag",
            "etag-value",
        ]);

        match confirm.command {
            Commands::Storage { action } => match action {
                StorageAction::Objects { bucket, action } => {
                    assert_eq!(bucket.as_deref(), Some("employee-files"));
                    match action {
                        ObjectStorageObjectAction::Confirm {
                            object_id,
                            sha256,
                            byte_length,
                            etag,
                        } => {
                            assert_eq!(
                                object_id,
                                Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
                            );
                            assert_eq!(
                                sha256.as_deref(),
                                Some(
                                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                                )
                            );
                            assert_eq!(byte_length, Some(42));
                            assert_eq!(etag.as_deref(), Some("etag-value"));
                        }
                        _ => panic!("unexpected Seren Storage object action parsed"),
                    }
                }
                _ => panic!("unexpected Seren Storage action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn object_storage_object_target_forms_parse() {
        let upload = parse_cli_with_large_stack(vec![
            "seren",
            "storage",
            "objects",
            "put",
            "employee-files/notes/report.txt",
            "--path",
            "report.txt",
        ]);

        match upload.command {
            Commands::Storage { action } => match action {
                StorageAction::Objects { bucket, action } => {
                    assert!(bucket.is_none());
                    match action {
                        ObjectStorageObjectAction::Upload {
                            target, key, path, ..
                        } => {
                            assert_eq!(target.as_deref(), Some("employee-files/notes/report.txt"));
                            assert!(key.is_none());
                            assert_eq!(path, std::path::PathBuf::from("report.txt"));
                        }
                        _ => panic!("unexpected Seren Storage object action parsed"),
                    }
                }
                _ => panic!("unexpected Seren Storage action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }

        let download = parse_cli_with_large_stack(vec![
            "seren",
            "storage",
            "objects",
            "get",
            "employee-files/notes/report.txt",
        ]);

        match download.command {
            Commands::Storage { action } => match action {
                StorageAction::Objects { bucket, action } => {
                    assert!(bucket.is_none());
                    match action {
                        ObjectStorageObjectAction::Download {
                            target,
                            key,
                            output,
                        } => {
                            assert_eq!(target.as_deref(), Some("employee-files/notes/report.txt"));
                            assert!(key.is_none());
                            assert!(output.is_none());
                        }
                        _ => panic!("unexpected Seren Storage object action parsed"),
                    }
                }
                _ => panic!("unexpected Seren Storage action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn psql_command_accepts_args_after_separator() {
        let cli = parse_cli_with_large_stack(vec![
            "seren",
            "psql",
            "--project-id",
            "11111111-1111-1111-1111-111111111111",
            "--branch-id",
            "22222222-2222-2222-2222-222222222222",
            "--",
            "-c",
            "select 1",
        ]);

        match cli.command {
            Commands::Psql {
                project_id,
                branch_id,
                psql_args,
                ..
            } => {
                assert_eq!(
                    project_id.as_deref(),
                    Some("11111111-1111-1111-1111-111111111111")
                );
                assert_eq!(
                    branch_id.as_deref(),
                    Some("22222222-2222-2222-2222-222222222222")
                );
                assert_eq!(psql_args, vec!["-c", "select 1"]);
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn mcp_start_server_accepts_primary_name() {
        let cli = parse_cli_with_large_stack(vec!["seren", "mcp", "start:server"]);

        match cli.command {
            Commands::Mcp { action } => match action {
                McpAction::StartServer => {}
                _ => panic!("unexpected mcp action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn mcp_start_server_accepts_legacy_alias() {
        let cli = parse_cli_with_large_stack(vec!["seren", "mcp", "start:oauth"]);

        match cli.command {
            Commands::Mcp { action } => match action {
                McpAction::StartServer => {}
                _ => panic!("unexpected mcp action parsed"),
            },
            _ => panic!("unexpected command parsed"),
        }
    }
}
