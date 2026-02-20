use clap::{ArgAction, Parser, Subcommand};
use uuid::Uuid;

mod command_context;
mod commands;
pub mod config;
pub mod defaults;
mod money;
pub mod output;

pub use command_context::CommandContext;
use money::UsdCents;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[derive(Parser)]
#[command(name = "seren")]
#[command(about = "CLI tool for Seren database management", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json or table)
    #[arg(long, short = 'o', global = true, default_value = "table")]
    format: OutputFormat,

    /// API host URL
    #[arg(long, global = true, env = "SEREN_API_HOST")]
    api_host: Option<String>,

    /// API key for authentication (overrides stored credentials)
    #[arg(long, global = true, env = "SEREN_API_KEY")]
    api_key: Option<String>,
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
    /// List all databases across all projects with human-readable project and branch names
    #[command(name = "list-all-databases")]
    ListAllDatabases {
        /// Optional project ID to filter databases to a specific project
        #[arg(long)]
        project_id: Option<String>,
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
    /// Disconnect from an OAuth provider
    Disconnect {
        /// Provider slug
        provider_slug: String,
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
    /// Deploy a skill to Seren Cloud
    Deploy {
        /// Path to the skill directory (containing scripts/ for the selected runtime)
        path: String,
        /// Deployment publisher slug (`seren-cloud` for direct runtime deploys, `seren-agent` for orchestrated app deploys)
        #[arg(long, default_value = "seren-cloud")]
        publisher: String,
        /// Deployment name
        #[arg(long)]
        name: Option<String>,
        /// Deployment mode: "always-on" or "cron"
        #[arg(long, default_value = "always-on")]
        mode: String,
        /// Cron schedule expression (required if mode is "cron")
        #[arg(long)]
        cron_schedule: Option<String>,
        /// Compute backend target (aws_container, cloudflare_worker, or daytona)
        #[arg(long)]
        compute_backend: Option<String>,
        /// Runtime kind (python, javascript, typescript, rust, rust_wasm_adk)
        #[arg(long)]
        runtime_kind: Option<String>,
        /// Path to config.json
        #[arg(long)]
        config: Option<String>,
        /// Path to .env secrets file
        #[arg(long, name = "env")]
        env_file: Option<String>,
    },
    /// List cloud agent deployments
    CloudList,
    /// Get status of a cloud agent deployment
    CloudStatus {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Start a stopped always-on cloud agent
    CloudStart {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Stop a running always-on cloud agent
    CloudStop {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Trigger a one-shot run of a cloud agent
    CloudRun {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Get logs from a running cloud agent
    CloudLogs {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
    },
    /// Destroy a cloud agent deployment
    CloudDestroy {
        /// Deployment ID (UUID)
        deployment_id: Uuid,
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

        /// New password
        #[arg(long)]
        password: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Create shared command context for all commands
    let ctx = CommandContext::new(cli.api_host.clone(), cli.api_key.clone(), cli.format);

    match cli.command {
        Commands::Auth { action } => match action {
            AuthAction::Login => commands::auth::login().await?,
            AuthAction::Status => commands::auth::status().await?,
            AuthAction::Logout => commands::auth::logout().await?,
        },
        Commands::Me => commands::auth::me(cli.format, cli.api_host, cli.api_key.clone()).await?,
        Commands::Organizations => {
            commands::auth::organizations(cli.format, cli.api_host, cli.api_key.clone()).await?
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
        Commands::ListAllDatabases { project_id } => {
            commands::databases::list_all(project_id.as_deref(), &ctx).await?
        }
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
            RoleAction::ResetPassword { id, password } => {
                commands::roles::reset_password(&project_id, &branch_id, &id, &password, &ctx)
                    .await?
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
        Commands::Agent { action } => match *action {
            AgentAction::ListPublishers => commands::agent::list_publishers(&ctx).await?,
            AgentAction::GetPublisher { publisher } => {
                commands::agent::get_publisher(&publisher, &ctx).await?
            }
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
            AgentAction::Deploy {
                path,
                publisher,
                name,
                mode,
                cron_schedule,
                compute_backend,
                runtime_kind,
                config,
                env_file,
            } => {
                commands::agent::cloud_deploy(
                    &path,
                    commands::agent::CloudDeployOptions {
                        publisher_slug: Some(&publisher),
                        name: name.as_deref(),
                        mode: &mode,
                        cron_schedule: cron_schedule.as_deref(),
                        compute_backend: compute_backend.as_deref(),
                        runtime_kind: runtime_kind.as_deref(),
                        config_path: config.as_deref(),
                        env_path: env_file.as_deref(),
                    },
                    &ctx,
                )
                .await?
            }
            AgentAction::CloudList => commands::agent::cloud_list(&ctx).await?,
            AgentAction::CloudStatus { deployment_id } => {
                commands::agent::cloud_status(deployment_id, &ctx).await?
            }
            AgentAction::CloudStart { deployment_id } => {
                commands::agent::cloud_start(deployment_id, &ctx).await?
            }
            AgentAction::CloudStop { deployment_id } => {
                commands::agent::cloud_stop(deployment_id, &ctx).await?
            }
            AgentAction::CloudRun { deployment_id } => {
                commands::agent::cloud_run(deployment_id, &ctx).await?
            }
            AgentAction::CloudLogs { deployment_id } => {
                commands::agent::cloud_logs(deployment_id, &ctx).await?
            }
            AgentAction::CloudDestroy { deployment_id } => {
                commands::agent::cloud_destroy(deployment_id, &ctx).await?
            }
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
            OAuthAction::Disconnect { provider_slug } => {
                commands::oauth::disconnect(&provider_slug, &ctx).await?
            }
        },
    }

    Ok(())
}
