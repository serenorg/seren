use clap::{Parser, Subcommand};

mod commands;
pub mod config;
pub mod output;

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
    /// Manage VPC endpoints
    Vpc {
        #[command(subcommand)]
        action: VpcAction,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Login to Seren
    Login {
        /// Email address
        #[arg(long)]
        email: String,

        /// Password
        #[arg(long)]
        password: String,
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
    },
    /// Delete a project
    Delete {
        /// Project ID
        id: String,
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
    },
    /// Delete a branch
    Delete {
        /// Branch ID
        id: String,
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

        /// Use pooled connection (PgBouncer)
        #[arg(long)]
        pooled: bool,

        /// Format for Prisma ORM
        #[arg(long)]
        prisma: bool,

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

        /// Compute unit (e.g., small, medium, large)
        #[arg(long)]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth { action } => match action {
            AuthAction::Login {
                email: _,
                password: _,
            } => commands::auth::login().await?,
        },
        Commands::Me => commands::auth::me(cli.format, cli.api_host).await?,
        Commands::Organizations => commands::auth::organizations(cli.format, cli.api_host).await?,
        Commands::Projects { action } => match action {
            ProjectAction::List => commands::projects::list(cli.format, cli.api_host).await?,
            ProjectAction::Get { id } => {
                commands::projects::get(&id, cli.format, cli.api_host).await?
            }
            ProjectAction::Create {
                name,
                region,
                block_public_connections,
                block_vpc_connections,
                hipaa,
                protected_branches_only,
                compute_unit_min,
                compute_unit_max,
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
                    cli.format,
                    cli.api_host,
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
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            ProjectAction::Delete { id } => commands::projects::delete(&id, cli.api_host).await?,
        },
        Commands::Branches { project_id, action } => match action {
            BranchAction::List => {
                commands::branches::list(&project_id, cli.format, cli.api_host).await?
            }
            BranchAction::Get { id } => {
                commands::branches::get(&project_id, &id, cli.format, cli.api_host).await?
            }
            BranchAction::Create { name, parent } => {
                commands::branches::create(
                    &project_id,
                    &name,
                    parent.as_deref(),
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            BranchAction::Delete { id } => {
                commands::branches::delete(&project_id, &id, cli.api_host).await?
            }
            BranchAction::Rename { id, name } => {
                commands::branches::rename(&project_id, &id, &name, cli.format, cli.api_host)
                    .await?
            }
            BranchAction::SetDefault { id } => {
                commands::branches::set_default(&project_id, &id, cli.api_host).await?
            }
            BranchAction::ConnectionString {
                id,
                pooled,
                prisma,
                ssl,
            } => {
                commands::branches::connection_string(
                    &project_id,
                    &id,
                    pooled,
                    prisma,
                    ssl.as_deref(),
                    cli.format,
                    cli.api_host,
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
                    cli.format,
                    cli.api_host,
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
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            BranchAction::Reset { id } => {
                commands::branches::reset(&project_id, &id, cli.api_host).await?
            }
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
                    cli.api_host,
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
                commands::databases::list(&project_id, &branch_id, cli.format, cli.api_host).await?
            }
            DatabaseAction::Create { name, owner } => {
                commands::databases::create(
                    &project_id,
                    &branch_id,
                    &name,
                    owner.as_deref(),
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            DatabaseAction::Delete { id } => {
                commands::databases::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
        },
        Commands::Roles {
            project_id,
            branch_id,
            action,
        } => match action {
            RoleAction::List => {
                commands::roles::list(&project_id, &branch_id, cli.format, cli.api_host).await?
            }
            RoleAction::Create { name } => {
                commands::roles::create(&project_id, &branch_id, &name, cli.format, cli.api_host)
                    .await?
            }
            RoleAction::Delete { id } => {
                commands::roles::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
            RoleAction::ResetPassword { id, password } => {
                commands::roles::reset_password(
                    &project_id,
                    &branch_id,
                    &id,
                    &password,
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
        },
        Commands::Endpoints {
            project_id,
            branch_id,
            action,
        } => match action {
            EndpointAction::List => {
                commands::endpoints::list(&project_id, &branch_id, cli.format, cli.api_host).await?
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
                    cli.format,
                    cli.api_host,
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
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            EndpointAction::Delete { id } => {
                commands::endpoints::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
            EndpointAction::Suspend { id } => {
                commands::endpoints::suspend(&project_id, &branch_id, &id, cli.format, cli.api_host)
                    .await?
            }
            EndpointAction::Start { id } => {
                commands::endpoints::start(&project_id, &branch_id, &id, cli.format, cli.api_host)
                    .await?
            }
            EndpointAction::Health { id } => {
                commands::endpoints::health(&project_id, &branch_id, &id, cli.format, cli.api_host)
                    .await?
            }
            EndpointAction::Metrics { id } => {
                commands::endpoints::metrics(&project_id, &branch_id, &id, cli.format, cli.api_host)
                    .await?
            }
        },
        Commands::Operations { project_id, action } => match action {
            OperationAction::List => {
                commands::operations::list(&project_id, cli.format, cli.api_host).await?
            }
            OperationAction::Get { id } => {
                commands::operations::get(&project_id, &id, cli.format, cli.api_host).await?
            }
        },
        Commands::IpAllowList { project_id, action } => match action {
            IpAllowListAction::List => {
                commands::ip_allow_list::list(&project_id, cli.format, cli.api_host).await?
            }
            IpAllowListAction::Add {
                ip_address,
                description,
            } => {
                commands::ip_allow_list::add(
                    &project_id,
                    &ip_address,
                    description.clone(),
                    cli.format,
                    cli.api_host,
                )
                .await?
            }
            IpAllowListAction::Remove { id } => {
                commands::ip_allow_list::remove(&project_id, &id, cli.api_host).await?
            }
            IpAllowListAction::Reset { ips } => {
                commands::ip_allow_list::reset(&project_id, &ips, cli.format, cli.api_host).await?
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
                    commands::vpc::endpoint_list(&org_id, region, cli.format, cli.api_host).await?
                }
                VpcEndpointAction::Add {
                    region,
                    endpoint_id,
                    label,
                } => {
                    commands::vpc::endpoint_create(
                        &org_id,
                        &region,
                        &endpoint_id,
                        label,
                        cli.format,
                        cli.api_host,
                    )
                    .await?
                }
                VpcEndpointAction::Get { endpoint_id } => {
                    commands::vpc::endpoint_get(&org_id, &endpoint_id, cli.format, cli.api_host)
                        .await?
                }
                VpcEndpointAction::Remove { endpoint_id } => {
                    commands::vpc::endpoint_remove(&org_id, &endpoint_id, cli.api_host).await?
                }
            },
            VpcAction::Project { project_id, action } => match action {
                VpcProjectAction::List => {
                    commands::vpc::project_list(&project_id, cli.format, cli.api_host).await?
                }
                VpcProjectAction::Assign {
                    vpc_endpoint_id,
                    label,
                } => {
                    commands::vpc::project_assign(
                        &project_id,
                        &vpc_endpoint_id,
                        label,
                        cli.format,
                        cli.api_host,
                    )
                    .await?
                }
                VpcProjectAction::Remove { assignment_id } => {
                    commands::vpc::project_remove(&project_id, &assignment_id, cli.api_host).await?
                }
            },
        },
    }

    Ok(())
}
