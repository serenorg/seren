use clap::{Parser, Subcommand};

mod commands;
mod config;
mod output;

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
        
        /// Organization ID
        #[arg(long)]
        org_id: String,
    },
    /// Update a project
    Update {
        /// Project ID
        id: String,
        
        /// New project name
        #[arg(long)]
        name: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Auth { action } => match action {
            AuthAction::Login { email: _, password: _ } => {
                commands::auth::login().await?
            }
        },
        Commands::Me => {
            commands::auth::me(cli.format, cli.api_host).await?
        }
        Commands::Organizations => {
            commands::auth::organizations(cli.format, cli.api_host).await?
        }
        Commands::Projects { action } => match action {
            ProjectAction::List => commands::projects::list(cli.format, cli.api_host).await?,
            ProjectAction::Get { id } => commands::projects::get(&id, cli.format, cli.api_host).await?,
            ProjectAction::Create { name, org_id } => {
                commands::projects::create(&name, &org_id, cli.format, cli.api_host).await?
            }
            ProjectAction::Update { id, name } => {
                commands::projects::update(&id, &name, cli.format, cli.api_host).await?
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
                commands::branches::create(&project_id, &name, parent.as_deref(), cli.format, cli.api_host).await?
            }
            BranchAction::Delete { id } => {
                commands::branches::delete(&project_id, &id, cli.api_host).await?
            }
            BranchAction::Rename { id, name } => {
                commands::branches::rename(&project_id, &id, &name, cli.format, cli.api_host).await?
            }
            BranchAction::SetDefault { id } => {
                commands::branches::set_default(&project_id, &id, cli.api_host).await?
            }
            BranchAction::ConnectionString { id } => {
                commands::branches::connection_string(&project_id, &id, cli.format, cli.api_host).await?
            }
            BranchAction::SetExpiration { id, expires_at, no_expiration } => {
                commands::branches::set_expiration(&project_id, &id, expires_at.as_deref(), no_expiration, cli.format, cli.api_host).await?
            }
        },
        Commands::Databases { project_id, branch_id, action } => match action {
            DatabaseAction::List => {
                commands::databases::list(&project_id, &branch_id, cli.format, cli.api_host).await?
            }
            DatabaseAction::Create { name, owner } => {
                commands::databases::create(&project_id, &branch_id, &name, owner.as_deref(), cli.format, cli.api_host).await?
            }
            DatabaseAction::Delete { id } => {
                commands::databases::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
        },
        Commands::Roles { project_id, branch_id, action } => match action {
            RoleAction::List => {
                commands::roles::list(&project_id, &branch_id, cli.format, cli.api_host).await?
            }
            RoleAction::Create { name } => {
                commands::roles::create(&project_id, &branch_id, &name, cli.format, cli.api_host).await?
            }
            RoleAction::Delete { id } => {
                commands::roles::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
            RoleAction::ResetPassword { id, password } => {
                commands::roles::reset_password(&project_id, &branch_id, &id, &password, cli.format, cli.api_host).await?
            }
        },
        Commands::Endpoints { project_id, branch_id, action } => match action {
            EndpointAction::List => {
                commands::endpoints::list(&project_id, &branch_id, cli.format, cli.api_host).await?
            }
            EndpointAction::Create { name, compute_unit, autoscaling_min, autoscaling_max, suspend_timeout } => {
                commands::endpoints::create(&project_id, &branch_id, &name, compute_unit, autoscaling_min, autoscaling_max, suspend_timeout, cli.format, cli.api_host).await?
            }
            EndpointAction::Update { id, autoscaling_min, autoscaling_max, suspend_timeout } => {
                commands::endpoints::update(&project_id, &branch_id, &id, autoscaling_min, autoscaling_max, suspend_timeout, cli.format, cli.api_host).await?
            }
            EndpointAction::Delete { id } => {
                commands::endpoints::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
            EndpointAction::Suspend { id } => {
                commands::endpoints::suspend(&project_id, &branch_id, &id, cli.format, cli.api_host).await?
            }
            EndpointAction::Start { id } => {
                commands::endpoints::start(&project_id, &branch_id, &id, cli.format, cli.api_host).await?
            }
            EndpointAction::Health { id } => {
                commands::endpoints::health(&project_id, &branch_id, &id, cli.format, cli.api_host).await?
            }
            EndpointAction::Metrics { id } => {
                commands::endpoints::metrics(&project_id, &branch_id, &id, cli.format, cli.api_host).await?
            }
        },
        Commands::Operations { project_id, action } => match action {
            OperationAction::List => {
                commands::operations::list(&project_id, cli.format, cli.api_host).await?
            }
            OperationAction::Get { id: _ } => {
                eprintln!("Error: Operation get is not yet implemented");
                std::process::exit(1);
            }
        },
        Commands::IpAllowList { project_id, action } => match action {
            IpAllowListAction::List => {
                commands::ip_allow_lists::list(&project_id, cli.format, cli.api_host).await?
            }
            IpAllowListAction::Add { ip_address, description } => {
                commands::ip_allow_lists::add(&project_id, &ip_address, description.clone(), cli.format, cli.api_host).await?
            }
            IpAllowListAction::Remove { id } => {
                commands::ip_allow_lists::remove(&project_id, &id, cli.api_host).await?
            }
        },
        Commands::SetContext { action } => match action {
            ContextAction::Set { project_id, org_id } => {
                commands::context::set(project_id, org_id).await?
            }
            ContextAction::Show => {
                commands::context::show(cli.format).await?
            }
            ContextAction::Clear => {
                commands::context::clear().await?
            }
        },
    }

    Ok(())
}
