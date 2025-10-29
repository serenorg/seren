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
#[command(name = "serenctl")]
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
    /// Delete an endpoint
    Delete {
        /// Endpoint ID
        id: String,
    },
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
            EndpointAction::Delete { id } => {
                commands::endpoints::delete(&project_id, &branch_id, &id, cli.api_host).await?
            }
        },
    }

    Ok(())
}
