# Seren CLI

Command-line interface for managing SerenDB databases, projects, branches, and more.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install serenorg/tap/seren
```

### Cargo

```bash
cargo install seren-cli
```

### From Source

```bash
git clone https://github.com/serenorg/seren.git
cd seren
cargo install --path cli
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/serenorg/seren/releases):

- `seren-darwin-arm64` - macOS Apple Silicon
- `seren-darwin-x86_64` - macOS Intel
- `seren-linux-x86_64` - Linux x86_64
- `seren-linux-arm64` - Linux ARM64
- `seren-windows-x86_64.exe` - Windows

## Quick Start

```bash
# Authenticate with SerenDB
seren auth login

# List your projects
seren projects list

# Create a new project
seren projects create --name my-app --region aws-us-east-1

# Get connection string
seren projects connection-uri <project-id>
```

## Authentication

### OAuth Login (Recommended)

```bash
seren auth login
```

Opens your browser for secure OAuth authentication.

### API Key

```bash
# Set via environment variable
export SEREN_API_KEY=seren_your_api_key_here
seren projects list

# Or pass directly
seren --api-key seren_your_api_key projects list
```

### Check Status

```bash
seren auth status
seren me
```

## Commands

### Projects

```bash
# List all projects
seren projects list

# Get project details
seren projects get <project-id>

# Create a project
seren projects create --name my-project --region aws-us-east-1

# Create and connect via psql
seren projects create --name my-project --region aws-us-east-1 --psql

# Update a project
seren projects update <project-id> --name new-name

# Get connection URI
seren projects connection-uri <project-id>
seren projects connection-uri <project-id> --pooled --prisma

# Delete a project
seren projects delete <project-id>
seren projects delete <project-id> --yes  # Skip confirmation
```

### Branches

```bash
# List branches
seren branches --project-id <id> list

# Create a branch
seren branches --project-id <id> create --name feature-branch

# Create from parent with point-in-time recovery
seren branches --project-id <id> create --name restore-branch \
  --parent <parent-id> --parent-timestamp "2024-01-15T10:00:00Z"

# Create with auto-expiration
seren branches --project-id <id> create --name temp-branch --expires-in 7d

# Create schema-only branch (no data)
seren branches --project-id <id> create --name schema-branch --schema-only

# Get connection string
seren branches --project-id <id> connection-string <branch-id>
seren branches --project-id <id> connection-string <branch-id> --pooled

# Compare schemas between branches
seren branches --project-id <id> schema-diff \
  --base-branch-id <id> --compare-branch-id <id>

# Reset branch to parent
seren branches --project-id <id> reset <branch-id>

# Restore branch (point-in-time recovery)
seren branches --project-id <id> restore <branch-id> \
  --source ^self --preserve-under-name backup \
  --timestamp "2024-01-15T10:00:00Z"

# Delete a branch
seren branches --project-id <id> delete <branch-id>
```

### Endpoints

```bash
# List endpoints
seren endpoints --project-id <id> --branch-id <id> list

# Create an endpoint
seren endpoints --project-id <id> --branch-id <id> create \
  --name my-endpoint --compute-unit medium

# Create with autoscaling
seren endpoints --project-id <id> --branch-id <id> create \
  --name my-endpoint --autoscaling-min 1 --autoscaling-max 4

# Suspend/start endpoint
seren endpoints --project-id <id> --branch-id <id> suspend <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> start <endpoint-id>

# Check health and metrics
seren endpoints --project-id <id> --branch-id <id> health <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> metrics <endpoint-id>
```

### Databases & Roles

```bash
# List databases
seren databases --project-id <id> --branch-id <id> list

# Create a database
seren databases --project-id <id> --branch-id <id> create --name mydb

# List roles
seren roles --project-id <id> --branch-id <id> list

# Create a role
seren roles --project-id <id> --branch-id <id> create --name myrole

# Reset role password
seren roles --project-id <id> --branch-id <id> reset-password \
  --id <role-id> --password newpassword
```

### Environment Files

```bash
# Initialize .env with connection string
seren env init --project-id <id>

# Specify branch and key name
seren env init --project-id <id> --branch-id <id> \
  --key DATABASE_URL --pooled

# Prisma format
seren env init --project-id <id> --prisma
```

### Organizations

```bash
# List organizations
seren organizations

# List members
seren orgs members --org-id <id>

# Invite a member
seren orgs invite --org-id <id> --email user@example.com --role member
```

### IP Allow List

```bash
# List allowed IPs
seren ip-allow-list --project-id <id> list

# Add an IP
seren ip-allow-list --project-id <id> add \
  --ip-address 192.168.1.0/24 --description "Office network"

# Remove an IP
seren ip-allow-list --project-id <id> remove <entry-id>

# Reset (replace all)
seren ip-allow-list --project-id <id> reset 10.0.0.0/8 172.16.0.0/12
```

### VPC Endpoints

```bash
# List organization VPC endpoints
seren vpc endpoint --org-id <id> list

# Register a VPC endpoint
seren vpc endpoint --org-id <id> add \
  --region aws-us-east-1 --endpoint-id vpce-xxx --label production

# Assign to project
seren vpc project --project-id <id> assign --vpc-endpoint-id <id>
```

### Branch Protection

```bash
# List protection rules
seren branch-protection --project-id <id> list

# Protect a branch
seren branch-protection --project-id <id> create <branch-id> \
  --prevent-deletion --prevent-reset --require-approval
```

### Logical Replication

```bash
# Enable logical replication
seren replication --project-id <id> enable

# List publications
seren replication --project-id <id> list-publications --branch-id <id>

# Create a publication
seren replication --project-id <id> create-publication \
  --branch-id <id> --name my_pub --table users --table orders

# Create replication slot
seren replication --project-id <id> create-slot \
  --branch-id <id> --name my_slot
```

### Webhooks

```bash
# List webhooks
seren webhooks --org-id <id> list

# Create a webhook
seren webhooks --org-id <id> create \
  --url https://example.com/webhook \
  --event project.created --event branch.created

# Rotate secret
seren webhooks --org-id <id> rotate-secret <webhook-id>
```

### Audit Logs

```bash
# View audit logs
seren audit-logs --org-id <id> list --limit 100
```

### RBAC

```bash
# List roles
seren rbac --org-id <id> list-roles

# Create a custom role
seren rbac --org-id <id> create-role \
  --name developer --permission project.read --permission branch.create

# Assign role to member
seren rbac --org-id <id> assign-role --member-id <id> --role-id <id>
```

### Sessions

```bash
# List active sessions
seren sessions list

# Revoke a session
seren sessions revoke <session-id>

# Revoke all other sessions
seren sessions revoke-others <current-session-id>
```

### Billing

```bash
# List payment methods
seren billing list-payment-methods

# Get usage summary
seren billing get-usage --organization-id <id> \
  --start-date 2024-01-01 --end-date 2024-01-31
```

## Context Management

Set default project and organization to avoid passing `--project-id` repeatedly:

```bash
# Set defaults
seren set-context set --project-id <id> --org-id <id>

# Show current context
seren set-context show

# Clear context
seren set-context clear
```

## Output Formats

```bash
# Table output (default)
seren projects list

# JSON output
seren projects list --format json
seren -o json projects list
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SEREN_API_KEY` | API key for authentication |
| `SEREN_API_HOST` | Custom API host URL |

## Configuration

Config files are stored in:
- macOS: `~/Library/Application Support/seren/`
- Linux: `~/.config/seren/`
- Windows: `%APPDATA%\seren\`

## License

MIT License - see [LICENSE](../LICENSE) for details.
