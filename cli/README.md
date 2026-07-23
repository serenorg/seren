# Seren CLI

Command-line interface for managing SerenAI from a terminal, script, CI job, or coding agent.

The `seren` binary is the operational interface for SerenDB and the surrounding agent platform. Use it to deploy Seren Employees and other managed agents on Seren Cloud, provision encrypted vault access for agents, install skills, configure model services, manage Postgres databases and supporting storage, and emit JSON for automation.

## What You Can Do

| Area | CLI workflows |
|------|---------------|
| Seren Employees and managed agents | Deploy prompt-defined `seren-agent` services on Seren Cloud, manage revisions, start/stop deployments, configure tool and model policy, and roll back changes |
| Seren Cloud operations | Review cloud activity, approve or reject blocked runs, inspect artifacts/eval sets, manage schedules, and deploy agent bundles |
| Seren Passwords | Create encrypted vaults, store logins/API keys/secure notes, upload encrypted attachments, grant scoped agent identities, require approvals, audit access, and rotate vault keys |
| Skills and agent workspace support | Search/install skills, fetch generated skill docs, manage organization custom skills, configure private-model policy, and prepare workflows used by Seren Desktop employees and agents |
| Organizations and security | Manage members, invites, OAuth providers, IP allow lists, VPC endpoints, RBAC, sessions, audit logs, webhooks, billing, and operations |
| Agent automation | Use stable command groups, `-o json`, and saved context so coding agents can inspect state, make changes, and verify results without scraping the dashboard |
| SerenDB projects | Create projects, list branches, manage databases and roles, fetch direct or pooled connection strings, configure endpoints, and initialize `.env` files |
| Branching and recovery | Create development branches, restore a branch from a timestamp, compare schemas, set branch expiration, protect production branches, and reset or delete branches |
| Object storage | Create buckets, upload/download objects, attach metadata, and manage supporting files for Seren agents, employees, and applications |
| Publishers and payments | Discover publishers, call paid SQL/API/MCP integrations, estimate cost, manage prepaid balance, and prepare x402 payment flows |

## CLI vs MCP

Use the CLI when a human, script, CI job, or coding agent can run shell commands. Use the MCP server when an AI assistant should call Seren tools directly inside the assistant protocol. The same binary includes both interfaces:

```bash
seren projects list
seren -o json agent cloud overview
seren mcp start
```

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/serenorg/seren.git
cd seren
cargo install --path cli
```

### From Git (No Clone)

```bash
cargo install --git https://github.com/serenorg/seren.git --package seren-cli
```

### Pre-built Binaries

Download pre-built binaries from GitHub Releases (tagged versions): https://github.com/serenorg/seren/releases

## Quick Start

Start with browser login for interactive use:

```bash
seren auth login
seren agent cloud overview
seren skills search issues
seren projects list
```

For automation, set an API key and request JSON output:

```bash
export SEREN_API_KEY=your_seren_api_key
seren -o json agent cloud overview
seren -o json projects list
```

Common first workflows:

```bash
# Deploy a managed prompt-based agent
seren agent deploy-prompt \
  --name "Ops Router" \
  --template workflow_agent \
  --tool-preset live_data,publisher_actions \
  --approval-policy allow_mutations \
  --model-policy balanced \
  --prompt "Triage requests, use Seren publishers first, and ask for approval before mutations."

# Create a vault and provision an agent identity with read access
seren passwords vaults create --name "Production APIs" --requires-approval sensitive-only
seren passwords agent provision --vault <vault-id> --access read --name "Claude ops agent" --expires-in-days 30

# Search reusable skills and model services
seren skills search browser
seren agent private-models list

# Review cloud activity across the organization
seren agent cloud overview
seren agent cloud approvals list --limit 20

# Create an isolated branch for development
seren branches --project-id <project-id> create --name feature-auth

# Initialize an env file with a database URL
seren env init --project-id <project-id> --branch-id <branch-id> --key DATABASE_URL --pooled
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
export SEREN_API_KEY=your_seren_api_key
seren projects list

# Or pass directly
seren --api-key your_seren_api_key projects list
```

### Check Status

```bash
seren auth status
seren me
```

## Commands

### Projects

```bash
seren projects list
seren projects get <project-id>
seren projects create --name my-project --region aws-us-east-1
seren projects create --name my-project --region aws-us-east-1 --psql  # connect via psql after creation
seren projects update <project-id> --name new-name
seren projects connection-uri <project-id>
seren projects connection-uri <project-id> --pooled --branch-id <id>
seren projects delete <project-id>
seren projects delete <project-id> --yes
```

### Branches

```bash
seren branches --project-id <id> list
seren branches --project-id <id> get <branch-id>
seren branches --project-id <id> create --name feature-branch
seren branches --project-id <id> create --name restore-branch \
  --parent <parent-id> --parent-timestamp "2025-01-15T10:00:00Z"
seren branches --project-id <id> create --name temp-branch --expires-in 7d
seren branches --project-id <id> create --name schema-branch --schema-only
seren branches --project-id <id> connection-string <branch-id>
seren branches --project-id <id> connection-string <branch-id> --pooled
seren branches --project-id <id> rename <branch-id> --name new-name
seren branches --project-id <id> set-default <branch-id>
seren branches --project-id <id> set-expiration <branch-id> --expires-at "2025-12-31T23:59:59Z"
seren branches --project-id <id> schema-diff \
  --base-branch-id <id> --compare-branch-id <id>
seren branches --project-id <id> reset <branch-id>
seren branches --project-id <id> restore <branch-id> \
  --source ^self --preserve-under-name backup \
  --timestamp "2025-01-15T10:00:00Z"
seren branches --project-id <id> delete <branch-id>
```

### Databases & Roles

```bash
# Databases
seren databases --project-id <id> --branch-id <id> list
seren databases --project-id <id> --branch-id <id> create --name mydb
seren databases --project-id <id> --branch-id <id> delete <db-id>

# List all databases across projects
seren database list
seren database list --project-id <id>

# Roles
seren roles --project-id <id> --branch-id <id> list
seren roles --project-id <id> --branch-id <id> create --name myrole
seren roles --project-id <id> --branch-id <id> reset-password --id <role-id> --password newpass
seren roles --project-id <id> --branch-id <id> reveal-password --name <role-name>
seren roles --project-id <id> --branch-id <id> delete <role-id>
```

### Endpoints

```bash
seren endpoints --project-id <id> --branch-id <id> list
seren endpoints --project-id <id> --branch-id <id> create \
  --name my-endpoint --compute-unit medium
seren endpoints --project-id <id> --branch-id <id> create \
  --name my-endpoint --autoscaling-min 1 --autoscaling-max 4
seren endpoints --project-id <id> --branch-id <id> update <endpoint-id> \
  --autoscaling-min 2 --autoscaling-max 8
seren endpoints --project-id <id> --branch-id <id> suspend <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> start <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> restart <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> health <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> metrics <endpoint-id>
seren endpoints --project-id <id> --branch-id <id> delete <endpoint-id>
```

### Seren Passwords

Use Seren Passwords when an agent needs credentials without copying them into prompts, shell history, or plaintext config files. Vaults can store logins, API keys, secure notes, and encrypted attachments. Agent identities can be granted read/write access to specific vaults and revoked later.

```bash
# Vaults
seren passwords vaults list
seren passwords vaults create --name "Production APIs" --requires-approval sensitive-only
seren passwords vaults update <vault-id> --name "Production Integrations"
seren passwords vaults rotate initiate <vault-id>
seren passwords vaults rotate complete <vault-id>

# Items
printf "%s" "$API_TOKEN" | seren passwords items create-api-key \
  --vault-id <vault-id> --title "Stripe API" --key-stdin --credential-kind api_key \
  --tag production --tag billing --sensitive
seren passwords items create-login \
  --vault-id <vault-id> --title "Admin console" --username ops@example.com \
  --password-stdin --url https://admin.example.com --sensitive
seren passwords items create-note --vault-id <vault-id> --title "Runbook note" --body-stdin
seren passwords items list --vault-id <vault-id>
seren passwords items get --vault-id <vault-id> --item-id <item-id>
seren passwords items get --vault-id <vault-id> --item-id <item-id> --reveal

# Attachments
seren passwords attachments upload --vault-id <vault-id> --item-id <item-id> --path ./client.pem
seren passwords attachments list --vault-id <vault-id> --item-id <item-id>
seren passwords attachments download \
  --vault-id <vault-id> --item-id <item-id> --attachment-id <attachment-id> --output ./client.pem

# Agent access
seren passwords agent provision --vault <vault-id> --access read --name "Research agent"
seren passwords agent list
seren passwords agent revoke <agent-identity-id> --vault <vault-id>
seren passwords agent freeze

# Approvals, membership, sharing, and audit
seren passwords approvals list
seren passwords approvals approve <approval-id>
seren passwords memberships list <vault-id>
seren passwords invitations create <vault-id> --email teammate@example.com --access read
seren passwords shares outbound
seren passwords audit list --limit 100
seren passwords audit verify
```

Use `--password-stdin`, `--key-stdin`, and `--body-stdin` for secret material so values do not end up in shell history. Use `seren passwords export` and `seren passwords import` only for explicit plaintext backup or migration workflows.

### Environment Files

```bash
seren env init --project-id <id>
seren env init --project-id <id> --branch-id <id> --key DATABASE_URL --pooled
```

### Organizations

```bash
seren organizations                              # list organizations
seren orgs members --org-id <id>                  # list members
seren orgs invites --org-id <id>                  # list invites
seren orgs invite --org-id <id> --email user@example.com --role member
seren orgs skills --org-id <id> list
seren orgs private-models-policy --org-id <id> get
```

### Skills

Seren skills are installable capability packs that drop into the skills directory of whatever coding agent you use (Claude Code, Codex, Cursor, Gemini, GitHub Copilot, Windsurf, and more), pulled from the public [seren-skills](https://github.com/serenorg/seren-skills) registry.

```bash
seren skills list                        # browse the registry
seren skills search issues               # search by name or description
seren skills show linear-issue-tracking  # view a skill's details
seren skills add linear-issue-tracking   # install into detected agent directories
seren skills add --all                   # install every available skill
seren skills installed                   # list locally installed skills
seren skills update                      # update all installed skills
seren skills remove linear-issue-tracking
seren skills init my-skill               # scaffold a new skill template
```

### Agent Commerce

```bash
# Publishers
seren agent list-publishers
seren agent get-publisher <slug-or-id>
seren agent create-publisher --name "My API" --slug my-api \
  --organization-id <uuid> --wallet-address 0x... --wallet-network-id base-mainnet \
  --publisher-category integration --integration-type api --api-url https://...

# Prepaid balance (SerenBucks)
seren agent get-prepaid-balance
seren agent create-prepaid-deposit --amount 10.00
seren agent get-transaction-history

# Execute paid queries
seren agent execute-query --publisher <slug> --query "SELECT * FROM data LIMIT 10"
seren agent estimate-query-cost --publisher <slug> --query "SELECT * FROM data"

# x402 crypto deposits
seren agent get-deposit-requirements <publisher> <amount> <wallet-address>
seren agent get-supported

# Agent templates
# Supported template languages: python, typescript, javascript
seren agent list-templates
seren agent get-template <slug>
seren agent publish-template --name "My Agent" --slug my-agent \
  --code agent.py --language python --price "0.05"
seren agent invoke-template --slug my-agent --input '{"query": "..."}'

# Generated skill guidance
seren agent api-skill-doc
seren agent publisher-skill-doc seren-agent

# Private models
seren agent private-models list
seren agent private-models catalog --region aws-us-east-1
seren agent private-models chat --model <model-id> --message "Summarize this incident."
```

### Managed Agents

Managed prompt-based agents run through the first-class `seren-agent` publisher. Use them when you want a hosted agent with prompt-defined behavior, publisher-backed tool presets, approval controls, revision history, and optional remote A2A delegation without shipping a code bundle. Seren Employees is the product name for managed `seren-agent` deployments that run on Seren Cloud with a stable role, instructions, tools, approvals, and lifecycle.

See [docs/managed-agents.md](../docs/managed-agents.md) for the full guide.

```bash
# Deploy a read-oriented managed agent
seren agent deploy-prompt \
  --name "BTC Watcher" \
  --template research_monitor \
  --tool-preset live_data,database \
  --approval-policy read_only \
  --model-policy balanced \
  --model-id gpt-5 \
  --prompt "Track BTC/USD, use Seren publishers first, and return a concise summary."

# Inspect the resolved managed deployment
seren agent managed-get <deployment-id>
seren agent managed-revisions <deployment-id>

# Manage the deployment lifecycle through seren-agent
seren agent managed-start <deployment-id>
seren agent managed-stop <deployment-id>
seren agent managed-delete <deployment-id>

# Preview and apply remote A2A delegation settings
seren agent managed-preview <deployment-id> \
  --allow-remote-agent-origin https://agents.seren.ai \
  --allow-remote-agent-origin agents.internal

seren agent managed-update <deployment-id> \
  --allow-remote-agent-origin https://agents.seren.ai \
  --allow-remote-agent-origin agents.internal

# Preview, apply, or clear an eval gate
seren agent managed-preview <deployment-id> \
  --eval-gate-set-id <eval-set-id> \
  --eval-gate-max-age-seconds 86400

seren agent managed-update <deployment-id> \
  --eval-gate-set-id <eval-set-id> \
  --eval-gate-max-age-seconds 86400

seren agent managed-update <deployment-id> --clear-eval-gate

# Invoke the deployment
seren agent cloud run start --deployment-id <deployment-id> \
  --message "Give me the latest BTC update."

# See the org-wide activity overview
seren agent cloud overview
seren agent cloud overview --runs-limit 12 --approvals-limit 6

# Pull the same activity feed as JSON for automation
seren -o json agent cloud runs list --limit 20
seren -o json agent cloud approvals list --limit 20
```

Advanced managed-agent deploys can also use `--agent-config <path>` to supply raw `tool_definitions`. Each tool definition may include:

- `timeout_override_seconds`
- `max_output_bytes`

To attach an existing SerenDB database, add `external_databases` to the skill's `orchestration.json` for `agent deploy`, or to the JSON supplied through `--agent-config` for managed-agent deploys and updates. Omit `access` for read-only access, or request `read_write` when the deployment's approval policy permits mutations.

```json
{
  "external_databases": [
    {
      "project_id": "<project-id>",
      "branch_id": "<branch-id>",
      "database": "existing_database",
      "access": "read_only"
    }
  ]
}
```

Managed skill storage is separate: declare it in the skill manifest under `storage.databases` instead of attaching a physical project, branch, and database.

Changing database attachments on an existing code-bundle deployment requires redeploying it. Prompt-based managed employees can replace or clear attachments through the managed-agent update command.

### Cloud Activity

```bash
# Deployment inventory
seren agent cloud deployment list
seren -o json agent cloud deployment list
seren agent cloud deployment bundle get <deployment-bundle-id>

# Org-wide summary: deployments, recent runs, pending approvals
seren agent cloud overview

# Global activity feeds
seren agent cloud runs list --limit 20 --status running,awaiting_approval
seren agent cloud approvals list --limit 20

# Deployment-scoped activity feeds
seren agent cloud runs list --deployment-id <deployment-id> --limit 20
seren agent cloud approvals list --deployment-id <deployment-id>

# Resolve a blocked run inline
seren agent cloud run pending-approvals <run-id>
seren agent cloud run approve <run-id>
seren agent cloud run reject <run-id>
```

### Object Storage

```bash
seren object-storage buckets list
seren object-storage buckets create \
  --slug employee-files --display-name "Employee files" \
  --metadata '{"team":"ops"}'
seren object-storage buckets delete --bucket employee-files

seren object-storage objects --bucket employee-files list
seren object-storage objects --bucket employee-files list --prefix reports/ --limit 50
seren object-storage objects --bucket employee-files upload \
  --key reports/q1.txt --path ./q1.txt --content-type text/plain
seren object-storage objects --bucket employee-files download \
  --key reports/q1.txt --output ./q1-copy.txt
seren object-storage objects --bucket employee-files delete --object-id <uuid>
```

`seren storage` is a separate command that browses and manages objects through the Seren Storage publisher, scoped to the organization of the authenticated API key. `object-storage` remains the Seren Core organization-administration surface shown above (with explicit `--org-id` selection). `storage` is no longer an alias for `object-storage`.

### OAuth Connections (BYOC)

```bash
seren oauth providers                         # list available OAuth providers
seren oauth connections                       # list your connections
seren oauth connect <provider-slug>           # connect to a provider
seren oauth default <connection-id>           # select the default account for its provider
seren oauth disconnect <connection-id>        # disconnect an exact account

# Organization OAuth provider management
seren orgs oauth --org-id <id> list
seren orgs oauth --org-id <id> create --slug attio --name Attio \
  --authorization-url https://... --token-url https://... \
  --client-id <id> --client-secret <secret> --scope "read,write"
seren orgs oauth --org-id <id> update <provider-id> --name "New Name"
seren orgs oauth --org-id <id> delete <provider-id>
```

### IP Allow List

```bash
seren ip-allow-list --project-id <id> list
seren ip-allow-list --project-id <id> add \
  --ip-address 192.168.1.0/24 --description "Office network"
seren ip-allow-list --project-id <id> remove <entry-id>
seren ip-allow-list --project-id <id> reset 10.0.0.0/8 172.16.0.0/12
```

### VPC Endpoints

```bash
seren vpc endpoint --org-id <id> list
seren vpc endpoint --org-id <id> add \
  --region aws-us-east-1 --endpoint-id vpce-xxx --label production
seren vpc endpoint --org-id <id> get <endpoint-id>
seren vpc endpoint --org-id <id> remove <endpoint-id>
seren vpc project --project-id <id> list
seren vpc project --project-id <id> assign --vpc-endpoint-id <id>
seren vpc project --project-id <id> remove <assignment-id>
```

### Branch Protection

```bash
seren branch-protection --project-id <id> list
seren branch-protection --project-id <id> get <branch-id>
seren branch-protection --project-id <id> create <branch-id> \
  --prevent-deletion --prevent-reset --require-approval
seren branch-protection --project-id <id> update <branch-id> \
  --require-approval true
seren branch-protection --project-id <id> delete <branch-id>
```

### Logical Replication

```bash
seren replication --project-id <id> settings
seren replication --project-id <id> enable
seren replication --project-id <id> list-publications --branch-id <id>
seren replication --project-id <id> create-publication \
  --branch-id <id> --name my_pub --table users --table orders
seren replication --project-id <id> create-slot --branch-id <id> --name my_slot
seren replication --project-id <id> list-slots --branch-id <id>
```

### Webhooks

```bash
seren webhooks --org-id <id> list
seren webhooks --org-id <id> create --name alerts \
  --url https://example.com/webhook \
  --event project.created --event branch.created
seren webhooks --org-id <id> get <webhook-id>
seren webhooks --org-id <id> update <webhook-id> --enabled false
seren webhooks --org-id <id> rotate-secret <webhook-id>
seren webhooks --org-id <id> deliveries <webhook-id>
seren webhooks --org-id <id> event-types
seren webhooks --org-id <id> delete <webhook-id>
```

### Audit Logs

```bash
seren audit-logs --org-id <id> list --limit 100
seren audit-logs --org-id <id> get <log-id>
```

### RBAC

```bash
seren rbac --org-id <id> list-roles
seren rbac --org-id <id> get-role <role-id>
seren rbac --org-id <id> create-role \
  --name developer --permission project.read --permission branch.create
seren rbac --org-id <id> update-role <role-id> --name "Senior Dev"
seren rbac --org-id <id> delete-role <role-id>
seren rbac --org-id <id> assign-role --member-id <id> --role-id <id>
seren rbac --org-id <id> list-permissions
seren rbac --org-id <id> my-permissions
```

### Sessions

```bash
seren sessions list
seren sessions revoke <session-id>
seren sessions revoke-others <current-session-id>
seren sessions revoke-all
```

### Billing

```bash
seren billing list-payment-methods
seren billing add-payment-method <stripe-pm-id>
seren billing remove-payment-method <id>
seren billing get-usage --organization-id <id> \
  --start-date 2025-01-01 --end-date 2025-01-31
seren billing generate-invoices --year 2025 --month 1
seren billing get-invoice <invoice-id>
seren billing issue-invoice <invoice-id>
seren billing health
```

### Operations

```bash
seren operations --project-id <id> list
seren operations --project-id <id> get <operation-id>
```

## Context Management

Set default project and organization to avoid passing `--project-id` repeatedly:

```bash
seren set-context set --project-id <id> --org-id <id>
seren set-context show
seren set-context clear
```

## Output Formats

```bash
seren projects list                # table output (default)
seren projects list --format json  # JSON output
seren -o json projects list        # short form
seren -o json agent cloud overview # machine-readable activity summary
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SEREN_API_KEY` | API key for authentication |
| `SEREN_API_BASE` | Custom API base URL |

## Configuration

Config files are stored in:
- macOS/Linux: `$XDG_CONFIG_HOME/seren/` with `~/.config/seren/` as the fallback
- Windows: `%APPDATA%\seren\`

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7

## License

MIT License - see [LICENSE](../LICENSE) for details.
