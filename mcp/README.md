# Seren MCP Server

Model Context Protocol (MCP) server for SerenAI. It lets Claude, Codex, and other MCP-compatible assistants operate SerenDB and the Seren agent platform directly from a conversation.

Seren MCP is the agent-facing control plane for Seren. Once connected, an assistant can deploy Seren Employees and other managed agents on Seren Cloud, request approved vault access, fetch skills and model-service guidance, inspect backend state, work with Postgres databases and branches, manage supporting storage, and use payment flows without switching to a dashboard.

## What Assistants Can Do

| Area | MCP capabilities |
|------|------------------|
| Seren Employees and managed agents | Deploy prompt-defined `seren-agent` services on Seren Cloud, inspect revisions, preview updates, roll back deployments, and configure tool presets, model policy, approval policy, eval gates, and remote A2A delegation |
| Seren Cloud operations | Get organization-wide cloud overview, list deployments, inspect runs and conversations, stream activity, approve or reject pending actions, manage schedules, and inspect artifacts/eval sets |
| Seren Passwords | Let agents list vaults and retrieve approved secrets through encrypted vault access, hosted browser consent, scoped agent identities, read approvals, audit logs, and local unlock modes |
| Skills, models, and services | Fetch publisher and Seren API skill docs so the assistant learns an integration before calling it, create and publish organization custom skills, apply private-model policy and model routing, and reach the notes, memory, and browser-automation services Desktop agents build on |
| Publisher integrations | Discover Seren publishers, inspect and select user OAuth account identities, list MCP tools/resources exposed by a publisher, estimate cost, and call SQL/API/MCP publishers through one interface |
| Backend context | List projects, branches, databases, roles, endpoints, connection strings, and organization resources so the assistant understands the current environment |
| Database work | Create projects and branches, run SQL, inspect schema differences, manage databases/roles, and prepare connection strings for application code |
| Object storage | Create buckets, list objects, upload base64 payloads, create presigned uploads, download objects, delete by object ID or key, and manage supporting file metadata for Seren agents, employees, and applications |
| Payments | Use prepaid balance flows for publisher access, request wallet transfers, or use local x402 wallet signing when running a local MCP server |

## Hosted vs Local

Most users should start with the hosted streamable-HTTP endpoint. It requires no local process and uses OAuth 2.1 for account authorization:

```bash
claude mcp add --scope user --transport http seren https://mcp.serendb.com/mcp
```

Run locally when you need an API key based stdio server, a custom API backend, local Seren Passwords unlock mode, local x402 wallet signing, or development access to MCP logs:

```bash
seren mcp start
```

## Features

- Hosted streamable-HTTP MCP at `https://mcp.serendb.com/mcp`
- Local stdio mode through the unified `seren` CLI binary
- HTTP bearer mode for local testing
- OAuth 2.1 (Authorization Code + PKCE) mode for hosted deployments
- Read-only mode for safer inspection-only use
- Seren Passwords hosted delegation and local vault unlock modes
- Optional local x402 wallet signing for advanced paid publisher flows
- Tool schemas normalized for strict MCP clients

## Usage Modes

### Hosted (Remote)

If your MCP client supports Streamable HTTP servers, connect to:

- `https://mcp.serendb.com/mcp`

Authentication is handled via OAuth 2.1 (Auth Code + PKCE).

### Local

Run the MCP server locally if you need full control or are developing:

#### Cargo (Rust)

```bash
# Build/install from source
git clone https://github.com/serenorg/seren.git
cd seren
cargo install --path cli

# Or install directly from Git (no clone)
cargo install --git https://github.com/serenorg/seren.git --package seren-cli
```

#### Docker

```bash
# Run the hosted MCP server image
docker run -p 8080:8080 ghcr.io/serenorg/seren-mcp:latest

# With environment configuration
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://..." \
  -e PUBLIC_URL="https://mcp.example.com" \
  -e JWT_SECRET="replace-with-32-byte-secret" \
  -e OAUTH_TOKEN_ENCRYPTION_KEYS="replace-with-32-byte-secret" \
  ghcr.io/serenorg/seren-mcp:latest
```

#### GitHub Releases

Download pre-built binaries from GitHub Releases (tagged versions): https://github.com/serenorg/seren/releases

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_URL` | SerenAI API base URL | `https://api.serendb.com` |
| `SEREN_PASSWORDS_API_URL` | HTTPS Seren API gateway base URL for Seren Passwords vault traffic | Defaults to `API_URL` |
| `SEREN_PASSWORDS_URL` | Seren Passwords browser app base URL for hosted delegation consent | `https://passwords.serendb.com` |
| `API_KEY` | SerenAI API key (for `start`/`start:http`) | Required |
| `AUTH_TOKEN` | Auth token for `start:http` (bearer) | Required for `start:http` |
| `DATABASE_URL` | Postgres URL for OAuth token storage | Required for `start:server` |
| `PUBLIC_URL` | Public base URL of this server | Required for `start:server` |
| `JWT_SECRET` | HS256 secret for signing MCP access tokens (min 32 bytes) | Required unless `JWT_SECRETS` is set |
| `JWT_SECRETS` | Comma-separated HS256 secrets (first signs; all validate for rotation) | Optional |
| `OAUTH_TOKEN_ENCRYPTION_KEYS` | Comma-separated keys for encrypting upstream OAuth tokens at rest (first is primary; others allow rotation). Use a single value for one key. | Required for `start:server` |
| `OAUTH_REDIRECT_URL` | Public URL for OAuth browser redirects | Defaults to `API_URL` |
| `UPSTREAM_TIMEOUT_SECS` | Timeout for upstream API requests | `15` |
| `UPSTREAM_CONNECT_TIMEOUT_SECS` | Connect timeout for upstream API | `5` |
| `WALLET_PRIVATE_KEY` | Ethereum private key for x402 crypto payments (local mode only) | Optional |
| `CLEANUP_TOKEN` | Bearer token to enable /cleanup endpoint | Disabled |
| `HOST` | Listen host | `0.0.0.0` |
| `PORT` | Listen port | `3000` |
| `READ_ONLY` | Enable read-only mode (blocks write operations) | `false` |
| `RUST_LOG` | Log level | `seren_mcp=info` |

### Claude Desktop Setup

#### Method 1: Using the Hosted Remote Server (Recommended)

The easiest way to use Seren MCP is through the hosted server at `mcp.serendb.com`. No local installation is required.

**Using the Claude CLI:**

```bash
# Add hosted Seren MCP server globally (recommended - available in all conversations)
claude mcp add --scope user --transport http seren https://mcp.serendb.com/mcp

# Or add to current project only
claude mcp add --scope local --transport http seren https://mcp.serendb.com/mcp
```

**Manual configuration:**

```json
{
  "mcpServers": {
    "seren": {
      "url": "https://mcp.serendb.com/mcp",
      "transport": "streamable-http"
    }
  }
}
```

When you first use the MCP server, you'll be prompted to authorize Claude to access your SerenAI account via OAuth 2.1.

#### Method 2: Using the Local Server

If you need to run the MCP server locally (for development or offline use):

**Using the Claude CLI:**

```bash
# With the unified CLI binary
claude mcp add seren seren mcp start

# With custom API key
claude mcp add seren seren mcp start --env API_KEY=seren_...
```

**Manual configuration:**

```json
{
  "mcpServers": {
    "seren": {
      "command": "seren",
      "args": ["mcp", "start"],
      "env": {
        "API_KEY": "seren_..."
      }
    }
  }
}
```

After adding the server configuration, restart Claude Desktop and use Seren MCP from your conversations.

## Usage Examples

Once configured, you can ask Claude to:

- "Deploy a managed seren-agent for triage, then show me its revision history."
- "Show all cloud deployments waiting for approval and summarize what each run wants to do."
- "Approve this run after you inspect the pending approval details."
- "Deploy this tar.gz deployment bundle to Seren Cloud and return the deployment id."
- "Request access to my Seren Passwords vault, then retrieve the approved API key for the staging deploy."
- "Fetch skill docs for this publisher before calling its tools."
- "List MCP tools exposed by a publisher before calling it."
- "List my SerenDB projects and tell me which branch is production."
- "Create a development branch for this migration and give me a pooled connection string."
- "Run this SQL query on the analytics database: SELECT * FROM users LIMIT 10."
- "Create an object storage bucket for customer exports, upload this generated CSV, and delete the old export by key."
- "Find a publisher that can answer this task, estimate the cost, and call it if the prepaid balance is enough."

### Publisher OAuth Account Selection

Publishers with `requires_user_oauth` use connections authorized by the current user. Assistants can inspect the provider account email or user ID instead of guessing which identity a publisher call will use.

1. Call `list_user_oauth_connections` to inspect connection IDs, provider identities, validity, and defaults.
2. If no connection exists, call `list_user_oauth_providers`, then `start_user_oauth_connection` with an allowed redirect URI and ask the user to open the returned consent URL.
3. Pass `connection_id` to `call_publisher`, `list_mcp_tools`, or `list_mcp_resources` when a workflow requires an exact account. Use `set_default_user_oauth_connection` when selector-less calls should use that account by default.
4. For a managed deployment, set `oauth_connection_id` on each publisher `tool_ref` that must remain bound to an exact account. The runtime rejects a different per-call connection ID.

OAuth consent remains a human action. These tools expose connection metadata and selection controls but never return provider tokens.

### Seren Passwords Tools

Seren Passwords lets agents use credentials without pasting secrets into prompts or committing them into project files. Hosted MCP uses browser consent to create a scoped agent identity, and local MCP can unlock a vault from the user's machine. Vault owners can require approvals for sensitive reads, grant or revoke memberships, rotate vault keys, and inspect audit logs.

Typical hosted flow:

1. Call `passwords_request_access` to create a short-lived browser consent URL.
2. Open the returned URL and approve the vaults the hosted MCP agent may access.
3. Call `passwords_grant_status` until it returns `granted`.
4. Use `passwords_vaults_list`, `passwords_items_list`, and `passwords_item_get` directly, or call them through `call_publisher` with publisher `seren-passwords`.

Built-in helper tools:

- `passwords_request_access` starts hosted access setup and returns a consent URL
- `passwords_grant_status` checks and finalizes the hosted access request
- `passwords_vaults_list` lists vaults available to the current agent/session
- `passwords_items_list` lists decrypted item metadata in a vault
- `passwords_item_get` retrieves one item, with reveal behavior controlled by the tool parameters

Local MCP mode also exposes vault administration and migration tools, including vault create/archive/rotate, item create/update/delete/restore, encrypted attachments, approvals, memberships, invitations, shares, audit verification, import/export, and agent identity provisioning.

### Managed Agent Tools

The MCP server also exposes first-class tools for managed `seren-agent` deployments. Use these when you want prompt-defined cloud agents without uploading a code bundle. Seren Employees is the product name for managed `seren-agent` deployments that run on Seren Cloud with a stable role, instructions, tools, approvals, and lifecycle.

See [docs/managed-agents.md](../docs/managed-agents.md) for the full model and CLI equivalents.

- `deploy_seren_agent` deploys a managed prompt-based agent
- `get_seren_agent_deployment` returns the resolved deployment detail
- `list_seren_agent_deployment_revisions` shows immutable revision history
- `start_seren_agent_deployment` starts a managed deployment through the seren-agent lifecycle API
- `stop_seren_agent_deployment` stops a managed deployment through the seren-agent lifecycle API
- `delete_seren_agent_deployment` deletes a managed deployment through the seren-agent lifecycle API
- `preview_seren_agent_deployment_update` returns a resolved diff before mutation
- `update_seren_agent_deployment` applies the managed update
- `preview_seren_agent_deployment_rollback` previews a rollback diff
- `rollback_seren_agent_deployment` reverts to a prior revision

### Cloud Activity Tools

Use these tools when you want an organization-wide operator view before drilling into one deployment.

- `get_cloud_overview` returns deployment counts, recent runs, and pending approvals in one response
- `list_all_cloud_runs` returns the global run feed across all deployments
- `list_pending_cloud_approvals` returns the global approval inbox
- `list_cloud_agents` returns the deployment inventory
- `deploy_cloud_agent` accepts either `deployment_bundle_id` or `deployment_bundle_content_base64`, registers/uploads the bundle when needed, and deploys by bundle id
- `get_cloud_deployment_bundle` returns uploaded bundle metadata without raw content

`deployment_bundle_content_base64` is an MCP tool-input convenience for clients that cannot pass a local file path; the Seren Cloud API still receives raw bundle bytes through the generated deployment-bundle upload endpoint.

Example `get_cloud_overview` parameters:

```json
{
  "runs_limit": 8,
  "approvals_limit": 8
}
```

Typical workflow:

1. Call `get_cloud_overview` to see whether anything is stuck or awaiting approval.
2. Use `list_pending_cloud_approvals` to inspect the approval queue in more detail.
3. Use `get_cloud_agent_run` or `get_cloud_agent_deployment` once you know which run or deployment needs attention.

Example `deploy_seren_agent` parameters:

```json
{
  "name": "Ops Router",
  "mode": "always_on",
  "template": "workflow_agent",
  "tool_presets": ["live_data", "publisher_actions"],
  "approval_policy": "allow_mutations",
  "model_policy": "balanced",
  "prompt": "Triage requests, use Seren publishers first, and delegate to approved remote agents when appropriate.",
  "model_id": "gpt-5",
  "allowed_remote_agent_origins": [
    "https://agents.seren.ai",
    "agents.internal"
  ]
}
```

`prompt` is an MCP convenience field. The server materializes it as the `SKILL.md` instruction in `workload.execution.bundle`; it does not send `prompt` or `system_prompt` as top-level Seren Agent API fields.

`allowed_remote_agent_origins` is optional. Leave it unset to disable remote A2A delegation entirely.

Advanced managed-agent deploys can also pass raw `tool_definitions`. Each tool definition may include:

- `timeout_override_seconds`
- `max_output_bytes`

Example `update_seren_agent_deployment` parameters for an eval gate:

```json
{
  "deployment_id": "dep_123",
  "eval_gate_set_id": "8c74c3cb-9fd0-45d7-972c-3ca0fe5b8b88",
  "eval_gate_max_age_seconds": 86400
}
```

Clear the gate:

```json
{
  "deployment_id": "dep_123",
  "clear_eval_gate": true
}
```

### Store Prepaid Tools

Use prepaid balance (fiat/Stripe) for store access:

- `get_prepaid_balance` - Check your prepaid balance summary (virtual wallet)
- `create_prepaid_deposit` - Create a prepaid deposit (returns provider client data)
- `execute_paid_query` - Run a prepaid SQL query against a publisher database
- `execute_paid_api` - Run a prepaid HTTP request against a publisher API

`execute_paid_query` and `execute_paid_api` accept an optional `request_id` (UUID) for idempotency.

### Hosted Settlement Metadata

Successful hosted publisher calls can include Seren settlement details in the MCP result `_meta` object. Clients that enforce local spend limits can use `seren/settlementReceipt.receiptId` as the idempotent correlation key and `seren/settledCharge` as an immediate settled-cost hint. A receipt can be present without a settled charge while an asynchronous or streaming operation is still pending.

- `seren/settlementReceipt`: `{ "receiptId": "<uuid>" }`
- `seren/settledCharge`: `{ "micros": <integer>, "asset": "<symbol>" }`

Only trust this metadata when it comes from the configured hosted Seren MCP origin. Publisher content and metadata from arbitrary MCP servers are not settlement records.

### X402 Local Signing (Advanced)

For advanced users who want to pay for store data using cryptocurrency, you can configure a local wallet for x402 payments. This keeps your private key on your local machine - it never leaves your device.

**Setup:**

1. Set the `WALLET_PRIVATE_KEY` environment variable with your Ethereum private key:

    ```bash
    # In your Claude Desktop config or shell
    export WALLET_PRIVATE_KEY="0x..."
    ```

2. Configure spending thresholds in your config directory:

    - Linux/macOS: `~/.config/seren-mcp/signer.toml` (XDG, respects `$XDG_CONFIG_HOME`)
    - Windows: `%APPDATA%\seren-mcp\signer.toml`

    ```toml
    # Auto-approve payments under this amount (in USD)
    # Payments above this threshold will prompt for confirmation
    # Set to 0 to always prompt for confirmation
    auto_approve_limit = 0.10
    ```

3. The config file is auto-created with safe defaults on first use.

**How it works:**

- When you run a paid query and the publisher supports x402 payments, the MCP server will automatically sign the payment using EIP-712 typed data signing
- Payments under your `auto_approve_limit` are processed automatically
- Larger payments require explicit confirmation via the `confirm: true` parameter
- Your private key is NEVER sent to any server - all signing happens locally

**Security notes:**

- Only use x402 local signing with the local MCP server (`start` mode)
- The hosted server (`start:server`) disables local wallet for security
- Your private key is never logged, even in debug mode
- Consider using a separate wallet with limited funds for x402 payments

## Commands

```bash
# Start in stdio mode (Claude Desktop / local)
seren mcp start

# Start in HTTP mode with simple bearer auth
seren mcp start:http

# Start in HTTP mode with OAuth 2.1 (hosted)
seren mcp start:server

# Show help
seren mcp --help

# Show version
seren --version
```

## Running Against a Local API

If you're running your own API backend (e.g., for self-hosted deployments or development), you can point the MCP server at it.

### Option 1: HTTP with OAuth (Full Authentication)

This mode runs the MCP server with full OAuth 2.1 authentication against your local API.

**Requirements:**
- PostgreSQL database for MCP token storage
- Local API running with OAuth support

**Quick start with Make:**

```bash
make mcp-dev
```

This will:
- Create an MCP database (using PostgreSQL on port 55433)
- Start the MCP server on port 3100
- Connect to the API at `http://localhost:8080`

**Manual setup:**

```bash
# Set environment variables
export API_URL=http://localhost:8080           # Your API server
export OAUTH_REDIRECT_URL=http://localhost:8080
export PUBLIC_URL=http://localhost:3100        # MCP server URL
export DATABASE_URL=postgresql://user:pass@localhost:5432/mcp_db
export JWT_SECRET=your-secret-at-least-32-bytes-long
export HOST=0.0.0.0
export PORT=3100

# Start with OAuth
seren mcp start:server
```

**Add to Claude Code:**

```bash
# Add globally (available in all projects)
claude mcp add --scope user --transport http seren-local http://localhost:3100/mcp

# Or add to current project only
claude mcp add --scope project --transport http seren-local http://localhost:3100/mcp
```

Or manually in your config:

```json
{
  "mcpServers": {
    "seren-local": {
      "url": "http://localhost:3100/mcp",
      "transport": "http"
    }
  }
}
```

When Claude connects, it will trigger the OAuth flow against your local API.

### Option 2: stdio Mode (Simple, API Key Required)

If you have an API key from your local API, you can run in stdio mode without needing a separate database.

**Add to Claude Code:**

```bash
# Add globally (available in all projects)
claude mcp add --scope user seren-local seren mcp start \
  --env API_KEY=your-api-key \
  --env API_URL=http://localhost:8080

# Or add to current project only
claude mcp add --scope project seren-local seren mcp start \
  --env API_KEY=your-api-key \
  --env API_URL=http://localhost:8080
```

Or manually in your config:

```json
{
  "mcpServers": {
    "seren-local": {
      "command": "seren",
      "args": ["mcp", "start"],
      "env": {
        "API_KEY": "your-api-key",
        "API_URL": "http://localhost:8080"
      }
    }
  }
}
```

**Running from source:**

```json
{
  "mcpServers": {
    "seren-local": {
      "command": "cargo",
      "args": ["run", "--package", "seren-cli", "--", "mcp", "start"],
      "cwd": "/path/to/seren",
      "env": {
        "API_KEY": "your-api-key",
        "API_URL": "http://localhost:8080"
      }
    }
  }
}
```

### Option 3: HTTP with Bearer Token

For testing without OAuth, you can use simple bearer token authentication:

```bash
export API_KEY=your-api-key
export API_URL=http://localhost:8080
export AUTH_TOKEN=your-bearer-token
export PORT=3100

seren mcp start:http
```

**Claude Code configuration:**

```json
{
  "mcpServers": {
    "seren-local": {
      "url": "http://localhost:3100/mcp",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer your-bearer-token"
      }
    }
  }
}
```

## Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/serenorg/seren.git
cd seren

# Build the unified CLI binary
cargo build --release --package seren-cli

# Run locally
./target/release/seren mcp start:http
```

### Building Docker Image

```bash
# Build from repository root
docker build -f docker/mcp.Dockerfile -t seren-mcp .

# Run the hosted container
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://..." \
  -e PUBLIC_URL="https://mcp.example.com" \
  -e JWT_SECRET="replace-with-32-byte-secret" \
  -e OAUTH_TOKEN_ENCRYPTION_KEYS="replace-with-32-byte-secret" \
  seren-mcp
```

### Running Tests

```bash
cargo test --package seren-mcp
cargo test --package seren-cli
```

### Building with Telemetry (Production)

For hosted deployments with OpenTelemetry support:

```bash
cargo build --release --package seren-cli --features telemetry
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude/AI      │────▶│  Seren MCP      │────▶│  SerenAI API    │
│  Assistant      │◀────│  Server         │◀────│  (api.serendb)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │
        │                       ▼
        │               ┌─────────────────┐
        │               │  OAuth Flow     │
        │               │  (User Auth)    │
        │               └─────────────────┘
        │                       │
        ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SerenDB Platform                          │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │
│  │ Projects  │  │ Branches  │  │ Databases │  │ Endpoints │    │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Security

- OAuth 2.1 with PKCE for secure authentication
- Upstream OAuth tokens are encrypted at rest in Postgres (set `OAUTH_TOKEN_ENCRYPTION_KEYS`)
- Tokens are refreshed automatically
- All API communication uses TLS encryption
- Refresh tokens are never stored in plaintext (SHA-256 hashes only)

## Troubleshooting

### "Connection refused" error

Ensure the MCP server is running and accessible:

```bash
curl http://localhost:3000/readyz
```

### OAuth authentication fails

1. Verify your OAuth client ID is correct
2. Check that the authorization URL is accessible
3. Ensure your browser can open the OAuth popup

### Claude doesn't see the server

1. Restart Claude Desktop after configuration changes
2. Check the MCP server logs for errors
3. Verify the configuration file syntax is valid JSON

## Support

- Documentation: https://docs.serendb.com/mcp
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7

## License

MIT License - see [LICENSE](../LICENSE) for details.
