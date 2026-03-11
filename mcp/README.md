# Seren MCP Server

Model Context Protocol (MCP) server for SerenAI, enabling AI agents like Claude to manage your SerenDB databases through natural language.

## Features

- **Project Management**: Create, list, and manage SerenDB projects
- **Branch Operations**: Create branches, manage development workflows
- **Database Queries**: Execute SQL queries directly through your AI assistant
- **Secure OAuth**: OAuth 2.1 (Auth Code + PKCE) for hosted deployments

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
cargo install --path mcp

# Or install directly from Git (no clone)
cargo install --git https://github.com/serenorg/seren.git --package seren-mcp
```

#### Docker

```bash
# Run the MCP server (HTTP mode)
docker run -p 8080:8080 ghcr.io/serenorg/seren-mcp:latest

# With environment configuration
docker run -p 8080:8080 \
  -e API_KEY="seren_..." \
  -e AUTH_TOKEN="..." \
  ghcr.io/serenorg/seren-mcp:latest
```

#### GitHub Releases

Download pre-built binaries from GitHub Releases (tagged versions): https://github.com/serenorg/seren/releases

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_URL` | SerenAI API base URL | `https://api.serendb.com` |
| `API_KEY` | SerenAI API key (for `start`/`start:http`) | Required |
| `AUTH_TOKEN` | Auth token for `start:http` (bearer) | Required for `start:http` |
| `DATABASE_URL` | Postgres URL for OAuth token storage | Required for `start:oauth` |
| `PUBLIC_URL` | Public base URL of this server | Required for `start:oauth` |
| `JWT_SECRET` | HS256 secret for signing MCP access tokens (min 32 bytes) | Required unless `JWT_SECRETS` is set |
| `JWT_SECRETS` | Comma-separated HS256 secrets (first signs; all validate for rotation) | Optional |
| `OAUTH_TOKEN_ENCRYPTION_KEYS` | Comma-separated keys for encrypting upstream OAuth tokens at rest (first is primary; others allow rotation). Use a single value for one key. | Required for `start:oauth` |
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

The easiest way to use Seren MCP is through our hosted server at `mcp.serendb.com`. No local installation required!

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
# If you have seren-mcp installed globally
claude mcp add seren seren-mcp start

# With custom API key
claude mcp add seren seren-mcp start --env API_KEY=seren_...
```

**Manual configuration:**

```json
{
  "mcpServers": {
    "seren": {
      "command": "seren-mcp",
      "args": ["start"],
      "env": {
        "API_KEY": "seren_..."
      }
    }
  }
}
```

After adding the server configuration (either method), restart Claude Desktop and you can start using Seren MCP in your conversations!

## Usage Examples

Once configured, you can ask Claude to:

- "List all my SerenDB projects"
- "Create a new project called 'analytics-db'"
- "Show me the branches in my project"
- "Create a development branch from main"
- "Run this SQL query on my database: SELECT * FROM users LIMIT 10"
- "Run a prepaid API request against a store publisher"

### Managed Agent Tools

The MCP server also exposes first-class tools for managed `seren-agent` deployments. Use these when you want prompt-defined cloud agents without uploading a code bundle.

See [docs/managed-agents.md](../docs/managed-agents.md) for the full model and CLI equivalents.

- `deploy_seren_agent` deploys a managed prompt-based agent
- `get_seren_agent_deployment` returns the resolved deployment detail
- `list_seren_agent_deployment_revisions` shows immutable revision history
- `preview_seren_agent_deployment_update` returns a resolved diff before mutation
- `update_seren_agent_deployment` applies the managed update
- `preview_seren_agent_deployment_rollback` previews a rollback diff
- `rollback_seren_agent_deployment` reverts to a prior revision

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

`allowed_remote_agent_origins` is optional. Leave it unset to disable remote A2A delegation entirely.

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

Both tools accept an optional `request_id` (UUID) for idempotency.

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
- The hosted server (`start:oauth`) disables local wallet for security
- Your private key is never logged, even in debug mode
- Consider using a separate wallet with limited funds for x402 payments

## Commands

```bash
# Start in stdio mode (Claude Desktop / local)
seren-mcp start

# Start in HTTP mode with simple bearer auth
seren-mcp start:http

# Start in HTTP mode with OAuth 2.1 (hosted)
seren-mcp start:oauth

# Show help
seren-mcp --help

# Show version
seren-mcp --version
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
seren-mcp start:oauth
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
claude mcp add --scope user seren-local seren-mcp start \
  --env API_KEY=your-api-key \
  --env API_URL=http://localhost:8080

# Or add to current project only
claude mcp add --scope project seren-local seren-mcp start \
  --env API_KEY=your-api-key \
  --env API_URL=http://localhost:8080
```

Or manually in your config:

```json
{
  "mcpServers": {
    "seren-local": {
      "command": "seren-mcp",
      "args": ["start"],
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
      "args": ["run", "--package", "seren-mcp", "--", "start"],
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

seren-mcp start:http
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

# Build the MCP server
cargo build --release --package seren-mcp

# Run locally
./target/release/seren-mcp start:http
```

### Building Docker Image

```bash
# Build from repository root
docker build -f docker/mcp.Dockerfile -t seren-mcp .

# Run the container
docker run -p 8080:8080 seren-mcp
```

### Running Tests

```bash
cargo test --package seren-mcp
```

### Building with Telemetry (Production)

For hosted deployments with OpenTelemetry support:

```bash
cargo build --release --package seren-mcp --features telemetry
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
curl http://localhost:3000/health
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
