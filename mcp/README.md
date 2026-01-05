# Seren MCP Server

Model Context Protocol (MCP) server for SerenDB, enabling AI assistants like Claude to manage your Seren databases through natural language.

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
# Install from crates.io
cargo install seren-mcp

# Or build from source
git clone https://github.com/serenorg/seren.git
cd seren
cargo install --path mcp
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

Download pre-built binaries from [GitHub Releases](https://github.com/serenorg/seren/releases):

- `seren-mcp-darwin-arm64` - macOS Apple Silicon
- `seren-mcp-darwin-x86_64` - macOS Intel
- `seren-mcp-linux-x86_64` - Linux x86_64
- `seren-mcp-linux-arm64` - Linux ARM64
- `seren-mcp-windows-x86_64.exe` - Windows x86_64

```bash
# Download and install (macOS/Linux)
curl -L https://github.com/serenorg/seren/releases/latest/download/seren-mcp-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o seren-mcp
chmod +x seren-mcp
sudo mv seren-mcp /usr/local/bin/
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_URL` | Seren API base URL | `https://api.serendb.com` |
| `API_KEY` | Seren API key (for `start`/`start:http`) | Required |
| `AUTH_TOKEN` | Auth token for `start:http` (bearer) | Required for `start:http` |
| `DATABASE_URL` | Postgres URL for OAuth token storage | Required for `start:oauth` |
| `PUBLIC_URL` | Public base URL of this server | Required for `start:oauth` |
| `JWT_SECRET` | Secret key for signing MCP access tokens (min 32 bytes) | Required for `start:oauth` |
| `OAUTH_TOKEN_ENCRYPTION_KEYS` | Comma-separated keys for encrypting upstream OAuth tokens at rest (first is primary; others allow rotation) | Optional |
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

When you first use the MCP server, you'll be prompted to authorize Claude to access your SerenDB account via OAuth 2.1.

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
- "Run a prepaid API request against a marketplace publisher"

### Marketplace Prepaid Tools

Use prepaid balance (fiat/Stripe) for marketplace access:

- `get_prepaid_balance` — Check your prepaid balance summary (virtual wallet)
- `create_prepaid_deposit` — Create a prepaid deposit (returns provider client data)
- `execute_paid_query` — Run a prepaid SQL query against a publisher database
- `execute_paid_api` — Run a prepaid HTTP request against a publisher API

Both tools accept an optional `request_id` (UUID) for idempotency.

### X402 Local Signing (Advanced)

For advanced users who want to pay for marketplace data using cryptocurrency, you can configure a local wallet for x402 payments. This keeps your private key on your local machine - it never leaves your device.

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
│  Claude/AI      │────▶│  Seren MCP      │────▶│  SerenDB API    │
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

- OAuth 2.0 with PKCE for secure authentication
- Tokens are stored securely and refreshed automatically
- All API communication uses TLS encryption
- No credentials are stored in plain text

## Troubleshooting

### "Connection refused" error

Ensure the MCP server is running and accessible:

```bash
curl http://localhost:8080/health
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
- Discord: https://discord.gg/serendb

## License

MIT License - see [LICENSE](../LICENSE) for details.
