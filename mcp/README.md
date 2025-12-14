# Seren MCP Server

Model Context Protocol (MCP) server for SerenDB, enabling AI assistants like Claude to manage your Seren databases through natural language.

## Features

- **Project Management**: Create, list, and manage SerenDB projects
- **Branch Operations**: Create branches, manage development workflows
- **Database Queries**: Execute SQL queries directly through your AI assistant
- **Secure OAuth**: Industry-standard OAuth 2.0 authentication flow

## Installation

### Option 1: Hosted (Recommended)

The easiest way to use Seren MCP is through our hosted service. No installation required.

**Claude Desktop Configuration** (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "seren": {
      "command": "npx",
      "args": ["-y", "seren-mcp@latest", "start:oauth"],
      "env": {
        "MCP_SERVER_URL": "https://mcp.serendb.com"
      }
    }
  }
}
```

### Option 2: npm/npx

Install and run via npm:

```bash
# Run directly with npx (no install needed)
npx seren-mcp start:oauth

# Or install globally
npm install -g seren-mcp
seren-mcp start:oauth
```

### Option 3: Homebrew (macOS/Linux)

```bash
# Add the Seren tap
brew tap serenorg/tap

# Install seren-mcp
brew install seren-mcp

# Run the server
seren-mcp start:oauth
```

### Option 4: Cargo (Rust)

```bash
# Install from crates.io
cargo install seren-mcp

# Or build from source
git clone https://github.com/serenorg/seren.git
cd seren
cargo install --path mcp
```

### Option 5: Docker

```bash
# Run the MCP server
docker run -p 8080:8080 ghcr.io/serenorg/seren-mcp:latest

# With environment configuration
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://..." \
  -e OAUTH_CLIENT_ID="..." \
  ghcr.io/serenorg/seren-mcp:latest
```

### Option 6: GitHub Releases

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
| `PORT` | Server port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | Required for OAuth mode |
| `OAUTH_CLIENT_ID` | OAuth client ID | Required for OAuth mode |
| `OAUTH_AUTHORIZATION_URL` | OAuth authorization endpoint | `https://api.serendb.com/oauth/authorize` |
| `OAUTH_TOKEN_URL` | OAuth token endpoint | `https://api.serendb.com/oauth/token` |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins | `*` |
| `RUST_LOG` | Log level | `seren_mcp=info` |

### Claude Desktop Setup

1. Open Claude Desktop settings
2. Navigate to the MCP configuration
3. Add the Seren server configuration:

```json
{
  "mcpServers": {
    "seren": {
      "command": "seren-mcp",
      "args": ["start:oauth"]
    }
  }
}
```

4. Restart Claude Desktop
5. Start a conversation and ask Claude to help with your SerenDB databases

## Usage Examples

Once configured, you can ask Claude to:

- "List all my SerenDB projects"
- "Create a new project called 'analytics-db'"
- "Show me the branches in my project"
- "Create a development branch from main"
- "Run this SQL query on my database: SELECT * FROM users LIMIT 10"

## Commands

```bash
# Start with OAuth authentication (recommended)
seren-mcp start:oauth

# Start in HTTP mode (for development)
seren-mcp start:http

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
