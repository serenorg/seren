# Seren

Official Rust SDK, CLI, and MCP server for SerenAI - the team behind [SerenDB](https://serendb.com), a serverless Postgres platform with built-in agent commerce and micropayments.

## Packages

| Package | Description | Status |
|---------|-------------|--------|
| [seren](./api/) | Rust SDK for the SerenAI API (SerenDB) | [![crates.io](https://img.shields.io/crates/v/seren.svg)](https://crates.io/crates/seren) |
| [seren-cli](./cli/) | Command-line interface | Not published on crates.io yet |
| [seren-mcp](./mcp/) | MCP server for AI assistants | Not published on crates.io yet |

## Quick Start

### MCP Server (AI Integration)

Connect Claude or other AI assistants to SerenAI:

```bash
# Claude Code (recommended - no local install needed)
claude mcp add --scope user --transport http seren https://mcp.serendb.com/mcp
```

Or configure manually for Claude Desktop:

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

See [mcp/README.md](./mcp/README.md) for local server setup and all configuration options.

### CLI

```bash
# Install from source (see Installation below)
cargo install --path cli

# Login and start managing databases
seren auth login
seren projects list
seren projects create --name my-project --region aws-us-east-1
```

### Rust SDK

```toml
[dependencies]
seren = "0.5"
```

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new("seren_your_api_key");
    let client = Client::from_config(&config)?;

    let projects = client.list_projects(None, None, None).await?;
    println!("Found {} projects", projects.into_inner().data.len());

    Ok(())
}
```

## Installation

### From Source

```bash
git clone https://github.com/serenorg/seren.git
cd seren

# Build all packages
cargo build --release

# Install CLI
cargo install --path cli

# Install MCP server
cargo install --path mcp
```

### Pre-built Binaries

Download pre-built binaries from GitHub Releases (tagged versions): https://github.com/serenorg/seren/releases

Each release asset includes:
- `seren` (CLI)
- `seren-mcp` (MCP server)

## Development

### Prerequisites

- Rust 1.85+ (edition 2024)
- PostgreSQL (for MCP OAuth mode and integration tests)

### Building

```bash
# Build all packages
cargo build --workspace

# Run tests
cargo test --workspace

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all
```

### Project Structure

```
seren/
├── api/            # Rust SDK - OpenAPI-generated type-safe client
├── cli/            # CLI tool - clap-based database management
├── mcp/            # MCP server - stdio, HTTP, and OAuth modes
│   ├── oauth/      #   OAuth 2.1 + PKCE implementation
│   ├── wallet/     #   x402 crypto payment support
│   └── migrations/ #   Embedded SQL migrations
├── openapi/        # OpenAPI spec (source for SDK codegen)
├── docker/         # Dockerfiles
└── Cargo.toml      # Workspace configuration
```

## Documentation

- **CLI Reference**: [cli/README.md](./cli/README.md)
- **SDK Reference**: [api/README.md](./api/README.md)
- **MCP Server**: [mcp/README.md](./mcp/README.md)
- **API Documentation**: [docs.serendb.com](https://docs.serendb.com)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7
