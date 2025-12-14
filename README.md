# Seren

Official Rust SDK, CLI, and MCP server for [SerenDB](https://serendb.com) - the serverless Postgres platform.

## Packages

| Package | Description | Crate |
|---------|-------------|-------|
| [seren](./api/) | Rust SDK for the SerenDB API | [![crates.io](https://img.shields.io/crates/v/seren.svg)](https://crates.io/crates/seren) |
| [seren-cli](./cli/) | Command-line interface | [![crates.io](https://img.shields.io/crates/v/seren-cli.svg)](https://crates.io/crates/seren-cli) |
| [seren-mcp](./mcp/) | MCP server for AI assistants | [![crates.io](https://img.shields.io/crates/v/seren-mcp.svg)](https://crates.io/crates/seren-mcp) |

## Quick Start

### CLI

```bash
# Install
cargo install seren-cli

# Or via Homebrew
brew install serenorg/tap/seren

# Login and start managing databases
seren auth login
seren projects list
seren projects create --name my-project --region aws-us-east-1
```

### Rust SDK

```toml
[dependencies]
seren = "0.1"
```

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(ClientConfig::new("seren_your_api_key"))?;

    let projects = client.projects().list().await?;
    println!("Found {} projects", projects.len());

    Ok(())
}
```

### MCP Server (AI Integration)

Enable Claude and other AI assistants to manage your SerenDB databases:

```json
{
  "mcpServers": {
    "seren": {
      "command": "npx",
      "args": ["-y", "seren-mcp@latest", "start:oauth"]
    }
  }
}
```

See [mcp/README.md](./mcp/README.md) for detailed setup instructions.

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

Download from [GitHub Releases](https://github.com/serenorg/seren/releases).

### Package Managers

```bash
# Homebrew (macOS/Linux)
brew install serenorg/tap/seren

# Cargo
cargo install seren-cli
cargo install seren-mcp

# npm (MCP server only)
npx seren-mcp start:oauth
```

## Documentation

- **CLI Reference**: [cli/README.md](./cli/README.md)
- **SDK Reference**: [api/README.md](./api/README.md)
- **MCP Server**: [mcp/README.md](./mcp/README.md)
- **API Documentation**: [docs.serendb.com](https://docs.serendb.com)

## Development

### Prerequisites

- Rust 1.75+
- PostgreSQL (for integration tests)

### Building

```bash
# Build all packages
cargo build

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets

# Format code
cargo fmt
```

### Project Structure

```
seren/
├── api/          # Rust SDK (seren crate)
├── cli/          # CLI tool (seren-cli crate)
├── mcp/          # MCP server (seren-mcp crate)
├── Dockerfile.mcp  # Docker build for MCP server
└── Cargo.toml    # Workspace configuration
```

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting a PR.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/serendb
