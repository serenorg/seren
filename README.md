# seren-cli

Command-line interface for Seren database management.

## Overview

`seren` is the official CLI tool for managing Seren databases, projects, and resources. Built in Rust for maximum performance and reliability.

## Architecture

This project is a standalone CLI tool that uses the `seren` SDK (seren-api).

- **`seren-api`**: Rust SDK for the Seren API (separate repository)
- **`seren-cli`**: CLI binary that uses the SDK (this repository)

This separation allows the API client to be reused in other Rust projects, integrations, or tools.

## Installation

### From Source

```bash
cargo build --release
```

The binary will be at `target/release/seren`.

### Install Locally

```bash
cargo install --path .
```

## Quick Start

### 1. Authenticate

```bash
seren auth login
```

You'll be prompted for your API key. Get one at: https://app.seren.com/settings/api-keys

### 2. List Projects

```bash
seren projects list
```

### 3. Create a Project

```bash
seren projects create --name "My Project" --org "org-123"
```

## Commands

### Authentication

```bash
# Login with API key
seren auth login

# Check authentication status
seren auth status

# Logout (remove credentials)
seren auth logout
```

### Projects

```bash
# List all projects
seren projects list

# Get project details
seren projects get <project-id>

# Create a new project
seren projects create --name "Project Name" --org "org-id"

# Delete a project
seren projects delete <project-id>
```

## Global Flags

- `--output <format>`: Output format (`table` or `json`) - default: `table`
- `--api-host <url>`: Override API host URL

Example:

```bash
seren projects list --output json
seren projects list --api-host http://localhost:3000/api/v1
```

## Configuration

Credentials are stored at:
- macOS/Linux: `~/.config/seren/credentials.toml`
- Windows: `%APPDATA%\seren\credentials.toml`

## Using the Rust SDK

The `seren` SDK can be used independently in your Rust projects:

```toml
[dependencies]
seren = { path = "../seren-api" }
# Or when published: seren = "0.1"
```

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new("seren_your_api_key");
    let client = Client::new(config)?;
    
    let projects = client.projects().list().await?;
    println!("Found {} projects", projects.len());
    
    Ok(())
}
```

## Development

### Build

```bash
cargo build
```

### Run

```bash
cargo run -- projects list
```

#### Connection strings (direct vs pooled)

The `branches connection-string` command now returns both direct and pooled
connection strings, backed by the SerenDB proxy:

```bash
# Direct proxy connection string (recommended default)
seren branches connection-string <branch-id>

# Pooled proxy connection string (PgBouncer via SerenDB proxy)
seren branches connection-string <branch-id> --pooled

# JSON output with both variants
seren branches connection-string <branch-id> --format json
```

In table output, the CLI shows:

- `Active Mode`: which DSN is currently selected (Direct or Pooled)
- `Direct`: direct connection string (typically via SerenDB proxy)
- `Pooled`: pooled connection string when available (via PgBouncer/proxy)

Flags:

- `--pooled`: prefer the pooled DSN when printing the “active” connection
- `--ssl=<mode>`: override `sslmode` (e.g. `require`, `disable`)
- `--prisma`: emit a Prisma-style `DATABASE_URL="..."` using the active DSN

Example JSON output:

```bash
seren branches connection-string <branch-id> --format json
```

```json
{
  "direct": "postgresql://user:password@ep-radiant-sirius-a1b2c3d4.c-1.us-east-1.dev.serendb.com:5432/mydb?sslmode=require&channel_binding=require",
  "pooled": "postgresql://user:password@ep-radiant-sirius-a1b2c3d4-pooler.c-1.us-east-1.dev.serendb.com:5432/mydb?sslmode=require&channel_binding=require",
  "active": "postgresql://user:password@ep-radiant-sirius-a1b2c3d4.c-1.us-east-1.dev.serendb.com:5432/mydb?sslmode=require&channel_binding=require"
}
```

### Test

```bash
cargo test
```

### Format

```bash
cargo fmt
```

### Lint

```bash
cargo clippy
```

## Technology Stack

- **Language**: Rust 2021 edition
- **CLI**: clap v4 (derive API)
- **HTTP**: reqwest with rustls-tls
- **Async**: tokio
- **Serialization**: serde + serde_json
- **Tables**: comfy-table
- **Colors**: colored

## Commit Conventions

This workspace uses **Conventional Commits** for git history quality.

- Commit messages must follow:
  - `type(scope): description`
  - Example: `feat(cli): add billing health command`
- A shared `commit-msg` hook is provided in `.githooks/commit-msg`.

To enable the hook locally:

```bash
git config core.hooksPath .githooks
```

## License

MIT
