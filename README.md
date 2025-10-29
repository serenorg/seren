# serenctl

Command-line interface for Seren database management.

## Overview

`serenctl` is the official CLI tool for managing Seren databases, projects, and resources. Built in Rust for maximum performance and reliability.

## Architecture

This project uses a Cargo workspace with two crates:

- **`seren-api`**: Rust SDK for the Seren API (can be used independently)
- **`serenctl`**: CLI binary that uses the SDK

This separation allows the API client to be reused in other Rust projects, integrations, or tools.

## Installation

### From Source

```bash
cargo build --release
```

The binary will be at `target/release/serenctl`.

### Install Locally

```bash
cargo install --path crates/serenctl
```

## Quick Start

### 1. Authenticate

```bash
serenctl auth login
```

You'll be prompted for your API key. Get one at: https://app.seren.com/settings/api-keys

### 2. List Projects

```bash
serenctl projects list
```

### 3. Create a Project

```bash
serenctl projects create --name "My Project" --org "org-123"
```

## Commands

### Authentication

```bash
# Login with API key
serenctl auth login

# Check authentication status
serenctl auth status

# Logout (remove credentials)
serenctl auth logout
```

### Projects

```bash
# List all projects
serenctl projects list

# Get project details
serenctl projects get <project-id>

# Create a new project
serenctl projects create --name "Project Name" --org "org-id"

# Delete a project
serenctl projects delete <project-id>
```

## Global Flags

- `--output <format>`: Output format (`table` or `json`) - default: `table`
- `--api-host <url>`: Override API host URL

Example:

```bash
serenctl projects list --output json
serenctl projects list --api-host http://localhost:3000/api/v1
```

## Configuration

Credentials are stored at:
- macOS/Linux: `~/.config/seren/credentials.toml`
- Windows: `%APPDATA%\seren\credentials.toml`

## Using the Rust SDK

The `seren-api` crate can be used independently in your Rust projects:

```toml
[dependencies]
seren-api = { path = "../serenctl/crates/seren-api" }
# Or when published: seren-api = "0.1"
```

```rust
use seren_api::{Client, ClientConfig};

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

## License

MIT
