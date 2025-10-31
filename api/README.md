# seren

Rust SDK for the Seren API, providing programmatic access to Seren database management.

## Overview

`seren` is the official Rust SDK for managing Seren databases, projects, and resources. It provides a type-safe, ergonomic interface to the Seren API.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
seren = "0.1"
```

## Quick Start

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with your API key
    let config = ClientConfig::new("seren_your_api_key_here");
    let client = Client::new(config)?;
    
    // List all projects
    let projects = client.projects().list().await?;
    println!("Found {} projects", projects.len());
    
    // Get a specific project
    let project = client.projects().get("project-id").await?;
    println!("Project: {}", project.name);
    
    // Create a new project
    use seren::CreateProjectRequest;
    let new_project = client.projects().create(CreateProjectRequest {
        name: "My New Project".to_string(),
        organization_id: "org-id".to_string(),
    }).await?;
    
    Ok(())
}
```

## Configuration

### API Key

Get your API key from the Seren Console at: https://app.seren.com/settings/api-keys

### Custom API Host

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_base_url("https://api.seren.com/v1");
```

### Custom Timeout

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_timeout(120); // 120 seconds
```

## API Reference

### Projects

```rust
// List all projects
let projects = client.projects().list().await?;

// Get a project by ID
let project = client.projects().get("project-id").await?;

// Create a project
let project = client.projects().create(CreateProjectRequest {
    name: "Project Name".to_string(),
    organization_id: "org-id".to_string(),
}).await?;

// Delete a project
client.projects().delete("project-id").await?;
```

## Error Handling

The SDK uses a custom `Result` type with detailed error variants:

```rust
use seren::{Client, Error};

match client.projects().get("invalid-id").await {
    Ok(project) => println!("Found: {}", project.name),
    Err(Error::NotFound(msg)) => println!("Not found: {}", msg),
    Err(Error::Auth(msg)) => println!("Auth error: {}", msg),
    Err(Error::Api { status, message }) => println!("API error {}: {}", status, message),
    Err(e) => println!("Error: {}", e),
}
```

## Features

- **Type-safe API**: Leverage Rust's type system for compile-time safety
- **Async/await**: Built on tokio for efficient async operations
- **Comprehensive error handling**: Detailed error types for better debugging
- **Configurable**: Customize API host, timeout, and other settings
- **Lightweight**: Minimal dependencies, small binary footprint

## Examples

See the [examples](examples/) directory for more usage examples:

- `basic.rs` - Basic project management
- `error_handling.rs` - Error handling patterns
- `custom_config.rs` - Advanced configuration

## Development

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

### Generate Docs

```bash
cargo doc --open
```

## Used By

- [serenctl](https://github.com/seren/serenctl) - Official CLI tool
- Your project here! Open a PR to add your project

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.seren.com
- Issues: https://github.com/seren/seren/issues
- Community: https://discord.gg/seren
