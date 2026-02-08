# seren

Rust SDK for the [SerenAI](https://serendb.com) API. Type-safe client generated from the OpenAPI spec via [progenitor](https://github.com/oxidecomputer/progenitor).

## Installation

```toml
[dependencies]
seren = "0.3"
```

## Quick Start

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new("seren_your_api_key_here");
    let client = Client::from_config(&config)?;

    // List all projects
    let projects = client.list_projects(None, None, None).await?;
    println!("Found {} projects", projects.into_inner().data.len());

    Ok(())
}
```

## Configuration

### API Key

Get your API key from the SerenAI Console at: https://console.serendb.com/settings/api-keys

### Custom API Host

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_base_url("https://api.serendb.com");
```

### Custom Timeout

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_timeout(120); // 120 seconds
```

## API

The client is auto-generated from `openapi/openapi.json` at build time. All API methods are available directly on the `Client` struct (e.g., `client.list_projects()`, `client.get_project()`, `client.create_project()`).

Return values are wrapped in `ResponseValue<T>` - call `.into_inner()` to get the response body.

### Error Handling

The SDK uses `progenitor_client::Error` for all errors:

```rust
use seren::{Client, ClientConfig, Error};

let config = ClientConfig::new("seren_your_api_key");
let client = Client::from_config(&config)?;

match client.get_project("project-id").await {
    Ok(response) => println!("Found: {:?}", response.into_inner()),
    Err(Error::InvalidRequest(msg)) => println!("Bad request: {}", msg),
    Err(Error::ErrorResponse(resp)) => {
        println!("API error {}: {:?}", resp.status(), resp.into_inner());
    }
    Err(e) => println!("Error: {}", e),
}
```

## Features

- **Type-safe**: Generated from OpenAPI spec with compile-time type checking
- **Async**: Built on tokio and reqwest
- **Complete**: Covers all SerenAI API endpoints including agent commerce and x402 payments

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7

## License

MIT License - see [LICENSE](../LICENSE) for details.
