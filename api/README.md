# seren

Rust SDK for the [Seren](https://serendb.com) API. The client is generated from the Seren OpenAPI specs via [progenitor](https://github.com/oxidecomputer/progenitor) and covers managed agents, Seren Passwords, branchable Postgres, object storage, payments, and other platform APIs.

## Installation

```toml
[dependencies]
seren = "0.8"
```

## Quick Start

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new("seren_your_api_key_here");
    let client = Client::from_config(&config)?;

    let projects = client.seren_db_list_projects().await?;
    println!("Found {} projects", projects.into_inner().data.len());

    Ok(())
}
```

## Configuration

### API Key

Get your API key from the Seren Console at https://console.serendb.com/settings/api-keys.

### Custom API Host

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_base_url("https://api.serendb.com");
```

### Custom Timeout

```rust
let config = ClientConfig::new("seren_your_api_key")
    .with_timeout(120);
```

## Product Examples

The crate exports static product example metadata for docs, CLIs, notebooks, and onboarding flows:

```rust
use seren::get_seren_product_examples;

for example in get_seren_product_examples() {
    println!("{}", example.title);
    for request in example.requests {
        println!("{} {}", request.method.as_str(), request.path);
    }
}
```

The examples cover Seren Employees, Seren Passwords, branchable Postgres, and object storage. They do not make network calls on their own.

## API

The client is auto-generated from the OpenAPI specs at build time. Methods are available directly on the `Client` struct, such as `client.seren_db_list_projects()`, `client.seren_agent_list_deployments()`, and `client.list_object_storage_buckets(...)`.

Return values are wrapped in `ResponseValue<T>`. Call `.into_inner()` to get the response body.

### Error Handling

The SDK uses `progenitor_client::Error` for API and transport errors:

```rust
use seren::{Client, ClientConfig, Error};

let config = ClientConfig::new("seren_your_api_key");
let client = Client::from_config(&config)?;

match client.seren_db_list_projects().await {
    Ok(response) => println!("Found: {:?}", response.into_inner()),
    Err(Error::InvalidRequest(msg)) => println!("Bad request: {}", msg),
    Err(Error::ErrorResponse(resp)) => {
        println!("API error {}: {:?}", resp.status(), resp.into_inner());
    }
    Err(e) => println!("Error: {}", e),
}
```

## Features

- Type-safe generated client.
- Async API built on `reqwest`.
- Configuration for API keys, bearer tokens, custom base URLs, user agents, and timeouts.
- Static product example metadata for Seren Employees, Seren Passwords, branchable Postgres, and object storage.

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7

## License

MIT License - see [LICENSE](../LICENSE) for details.
