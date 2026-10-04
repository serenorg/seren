# seren

Rust SDK for the [Seren](https://serendb.com) API. The client is generated from the Seren OpenAPI specs via [progenitor](https://github.com/oxidecomputer/progenitor) and covers Seren Agent, Seren Passwords, Seren Memory, Seren DB, Seren Storage, payments, and other platform APIs.

## Installation

```toml
[dependencies]
seren = { package = "seren-sdk", git = "https://github.com/serenorg/seren.git", tag = "v0.10.0" }
```

## Quick Start

```rust
use seren::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new("your_seren_api_key");
    let client = Client::from_config(&config)?;

    let projects = client.seren_db_list_projects().await?;
    println!("Found {} projects", projects.into_inner().data.len());

    Ok(())
}
```

## Configuration

### API Key

Get your API key from the Seren Console at https://console.serendb.com/settings/api-keys.

### From the environment

`ClientConfig::from_env()` reads `SEREN_API_KEY` for the bearer token and `SEREN_API_BASE` for the base URL, matching the `@serendb/sdk` and `seren-python` defaults. Both are optional; a missing key yields an unauthenticated configuration.

```rust
let config = ClientConfig::from_env();
let client = Client::from_config(&config)?;
```

### Custom API Host

```rust
let config = ClientConfig::new("your_seren_api_key")
    .with_base_url("https://api.serendb.com");
```

### Custom Timeout

```rust
let config = ClientConfig::new("your_seren_api_key")
    .with_timeout(120);
```

## Product Examples

Runnable examples are included with the crate:

```bash
cargo run -p seren-sdk --example product_catalog
cargo run -p seren-sdk --example employee_lifecycle -- preview site-reliability-engineer
SEREN_API_KEY=your_seren_api_key cargo run -p seren-sdk --example quickstart
SEREN_API_KEY=your_seren_api_key cargo run -p seren-sdk --example memory -- "release approval process"
SEREN_ACCESS_TOKEN=your_user_access_token cargo run -p seren-sdk --example account
```

`examples/employees/` contains four portable employee bundles: `chief-financial-officer/`, `research-analyst/`, `launch-operations-coordinator/`, and `site-reliability-engineer/`. The first is grounded in the complete Seren Desktop demo employee, the second follows the ADK research-then-write pattern and publishes one approval-gated completed report, the third combines the Seren Desktop Launch Room scenario with an ADK-style sequential workflow, and the fourth demonstrates evidence-first incident triage with one approval-gated low-risk coordination update per run.

Every folder owns its `employee.json` deployment manifest, `IDENTITY.md`, `SOUL.md`, `SKILL.md`, `TOOLS.md`, `MEMORY.md`, `EVAL.md`, and a short README. `employee_lifecycle` validates the selected folder and converts it to the generated `AgentSpec`; employee content does not live in the runner. Previewing is offline. `quickstart` lists Seren DB projects, `memory` performs a typed private-memory recall, `account` reads the signed-in user's profile, recovery-email state, and organization memberships, and `product_catalog` runs offline.

Draft tests can incur model charges, and deployments create or update recurring infrastructure. The example requires explicit opt-ins for both actions:

```bash
SEREN_API_KEY=your_seren_api_key \
SEREN_EXAMPLE_ALLOW_PAID=1 \
cargo run -p seren-sdk --example employee_lifecycle -- test chief-financial-officer "Prepare a board operating review"

SEREN_API_KEY=your_seren_api_key \
SEREN_EXAMPLE_ALLOW_PAID=1 \
SEREN_EXAMPLE_ALLOW_DEPLOY=1 \
cargo run -p seren-sdk --example employee_lifecycle -- deploy research-analyst
```

The crate also exports the underlying static product example metadata for docs, CLIs, notebooks, and onboarding flows:

```rust
use seren::get_seren_product_examples;

for example in get_seren_product_examples() {
    println!("{}", example.title);
    for request in example.requests {
        println!("{} {}", request.method.as_str(), request.path);
    }
}
```

The product catalog covers Seren Employees powered by Seren Agent, Seren Cloud, Seren Passwords, Seren Skills, Seren Notes, Seren Memory, Seren Models, Seren Private Models, Seren DB, Seren Storage, and Seren Publishers. Catalog metadata does not make network calls on its own.

## API

The client is auto-generated from the OpenAPI specs at build time. Methods are available directly on the `Client` struct, including generated calls for Seren DB projects, Seren Agent deployments, and Seren Storage buckets. Seren Storage publisher methods use the `seren_storage_` prefix.

The crate stores its OpenAPI inputs in `sdk/openapi`. Cargo packages include this directory, so code generation does not depend on files outside the crate.

Managed Employee methods cover template hires, publisher access requests and grants, exact-operation allowances, browser sign-in handoffs, work records, feedback, and skill proposal review. Cloud approval inbox methods let an owner decide one entry with `approve`, `deny`, or `allow_always`; standing approvals can carry an expiry and use budget. Browser consent confirmation uses the proof returned by the consent flow. Template release publication requires an organization user API key with the explicit `managed-agent-template:publish` scope. Runtime operations, including allowance checks and publishing state or work records, require the deployment's runtime credential.

Set `rollout: true` in a template release request to apply the template's current revision to existing hires. Inspect the response's `rollout` report for each hire's outcome and applied template revision; another publication can advance that revision beyond the response's published `revision`. Use `ClientConfig::with_timeout(600)` for rollout publication, which can outlast the SDK's default 60-second timeout. CLI and MCP publication commands use a 600-second timeout for requested rollouts. Omit `rollout` or set it to `false` to publish without applying the release to existing hires.

Publication commits before rollout begins. A timeout or transport error can leave the release published and some hires updated; inspect state before retrying. Configure any outer MCP client or proxy deadline to allow the rollout request's 600-second budget.

Return values are wrapped in `ResponseValue<T>`. Call `.into_inner()` to get the response body.

### Updating the API contract

Export the contract from the owning `seren-core` checkout with `make openapi openapi-publishers`. Copy its `openapi.json`, `openapi-seren-db.json`, `openapi-seren-cloud.json`, `openapi-seren-agent.json`, `openapi-seren-models.json`, and `openapi-seren-private-models.json` into `sdk/openapi`, then rebuild the SDK. Do not edit these generated inputs directly. Keep the producer revision stable while syncing the Python SDK, TypeScript SDK, and documentation from the same inputs.

Compare parsed OpenAPI operations and their referenced schemas, including changed requests, responses, enums, headers, and security requirements. Review the producer commits for behavior the schema cannot express, such as authorization, approval lifecycles, pagination, streaming, and owner versus runtime access. Verify handwritten CLI and MCP calls against those changes and exercise new operations through their generated clients.

### Error Handling

The SDK uses `progenitor_client::Error` for API and transport errors:

```rust
use seren::{Client, ClientConfig, Error};

let config = ClientConfig::new("your_seren_api_key");
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
- Static product example metadata for the core Seren product surfaces.

## Support

- Documentation: https://docs.serendb.com
- Issues: https://github.com/serenorg/seren/issues
- Discord: https://discord.gg/jseg7q4KS7

## License

MIT License - see [LICENSE](./LICENSE) for details.
