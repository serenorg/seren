mod config;
mod error;
mod oauth;
mod server;

use anyhow::Result;
use config::{AuthConfig, Config};
use rmcp::ServiceExt;
use server::SerenMcpServer;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env()?;

    match std::env::args().nth(1).as_deref() {
        Some("start") | None => {
            // Stdio mode: log to stderr to avoid interfering with JSON-RPC on stdout
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(tracing::Level::INFO.into()),
                )
                .with_writer(std::io::stderr)
                .init();

            tracing::info!("Starting in stdio mode (local)");
            run_stdio(config).await
        }
        Some("start:http") => {
            // HTTP mode: log to stdout normally
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::from_default_env()
                        .add_directive(tracing::Level::INFO.into()),
                )
                .init();

            tracing::info!("Starting in Streamable HTTP mode (hosted)");
            run_http(config).await
        }
        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            eprintln!("Usage: seren-mcp [start|start:http]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  start       Start in stdio mode (local, default)");
            eprintln!("  start:http  Start in Streamable HTTP mode (hosted)");
            std::process::exit(1);
        }
    }
}

async fn run_stdio(config: Config) -> Result<()> {
    let api_key = match &config.auth {
        AuthConfig::ApiKey(key) => key.clone(),
        AuthConfig::OAuth { .. } => {
            anyhow::bail!("Stdio mode requires SEREN_API_KEY environment variable");
        }
    };

    let server = SerenMcpServer::new(&api_key, &config.api_base_url)?;

    // Use rmcp's stdio transport
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;

    Ok(())
}

async fn run_http(config: Config) -> Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let api_base_url = config.api_base_url.clone();
    let ct = CancellationToken::new();

    // Create session manager
    let session_manager = Arc::new(LocalSessionManager::default());

    // Create streamable HTTP service config
    let http_config = StreamableHttpServerConfig {
        sse_keep_alive: Some(std::time::Duration::from_secs(15)),
        stateful_mode: true,
        cancellation_token: ct.clone(),
    };

    // Create streamable HTTP service - it's a tower Service
    let mcp_service = StreamableHttpService::new(
        move || {
            let api_key = std::env::var("SEREN_API_KEY").unwrap_or_default();
            SerenMcpServer::new(&api_key, &api_base_url).map_err(std::io::Error::other)
        },
        session_manager,
        http_config,
    );

    // Create axum router using the tower service
    // StreamableHttpService implements tower::Service, so we use it directly with axum
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
    );

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Streamable HTTP MCP server listening on {}", addr);
    tracing::info!("  POST   /mcp - send JSON-RPC messages");
    tracing::info!("  GET    /mcp - establish SSE stream (with session)");
    tracing::info!("  DELETE /mcp - close session");

    let server_ct = ct.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            server_ct.cancelled().await;
        })
        .await?;

    Ok(())
}
