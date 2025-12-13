mod config;
mod error;
mod oauth;
mod server;

use anyhow::Result;
use axum::response::IntoResponse;
use config::{AuthConfig, Config};
use rmcp::ServiceExt;
use server::SerenMcpServer;

#[derive(Clone)]
struct HttpAuthState {
    token: String,
}

async fn require_http_auth(
    axum::extract::State(state): axum::extract::State<HttpAuthState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            req.headers()
                .get("x-mcp-auth-token")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|v| !v.is_empty())
        });

    if token != Some(state.token.as_str()) {
        return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    next.run(req).await
}

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

    let api_key = match &config.auth {
        AuthConfig::ApiKey(key) => key.clone(),
        AuthConfig::OAuth { .. } => {
            anyhow::bail!(
                "Streamable HTTP mode currently requires SEREN_API_KEY (OAuth not wired yet)"
            );
        }
    };

    let auth_token = std::env::var("MCP_AUTH_TOKEN")
        .map_err(|_| anyhow::anyhow!("MCP_AUTH_TOKEN is required for start:http"))?;

    let api_base_url = config.api_base_url.clone();
    let ct = CancellationToken::new();

    tokio::spawn({
        let ct = ct.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::info!("Shutdown signal received");
                ct.cancel();
            }
        }
    });

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
        move || SerenMcpServer::new(&api_key, &api_base_url).map_err(std::io::Error::other),
        session_manager,
        http_config,
    );

    // Create axum router using the tower service
    // StreamableHttpService implements tower::Service, so we use it directly with axum
    let app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            HttpAuthState { token: auth_token },
            require_http_auth,
        ));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Streamable HTTP MCP server listening on {}", addr);
    tracing::info!("  POST   /mcp - send JSON-RPC messages");
    tracing::info!("  GET    /mcp - establish SSE stream (with session)");
    tracing::info!("  DELETE /mcp - close session");
    tracing::info!("Auth: set `Authorization: Bearer <MCP_AUTH_TOKEN>` (or `x-mcp-auth-token`)");
    tracing::info!("Read-only: set `x-read-only: true` (or `SEREN_MCP_READ_ONLY=true`)");

    let server_ct = ct.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            server_ct.cancelled().await;
        })
        .await?;

    Ok(())
}
