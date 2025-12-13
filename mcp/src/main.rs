mod config;
mod error;
mod oauth;
mod server;
mod telemetry;

use anyhow::Result;
use axum::response::IntoResponse;
use config::{AuthConfig, Config};
use oauth::store::TokenStore;
use rmcp::ServiceExt;
use server::SerenMcpServer;

/// Auth state for simple token-based HTTP mode
#[derive(Clone)]
struct SimpleAuthState {
    token: String,
}

/// Auth state for OAuth mode with database-backed tokens
#[derive(Clone)]
struct OAuthAuthState {
    store: TokenStore,
}

/// Extract bearer token from Authorization header (case-insensitive scheme per RFC 6750)
fn extract_bearer_token(req: &axum::http::Request<axum::body::Body>) -> Option<&str> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // Case-insensitive "Bearer " prefix per RFC 6750
            let (scheme, token) = v.split_once(' ')?;
            if scheme.eq_ignore_ascii_case("bearer") {
                Some(token.trim())
            } else {
                None
            }
        })
        .filter(|v| !v.is_empty())
}

/// Simple token auth middleware (for start:http mode)
async fn require_simple_auth(
    axum::extract::State(state): axum::extract::State<SimpleAuthState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let token = extract_bearer_token(&req);

    if token != Some(state.token.as_str()) {
        return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    next.run(req).await
}

/// OAuth token validation middleware (for start:oauth mode)
async fn require_oauth_auth(
    axum::extract::State(state): axum::extract::State<OAuthAuthState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let token = extract_bearer_token(&req);

    let Some(token) = token else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "unauthorized",
                "error_description": "Bearer token required"
            })),
        )
            .into_response();
    };

    // Validate token against database
    match state.store.get_access_token(token).await {
        Ok(Some(_access_token)) => {
            // Token is valid and not expired (get_access_token checks expiry)
            next.run(req).await
        }
        Ok(None) => (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Token is invalid or expired"
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Token validation error: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Token validation failed"
                })),
            )
                .into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "start".to_string());

    match command.as_str() {
        "start" => {
            let config = Config::from_env_for_command("start")?;

            // Stdio mode: log to stderr to avoid interfering with JSON-RPC on stdout
            let _guard = telemetry::init_subscriber(true);

            tracing::info!("Starting in stdio mode (local)");
            run_stdio(config).await
        }
        "start:http" => {
            let config = Config::from_env_for_command("start:http")?;

            // HTTP mode with simple token auth: log to stdout normally
            let _guard = telemetry::init_subscriber(false);

            tracing::info!("Starting in Streamable HTTP mode (simple auth)");
            run_http(config).await
        }
        "start:oauth" => {
            let config = Config::from_env_for_command("start:oauth")?;

            // HTTP mode with full OAuth 2.1: log to stdout normally
            let _guard = telemetry::init_subscriber(false);

            tracing::info!("Starting in Streamable HTTP mode (OAuth 2.1)");
            run_oauth(config).await
        }
        cmd => {
            eprintln!("Unknown command: {}", cmd);
            eprintln!("Usage: seren-mcp [start|start:http|start:oauth]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  start        Start in stdio mode (local, default)");
            eprintln!("  start:http   Start in HTTP mode with simple token auth");
            eprintln!("  start:oauth  Start in HTTP mode with full OAuth 2.1");
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
    use tower_http::cors::{Any, CorsLayer};

    let api_key = match &config.auth {
        AuthConfig::ApiKey(key) => key.clone(),
        AuthConfig::OAuth { .. } => {
            anyhow::bail!("start:http mode requires SEREN_API_KEY (use start:oauth for OAuth)");
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

    // CORS configuration per MCP spec - allow browser-based clients
    // Must allow and expose Mcp-Session-Id for rmcp session management
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::HeaderName::from_static("x-read-only"),
            axum::http::header::HeaderName::from_static("mcp-session-id"),
        ])
        .expose_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderName::from_static("mcp-session-id"),
        ]);

    // Create axum router using the tower service
    // StreamableHttpService implements tower::Service, so we use it directly with axum
    let app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            SimpleAuthState { token: auth_token },
            require_simple_auth,
        ))
        // CORS must be outermost so preflight requests work and error responses include headers.
        .layer(cors);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Streamable HTTP MCP server listening on {}", addr);
    tracing::info!("  POST   /mcp - send JSON-RPC messages");
    tracing::info!("  GET    /mcp - establish SSE stream (with session)");
    tracing::info!("  DELETE /mcp - close session");
    tracing::info!("Auth: set `Authorization: Bearer <MCP_AUTH_TOKEN>`");
    tracing::info!("Read-only: set `x-read-only: true` header (or `SEREN_MCP_READ_ONLY=true`)");

    let server_ct = ct.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            server_ct.cancelled().await;
        })
        .await?;

    Ok(())
}

async fn run_oauth(config: Config) -> Result<()> {
    use oauth::{oauth_router, OAuthState};
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;
    use tower_http::cors::{Any, CorsLayer};

    let (database_url, client_id, server_host) = match &config.auth {
        AuthConfig::OAuth {
            database_url,
            client_id,
            server_host,
        } => (database_url.clone(), client_id.clone(), server_host.clone()),
        AuthConfig::ApiKey(_) => {
            anyhow::bail!(
                "start:oauth mode requires MCP_DATABASE_URL, SEREN_OAUTH_CLIENT_ID, and MCP_SERVER_HOST"
            );
        }
    };

    // Connect to token store
    let store = TokenStore::connect(&database_url).await?;
    tracing::info!("Connected to OAuth database");

    // API key for the MCP server to use when calling the Seren API.
    let api_key = std::env::var("SEREN_API_KEY")
        .map_err(|_| anyhow::anyhow!("SEREN_API_KEY is required for start:oauth"))?;
    let api_base_url = config.api_base_url.clone();
    let seren_api_key = api_key.clone();

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

    // Create streamable HTTP service
    let mcp_service = StreamableHttpService::new(
        move || SerenMcpServer::new(&api_key, &api_base_url).map_err(std::io::Error::other),
        session_manager,
        http_config,
    );

    // CORS configuration per MCP spec
    // Must allow and expose Mcp-Session-Id for rmcp session management
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::HeaderName::from_static("x-read-only"),
            axum::http::header::HeaderName::from_static("mcp-session-id"),
        ])
        .expose_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::HeaderName::from_static("mcp-session-id"),
        ]);

    // OAuth state for routes
    let oauth_state = Arc::new(OAuthState {
        store: store.clone(),
        server_host: server_host.clone(),
        client_id,
        seren_api_key,
    });

    // MCP endpoint with OAuth token validation
    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            OAuthAuthState { store },
            require_oauth_auth,
        ));

    // Combine OAuth routes and MCP endpoint
    let app = axum::Router::new()
        .merge(oauth_router(oauth_state))
        .merge(mcp_router)
        .layer(cors);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("OAuth MCP server listening on {}", addr);
    tracing::info!("OAuth endpoints:");
    tracing::info!("  GET  /.well-known/oauth-authorization-server - Server metadata");
    tracing::info!("  POST /register - Dynamic client registration");
    tracing::info!("  GET  /authorize - Authorization endpoint");
    tracing::info!("  POST /token - Token endpoint");
    tracing::info!("MCP endpoint:");
    tracing::info!("  POST   /mcp - send JSON-RPC messages");
    tracing::info!("  GET    /mcp - establish SSE stream (with session)");
    tracing::info!("  DELETE /mcp - close session");
    tracing::info!("Server host: {}", server_host);

    let server_ct = ct.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            server_ct.cancelled().await;
        })
        .await?;

    Ok(())
}
