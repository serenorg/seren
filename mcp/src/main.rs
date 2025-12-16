mod config;
mod error;
mod middleware;
mod oauth;
mod server;
mod telemetry;

use anyhow::Result;
use axum::extract::State;
use axum::response::IntoResponse;
use config::{AuthConfig, Config};
use oauth::store::TokenStore;
use rmcp::ServiceExt;
use server::SerenMcpServer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Health check state with optional database store
#[derive(Clone)]
struct HealthCheckState {
    store: Option<Arc<TokenStore>>,
}

/// Health check endpoint for k8s liveness/readiness probes
async fn health_check(
    State(state): State<HealthCheckState>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    // Check database connectivity if store is available
    if let Some(store) = &state.store
        && let Err(e) = store.health_check().await
    {
        tracing::error!("Health check failed: database unavailable: {}", e);
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "unhealthy",
                "service": "seren-mcp",
                "version": env!("CARGO_PKG_VERSION"),
                "error": "database unavailable"
            })),
        ));
    }

    Ok(axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "seren-mcp",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

/// Auth state for simple token-based HTTP mode
#[derive(Clone)]
struct SimpleAuthState {
    token: String,
}

/// Auth state for OAuth mode with database-backed tokens
#[derive(Clone)]
struct OAuthAuthState {
    store: TokenStore,
    /// Per-session bearer token cache keyed by `Mcp-Session-Id`.
    ///
    /// Some Streamable HTTP clients only send the `Authorization` header on the initial
    /// session-creating request. Subsequent requests carry only `Mcp-Session-Id`.
    /// We cache the validated token so later requests can be authorized and the token
    /// can be re-injected for downstream API calls.
    session_tokens: Arc<RwLock<HashMap<String, String>>>,
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
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let session_id = req
        .headers()
        .get(axum::http::header::HeaderName::from_static(
            "mcp-session-id",
        ))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    // Prefer an explicit Authorization header.
    let mut token = extract_bearer_token(&req).map(|t| t.to_string());

    // If missing, try to recover the token from the session cache.
    if token.is_none() {
        if let Some(ref sid) = session_id {
            token = state.session_tokens.read().await.get(sid).cloned();
            if token.is_some() {
                // Re-inject Authorization so rmcp can propagate it into Extensions for tools.
                if let Some(ref t) = token {
                    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {}", t)) {
                        req.headers_mut()
                            .insert(axum::http::header::AUTHORIZATION, v);
                    }
                }
            }
        }
    }

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
    let is_valid = match state.store.get_access_token(&token).await {
        Ok(Some(_access_token)) => true, // get_access_token checks expiry
        Ok(None) => false,
        Err(e) => {
            tracing::error!("Token validation error: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Token validation failed"
                })),
            )
                .into_response();
        }
    };

    if !is_valid {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Token is invalid or expired"
            })),
        )
            .into_response();
    }

    // If the request includes a session id, remember/update the token for that session.
    if let Some(ref sid) = session_id {
        state
            .session_tokens
            .write()
            .await
            .insert(sid.clone(), token.clone());
    }

    let method = req.method().clone();
    let response = next.run(req).await;

    // For the initial session-creating initialize request, rmcp returns `Mcp-Session-Id`
    // in the response headers. Cache the token under that session id so clients can
    // omit Authorization on subsequent requests.
    if let Some(sid) = response
        .headers()
        .get(axum::http::header::HeaderName::from_static(
            "mcp-session-id",
        ))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        state
            .session_tokens
            .write()
            .await
            .insert(sid, token.clone());
    }

    // Best-effort cleanup: when a session is explicitly closed, drop the cached token.
    if method == axum::http::Method::DELETE {
        if let Some(sid) = session_id {
            state.session_tokens.write().await.remove(&sid);
        }
    }

    response
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
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
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

    // MCP endpoint with auth
    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            SimpleAuthState { token: auth_token },
            require_simple_auth,
        ));

    // Health endpoint (no auth required) for k8s probes
    let health_router = axum::Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(HealthCheckState { store: None });

    // Combine routers - CORS must be outermost, request ID middleware before CORS
    let app = axum::Router::new()
        .merge(health_router)
        .merge(mcp_router)
        .layer(cors)
        .layer(axum::middleware::from_fn(middleware::request_id_middleware));

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
    use oauth::{OAuthState, oauth_router};
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
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

    let api_base_url = config.api_base_url.clone();
    let oauth_redirect_base_url = config.oauth_redirect_base_url.clone();
    let api_base_url_for_service = api_base_url.clone();

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

    // Periodic cleanup of expired auth requests/tokens (defense-in-depth).
    tokio::spawn({
        let store = store.clone();
        let ct = ct.clone();
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = ct.cancelled() => break,
                    _ = interval.tick() => {
                        match store.cleanup_expired(Some(1000)).await {
                            Ok(deleted) => {
                                tracing::info!(deleted_count = deleted, "OAuth cleanup completed");
                            }
                            Err(e) => {
                                tracing::warn!("OAuth cleanup failed: {}", e);
                            }
                        }
                    }
                }
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
        move || SerenMcpServer::new_oauth(&api_base_url_for_service).map_err(std::io::Error::other),
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
        http: reqwest::Client::new(),
        server_host: server_host.clone(),
        upstream_client_id: client_id,
        upstream_api_base_url: api_base_url,
        upstream_oauth_redirect_base_url: oauth_redirect_base_url,
        circuit_breaker: oauth::circuit_breaker::create_oauth_circuit_breaker(),
    });

    // Clone store for health check before moving it
    let health_store = Arc::new(store.clone());

    // MCP endpoint with OAuth token validation
    let session_tokens = Arc::new(RwLock::new(HashMap::<String, String>::new()));

    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            OAuthAuthState {
                store,
                session_tokens,
            },
            require_oauth_auth,
        ));

    // Health endpoint (no auth required) for k8s probes
    let health_router = axum::Router::new()
        .route("/health", axum::routing::get(health_check))
        .with_state(HealthCheckState {
            store: Some(health_store),
        });

    // Combine OAuth routes, health, and MCP endpoint
    // CORS must be outermost, request ID middleware before CORS
    let app = axum::Router::new()
        .merge(health_router)
        .merge(oauth_router(oauth_state))
        .merge(mcp_router)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(middleware::request_id_middleware));

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

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn extract_bearer_token_is_case_insensitive_and_trims() {
        let request = Request::builder()
            .uri("http://localhost/")
            .header(axum::http::header::AUTHORIZATION, "bEaReR   token123  ")
            .body(Body::empty())
            .unwrap();

        assert_eq!(extract_bearer_token(&request), Some("token123"));

        let request = Request::builder()
            .uri("http://localhost/")
            .header(axum::http::header::AUTHORIZATION, "Basic abc")
            .body(Body::empty())
            .unwrap();

        assert_eq!(extract_bearer_token(&request), None);
    }

    #[tokio::test]
    async fn require_simple_auth_enforces_bearer_token() {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                SimpleAuthState {
                    token: "secret".to_string(),
                },
                require_simple_auth,
            ));

        // Missing auth => 401
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        // Wrong token => 401
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(axum::http::header::AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        // Correct token (case-insensitive scheme) => 200
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(axum::http::header::AUTHORIZATION, "bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
