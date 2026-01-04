mod config;
mod error;
mod middleware;
mod oauth;
mod server;
mod telemetry;
mod wallet;

use anyhow::Result;
use axum::extract::State;
use axum::response::IntoResponse;
use config::{AuthConfig, Config};
use lru::LruCache;
use oauth::routes::OAuthState;
use oauth::store::TokenStore;
use rmcp::ServiceExt;
use server::SerenMcpServer;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    /// Per-session bearer token cache keyed by `Mcp-Session-Id` (bounded LRU).
    ///
    /// Some Streamable HTTP clients only send the `Authorization` header on the initial
    /// session-creating request. Subsequent requests carry only `Mcp-Session-Id`.
    /// We cache the validated token so later requests can be authorized and the token
    /// can be re-injected for downstream API calls.
    session_tokens: Arc<Mutex<LruCache<String, String>>>,
    /// Shared OAuth state for transparent token refresh.
    /// When an access token is expired but has a valid refresh token,
    /// we can refresh it server-side without requiring client action.
    oauth_state: Arc<OAuthState>,
}

impl OAuthAuthState {
    /// Build a 401 Unauthorized response with WWW-Authenticate header.
    ///
    /// Per RFC 6750 and the MCP OAuth spec, the WWW-Authenticate header must include
    /// `resource_metadata` pointing to the OAuth authorization server metadata endpoint.
    /// This allows clients like Claude Code to automatically discover and initiate OAuth flow.
    fn unauthorized_response(
        &self,
        error: &str,
        error_description: &str,
    ) -> axum::response::Response {
        let server_host = self.oauth_state.server_host.trim_end_matches('/');
        let www_authenticate = format!(
            r#"Bearer realm="serendb", resource_metadata="{}/.well-known/oauth-authorization-server""#,
            server_host
        );

        (
            axum::http::StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, www_authenticate)],
            axum::Json(serde_json::json!({
                "error": error,
                "error_description": error_description
            })),
        )
            .into_response()
    }
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

/// Attempt to transparently refresh an expired access token.
/// Returns (new_access_token, new_token_string) if successful, None if no refresh possible.
async fn try_transparent_refresh(
    state: &OAuthAuthState,
    expired_token: &str,
) -> Result<Option<(oauth::store::AccessToken, String)>, Box<dyn std::error::Error + Send + Sync>> {
    use time::{Duration, OffsetDateTime};

    // First, check if the token exists (even if expired)
    let expired_access_token = match state
        .store
        .get_access_token_unchecked(expired_token)
        .await?
    {
        Some(t) => t,
        None => return Ok(None), // Token doesn't exist at all
    };

    // Check if it's actually expired (not just invalid)
    if expired_access_token.expires_at > OffsetDateTime::now_utc() {
        // Token is not expired, something else is wrong
        return Ok(None);
    }

    // Look up the refresh token for this access token
    let refresh_token = match state
        .store
        .get_refresh_token_by_access_token(expired_token)
        .await?
    {
        Some(rt) => rt,
        None => {
            tracing::debug!(
                event = "no_refresh_token",
                access_token_client_id = %expired_access_token.client_id,
                "No valid refresh token found for expired access token"
            );
            return Ok(None);
        }
    };

    // Call upstream to refresh the token using the shared function
    let token_body = match oauth::routes::exchange_upstream_token(
        &state.oauth_state.http,
        &state.oauth_state.upstream_api_base_url,
        vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token.token),
            ("client_id", &state.oauth_state.upstream_client_id),
        ],
        &state.oauth_state.circuit_breaker,
    )
    .await
    {
        Ok(body) => body,
        Err(e) => {
            tracing::debug!(
                event = "upstream_refresh_failed",
                error = ?e,
                "Upstream token refresh returned error"
            );
            return Ok(None);
        }
    };

    let new_expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(token_body.expires_in.max(0));

    // Create new access token record
    let new_access_token = oauth::store::AccessToken {
        token: token_body.access_token.clone(),
        client_id: expired_access_token.client_id.clone(),
        user_id: expired_access_token.user_id.clone(),
        scope: expired_access_token.scope.clone(),
        expires_at: new_expires_at,
        created_at: OffsetDateTime::now_utc(),
    };

    // Save new access token
    state.store.save_access_token(&new_access_token).await?;

    // Update refresh token to point to new access token (and rotate if new one provided)
    let new_refresh_token_str = token_body
        .refresh_token
        .unwrap_or_else(|| refresh_token.token.clone());

    state
        .store
        .update_refresh_token(
            &refresh_token.token,
            &new_refresh_token_str,
            &token_body.access_token,
            Some(oauth::store::TokenStore::token_expiry(
                oauth::store::REFRESH_TOKEN_TTL_HOURS,
            )),
        )
        .await?;

    // Revoke old access token
    state.store.revoke_access_token(expired_token).await.ok();

    Ok(Some((new_access_token, token_body.access_token)))
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
    let mut token_from_session_cache = false;

    // If missing, try to recover the token from the session cache.
    if token.is_none()
        && let Some(ref sid) = session_id
    {
        token = state.session_tokens.lock().await.get(sid).cloned();
        token_from_session_cache = token.is_some();
    }

    let Some(token) = token else {
        return state.unauthorized_response("unauthorized", "Bearer token required");
    };

    // Validate token against database and get client metadata.
    // If token is expired and came from the session cache (not the client),
    // attempt a transparent refresh using the refresh token.
    let (access_token, new_token) = match state.store.get_access_token(&token).await {
        Ok(Some(access_token)) => (access_token, None),
        Ok(None) => {
            if token_from_session_cache {
                // Token not valid - check if it exists but is expired
                match try_transparent_refresh(&state, &token).await {
                    Ok(Some((new_access_token, new_token_str))) => {
                        tracing::info!(
                            event = "transparent_token_refresh",
                            client_id = %new_access_token.client_id,
                            user_id = %new_access_token.user_id,
                            "Transparently refreshed expired access token"
                        );
                        (new_access_token, Some(new_token_str))
                    }
                    Ok(None) => {
                        // No refresh token available or refresh failed
                        tracing::debug!(
                            event = "token_validation_failed",
                            "Token is invalid or expired and no refresh token available"
                        );
                        return state
                            .unauthorized_response("invalid_token", "Token is invalid or expired");
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "transparent_refresh_failed",
                            error = %e,
                            "Failed to transparently refresh token"
                        );
                        return state
                            .unauthorized_response("invalid_token", "Token is invalid or expired");
                    }
                }
            } else {
                // If the client provided this token, the client should be responsible for refresh.
                return state.unauthorized_response("invalid_token", "Token is invalid or expired");
            }
        }
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

    // If we got a new token from transparent refresh, update the token variable for session caching.
    let token = new_token.clone().unwrap_or(token);

    // Ensure the request has an up-to-date Authorization header so rmcp can propagate it into
    // Extensions for downstream tool calls (and so refreshed tokens take effect immediately).
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {}", token)) {
        req.headers_mut()
            .insert(axum::http::header::AUTHORIZATION, v);
    }

    // Look up client metadata for agent tracking
    if let Ok(Some(client)) = state.store.get_client(&access_token.client_id).await {
        // Inject agent metadata headers for downstream tracking
        if let Ok(v) = axum::http::HeaderValue::from_str(&client.id) {
            req.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-agent-client-id"),
                v,
            );
        }
        if let Ok(v) = axum::http::HeaderValue::from_str(&client.name) {
            req.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-agent-client-name"),
                v,
            );
        }
        if let Some(ref software_id) = client.software_id
            && let Ok(v) = axum::http::HeaderValue::from_str(software_id)
        {
            req.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-agent-software-id"),
                v,
            );
        }
        if let Some(ref software_version) = client.software_version
            && let Ok(v) = axum::http::HeaderValue::from_str(software_version)
        {
            req.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-agent-software-version"),
                v,
            );
        }
    }

    // If the request includes a session id, remember/update the token for that session.
    if let Some(ref sid) = session_id {
        state
            .session_tokens
            .lock()
            .await
            .put(sid.clone(), token.clone());
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
        state.session_tokens.lock().await.put(sid, token.clone());
    }

    // Best-effort cleanup: when a session is explicitly closed, drop the cached token.
    if method == axum::http::Method::DELETE
        && let Some(sid) = session_id
    {
        state.session_tokens.lock().await.pop(&sid);
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
            anyhow::bail!("Stdio mode requires API_KEY environment variable");
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
            anyhow::bail!("start:http mode requires API_KEY (use start:oauth for OAuth)");
        }
    };

    let auth_token = std::env::var("AUTH_TOKEN")
        .map_err(|_| anyhow::anyhow!("AUTH_TOKEN is required for start:http"))?;

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
    tracing::info!("Auth: set `Authorization: Bearer <AUTH_TOKEN>`");
    tracing::info!("Read-only: set `x-read-only: true` header (or `READ_ONLY=true`)");

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
            public_url,
        } => (database_url.clone(), client_id.clone(), public_url.clone()),
        AuthConfig::ApiKey(_) => {
            anyhow::bail!("start:oauth mode requires DATABASE_URL and PUBLIC_URL");
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
        http: {
            let upstream_timeout_secs = std::env::var("OAUTH_UPSTREAM_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(15);
            let upstream_connect_timeout_secs =
                std::env::var("OAUTH_UPSTREAM_CONNECT_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(5);

            reqwest::Client::builder()
                .user_agent(format!("seren-mcp/{}", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(upstream_timeout_secs))
                .connect_timeout(std::time::Duration::from_secs(
                    upstream_connect_timeout_secs,
                ))
                .build()?
        },
        server_host: server_host.clone(),
        upstream_client_id: client_id,
        upstream_api_base_url: api_base_url,
        upstream_oauth_redirect_base_url: oauth_redirect_base_url,
        circuit_breaker: oauth::circuit_breaker::create_oauth_circuit_breaker(),
    });

    // Clone store for health check before moving it
    let health_store = Arc::new(store.clone());

    // MCP endpoint with OAuth token validation
    const SESSION_TOKEN_CACHE_SIZE: usize = 10_000;
    let session_tokens = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(SESSION_TOKEN_CACHE_SIZE).expect("SESSION_TOKEN_CACHE_SIZE must be > 0"),
    )));

    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(tower::ServiceBuilder::new().service(mcp_service)),
        )
        .layer(axum::middleware::from_fn_with_state(
            OAuthAuthState {
                store,
                session_tokens,
                oauth_state: oauth_state.clone(),
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
