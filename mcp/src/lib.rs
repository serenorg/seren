mod config;
mod docs;
mod error;
#[cfg(feature = "telemetry")]
mod metrics;
mod middleware;
mod money;
mod oauth;
mod passwords;
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
use uuid::Uuid;

/// Canonical name for the MCP server binary/service.
pub(crate) const MCP_SERVER_NAME: &str = "seren-mcp";

/// HTTP Bearer auth realm used in WWW-Authenticate challenges.
pub(crate) const MCP_AUTH_REALM: &str = MCP_SERVER_NAME;

/// Response headers that flag when an MCP request failed because the upstream
/// Seren session must be re-established. Browser clients can only read these
/// when they are listed in `Access-Control-Expose-Headers` (see the OAuth-mode
/// CORS layer), so the same signal is mirrored in the JSON body.
pub(crate) const REAUTH_REQUIRED_HEADER: &str = "x-seren-reauth-required";
pub(crate) const REAUTH_REASON_HEADER: &str = "x-seren-reauth-reason";

/// Stable `reauth_reason` codes surfaced to MCP/OAuth clients. These are part
/// of the public response contract; do not rename without a compatibility plan.
pub(crate) const REAUTH_REASON_REFRESH_TOKEN_MISSING: &str = "upstream_refresh_token_missing";
pub(crate) const REAUTH_REASON_AUTHORIZATION_EXPIRED: &str = "upstream_authorization_expired";
pub(crate) const REAUTH_REASON_TOKEN_PERSIST_FAILED: &str = "upstream_token_persist_failed";

/// Health check state with optional database store
#[derive(Clone)]
struct HealthCheckState {
    store: Option<Arc<TokenStore>>,
}

/// Liveness probe - process is alive and the HTTP stack is responding.
async fn livez() -> impl IntoResponse {
    axum::http::StatusCode::OK
}

/// Readiness probe - verifies required dependencies before taking traffic.
async fn readyz(
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
                "service": MCP_SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
                "error": "database unavailable"
            })),
        ));
    }

    Ok(axum::Json(serde_json::json!({
        "status": "healthy",
        "service": MCP_SERVER_NAME,
        "version": env!("CARGO_PKG_VERSION")
    })))
}

/// Auth state for simple token-based HTTP mode
#[derive(Clone)]
struct SimpleAuthState {
    token: String,
}

/// Auth state for OAuth mode with MCP JWT validation
#[derive(Clone)]
struct OAuthAuthState {
    store: TokenStore,
    /// API key validation cache with TTL (reduces backend calls for repeated API key auth).
    ///
    /// When users authenticate with API keys instead of OAuth, we cache the validated
    /// user info to avoid hitting the backend /auth/me endpoint on every request.
    /// Cache entries expire after 5 minutes (similar to Neon's approach).
    api_key_cache: Arc<Mutex<LruCache<String, CachedApiKeyValidation>>>,
    /// Shared OAuth state for endpoints and configuration.
    oauth_state: Arc<OAuthState>,
}

type JsonError = (axum::http::StatusCode, axum::Json<serde_json::Value>);

fn authenticated_user_id_from_headers(
    headers: &axum::http::HeaderMap,
) -> std::result::Result<Uuid, JsonError> {
    let user_id = headers
        .get(axum::http::HeaderName::from_static("x-user-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v.trim()).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Authenticated user is missing",
                })),
            )
        })?;
    Ok(user_id)
}

/// Delete a hosted Seren Passwords agent credential for the authenticated user.
async fn delete_hosted_passwords_agent(
    State(state): State<OAuthAuthState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(identity_id): axum::extract::Path<Uuid>,
) -> std::result::Result<axum::http::StatusCode, JsonError> {
    let user_id = authenticated_user_id_from_headers(&headers)?;

    state
        .store
        .delete_hosted_passwords_agent(user_id, identity_id)
        .await
        .map_err(|e| {
            tracing::error!(
                event = "hosted_passwords_agent_delete_failed",
                user_id = %user_id,
                identity_id = %identity_id,
                error = %e,
                "Failed to delete hosted Seren Passwords agent"
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Could not delete hosted passwords agent",
                })),
            )
        })?;

    // NO_CONTENT whether or not a row existed: delete is idempotent so a CLI
    // revoke that runs after the row is already gone still succeeds.
    Ok(axum::http::StatusCode::NO_CONTENT)
}

impl OAuthAuthState {
    /// Escape a value for inclusion in a quoted-string auth parameter (e.g. error_description="...").
    ///
    /// We keep this intentionally conservative: remove newlines and escape quotes/backslashes to
    /// avoid producing invalid headers.
    fn escape_www_auth_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\r', '\n'], " ")
    }

    fn build_www_authenticate(error: &str, error_description: &str, server_host: &str) -> String {
        let server_host = server_host.trim_end_matches('/');
        format!(
            r#"Bearer realm="{}", resource_metadata="{}/.well-known/oauth-protected-resource", scope="api", error="{}", error_description="{}""#,
            MCP_AUTH_REALM,
            server_host,
            Self::escape_www_auth_value(error),
            Self::escape_www_auth_value(error_description)
        )
    }

    /// Build a 401 Unauthorized response with WWW-Authenticate header.
    ///
    /// Per RFC 9728 and the MCP OAuth spec, the WWW-Authenticate header must include
    /// `resource_metadata` pointing to the OAuth protected resource metadata endpoint.
    /// This allows clients like Claude Code to automatically discover and initiate OAuth flow.
    fn unauthorized_response(
        &self,
        error: &str,
        error_description: &str,
    ) -> axum::response::Response {
        let www_authenticate =
            Self::build_www_authenticate(error, error_description, &self.oauth_state.server_host);

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

    fn upstream_reauth_required_response(
        &self,
        error_description: &str,
        reauth_reason: &str,
    ) -> axum::response::Response {
        Self::upstream_reauth_required_response_for_server(
            error_description,
            reauth_reason,
            &self.oauth_state.server_host,
        )
    }

    fn upstream_reauth_required_response_for_server(
        error_description: &str,
        reauth_reason: &str,
        server_host: &str,
    ) -> axum::response::Response {
        let www_authenticate =
            Self::build_www_authenticate("invalid_token", error_description, server_host);

        (
            axum::http::StatusCode::UNAUTHORIZED,
            [
                (axum::http::header::WWW_AUTHENTICATE, www_authenticate),
                (
                    axum::http::HeaderName::from_static(REAUTH_REQUIRED_HEADER),
                    "true".to_string(),
                ),
                (
                    axum::http::HeaderName::from_static(REAUTH_REASON_HEADER),
                    reauth_reason.to_string(),
                ),
            ],
            axum::Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": error_description,
                "reauth_required": true,
                "reauth_reason": reauth_reason,
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

fn build_mcp_allowed_hosts(configured_urls: &[&str]) -> Vec<String> {
    let mut allowed = Vec::from([
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ]);

    for value in configured_urls {
        let Ok(uri) = value.trim().parse::<axum::http::Uri>() else {
            continue;
        };
        let Some(authority) = uri.authority() else {
            continue;
        };

        push_unique_allowed_host(&mut allowed, authority.as_str());
        if authority.port_u16().is_some() {
            push_unique_allowed_host(&mut allowed, authority.host());
        }
    }

    allowed
}

fn push_unique_allowed_host(allowed: &mut Vec<String>, host: &str) {
    if host.is_empty() || allowed.iter().any(|existing| existing == host) {
        return;
    }
    allowed.push(host.to_string());
}

/// Seren API key prefix - all Seren API keys start with this.
const SEREN_API_KEY_PREFIX: &str = "seren_";

/// API key validation cache TTL in seconds (5 minutes, similar to Neon's approach).
const API_KEY_CACHE_TTL_SECS: u64 = 300;

/// Maximum number of cached API key validations.
const API_KEY_CACHE_SIZE: usize = 1_000;

/// Maximum attempts for transient API-key validation failures.
const API_KEY_VALIDATION_MAX_ATTEMPTS: usize = 3;

/// Initial retry delay for transient API-key validation failures.
const API_KEY_VALIDATION_RETRY_DELAY_MS: u64 = 100;

/// Cached API key validation result with expiry timestamp.
#[derive(Clone)]
struct CachedApiKeyValidation {
    user_info: seren::DataResponseUserMeData,
    expires_at: std::time::Instant,
}

#[derive(Debug)]
enum ApiKeyValidationError {
    InvalidToken,
    UpstreamError {
        status: Option<axum::http::StatusCode>,
    },
}

#[derive(Debug, Clone)]
struct ResolvedOAuthIdentity {
    user_id: uuid::Uuid,
    client_id: String,
    email: Option<String>,
    refresh_token_hash: Option<String>,
}

/// Check if a token is a Seren API key (starts with "seren_" prefix).
fn is_seren_api_key(token: &str) -> bool {
    token.starts_with(SEREN_API_KEY_PREFIX)
}

/// Validate an API key against the Seren API by calling /auth/me.
/// Uses an LRU cache with 5-minute TTL to avoid redundant API calls.
/// Returns the user info if the API key is valid, None otherwise.
async fn validate_api_key_cached(
    api_base_url: &str,
    api_key: &str,
    cache: &Arc<Mutex<LruCache<String, CachedApiKeyValidation>>>,
    circuit_breaker: &Arc<oauth::circuit_breaker::OAuthCircuitBreaker>,
) -> Result<seren::DataResponseUserMeData, ApiKeyValidationError> {
    // Check cache first
    {
        let mut cache_guard = cache.lock().await;
        if let Some(cached) = cache_guard.get(api_key) {
            if cached.expires_at > std::time::Instant::now() {
                tracing::debug!(
                    event = "api_key_cache_hit",
                    user_id = %cached.user_info.id,
                    "API key validation served from cache"
                );
                return Ok(cached.user_info.clone());
            }
            // Expired entry - remove it
            cache_guard.pop(api_key);
            tracing::debug!(
                event = "api_key_cache_expired",
                "Cached API key validation expired"
            );
        }
    }

    // Cache miss - validate against backend
    let user_info =
        validate_api_key_uncached_with_retry(api_base_url, api_key, circuit_breaker).await?;

    // Store in cache
    {
        let mut cache_guard = cache.lock().await;
        cache_guard.put(
            api_key.to_string(),
            CachedApiKeyValidation {
                user_info: user_info.clone(),
                expires_at: std::time::Instant::now()
                    + std::time::Duration::from_secs(API_KEY_CACHE_TTL_SECS),
            },
        );
        tracing::debug!(
            event = "api_key_cache_miss",
            user_id = %user_info.id,
            ttl_secs = API_KEY_CACHE_TTL_SECS,
            "API key validated and cached"
        );
    }

    Ok(user_info)
}

/// Validate an API key against the Seren API with retry/backoff for transient failures.
async fn validate_api_key_uncached_with_retry(
    api_base_url: &str,
    api_key: &str,
    circuit_breaker: &Arc<oauth::circuit_breaker::OAuthCircuitBreaker>,
) -> Result<seren::DataResponseUserMeData, ApiKeyValidationError> {
    if !circuit_breaker.is_call_permitted() {
        tracing::warn!(
            event = "api_key_validation_circuit_open",
            "Skipping API key validation because upstream auth circuit is open"
        );
        return Err(ApiKeyValidationError::UpstreamError { status: None });
    }

    let mut last_status = None;
    for attempt in 1..=API_KEY_VALIDATION_MAX_ATTEMPTS {
        match validate_api_key_uncached(api_base_url, api_key).await {
            Ok(user_info) => {
                circuit_breaker.record_success();
                return Ok(user_info);
            }
            Err(ApiKeyValidationError::InvalidToken) => {
                return Err(ApiKeyValidationError::InvalidToken);
            }
            Err(ApiKeyValidationError::UpstreamError { status }) => {
                last_status = status;
                if attempt == API_KEY_VALIDATION_MAX_ATTEMPTS {
                    break;
                }

                tracing::warn!(
                    event = "api_key_validation_retry",
                    attempt,
                    max_attempts = API_KEY_VALIDATION_MAX_ATTEMPTS,
                    status = ?status,
                    "API key validation hit a transient upstream error; retrying"
                );
                let delay_ms = API_KEY_VALIDATION_RETRY_DELAY_MS.saturating_mul(attempt as u64);
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }

    circuit_breaker.record_failure();
    Err(ApiKeyValidationError::UpstreamError {
        status: last_status,
    })
}

/// Validate an API key against the Seren API by calling /auth/me (uncached).
async fn validate_api_key_uncached(
    api_base_url: &str,
    api_key: &str,
) -> Result<seren::DataResponseUserMeData, ApiKeyValidationError> {
    // Build HTTP client with the API key as bearer token
    let mut headers = reqwest::header::HeaderMap::new();
    let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_key))
        .map_err(|_| ApiKeyValidationError::InvalidToken)?;
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);

    let http_client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| ApiKeyValidationError::UpstreamError { status: e.status() })?;

    let api_client = seren::Client::new_with_client(api_base_url, http_client);

    match api_client.get_current_user().await {
        Ok(response) => Ok(response.into_inner().data),
        Err(e) => {
            let status = e.status();
            match status {
                Some(axum::http::StatusCode::UNAUTHORIZED)
                | Some(axum::http::StatusCode::FORBIDDEN) => {
                    Err(ApiKeyValidationError::InvalidToken)
                }
                _ => Err(ApiKeyValidationError::UpstreamError { status }),
            }
        }
    }
}

/// Simple token auth middleware (for start:http mode)
async fn require_simple_auth(
    axum::extract::State(state): axum::extract::State<SimpleAuthState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use subtle::ConstantTimeEq;

    let token = extract_bearer_token(&req);

    // Avoid token-dependent timing in the auth comparison.
    let authorized = match token {
        Some(token) => bool::from(token.as_bytes().ct_eq(state.token.as_bytes())),
        None => false,
    };
    if !authorized {
        return (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    next.run(req).await
}

/// OAuth token validation middleware (for start:server mode)
///
/// Validates MCP-issued JWTs and looks up upstream tokens for API calls.
/// MCP tokens are issued by this server and signed with HS256.
/// Upstream tokens (for backend API calls) are stored server-side and never exposed to clients.
async fn require_oauth_auth(
    axum::extract::State(state): axum::extract::State<OAuthAuthState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    tracing::debug!(
        event = "oauth_auth_start",
        method = %method,
        uri = %uri,
        "Starting OAuth authentication"
    );

    // Identity headers are owned by this middleware, not by callers.
    {
        let headers = req.headers_mut();
        headers.remove(axum::http::header::HeaderName::from_static("x-user-id"));
        headers.remove(axum::http::header::HeaderName::from_static("x-user-email"));
    }

    let session_id = req
        .headers()
        .get(axum::http::header::HeaderName::from_static(
            "mcp-session-id",
        ))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    tracing::debug!(
        event = "oauth_auth_session",
        session_id = ?session_id,
        "Session ID from request"
    );

    // MCP auth is per-request. Session IDs are transport state only and must not
    // be treated as authentication credentials.
    let token = extract_bearer_token(&req).map(|t| t.to_string());

    let resolved_auth = if let Some(token) = token {
        // Check if this is a Seren API key (starts with "seren_" prefix).
        // API keys can be used directly against the hosted MCP without going through OAuth flow.
        if is_seren_api_key(&token) {
            tracing::debug!(
                event = "oauth_auth_api_key_detected",
                method = %method,
                uri = %uri,
                "Seren API key detected, using API key authentication"
            );

            // Validate the API key against Seren API (with caching)
            match validate_api_key_cached(
                &state.oauth_state.upstream_api_base_url,
                &token,
                &state.api_key_cache,
                &state.oauth_state.circuit_breaker,
            )
            .await
            {
                Ok(user_info) => {
                    tracing::info!(
                        event = "oauth_auth_api_key_valid",
                        user_id = %user_info.id,
                        "API key authentication successful"
                    );

                    // Inject the API key directly as the upstream token
                    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("Bearer {}", token)) {
                        req.headers_mut()
                            .insert(axum::http::header::AUTHORIZATION, v);
                    }

                    // Inject user metadata headers
                    if let Ok(v) = axum::http::HeaderValue::from_str(&user_info.id.to_string()) {
                        req.headers_mut()
                            .insert(axum::http::header::HeaderName::from_static("x-user-id"), v);
                    }
                    if let Ok(v) = axum::http::HeaderValue::from_str(&user_info.email) {
                        req.headers_mut().insert(
                            axum::http::header::HeaderName::from_static("x-user-email"),
                            v,
                        );
                    }

                    // Mark this as an API key session (no MCP client registration)
                    req.headers_mut().insert(
                        axum::http::header::HeaderName::from_static("x-auth-method"),
                        axum::http::HeaderValue::from_static("api_key"),
                    );

                    let response = next.run(req).await;

                    let response_status = response.status();
                    if response_status.is_server_error() {
                        tracing::error!(
                            event = "oauth_auth_api_key_response_error",
                            method = %method,
                            uri = %uri,
                            status = %response_status,
                            user_id = %user_info.id,
                            "Handler returned server error after API key auth"
                        );
                    } else {
                        tracing::debug!(
                            event = "oauth_auth_api_key_response",
                            method = %method,
                            uri = %uri,
                            status = %response_status,
                            "API key authenticated request completed"
                        );
                    }

                    return response;
                }
                Err(ApiKeyValidationError::InvalidToken) => {
                    tracing::warn!(
                        event = "oauth_auth_api_key_invalid",
                        method = %method,
                        uri = %uri,
                        "API key validation failed"
                    );
                    return state
                        .unauthorized_response("invalid_token", "Invalid API key or token");
                }
                Err(ApiKeyValidationError::UpstreamError { status }) => {
                    tracing::warn!(
                        event = "oauth_auth_api_key_upstream_error",
                        method = %method,
                        uri = %uri,
                        status = ?status,
                        "API key validation failed due to upstream error"
                    );
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Authentication backend unavailable",
                        })),
                    )
                        .into_response();
                }
            }
        }

        // Token looks like a JWT - validate MCP-issued JWT (signed by this server with HS256)
        tracing::debug!(
            event = "oauth_auth_validating_mcp_jwt",
            "Validating MCP-issued JWT"
        );

        let claims = match state.oauth_state.jwt_signer.validate_access_token(&token) {
            Ok(claims) => {
                tracing::debug!(
                    event = "oauth_auth_jwt_valid",
                    user_id = %claims.sub,
                    client_id = %claims.client_id,
                    scope = %claims.scope,
                    "MCP JWT validated successfully"
                );
                claims
            }
            Err(e) => {
                tracing::debug!(
                    event = "oauth_auth_jwt_invalid",
                    error = %e,
                    "MCP JWT validation failed"
                );
                return state.unauthorized_response("invalid_token", "Token is invalid or expired");
            }
        };

        let user_id = match claims.user_id() {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    event = "oauth_auth_invalid_user_id",
                    sub = %claims.sub,
                    error = %e,
                    "Invalid user_id in JWT claims"
                );
                return state.unauthorized_response("invalid_token", "Invalid user_id in token");
            }
        };

        ResolvedOAuthIdentity {
            user_id,
            client_id: claims.client_id,
            email: claims.email,
            refresh_token_hash: claims.rth,
        }
    } else {
        tracing::warn!(
            event = "oauth_auth_no_token",
            method = %method,
            uri = %uri,
            session_id = ?session_id,
            "No bearer token found in request"
        );
        return state.unauthorized_response("unauthorized", "Bearer token required");
    };

    let user_id = resolved_auth.user_id;
    let user_id_text = user_id.to_string();
    let client_id_value = resolved_auth.client_id.clone();
    let client_id = Some(client_id_value.clone());

    // Look up upstream token for API calls (server-side only, never exposed to client).
    // New tokens include an `rth` (refresh_token_hash) claim that links directly to
    // their upstream token vault. Legacy tokens without `rth` fall back to user/client lookup.
    let mut refresh_token = match &resolved_auth.refresh_token_hash {
        Some(token_hash) => {
            // New path: lookup by the JWT's embedded refresh_token_hash
            match state.store.get_refresh_token_by_hash(token_hash).await {
                Ok(Some(refresh_token)) => {
                    tracing::debug!(
                        event = "oauth_auth_upstream_token_found_by_hash",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        token_hash = %token_hash,
                        "Found upstream token via JWT rth claim"
                    );
                    refresh_token
                }
                Ok(None) => {
                    tracing::warn!(
                        event = "oauth_auth_no_upstream_token_for_hash",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        token_hash = %token_hash,
                        "No upstream token found for JWT rth claim - session may have been revoked"
                    );
                    return state.unauthorized_response(
                        "invalid_token",
                        "Session has been revoked or expired (re-authentication required)",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        event = "oauth_auth_upstream_token_hash_error",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        token_hash = %token_hash,
                        error = %e,
                        "Failed to look up upstream token by hash"
                    );
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Token lookup failed",
                        })),
                    )
                        .into_response();
                }
            }
        }
        None => {
            // Legacy fallback: tokens without rth claim use user/client lookup
            // This returns the most recent token, which may not be this session's token
            // if the user has multiple concurrent sessions.
            tracing::debug!(
                event = "oauth_auth_legacy_token_lookup",
                user_id = %user_id,
                client_id = %client_id_value,
                "JWT missing rth claim, using legacy user/client lookup"
            );
            match state
                .store
                .get_refresh_token_by_user_client(user_id, &client_id_value)
                .await
            {
                Ok(Some(refresh_token)) => {
                    tracing::debug!(
                        event = "oauth_auth_upstream_token_found",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        "Found upstream token for API calls (legacy path)"
                    );
                    refresh_token
                }
                Ok(None) => {
                    tracing::warn!(
                        event = "oauth_auth_no_upstream_token",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        "No upstream token found - user may need to re-authenticate"
                    );
                    return state.unauthorized_response(
                        "invalid_token",
                        "No active session found for this token (re-authentication required)",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        event = "oauth_auth_upstream_token_error",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        error = %e,
                        "Failed to look up upstream token"
                    );
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Token lookup failed",
                        })),
                    )
                        .into_response();
                }
            }
        }
    };

    // Ensure the upstream access token is fresh for backend API calls.
    let refresh_window = time::Duration::seconds(60);

    if refresh_token.upstream_expires_at <= time::OffsetDateTime::now_utc() + refresh_window {
        let refresh_token_hash = refresh_token.token_hash.clone();

        // Refresh can race across concurrent requests; serialize per refresh_token_hash
        // so concurrent sessions for the same (user_id, client_id) don't trample each other.
        let lock_key: i64 = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(refresh_token_hash.as_bytes());
            let digest = h.finalize();
            i64::from_le_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
        };

        let mut lock_conn = match state.store.pool().acquire().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(
                    event = "oauth_auth_refresh_lock_acquire_failed",
                    user_id = %user_id,
                    client_id = %client_id_value,
                    error = %e,
                    "Failed to acquire database connection for refresh lock"
                );
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Token refresh temporarily unavailable",
                    })),
                )
                    .into_response();
            }
        };

        if let Err(e) = sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
        {
            tracing::warn!(
                event = "oauth_auth_refresh_lock_failed",
                user_id = %user_id,
                client_id = %client_id_value,
                error = %e,
                "Failed to acquire refresh lock"
            );
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Token refresh temporarily unavailable",
                })),
            )
                .into_response();
        }

        let mut lock_result: Option<axum::response::Response> = None;

        // Re-fetch the latest token under the lock (another request may have refreshed it).
        match state
            .store
            .get_refresh_token_by_hash(&refresh_token_hash)
            .await
        {
            Ok(Some(latest)) => refresh_token = latest,
            Ok(None) => {
                lock_result = Some(state.unauthorized_response(
                    "invalid_token",
                    "No active session found for this token (re-authentication required)",
                ));
            }
            Err(e) => {
                tracing::warn!(
                    event = "oauth_auth_upstream_token_error",
                    user_id = %user_id,
                    client_id = %client_id_value,
                    error = %e,
                    "Failed to look up upstream token"
                );
                lock_result = Some(
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        axum::Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Token lookup failed",
                        })),
                    )
                        .into_response(),
                );
            }
        }

        if lock_result.is_none()
            && refresh_token.upstream_expires_at <= time::OffsetDateTime::now_utc() + refresh_window
        {
            tracing::debug!(
                event = "oauth_auth_upstream_token_expired",
                user_id = %user_id,
                client_id = %client_id_value,
                "Upstream access token expired or near expiry; refreshing"
            );

            let upstream_refresh_token = match refresh_token.upstream_refresh_token.clone() {
                Some(token) => token,
                None => {
                    tracing::warn!(
                        event = "oauth_auth_missing_upstream_refresh_token",
                        user_id = %user_id,
                        client_id = %client_id_value,
                        "Missing upstream refresh token"
                    );
                    lock_result = Some(state.upstream_reauth_required_response(
                        "Upstream session cannot be refreshed (re-authentication required)",
                        REAUTH_REASON_REFRESH_TOKEN_MISSING,
                    ));
                    String::new()
                }
            };

            if lock_result.is_none() {
                let token_body = match crate::oauth::routes::exchange_upstream_token(
                    &state.oauth_state.http,
                    &state.oauth_state.upstream_api_base_url,
                    vec![
                        ("grant_type", "refresh_token"),
                        ("refresh_token", upstream_refresh_token.as_str()),
                        ("client_id", state.oauth_state.upstream_client_id.as_str()),
                    ],
                    &state.oauth_state.circuit_breaker,
                )
                .await
                {
                    Ok(body) => Some(body),
                    Err(crate::oauth::routes::OAuthError::InvalidGrant(_))
                    | Err(crate::oauth::routes::OAuthError::InvalidClient) => {
                        lock_result = Some(state.upstream_reauth_required_response(
                            "Upstream authorization expired (re-authentication required)",
                            REAUTH_REASON_AUTHORIZATION_EXPIRED,
                        ));
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "oauth_auth_upstream_refresh_failed",
                            user_id = %user_id,
                            client_id = %client_id_value,
                            error = ?e,
                            "Failed to refresh upstream token"
                        );
                        lock_result = Some(
                            (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                axum::Json(serde_json::json!({
                                    "error": "server_error",
                                    "error_description": "Upstream service temporarily unavailable",
                                })),
                            )
                                .into_response(),
                        );
                        None
                    }
                };

                if let Some(token_body) = token_body {
                    let crate::oauth::routes::UpstreamTokenResponse {
                        access_token: new_upstream_access_token,
                        expires_in,
                        refresh_token: new_upstream_refresh_token,
                        ..
                    } = token_body;

                    let refresh_now = time::OffsetDateTime::now_utc();
                    let new_upstream_expires_at =
                        refresh_now + time::Duration::seconds(expires_in.max(0));

                    match state
                        .store
                        .update_upstream_tokens(
                            &refresh_token.token_hash,
                            &new_upstream_access_token,
                            new_upstream_refresh_token.as_deref(),
                            new_upstream_expires_at,
                        )
                        .await
                    {
                        Ok(true) => {
                            tracing::debug!(
                                event = "oauth_auth_upstream_token_refreshed",
                                user_id = %user_id,
                                client_id = %client_id_value,
                                "Upstream token refreshed and persisted"
                            );
                            refresh_token.upstream_access_token = new_upstream_access_token;
                            refresh_token.upstream_expires_at = new_upstream_expires_at;
                            if new_upstream_refresh_token.is_some() {
                                refresh_token.upstream_refresh_token = new_upstream_refresh_token;
                            }
                        }
                        Ok(false) => {
                            tracing::warn!(
                                event = "oauth_auth_upstream_token_refresh_not_persisted",
                                user_id = %user_id,
                                client_id = %client_id_value,
                                "Refresh token record disappeared during refresh"
                            );
                            lock_result = Some(state.unauthorized_response(
                                "invalid_token",
                                "Session revoked (re-authentication required)",
                            ));
                        }
                        Err(e) => {
                            tracing::error!(
                                event = "oauth_auth_upstream_token_persist_error",
                                user_id = %user_id,
                                client_id = %client_id_value,
                                error = %e,
                                "Failed to persist refreshed upstream token"
                            );
                            lock_result = Some(state.upstream_reauth_required_response(
                                "Upstream session could not be saved (re-authentication required)",
                                REAUTH_REASON_TOKEN_PERSIST_FAILED,
                            ));
                        }
                    }
                }
            }
        }

        if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await
        {
            tracing::warn!(
                event = "oauth_auth_refresh_unlock_failed",
                user_id = %user_id,
                client_id = %client_id_value,
                error = %e,
                "Failed to release refresh lock"
            );
        }

        if let Some(resp) = lock_result {
            return resp;
        }
    }

    // Sliding expiry: extend the server-side session without requiring client re-login.
    if let Some(expires_at) = refresh_token.expires_at {
        let now = time::OffsetDateTime::now_utc();
        let new_expires_at = now + time::Duration::hours(oauth::store::REFRESH_TOKEN_TTL_HOURS);
        let renew_before = now
            + time::Duration::hours(
                oauth::store::REFRESH_TOKEN_TTL_HOURS
                    - oauth::store::SLIDING_EXPIRY_RENEWAL_INTERVAL_HOURS,
            );

        if expires_at < renew_before {
            let store = state.store.clone();
            let token_hash = refresh_token.token_hash.clone();
            let user_id_for_log = user_id;
            let client_id_for_log = client_id_value.clone();
            let session_id = session_id.clone();
            tokio::spawn(async move {
                match store
                    .extend_refresh_token_expiry_if_needed(
                        &token_hash,
                        new_expires_at,
                        renew_before,
                    )
                    .await
                {
                    Ok(true) => tracing::debug!(
                        event = "refresh_token_extended",
                        user_id = %user_id_for_log,
                        client_id = %client_id_for_log,
                        "Extended refresh token expiry"
                    ),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(
                        event = "refresh_token_extend_error",
                        user_id = %user_id_for_log,
                        client_id = %client_id_for_log,
                        error = %e,
                        "Failed to extend refresh token expiry"
                    ),
                }

                if let Some(session_id) = session_id
                    && let Err(e) = store
                        .extend_session_expiry_if_needed(&session_id, new_expires_at, renew_before)
                        .await
                {
                    tracing::warn!(
                        event = "session_token_extend_error",
                        user_id = %user_id_for_log,
                        client_id = %client_id_for_log,
                        error = %e,
                        "Failed to extend session token expiry"
                    );
                }
            });
        }
    }

    // Inject upstream token for API calls (backend expects upstream bearer token).
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
        "Bearer {}",
        refresh_token.upstream_access_token
    )) {
        req.headers_mut()
            .insert(axum::http::header::AUTHORIZATION, v);
    }

    // Inject user metadata from the resolved auth context.
    if let Ok(v) = axum::http::HeaderValue::from_str(&user_id_text) {
        req.headers_mut()
            .insert(axum::http::header::HeaderName::from_static("x-user-id"), v);
    }
    if let Some(ref email) = resolved_auth.email
        && let Ok(v) = axum::http::HeaderValue::from_str(email)
    {
        req.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-user-email"),
            v,
        );
    }

    // Look up client metadata for agent tracking
    if let Some(ref cid) = client_id
        && let Ok(Some(client)) = state.store.get_client(cid).await
    {
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

    let req_method = req.method().clone();
    let req_uri = req.uri().clone();
    tracing::debug!(
        event = "oauth_auth_calling_next",
        method = %req_method,
        uri = %req_uri,
        user_id = %user_id,
        client_id = ?client_id,
        "Authentication successful, calling next handler"
    );

    let response = next.run(req).await;

    let response_status = response.status();
    if response_status.is_server_error() {
        tracing::error!(
            event = "oauth_auth_response_error",
            method = %req_method,
            uri = %req_uri,
            status = %response_status,
            user_id = %user_id,
            "Handler returned server error after OAuth auth"
        );
    } else {
        tracing::debug!(
            event = "oauth_auth_response",
            method = %req_method,
            uri = %req_uri,
            status = %response_status,
            "Request completed"
        );
    }

    // Best-effort cleanup: when a session is explicitly closed, delete it from the database.
    if req_method == axum::http::Method::DELETE
        && let Some(sid) = session_id
    {
        // Remove from database asynchronously (fire-and-forget)
        let store = state.store.clone();
        let sid_clone = sid;
        tokio::spawn(async move {
            if let Err(e) = store.delete_session(&sid_clone).await {
                tracing::warn!(
                    event = "session_delete_error",
                    session_id = %sid_clone,
                    error = %e,
                    "Failed to delete session from database"
                );
            } else {
                tracing::debug!(
                    event = "session_deleted",
                    session_id = %sid_clone,
                    "Session token deleted from database"
                );
            }
        });
    }

    response
}

/// The MCP server operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpMode {
    /// Local stdio mode — for Claude Desktop and local MCP clients.
    /// Requires `API_KEY` env var.
    Stdio,
    /// HTTP mode with static bearer token auth.
    /// Requires `API_KEY` and `AUTH_TOKEN` env vars.
    Http,
    /// Hosted HTTP mode with full OAuth 2.1 + PKCE (production).
    /// Requires `DATABASE_URL` and `PUBLIC_URL` env vars.
    Server,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub passwords_master_password_file: Option<std::path::PathBuf>,
}

/// Start the MCP server in the given mode.
#[allow(clippy::result_large_err)]
pub async fn run(mode: McpMode) -> Result<()> {
    run_with_options(mode, RunOptions::default()).await
}

#[allow(clippy::result_large_err)]
pub async fn run_with_options(mode: McpMode, options: RunOptions) -> Result<()> {
    match mode {
        McpMode::Stdio => {
            let mut config = Config::from_env_for_command("start")?;
            config.passwords_master_password_file = options.passwords_master_password_file;

            // Stdio mode: log to stderr to avoid interfering with JSON-RPC on stdout
            let _guard = telemetry::init_subscriber(true);

            tracing::info!("Starting in stdio mode (local)");
            run_stdio(config).await
        }
        McpMode::Http => {
            let mut config = Config::from_env_for_command("start:http")?;
            config.passwords_master_password_file = options.passwords_master_password_file;

            // HTTP mode with simple token auth: log to stdout normally
            let _guard = telemetry::init_subscriber(false);

            tracing::info!("Starting in Streamable HTTP mode (simple auth)");
            run_http(config).await
        }
        McpMode::Server => {
            if options.passwords_master_password_file.is_some() {
                anyhow::bail!(
                    "--passwords-master-password-file is only available in local MCP modes"
                );
            }
            let config = Config::from_env_for_command("start:server")?;

            // HTTP mode with full OAuth 2.1: log to stdout normally
            let _guard = telemetry::init_subscriber(false);

            tracing::info!("Starting in Streamable HTTP mode (OAuth 2.1)");
            run_oauth(config).await
        }
    }
}

/// Entry point for the `seren-mcp` standalone binary.
///
/// Parses the mode from the first CLI argument (`start`, `start:http`, `start:server`,
/// or the legacy alias `start:oauth`) and delegates to [`run`].
pub async fn run_cli() -> Result<()> {
    let (mode, options) = parse_cli_args(std::env::args().skip(1))?;
    run_with_options(mode, options).await
}

fn parse_cli_args<I>(args: I) -> Result<(McpMode, RunOptions)>
where
    I: IntoIterator<Item = String>,
{
    let mut mode = None;
    let mut options = RunOptions::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "start" => set_mode(&mut mode, McpMode::Stdio)?,
            "start:http" => set_mode(&mut mode, McpMode::Http)?,
            "start:server" | "start:oauth" => set_mode(&mut mode, McpMode::Server)?,
            "--passwords-master-password-file" => {
                let path = args.next().ok_or_else(|| {
                    usage_error("--passwords-master-password-file requires a path")
                })?;
                options.passwords_master_password_file = Some(path.into());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            cmd => return Err(usage_error(format!("Unknown MCP command or option: {cmd}"))),
        }
    }

    Ok((mode.unwrap_or(McpMode::Stdio), options))
}

fn set_mode(mode: &mut Option<McpMode>, next: McpMode) -> Result<()> {
    if mode.replace(next).is_some() {
        return Err(usage_error("pass only one MCP command"));
    }
    Ok(())
}

fn usage_error(message: impl Into<String>) -> anyhow::Error {
    print_usage();
    anyhow::anyhow!(message.into())
}

fn print_usage() {
    eprintln!("Usage: seren-mcp [start|start:http|start:server] [OPTIONS]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  start         Start in stdio mode (local, default)");
    eprintln!("  start:http    Start in HTTP mode with simple token auth");
    eprintln!("  start:server  Start in HTTP mode with full OAuth 2.1");
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  --passwords-master-password-file <PATH>  Read the Seren Passwords master password from a file in local MCP modes"
    );
}

async fn run_stdio(config: Config) -> Result<()> {
    let api_key = match &config.auth {
        AuthConfig::ApiKey(key) => key.clone(),
        AuthConfig::OAuth { .. } => {
            anyhow::bail!("Stdio mode requires API_KEY environment variable");
        }
    };

    let server = SerenMcpServer::new_with_passwords_api_url_and_master_password_file(
        &api_key,
        &config.api_base_url,
        &config.passwords_api_base_url,
        config.passwords_master_password_file,
    )?;

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
            anyhow::bail!("start:http mode requires API_KEY (use start:server for hosted OAuth)");
        }
    };

    let auth_token = std::env::var("AUTH_TOKEN")
        .map_err(|_| anyhow::anyhow!("AUTH_TOKEN is required for start:http"))?;

    let api_base_url = config.api_base_url.clone();
    let passwords_api_base_url = config.passwords_api_base_url.clone();
    let passwords_master_password_file = config.passwords_master_password_file.clone();
    let public_url = config.public_url.clone();
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
    let public_urls = public_url.iter().map(String::as_str).collect::<Vec<_>>();
    let allowed_hosts = build_mcp_allowed_hosts(&public_urls);
    tracing::info!(
        allowed_hosts = ?allowed_hosts,
        "Configured MCP streamable HTTP Host allowlist"
    );
    let mut http_config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts);
    http_config.sse_keep_alive = Some(std::time::Duration::from_secs(15));
    http_config.sse_retry = Some(std::time::Duration::from_secs(3));
    http_config.stateful_mode = true;
    http_config.cancellation_token = ct.clone();

    // Create streamable HTTP service - it's a tower Service
    let mcp_service = StreamableHttpService::new(
        move || {
            SerenMcpServer::new_with_passwords_api_url_and_master_password_file(
                &api_key,
                &api_base_url,
                &passwords_api_base_url,
                passwords_master_password_file.clone(),
            )
            .map_err(std::io::Error::other)
        },
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
    // Wrap with StaleSessionRecoveryService to handle stale sessions after pod restarts
    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(
                tower::ServiceBuilder::new()
                    .service(middleware::StaleSessionRecoveryService::new(mcp_service)),
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            SimpleAuthState { token: auth_token },
            require_simple_auth,
        ));

    // Health endpoints (no auth required) for k8s probes
    let health_router = axum::Router::new()
        .route("/livez", axum::routing::get(livez))
        .route("/readyz", axum::routing::get(readyz))
        .with_state(HealthCheckState { store: None });

    // Documentation fallback - serves docs at any unmatched route
    let docs_router = axum::Router::new().fallback(docs::docs_handler);

    // Combine routers - CORS must be outermost, request ID middleware before CORS
    let app = axum::Router::new()
        .merge(health_router)
        .merge(mcp_router)
        .merge(docs_router);
    #[cfg(feature = "telemetry")]
    let app = app
        .route("/metrics", axum::routing::get(metrics::metrics_handler))
        .layer(axum::middleware::from_fn(middleware::metrics_middleware));
    let app = app
        .layer(cors)
        .layer(axum::middleware::from_fn(middleware::request_id_middleware));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Streamable HTTP MCP server listening on {}", addr);
    tracing::info!("Health endpoints:");
    tracing::info!("  GET /livez   - liveness");
    tracing::info!("  GET /readyz  - readiness");
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
        StreamableHttpServerConfig, StreamableHttpService, session::local::SessionConfig,
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
            anyhow::bail!("start:server mode requires DATABASE_URL and PUBLIC_URL");
        }
    };

    // Connect to token store
    let store = TokenStore::connect(&database_url).await?;
    tracing::info!("Connected to OAuth database");

    // Hosted OAuth mode stores upstream OAuth tokens in Postgres.
    // Require encryption at rest for start:server mode.
    if !store.token_encryption_enabled() {
        anyhow::bail!("OAUTH_TOKEN_ENCRYPTION_KEYS is required for start:server mode.");
    }

    // Run database migrations (embedded at compile time)
    tracing::info!("Running database migrations");
    sqlx::migrate!("./migrations").run(store.pool()).await?;
    tracing::info!("Database migrations completed");

    let api_base_url = config.api_base_url.clone();
    let passwords_api_base_url = config.passwords_api_base_url.clone();
    let oauth_redirect_base_url = config.oauth_redirect_base_url.clone();
    let api_base_url_for_service = api_base_url.clone();
    let passwords_api_base_url_for_service = passwords_api_base_url.clone();
    let api_base_url_for_session_manager = api_base_url.clone();
    let passwords_api_base_url_for_session_manager = passwords_api_base_url.clone();

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

    // Create restorable session manager that can restore sessions after server restart
    // Sessions are persisted to PostgreSQL and restored transparently when clients reconnect
    let session_manager = Arc::new(middleware::RestorableSessionManager::new(
        Arc::new(store.clone()),
        SessionConfig::default(),
        api_base_url_for_session_manager,
        passwords_api_base_url_for_session_manager,
    ));

    // Log initial session count (sessions from previous instance can now be restored)
    match store.count_sessions().await {
        Ok(count) => {
            if count > 0 {
                tracing::info!(
                    event = "restorable_sessions_detected",
                    count = count,
                    "Found {} sessions in database that can be restored",
                    count
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                event = "rmcp_session_count_failed",
                error = %e,
                "Failed to count existing rmcp sessions"
            );
        }
    }

    // Create streamable HTTP service config
    let allowed_hosts = build_mcp_allowed_hosts(&[&server_host]);
    tracing::info!(
        allowed_hosts = ?allowed_hosts,
        "Configured MCP streamable HTTP Host allowlist"
    );
    let mut http_config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts);
    http_config.sse_keep_alive = Some(std::time::Duration::from_secs(15));
    http_config.sse_retry = Some(std::time::Duration::from_secs(3));
    http_config.stateful_mode = true;
    http_config.cancellation_token = ct.clone();

    // Create streamable HTTP service with persistent session manager
    let store_for_service = Arc::new(store.clone());
    let mcp_service = StreamableHttpService::new(
        move || {
            SerenMcpServer::new_oauth_with_store_and_passwords_api_url(
                &api_base_url_for_service,
                &passwords_api_base_url_for_service,
                Some(store_for_service.clone()),
            )
            .map_err(std::io::Error::other)
        },
        session_manager,
        http_config,
    );

    // CORS configuration per MCP spec
    // Must allow and expose Mcp-Session-Id for rmcp session management.
    // WWW-Authenticate and the reauth headers are exposed so browser-based MCP
    // clients can read the OAuth discovery challenge and the upstream-reauth
    // signal emitted by the auth middleware.
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
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::header::HeaderName::from_static("mcp-session-id"),
            axum::http::header::HeaderName::from_static(REAUTH_REQUIRED_HEADER),
            axum::http::header::HeaderName::from_static(REAUTH_REASON_HEADER),
        ]);

    // Create MCP JWT signer for issuing and validating MCP access tokens
    // MCP tokens are signed with HS256 using a symmetric secret key
    let jwt_secrets = match std::env::var("JWT_SECRETS") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => vec![std::env::var("JWT_SECRET").map_err(|_| {
            anyhow::anyhow!("JWT_SECRET or JWT_SECRETS is required for start:server mode")
        })?],
    };

    if jwt_secrets.is_empty() {
        anyhow::bail!("JWT_SECRETS is set but empty");
    }
    if jwt_secrets.iter().any(|s| s.len() < 32) {
        anyhow::bail!("All JWT secrets must be at least 32 bytes for security");
    }

    let jwt_secret_refs = jwt_secrets.iter().map(|s| s.as_bytes()).collect::<Vec<_>>();
    let jwt_signer = Arc::new(if jwt_secret_refs.len() == 1 {
        oauth::McpJwtSigner::new(jwt_secret_refs[0], &server_host)
    } else {
        oauth::McpJwtSigner::new_with_secrets(&jwt_secret_refs, &server_host)
    });
    tracing::info!(
        issuer = %jwt_signer.issuer(),
        audience = %jwt_signer.audience(),
        num_validation_secrets = jwt_secrets.len(),
        "MCP JWT signer initialized"
    );

    // OAuth state for routes
    let oauth_state = Arc::new(OAuthState {
        store: store.clone(),
        http: {
            let upstream_timeout_secs = std::env::var("UPSTREAM_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(15);
            let upstream_connect_timeout_secs = std::env::var("UPSTREAM_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);

            reqwest::Client::builder()
                .user_agent(format!("{}/{}", MCP_SERVER_NAME, env!("CARGO_PKG_VERSION")))
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
        jwt_signer,
    });

    // Clone store for health check before moving it
    let health_store = Arc::new(store.clone());

    // MCP endpoint with OAuth token validation
    // API key validation cache (5-minute TTL to reduce backend calls)
    let api_key_cache = Arc::new(Mutex::new(LruCache::new(
        NonZeroUsize::new(API_KEY_CACHE_SIZE).expect("API_KEY_CACHE_SIZE must be > 0"),
    )));
    let oauth_auth_state = OAuthAuthState {
        store,
        api_key_cache,
        oauth_state: oauth_state.clone(),
    };

    // Wrap with StaleSessionRecoveryService to handle stale sessions after pod restarts
    let mcp_router = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::any_service(
                tower::ServiceBuilder::new()
                    .service(middleware::StaleSessionRecoveryService::new(mcp_service)),
            ),
        )
        .route(
            "/passwords/hosted-agent/{identity_id}",
            axum::routing::delete(delete_hosted_passwords_agent),
        )
        .with_state(oauth_auth_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            oauth_auth_state,
            require_oauth_auth,
        ));

    // Health endpoints (no auth required) for k8s probes
    let health_router = axum::Router::new()
        .route("/livez", axum::routing::get(livez))
        .route("/readyz", axum::routing::get(readyz))
        .with_state(HealthCheckState {
            store: Some(health_store),
        });

    // Documentation fallback - serves docs at any unmatched route
    let docs_router = axum::Router::new().fallback(docs::docs_handler);

    // Combine OAuth routes, health, MCP endpoint, and docs fallback
    // CORS must be outermost, request ID middleware before CORS
    let app = axum::Router::new()
        .merge(health_router)
        .merge(oauth_router(oauth_state))
        .merge(mcp_router)
        .merge(docs_router);
    #[cfg(feature = "telemetry")]
    let app = app
        .route("/metrics", axum::routing::get(metrics::metrics_handler))
        .layer(axum::middleware::from_fn(middleware::metrics_middleware));
    let app = app
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(middleware::request_id_middleware));

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("OAuth MCP server listening on {}", addr);
    tracing::info!("OAuth endpoints:");
    tracing::info!("  GET  /.well-known/oauth-protected-resource - Resource metadata (RFC 9728)");
    tracing::info!("  GET  /.well-known/oauth-authorization-server - Server metadata (RFC 8414)");
    tracing::info!("  POST /register - Dynamic client registration");
    tracing::info!("  GET  /authorize - Authorization endpoint");
    tracing::info!("  POST /token - Token endpoint");
    tracing::info!("Health endpoints:");
    tracing::info!("  GET  /livez   - liveness");
    tracing::info!("  GET  /readyz  - readiness");
    tracing::info!("MCP endpoint:");
    tracing::info!("  POST   /mcp - send JSON-RPC messages");
    tracing::info!("  GET    /mcp - establish SSE stream (with session)");
    tracing::info!("  DELETE /mcp - close session");
    tracing::info!("Server host: {}", server_host);

    let server_ct = ct.clone();
    // Use into_make_service_with_connect_info to provide SocketAddr to rate limiter.
    // SmartIpKeyExtractor falls back to ConnectInfo when proxy headers aren't present.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[test]
    fn parse_cli_args_accepts_passwords_master_password_file() {
        let (mode, options) = parse_cli_args([
            "start".to_string(),
            "--passwords-master-password-file".to_string(),
            "/tmp/password".to_string(),
        ])
        .unwrap();

        assert_eq!(mode, McpMode::Stdio);
        assert_eq!(
            options.passwords_master_password_file,
            Some(std::path::PathBuf::from("/tmp/password"))
        );
    }

    #[test]
    fn parse_cli_args_defaults_to_start_with_passwords_file() {
        let (mode, options) = parse_cli_args([
            "--passwords-master-password-file".to_string(),
            "/tmp/password".to_string(),
        ])
        .unwrap();

        assert_eq!(mode, McpMode::Stdio);
        assert_eq!(
            options.passwords_master_password_file,
            Some(std::path::PathBuf::from("/tmp/password"))
        );
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

    #[tokio::test]
    async fn validate_api_key_retries_transient_auth_backend_failure() {
        let upstream = MockServer::start().await;
        let api_key = "seren_test_key";

        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .and(header("authorization", format!("Bearer {api_key}")))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "error": "temporarily unavailable"
            })))
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&upstream)
            .await;

        let user_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .and(header("authorization", format!("Bearer {api_key}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "id": user_id,
                    "email": "user@example.com",
                    "name": "Test User",
                    "status": "active",
                    "created_at": "2026-01-01T00:00:00Z",
                    "default_organization_id": organization_id
                }
            })))
            .with_priority(2)
            .mount(&upstream)
            .await;

        let user = validate_api_key_uncached_with_retry(
            &upstream.uri(),
            api_key,
            &oauth::circuit_breaker::create_oauth_circuit_breaker(),
        )
        .await
        .expect("transient validation failure should be retried");

        assert_eq!(user.id, user_id);
    }

    #[test]
    fn is_seren_api_key_detects_prefix() {
        // Valid Seren API keys (start with "seren_")
        assert!(is_seren_api_key("seren_aK4iP9zB1234567890"));
        assert!(is_seren_api_key("seren_"));
        assert!(is_seren_api_key("seren_abc"));

        // Not Seren API keys
        assert!(!is_seren_api_key("sk-1234567890abcdef"));
        assert!(!is_seren_api_key("simple-api-key"));
        assert!(!is_seren_api_key("1234567890"));
        assert!(!is_seren_api_key(""));

        // JWTs are not API keys
        assert!(!is_seren_api_key(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        ));

        // Case sensitive - must be lowercase
        assert!(!is_seren_api_key("SEREN_abc"));
        assert!(!is_seren_api_key("Seren_abc"));
    }

    #[test]
    fn build_www_authenticate_includes_error_and_resource_metadata() {
        let header = OAuthAuthState::build_www_authenticate(
            "invalid_token",
            "Bad \"token\"\ntry again",
            "https://mcp.serendb.com/",
        );

        assert!(header.starts_with("Bearer "));
        assert!(header.contains(&format!(r#"realm="{}""#, MCP_AUTH_REALM)));
        assert!(header.contains(
            r#"resource_metadata="https://mcp.serendb.com/.well-known/oauth-protected-resource""#
        ));
        assert!(header.contains(r#"error="invalid_token""#));
        assert!(header.contains(r#"error_description="Bad \"token\" try again""#));
    }

    #[tokio::test]
    async fn upstream_reauth_required_response_is_machine_readable() {
        let response = OAuthAuthState::upstream_reauth_required_response_for_server(
            "Upstream authorization expired (re-authentication required)",
            REAUTH_REASON_AUTHORIZATION_EXPIRED,
            "https://mcp.serendb.com/",
        );

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let headers = response.headers();
        assert_eq!(
            headers
                .get(axum::http::HeaderName::from_static(REAUTH_REQUIRED_HEADER))
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            headers
                .get(axum::http::HeaderName::from_static(REAUTH_REASON_HEADER))
                .and_then(|value| value.to_str().ok()),
            Some(REAUTH_REASON_AUTHORIZATION_EXPIRED)
        );
        assert!(
            headers
                .get(axum::http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains(
                    r#"resource_metadata="https://mcp.serendb.com/.well-known/oauth-protected-resource""#
                ))
        );

        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "invalid_token");
        assert_eq!(body["reauth_required"], true);
        assert_eq!(body["reauth_reason"], REAUTH_REASON_AUTHORIZATION_EXPIRED);
    }

    #[test]
    fn build_mcp_allowed_hosts_includes_public_and_local_hosts() {
        let hosts = build_mcp_allowed_hosts(&[
            "https://mcp.serendb.com/mcp",
            "https://staging-mcp.serendb.com:8443/mcp",
            "not a url",
        ]);

        assert!(hosts.contains(&"localhost".to_string()));
        assert!(hosts.contains(&"127.0.0.1".to_string()));
        assert!(hosts.contains(&"::1".to_string()));
        assert!(hosts.contains(&"mcp.serendb.com".to_string()));
        assert!(hosts.contains(&"staging-mcp.serendb.com:8443".to_string()));
        assert!(hosts.contains(&"staging-mcp.serendb.com".to_string()));
    }

    #[test]
    fn parse_cli_args_parses_server_mode_with_file() {
        // Parsing is permissive; run_with_options enforces the hosted rejection.
        let (mode, options) = parse_cli_args([
            "start:server".to_string(),
            "--passwords-master-password-file".to_string(),
            "/tmp/password".to_string(),
        ])
        .unwrap();

        assert_eq!(mode, McpMode::Server);
        assert_eq!(
            options.passwords_master_password_file,
            Some(std::path::PathBuf::from("/tmp/password"))
        );
    }

    #[test]
    fn parse_cli_args_requires_file_value() {
        let err = parse_cli_args([
            "start".to_string(),
            "--passwords-master-password-file".to_string(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("requires a path"));
    }

    #[test]
    fn parse_cli_args_rejects_two_modes() {
        let err = parse_cli_args(["start".to_string(), "start:http".to_string()]).unwrap_err();
        assert!(err.to_string().contains("only one MCP command"));
    }

    #[tokio::test]
    async fn run_with_options_rejects_master_password_file_in_server_mode() {
        let options = RunOptions {
            passwords_master_password_file: Some(std::path::PathBuf::from("/tmp/password")),
        };

        let err = run_with_options(McpMode::Server, options)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only available in local MCP modes")
        );
    }
}
