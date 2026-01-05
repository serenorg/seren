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

/// Auth state for OAuth mode with MCP JWT validation
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
    /// Shared OAuth state for endpoints and configuration.
    oauth_state: Arc<OAuthState>,
}

impl OAuthAuthState {
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
        let server_host = self.oauth_state.server_host.trim_end_matches('/');
        let www_authenticate = format!(
            r#"Bearer realm="serendb", resource_metadata="{}/.well-known/oauth-protected-resource", scope="api""#,
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

/// OAuth token validation middleware (for start:oauth mode)
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

    // Prefer an explicit Authorization header.
    let mut token = extract_bearer_token(&req).map(|t| t.to_string());
    let mut token_from_session_cache = false;

    // If missing, try to recover the token from the session cache.
    // First check the in-memory LRU cache (fast path), then fall back to database (survives restarts).
    if token.is_none()
        && let Some(ref sid) = session_id
    {
        // Try LRU cache first
        token = state.session_tokens.lock().await.get(sid).cloned();
        if token.is_some() {
            token_from_session_cache = true;
            tracing::debug!(
                event = "oauth_auth_token_from_lru_cache",
                session_id = %sid,
                "Retrieved token from LRU cache"
            );
        } else {
            // Fall back to database lookup
            match state.store.get_session_token(sid).await {
                Ok(Some(session_token)) => {
                    token = Some(session_token.access_token.clone());
                    token_from_session_cache = true;
                    // Populate the LRU cache for future requests
                    state
                        .session_tokens
                        .lock()
                        .await
                        .put(sid.clone(), session_token.access_token);
                    tracing::debug!(
                        event = "oauth_auth_token_from_database",
                        session_id = %sid,
                        user_id = %session_token.user_id,
                        "Retrieved token from database and populated LRU cache"
                    );
                }
                Ok(None) => {
                    tracing::debug!(
                        event = "oauth_auth_session_not_in_db",
                        session_id = %sid,
                        "Session token not found in database"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        event = "oauth_auth_session_db_error",
                        session_id = %sid,
                        error = %e,
                        "Failed to lookup session token from database"
                    );
                }
            }
        }
    }

    let Some(mut token) = token else {
        tracing::warn!(
            event = "oauth_auth_no_token",
            method = %method,
            uri = %uri,
            session_id = ?session_id,
            "No bearer token found in request or session cache"
        );
        return state.unauthorized_response("unauthorized", "Bearer token required");
    };

    // Validate MCP-issued JWT (signed by this server with HS256)
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

            // Streamable HTTP clients may omit Authorization after the initial request.
            // If we have a session id, re-issue a fresh MCP access token server-side and continue.
            if let Some(ref sid) = session_id {
                tracing::debug!(
                    event = "oauth_auth_jwt_invalid_attempt_session_reissue",
                    session_id = %sid,
                    token_from_session_cache = token_from_session_cache,
                    "Attempting to re-issue MCP access token from session"
                );

                let session_token = match state.store.get_session_token(sid).await {
                    Ok(Some(session_token)) => session_token,
                    Ok(None) => {
                        return state.unauthorized_response(
                            "invalid_token",
                            "Session not found or expired (re-authentication required)",
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "oauth_auth_session_db_error",
                            session_id = %sid,
                            error = %e,
                            "Failed to lookup session token for re-issue"
                        );
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(serde_json::json!({
                                "error": "server_error",
                                "error_description": "Session lookup failed",
                            })),
                        )
                            .into_response();
                    }
                };

                let Some(session_client_id) = session_token.client_id else {
                    return state.unauthorized_response(
                        "invalid_token",
                        "Session missing client id (re-authentication required)",
                    );
                };

                let refresh_token = match state
                    .store
                    .get_refresh_token_by_user_client(session_token.user_id, &session_client_id)
                    .await
                {
                    Ok(Some(refresh_token)) => refresh_token,
                    Ok(None) => {
                        return state.unauthorized_response(
                            "invalid_token",
                            "No active session found for this user/client (re-authentication required)",
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "oauth_auth_refresh_token_db_error",
                            session_id = %sid,
                            user_id = %session_token.user_id,
                            client_id = %session_client_id,
                            error = %e,
                            "Failed to lookup refresh token for session re-issue"
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
                };

                let (new_token, _) = match state.oauth_state.jwt_signer.sign_access_token(
                    session_token.user_id,
                    &session_client_id,
                    &refresh_token.scope,
                    None,
                    None,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(
                            event = "oauth_auth_session_reissue_failed",
                            session_id = %sid,
                            error = %e,
                            "Failed to sign new MCP access token"
                        );
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(serde_json::json!({
                                "error": "server_error",
                                "error_description": "Token signing failed",
                            })),
                        )
                            .into_response();
                    }
                };

                token = new_token;

                match state.oauth_state.jwt_signer.validate_access_token(&token) {
                    Ok(claims) => claims,
                    Err(e) => {
                        tracing::warn!(
                            event = "oauth_auth_session_reissue_validation_failed",
                            session_id = %sid,
                            error = %e,
                            "Re-issued MCP token failed validation"
                        );
                        return state
                            .unauthorized_response("invalid_token", "Token is invalid or expired");
                    }
                }
            } else {
                return state.unauthorized_response("invalid_token", "Token is invalid or expired");
            }
        }
    };

    // Get client_id from JWT claims (MCP tokens include client_id)
    let client_id = Some(claims.client_id.clone());
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

    // Look up upstream token for API calls (server-side only, never exposed to client).
    let mut refresh_token = match state
        .store
        .get_refresh_token_by_user_client(user_id, &claims.client_id)
        .await
    {
        Ok(Some(refresh_token)) => {
            tracing::debug!(
                event = "oauth_auth_upstream_token_found",
                user_id = %user_id,
                client_id = %claims.client_id,
                "Found upstream token for API calls"
            );
            refresh_token
        }
        Ok(None) => {
            tracing::warn!(
                event = "oauth_auth_no_upstream_token",
                user_id = %user_id,
                client_id = %claims.client_id,
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
                client_id = %claims.client_id,
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
    };

    // Ensure the upstream access token is fresh for backend API calls.
    let refresh_window = time::Duration::seconds(60);

    if refresh_token.upstream_expires_at <= time::OffsetDateTime::now_utc() + refresh_window {
        // Refresh can race across concurrent requests; serialize per (user_id, client_id)
        // to avoid refresh token rotation conflicts.
        let lock_key: i64 = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(user_id.as_bytes());
            h.update(claims.client_id.as_bytes());
            let digest = h.finalize();
            i64::from_le_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"))
        };

        let mut lock_conn = match state.store.pool().acquire().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(
                    event = "oauth_auth_refresh_lock_acquire_failed",
                    user_id = %user_id,
                    client_id = %claims.client_id,
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
                client_id = %claims.client_id,
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
            .get_refresh_token_by_user_client(user_id, &claims.client_id)
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
                    client_id = %claims.client_id,
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
                client_id = %claims.client_id,
                "Upstream access token expired or near expiry; refreshing"
            );

            let upstream_refresh_token = match refresh_token.upstream_refresh_token.clone() {
                Some(token) => token,
                None => {
                    tracing::warn!(
                        event = "oauth_auth_missing_upstream_refresh_token",
                        user_id = %user_id,
                        client_id = %claims.client_id,
                        "Missing upstream refresh token"
                    );
                    lock_result = Some(state.unauthorized_response(
                        "invalid_token",
                        "Upstream session cannot be refreshed (re-authentication required)",
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
                        lock_result = Some(state.unauthorized_response(
                            "invalid_token",
                            "Upstream authorization expired (re-authentication required)",
                        ));
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "oauth_auth_upstream_refresh_failed",
                            user_id = %user_id,
                            client_id = %claims.client_id,
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
                                client_id = %claims.client_id,
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
                                client_id = %claims.client_id,
                                "Refresh token record disappeared during refresh"
                            );
                            lock_result = Some(state.unauthorized_response(
                                "invalid_token",
                                "Session revoked (re-authentication required)",
                            ));
                        }
                        Err(e) => {
                            tracing::warn!(
                                event = "oauth_auth_upstream_token_persist_error",
                                user_id = %user_id,
                                client_id = %claims.client_id,
                                error = %e,
                                "Failed to persist refreshed upstream token"
                            );
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
                client_id = %claims.client_id,
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
            let token = refresh_token.token_hash.clone();
            let user_id_for_log = user_id;
            let client_id_for_log = claims.client_id.clone();
            let session_id = session_id.clone();
            tokio::spawn(async move {
                match store
                    .extend_refresh_token_expiry_if_needed(&token, new_expires_at, renew_before)
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
                        .extend_session_token_expiry_if_needed(
                            &session_id,
                            new_expires_at,
                            renew_before,
                        )
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

    // Inject user metadata from JWT claims
    if let Ok(v) = axum::http::HeaderValue::from_str(&claims.sub) {
        req.headers_mut()
            .insert(axum::http::header::HeaderName::from_static("x-user-id"), v);
    }
    if let Some(ref email) = claims.email
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

    // If the request includes a session id, remember/update the token for that session.
    // Save to the LRU cache (fast path). Database TTL is extended in the background.
    if let Some(ref sid) = session_id {
        state
            .session_tokens
            .lock()
            .await
            .put(sid.clone(), token.clone());
    }

    let req_method = req.method().clone();
    let req_uri = req.uri().clone();
    tracing::debug!(
        event = "oauth_auth_calling_next",
        method = %req_method,
        uri = %req_uri,
        user_id = %claims.sub,
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
            user_id = %claims.sub,
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

    // For the initial session-creating initialize request, rmcp returns `Mcp-Session-Id`
    // in the response headers. Cache the token under that session id so clients can
    // omit Authorization on subsequent requests.
    // Save to both LRU cache (fast path) and database (persistence across restarts).
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
            .lock()
            .await
            .put(sid.clone(), token.clone());

        // Persist to database asynchronously (fire-and-forget to not block response)
        // Use refresh token TTL for session expiry to allow session persistence
        let store = state.store.clone();
        let sid_clone = sid;
        let token_clone = token.clone();
        let client_id_clone = client_id.clone();
        let session_expires_at = time::OffsetDateTime::now_utc()
            + time::Duration::hours(oauth::store::REFRESH_TOKEN_TTL_HOURS);
        tokio::spawn(async move {
            if let Err(e) = store
                .save_session_token(
                    &sid_clone,
                    &token_clone,
                    client_id_clone.as_deref(),
                    user_id,
                    session_expires_at,
                )
                .await
            {
                tracing::warn!(
                    event = "session_token_persist_error",
                    session_id = %sid_clone,
                    error = %e,
                    "Failed to persist new session token to database"
                );
            } else {
                tracing::debug!(
                    event = "session_token_persisted",
                    session_id = %sid_clone,
                    "New session token persisted to database"
                );
            }
        });
    }

    // Best-effort cleanup: when a session is explicitly closed, drop the cached token.
    // Remove from both LRU cache and database.
    if req_method == axum::http::Method::DELETE
        && let Some(sid) = session_id
    {
        state.session_tokens.lock().await.pop(&sid);

        // Remove from database asynchronously (fire-and-forget)
        let store = state.store.clone();
        let sid_clone = sid;
        tokio::spawn(async move {
            if let Err(e) = store.delete_session_token(&sid_clone).await {
                tracing::warn!(
                    event = "session_token_delete_error",
                    session_id = %sid_clone,
                    error = %e,
                    "Failed to delete session token from database"
                );
            } else {
                tracing::debug!(
                    event = "session_token_deleted",
                    session_id = %sid_clone,
                    "Session token deleted from database"
                );
            }
        });
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

    // Run database migrations (embedded at compile time)
    tracing::info!("Running database migrations");
    sqlx::migrate!("./migrations").run(store.pool()).await?;
    tracing::info!("Database migrations completed");

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

    // Create MCP JWT signer for issuing and validating MCP access tokens
    // MCP tokens are signed with HS256 using a symmetric secret key
    let jwt_secrets = match std::env::var("JWT_SECRETS") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        Err(_) => vec![std::env::var("JWT_SECRET").map_err(|_| {
            anyhow::anyhow!("JWT_SECRET or JWT_SECRETS is required for start:oauth mode")
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
        jwt_signer,
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
    tracing::info!("  GET  /.well-known/oauth-protected-resource - Resource metadata (RFC 9728)");
    tracing::info!("  GET  /.well-known/oauth-authorization-server - Server metadata (RFC 8414)");
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
