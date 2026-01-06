//! OAuth2 HTTP routes for hosted MCP server mode.
//!
//! Implements OAuth 2.1 endpoints per MCP specification:
//! - `/.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
//! - `/authorize` - Authorization endpoint (downstream: MCP client -> this server)
//! - `/callback` - Callback endpoint (upstream -> this server)
//! - `/token` - Token endpoint
//! - `/register` - Dynamic client registration (RFC 7591)
//!
//! This server acts as the OAuth authorization server for MCP clients, but delegates
//! actual user authentication to upstream `/oauth2/*` (Authorization Code + PKCE).

use crate::oauth::circuit_breaker::OAuthCircuitBreaker;
use crate::oauth::jwt::McpJwtSigner;
use crate::oauth::store::{
    AuthRequest, AuthorizationCode, PkceMethod, REFRESH_TOKEN_TTL_HOURS, RefreshToken, TokenStore,
};
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tracing::debug;
use uuid::Uuid;

/// OAuth server state.
#[derive(Clone)]
pub struct OAuthState {
    pub store: TokenStore,
    /// Shared HTTP client for upstream requests.
    pub http: reqwest::Client,
    /// Public base URL of this MCP server (e.g. `https://mcp.serendb.com`).
    pub server_host: String,
    /// Client id used with upstream `/oauth2/*` endpoints.
    pub upstream_client_id: String,
    /// Base URL for upstream API server-to-server calls (e.g. internal cluster URL).
    pub upstream_api_base_url: String,
    /// Base URL for upstream API used in OAuth browser redirects (e.g. public URL).
    pub upstream_oauth_redirect_base_url: String,
    /// Circuit breaker for upstream API resilience.
    pub circuit_breaker: Arc<OAuthCircuitBreaker>,
    /// JWT signer for MCP-issued access tokens.
    pub jwt_signer: Arc<McpJwtSigner>,
}

const SUPPORTED_GRANT_TYPES: &[&str] = &["authorization_code", "refresh_token"];
const SUPPORTED_RESPONSE_TYPES: &[&str] = &["code"];
const SUPPORTED_AUTH_METHODS: &[&str] = &["none", "client_secret_post"];
const ALLOWED_SCOPES: &[&str] = &["api"];

// ============================================================================
// Metadata Endpoint (RFC 8414)
// ============================================================================

/// Protected Resource Metadata (RFC 9728)
/// This describes the MCP server as a protected resource and points to the authorization server.
#[derive(Debug, Serialize)]
struct ProtectedResourceMetadata {
    /// The canonical URI of this protected resource
    resource: String,
    /// List of authorization servers that can issue tokens for this resource
    authorization_servers: Vec<String>,
    /// Scopes supported by this resource
    scopes_supported: Vec<String>,
    /// Methods for passing bearer tokens (typically just "header")
    bearer_methods_supported: Vec<String>,
    /// Optional: resource documentation URL
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_documentation: Option<String>,
}

/// GET /.well-known/oauth-protected-resource (RFC 9728)
/// Clients use this to discover which authorization server to use.
async fn protected_resource_metadata(
    State(state): State<Arc<OAuthState>>,
) -> Json<ProtectedResourceMetadata> {
    let server_host = state.server_host.trim_end_matches('/').to_string();
    Json(ProtectedResourceMetadata {
        resource: format!("{}/mcp", server_host),
        // RFC 9728: `authorization_servers` contains authorization server issuer identifiers
        // (NOT the metadata endpoint URL). The client will discover metadata from the issuer.
        authorization_servers: vec![server_host.clone()],
        scopes_supported: ALLOWED_SCOPES.iter().map(|s| (*s).into()).collect(),
        bearer_methods_supported: vec!["header".into()],
        resource_documentation: Some("https://mcp.serendb.com".into()),
    })
}

/// Authorization Server Metadata (RFC 8414)
#[derive(Debug, Serialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    registration_endpoint: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    revocation_endpoint_auth_methods_supported: Vec<String>,
}

/// GET /.well-known/oauth-authorization-server (RFC 8414)
async fn metadata(State(state): State<Arc<OAuthState>>) -> Json<AuthorizationServerMetadata> {
    let server_host = state.server_host.trim_end_matches('/').to_string();
    Json(AuthorizationServerMetadata {
        issuer: server_host.clone(),
        authorization_endpoint: format!("{}/authorize", server_host),
        token_endpoint: format!("{}/token", server_host),
        revocation_endpoint: format!("{}/revoke", server_host),
        registration_endpoint: format!("{}/register", server_host),
        scopes_supported: ALLOWED_SCOPES.iter().map(|s| (*s).into()).collect(),
        response_types_supported: vec!["code".into()],
        grant_types_supported: SUPPORTED_GRANT_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        token_endpoint_auth_methods_supported: SUPPORTED_AUTH_METHODS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        code_challenge_methods_supported: vec!["S256".into()],
        revocation_endpoint_auth_methods_supported: vec![
            "none".into(),
            "client_secret_post".into(),
        ],
    })
}

// ============================================================================
// Dynamic Client Registration (RFC 7591)
// ============================================================================

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    client_name: String,
    redirect_uris: Vec<String>,
    response_types: Vec<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    // Optional metadata (RFC 7591)
    #[serde(default)]
    client_uri: Option<String>,
    #[serde(default)]
    software_id: Option<String>,
    #[serde(default)]
    software_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
    token_endpoint_auth_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    software_version: Option<String>,
}

async fn register(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, OAuthError> {
    debug!(client_name = %req.client_name, "Client registration request");

    if req.client_name.trim().is_empty() {
        return Err(OAuthError::InvalidRequest("client_name is required".into()));
    }
    if req.redirect_uris.is_empty() {
        return Err(OAuthError::InvalidRequest(
            "redirect_uris is required".into(),
        ));
    }
    if req.response_types.is_empty()
        || !req
            .response_types
            .iter()
            .all(|t| SUPPORTED_RESPONSE_TYPES.contains(&t.as_str()))
    {
        return Err(OAuthError::InvalidRequest(
            "response_types is required and must include only 'code'".into(),
        ));
    }

    for uri in &req.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err(OAuthError::InvalidRequest(
                "redirect_uris must be loopback (localhost/127.0.0.1) or mcp:// URLs".into(),
            ));
        }
    }

    let client_id = TokenStore::generate_token();
    let grants = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into()]);
    if !grants
        .iter()
        .all(|g| SUPPORTED_GRANT_TYPES.contains(&g.as_str()))
    {
        return Err(OAuthError::InvalidRequest(
            "grant_types must include only supported grant types".into(),
        ));
    }
    if !grants.iter().any(|g| g == "authorization_code") {
        return Err(OAuthError::InvalidRequest(
            "grant_types must include 'authorization_code'".into(),
        ));
    }
    let scopes: Vec<String> = req
        .scope
        .unwrap_or_else(|| "api".into())
        .split_whitespace()
        .map(String::from)
        .collect();

    // Validate scopes against allowed whitelist
    if scopes.is_empty() {
        return Err(OAuthError::InvalidScope);
    }
    for scope in &scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(OAuthError::InvalidScope);
        }
    }

    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_post".into());
    if !SUPPORTED_AUTH_METHODS.contains(&token_endpoint_auth_method.as_str()) {
        return Err(OAuthError::InvalidRequest(
            "token_endpoint_auth_method must be 'none' or 'client_secret_post'".into(),
        ));
    }

    let (client_secret, secret_hash) = if token_endpoint_auth_method == "none" {
        (None, None)
    } else {
        let secret = TokenStore::generate_token();
        let secret_hash = hash_secret(&secret);
        (Some(secret), Some(secret_hash))
    };

    sqlx::query(
        r#"
        INSERT INTO mcp_oauth.clients
            (id, name, secret_hash, redirect_uris, grants, scopes,
            client_uri, software_id, software_version)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&client_id)
    .bind(&req.client_name)
    .bind(&secret_hash)
    .bind(&req.redirect_uris)
    .bind(&grants)
    .bind(&scopes)
    .bind(&req.client_uri)
    .bind(&req.software_id)
    .bind(&req.software_version)
    .execute(state.store.pool())
    .await
    .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    Ok(Json(RegisterResponse {
        client_id,
        client_secret,
        client_name: req.client_name,
        redirect_uris: req.redirect_uris,
        grant_types: grants,
        scope: scopes.join(" "),
        token_endpoint_auth_method,
        client_uri: req.client_uri,
        software_id: req.software_id,
        software_version: req.software_version,
    }))
}

// ============================================================================
// Authorization Endpoint (downstream)
// ============================================================================

#[derive(Debug, Deserialize)]
struct AuthorizeRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
}

async fn authorize(
    State(state): State<Arc<OAuthState>>,
    Query(req): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    debug!(
        event = "oauth_authorize",
        client_id = %req.client_id,
        "OAuth authorize request"
    );

    if req.response_type != "code" {
        return Err(OAuthError::UnsupportedResponseType);
    }

    let client = state
        .store
        .get_client(&req.client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or(OAuthError::InvalidClient)?;

    if !client.allows_redirect_uri(&req.redirect_uri) {
        return Err(OAuthError::InvalidRequest(
            "redirect_uri not registered for this client".into(),
        ));
    }

    // Validate requested scopes.
    // - Must be non-empty (or defaults to "api" if omitted)
    // - Must be within server allowlist and client-registered scopes
    let requested_scope = req.scope.clone().unwrap_or_else(|| "api".into());
    let requested_scopes: Vec<&str> = requested_scope.split_whitespace().collect();
    let requested_scopes = if requested_scopes.is_empty() {
        vec!["api"]
    } else {
        requested_scopes
    };
    for scope in &requested_scopes {
        if !ALLOWED_SCOPES.contains(scope) || !client.scopes.iter().any(|s| s == scope) {
            return Err(OAuthError::InvalidScope);
        }
    }

    let code_challenge = req
        .code_challenge
        .ok_or(OAuthError::InvalidRequest("code_challenge required".into()))?;

    // OAuth 2.1 requires S256; plain is insecure and not allowed
    let code_challenge_method = match req.code_challenge_method.as_deref() {
        Some("S256") | None => PkceMethod::S256,
        _ => {
            return Err(OAuthError::InvalidRequest(
                "code_challenge_method must be S256 (plain is not supported)".into(),
            ));
        }
    };

    // Create a pending authorization request so we can complete the upstream callback.
    let upstream_state = TokenStore::generate_token();
    let upstream_code_verifier = TokenStore::generate_token();
    let upstream_code_challenge = pkce_s256_challenge(&upstream_code_verifier);

    let auth_request = AuthRequest {
        id: upstream_state.clone(),
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: requested_scopes.join(" "),
        client_state: req.state.clone(),
        code_challenge,
        code_challenge_method,
        upstream_code_verifier,
        expires_at: TokenStore::code_expiry(),
        created_at: OffsetDateTime::now_utc(),
    };

    state
        .store
        .save_auth_request(&auth_request)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    let upstream_redirect_uri = format!("{}/callback", state.server_host.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&format!(
        "{}/oauth2/authorize",
        state.upstream_oauth_redirect_base_url.trim_end_matches('/')
    ))
    .map_err(|_| OAuthError::ServerError("Invalid upstream_oauth_redirect_base_url".into()))?;

    url.query_pairs_mut()
        .append_pair("client_id", &state.upstream_client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &upstream_redirect_uri)
        .append_pair("code_challenge", &upstream_code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &upstream_state)
        .append_pair("scope", "openid profile email");

    Ok(Redirect::temporary(url.as_str()).into_response())
}

// ============================================================================
// Callback Endpoint (upstream)
// ============================================================================

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Response from the upstream OAuth token endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct UpstreamTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

async fn callback(
    State(state): State<Arc<OAuthState>>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, OAuthError> {
    debug!(
        event = "oauth_callback",
        has_code = q.code.is_some(),
        has_error = q.error.is_some(),
        "OAuth callback from upstream"
    );

    let upstream_state = q
        .state
        .ok_or_else(|| OAuthError::InvalidRequest("state required".into()))?;

    let auth_request = state
        .store
        .consume_auth_request(&upstream_state)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or(OAuthError::InvalidGrant(
            "Invalid or expired authorization request".into(),
        ))?;

    // Upstream error -> redirect back to downstream client.
    if let Some(error) = q.error {
        return redirect_with_error(
            &auth_request.redirect_uri,
            auth_request.client_state.as_deref(),
            &error,
            q.error_description.as_deref(),
        );
    }

    let code = q
        .code
        .ok_or_else(|| OAuthError::InvalidRequest("code required".into()))?;

    let upstream_redirect_uri = format!("{}/callback", state.server_host.trim_end_matches('/'));

    let token_body = match exchange_upstream_token(
        &state.http,
        &state.upstream_api_base_url,
        vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", upstream_redirect_uri.as_str()),
            ("client_id", state.upstream_client_id.as_str()),
            (
                "code_verifier",
                auth_request.upstream_code_verifier.as_str(),
            ),
        ],
        &state.circuit_breaker,
    )
    .await
    {
        Ok(body) => body,
        Err(_) => {
            return redirect_with_error(
                &auth_request.redirect_uri,
                auth_request.client_state.as_deref(),
                "server_error",
                Some("Authorization failed. Please try again."),
            );
        }
    };

    // Log the granted scope for debugging
    if let Some(ref granted_scope) = token_body.scope {
        debug!(
            scope = %granted_scope,
            requested_scope = "openid profile email",
            "Upstream token granted"
        );
    }

    // Validate token type per OAuth 2.0 spec
    if !token_body.token_type.eq_ignore_ascii_case("bearer") {
        return redirect_with_error(
            &auth_request.redirect_uri,
            auth_request.client_state.as_deref(),
            "server_error",
            Some(&format!(
                "Unsupported upstream token_type: {}",
                token_body.token_type
            )),
        );
    }

    let upstream_expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(token_body.expires_in.max(0));

    let user_id = fetch_user_id(
        &state.upstream_api_base_url,
        &token_body.access_token,
        &state.circuit_breaker,
    )
    .await
    .ok_or_else(|| OAuthError::ServerError("Failed to fetch user id".into()))?;

    // Enforce per-user consent before issuing a downstream authorization code redirect.
    let approved = state
        .store
        .is_client_approved(user_id, &auth_request.client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    // Create downstream authorization code carrying upstream tokens.
    let downstream_code = TokenStore::generate_code();
    let auth_code = AuthorizationCode {
        code: downstream_code.clone(),
        client_id: auth_request.client_id.clone(),
        user_id,
        redirect_uri: auth_request.redirect_uri.clone(),
        scope: auth_request.scope.clone(),
        code_challenge: Some(auth_request.code_challenge),
        code_challenge_method: Some(auth_request.code_challenge_method),
        expires_at: TokenStore::code_expiry(),
        created_at: OffsetDateTime::now_utc(),
        upstream_access_token: token_body.access_token,
        upstream_refresh_token: token_body.refresh_token,
        upstream_expires_at,
    };

    state
        .store
        .save_authorization_code(&auth_code)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    if approved {
        let mut redirect_url = reqwest::Url::parse(&auth_request.redirect_uri)
            .map_err(|_| OAuthError::InvalidRequest("Invalid redirect_uri".into()))?;
        redirect_url
            .query_pairs_mut()
            .append_pair("code", &downstream_code);
        if let Some(client_state) = auth_request.client_state {
            redirect_url
                .query_pairs_mut()
                .append_pair("state", &client_state);
        }

        debug!(
            event = "oauth_callback_complete",
            user_id = %user_id,
            client_id = %auth_request.client_id,
            "OAuth authorization code issued (pre-approved)"
        );

        return Ok(Redirect::temporary(redirect_url.as_str()).into_response());
    }

    // Not yet approved: create a pending consent record and redirect to a local consent page.
    let consent_id = TokenStore::generate_token();
    let csrf_token = TokenStore::generate_token();
    let consent_expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let consent = crate::oauth::store::PendingConsent {
        id: consent_id.clone(),
        user_id,
        client_id: auth_request.client_id.clone(),
        authorization_code: downstream_code.clone(),
        redirect_uri: auth_request.redirect_uri.clone(),
        client_state: auth_request.client_state.clone(),
        scope: auth_request.scope.clone(),
        csrf_token,
        expires_at: consent_expires_at,
        created_at: OffsetDateTime::now_utc(),
    };
    state
        .store
        .save_pending_consent(&consent)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    let server_host = state.server_host.trim_end_matches('/');
    let consent_url = format!("{server_host}/consent?token={consent_id}");

    debug!(
        event = "oauth_callback_consent_required",
        user_id = %user_id,
        client_id = %auth_request.client_id,
        "Redirecting to consent page"
    );

    Ok(Redirect::temporary(&consent_url).into_response())
}

// ============================================================================
// Token Endpoint (downstream)
// ============================================================================

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

fn no_store_json<T: Serialize>(value: T) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    (headers, Json(value)).into_response()
}

async fn token(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<TokenRequest>,
) -> Result<Response, OAuthError> {
    debug!(
        event = "oauth_token",
        grant_type = %req.grant_type,
        "Token exchange request"
    );

    match req.grant_type.as_str() {
        "authorization_code" => {
            let code = req
                .code
                .ok_or_else(|| OAuthError::InvalidRequest("code required".into()))?;
            let redirect_uri = req
                .redirect_uri
                .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri required".into()))?;
            let code_verifier = req
                .code_verifier
                .ok_or_else(|| OAuthError::InvalidRequest("code_verifier required".into()))?;

            let auth_code = state
                .store
                .consume_authorization_code(&code)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?
                .ok_or(OAuthError::InvalidGrant("Invalid or expired code".into()))?;

            // Q1 fix: Use extracted validation helper
            // Validate client (and optional client_secret)
            if let Some(client_id) = req.client_id.as_deref()
                && client_id != auth_code.client_id
            {
                return Err(OAuthError::InvalidClient);
            }

            let _client = validate_client_credentials(
                &state.store,
                &auth_code.client_id,
                req.client_secret.as_deref(),
            )
            .await?;

            if auth_code.redirect_uri != redirect_uri {
                return Err(OAuthError::InvalidGrant("redirect_uri mismatch".into()));
            }

            if let Some(challenge) = &auth_code.code_challenge
                && !TokenStore::verify_pkce(
                    &code_verifier,
                    challenge,
                    auth_code.code_challenge_method,
                )
            {
                return Err(OAuthError::InvalidGrant("PKCE verification failed".into()));
            }

            // Mint MCP access token (JWT signed by this server)
            let (mcp_access_token, mcp_expires_in) = state
                .jwt_signer
                .sign_access_token(
                    auth_code.user_id,
                    &auth_code.client_id,
                    &auth_code.scope,
                    None, // email not available here
                    None, // name not available here
                )
                .map_err(|e| OAuthError::ServerError(format!("Failed to sign token: {}", e)))?;

            // Generate MCP refresh token and store upstream tokens server-side
            let mcp_refresh_token = TokenStore::generate_token();
            let refresh_token = RefreshToken {
                token_hash: TokenStore::hash_refresh_token(&mcp_refresh_token),
                client_id: auth_code.client_id.clone(),
                user_id: auth_code.user_id,
                scope: auth_code.scope.clone(),
                expires_at: Some(TokenStore::token_expiry(REFRESH_TOKEN_TTL_HOURS)),
                created_at: OffsetDateTime::now_utc(),
                // Store upstream tokens server-side (never exposed to clients)
                upstream_access_token: auth_code.upstream_access_token,
                upstream_refresh_token: auth_code.upstream_refresh_token,
                upstream_expires_at: auth_code.upstream_expires_at,
            };
            state
                .store
                .save_refresh_token(&refresh_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            debug!(
                event = "oauth_token_complete",
                grant_type = "authorization_code",
                client_id = %auth_code.client_id,
                user_id = %auth_code.user_id,
                "Token exchange completed (MCP token issued)"
            );

            Ok(no_store_json(TokenResponse {
                access_token: mcp_access_token,
                token_type: "Bearer".into(),
                expires_in: mcp_expires_in,
                refresh_token: Some(mcp_refresh_token),
                scope: auth_code.scope,
            }))
        }
        "refresh_token" => {
            let refresh_token_str = req
                .refresh_token
                .ok_or_else(|| OAuthError::InvalidRequest("refresh_token required".into()))?;

            let refresh_token = match state.store.get_refresh_token(&refresh_token_str).await {
                Ok(Some(token)) => token,
                Ok(None) => {
                    debug!(
                        event = "oauth_refresh_token_not_found",
                        "Refresh token not found"
                    );
                    return Err(OAuthError::InvalidGrant(
                        "Invalid or expired refresh token".into(),
                    ));
                }
                Err(e) => {
                    debug!(
                        event = "oauth_refresh_token_db_error",
                        error = %e,
                        "Database error looking up refresh token"
                    );
                    return Err(OAuthError::ServerError(e.to_string()));
                }
            };

            // Q1 fix: Use extracted validation helper
            // Validate client (and optional client_secret)
            if let Some(client_id) = req.client_id.as_deref()
                && client_id != refresh_token.client_id
            {
                return Err(OAuthError::InvalidClient);
            }

            let _client = validate_client_credentials(
                &state.store,
                &refresh_token.client_id,
                req.client_secret.as_deref(),
            )
            .await?;

            // Get the stored upstream refresh token for server-side refresh
            let upstream_refresh_token =
                refresh_token
                    .upstream_refresh_token
                    .as_ref()
                    .ok_or_else(|| {
                        OAuthError::ServerError("No upstream refresh token stored".into())
                    })?;

            // Refresh upstream tokens server-side (using stored upstream refresh token)
            let token_body = exchange_upstream_token(
                &state.http,
                &state.upstream_api_base_url,
                vec![
                    ("grant_type", "refresh_token"),
                    ("refresh_token", upstream_refresh_token.as_str()),
                    ("client_id", state.upstream_client_id.as_str()),
                ],
                &state.circuit_breaker,
            )
            .await?;

            // Log the granted scope for debugging
            if let Some(ref granted_scope) = token_body.scope {
                debug!(scope = %granted_scope, "Upstream token refreshed");
            }

            let new_upstream_expires_at =
                OffsetDateTime::now_utc() + Duration::seconds(token_body.expires_in.max(0));

            // Mint new MCP access token
            let (new_mcp_access_token, mcp_expires_in) = state
                .jwt_signer
                .sign_access_token(
                    refresh_token.user_id,
                    &refresh_token.client_id,
                    &refresh_token.scope,
                    None,
                    None,
                )
                .map_err(|e| OAuthError::ServerError(format!("Failed to sign token: {}", e)))?;

            // Generate new MCP refresh token (rotation)
            let new_mcp_refresh_token = TokenStore::generate_token();

            // Update stored upstream tokens and rotate MCP refresh token
            let updated = state
                .store
                .update_refresh_token(
                    &refresh_token_str,
                    &new_mcp_refresh_token,
                    Some(TokenStore::token_expiry(REFRESH_TOKEN_TTL_HOURS)),
                    &token_body.access_token,
                    token_body.refresh_token.as_deref(),
                    new_upstream_expires_at,
                )
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            if !updated {
                return Err(OAuthError::InvalidGrant("refresh_token not found".into()));
            }

            debug!(
                event = "oauth_token_complete",
                grant_type = "refresh_token",
                client_id = %refresh_token.client_id,
                user_id = %refresh_token.user_id,
                "Token refresh completed (MCP token issued)"
            );

            Ok(no_store_json(TokenResponse {
                access_token: new_mcp_access_token,
                token_type: "Bearer".into(),
                expires_in: mcp_expires_in,
                refresh_token: Some(new_mcp_refresh_token),
                scope: refresh_token.scope,
            }))
        }
        _ => Err(OAuthError::UnsupportedGrantType),
    }
}

// ============================================================================
// Token Revocation Endpoint (RFC 7009)
// ============================================================================

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token: String,
    /// Kept for RFC 7009 compatibility (clients may send this)
    #[serde(default)]
    #[allow(dead_code)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Token revocation endpoint per RFC 7009.
///
/// Revokes refresh tokens. Access tokens are JWTs issued by this server, so they
/// cannot be server-side revoked and remain valid until expiry.
/// Per the spec, this endpoint always returns 200 OK even if the token was
/// invalid or already revoked.
async fn revoke(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    // Validate client credentials if provided
    if let Some(client_id) = req.client_id.as_deref() {
        validate_client_credentials(&state.store, client_id, req.client_secret.as_deref()).await?;
    }

    // Try to revoke as refresh token (access tokens are JWTs that can't be revoked)
    state.store.revoke_refresh_token(&req.token).await.ok();

    // RFC 7009: Always return 200 OK regardless of whether token existed
    Ok(StatusCode::OK)
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug)]
pub(crate) enum OAuthError {
    InvalidRequest(String),
    InvalidClient,
    InvalidGrant(String),
    InvalidScope,
    UnsupportedResponseType,
    UnsupportedGrantType,
    ServerError(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            OAuthError::InvalidRequest(desc) => (StatusCode::BAD_REQUEST, "invalid_request", desc),
            OAuthError::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed".into(),
            ),
            OAuthError::InvalidGrant(desc) => (StatusCode::BAD_REQUEST, "invalid_grant", desc),
            OAuthError::InvalidScope => (
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Requested scope is invalid or not allowed".into(),
            ),
            OAuthError::UnsupportedResponseType => (
                StatusCode::BAD_REQUEST,
                "unsupported_response_type",
                "Only 'code' response type is supported".into(),
            ),
            OAuthError::UnsupportedGrantType => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Only 'authorization_code' and 'refresh_token' grants are supported".into(),
            ),
            OAuthError::ServerError(desc) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error", desc)
            }
        };

        let body = serde_json::json!({
            "error": error,
            "error_description": description,
        });

        (status, Json(body)).into_response()
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Q1 fix: Extract duplicate client validation logic
async fn validate_client_credentials(
    store: &TokenStore,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<crate::oauth::store::Client, OAuthError> {
    let client = store
        .get_client(client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or(OAuthError::InvalidClient)?;

    // If client has a secret, verify it
    if let Some(ref secret_hash) = client.secret_hash {
        let provided_secret = client_secret.ok_or(OAuthError::InvalidClient)?;
        if !verify_secret(provided_secret, secret_hash) {
            return Err(OAuthError::InvalidClient);
        }
    }

    Ok(client)
}

/// Exchange tokens with the upstream OAuth server.
/// Used for both authorization code exchange and refresh token flows.
pub async fn exchange_upstream_token(
    http_client: &reqwest::Client,
    upstream_api_base_url: &str,
    params: Vec<(&str, &str)>,
    circuit_breaker: &Arc<OAuthCircuitBreaker>,
) -> Result<UpstreamTokenResponse, OAuthError> {
    // Check circuit breaker before making request
    if !circuit_breaker.is_call_permitted() {
        tracing::warn!("Circuit breaker open - rejecting upstream token request");
        return Err(OAuthError::ServerError(
            "Upstream service temporarily unavailable - please try again later".into(),
        ));
    }

    let token_url = format!(
        "{}/oauth2/token",
        upstream_api_base_url.trim_end_matches('/')
    );

    // Execute request
    let res = match http_client.post(token_url).form(&params).send().await {
        Ok(response) => {
            circuit_breaker.record_success();
            response
        }
        Err(e) => {
            circuit_breaker.record_failure();
            return Err(OAuthError::ServerError(format!(
                "Upstream request failed: {}",
                e
            )));
        }
    };

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        tracing::error!(
            status = %status,
            body = %body,
            "Upstream token exchange failed"
        );
        if status.is_client_error() {
            return Err(OAuthError::InvalidGrant(
                "Token exchange failed. Please re-authenticate.".into(),
            ));
        }
        return Err(OAuthError::ServerError(
            "Upstream service error. Please try again later.".into(),
        ));
    }

    res.json()
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    if let Ok(url) = reqwest::Url::parse(uri) {
        match url.scheme() {
            // Loopback redirect URIs (RFC 8252) – allow http/https on localhost.
            "http" | "https" => {
                let host = url.host_str().unwrap_or("");
                host == "localhost" || host == "127.0.0.1"
            }
            // Native app custom scheme used by some MCP clients.
            "mcp" => true,
            _ => false,
        }
    } else {
        false
    }
}

fn hash_secret(secret: &str) -> String {
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(secret.as_bytes(), &salt)
        .expect("Failed to hash secret")
        .to_string()
}

fn verify_secret(secret: &str, hash: &str) -> bool {
    use argon2::{
        Argon2,
        password_hash::{PasswordHash, PasswordVerifier},
    };
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_ok()
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(code_verifier.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
}

fn redirect_with_error(
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: Option<&str>,
) -> Result<Response, OAuthError> {
    let mut redirect_url = reqwest::Url::parse(redirect_uri)
        .map_err(|_| OAuthError::InvalidRequest("Invalid redirect_uri".into()))?;
    redirect_url.query_pairs_mut().append_pair("error", error);
    if let Some(desc) = description {
        let truncated = if desc.len() > 500 { &desc[..500] } else { desc };
        redirect_url
            .query_pairs_mut()
            .append_pair("error_description", truncated);
    }
    if let Some(state) = state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }
    // Use 303 See Other to ensure POST requests (e.g., consent deny) are
    // converted to GET when redirecting to the client's callback.
    Ok(Redirect::to(redirect_url.as_str()).into_response())
}

async fn fetch_user_id(
    api_base_url: &str,
    access_token: &str,
    circuit_breaker: &Arc<OAuthCircuitBreaker>,
) -> Option<Uuid> {
    // Check circuit breaker before making request
    if !circuit_breaker.is_call_permitted() {
        tracing::warn!("Circuit breaker open - rejecting upstream user info request");
        return None;
    }

    // Build HTTP client with bearer token for the generated API client
    let mut headers = reqwest::header::HeaderMap::new();
    let auth_value =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", access_token)).ok()?;
    headers.insert(reqwest::header::AUTHORIZATION, auth_value);

    let http_client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let api_client = seren::Client::new_with_client(api_base_url, http_client);

    match api_client.get_current_user().await {
        Ok(response) => {
            circuit_breaker.record_success();
            Some(response.into_inner().data.id)
        }
        Err(_) => {
            circuit_breaker.record_failure();
            None
        }
    }
}

// ============================================================================
// Router
// ============================================================================

/// Cleanup expired tokens endpoint.
///
/// This endpoint triggers cleanup of expired authorization codes, access tokens,
/// and refresh tokens. It can be called periodically by a cron job or health check.
/// Uses batch limits to prevent table locks.
async fn cleanup(
    State(state): State<Arc<OAuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, OAuthError> {
    let Some(expected_token) = std::env::var("CLEANUP_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        // Endpoint disabled unless explicitly configured.
        return Ok(StatusCode::NOT_FOUND);
    };

    let provided_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, token) = v.split_once(' ')?;
            if scheme.eq_ignore_ascii_case("bearer") {
                Some(token.trim())
            } else {
                None
            }
        })
        .filter(|v| !v.is_empty());

    if provided_token != Some(expected_token.as_str()) {
        return Ok(StatusCode::UNAUTHORIZED);
    }

    let deleted = state
        .store
        .cleanup_expired(Some(1000))
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    tracing::info!(deleted_count = deleted, "Cleaned up expired OAuth records");
    Ok(StatusCode::OK)
}

// ============================================================================
// Consent Endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
struct ConsentQuery {
    token: String,
}

async fn consent_page(
    State(state): State<Arc<OAuthState>>,
    Query(q): Query<ConsentQuery>,
) -> Result<Response, OAuthError> {
    let consent = state
        .store
        .get_pending_consent(&q.token)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired consent request".into()))?;

    let client = state
        .store
        .get_client(&consent.client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or(OAuthError::InvalidClient)?;

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Approve MCP Client</title>
    <style>
        body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e6e8ee; margin: 0; }}
        .wrap {{ max-width: 720px; margin: 40px auto; padding: 0 16px; }}
        .card {{ background: #11182a; border: 1px solid #23304a; border-radius: 14px; padding: 22px; }}
        .title {{ font-size: 20px; font-weight: 700; margin: 0 0 8px; }}
        .muted {{ color: #a7b0c2; margin: 0 0 18px; }}
        .row {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 18px; }}
        button {{ border: 0; border-radius: 10px; padding: 12px 14px; font-weight: 700; cursor: pointer; }}
        .approve {{ background: #2d6cdf; color: white; }}
        .deny {{ background: #2a3246; color: #e6e8ee; }}
        .box {{ background: #0c1220; border: 1px solid #23304a; border-radius: 10px; padding: 12px; margin-top: 12px; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            <p class="title">Allow <code>{client_name}</code> to access your Seren account?</p>
            <p class="muted">This will let the MCP client manage your SerenDB projects and run SQL using your account permissions.</p>
            <div class="box">
                <div><strong>Client</strong>: {client_name}</div>
                <div><strong>Requested scope</strong>: <code>{scope}</code></div>
            </div>
            <div class="row">
                <form method="post" action="{consent_url}">
                    <input type="hidden" name="token" value="{token}">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <input type="hidden" name="action" value="approve">
                    <button class="approve" type="submit">Approve</button>
                </form>
                <form method="post" action="{consent_url}">
                    <input type="hidden" name="token" value="{token}">
                    <input type="hidden" name="csrf_token" value="{csrf_token}">
                    <input type="hidden" name="action" value="deny">
                    <button class="deny" type="submit">Deny</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"#,
        client_name = html_escape(&client.name),
        scope = html_escape(&consent.scope),
        token = html_escape(&q.token),
        csrf_token = html_escape(&consent.csrf_token),
        consent_url = html_escape(&format!(
            "{}/consent",
            state.server_host.trim_end_matches('/')
        ))
    );

    let server_host = state.server_host.trim_end_matches('/');
    // Include both with and without trailing slash to handle browser extensions
    // that may normalize URLs differently in CSP directives
    let csp = format!(
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {} {}/; base-uri 'none'; frame-ancestors 'none'",
        server_host, server_host
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::try_from(csp).unwrap_or_else(|_| {
            HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        }),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );

    Ok((headers, Html(html)).into_response())
}

#[derive(Debug, Deserialize)]
struct ConsentForm {
    token: String,
    csrf_token: String,
    action: String,
}

async fn consent_submit(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<ConsentForm>,
) -> Result<Response, OAuthError> {
    debug!(
        event = "oauth_consent_submit",
        action = %req.action,
        "Consent form submitted"
    );

    // Fetch consent without consuming so invalid CSRF attempts don't destroy the consent record.
    let consent = state
        .store
        .get_pending_consent(&req.token)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired consent request".into()))?;

    // Verify CSRF token (constant-time comparison to prevent timing attacks)
    use subtle::ConstantTimeEq;
    if req
        .csrf_token
        .as_bytes()
        .ct_eq(consent.csrf_token.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(OAuthError::InvalidRequest("Invalid CSRF token".into()));
    }

    // Consume after CSRF verification to enforce one-time use.
    let consent = state
        .store
        .consume_pending_consent(&req.token)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or_else(|| OAuthError::InvalidGrant("Invalid or expired consent request".into()))?;

    match req.action.as_str() {
        "approve" => {
            state
                .store
                .approve_client(consent.user_id, &consent.client_id)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            let mut redirect_url = reqwest::Url::parse(&consent.redirect_uri)
                .map_err(|_| OAuthError::InvalidRequest("Invalid redirect_uri".into()))?;
            redirect_url
                .query_pairs_mut()
                .append_pair("code", &consent.authorization_code);
            if let Some(state_param) = consent.client_state.as_deref() {
                redirect_url
                    .query_pairs_mut()
                    .append_pair("state", state_param);
            }

            debug!(
                event = "oauth_consent_approved",
                user_id = %consent.user_id,
                client_id = %consent.client_id,
                "User approved OAuth consent"
            );

            // Use 303 See Other to convert POST to GET for the callback redirect.
            // 307 would preserve POST method, which callback endpoints don't expect.
            Ok(Redirect::to(redirect_url.as_str()).into_response())
        }
        "deny" => {
            debug!(
                event = "oauth_consent_denied",
                user_id = %consent.user_id,
                client_id = %consent.client_id,
                "User denied OAuth consent"
            );

            state
                .store
                .delete_authorization_code(&consent.authorization_code)
                .await
                .ok();
            redirect_with_error(
                &consent.redirect_uri,
                consent.client_state.as_deref(),
                "access_denied",
                Some("User denied access"),
            )
        }
        _ => Err(OAuthError::InvalidRequest("Invalid action".into())),
    }
}

fn html_escape(input: &str) -> String {
    html_escape::encode_safe(input).to_string()
}

pub fn oauth_router(state: Arc<OAuthState>) -> Router {
    // Rate limiter for /register: 10 requests per minute per IP
    let register_governor_conf = GovernorConfigBuilder::default()
        .per_second(6) // refill rate: ~10 per minute
        .burst_size(10)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to create rate limiter config");
    let register_limiter = GovernorLayer::new(register_governor_conf);

    // Rate limiter for /consent POST: 5 requests per minute per IP (S2 fix)
    // Prevents CSRF token enumeration attacks
    let consent_governor_conf = GovernorConfigBuilder::default()
        .per_second(2) // refill rate: ~5 per minute
        .burst_size(5)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to create consent rate limiter config");
    let consent_limiter = GovernorLayer::new(consent_governor_conf);

    // Rate limiter for /token: 20 requests per minute per IP (S6 fix)
    // Prevents brute force attacks on authorization codes
    let token_governor_conf = GovernorConfigBuilder::default()
        .per_second(10) // refill rate: ~20 per minute
        .burst_size(20)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Failed to create token rate limiter config");
    let token_limiter = GovernorLayer::new(token_governor_conf);

    // Separate router for rate-limited /register endpoint
    let register_router = Router::new()
        .route("/register", post(register))
        .layer(register_limiter)
        .with_state(state.clone());

    // Separate router for rate-limited /consent POST endpoint
    let consent_post_router = Router::new()
        .route("/consent", post(consent_submit))
        .layer(consent_limiter)
        .with_state(state.clone());

    // Separate router for rate-limited /token endpoint
    let token_router = Router::new()
        .route("/token", post(token))
        .layer(token_limiter)
        .with_state(state.clone());

    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback))
        .route("/consent", get(consent_page)) // GET not rate-limited
        .route("/revoke", post(revoke))
        .route("/_cleanup", post(cleanup))
        .with_state(state)
        .merge(register_router)
        .merge(consent_post_router)
        .merge(token_router)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;
    use wiremock::matchers::{body_string_contains, header as wm_header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn integration_tests_enabled() -> bool {
        std::env::var("SEREN_MCP_INTEGRATION_TESTS")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .is_some_and(|v| v == "1" || v == "true" || v == "yes" || v == "on")
    }

    fn find_query_param(url: &reqwest::Url, key: &str) -> Option<String> {
        url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    }

    #[tokio::test]
    async fn oauth_full_flow_consent_token_and_refresh() {
        if !integration_tests_enabled() {
            eprintln!(
                "skipping oauth integration test; set SEREN_MCP_INTEGRATION_TESTS=1 to enable"
            );
            return;
        }

        use testcontainers::runners::AsyncRunner;
        use testcontainers_modules::postgres::Postgres;

        // Docker container must stay in scope for the duration of the test.
        let container = Postgres::default().start().await.unwrap();
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let database_url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);

        let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
        let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let migrator = sqlx::migrate::Migrator::new(migrations_dir).await.unwrap();
        migrator.run(&pool).await.unwrap();

        let store = TokenStore::new(pool);
        let upstream = MockServer::start().await;

        let server_host = "http://mcp.test".to_string();
        let upstream_client_id = "upstream-client-id".to_string();

        // Upstream token exchange for authorization_code
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .and(body_string_contains("client_id=upstream-client-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "up_access_1",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "up_refresh_1",
                "scope": "openid profile email",
            })))
            .mount(&upstream)
            .await;

        // Upstream user info
        Mock::given(method("GET"))
            .and(path("/auth/me"))
            .and(wm_header("authorization", "Bearer up_access_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "id": "user-123" }
            })))
            .mount(&upstream)
            .await;

        // Upstream token refresh
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=up_refresh_1"))
            .and(body_string_contains("client_id=upstream-client-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "up_access_2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "up_refresh_2",
                "scope": "openid profile email",
            })))
            .mount(&upstream)
            .await;

        let jwt_signer = Arc::new(crate::oauth::jwt::McpJwtSigner::new(
            b"test-secret-key-at-least-32-bytes!!",
            &server_host,
        ));
        let state = Arc::new(OAuthState {
            store: store.clone(),
            http: reqwest::Client::new(),
            server_host: server_host.clone(),
            upstream_client_id: upstream_client_id.clone(),
            upstream_api_base_url: upstream.uri(),
            upstream_oauth_redirect_base_url: upstream.uri(),
            circuit_breaker: crate::oauth::circuit_breaker::create_oauth_circuit_breaker(),
            jwt_signer,
        });
        let app = oauth_router(state.clone());

        // 1) Register downstream client (public client, PKCE only)
        let register_req = serde_json::json!({
            "client_name": "test-client",
            "redirect_uris": ["http://localhost/callback"],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "api",
            "token_endpoint_auth_method": "none",
        });
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(register_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let reg: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let client_id = reg
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // 2) Start authorization request (downstream) -> should redirect to upstream authorize
        let downstream_state = "client-state-xyz";
        let downstream_code_verifier = "downstream-verifier-123";
        let downstream_code_challenge = pkce_s256_challenge(downstream_code_verifier);

        let mut authorize_url = reqwest::Url::parse("http://localhost/authorize").unwrap();
        authorize_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "http://localhost/callback")
            .append_pair("scope", "api")
            .append_pair("state", downstream_state)
            .append_pair("code_challenge", &downstream_code_challenge)
            .append_pair("code_challenge_method", "S256");
        let authorize_uri = format!(
            "{}?{}",
            authorize_url.path(),
            authorize_url.query().unwrap()
        );

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&authorize_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = res
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let redirect = reqwest::Url::parse(&location).unwrap();
        let upstream_state = find_query_param(&redirect, "state").unwrap();
        let upstream_redirect_uri = find_query_param(&redirect, "redirect_uri").unwrap();
        assert_eq!(upstream_redirect_uri, format!("{}/callback", server_host));

        // Verify authorize created an auth_request with a verifier matching the upstream challenge.
        let row: (String,) = sqlx::query_as(
            r#"
            SELECT upstream_code_verifier
            FROM mcp_oauth.auth_requests
            WHERE id = $1
            "#,
        )
        .bind(&upstream_state)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let upstream_code_verifier = row.0;
        let upstream_code_challenge = find_query_param(&redirect, "code_challenge").unwrap();
        assert_eq!(
            upstream_code_challenge,
            pkce_s256_challenge(&upstream_code_verifier)
        );

        // 3) Callback from upstream -> should require consent (not yet approved)
        let mut callback_url = reqwest::Url::parse("http://localhost/callback").unwrap();
        callback_url
            .query_pairs_mut()
            .append_pair("code", "upstream-auth-code")
            .append_pair("state", &upstream_state);
        let callback_uri = format!("{}?{}", callback_url.path(), callback_url.query().unwrap());

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&callback_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        let consent_location = res
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let consent_redirect = reqwest::Url::parse(&consent_location).unwrap();
        assert_eq!(consent_redirect.path(), "/consent");
        let consent_token = find_query_param(&consent_redirect, "token").unwrap();

        // 4) Approve consent -> should redirect back to downstream redirect_uri with code+state
        let consent_body = "token=".to_string() + &consent_token + "&action=approve";
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/consent")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(consent_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        let downstream_location = res
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let downstream_redirect = reqwest::Url::parse(&downstream_location).unwrap();
        assert_eq!(downstream_redirect.path(), "/callback");
        let downstream_code = find_query_param(&downstream_redirect, "code").unwrap();
        assert_eq!(
            find_query_param(&downstream_redirect, "state").as_deref(),
            Some(downstream_state)
        );

        // 5) Token exchange (downstream) -> should return upstream access token and persist it
        let token_body = format!(
            "grant_type=authorization_code&code={}&redirect_uri=http://localhost/callback&client_id={}&code_verifier={}",
            downstream_code, client_id, downstream_code_verifier
        );
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(token_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let token_res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            token_res.get("access_token").and_then(|v| v.as_str()),
            Some("up_access_1")
        );
        assert_eq!(
            token_res.get("refresh_token").and_then(|v| v.as_str()),
            Some("up_refresh_1")
        );
        assert_eq!(
            token_res.get("token_type").and_then(|v| v.as_str()),
            Some("Bearer")
        );

        // 6) Refresh token (downstream) -> should call upstream refresh and return new tokens
        let refresh_body = format!(
            "grant_type=refresh_token&refresh_token=up_refresh_1&client_id={}",
            client_id
        );
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(refresh_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let refresh_res: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            refresh_res.get("access_token").and_then(|v| v.as_str()),
            Some("up_access_2")
        );
        assert_eq!(
            refresh_res.get("refresh_token").and_then(|v| v.as_str()),
            Some("up_refresh_2")
        );
        assert_eq!(
            refresh_res.get("token_type").and_then(|v| v.as_str()),
            Some("Bearer")
        );
    }
}
