//! OAuth2 HTTP routes for hosted MCP server mode.
//!
//! Implements OAuth 2.1 endpoints per MCP specification:
//! - `/.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
//! - `/authorize` - Authorization endpoint (downstream: MCP client -> this server)
//! - `/callback` - Callback endpoint (upstream: SerenCore -> this server)
//! - `/token` - Token endpoint
//! - `/register` - Dynamic client registration (RFC 7591)
//!
//! This server acts as the OAuth authorization server for MCP clients, but delegates
//! actual user authentication to SerenCore via `/api/oauth2/*` (Authorization Code + PKCE).

use crate::oauth::store::{AccessToken, AuthRequest, AuthorizationCode, RefreshToken, TokenStore};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// OAuth server state.
#[derive(Clone)]
pub struct OAuthState {
    pub store: TokenStore,
    /// Shared HTTP client for upstream requests.
    pub http: reqwest::Client,
    /// Public base URL of this MCP server (e.g. `https://mcp.serendb.com`).
    pub server_host: String,
    /// Client id used with SerenCore `/api/oauth2/*` endpoints.
    pub upstream_client_id: String,
    /// Base URL for SerenCore API (e.g. `https://api.serendb.com/api`).
    pub upstream_api_base_url: String,
}

// ============================================================================
// Metadata Endpoint (RFC 8414)
// ============================================================================

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

async fn metadata(State(state): State<Arc<OAuthState>>) -> Json<AuthorizationServerMetadata> {
    Json(AuthorizationServerMetadata {
        issuer: state.server_host.clone(),
        authorization_endpoint: format!("{}/authorize", state.server_host),
        token_endpoint: format!("{}/token", state.server_host),
        revocation_endpoint: format!("{}/revoke", state.server_host),
        registration_endpoint: format!("{}/register", state.server_host),
        scopes_supported: vec!["api".into(), "api:read".into()],
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_methods_supported: vec!["none".into(), "client_secret_post".into()],
        code_challenge_methods_supported: vec!["S256".into(), "plain".into()],
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
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    scope: Option<String>,
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
    client_secret: Option<String>,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
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
    for uri in &req.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err(OAuthError::InvalidRequest(
                "redirect_uris must be localhost, HTTPS, or mcp:// URLs".into(),
            ));
        }
    }

    let client_id = TokenStore::generate_token();
    let client_secret = TokenStore::generate_token();
    let grants = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into()]);
    let scopes: Vec<String> = req
        .scope
        .unwrap_or_else(|| "api".into())
        .split_whitespace()
        .map(String::from)
        .collect();

    let secret_hash = hash_secret(&client_secret);
    sqlx::query(
        r#"INSERT INTO mcp_oauth.clients
           (id, name, secret_hash, redirect_uris, grants, scopes, client_uri, software_id, software_version)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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
        client_secret: Some(client_secret),
        client_name: req.client_name,
        redirect_uris: req.redirect_uris,
        grant_types: grants,
        scope: scopes.join(" "),
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

    let code_challenge = req
        .code_challenge
        .ok_or(OAuthError::InvalidRequest("code_challenge required".into()))?;

    let code_challenge_method = req.code_challenge_method.unwrap_or_else(|| "S256".into());
    if code_challenge_method != "S256" && code_challenge_method != "plain" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be S256 or plain".into(),
        ));
    }

    // Create a pending authorization request so we can complete the upstream callback.
    let upstream_state = TokenStore::generate_token();
    let upstream_code_verifier = TokenStore::generate_token();
    let upstream_code_challenge = pkce_s256_challenge(&upstream_code_verifier);

    let auth_request = AuthRequest {
        id: upstream_state.clone(),
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.unwrap_or_else(|| "api".into()),
        client_state: req.state.clone(),
        code_challenge,
        code_challenge_method,
        upstream_code_verifier,
        expires_at: TokenStore::code_expiry(),
        created_at: Utc::now(),
    };

    state
        .store
        .save_auth_request(&auth_request)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    let upstream_redirect_uri = format!("{}/callback", state.server_host.trim_end_matches('/'));
    let mut url = reqwest::Url::parse(&format!(
        "{}/oauth2/authorize",
        state.upstream_api_base_url.trim_end_matches('/')
    ))
    .map_err(|_| OAuthError::ServerError("Invalid upstream_api_base_url".into()))?;

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

#[derive(Debug, Deserialize)]
struct UpstreamTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn callback(
    State(state): State<Arc<OAuthState>>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, OAuthError> {
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
    let token_url = format!(
        "{}/oauth2/token",
        state.upstream_api_base_url.trim_end_matches('/')
    );

    let token_res = state
        .http
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", upstream_redirect_uri.as_str()),
            ("client_id", state.upstream_client_id.as_str()),
            (
                "code_verifier",
                auth_request.upstream_code_verifier.as_str(),
            ),
        ])
        .send()
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    if !token_res.status().is_success() {
        let status = token_res.status();
        let body = token_res.text().await.unwrap_or_default();
        return redirect_with_error(
            &auth_request.redirect_uri,
            auth_request.client_state.as_deref(),
            "server_error",
            Some(&format!(
                "Upstream token exchange failed ({status}): {body}"
            )),
        );
    }

    let token_body: UpstreamTokenResponse = token_res
        .json()
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

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

    let upstream_expires_at = Utc::now() + Duration::seconds(token_body.expires_in.max(0));

    let user_id = fetch_user_id(
        &state.http,
        &state.upstream_api_base_url,
        &token_body.access_token,
    )
    .await
    .ok_or_else(|| OAuthError::ServerError("Failed to fetch user id".into()))?;

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
        created_at: Utc::now(),
        upstream_access_token: token_body.access_token,
        upstream_refresh_token: token_body.refresh_token,
        upstream_expires_at,
    };

    state
        .store
        .save_authorization_code(&auth_code)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

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

    Ok(Redirect::temporary(redirect_url.as_str()).into_response())
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

async fn token(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
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

            // Validate client (and optional client_secret)
            if let Some(client_id) = req.client_id.as_deref() {
                if client_id != auth_code.client_id {
                    return Err(OAuthError::InvalidClient);
                }
            }

            let client = state
                .store
                .get_client(&auth_code.client_id)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?
                .ok_or(OAuthError::InvalidClient)?;

            if let Some(ref secret_hash) = client.secret_hash {
                let provided_client_id =
                    req.client_id.as_deref().ok_or(OAuthError::InvalidClient)?;
                if provided_client_id != client.id {
                    return Err(OAuthError::InvalidClient);
                }
                let provided_secret = req
                    .client_secret
                    .as_deref()
                    .ok_or(OAuthError::InvalidClient)?;
                if hash_secret(provided_secret) != *secret_hash {
                    return Err(OAuthError::InvalidClient);
                }
            }

            if auth_code.redirect_uri != redirect_uri {
                return Err(OAuthError::InvalidGrant("redirect_uri mismatch".into()));
            }

            if let Some(challenge) = &auth_code.code_challenge {
                if !TokenStore::verify_pkce(
                    &code_verifier,
                    challenge,
                    auth_code.code_challenge_method.as_deref(),
                ) {
                    return Err(OAuthError::InvalidGrant("PKCE verification failed".into()));
                }
            }

            // Persist upstream tokens (access token is used as bearer token on /mcp).
            let access_token = AccessToken {
                token: auth_code.upstream_access_token.clone(),
                client_id: auth_code.client_id.clone(),
                user_id: auth_code.user_id.clone(),
                scope: auth_code.scope.clone(),
                expires_at: auth_code.upstream_expires_at,
                created_at: Utc::now(),
            };
            state
                .store
                .save_access_token(&access_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            if let Some(refresh_token_str) = auth_code.upstream_refresh_token.as_deref() {
                let refresh_token = RefreshToken {
                    token: refresh_token_str.to_string(),
                    access_token: access_token.token.clone(),
                    client_id: auth_code.client_id.clone(),
                    user_id: auth_code.user_id.clone(),
                    expires_at: Some(TokenStore::token_expiry(168)), // 7 days
                    created_at: Utc::now(),
                };
                state
                    .store
                    .save_refresh_token(&refresh_token)
                    .await
                    .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            }

            let expires_in = (auth_code.upstream_expires_at - Utc::now())
                .num_seconds()
                .max(0);
            Ok(Json(TokenResponse {
                access_token: auth_code.upstream_access_token,
                token_type: "Bearer".into(),
                expires_in,
                refresh_token: auth_code.upstream_refresh_token,
                scope: auth_code.scope,
            }))
        }
        "refresh_token" => {
            let refresh_token_str = req
                .refresh_token
                .ok_or_else(|| OAuthError::InvalidRequest("refresh_token required".into()))?;

            let refresh_token = state
                .store
                .get_refresh_token(&refresh_token_str)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?
                .ok_or(OAuthError::InvalidGrant(
                    "Invalid or expired refresh token".into(),
                ))?;

            // Validate client (and optional client_secret)
            if let Some(client_id) = req.client_id.as_deref() {
                if client_id != refresh_token.client_id {
                    return Err(OAuthError::InvalidClient);
                }
            }

            let client = state
                .store
                .get_client(&refresh_token.client_id)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?
                .ok_or(OAuthError::InvalidClient)?;

            if let Some(ref secret_hash) = client.secret_hash {
                let provided_client_id =
                    req.client_id.as_deref().ok_or(OAuthError::InvalidClient)?;
                if provided_client_id != client.id {
                    return Err(OAuthError::InvalidClient);
                }
                let provided_secret = req
                    .client_secret
                    .as_deref()
                    .ok_or(OAuthError::InvalidClient)?;
                if hash_secret(provided_secret) != *secret_hash {
                    return Err(OAuthError::InvalidClient);
                }
            }

            // Get the old access token to preserve scope
            let old_token = state
                .store
                .get_access_token(&refresh_token.access_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            let preserved_scope = old_token.map(|t| t.scope).unwrap_or_else(|| "api".into());

            // Refresh upstream tokens via SerenCore.
            let token_url = format!(
                "{}/oauth2/token",
                state.upstream_api_base_url.trim_end_matches('/')
            );
            let res = state
                .http
                .post(token_url)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token_str.as_str()),
                    ("client_id", state.upstream_client_id.as_str()),
                ])
                .send()
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            if !res.status().is_success() {
                let status = res.status();
                let body = res.text().await.unwrap_or_default();
                return Err(OAuthError::InvalidGrant(format!(
                    "Upstream refresh failed ({}): {}",
                    status, body
                )));
            }

            let token_body: UpstreamTokenResponse = res
                .json()
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            // Log the granted scope for debugging
            if let Some(ref granted_scope) = token_body.scope {
                debug!(scope = %granted_scope, "Upstream token refreshed");
            }

            let new_expires_at = Utc::now() + Duration::seconds(token_body.expires_in.max(0));

            let new_access_token_str = token_body.access_token;
            let new_refresh_token_str = token_body
                .refresh_token
                .unwrap_or_else(|| refresh_token_str.clone());

            let new_access_token = AccessToken {
                token: new_access_token_str.clone(),
                client_id: refresh_token.client_id.clone(),
                user_id: refresh_token.user_id.clone(),
                scope: preserved_scope.clone(),
                expires_at: new_expires_at,
                created_at: Utc::now(),
            };
            state
                .store
                .save_access_token(&new_access_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            // Update refresh token row first (avoid FK cascade delete).
            let old_access_token = refresh_token.access_token.clone();
            let result = sqlx::query(
                "UPDATE mcp_oauth.refresh_tokens SET token = $1, access_token = $2, expires_at = $3 WHERE token = $4",
            )
            .bind(&new_refresh_token_str)
            .bind(&new_access_token_str)
            .bind(Some(TokenStore::token_expiry(168))) // 7 days
            .bind(&refresh_token_str)
            .execute(state.store.pool())
            .await
            .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            if result.rows_affected() == 0 {
                return Err(OAuthError::InvalidGrant("refresh_token not found".into()));
            }

            state
                .store
                .revoke_access_token(&old_access_token)
                .await
                .ok();

            let expires_in = (new_expires_at - Utc::now()).num_seconds().max(0);
            Ok(Json(TokenResponse {
                access_token: new_access_token_str,
                token_type: "Bearer".into(),
                expires_in,
                refresh_token: Some(new_refresh_token_str),
                scope: new_access_token.scope,
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
    #[serde(default)]
    token_type_hint: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

/// Token revocation endpoint per RFC 7009.
///
/// Revokes access tokens or refresh tokens. Per the spec, this endpoint
/// always returns 200 OK even if the token was invalid or already revoked.
async fn revoke(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    // Validate client credentials if provided
    if let Some(client_id) = req.client_id.as_deref() {
        let client = state
            .store
            .get_client(client_id)
            .await
            .map_err(|e| OAuthError::ServerError(e.to_string()))?
            .ok_or(OAuthError::InvalidClient)?;

        if let Some(ref secret_hash) = client.secret_hash {
            let provided_secret = req
                .client_secret
                .as_deref()
                .ok_or(OAuthError::InvalidClient)?;
            if hash_secret(provided_secret) != *secret_hash {
                return Err(OAuthError::InvalidClient);
            }
        }
    }

    // Try to revoke based on token_type_hint, or try both if not specified
    let token = &req.token;
    match req.token_type_hint.as_deref() {
        Some("refresh_token") => {
            // Try refresh token first, then access token
            if !state
                .store
                .revoke_refresh_token(token)
                .await
                .unwrap_or(false)
            {
                state.store.revoke_access_token(token).await.ok();
            }
        }
        Some("access_token") => {
            // Try access token first, then refresh token
            if !state
                .store
                .revoke_access_token(token)
                .await
                .unwrap_or(false)
            {
                state.store.revoke_refresh_token(token).await.ok();
            }
        }
        _ => {
            // No hint - try both (access tokens are more common)
            if !state
                .store
                .revoke_access_token(token)
                .await
                .unwrap_or(false)
            {
                state.store.revoke_refresh_token(token).await.ok();
            }
        }
    }

    // RFC 7009: Always return 200 OK regardless of whether token existed
    Ok(StatusCode::OK)
}

// ============================================================================
// Error Handling
// ============================================================================

#[derive(Debug)]
enum OAuthError {
    InvalidRequest(String),
    InvalidClient,
    InvalidGrant(String),
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

fn is_valid_redirect_uri(uri: &str) -> bool {
    if let Ok(url) = reqwest::Url::parse(uri) {
        match url.scheme() {
            // Loopback redirect URIs (RFC 8252) – allow http/https on localhost.
            "http" | "https" => {
                let host = url.host_str().unwrap_or("");
                host == "localhost" || host == "127.0.0.1" || url.scheme() == "https"
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
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(secret.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash)
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
    Ok(Redirect::temporary(redirect_url.as_str()).into_response())
}

async fn fetch_user_id(
    http: &reqwest::Client,
    api_base_url: &str,
    access_token: &str,
) -> Option<String> {
    let url = format!("{}/auth/me", api_base_url.trim_end_matches('/'));
    let res = http.get(url).bearer_auth(access_token).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let v: serde_json::Value = res.json().await.ok()?;
    v.get("data")
        .and_then(|d| d.get("id"))
        .and_then(|id| id.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("id")
                .and_then(|id| id.as_str())
                .map(|s| s.to_string())
        })
}

// ============================================================================
// Router
// ============================================================================

/// Cleanup expired tokens endpoint.
///
/// This endpoint triggers cleanup of expired authorization codes, access tokens,
/// and refresh tokens. It can be called periodically by a cron job or health check.
async fn cleanup(State(state): State<Arc<OAuthState>>) -> Result<StatusCode, OAuthError> {
    state
        .store
        .cleanup_expired()
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;
    Ok(StatusCode::OK)
}

pub fn oauth_router(state: Arc<OAuthState>) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/register", post(register))
        .route("/_cleanup", post(cleanup))
        .with_state(state)
}
