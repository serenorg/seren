//! OAuth2 HTTP routes for hosted MCP server mode
//!
//! Implements OAuth 2.1 endpoints per MCP specification:
//! - `/.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
//! - `/authorize` - Authorization endpoint
//! - `/token` - Token endpoint
//! - `/register` - Dynamic client registration (RFC 7591)

use crate::oauth::store::{AccessToken, AuthorizationCode, RefreshToken, TokenStore};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OAuth server state
#[derive(Clone)]
pub struct OAuthState {
    pub store: TokenStore,
    pub server_host: String,
    pub client_id: String,
    /// Seren API key used by the MCP server when calling the Seren API in hosted mode.
    ///
    /// Note: this is currently a single-tenant implementation; all OAuth clients share this key.
    pub seren_api_key: String,
}

// ============================================================================
// Metadata Endpoint (RFC 8414)
// ============================================================================

#[derive(Debug, Serialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
}

async fn metadata(State(state): State<Arc<OAuthState>>) -> Json<AuthorizationServerMetadata> {
    Json(AuthorizationServerMetadata {
        issuer: state.server_host.clone(),
        authorization_endpoint: format!("{}/authorize", state.server_host),
        token_endpoint: format!("{}/token", state.server_host),
        registration_endpoint: format!("{}/register", state.server_host),
        scopes_supported: vec!["api".into(), "api:read".into()],
        response_types_supported: vec!["code".into()],
        grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
        token_endpoint_auth_methods_supported: vec!["none".into(), "client_secret_post".into()],
        code_challenge_methods_supported: vec!["S256".into(), "plain".into()],
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
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    client_id: String,
    client_secret: Option<String>,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
}

async fn register(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, OAuthError> {
    // Validate redirect URIs per MCP spec
    for uri in &req.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return Err(OAuthError::InvalidRequest(
                "redirect_uris must be localhost or HTTPS URLs".into(),
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

    // Store the client (hashing the secret)
    let secret_hash = hash_secret(&client_secret);
    sqlx::query(
        r#"INSERT INTO mcp_oauth.clients
           (id, name, secret_hash, redirect_uris, grants, scopes)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(&client_id)
    .bind(&req.client_name)
    .bind(&secret_hash)
    .bind(&req.redirect_uris)
    .bind(&grants)
    .bind(&scopes)
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
    }))
}

// ============================================================================
// Authorization Endpoint
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
    // Validate response_type
    if req.response_type != "code" {
        return Err(OAuthError::UnsupportedResponseType);
    }

    // Validate client
    let client = state
        .store
        .get_client(&req.client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?
        .ok_or(OAuthError::InvalidClient)?;

    // Validate redirect URI
    if !client.allows_redirect_uri(&req.redirect_uri) {
        return Err(OAuthError::InvalidRequest(
            "redirect_uri not registered for this client".into(),
        ));
    }

    // PKCE is required per MCP spec
    let code_challenge = req
        .code_challenge
        .ok_or(OAuthError::InvalidRequest("code_challenge required".into()))?;

    let code_challenge_method = req.code_challenge_method.unwrap_or_else(|| "S256".into());
    if code_challenge_method != "S256" && code_challenge_method != "plain" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be S256 or plain".into(),
        ));
    }

    // Generate authorization code
    let code = TokenStore::generate_code();
    let auth_code = AuthorizationCode {
        code: code.clone(),
        client_id: req.client_id,
        user_id: "mcp-user".into(), // In a real implementation, this would be the authenticated user
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.unwrap_or_else(|| "api".into()),
        code_challenge: Some(code_challenge),
        code_challenge_method: Some(code_challenge_method),
        expires_at: TokenStore::code_expiry(),
        created_at: chrono::Utc::now(),
    };

    state
        .store
        .save_authorization_code(&auth_code)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    // Redirect back to client with code
    let mut redirect_url = reqwest::Url::parse(&req.redirect_uri)
        .map_err(|_| OAuthError::InvalidRequest("Invalid redirect_uri".into()))?;

    redirect_url.query_pairs_mut().append_pair("code", &code);

    if let Some(state_param) = req.state {
        redirect_url
            .query_pairs_mut()
            .append_pair("state", &state_param);
    }

    Ok(Redirect::temporary(redirect_url.as_str()).into_response())
}

// ============================================================================
// Token Endpoint
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
                .ok_or(OAuthError::InvalidRequest("code required".into()))?;
            let redirect_uri = req
                .redirect_uri
                .ok_or(OAuthError::InvalidRequest("redirect_uri required".into()))?;
            let code_verifier = req
                .code_verifier
                .ok_or(OAuthError::InvalidRequest("code_verifier required".into()))?;

            // Consume the authorization code
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

            // Validate redirect_uri matches
            if auth_code.redirect_uri != redirect_uri {
                return Err(OAuthError::InvalidGrant("redirect_uri mismatch".into()));
            }

            // Validate PKCE
            if let Some(challenge) = &auth_code.code_challenge {
                if !TokenStore::verify_pkce(
                    &code_verifier,
                    challenge,
                    auth_code.code_challenge_method.as_deref(),
                ) {
                    return Err(OAuthError::InvalidGrant("PKCE verification failed".into()));
                }
            }

            // Generate tokens
            let access_token_str = TokenStore::generate_token();
            let refresh_token_str = TokenStore::generate_token();
            let expires_in = 3600; // 1 hour

            // Single-tenant: use the server-configured Seren API key for all clients.
            let seren_api_key = state.seren_api_key.clone();

            let access_token = AccessToken {
                token: access_token_str.clone(),
                client_id: auth_code.client_id.clone(),
                user_id: auth_code.user_id.clone(),
                scope: auth_code.scope.clone(),
                expires_at: TokenStore::token_expiry(1), // 1 hour
                created_at: chrono::Utc::now(),
                seren_api_key,
            };

            let refresh_token = RefreshToken {
                token: refresh_token_str.clone(),
                access_token: access_token_str.clone(),
                client_id: auth_code.client_id,
                user_id: auth_code.user_id,
                expires_at: Some(TokenStore::token_expiry(24 * 30)), // 30 days
                created_at: chrono::Utc::now(),
            };

            state
                .store
                .save_access_token(&access_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            state
                .store
                .save_refresh_token(&refresh_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            Ok(Json(TokenResponse {
                access_token: access_token_str,
                token_type: "Bearer".into(),
                expires_in,
                refresh_token: Some(refresh_token_str),
                scope: access_token.scope,
            }))
        }
        "refresh_token" => {
            let refresh_token_str = req
                .refresh_token
                .ok_or(OAuthError::InvalidRequest("refresh_token required".into()))?;

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

            // Generate new access token
            let new_access_token_str = TokenStore::generate_token();
            let seren_api_key = state.seren_api_key.clone();

            let new_access_token = AccessToken {
                token: new_access_token_str.clone(),
                client_id: refresh_token.client_id.clone(),
                user_id: refresh_token.user_id.clone(),
                scope: "api".into(), // Would be stored with refresh token in full implementation
                expires_at: TokenStore::token_expiry(1),
                created_at: chrono::Utc::now(),
                seren_api_key,
            };

            state
                .store
                .save_access_token(&new_access_token)
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;

            // Update refresh token to point to new access token
            let old_access_token = refresh_token.access_token.clone();
            let result = sqlx::query(
                "UPDATE mcp_oauth.refresh_tokens SET access_token = $1 WHERE token = $2",
            )
            .bind(&new_access_token_str)
            .bind(&refresh_token_str)
            .execute(state.store.pool())
            .await
            .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            if result.rows_affected() == 0 {
                return Err(OAuthError::InvalidGrant("refresh_token not found".into()));
            }

            // Revoke the old access token after the refresh token has been repointed.
            // (Deleting the old access token first would cascade-delete the refresh token row.)
            state
                .store
                .revoke_access_token(&old_access_token)
                .await
                .ok();

            Ok(Json(TokenResponse {
                access_token: new_access_token_str,
                token_type: "Bearer".into(),
                expires_in: 3600,
                refresh_token: Some(refresh_token_str),
                scope: new_access_token.scope,
            }))
        }
        _ => Err(OAuthError::UnsupportedGrantType),
    }
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

// ============================================================================
// Router
// ============================================================================

pub fn oauth_router(state: Arc<OAuthState>) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/register", post(register))
        .with_state(state)
}
