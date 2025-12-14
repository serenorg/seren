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
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
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

const SUPPORTED_GRANT_TYPES: &[&str] = &["authorization_code", "refresh_token"];
const SUPPORTED_RESPONSE_TYPES: &[&str] = &["code"];
const SUPPORTED_AUTH_METHODS: &[&str] = &["none", "client_secret_post"];

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
    let server_host = state.server_host.trim_end_matches('/').to_string();
    Json(AuthorizationServerMetadata {
        issuer: server_host.clone(),
        authorization_endpoint: format!("{}/authorize", server_host),
        token_endpoint: format!("{}/token", server_host),
        revocation_endpoint: format!("{}/revoke", server_host),
        registration_endpoint: format!("{}/register", server_host),
        scopes_supported: vec!["api".into(), "api:read".into()],
        response_types_supported: vec!["code".into()],
        grant_types_supported: SUPPORTED_GRANT_TYPES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        token_endpoint_auth_methods_supported: SUPPORTED_AUTH_METHODS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
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
    const ALLOWED_SCOPES: &[&str] = &["api", "api:read", "openid", "profile", "email"];
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

    // OAuth 2.1 requires S256; plain is insecure and not allowed
    let code_challenge_method = req.code_challenge_method.unwrap_or_else(|| "S256".into());
    if code_challenge_method != "S256" {
        return Err(OAuthError::InvalidRequest(
            "code_challenge_method must be S256 (plain is not supported)".into(),
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
        // Log details server-side but don't expose to client
        tracing::error!(
            status = %status,
            body = %body,
            "Upstream token exchange failed"
        );
        return redirect_with_error(
            &auth_request.redirect_uri,
            auth_request.client_state.as_deref(),
            "server_error",
            Some("Authorization failed. Please try again."),
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

    // Enforce per-user consent before issuing a downstream authorization code redirect.
    let approved = state
        .store
        .is_client_approved(&user_id, &auth_request.client_id)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    // Create downstream authorization code carrying upstream tokens.
    let downstream_code = TokenStore::generate_code();
    let auth_code = AuthorizationCode {
        code: downstream_code.clone(),
        client_id: auth_request.client_id.clone(),
        user_id: user_id.clone(),
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
        return Ok(Redirect::temporary(redirect_url.as_str()).into_response());
    }

    // Not yet approved: create a pending consent record and redirect to a local consent page.
    let consent_id = TokenStore::generate_token();
    let csrf_token = TokenStore::generate_token();
    let consent_expires_at = Utc::now() + Duration::minutes(10);
    let consent = crate::oauth::store::PendingConsent {
        id: consent_id.clone(),
        user_id: user_id.clone(),
        client_id: auth_request.client_id.clone(),
        authorization_code: downstream_code.clone(),
        redirect_uri: auth_request.redirect_uri.clone(),
        client_state: auth_request.client_state.clone(),
        scope: auth_request.scope.clone(),
        csrf_token,
        expires_at: consent_expires_at,
        created_at: Utc::now(),
    };
    state
        .store
        .save_pending_consent(&consent)
        .await
        .map_err(|e| OAuthError::ServerError(e.to_string()))?;

    let server_host = state.server_host.trim_end_matches('/');
    let consent_url = format!("{server_host}/consent?token={consent_id}");
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
                if !verify_secret(provided_secret, secret_hash) {
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
                if !verify_secret(provided_secret, secret_hash) {
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
                // Log details server-side but don't expose to client
                tracing::error!(
                    status = %status,
                    body = %body,
                    "Upstream token refresh failed"
                );
                return Err(OAuthError::InvalidGrant(
                    "Token refresh failed. Please re-authenticate.".into(),
                ));
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
            // Always rotate refresh token for security (don't reuse the old one)
            let new_refresh_token_str = token_body
                .refresh_token
                .unwrap_or_else(TokenStore::generate_token);

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
            let updated = state
                .store
                .update_refresh_token(
                    &refresh_token_str,
                    &new_refresh_token_str,
                    &new_access_token_str,
                    Some(TokenStore::token_expiry(168)), // 7 days
                )
                .await
                .map_err(|e| OAuthError::ServerError(e.to_string()))?;
            if !updated {
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
            if !verify_secret(provided_secret, secret_hash) {
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
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
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
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
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
        <form method="post" action="/consent">
          <input type="hidden" name="token" value="{token}">
          <input type="hidden" name="csrf_token" value="{csrf_token}">
          <input type="hidden" name="action" value="approve">
          <button class="approve" type="submit">Approve</button>
        </form>
        <form method="post" action="/consent">
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
        csrf_token = html_escape(&consent.csrf_token)
    );

    Ok(Html(html).into_response())
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
    let consent = state
        .store
        .consume_pending_consent(&req.token)
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

    match req.action.as_str() {
        "approve" => {
            state
                .store
                .approve_client(&consent.user_id, &consent.client_id)
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
            Ok(Redirect::temporary(redirect_url.as_str()).into_response())
        }
        "deny" => {
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

    // Separate router for rate-limited /register endpoint
    let register_router = Router::new()
        .route("/register", post(register))
        .layer(register_limiter)
        .with_state(state.clone());

    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/authorize", get(authorize))
        .route("/callback", get(callback))
        .route("/consent", get(consent_page).post(consent_submit))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/_cleanup", post(cleanup))
        .with_state(state)
        .merge(register_router)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{to_bytes, Body};
    use axum::http::{header, Request, StatusCode};
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

        let state = Arc::new(OAuthState {
            store: store.clone(),
            http: reqwest::Client::new(),
            server_host: server_host.clone(),
            upstream_client_id: upstream_client_id.clone(),
            upstream_api_base_url: upstream.uri(),
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
            "SELECT upstream_code_verifier FROM mcp_oauth.auth_requests WHERE id = $1",
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
