//! Stale MCP session recovery service
//!
//! This Tower service wraps the rmcp StreamableHttpService and handles the case where
//! a client sends a request with an `Mcp-Session-Id` header for a session that no longer
//! exists (e.g., after a server restart).
//!
//! When rmcp returns an error (401/404/500) for a stale session, this service:
//! 1. Removes the stale `Mcp-Session-Id` header
//! 2. Retries the request to create a fresh session
//! 3. The client will receive a new session ID in the response

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, Uri, header::HeaderName};
use futures::future::BoxFuture;
use std::task::{Context, Poll};
use tower::Service;

/// Header name for MCP session ID
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";

/// Max body size to buffer for retry (1MB should be plenty for MCP JSON-RPC)
const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Tower service that recovers from stale MCP sessions by retrying without the session ID
#[derive(Clone)]
pub struct StaleSessionRecoveryService<S> {
    inner: S,
}

impl<S> StaleSessionRecoveryService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ResBody> Service<Request<Body>> for StaleSessionRecoveryService<S>
where
    S: Service<Request<Body>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: std::fmt::Debug + Send,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let session_id_header = HeaderName::from_static(MCP_SESSION_ID_HEADER);

        // Check if request has a session ID
        let session_id = req
            .headers()
            .get(&session_id_header)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let method = req.method().clone();
        let uri = req.uri().clone();

        tracing::info!(
            event = "stale_session_middleware_entry",
            session_id = ?session_id,
            method = %method,
            uri = %uri,
            "StaleSessionRecoveryService processing request"
        );

        // For requests with a session ID (GET or POST), we might need to retry
        let should_check_for_stale = session_id.is_some();
        let cloned_headers = if should_check_for_stale {
            Some(req.headers().clone())
        } else {
            None
        };

        // Clone the service for potential retry
        let mut inner = self.inner.clone();
        let mut retry_inner = self.inner.clone();

        Box::pin(async move {
            // For POST requests with session ID, we need to buffer the body for potential retry
            if should_check_for_stale && method == Method::POST {
                // Extract body parts
                let (parts, body) = req.into_parts();

                // Try to read the body
                match to_bytes(body, MAX_BODY_SIZE).await {
                    Ok(bytes) => {
                        // Rebuild request with cloned body
                        let new_body = Body::from(bytes.clone());
                        let rebuilt_req = Request::from_parts(parts, new_body);

                        // Call inner with rebuilt request
                        let response = inner.call(rebuilt_req).await?;

                        // Check if stale session error
                        let status = response.status();

                        tracing::info!(
                            event = "stale_session_post_response",
                            session_id = ?session_id,
                            status = %status,
                            method = %method,
                            uri = %uri,
                            "StaleSessionRecoveryService got response from inner service"
                        );

                        let is_stale_session_error = session_id.is_some()
                            && matches!(
                                status,
                                StatusCode::UNAUTHORIZED
                                    | StatusCode::NOT_FOUND
                                    | StatusCode::INTERNAL_SERVER_ERROR
                            );

                        if is_stale_session_error
                            && let (Some(sid), Some(original_headers)) =
                                (&session_id, &cloned_headers)
                        {
                            tracing::info!(
                                event = "stale_session_detected",
                                session_id = %sid,
                                status = %status,
                                method = %method,
                                uri = %uri,
                                "Detected stale MCP session on POST, retrying without session ID"
                            );

                            // Build retry request with buffered body
                            if let Some(retry_req) = build_retry_request(
                                &method,
                                &uri,
                                original_headers,
                                &session_id_header,
                                Body::from(bytes),
                            ) {
                                match retry_inner.call(retry_req).await {
                                    Ok(retry_response) => {
                                        let new_session_id = retry_response
                                            .headers()
                                            .get(&session_id_header)
                                            .and_then(|v| v.to_str().ok());

                                        tracing::info!(
                                            event = "stale_session_recovered",
                                            old_session_id = %sid,
                                            new_session_id = ?new_session_id,
                                            status = %retry_response.status(),
                                            method = %method,
                                            uri = %uri,
                                            "Successfully recovered from stale session"
                                        );
                                        return Ok(retry_response);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            event = "stale_session_retry_failed",
                                            error = ?e,
                                            session_id = %sid,
                                            method = %method,
                                            uri = %uri,
                                            "Failed to retry after stale session detection"
                                        );
                                    }
                                }
                            }
                        }

                        return Ok(response);
                    }
                    Err(e) => {
                        tracing::warn!(
                            event = "stale_session_body_read_failed",
                            error = ?e,
                            uri = %uri,
                            "Failed to read request body for potential stale session retry, passing through"
                        );
                        // Can't retry, rebuild request with empty body and let it fail naturally
                        let new_body = Body::empty();
                        let rebuilt_req = Request::from_parts(parts, new_body);
                        return inner.call(rebuilt_req).await;
                    }
                }
            }

            // For GET requests or requests without session ID
            let response = inner.call(req).await?;

            // Check if this looks like a stale session error on GET
            let status = response.status();

            tracing::info!(
                event = "stale_session_get_response",
                session_id = ?session_id,
                status = %status,
                method = %method,
                uri = %uri,
                "StaleSessionRecoveryService got response for non-POST request"
            );
            let is_stale_session_error = session_id.is_some()
                && method == Method::GET
                && matches!(
                    status,
                    StatusCode::UNAUTHORIZED
                        | StatusCode::NOT_FOUND
                        | StatusCode::INTERNAL_SERVER_ERROR
                );

            if is_stale_session_error
                && let (Some(sid), Some(original_headers)) = (&session_id, cloned_headers)
            {
                tracing::info!(
                    event = "stale_session_detected",
                    session_id = %sid,
                    status = %status,
                    method = %method,
                    uri = %uri,
                    "Detected stale MCP session on GET, retrying without session ID"
                );

                // Build a new request without the session ID
                if let Some(retry_req) = build_retry_request(
                    &method,
                    &uri,
                    &original_headers,
                    &session_id_header,
                    Body::empty(),
                ) {
                    match retry_inner.call(retry_req).await {
                        Ok(retry_response) => {
                            let new_session_id = retry_response
                                .headers()
                                .get(&session_id_header)
                                .and_then(|v| v.to_str().ok());

                            tracing::info!(
                                event = "stale_session_recovered",
                                old_session_id = %sid,
                                new_session_id = ?new_session_id,
                                status = %retry_response.status(),
                                method = %method,
                                uri = %uri,
                                "Successfully recovered from stale session"
                            );
                            return Ok(retry_response);
                        }
                        Err(e) => {
                            tracing::warn!(
                                event = "stale_session_retry_failed",
                                error = ?e,
                                session_id = %sid,
                                method = %method,
                                uri = %uri,
                                "Failed to retry after stale session detection"
                            );
                        }
                    }
                }
            }

            Ok(response)
        })
    }
}

/// Build a retry request without the session ID header
fn build_retry_request(
    method: &Method,
    uri: &Uri,
    original_headers: &HeaderMap,
    session_id_header: &HeaderName,
    body: Body,
) -> Option<Request<Body>> {
    let mut builder = Request::builder().method(method.clone()).uri(uri.clone());

    // Copy all headers except the stale session ID
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in original_headers.iter() {
            if name != session_id_header {
                headers.insert(name.clone(), value.clone());
            }
        }
    }

    builder.body(body).ok()
}
