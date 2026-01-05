//! Stale MCP session detection middleware
//!
//! This Tower service wraps the rmcp StreamableHttpService and provides visibility
//! into stale session errors. When rmcp returns an error for a stale session (e.g.,
//! after a server restart), this middleware logs the event for observability.
//!
//! NOTE: Server-side retry doesn't work for MCP because the protocol requires
//! `initialize` as the first message for new sessions. Retrying a non-initialize
//! request without a session ID will fail with "Unexpected message, expect initialize".
//! The proper fix is client-side: clients should detect session errors and reconnect.

use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header::HeaderName};
use futures::future::BoxFuture;
use std::task::{Context, Poll};
use tower::Service;

/// Header name for MCP session ID
const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";

/// Tower service that detects stale MCP sessions and logs them for observability.
/// Does NOT retry requests because MCP protocol requires initialization for new sessions.
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

        tracing::debug!(
            event = "stale_session_middleware_entry",
            session_id = ?session_id,
            method = %method,
            uri = %uri,
            "StaleSessionRecoveryService processing request"
        );

        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Call the inner service directly
            let response = inner.call(req).await?;
            let status = response.status();

            // Check if this looks like a stale session error
            let is_stale_session_error = session_id.is_some()
                && matches!(status, StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND);

            if is_stale_session_error {
                if let Some(sid) = &session_id {
                    tracing::warn!(
                        event = "stale_session_detected",
                        session_id = %sid,
                        status = %status,
                        method = %method,
                        uri = %uri,
                        "Detected stale MCP session. Client should reconnect and re-initialize."
                    );
                }
            } else if session_id.is_some() {
                tracing::debug!(
                    event = "stale_session_response",
                    session_id = ?session_id,
                    status = %status,
                    method = %method,
                    uri = %uri,
                    "Request completed with session"
                );
            }

            Ok(response)
        })
    }
}
