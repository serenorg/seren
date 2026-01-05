//! HTTP middleware for request tracing and observability

use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use uuid::Uuid;

// Re-export the stale session recovery service
mod stale_session;
pub use stale_session::StaleSessionRecoveryService;

/// Header name for correlation/request ID
pub const X_REQUEST_ID: &str = "x-request-id";

/// Middleware that adds correlation ID to requests and responses
///
/// - Extracts existing x-request-id header or generates a new UUID
/// - Adds request_id to tracing span for all logs in this request
/// - Includes x-request-id in response headers for client correlation
pub async fn request_id_middleware(request: Request, next: Next) -> Response {
    // Extract or generate request ID
    let request_id = request
        .headers()
        .get(X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Add to tracing span
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
    );

    let _guard = span.enter();

    // Process request
    let mut response = next.run(request).await;

    // Add request ID to response headers
    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, header_value);
    }

    response
}
