use futures::StreamExt;
use serde::Deserialize;

/// Non-secret error discriminants emitted by the first-party SerenDB API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum SerenDbQueryErrorReason {
    BadRequest,
    ValidationError,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    PayloadTooLarge,
    TooManyRequests,
    PaymentRequired,
    QuotaExceeded,
    FeatureNotAvailable,
    OAuthRequired,
    OtpRequired,
    InternalError,
    DatabaseError,
    BadGateway,
    GatewayTimeout,
    ServiceUnavailable,
    NotImplemented,
    MethodNotAllowed,
    #[default]
    #[serde(other)]
    Unknown,
}

impl SerenDbQueryErrorReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "BadRequest",
            Self::ValidationError => "ValidationError",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "NotFound",
            Self::Conflict => "Conflict",
            Self::PayloadTooLarge => "PayloadTooLarge",
            Self::TooManyRequests => "TooManyRequests",
            Self::PaymentRequired => "PaymentRequired",
            Self::QuotaExceeded => "QuotaExceeded",
            Self::FeatureNotAvailable => "FeatureNotAvailable",
            Self::OAuthRequired => "OAuthRequired",
            Self::OtpRequired => "OtpRequired",
            Self::InternalError => "InternalError",
            Self::DatabaseError => "DatabaseError",
            Self::BadGateway => "BadGateway",
            Self::GatewayTimeout => "GatewayTimeout",
            Self::ServiceUnavailable => "ServiceUnavailable",
            Self::NotImplemented => "NotImplemented",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::Unknown => "Unknown",
        }
    }

    /// Stable snake_case discriminant for diagnostics and recovery metadata.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::ValidationError => "validation_error",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::TooManyRequests => "too_many_requests",
            Self::PaymentRequired => "payment_required",
            Self::QuotaExceeded => "quota_exceeded",
            Self::FeatureNotAvailable => "feature_not_available",
            Self::OAuthRequired => "oauth_required",
            Self::OtpRequired => "otp_required",
            Self::InternalError => "internal_error",
            Self::DatabaseError => "database_error",
            Self::BadGateway => "bad_gateway",
            Self::GatewayTimeout => "gateway_timeout",
            Self::ServiceUnavailable => "service_unavailable",
            Self::NotImplemented => "not_implemented",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Unknown => "unknown",
        }
    }
}

/// Safe diagnostics for a failed first-party query; never includes response text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerenDbQueryFailure {
    pub status: Option<u16>,
    pub reason: SerenDbQueryErrorReason,
    pub request_id: Option<uuid::Uuid>,
    pub timeout: bool,
}

#[derive(Deserialize)]
struct QueryErrorBody {
    error: SerenDbQueryErrorReason,
}

fn request_id(headers: &reqwest::header::HeaderMap) -> Option<uuid::Uuid> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
}

/// Consume a query failure without exposing SQL, server messages, or credentials.
///
/// Unknown, malformed, and oversized bodies retain HTTP status and a UUID request
/// ID when available. Only known first-party error discriminants are retained.
pub async fn seren_db_query_failure(error: crate::Error<()>) -> SerenDbQueryFailure {
    let mut failure = SerenDbQueryFailure {
        status: error.status().map(|status| status.as_u16()),
        reason: SerenDbQueryErrorReason::Unknown,
        request_id: None,
        timeout: false,
    };
    match error {
        crate::Error::UnexpectedResponse(response) => {
            failure.request_id = request_id(response.headers());
            const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
            let mut body = Vec::new();
            let stream = response.bytes_stream();
            futures::pin_mut!(stream);
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => {
                        if chunk.len() > MAX_ERROR_BODY_BYTES - body.len() {
                            return failure;
                        }
                        body.extend_from_slice(&chunk);
                    }
                    Err(error) => {
                        failure.timeout = error.is_timeout();
                        return failure;
                    }
                }
            }
            if let Ok(body) = serde_json::from_slice::<QueryErrorBody>(&body) {
                failure.reason = body.error;
            }
        }
        crate::Error::ErrorResponse(response) => {
            failure.request_id = request_id(response.headers());
        }
        crate::Error::CommunicationError(error)
        | crate::Error::ResponseBodyError(error)
        | crate::Error::InvalidUpgrade(error) => {
            failure.timeout = error.is_timeout();
        }
        crate::Error::InvalidRequest(_)
        | crate::Error::InvalidResponsePayload(_, _)
        | crate::Error::Custom(_) => {}
    }
    failure
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    async fn query_failure(status: u16, body: String, correlation: &str) -> SerenDbQueryFailure {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publishers/seren-db/query"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("x-request-id", correlation)
                    .set_body_raw(body, "application/json"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::Client::from_config(
            &crate::ClientConfig::unauthenticated().with_base_url(server.uri()),
        )
        .unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "query": "SELECT 1", "database": "test", "read_only": true
        }))
        .unwrap();
        let failure =
            seren_db_query_failure(client.seren_db_query(&request).await.unwrap_err()).await;
        server.verify().await;
        failure
    }

    #[tokio::test]
    async fn query_failures_retain_checked_reason_status_and_request_id() {
        let correlation = uuid::Uuid::new_v4();
        for (status, reason) in [
            (400, SerenDbQueryErrorReason::BadRequest),
            (401, SerenDbQueryErrorReason::Unauthorized),
            (403, SerenDbQueryErrorReason::Forbidden),
            (404, SerenDbQueryErrorReason::NotFound),
            (429, SerenDbQueryErrorReason::TooManyRequests),
            (500, SerenDbQueryErrorReason::DatabaseError),
            (502, SerenDbQueryErrorReason::BadGateway),
            (503, SerenDbQueryErrorReason::ServiceUnavailable),
            (504, SerenDbQueryErrorReason::GatewayTimeout),
        ] {
            let failure = query_failure(
                status,
                serde_json::json!({
                    "error": reason.as_str(),
                    "message": "private query text and credentials",
                    "details": {"secret": "private"}
                })
                .to_string(),
                &correlation.to_string(),
            )
            .await;
            assert_eq!(failure.status, Some(status));
            assert_eq!(failure.reason, reason);
            assert_eq!(failure.request_id, Some(correlation));
            assert!(!format!("{failure:?}").contains("private"));
        }
    }

    #[tokio::test]
    async fn query_unknown_or_invalid_bodies_preserve_transport_metadata() {
        let correlation = uuid::Uuid::new_v4();
        for body in [
            "not JSON".to_string(),
            r#"{"error":"private unknown code","message":"invalid arguments"}"#.to_string(),
            r#"{"message":"invalid arguments"}"#.to_string(),
            r#"{"error":17}"#.to_string(),
            format!(
                r#"{{"error":"Forbidden","message":"{}"}}"#,
                "x".repeat(16 * 1024)
            ),
        ] {
            let failure = query_failure(403, body, &correlation.to_string()).await;
            assert_eq!(failure.status, Some(403));
            assert_eq!(failure.reason, SerenDbQueryErrorReason::Unknown);
            assert_eq!(failure.request_id, Some(correlation));
        }
    }

    #[tokio::test]
    async fn query_failure_rejects_non_uuid_request_ids() {
        let failure = query_failure(
            500,
            r#"{"error":"InternalError"}"#.to_string(),
            "private-header-value",
        )
        .await;
        assert_eq!(failure.request_id, None);
        assert_eq!(failure.reason, SerenDbQueryErrorReason::InternalError);
    }

    #[tokio::test]
    async fn query_transport_timeout_has_no_server_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/publishers/seren-db/query"))
            .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_secs(1)))
            .mount(&server)
            .await;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .unwrap();
        let client = crate::Client::new_with_client(&server.uri(), http);
        let request = serde_json::from_value(serde_json::json!({"query": "SELECT 1"})).unwrap();
        let failure =
            seren_db_query_failure(client.seren_db_query(&request).await.unwrap_err()).await;
        assert!(failure.timeout);
        assert_eq!(failure.status, None);
        assert_eq!(failure.reason, SerenDbQueryErrorReason::Unknown);
        assert_eq!(failure.request_id, None);
    }
}
