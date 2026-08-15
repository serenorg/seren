use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::command_context::CommandContext;

const MEMORY_GATEWAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug)]
pub(crate) struct MemoryGatewayError {
    context: &'static str,
    status: Option<u16>,
    detail: &'static str,
}

impl MemoryGatewayError {
    fn new(context: &'static str, status: Option<u16>, detail: &'static str) -> Self {
        Self {
            context,
            status,
            detail,
        }
    }

    pub(crate) fn status(&self) -> Option<u16> {
        self.status
    }

    #[cfg(feature = "claude-mem")]
    pub(crate) fn is_retryable(&self) -> bool {
        self.detail == "communication error"
            || self.status.is_some_and(|status| {
                status == 408 || status == 425 || status == 429 || status >= 500
            })
    }
}

impl fmt::Display for MemoryGatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(formatter, "{}: API error {status}", self.context),
            None => write!(formatter, "{}: {}", self.context, self.detail),
        }
    }
}

impl std::error::Error for MemoryGatewayError {}

pub(crate) fn memory_gateway_data<T>(
    result: Result<seren::ResponseValue<T>, seren::Error<()>>,
    context: &'static str,
) -> Result<T, MemoryGatewayError>
where
    T: DeserializeOwned,
{
    match result {
        Ok(response) => Ok(response.into_inner()),
        Err(seren::Error::InvalidResponsePayload(bytes, _)) => {
            decode_memory_gateway_body(&bytes, context)
        }
        Err(seren::Error::UnexpectedResponse(response)) => Err(MemoryGatewayError::new(
            context,
            Some(response.status().as_u16()),
            "unexpected response",
        )),
        Err(seren::Error::ErrorResponse(response)) => Err(MemoryGatewayError::new(
            context,
            Some(response.status().as_u16()),
            "error response",
        )),
        Err(seren::Error::CommunicationError(_)) => Err(MemoryGatewayError::new(
            context,
            None,
            "communication error",
        )),
        Err(_) => Err(MemoryGatewayError::new(
            context,
            None,
            "unexpected client error",
        )),
    }
}

pub(crate) async fn memory_gateway_post<T, B>(
    ctx: &CommandContext,
    publisher_path: &str,
    body: &B,
    context: &'static str,
) -> Result<T, MemoryGatewayError>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    let client = ctx
        .http_client()
        .await
        .map_err(|_| MemoryGatewayError::new(context, None, "communication error"))?;
    let response = client
        .post(format!(
            "{}/publishers/seren-memory/{}",
            ctx.api_base().trim_end_matches('/'),
            publisher_path.trim_start_matches('/')
        ))
        .json(body)
        .timeout(MEMORY_GATEWAY_TIMEOUT)
        .send()
        .await
        .map_err(|_| MemoryGatewayError::new(context, None, "communication error"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| MemoryGatewayError::new(context, None, "communication error"))?;
    if !status.is_success() {
        return Err(MemoryGatewayError::new(
            context,
            Some(status.as_u16()),
            "gateway error",
        ));
    }
    decode_memory_gateway_body(&bytes, context)
}

fn decode_memory_gateway_body<T>(
    bytes: &[u8],
    context: &'static str,
) -> Result<T, MemoryGatewayError>
where
    T: DeserializeOwned,
{
    let envelope: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| MemoryGatewayError::new(context, None, "invalid gateway response"))?;
    let data = envelope
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| MemoryGatewayError::new(context, None, "invalid gateway response"))?;
    let status = data
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .ok_or_else(|| MemoryGatewayError::new(context, None, "invalid gateway response"))?;
    if status >= 400 {
        return Err(MemoryGatewayError::new(
            context,
            Some(status),
            "publisher error",
        ));
    }
    let body = data
        .get("body")
        .ok_or_else(|| MemoryGatewayError::new(context, None, "gateway response has no body"))?;
    serde_json::from_value(body.clone())
        .map_err(|_| MemoryGatewayError::new(context, None, "invalid publisher response"))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct TestResponse {
        value: String,
    }

    #[test]
    fn decodes_successful_metered_publisher_body() {
        let response = decode_memory_gateway_body::<TestResponse>(
            br#"{"data":{"status":200,"body":{"value":"ok"},"cost":"0"}}"#,
            "memory request failed",
        )
        .unwrap();

        assert_eq!(
            response,
            TestResponse {
                value: "ok".to_string()
            }
        );
    }

    #[test]
    fn surfaces_upstream_status_without_exposing_body() {
        let error = decode_memory_gateway_body::<TestResponse>(
            br#"{"data":{"status":401,"body":{"message":"secret detail"},"cost":"0"}}"#,
            "memory request failed",
        )
        .unwrap_err();

        assert_eq!(error.status(), Some(401));
        assert_eq!(error.to_string(), "memory request failed: API error 401");
        assert!(!error.to_string().contains("secret detail"));
    }

    /// Serve one canned HTTP response and return the raw request head that
    /// the client sent, so tests can assert the path and headers.
    fn serve_one_response(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let base = format!(
            "http://{}/",
            listener.local_addr().expect("listener address")
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept test request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).expect("read test request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            sender
                .send(String::from_utf8_lossy(&request).to_string())
                .ok();
            let response = format!(
                "{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write test response");
        });
        (base, receiver)
    }

    fn test_context(base: String) -> CommandContext {
        CommandContext::new(
            Some(base),
            Some("test-key".to_string()),
            crate::OutputFormat::Json,
        )
    }

    #[tokio::test]
    async fn posts_authenticated_requests_to_the_publisher_path() {
        let (base, request) = serve_one_response(
            "HTTP/1.1 200 OK",
            r#"{"data":{"status":200,"body":{"value":"ok"}}}"#,
        );
        let response: TestResponse = memory_gateway_post(
            &test_context(base),
            "/capture_agent_turn",
            &serde_json::json!({"agent_platform": "claude"}),
            "capture request failed",
        )
        .await
        .expect("delivered capture");
        assert_eq!(response.value, "ok");

        let request = request.recv().expect("request head");
        assert!(
            request.starts_with("POST /publishers/seren-memory/capture_agent_turn HTTP/1.1"),
            "unexpected request line in: {request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer test-key"),
            "request must carry the CLI bearer credential"
        );
    }

    #[cfg(feature = "claude-mem")]
    #[tokio::test]
    async fn outer_gateway_errors_keep_their_status_and_stay_opaque() {
        let (base, _request) = serve_one_response(
            "HTTP/1.1 503 Service Unavailable",
            r#"{"secret":"internal"}"#,
        );
        let error = memory_gateway_post::<TestResponse, _>(
            &test_context(base),
            "capture_agent_turn",
            &serde_json::json!({}),
            "capture request failed",
        )
        .await
        .expect_err("gateway failure must surface");
        assert_eq!(error.status(), Some(503));
        assert!(error.is_retryable());
        assert!(!error.to_string().contains("internal"));
    }

    #[cfg(feature = "claude-mem")]
    #[tokio::test]
    async fn inner_publisher_errors_surface_as_delivery_failures() {
        let (base, _request) = serve_one_response(
            "HTTP/1.1 200 OK",
            r#"{"data":{"status":402,"body":{"message":"payment detail"}}}"#,
        );
        let error = memory_gateway_post::<TestResponse, _>(
            &test_context(base),
            "capture_agent_turn",
            &serde_json::json!({}),
            "capture request failed",
        )
        .await
        .expect_err("inner publisher failure must surface");
        assert_eq!(error.status(), Some(402));
        assert!(!error.is_retryable());
        assert!(!error.to_string().contains("payment detail"));
    }
}
