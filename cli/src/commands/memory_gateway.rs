use std::fmt;

use serde::de::DeserializeOwned;

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
}
