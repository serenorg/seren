//! Typed recovery for Storage, Skills, Notes, and other publisher calls.

use base64::Engine;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// The closed set of publisher gateway failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherErrorKind {
    PublisherError,
    ClientContractMismatch,
    CommunicationError,
}

impl std::fmt::Display for PublisherErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PublisherError => "publisher_error",
            Self::ClientContractMismatch => "client_contract_mismatch",
            Self::CommunicationError => "communication_error",
        })
    }
}

/// Bounded publisher diagnostics. Response bodies and decoding errors are never retained.
#[derive(Debug, Serialize, thiserror::Error)]
#[error("Publisher {kind}{status_text}{detail}")]
pub struct PublisherError {
    pub kind: PublisherErrorKind,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
    #[serde(skip)]
    status_text: String,
    #[serde(skip)]
    detail: String,
}

impl PublisherError {
    fn new(kind: PublisherErrorKind, status: Option<u16>) -> Self {
        Self {
            kind,
            status,
            error: None,
            message: None,
            status_text: status.map(|s| format!(": HTTP {s}")).unwrap_or_default(),
            detail: String::new(),
        }
    }
}

// Unconstrained Skills data must not swallow a gateway as a successful direct reply.
pub(crate) fn deserialize_direct_data<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.get("status").is_some()
        && (value.get("body").is_some() || value.get("body_base64").is_some())
    {
        return Err(serde::de::Error::custom(
            "publisher gateway requires unwrapping",
        ));
    }
    Ok(value)
}

// Service error fields are diagnostics, but can still contain signed addresses.
fn safe_diagnostic(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let mut result = String::new();
    for word in text.split_whitespace() {
        if !result.is_empty() {
            result.push(' ');
        }
        if word.contains("://") {
            result.push_str("[redacted URL]");
        } else {
            result.extend(word.chars().take(500));
        }
        if result.chars().count() >= 500 {
            break;
        }
    }
    Some(result.chars().take(500).collect())
}

fn publisher_error(status: u16, body: Option<&Value>) -> PublisherError {
    let mut error = PublisherError::new(PublisherErrorKind::PublisherError, Some(status));
    if let Some(body) = body {
        error.error = body.get("error").and_then(safe_diagnostic);
        error.message = body.get("message").and_then(safe_diagnostic);
        for field in [&error.error, &error.message].into_iter().flatten() {
            error.detail.push_str(": ");
            error.detail.push_str(field);
        }
    }
    error
}

fn decode_gateway<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PublisherError> {
    let mismatch = |status| PublisherError::new(PublisherErrorKind::ClientContractMismatch, status);
    let envelope: Value = serde_json::from_slice(bytes).map_err(|_| mismatch(None))?;
    let data = envelope
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| mismatch(None))?;
    let status = data
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| mismatch(None))?;
    let body = data.get("body").ok_or_else(|| mismatch(Some(status)))?;
    let body = match body {
        Value::String(raw) if raw.is_empty() && status == 204 => Ok(Value::Null),
        Value::String(raw) => serde_json::from_str(raw),
        body => Ok(body.clone()),
    };
    if !(200..300).contains(&status) {
        return Err(publisher_error(status, body.as_ref().ok()));
    }
    let body = body.map_err(|_| mismatch(Some(status)))?;
    if body.is_null() && status != 204 {
        return Err(mismatch(Some(status)));
    }
    // Never include serde's error: it may quote a signed URL or another private value.
    serde_json::from_value(body).map_err(|_| mismatch(Some(status)))
}

/// Recover a generated JSON or empty publisher response, without repeating the request.
///
/// Use this around Storage, Skills, and Notes generated calls. Direct replies retain their
/// generated contract; gateway replies use the publisher's inner status (any 2xx).
/// For binary/text download methods use [`publisher_bytes_result`] instead.
///
/// ```no_run
/// # async fn example(client: &seren::Client) -> Result<(), seren::PublisherError> {
/// let notes = seren::publisher_result(client.list_notes(None, None, None, None, None).await).await?;
/// # Ok(())
/// # }
/// ```
pub async fn publisher_result<T, E>(
    result: Result<crate::ResponseValue<T>, crate::Error<E>>,
) -> Result<T, PublisherError>
where
    T: DeserializeOwned,
    E: std::fmt::Debug,
{
    match result {
        Ok(response) => Ok(response.into_inner()),
        Err(crate::Error::InvalidResponsePayload(bytes, _)) => decode_gateway(&bytes),
        Err(crate::Error::UnexpectedResponse(response)) => {
            let status = response.status();
            if status == reqwest::StatusCode::OK {
                let bytes = response.bytes().await.map_err(|_| {
                    PublisherError::new(PublisherErrorKind::CommunicationError, Some(200))
                })?;
                decode_gateway(&bytes)
            } else if status.is_success() {
                Err(PublisherError::new(
                    PublisherErrorKind::ClientContractMismatch,
                    Some(status.as_u16()),
                ))
            } else {
                let body = response.json::<Value>().await.ok();
                Err(publisher_error(status.as_u16(), body.as_ref()))
            }
        }
        Err(crate::Error::ErrorResponse(response)) => {
            Err(publisher_error(response.status().as_u16(), None))
        }
        Err(_) => Err(PublisherError::new(
            PublisherErrorKind::CommunicationError,
            None,
        )),
    }
}

/// Recover exact file bytes from a generated publisher download without retrying.
///
/// Wrap `download_attachment`, `download_thumbnail`, or `skill_md` with this
/// function. Gateway JSON is decoded using `body_base64` or a textual `body`;
/// direct non-JSON binary/text replies pass through. Never log raw responses.
pub async fn publisher_bytes_result<E: std::fmt::Debug>(
    result: Result<crate::ResponseValue<crate::ByteStream>, crate::Error<E>>,
) -> Result<Vec<u8>, PublisherError> {
    let response = match result {
        Ok(response) => response,
        Err(crate::Error::UnexpectedResponse(response)) => {
            return read_raw_bytes(response).await;
        }
        Err(crate::Error::ErrorResponse(response)) => {
            return Err(publisher_error(response.status().as_u16(), None));
        }
        Err(crate::Error::InvalidResponsePayload(_, _)) => {
            return Err(PublisherError::new(
                PublisherErrorKind::ClientContractMismatch,
                None,
            ));
        }
        Err(_) => {
            return Err(PublisherError::new(
                PublisherErrorKind::CommunicationError,
                None,
            ));
        }
    };
    let status = response.status();
    let is_json = json_content_type(response.headers());
    let mut stream = response.into_inner_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.try_next().await.map_err(|_| {
        PublisherError::new(
            PublisherErrorKind::CommunicationError,
            Some(status.as_u16()),
        )
    })? {
        bytes.extend_from_slice(&chunk);
    }
    decode_bytes(status, is_json, &bytes)
}

fn json_content_type(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';').next().is_some_and(|v| {
                v.trim().eq_ignore_ascii_case("application/json")
                    || v.trim().to_ascii_lowercase().ends_with("+json")
            })
        })
}

async fn read_raw_bytes(response: reqwest::Response) -> Result<Vec<u8>, PublisherError> {
    let status = response.status();
    if status.is_success() && status != reqwest::StatusCode::OK {
        return Err(PublisherError::new(
            PublisherErrorKind::ClientContractMismatch,
            Some(status.as_u16()),
        ));
    }
    let is_json = json_content_type(response.headers());
    let bytes = response.bytes().await.map_err(|_| {
        PublisherError::new(
            PublisherErrorKind::CommunicationError,
            Some(status.as_u16()),
        )
    })?;
    decode_bytes(status, is_json, &bytes)
}

fn decode_bytes(
    outer: reqwest::StatusCode,
    is_json: bool,
    bytes: &[u8],
) -> Result<Vec<u8>, PublisherError> {
    if !outer.is_success() {
        let body = serde_json::from_slice::<Value>(bytes).ok();
        return Err(publisher_error(outer.as_u16(), body.as_ref()));
    }
    let envelope = serde_json::from_slice::<Value>(bytes).ok();
    let candidate = envelope.as_ref().and_then(|v| v.get("data"));
    if !is_json && !candidate.is_some_and(|v| v.get("status").is_some()) {
        return Ok(bytes.to_vec());
    }
    let mismatch = |status| PublisherError::new(PublisherErrorKind::ClientContractMismatch, status);
    let data = candidate
        .and_then(Value::as_object)
        .ok_or_else(|| mismatch(Some(outer.as_u16())))?;
    let status = data
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| mismatch(Some(outer.as_u16())))?;
    let body = data.get("body").ok_or_else(|| mismatch(Some(status)))?;
    if !(200..300).contains(&status) {
        let parsed = body
            .as_str()
            .and_then(|v| serde_json::from_str::<Value>(v).ok());
        return Err(publisher_error(
            status,
            Some(parsed.as_ref().unwrap_or(body)),
        ));
    }
    if let Some(encoded) = data.get("body_base64") {
        if !body.is_null() {
            return Err(mismatch(Some(status)));
        }
        return base64::engine::general_purpose::STANDARD
            .decode(encoded.as_str().ok_or_else(|| mismatch(Some(status)))?)
            .map_err(|_| mismatch(Some(status)));
    }
    match body {
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Null if status == 204 => Ok(Vec::new()),
        _ => Err(mismatch(Some(status))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_gateway_fixtures::*;
    use serde_json::json;

    #[test]
    fn failure_kinds_preserve_diagnostic_wire_values() {
        for (kind, wire) in [
            (PublisherErrorKind::PublisherError, "publisher_error"),
            (
                PublisherErrorKind::ClientContractMismatch,
                "client_contract_mismatch",
            ),
            (
                PublisherErrorKind::CommunicationError,
                "communication_error",
            ),
        ] {
            let error = PublisherError::new(kind, Some(409));
            assert_eq!(serde_json::to_value(&error).unwrap()["kind"], wire);
            assert_eq!(kind.to_string(), wire);
            assert_eq!(error.to_string(), format!("Publisher {wire}: HTTP 409"));
        }
    }

    #[test]
    fn all_success_statuses_and_textual_bodies_decode() {
        for status in [200, 201, 202, 204, 299] {
            for body in [
                json!({"data":{"status":"ok"}}),
                json!(r#"{"data":{"status":"ok"}}"#),
            ] {
                let result: crate::SerenStorageDataResponseHealthStatus =
                    decode_gateway(gateway(status, body).as_bytes()).unwrap();
                assert_eq!(result.data.status, "ok");
            }
        }
        for body in [Value::Null, json!("")] {
            decode_gateway::<()>(gateway(204, body.clone()).as_bytes()).unwrap();
            assert!(
                decode_gateway::<crate::SerenStorageDataResponseHealthStatus>(
                    gateway(204, body).as_bytes()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn non_success_statuses_preserve_only_bounded_safe_service_diagnostics() {
        for status in [100, 199, 300, 302, 400, 404, 409, 500, 599] {
            let error = decode_gateway::<()>(gateway(status, json!({"error":"not_found", "message":"Object not found.", "upload_url":SIGNED})).as_bytes()).unwrap_err();
            assert_eq!(error.kind, PublisherErrorKind::PublisherError);
            assert_eq!(error.status, Some(status));
            assert_eq!(error.error.as_deref(), Some("not_found"));
            assert_eq!(error.message.as_deref(), Some("Object not found."));
            assert!(!format!("{error:?} {error}").contains(SIGNED));
        }
        let error = decode_gateway::<()>(gateway(409, json!({"error":SIGNED, "message": format!("refused {SIGNED} {}", "界".repeat(600))})).as_bytes()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("do-not-disclose"));
        assert!(error.message.unwrap().chars().count() <= 500);
    }
    #[test]
    fn malformed_responses_never_echo_payloads() {
        for value in [
            json!({"data":{"status":0,"body":SIGNED}}),
            json!({"data":{"status":600,"body":SIGNED}}),
            json!({"data":{"status":200.5,"body":SIGNED}}),
            json!({"data":{"status":-1,"body":SIGNED}}),
            json!({"data":{"status":"200","body":SIGNED}}),
            json!({"data":{"status":200}}),
            json!({"data":{"status":200,"body":SIGNED}}),
            json!({"data":{"status":200,"body":{"data":{"status":[SIGNED]}}}}),
            json!({"data":{"status":200,"body":null,"body_base64":SIGNED}}),
        ] {
            let error = decode_gateway::<crate::SerenStorageDataResponseHealthStatus>(
                &serde_json::to_vec(&value).unwrap(),
            )
            .unwrap_err();
            assert_eq!(error.kind, PublisherErrorKind::ClientContractMismatch);
            assert!(!format!("{error:?} {error}").contains("do-not-disclose"));
        }
    }
}
