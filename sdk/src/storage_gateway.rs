//! Typed recovery of Seren Storage replies carried by Core's publisher gateway.

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// A Storage failure containing only safe diagnostics, never a response body.
#[derive(Debug, Serialize, thiserror::Error)]
#[error("Seren Storage {kind}{status_text}{detail}")]
pub struct StoragePublisherError {
    pub kind: &'static str,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
    #[serde(skip)]
    status_text: String,
    #[serde(skip)]
    detail: String,
}

impl StoragePublisherError {
    fn new(kind: &'static str, status: Option<u16>) -> Self {
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

fn publisher_error(status: u16, body: Option<&Value>) -> StoragePublisherError {
    let mut error = StoragePublisherError::new("publisher_error", Some(status));
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

fn decode_gateway<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, StoragePublisherError> {
    let mismatch = |status| StoragePublisherError::new("client_contract_mismatch", status);
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

/// Accept a generated direct reply or decode a valid HTTP-200 gateway envelope.
/// Undocumented direct success statuses remain contract mismatches. No request is retried.
pub async fn storage_publisher_result<T, E>(
    result: Result<crate::ResponseValue<T>, crate::Error<E>>,
) -> Result<T, StoragePublisherError>
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
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|_| StoragePublisherError::new("communication_error", Some(200)))?;
                decode_gateway(&bytes)
            } else if status.is_success() {
                Err(StoragePublisherError::new(
                    "client_contract_mismatch",
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
        Err(_) => Err(StoragePublisherError::new("communication_error", None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_gateway_fixtures::*;
    use serde_json::json;

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
            assert_eq!(error.kind, "publisher_error");
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
            assert_eq!(error.kind, "client_contract_mismatch");
            assert!(!format!("{error:?} {error}").contains("do-not-disclose"));
        }
    }
}
