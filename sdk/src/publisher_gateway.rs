//! Recovery for Skills, Notes and other typed publisher calls.

use base64::Engine;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

/// Bounded publisher diagnostics. Response bodies and decoding errors are never retained.
#[derive(Debug, Serialize, thiserror::Error)]
#[error("Publisher {kind}{status_text}{detail}")]
pub struct PublisherError {
    pub kind: &'static str,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub message: Option<String>,
    #[serde(skip)]
    status_text: String,
    #[serde(skip)]
    detail: String,
}

impl From<crate::StoragePublisherError> for PublisherError {
    fn from(error: crate::StoragePublisherError) -> Self {
        let mut detail = String::new();
        for field in [&error.error, &error.message].into_iter().flatten() {
            detail.push_str(": ");
            detail.push_str(field);
        }
        Self {
            kind: error.kind,
            status: error.status,
            status_text: error
                .status
                .map(|s| format!(": HTTP {s}"))
                .unwrap_or_default(),
            error: error.error,
            message: error.message,
            detail,
        }
    }
}

fn failure(kind: &'static str, status: Option<u16>) -> PublisherError {
    crate::StoragePublisherError::new(kind, status).into()
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

/// Recover a generated JSON or empty publisher response, without repeating the request.
///
/// Use this around Skills and Notes generated calls. Direct replies retain their
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
    crate::storage_publisher_result(result)
        .await
        .map_err(Into::into)
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
            return Err(
                crate::storage_gateway::publisher_error(response.status().as_u16(), None).into(),
            );
        }
        Err(crate::Error::InvalidResponsePayload(_, _)) => {
            return Err(failure("client_contract_mismatch", None));
        }
        Err(_) => return Err(failure("communication_error", None)),
    };
    let status = response.status();
    let is_json = json_content_type(response.headers());
    let mut stream = response.into_inner_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|_| failure("communication_error", Some(status.as_u16())))?
    {
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
        return Err(failure("client_contract_mismatch", Some(status.as_u16())));
    }
    let is_json = json_content_type(response.headers());
    let bytes = response
        .bytes()
        .await
        .map_err(|_| failure("communication_error", Some(status.as_u16())))?;
    decode_bytes(status, is_json, &bytes)
}

fn decode_bytes(
    outer: reqwest::StatusCode,
    is_json: bool,
    bytes: &[u8],
) -> Result<Vec<u8>, PublisherError> {
    if !outer.is_success() {
        let body = serde_json::from_slice::<Value>(bytes).ok();
        return Err(crate::storage_gateway::publisher_error(outer.as_u16(), body.as_ref()).into());
    }
    let envelope = serde_json::from_slice::<Value>(bytes).ok();
    let candidate = envelope.as_ref().and_then(|v| v.get("data"));
    if !is_json && !candidate.is_some_and(|v| v.get("status").is_some()) {
        return Ok(bytes.to_vec());
    }
    let mismatch = |status| failure("client_contract_mismatch", status);
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
        return Err(crate::storage_gateway::publisher_error(
            status,
            Some(parsed.as_ref().unwrap_or(body)),
        )
        .into());
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
