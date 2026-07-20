use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use reqwest::header::{CONTENT_LENGTH, HeaderName, HeaderValue};

pub struct UploadObjectOptions {
    pub object_key: String,
    pub path: PathBuf,
    pub content_type: Option<String>,
    pub metadata_json: Option<String>,
    pub metadata_file: Option<PathBuf>,
}

pub fn resolve_bucket_prefix(
    bucket: Option<&str>,
    target: Option<&str>,
    prefix: Option<&str>,
) -> Result<(String, Option<String>)> {
    let Some(target) = target else {
        let bucket = bucket.ok_or_else(|| {
            anyhow::anyhow!("Bucket is required. Pass --bucket or a bucket[/prefix] target.")
        })?;
        return Ok((bucket.to_string(), prefix.map(str::to_string)));
    };

    if let Some(bucket) = bucket {
        let prefix = prefix
            .map(str::to_string)
            .or_else(|| (!target.is_empty()).then(|| target.to_string()));
        return Ok((bucket.to_string(), prefix));
    }

    let (target_bucket, target_prefix) = split_bucket_target(target)?;
    if prefix.is_some() && target_prefix.is_some() {
        anyhow::bail!("Pass the prefix either in the target or with --prefix, not both.");
    }

    Ok((target_bucket, prefix.map(str::to_string).or(target_prefix)))
}

pub fn resolve_bucket_key(
    bucket: Option<&str>,
    target: Option<&str>,
    key: Option<&str>,
) -> Result<(String, String)> {
    if target.is_some() && key.is_some() {
        anyhow::bail!("Pass the object key either as a target or with --key, not both.");
    }

    if let Some(key) = key {
        let bucket = bucket.ok_or_else(|| {
            anyhow::anyhow!("Bucket is required when --key is used. Pass --bucket.")
        })?;
        ensure_non_empty_key(key)?;
        return Ok((bucket.to_string(), key.to_string()));
    }

    let target = target.ok_or_else(|| {
        anyhow::anyhow!("Object target is required. Pass bucket/key or use --bucket with --key.")
    })?;

    if let Some(bucket) = bucket {
        ensure_non_empty_key(target)?;
        return Ok((bucket.to_string(), target.to_string()));
    }

    let (bucket, key) = split_bucket_target(target)?;
    let key =
        key.ok_or_else(|| anyhow::anyhow!("Object target must include a key: bucket/key."))?;
    ensure_non_empty_key(&key)?;
    Ok((bucket, key))
}

pub fn resolve_bucket_for_object_id(bucket: Option<&str>, target: Option<&str>) -> Result<String> {
    match (bucket, target) {
        (Some(bucket), None) => Ok(bucket.to_string()),
        (None, Some(target)) if !target.contains('/') => Ok(target.to_string()),
        (Some(_), Some(_)) => {
            anyhow::bail!("Pass the bucket either with --bucket or as the target, not both.")
        }
        (None, Some(_)) => anyhow::bail!("Object ID deletion target must be a bucket slug."),
        (None, None) => anyhow::bail!("Bucket is required. Pass --bucket or a bucket target."),
    }
}

pub fn resolve_download_output(key: &str, output: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(output) = output {
        return Ok(output);
    }

    Path::new(key)
        .file_name()
        .filter(|name| !name.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!("Could not infer output path from object key. Pass --output.")
        })
}

fn split_bucket_target(target: &str) -> Result<(String, Option<String>)> {
    let target = target.trim_matches('/');
    if target.is_empty() {
        anyhow::bail!("Target must not be empty.");
    }

    if let Some((bucket, rest)) = target.split_once('/') {
        if bucket.is_empty() {
            anyhow::bail!("Target bucket must not be empty.");
        }
        let rest = (!rest.is_empty()).then(|| rest.to_string());
        Ok((bucket.to_string(), rest))
    } else {
        Ok((target.to_string(), None))
    }
}

fn ensure_non_empty_key(key: &str) -> Result<()> {
    if key.trim_matches('/').is_empty() {
        anyhow::bail!("Object key must not be empty.");
    }
    Ok(())
}

pub(crate) async fn put_presigned_object(
    url: &str,
    headers: &std::collections::HashMap<String, String>,
    bytes: Vec<u8>,
) -> Result<reqwest::Response> {
    let mut request = reqwest::Client::new().put(url).body(bytes);
    for (name, value) in headers {
        if should_replay_upload_header(name) {
            request = request.header(header_name(name)?, header_value(name, value)?);
        }
    }
    let response = request.send().await.context("Failed to upload object")?;
    ensure_success(response, "upload object").await
}

fn should_replay_upload_header(name: &str) -> bool {
    !name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
}

pub(crate) async fn get_presigned_object(
    url: &str,
    headers: &std::collections::HashMap<String, String>,
) -> Result<Vec<u8>> {
    let mut request = reqwest::Client::new().get(url);
    for (name, value) in headers {
        request = request.header(header_name(name)?, header_value(name, value)?);
    }
    let response = request.send().await.context("Failed to download object")?;
    let response = ensure_success(response, "download object").await?;
    Ok(response
        .bytes()
        .await
        .context("Failed to read downloaded object")?
        .to_vec())
}

async fn ensure_success(response: reqwest::Response, operation: &str) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<failed to read response body>".to_string());
    anyhow::bail!("Failed to {operation}: upstream returned {status}: {body}");
}

fn header_name(name: &str) -> Result<HeaderName> {
    HeaderName::from_bytes(name.as_bytes())
        .with_context(|| format!("Invalid presigned header name '{name}'"))
}

fn header_value(name: &str, value: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(value)
        .with_context(|| format!("Invalid presigned header value for '{name}'"))
}

pub(crate) fn parse_optional_metadata_object(
    metadata_json: Option<&str>,
    metadata_file: Option<&PathBuf>,
) -> Result<Option<serde_json::Value>> {
    let value = match (metadata_json, metadata_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("Use either --metadata or --metadata-file, not both");
        }
        (Some(raw), None) => Some(
            serde_json::from_str::<serde_json::Value>(raw).context("Invalid --metadata JSON")?,
        ),
        (None, Some(path)) => {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Some(
                serde_json::from_str::<serde_json::Value>(&raw)
                    .with_context(|| format!("Invalid JSON in {}", path.display()))?,
            )
        }
        (None, None) => None,
    };

    match value {
        Some(serde_json::Value::Object(_)) => Ok(value),
        Some(_) => anyhow::bail!("Object storage metadata must be a JSON object"),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_header_replay_skips_content_length() {
        assert!(!should_replay_upload_header("content-length"));
        assert!(!should_replay_upload_header("Content-Length"));
        assert!(should_replay_upload_header("x-amz-checksum-sha256"));
        assert!(should_replay_upload_header("x-amz-server-side-encryption"));
    }

    #[test]
    fn resolve_bucket_key_accepts_bucket_key_target() {
        let (bucket, key) = resolve_bucket_key(None, Some("assets/reports/q1.txt"), None).unwrap();
        assert_eq!(bucket, "assets");
        assert_eq!(key, "reports/q1.txt");
    }

    #[test]
    fn resolve_bucket_key_uses_parent_bucket_for_plain_target() {
        let (bucket, key) =
            resolve_bucket_key(Some("assets"), Some("reports/q1.txt"), None).unwrap();
        assert_eq!(bucket, "assets");
        assert_eq!(key, "reports/q1.txt");
    }

    #[test]
    fn resolve_bucket_prefix_rejects_duplicate_prefix_sources() {
        let err = resolve_bucket_prefix(None, Some("assets/reports"), Some("other")).unwrap_err();
        assert!(
            err.to_string()
                .contains("either in the target or with --prefix")
        );
    }
}
