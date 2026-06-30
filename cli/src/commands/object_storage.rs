use std::{fs, io::Write, path::PathBuf};

use anyhow::{Context, Result};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use reqwest::header::{CONTENT_LENGTH, ETAG, HeaderName, HeaderValue};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CommandContext, OutputFormat, output};

pub struct UploadObjectOptions {
    pub object_key: String,
    pub path: PathBuf,
    pub content_type: Option<String>,
    pub metadata_json: Option<String>,
    pub metadata_file: Option<PathBuf>,
}

pub async fn list_buckets(org_id: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .list_object_storage_buckets(org_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list object storage buckets: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_buckets_table(&response.data),
    }

    Ok(())
}

pub async fn create_bucket(
    org_id: &str,
    slug: String,
    display_name: Option<String>,
    metadata_json: Option<String>,
    metadata_file: Option<PathBuf>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let metadata =
        parse_optional_metadata_object(metadata_json.as_deref(), metadata_file.as_ref())?;
    let request = seren::CreateObjectStorageBucketRequest {
        slug,
        display_name,
        metadata,
    };
    let response = client
        .create_object_storage_bucket(org_id, &request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create object storage bucket: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_bucket_detail("Created object storage bucket", &response.data),
    }

    Ok(())
}

pub async fn delete_bucket(org_id: &str, bucket_slug: &str, ctx: &CommandContext) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .delete_object_storage_bucket(org_id, bucket_slug)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete object storage bucket: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_bucket_detail("Deleted object storage bucket", &response.data),
    }

    Ok(())
}

pub async fn list_objects(
    org_id: &str,
    bucket_slug: &str,
    prefix: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .list_object_storage_objects(org_id, bucket_slug, limit, offset, prefix.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list object storage objects: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_objects_table(&response.data),
    }

    Ok(())
}

pub async fn upload_object(
    org_id: &str,
    bucket_slug: &str,
    options: UploadObjectOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let UploadObjectOptions {
        object_key,
        path,
        content_type,
        metadata_json,
        metadata_file,
    } = options;
    let bytes = fs::read(&path).with_context(|| format!("Failed to read {}", path.display()))?;
    let byte_length = i64::try_from(bytes.len()).context("Object is too large to upload")?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let metadata =
        parse_optional_metadata_object(metadata_json.as_deref(), metadata_file.as_ref())?;
    let content_type = content_type.unwrap_or_else(|| "application/octet-stream".to_string());

    let client = ctx.client().await?;
    let upload = client
        .create_object_storage_upload(
            org_id,
            bucket_slug,
            &seren::CreateObjectStorageUploadRequest {
                byte_length,
                content_type: Some(content_type.clone()),
                metadata,
                object_key,
                sha256: sha256.clone(),
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create object storage upload: {}", e))?
        .into_inner()
        .data;

    let put_response =
        put_presigned_object(&upload.upload_url, &upload.upload_headers, bytes).await?;
    let etag = put_response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty());

    let confirmed = client
        .confirm_object_storage_upload(
            org_id,
            bucket_slug,
            &upload.object.id,
            &seren::ConfirmObjectStorageUploadRequest {
                byte_length: Some(byte_length),
                etag,
                sha256: Some(sha256),
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to confirm object storage upload: {}", e))?
        .into_inner();

    let output = UploadedObjectOutput {
        object: confirmed.data,
        path: path.display().to_string(),
    };
    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => print_object_detail(
            "Uploaded object storage object",
            &output.object,
            Some(&output.path),
        ),
    }

    Ok(())
}

pub async fn download_object(
    org_id: &str,
    bucket_slug: &str,
    object_key: &str,
    output_path: PathBuf,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let download = client
        .download_object_storage_object(org_id, bucket_slug, object_key)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create object storage download: {}", e))?
        .into_inner()
        .data;

    let bytes = get_presigned_object(&download.download_url, &download.download_headers).await?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    let output = DownloadedObjectOutput {
        object: download.object,
        output: output_path.display().to_string(),
        bytes: bytes.len(),
    };

    match ctx.format {
        OutputFormat::Json => output::print_json(&output)?,
        OutputFormat::Table => print_download_detail(&output),
    }

    Ok(())
}

pub async fn confirm_object(
    org_id: &str,
    bucket_slug: &str,
    object_id: Uuid,
    sha256: Option<String>,
    byte_length: Option<i64>,
    etag: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .confirm_object_storage_upload(
            org_id,
            bucket_slug,
            &object_id,
            &seren::ConfirmObjectStorageUploadRequest {
                byte_length,
                etag,
                sha256,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to confirm object storage upload: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_object_detail("Confirmed object storage object", &response.data, None)
        }
    }

    Ok(())
}

pub async fn delete_object(
    org_id: &str,
    bucket_slug: &str,
    object_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let response = client
        .delete_object_storage_object(org_id, bucket_slug, &object_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete object storage object: {}", e))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_object_detail("Deleted object storage object", &response.data, None)
        }
    }

    Ok(())
}

async fn put_presigned_object(
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

async fn get_presigned_object(
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

fn parse_optional_metadata_object(
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

fn print_buckets_table(buckets: &[seren::ObjectStorageBucket]) {
    if buckets.is_empty() {
        println!("No object storage buckets found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Slug").fg(Color::Green),
        Cell::new("Display Name").fg(Color::Green),
        Cell::new("Bucket ID").fg(Color::Green),
        Cell::new("Updated").fg(Color::Green),
    ]);
    for bucket in buckets {
        table.add_row(vec![
            Cell::new(&bucket.slug),
            Cell::new(bucket.display_name.as_deref().unwrap_or("-")),
            Cell::new(bucket.id.to_string()),
            Cell::new(bucket.updated_at.to_string()),
        ]);
    }
    println!("{table}");
}

fn print_objects_table(objects: &[seren::ObjectStorageObject]) {
    if objects.is_empty() {
        println!("No object storage objects found");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        Cell::new("Key").fg(Color::Green),
        Cell::new("Object ID").fg(Color::Green),
        Cell::new("Status").fg(Color::Green),
        Cell::new("Bytes").fg(Color::Green),
        Cell::new("Content Type").fg(Color::Green),
        Cell::new("Updated").fg(Color::Green),
    ]);
    for object in objects {
        table.add_row(vec![
            Cell::new(&object.object_key),
            Cell::new(object.id.to_string()),
            Cell::new(&object.status),
            Cell::new(object.byte_length.to_string()),
            Cell::new(&object.content_type),
            Cell::new(object.updated_at.to_string()),
        ]);
    }
    println!("{table}");
}

fn print_bucket_detail(title: &str, bucket: &seren::ObjectStorageBucket) {
    output::print_key_value_table(
        Some(title),
        &[
            ("Bucket ID", bucket.id.to_string()),
            ("Organization ID", bucket.organization_id.to_string()),
            ("Slug", bucket.slug.clone()),
            (
                "Display Name",
                bucket
                    .display_name
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("Created At", bucket.created_at.to_string()),
            ("Updated At", bucket.updated_at.to_string()),
        ],
    );
}

fn print_object_detail(title: &str, object: &seren::ObjectStorageObject, path: Option<&str>) {
    let mut rows = vec![
        ("Object ID", object.id.to_string()),
        ("Organization ID", object.organization_id.to_string()),
        ("Bucket", object.bucket_slug.clone()),
        ("Key", object.object_key.clone()),
        ("URI", object.uri.clone()),
        ("Status", object.status.clone()),
        ("Bytes", object.byte_length.to_string()),
        ("Content Type", object.content_type.clone()),
        ("SHA-256", object.sha256.clone()),
        ("Updated At", object.updated_at.to_string()),
    ];
    if let Some(path) = path {
        rows.push(("Path", path.to_string()));
    }
    output::print_key_value_table(Some(title), &rows);
}

fn print_download_detail(output: &DownloadedObjectOutput) {
    output::print_key_value_table(
        Some("Downloaded object storage object"),
        &[
            ("Object ID", output.object.id.to_string()),
            ("Bucket", output.object.bucket_slug.clone()),
            ("Key", output.object.object_key.clone()),
            ("Bytes", output.bytes.to_string()),
            ("Output", output.output.clone()),
        ],
    );
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
}

#[derive(Debug, Serialize)]
struct UploadedObjectOutput {
    object: seren::ObjectStorageObject,
    path: String,
}

#[derive(Debug, Serialize)]
struct DownloadedObjectOutput {
    object: seren::ObjectStorageObject,
    output: String,
    bytes: usize,
}
