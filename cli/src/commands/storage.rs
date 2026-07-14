use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use comfy_table::{Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use reqwest::header::ETAG;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::object_storage::{
    UploadObjectOptions, get_presigned_object, parse_optional_metadata_object, put_presigned_object,
};
use crate::{CommandContext, OutputFormat, output};

#[derive(Serialize)]
struct UploadedObjectOutput {
    object: seren::SerenStorageObjectStorageObject,
    path: String,
}

#[derive(Serialize)]
struct DownloadedObjectOutput {
    object: seren::SerenStorageObjectStorageObject,
    output: String,
    bytes: usize,
}

pub async fn health(ctx: &CommandContext) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_health()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to get Seren Storage health: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let mut table = table_with_header(["Service", "Status"]);
            table.add_row(["Seren Storage", response.data.status.as_str()]);
            println!("{table}");
        }
    }

    Ok(())
}

pub async fn list_buckets(ctx: &CommandContext) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_list_buckets()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage buckets: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_buckets_table(&response.data),
    }

    Ok(())
}

pub async fn list_objects(
    bucket_slug: &str,
    prefix: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_list_objects(bucket_slug, limit, offset, prefix.as_deref())
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage objects: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_objects_table(&response.data),
    }

    Ok(())
}

pub async fn upload_object(
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
        .seren_storage_create_upload(
            bucket_slug,
            &seren::SerenStorageCreateObjectStorageUploadRequest {
                byte_length,
                content_type: Some(content_type),
                metadata,
                object_key,
                sha256: sha256.clone(),
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to create Seren Storage upload: {error}"))?
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
        .seren_storage_confirm_upload(
            bucket_slug,
            &upload.object.id,
            &seren::SerenStorageConfirmObjectStorageUploadRequest {
                byte_length: Some(byte_length),
                etag,
                sha256: Some(sha256),
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to confirm Seren Storage upload: {error}"))?
        .into_inner();

    let result = UploadedObjectOutput {
        object: confirmed.data,
        path: path.display().to_string(),
    };
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => print_object_detail(
            "Uploaded Seren Storage object",
            &result.object,
            Some(&result.path),
        ),
    }

    Ok(())
}

pub async fn download_object(
    bucket_slug: &str,
    object_key: &str,
    output_path: PathBuf,
    ctx: &CommandContext,
) -> Result<()> {
    let download = ctx
        .client()
        .await?
        .seren_storage_download_object(bucket_slug, object_key)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to create Seren Storage download: {error}"))?
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

    let result = DownloadedObjectOutput {
        object: download.object,
        output: output_path.display().to_string(),
        bytes: bytes.len(),
    };
    match ctx.format {
        OutputFormat::Json => output::print_json(&result)?,
        OutputFormat::Table => {
            print_object_detail("Downloaded Seren Storage object", &result.object, None);
            println!("Saved {} bytes to {}", result.bytes, result.output);
        }
    }

    Ok(())
}

pub async fn confirm_object(
    bucket_slug: &str,
    object_id: Uuid,
    sha256: Option<String>,
    byte_length: Option<i64>,
    etag: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_confirm_upload(
            bucket_slug,
            &object_id,
            &seren::SerenStorageConfirmObjectStorageUploadRequest {
                byte_length,
                etag,
                sha256,
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to confirm Seren Storage upload: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_object_detail("Confirmed Seren Storage object", &response.data, None)
        }
    }

    Ok(())
}

pub async fn delete_object(bucket_slug: &str, object_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_delete_object(bucket_slug, &object_id)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to delete Seren Storage object: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_object_detail("Deleted Seren Storage object", &response.data, None)
        }
    }

    Ok(())
}

pub async fn delete_object_by_key(
    bucket_slug: &str,
    object_key: &str,
    ctx: &CommandContext,
) -> Result<()> {
    let client = ctx.client().await?;
    let limit = 100;
    let mut offset = 0;
    let object = loop {
        let response = client
            .seren_storage_list_objects(bucket_slug, Some(limit), Some(offset), Some(object_key))
            .await
            .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage objects: {error}"))?
            .into_inner();

        if let Some(object) = response
            .data
            .into_iter()
            .find(|object| object.object_key == object_key)
        {
            break object;
        }

        let Some(pagination) = response.pagination.filter(|page| page.has_more) else {
            anyhow::bail!(
                "Object '{}' was not found in bucket '{}'",
                object_key,
                bucket_slug
            );
        };
        offset = pagination.offset + pagination.count;
    };

    delete_object(bucket_slug, object.id, ctx).await
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

fn table_with_header<const N: usize>(header: [&str; N]) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header.map(|label| Cell::new(label).fg(Color::Cyan)));
    table
}

fn print_buckets_table(buckets: &[seren::SerenStorageObjectStorageBucket]) {
    if buckets.is_empty() {
        println!("No Seren Storage buckets found");
        return;
    }

    let mut table = table_with_header(["Slug", "Display Name", "Created"]);
    for bucket in buckets {
        table.add_row([
            bucket.slug.as_str(),
            bucket.display_name.as_deref().unwrap_or("-"),
            &bucket.created_at.to_string(),
        ]);
    }
    println!("{table}");
}

fn print_objects_table(objects: &[seren::SerenStorageObjectStorageObject]) {
    if objects.is_empty() {
        println!("No Seren Storage objects found");
        return;
    }

    let mut table = table_with_header(["ID", "Key", "Status", "Bytes", "Content Type"]);
    for object in objects {
        table.add_row([
            object.id.to_string(),
            object.object_key.clone(),
            object.status.clone(),
            object.byte_length.to_string(),
            object.content_type.clone(),
        ]);
    }
    println!("{table}");
}

fn print_object_detail(
    title: &str,
    object: &seren::SerenStorageObjectStorageObject,
    path: Option<&str>,
) {
    println!("{title}");
    let mut table = table_with_header(["Field", "Value"]);
    table.add_row(["ID".to_string(), object.id.to_string()]);
    table.add_row(["Bucket".to_string(), object.bucket_slug.clone()]);
    table.add_row(["Key".to_string(), object.object_key.clone()]);
    table.add_row(["Status".to_string(), object.status.clone()]);
    table.add_row(["Bytes".to_string(), object.byte_length.to_string()]);
    table.add_row(["Content Type".to_string(), object.content_type.clone()]);
    if let Some(path) = path {
        table.add_row(["Local Path".to_string(), path.to_string()]);
    }
    println!("{table}");
}
