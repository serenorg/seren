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
    cursor: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_list_objects(
            bucket_slug,
            cursor.as_deref(),
            None,
            limit,
            prefix.as_deref(),
            None,
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage objects: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_objects_table(&response.data.objects);
            if let Some(next_cursor) = &response.data.next_cursor {
                println!("More objects available. Continue with --cursor {next_cursor}");
            }
        }
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
                checksum: seren::SerenStorageObjectStorageChecksum {
                    algorithm: seren::SerenStorageObjectStorageChecksumAlgorithm::Sha256,
                    value: sha256,
                },
                content_type: Some(content_type),
                metadata,
                object_key,
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
            &seren::SerenStorageConfirmObjectStorageUploadRequest { etag },
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
    etag: Option<String>,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_confirm_upload(
            bucket_slug,
            &object_id,
            &seren::SerenStorageConfirmObjectStorageUploadRequest { etag },
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
    let mut cursor: Option<String> = None;
    let object = loop {
        let page = client
            .seren_storage_list_objects(
                bucket_slug,
                cursor.as_deref(),
                None,
                Some(limit),
                Some(object_key),
                None,
            )
            .await
            .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage objects: {error}"))?
            .into_inner()
            .data;

        if let Some(object) = page
            .objects
            .into_iter()
            .find(|object| object.object_key == object_key)
        {
            break object;
        }

        let Some(next_cursor) = page.next_cursor.filter(|value| !value.is_empty()) else {
            anyhow::bail!(
                "Object '{}' was not found in bucket '{}'",
                object_key,
                bucket_slug
            );
        };
        if cursor.as_deref() == Some(next_cursor.as_str()) {
            anyhow::bail!("Seren Storage returned a repeated pagination cursor");
        }
        cursor = Some(next_cursor);
    };

    delete_object(bucket_slug, object.id, ctx).await
}

pub async fn list_grants(bucket_slug: &str, ctx: &CommandContext) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_list_bucket_agent_grants(bucket_slug)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage agent grants: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_grants_table(&response.data),
    }

    Ok(())
}

pub async fn set_grant(
    bucket_slug: &str,
    agent_identity_id: Uuid,
    permission: seren::SerenStorageObjectStorageAgentPermission,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_put_bucket_agent_grant(
            bucket_slug,
            &agent_identity_id,
            &seren::SerenStoragePutObjectStorageBucketAgentGrantRequest { permission },
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to set Seren Storage agent grant: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_grant_detail("Set Seren Storage agent grant", &response.data),
    }

    Ok(())
}

pub async fn revoke_grant(
    bucket_slug: &str,
    agent_identity_id: Uuid,
    ctx: &CommandContext,
) -> Result<()> {
    ctx.client()
        .await?
        .seren_storage_delete_bucket_agent_grant(bucket_slug, &agent_identity_id)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to revoke Seren Storage agent grant: {error}"))?;

    match ctx.format {
        OutputFormat::Json => {
            output::print_json(&serde_json::json!({ "revoked": agent_identity_id }))?
        }
        OutputFormat::Table => {
            println!("Revoked Seren Storage agent grant for {agent_identity_id} on {bucket_slug}")
        }
    }

    Ok(())
}

pub async fn list_snapshots(
    bucket_slug: &str,
    deployment_id: Uuid,
    limit: Option<i64>,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_list_workspace_snapshots(bucket_slug, &deployment_id, limit)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list Seren Storage snapshots: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_snapshots_table(&response.data),
    }

    Ok(())
}

pub async fn latest_snapshot(
    bucket_slug: &str,
    deployment_id: Uuid,
    output_path: Option<PathBuf>,
    ctx: &CommandContext,
) -> Result<()> {
    let download = ctx
        .client()
        .await?
        .seren_storage_latest_workspace_snapshot(bucket_slug, &deployment_id)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to fetch latest Seren Storage snapshot: {error}"))?
        .into_inner()
        .data;

    if let Some(output_path) = output_path {
        let bytes =
            get_presigned_object(&download.download_url, &download.download_headers).await?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .with_context(|| format!("Failed to create {}", output_path.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;
        match ctx.format {
            OutputFormat::Json => output::print_json(&download.snapshot)?,
            OutputFormat::Table => {
                print_snapshot_detail("Downloaded latest workspace snapshot", &download.snapshot);
                println!("Saved {} bytes to {}", bytes.len(), output_path.display());
            }
        }
    } else {
        match ctx.format {
            OutputFormat::Json => output::print_json(&download)?,
            OutputFormat::Table => {
                print_snapshot_detail("Latest workspace snapshot", &download.snapshot);
                println!("Download URL expires at {}", download.download_expires_at);
            }
        }
    }

    Ok(())
}

pub struct CreateSnapshotOptions {
    pub deployment_id: Uuid,
    pub object_id: Uuid,
    pub archive_sha256: String,
    pub file_count: i64,
    pub uncompressed_bytes: i64,
    pub retention_count: Option<i32>,
}

pub async fn create_snapshot(
    bucket_slug: &str,
    options: CreateSnapshotOptions,
    ctx: &CommandContext,
) -> Result<()> {
    let response = ctx
        .client()
        .await?
        .seren_storage_create_workspace_snapshot(
            bucket_slug,
            &seren::SerenStorageCreateObjectStorageWorkspaceSnapshotRequest {
                archive_sha256: options.archive_sha256,
                deployment_id: options.deployment_id,
                file_count: options.file_count,
                object_id: options.object_id,
                retention_count: options.retention_count,
                uncompressed_bytes: options.uncompressed_bytes,
            },
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to create Seren Storage snapshot: {error}"))?
        .into_inner();

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => print_snapshot_detail("Created workspace snapshot", &response.data),
    }

    Ok(())
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
            object.status.to_string(),
            object.byte_length.to_string(),
            object.content_type.clone(),
        ]);
    }
    println!("{table}");
}

fn print_grants_table(grants: &[seren::SerenStorageObjectStorageBucketAgentGrant]) {
    if grants.is_empty() {
        println!("No Seren Storage agent grants found");
        return;
    }

    let mut table = table_with_header(["Agent Identity", "Permission", "Updated"]);
    for grant in grants {
        table.add_row([
            grant.agent_identity_id.to_string(),
            grant.permission.to_string(),
            grant.updated_at.to_string(),
        ]);
    }
    println!("{table}");
}

fn print_grant_detail(title: &str, grant: &seren::SerenStorageObjectStorageBucketAgentGrant) {
    println!("{title}");
    let mut table = table_with_header(["Field", "Value"]);
    table.add_row(["Bucket".to_string(), grant.bucket_slug.clone()]);
    table.add_row([
        "Agent Identity".to_string(),
        grant.agent_identity_id.to_string(),
    ]);
    table.add_row(["Permission".to_string(), grant.permission.to_string()]);
    println!("{table}");
}

fn print_snapshots_table(snapshots: &[seren::SerenStorageObjectStorageWorkspaceSnapshot]) {
    if snapshots.is_empty() {
        println!("No Seren Storage workspace snapshots found");
        return;
    }

    let mut table = table_with_header(["ID", "Status", "Files", "Bytes", "Created"]);
    for snapshot in snapshots {
        table.add_row([
            snapshot.id.to_string(),
            snapshot.status.to_string(),
            snapshot.file_count.to_string(),
            snapshot.uncompressed_bytes.to_string(),
            snapshot.created_at.to_string(),
        ]);
    }
    println!("{table}");
}

fn print_snapshot_detail(
    title: &str,
    snapshot: &seren::SerenStorageObjectStorageWorkspaceSnapshot,
) {
    println!("{title}");
    let mut table = table_with_header(["Field", "Value"]);
    table.add_row(["ID".to_string(), snapshot.id.to_string()]);
    table.add_row(["Bucket".to_string(), snapshot.bucket_slug.clone()]);
    table.add_row(["Deployment".to_string(), snapshot.deployment_id.to_string()]);
    table.add_row(["Status".to_string(), snapshot.status.to_string()]);
    table.add_row(["Files".to_string(), snapshot.file_count.to_string()]);
    table.add_row([
        "Uncompressed Bytes".to_string(),
        snapshot.uncompressed_bytes.to_string(),
    ]);
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
    table.add_row(["Status".to_string(), object.status.to_string()]);
    table.add_row(["Bytes".to_string(), object.byte_length.to_string()]);
    table.add_row(["Content Type".to_string(), object.content_type.clone()]);
    if let Some(path) = path {
        table.add_row(["Local Path".to_string(), path.to_string()]);
    }
    println!("{table}");
}
