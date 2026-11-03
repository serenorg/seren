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
    let response = storage_gateway_data(
        ctx.client().await?.seren_storage_health().await,
        "Failed to get Seren Storage health",
    )
    .await?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            let mut table = table_with_header(["Service", "Status"]);
            table.add_row(["Seren Storage", response.data.status.as_str()]);
            output::print_table(&mut table);
        }
    }

    Ok(())
}

pub async fn list_buckets(ctx: &CommandContext) -> Result<()> {
    let response = storage_gateway_data(
        ctx.client().await?.seren_storage_list_buckets().await,
        "Failed to list Seren Storage buckets",
    )
    .await?;

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
    let response = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_list_objects(
                bucket_slug,
                cursor.as_deref(),
                None,
                limit,
                prefix.as_deref(),
                None,
            )
            .await,
        "Failed to list Seren Storage objects",
    )
    .await?;

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
    let upload = storage_gateway_data(
        client
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
            .await,
        "Failed to create Seren Storage upload",
    )
    .await?
    .data;

    let put_response = put_presigned_object(&upload.upload_url, &upload.upload_headers, bytes)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to upload Seren Storage object"))?;
    let etag = put_response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty());

    let confirmed = storage_gateway_data(
        client
            .seren_storage_confirm_upload(
                bucket_slug,
                &upload.object.id,
                &seren::SerenStorageConfirmObjectStorageUploadRequest { etag },
            )
            .await,
        "Failed to confirm Seren Storage upload",
    )
    .await?;

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
    let download = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_download_object(bucket_slug, object_key)
            .await,
        "Failed to create Seren Storage download",
    )
    .await?
    .data;

    let bytes = get_presigned_object(&download.download_url, &download.download_headers)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to download Seren Storage object"))?;
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
    let response = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_confirm_upload(
                bucket_slug,
                &object_id,
                &seren::SerenStorageConfirmObjectStorageUploadRequest { etag },
            )
            .await,
        "Failed to confirm Seren Storage upload",
    )
    .await?;

    match ctx.format {
        OutputFormat::Json => output::print_json(&response)?,
        OutputFormat::Table => {
            print_object_detail("Confirmed Seren Storage object", &response.data, None)
        }
    }

    Ok(())
}

pub async fn delete_object(bucket_slug: &str, object_id: Uuid, ctx: &CommandContext) -> Result<()> {
    let response = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_delete_object(bucket_slug, &object_id)
            .await,
        "Failed to delete Seren Storage object",
    )
    .await?;

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
        let page = storage_gateway_data(
            client
                .seren_storage_list_objects(
                    bucket_slug,
                    cursor.as_deref(),
                    None,
                    Some(limit),
                    Some(object_key),
                    None,
                )
                .await,
            "Failed to list Seren Storage objects",
        )
        .await?
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
    let response = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_list_bucket_agent_grants(bucket_slug)
            .await,
        "Failed to list Seren Storage agent grants",
    )
    .await?;

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
    let response = storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_put_bucket_agent_grant(
                bucket_slug,
                &agent_identity_id,
                &seren::SerenStoragePutObjectStorageBucketAgentGrantRequest { permission },
            )
            .await,
        "Failed to set Seren Storage agent grant",
    )
    .await?;

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
    storage_gateway_data(
        ctx.client()
            .await?
            .seren_storage_delete_bucket_agent_grant(bucket_slug, &agent_identity_id)
            .await,
        "Failed to revoke Seren Storage agent grant",
    )
    .await?;

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
        .load_style(UTF8_FULL)
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
    output::print_table(&mut table);
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
    output::print_table(&mut table);
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
    output::print_table(&mut table);
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
    output::print_table(&mut table);
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
    output::print_table(&mut table);
}

async fn storage_gateway_data<T: serde::de::DeserializeOwned, E: std::fmt::Debug>(
    result: Result<seren::ResponseValue<T>, seren::Error<E>>,
    context: &'static str,
) -> Result<T> {
    seren::publisher_result(result).await.context(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_bytes, header, method, path},
    };
    #[allow(dead_code)]
    mod fixtures {
        include!("../../../sdk/src/storage_gateway_fixtures.rs");
    }
    use fixtures::*;

    async fn command(name: &str, ctx: &CommandContext, dir: &Path) -> Result<()> {
        let id = ID.parse().unwrap();
        match name {
            "health" => health(ctx).await,
            "list_buckets" => list_buckets(ctx).await,
            "list_objects" => list_objects("files", None, None, None, ctx).await,
            "create_upload" => {
                upload_object(
                    "files",
                    UploadObjectOptions {
                        object_key: KEY.into(),
                        path: dir.join("input"),
                        content_type: Some("application/json".into()),
                        metadata_json: None,
                        metadata_file: None,
                    },
                    ctx,
                )
                .await
            }
            "confirm_upload" => confirm_object("files", id, Some("verified".into()), ctx).await,
            "download_object" => download_object("files", KEY, dir.join("output"), ctx).await,
            "delete_object" => delete_object("files", id, ctx).await,
            "delete_by_key" => delete_object_by_key("files", KEY, ctx).await,
            "list_bucket_agent_grants" => list_grants("files", ctx).await,
            "put_bucket_agent_grant" => {
                set_grant(
                    "files",
                    id,
                    seren::SerenStorageObjectStorageAgentPermission::Writer,
                    ctx,
                )
                .await
            }
            "delete_bucket_agent_grant" => revoke_grant("files", id, ctx).await,
            _ => panic!("unknown command {name}"),
        }
    }
    fn context(proxy: &MockServer, format: OutputFormat) -> CommandContext {
        CommandContext::new(Some(proxy.uri()), Some("storage-test".into()), format)
    }
    #[tokio::test]
    async fn every_storage_command_decodes_gateway_and_direct_success() {
        for wrapped in [true, false] {
            for format in [OutputFormat::Json, OutputFormat::Table] {
                let proxy = MockServer::start().await;
                let dir = tempfile::tempdir().unwrap();
                fs::write(dir.path().join("input"), CONTENT).unwrap();
                for case in cases(&proxy.uri()) {
                    let response = if wrapped {
                        ResponseTemplate::new(200)
                            .set_body_raw(gateway(case.status, case.body), "application/json")
                    } else if case.status == 204 {
                        ResponseTemplate::new(204)
                    } else {
                        ResponseTemplate::new(case.status).set_body_json(case.body)
                    };
                    Mock::given(method(case.method))
                        .and(path(format!("/publishers/seren-storage{}", case.route)))
                        .and(header("authorization", "Bearer storage-test"))
                        .respond_with(response)
                        .mount(&proxy)
                        .await;
                }
                Mock::given(method("PUT"))
                    .and(path("/signed-upload"))
                    .and(header("x-storage-fixture", "required"))
                    .and(body_bytes(CONTENT))
                    .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"verified\""))
                    .expect(1)
                    .mount(&proxy)
                    .await;
                Mock::given(method("GET"))
                    .and(path("/signed-download"))
                    .and(header("x-storage-fixture", "required"))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(CONTENT))
                    .expect(1)
                    .mount(&proxy)
                    .await;
                let ctx = context(&proxy, format);
                for name in [
                    "health",
                    "list_buckets",
                    "list_objects",
                    "create_upload",
                    "confirm_upload",
                    "download_object",
                    "delete_object",
                    "delete_by_key",
                    "list_bucket_agent_grants",
                    "put_bucket_agent_grant",
                    "delete_bucket_agent_grant",
                ] {
                    command(name, &ctx, dir.path())
                        .await
                        .unwrap_or_else(|e| panic!("{name} wrapped={wrapped}: {e:#}"));
                }
                assert_eq!(fs::read(dir.path().join("output")).unwrap(), CONTENT);
                let requests = proxy.received_requests().await.unwrap();
                assert_eq!(requests.len(), 15);
                let confirms: Vec<_> = requests
                    .iter()
                    .filter(|r| r.url.path().ends_with("confirm-upload"))
                    .collect();
                assert_eq!(
                    confirms.len(),
                    2,
                    "both upload and explicit confirm must finish"
                );
                for confirm in confirms {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&confirm.body).unwrap(),
                        json!({"etag":"verified"})
                    );
                }
                let create = requests
                    .iter()
                    .find(|r| r.url.path().ends_with("/uploads"))
                    .unwrap();
                let create: Value = serde_json::from_slice(&create.body).unwrap();
                assert_eq!(
                    create["checksum"]["value"],
                    hex::encode(Sha256::digest(CONTENT))
                );
                proxy.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn every_storage_command_reports_publisher_errors() {
        for case in cases("https://objects.invalid")
            .into_iter()
            .filter(|c| c.tool != "download_object_by_id")
        {
            for status in [404, 409] {
                let proxy = MockServer::start().await;
                Mock::given(method(case.method)).and(path(format!("/publishers/seren-storage{}", case.route)))
                    .respond_with(ResponseTemplate::new(200).set_body_raw(gateway(status, json!({"error":"storage_error", "message":"Object storage key already exists."})), "application/json"))
                    .expect(1).mount(&proxy).await;
                let dir = tempfile::tempdir().unwrap();
                fs::write(dir.path().join("input"), CONTENT).unwrap();
                let error = command(case.tool, &context(&proxy, OutputFormat::Json), dir.path())
                    .await
                    .unwrap_err();
                let text = format!("{error:#}");
                assert!(text.contains(&format!("HTTP {status}")), "{text}");
                assert!(
                    text.contains("storage_error: Object storage key already exists."),
                    "{text}"
                );
                assert!(!text.contains("Invalid response payload"));
                proxy.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn malformed_upload_reply_does_not_print_signed_addresses_or_retry() {
        let proxy = MockServer::start().await;
        let mut body = upload("https://objects.invalid");
        body["data"]["upload_url"] = json!(SIGNED);
        body["data"]["upload_headers"] = json!({"bad":SIGNED});
        body["data"]["upload_expires_at"] = json!(SIGNED);
        Mock::given(method("POST"))
            .and(path(
                "/publishers/seren-storage/buckets/files/objects/uploads",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(gateway(201, body), "application/json"),
            )
            .expect(1)
            .mount(&proxy)
            .await;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("input"), CONTENT).unwrap();
        let error = command(
            "create_upload",
            &context(&proxy, OutputFormat::Json),
            dir.path(),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("client_contract_mismatch"));
        assert!(!format!("{error:#}").contains("do-not-disclose"));
        proxy.verify().await;
    }
}
