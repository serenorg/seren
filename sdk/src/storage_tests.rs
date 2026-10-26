use crate::{Client, ClientConfig, Error, SerenStorageCreateObjectStorageUploadRequest};
use serde_json::{Value, json};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

fn object(status: &str) -> Value {
    json!({
        "id": "00000000-0000-4000-8000-000000000001",
        "organization_id": "00000000-0000-4000-8000-000000000002",
        "bucket_id": "00000000-0000-4000-8000-000000000003",
        "bucket_slug": "files", "object_key": "reports/result.json",
        "content_type": "application/json", "byte_length": 17,
        "checksum": {"algorithm": "sha256", "value": "a".repeat(64)},
        "upload_mode": "single", "multipart_part_size": null,
        "multipart_part_count": null, "etag": null, "status": status,
        "uri": "seren-storage://files/reports/result.json",
        "metadata": {"purpose": "report", "nested": {"retained": false}},
        "created_by_user_id": "00000000-0000-4000-8000-000000000004",
        "uploaded_by_user_id": null, "trashed_by_user_id": null,
        "trash_reason": null, "uploaded_at": null,
        "upload_expires_at": "2026-10-26T18:00:00Z", "expires_at": null,
        "trashed_at": null, "purge_after": null,
        "created_at": "2026-10-26T17:00:00Z", "updated_at": "2026-10-26T17:00:00Z"
    })
}

// These response properties are optional and nullable in the published schema.
fn normalize_optional_object_fields(mut value: Value) -> Value {
    for key in [
        "multipart_part_size",
        "multipart_part_count",
        "etag",
        "expires_at",
        "uploaded_by_user_id",
        "trashed_by_user_id",
        "trash_reason",
        "uploaded_at",
        "trashed_at",
        "purge_after",
    ] {
        if value.get(key).is_some_and(Value::is_null) {
            value.as_object_mut().unwrap().remove(key);
        }
    }
    value
}

fn object_id() -> Uuid {
    "00000000-0000-4000-8000-000000000001".parse().unwrap()
}

fn object_path() -> String {
    format!(
        "/publishers/seren-storage/buckets/files/objects/{}",
        object_id()
    )
}

fn client(server: &MockServer) -> Client {
    Client::from_config(&ClientConfig::new("storage-test").with_base_url(server.uri())).unwrap()
}

fn upload_request() -> Value {
    json!({
        "object_key": "reports/result.json", "content_type": "application/json",
        "byte_length": 17, "checksum": {"algorithm": "sha256", "value": "a".repeat(64)},
        "metadata": {"purpose": "report", "nested": {"retained": false}}
    })
}

#[tokio::test]
async fn storage_allocation_http_preserves_creation_and_replay() {
    let request_wire = upload_request();
    let request: SerenStorageCreateObjectStorageUploadRequest =
        serde_json::from_value(request_wire.clone()).unwrap();
    for (status, object_status, url) in [
        (201, "pending", Some("https://objects.invalid/original-put")),
        (
            200,
            "pending",
            Some("https://objects.invalid/recovered-put"),
        ),
        (200, "uploaded", None),
    ] {
        let server = MockServer::start().await;
        let object_wire = object(object_status);
        let headers = if url.is_some() {
            json!({"content-type": "application/json", "x-amz-checksum-sha256": "bound-checksum"})
        } else {
            json!({})
        };
        Mock::given(method("PUT"))
            .and(path(object_path()))
            .and(header("authorization", "Bearer storage-test"))
            .and(body_json(request_wire.clone()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({"data": {
                "object": object_wire, "upload_url": url, "upload_headers": headers,
                "upload_expires_at": "2026-10-26T18:00:00Z"
            }})))
            .expect(1)
            .mount(&server)
            .await;
        let response = client(&server)
            .seren_storage_allocate_upload("files", &object_id(), &request)
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        let allocation = response.into_inner().data;
        assert_eq!(allocation.upload_url.as_deref(), url);
        assert_eq!(
            serde_json::to_value(&allocation.upload_headers).unwrap(),
            headers
        );
        assert_eq!(
            allocation.upload_expires_at.to_string(),
            "2026-10-26T18:00:00Z"
        );
        assert_eq!(
            normalize_optional_object_fields(serde_json::to_value(allocation.object).unwrap()),
            normalize_optional_object_fields(object_wire)
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn storage_allocation_http_retains_refusal_statuses() {
    let request_wire = upload_request();
    let request: SerenStorageCreateObjectStorageUploadRequest =
        serde_json::from_value(request_wire.clone()).unwrap();
    for status in [400, 404, 409] {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(object_path()))
            .and(body_json(request_wire.clone()))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                "error": match status { 400 => "bad_request", 404 => "not_found", 409 => "conflict", _ => unreachable!() },
                "message": "allocation refused"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let error = client(&server)
            .seren_storage_allocate_upload("files", &object_id(), &request)
            .await
            .expect_err("allocation refusals must not become successful retries");
        assert_eq!(error.status().unwrap().as_u16(), status);
        server.verify().await;
    }
}

#[tokio::test]
async fn storage_object_status_http_preserves_lifecycle_and_multipart_metadata() {
    for status in [
        "pending",
        "uploaded",
        "trashed",
        "delete_pending",
        "delete_failed",
        "deleted",
    ] {
        let server = MockServer::start().await;
        let mut wire = object(status);
        wire["upload_mode"] = json!("multipart");
        wire["multipart_part_size"] = json!(5_242_880);
        wire["multipart_part_count"] = json!(3);
        wire["byte_length"] = json!(12_000_000);
        Mock::given(method("GET"))
            .and(path(object_path()))
            .and(header("authorization", "Bearer storage-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": wire})))
            .expect(1)
            .mount(&server)
            .await;
        let response = client(&server)
            .seren_storage_object_status("files", &object_id())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.data.multipart_part_size, Some(5_242_880));
        assert_eq!(response.data.multipart_part_count, Some(3));
        assert_eq!(
            normalize_optional_object_fields(serde_json::to_value(response.data).unwrap()),
            normalize_optional_object_fields(wire)
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn storage_object_status_http_rejects_invalid_response_contracts() {
    for invalid in ["missing_upload_expires_at", "unknown_status"] {
        let server = MockServer::start().await;
        let mut wire = object("pending");
        if invalid == "missing_upload_expires_at" {
            wire.as_object_mut().unwrap().remove("upload_expires_at");
        } else {
            wire["status"] = json!("invented_status");
        }
        Mock::given(method("GET"))
            .and(path(object_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": wire})))
            .expect(1)
            .mount(&server)
            .await;
        let result = client(&server)
            .seren_storage_object_status("files", &object_id())
            .await;
        assert!(
            matches!(result, Err(Error::InvalidResponsePayload(..))),
            "{result:?}"
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn storage_existing_actions_http_preserve_recorded_states_and_downloads() {
    let server = MockServer::start().await;
    let api = client(&server);
    let request_wire = upload_request();
    let request = serde_json::from_value(request_wire.clone()).unwrap();
    let object_wire = object("pending");
    Mock::given(method("POST"))
        .and(path(
            "/publishers/seren-storage/buckets/files/objects/uploads",
        ))
        .and(body_json(request_wire))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"data": {
            "object": object_wire, "upload_url": "https://objects.invalid/put",
            "upload_headers": {}, "upload_expires_at": "2026-10-26T18:00:00Z"
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let upload = api
        .seren_storage_create_upload("files", &request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(upload.data.upload_url, "https://objects.invalid/put");
    assert_eq!(
        normalize_optional_object_fields(serde_json::to_value(upload.data.object).unwrap()),
        normalize_optional_object_fields(object_wire)
    );
    let uploaded = object("uploaded");
    Mock::given(method("POST"))
        .and(path(format!("{}/confirm-upload", object_path())))
        .and(body_json(json!({"etag": "verified-etag"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": uploaded})))
        .expect(1)
        .mount(&server)
        .await;
    let confirmed = api
        .seren_storage_confirm_upload(
            "files",
            &object_id(),
            &crate::SerenStorageConfirmObjectStorageUploadRequest {
                etag: Some("verified-etag".into()),
            },
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        normalize_optional_object_fields(serde_json::to_value(confirmed.data).unwrap()),
        normalize_optional_object_fields(uploaded)
    );
    let download_url = "https://objects.invalid/download?response-cache-control=no-store";
    Mock::given(method("GET"))
        .and(path(format!("{}/download", object_path())))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
            "object": object("uploaded"), "download_url": download_url,
            "download_headers": {"x-required": "exact"},
            "download_expires_at": "2026-10-26T18:00:00Z"
        }})))
        .expect(1)
        .mount(&server)
        .await;
    let download = api
        .seren_storage_download_object_by_id("files", &object_id())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(download.data.download_url, download_url);
    assert_eq!(
        download
            .data
            .download_headers
            .get("x-required")
            .map(String::as_str),
        Some("exact")
    );
    for status in ["delete_pending", "trashed"] {
        let wire = object(status);
        let scoped = Mock::given(method("DELETE"))
            .and(path(object_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": wire})))
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let deleted = api
            .seren_storage_delete_object("files", &object_id())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            normalize_optional_object_fields(serde_json::to_value(deleted.data).unwrap()),
            normalize_optional_object_fields(wire)
        );
        drop(scoped);
    }
    server.verify().await;
}
