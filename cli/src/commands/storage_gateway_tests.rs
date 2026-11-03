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
