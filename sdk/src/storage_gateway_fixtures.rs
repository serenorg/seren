// Core ApiResultResponse field order: seren-core main 8274366,
// seren-core/src/routes/agent_payments/types.rs:139. Health/error payloads
// reproduce production evidence in seren#286; identifiers and URLs are synthetic.
use serde_json::{Value, json};
pub const ID: &str = "00000000-0000-4000-8000-000000000001";
pub const KEY: &str = "reports/result.json";
pub const CONTENT: &[u8] = b"storage fixture";
pub const SIGNED: &str = "https://objects.invalid/file?X-Amz-Signature=do-not-disclose";
pub fn gateway(status: u16, body: Value) -> String {
    format!(
        r#"{{"data":{{"status":{status},"body":{body},"response_bytes":{},"execution_time_ms":12,"cost":"0.000000","asset_symbol":"USDC","payment_source":"prepaid_balance"}}}}"#,
        body.to_string().len()
    )
}
pub fn object(status: &str) -> Value {
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

pub fn upload(base: &str) -> Value {
    json!({"data": {"object": object("pending"), "upload_url": format!("{base}/signed-upload"),
        "upload_headers": {"x-storage-fixture": "required"}, "upload_expires_at": "2026-10-26T18:00:00Z"}})
}
pub fn download(base: &str) -> Value {
    json!({"data": {"object": object("uploaded"), "download_url": format!("{base}/signed-download"),
        "download_headers": {"x-storage-fixture": "required"}, "download_expires_at": "2026-10-26T18:00:00Z"}})
}
pub fn grant() -> Value {
    json!({"id": ID, "organization_id": ID, "bucket_id": ID, "bucket_slug": "files",
        "agent_identity_id": ID, "permission": "writer", "created_by_user_id": ID,
        "updated_by_user_id": ID, "created_at": "2026-10-26T17:00:00Z", "updated_at": "2026-10-26T17:00:00Z"})
}
pub fn request() -> Value {
    json!({"object_key": KEY, "byte_length": CONTENT.len(), "content_type": "application/json",
        "checksum": {"algorithm": "sha256", "value": "a".repeat(64)}})
}
pub fn page() -> Value {
    json!({"data": {"objects": [object("uploaded")], "common_prefixes": [], "next_cursor": null}})
}
pub fn buckets() -> Value {
    json!({"data": [{"id": ID, "organization_id": ID, "slug": "files", "metadata": {},
        "trash_retention_days": 30, "created_at": "2026-10-26T17:00:00Z", "updated_at": "2026-10-26T17:00:00Z"}]})
}
pub fn normalized(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                *v = normalized(v.take());
            }
        }
        Value::Array(items) => {
            for v in items {
                *v = normalized(v.take());
            }
        }
        _ => {}
    }
    value
}
pub struct Case {
    pub tool: &'static str,
    pub method: &'static str,
    pub route: String,
    pub arguments: Value,
    pub status: u16,
    pub body: Value,
}
pub fn cases(base: &str) -> Vec<Case> {
    let mut upload_arguments = request();
    upload_arguments["bucket_slug"] = json!("files");
    let bucket = "/buckets/files";
    let object = format!("{bucket}/objects/{ID}");
    vec![
        Case {
            tool: "health",
            method: "GET",
            route: "/health".into(),
            arguments: json!({}),
            status: 200,
            body: json!({"data":{"status":"ok"}}),
        },
        Case {
            tool: "list_buckets",
            method: "GET",
            route: "/buckets".into(),
            arguments: json!({}),
            status: 200,
            body: buckets(),
        },
        Case {
            tool: "list_objects",
            method: "GET",
            route: format!("{bucket}/objects"),
            arguments: json!({"bucket_slug":"files"}),
            status: 200,
            body: page(),
        },
        Case {
            tool: "create_upload",
            method: "POST",
            route: format!("{bucket}/objects/uploads"),
            arguments: upload_arguments,
            status: 201,
            body: upload(base),
        },
        Case {
            tool: "confirm_upload",
            method: "POST",
            route: format!("{object}/confirm-upload"),
            arguments: json!({"bucket_slug":"files", "object_id":ID, "etag":"verified"}),
            status: 200,
            body: json!({"data":self::object("uploaded")}),
        },
        Case {
            tool: "download_object",
            method: "GET",
            route: format!("{bucket}/objects/by-key/download"),
            arguments: json!({"bucket_slug":"files", "object_key":KEY}),
            status: 200,
            body: download(base),
        },
        Case {
            tool: "download_object_by_id",
            method: "GET",
            route: format!("{object}/download"),
            arguments: json!({"bucket_slug":"files", "object_id":ID}),
            status: 200,
            body: download(base),
        },
        Case {
            tool: "delete_object",
            method: "DELETE",
            route: object,
            arguments: json!({"bucket_slug":"files", "object_id":ID}),
            status: 200,
            body: json!({"data":self::object("trashed")}),
        },
        Case {
            tool: "list_bucket_agent_grants",
            method: "GET",
            route: format!("{bucket}/agent-grants"),
            arguments: json!({"bucket_slug":"files"}),
            status: 200,
            body: json!({"data":[grant()]}),
        },
        Case {
            tool: "put_bucket_agent_grant",
            method: "PUT",
            route: format!("{bucket}/agent-grants/{ID}"),
            arguments: json!({"bucket_slug":"files", "agent_identity_id":ID, "permission":"writer"}),
            status: 200,
            body: json!({"data":grant()}),
        },
        Case {
            tool: "delete_bucket_agent_grant",
            method: "DELETE",
            route: format!("{bucket}/agent-grants/{ID}"),
            arguments: json!({"bucket_slug":"files", "agent_identity_id":ID}),
            status: 204,
            body: Value::Null,
        },
    ]
}
