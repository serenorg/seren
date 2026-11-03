use super::*;

const MEDIA_TOOLS: [(&str, bool); 10] = [
    ("upload_seren_agent_template_avatar", false),
    ("delete_seren_agent_template_avatar", false),
    ("create_seren_agent_template_intro_video_upload", false),
    ("complete_seren_agent_template_intro_video_upload", false),
    ("get_seren_agent_template_intro_video", true),
    ("set_seren_agent_template_intro_video_captions", false),
    ("set_seren_agent_template_intro_video_poster", false),
    ("publish_seren_agent_template_intro_video", false),
    ("discard_seren_agent_template_intro_video_draft", false),
    ("delete_seren_agent_template_intro_video", false),
];

#[test]
fn template_media_tools_are_discoverable_with_owner_annotations() {
    let server = SerenMcpServer::new("owner-key", "http://localhost").unwrap();
    let tools = server.tool_router.list_all();
    for (name, read_only) in MEDIA_TOOLS {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("missing media tool {name}"));
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(read_only), "{name}");
        assert_eq!(annotations.open_world_hint, Some(false), "{name}");
        if !read_only {
            assert_eq!(annotations.destructive_hint, Some(true), "{name}");
        }
    }
}

use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

fn params_for(name: &str) -> Value {
    let mut params = json!({"organization_id": Uuid::from_u128(42), "slug": "anya"});
    if name.contains("avatar") && name.starts_with("upload_") {
        params["file_name"] = json!("picture.png");
        params["image_base64"] = json!(BASE64.encode(b"image bytes"));
    } else if name.starts_with("create_") {
        params["request"] =
            json!({"file_name": "intro.mp4", "content_type": "video/mp4", "size_bytes": 1000});
    } else if name.starts_with("complete_") {
        params["upload_id"] = json!(Uuid::from_u128(43));
    } else if name.ends_with("_captions") {
        params["request"] = json!({"vtt": "WEBVTT\n\n00:00.000 --> 00:02.000\nHello\n"});
    } else if name.ends_with("_poster") {
        params["request"] = json!({"at_ms": 1000});
    }
    params
}

async fn call_media(
    server: &SerenMcpServer,
    name: &str,
    params: Value,
    extensions: Extensions,
) -> Result<CallToolResult, McpError> {
    macro_rules! call {
        ($method:ident) => {
            server
                .$method(
                    Parameters(serde_json::from_value(params).unwrap()),
                    extensions,
                )
                .await
        };
    }
    match name {
        "upload_seren_agent_template_avatar" => call!(upload_seren_agent_template_avatar),
        "delete_seren_agent_template_avatar" => call!(delete_seren_agent_template_avatar),
        "create_seren_agent_template_intro_video_upload" => {
            call!(create_seren_agent_template_intro_video_upload)
        }
        "complete_seren_agent_template_intro_video_upload" => {
            call!(complete_seren_agent_template_intro_video_upload)
        }
        "get_seren_agent_template_intro_video" => call!(get_seren_agent_template_intro_video),
        "set_seren_agent_template_intro_video_captions" => {
            call!(set_seren_agent_template_intro_video_captions)
        }
        "set_seren_agent_template_intro_video_poster" => {
            call!(set_seren_agent_template_intro_video_poster)
        }
        "publish_seren_agent_template_intro_video" => {
            call!(publish_seren_agent_template_intro_video)
        }
        "discard_seren_agent_template_intro_video_draft" => {
            call!(discard_seren_agent_template_intro_video_draft)
        }
        "delete_seren_agent_template_intro_video" => call!(delete_seren_agent_template_intro_video),
        _ => panic!("unknown media tool {name}"),
    }
}

fn media_endpoint(name: &str) -> (&'static str, String) {
    let base = format!("/organizations/{}/templates/anya", Uuid::from_u128(42));
    let (verb, suffix) = match name {
        "upload_seren_agent_template_avatar" => ("POST", "/avatar".into()),
        "delete_seren_agent_template_avatar" => ("DELETE", "/avatar".into()),
        "create_seren_agent_template_intro_video_upload" => ("POST", "/intro-video/uploads".into()),
        "complete_seren_agent_template_intro_video_upload" => (
            "POST",
            format!("/intro-video/uploads/{}/complete", Uuid::from_u128(43)),
        ),
        "get_seren_agent_template_intro_video" => ("GET", "/intro-video".into()),
        "set_seren_agent_template_intro_video_captions" => {
            ("PUT", "/intro-video/draft/captions".into())
        }
        "set_seren_agent_template_intro_video_poster" => {
            ("PUT", "/intro-video/draft/poster".into())
        }
        "publish_seren_agent_template_intro_video" => ("POST", "/intro-video/draft/publish".into()),
        "discard_seren_agent_template_intro_video_draft" => ("DELETE", "/intro-video/draft".into()),
        "delete_seren_agent_template_intro_video" => ("DELETE", "/intro-video".into()),
        _ => panic!("unknown media tool {name}"),
    };
    (verb, format!("{base}{suffix}"))
}

fn response_json(result: CallToolResult) -> Value {
    assert!(!result.is_error.unwrap_or(false));
    let result = serde_json::to_value(result).unwrap();
    serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
}

// Generated SDK serialization may omit nullable fields whose value is null.
// Check every supplied field, including null semantics, without losing non-null metadata.
fn assert_response_fields(actual: &Value, expected: &Value) {
    match expected {
        Value::Object(fields) => {
            assert!(actual.is_object(), "expected object, got {actual}");
            for (key, value) in fields {
                assert_response_fields(&actual[key], value);
            }
        }
        Value::Array(items) => {
            let actual = actual.as_array().expect("expected an array");
            assert_eq!(actual.len(), items.len());
            for (actual, expected) in actual.iter().zip(items) {
                assert_response_fields(actual, expected);
            }
        }
        _ => assert_eq!(actual, expected),
    }
}

fn profile_fixture(avatar: bool) -> Value {
    json!({"data": {"avatar_url": if avatar { json!("https://api.serendb.com/agents/templates/anya/avatar") } else { Value::Null },
        "capabilities": [], "example_tasks": [], "works_in": [], "pronouns": "she/her"}})
}

fn video_fixture(state: &str, live: bool) -> Value {
    let active = json!({"object_id": Uuid::from_u128(44), "width": 1080, "height": 1620,
        "duration_ms": 20000, "published_at": "2026-11-03T12:00:00Z"});
    let mut ordered = active.clone();
    ordered["position"] = json!(0);
    json!({"data": {
        "active": if live { active } else { Value::Null },
        "videos": if live { vec![ordered] } else { vec![] }, "max_videos": 5,
        "draft": if state == "none" { Value::Null } else { json!({
            "upload_id": Uuid::from_u128(43), "replaces_video_id": Uuid::from_u128(44),
            "upload_expires_at": if state == "uploading" { json!("2026-11-03T12:15:00Z") } else { Value::Null },
            "state": state, "progress_percent": 50, "poster_at_ms": 1000,
            "width": 1080, "height": 1620, "duration_ms": 20000,
            "refusal": if state == "refused" { json!({"code": "intro_video_shape", "message": "Use portrait 2:3."}) } else { Value::Null },
            "captions": {"state": "failed", "failure": "Supply WebVTT captions to continue.", "text": null}
        }) }
    }})
}

#[tokio::test]
async fn template_media_picture_upload_replace_and_remove_preserve_multipart_and_profile() {
    let proxy = MockServer::start().await;
    let server = SerenMcpServer::new("owner-key", &proxy.uri()).unwrap();
    // Binary bytes must survive base64 and the multipart encoder without text conversion.
    let bytes: Vec<u8> = (0..=255).cycle().take(65536).collect();
    let expected = bytes.clone();
    let (verb, endpoint) = media_endpoint(MEDIA_TOOLS[0].0);
    Mock::given(method(verb))
        .and(path(endpoint))
        .and(header("authorization", "Bearer owner-key"))
        .and(move |request: &wiremock::Request| {
            request
                .body
                .windows(expected.len())
                .any(|window| window == expected)
                && request
                    .body
                    .windows(b"name=\"file\"; filename=\"picture.png\"".len())
                    .any(|window| window == b"name=\"file\"; filename=\"picture.png\"")
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_fixture(true)))
        .expect(2)
        .mount(&proxy)
        .await;
    let mut params = params_for(MEDIA_TOOLS[0].0);
    params["image_base64"] = json!(BASE64.encode(bytes));
    params["file_name"] = json!(" picture.png ");
    for _ in 0..2 {
        let actual = response_json(
            call_media(
                &server,
                MEDIA_TOOLS[0].0,
                params.clone(),
                Extensions::default(),
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            actual["data"]["avatar_url"],
            profile_fixture(true)["data"]["avatar_url"]
        );
    }
    let (verb, endpoint) = media_endpoint(MEDIA_TOOLS[1].0);
    Mock::given(method(verb))
        .and(path(endpoint))
        .and(header("authorization", "Bearer owner-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_fixture(false)))
        .expect(1)
        .mount(&proxy)
        .await;
    let removed = response_json(
        call_media(
            &server,
            MEDIA_TOOLS[1].0,
            params_for(MEDIA_TOOLS[1].0),
            Extensions::default(),
        )
        .await
        .unwrap(),
    );
    assert!(removed["data"]["avatar_url"].is_null());
    proxy.verify().await;
}

#[tokio::test]
async fn template_media_video_lifecycle_preserves_signed_upload_and_current_core_status() {
    let proxy = MockServer::start().await;
    let server = SerenMcpServer::new("owner-key", &proxy.uri()).unwrap();
    let mut captioned = video_fixture("ready", false);
    captioned["data"]["draft"]["captions"] = json!({
        "state": "owner", "text": "WEBVTT\n\n00:00.000 --> 00:02.000\nHello\n"
    });
    let signed = json!({"data": {"upload_id": Uuid::from_u128(43),
        "upload_url": "https://storage.example.test/intro?signature=private", "method": "PUT",
        "headers": {"Content-Type": "video/mp4", "Content-Length": "1000", "x-amz-checksum-sha256": "checksum"},
        "expires_at": "2026-11-03T12:15:00Z"}});
    for (name, response, status, calls) in [
        (MEDIA_TOOLS[2].0, signed, 200, 1),
        (MEDIA_TOOLS[3].0, video_fixture("processing", false), 202, 2),
        (MEDIA_TOOLS[5].0, captioned, 200, 1),
        (MEDIA_TOOLS[6].0, video_fixture("processing", false), 200, 1),
        (MEDIA_TOOLS[7].0, video_fixture("none", true), 200, 1),
        (MEDIA_TOOLS[8].0, video_fixture("none", true), 200, 2),
        (MEDIA_TOOLS[9].0, video_fixture("ready", false), 200, 2),
    ] {
        let (verb, endpoint) = media_endpoint(name);
        let params = params_for(name);
        let mut mock = Mock::given(method(verb))
            .and(path(endpoint))
            .and(header("authorization", "Bearer owner-key"));
        if let Some(body) = params.get("request") {
            mock = mock.and(body_json(body));
        }
        mock.respond_with(ResponseTemplate::new(status).set_body_json(response.clone()))
            .expect(calls)
            .mount(&proxy)
            .await;
        for _ in 0..calls {
            let actual = response_json(
                call_media(&server, name, params.clone(), Extensions::default())
                    .await
                    .unwrap(),
            );
            if name.starts_with("create_") {
                assert_eq!(actual, response);
            } else {
                for field in ["active", "videos", "max_videos", "draft"] {
                    assert_response_fields(&actual["data"][field], &response["data"][field]);
                }
            }
        }
    }
    // Status must expose upload deadlines, caption failures and processing refusals.
    for state in ["uploading", "processing", "ready", "refused"] {
        let name = MEDIA_TOOLS[4].0;
        let response = video_fixture(state, true);
        let (verb, endpoint) = media_endpoint(name);
        Mock::given(method(verb))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(response.clone()))
            .expect(1)
            .mount(&proxy)
            .await;
        let actual = response_json(
            call_media(&server, name, params_for(name), Extensions::default())
                .await
                .unwrap(),
        );
        assert_response_fields(&actual["data"], &response["data"]);
        proxy.verify().await;
        proxy.reset().await;
    }
}

fn auth_extensions(credential: crate::SerenRequestCredential) -> Extensions {
    let mut request = axum::http::Request::new(());
    request
        .extensions_mut()
        .insert(crate::SerenRequestAuthContext {
            user_id: Uuid::from_u128(1),
            email: None,
            credential,
        });
    let mut extensions = Extensions::default();
    extensions.insert(request.into_parts().0);
    extensions
}

fn read_only_extensions() -> Extensions {
    let request = axum::http::Request::builder()
        .header("x-read-only", "true")
        .body(())
        .unwrap();
    let mut extensions = Extensions::default();
    extensions.insert(request.into_parts().0);
    extensions
}

#[tokio::test]
async fn template_media_tools_enforce_owner_and_read_only_boundaries_before_network() {
    let proxy = MockServer::start().await;
    let server = SerenMcpServer::new("owner-key", &proxy.uri()).unwrap();
    for (name, read_only) in MEDIA_TOOLS {
        for credential in [
            crate::SerenRequestCredential::AgentApiKey {
                api_key_id: None,
                agent_identity_id: Some(Uuid::from_u128(1)),
            },
            crate::SerenRequestCredential::ApiKey { api_key_id: None },
        ] {
            let error = call_media(&server, name, params_for(name), auth_extensions(credential))
                .await
                .unwrap_err();
            assert!(
                error
                    .message
                    .contains("managed_agent_profile_owner_required"),
                "{name}"
            );
            assert_eq!(
                error.data.unwrap()["error"],
                "managed_agent_profile_owner_required"
            );
        }
        let mut extensions = Extensions::default();
        extensions.insert(RuntimeWorkContextToken("work-context".into()));
        let error = call_media(&server, name, params_for(name), extensions)
            .await
            .unwrap_err();
        assert!(
            error
                .message
                .contains("managed_agent_profile_owner_required"),
            "{name}"
        );
        if !read_only {
            let error = call_media(&server, name, params_for(name), read_only_extensions())
                .await
                .unwrap_err();
            assert!(error.message.contains("Read-only mode"), "{name}");
        }
    }
    assert!(proxy.received_requests().await.unwrap().is_empty());
    let name = MEDIA_TOOLS[4].0;
    let (verb, endpoint) = media_endpoint(name);
    Mock::given(method(verb))
        .and(path(endpoint))
        .respond_with(ResponseTemplate::new(200).set_body_json(video_fixture("none", false)))
        .expect(3)
        .mount(&proxy)
        .await;
    for extensions in [
        read_only_extensions(),
        auth_extensions(crate::SerenRequestCredential::UserSession),
        auth_extensions(crate::SerenRequestCredential::UserApiKey {
            api_key_id: None,
            api_key_scopes: None,
        }),
    ] {
        call_media(&server, name, params_for(name), extensions)
            .await
            .unwrap();
    }
    proxy.verify().await;
}

#[tokio::test]
async fn template_media_tools_preserve_core_owner_shape_size_and_video_refusals() {
    let proxy = MockServer::start().await;
    let server = SerenMcpServer::new("owner-key", &proxy.uri()).unwrap();
    let mut cases = vec![];
    for (name, _) in MEDIA_TOOLS {
        cases.push((name, 403, "managed_agent_profile_owner_required"));
    }
    cases.extend([
        (MEDIA_TOOLS[0].0, 400, "avatar_shape"),
        (MEDIA_TOOLS[0].0, 400, "avatar_width"),
        (MEDIA_TOOLS[0].0, 400, "avatar_too_large"),
        (MEDIA_TOOLS[0].0, 413, "avatar_too_large"),
        (MEDIA_TOOLS[0].0, 503, "picture_storage_unavailable"),
        (MEDIA_TOOLS[2].0, 400, "intro_video_too_large"),
        (MEDIA_TOOLS[2].0, 400, "intro_video_format_unsupported"),
        (MEDIA_TOOLS[2].0, 409, "intro_video_limit_reached"),
        (MEDIA_TOOLS[3].0, 400, "intro_video_upload_size_mismatch"),
        (MEDIA_TOOLS[3].0, 409, "intro_video_upload_missing"),
        (MEDIA_TOOLS[5].0, 400, "intro_video_captions_invalid"),
        (MEDIA_TOOLS[5].0, 409, "intro_video_draft_not_ready"),
        (MEDIA_TOOLS[6].0, 400, "intro_video_poster_time_invalid"),
        (MEDIA_TOOLS[7].0, 409, "intro_video_captions_required"),
    ]);
    for (name, status, code) in cases {
        let (verb, endpoint) = media_endpoint(name);
        let wire = json!({"error": code, "message": "Core's authoritative refusal.", "details": {"rule": "unchanged"}});
        Mock::given(method(verb))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(status).set_body_json(wire.clone()))
            .expect(1)
            .mount(&proxy)
            .await;
        let error = call_media(&server, name, params_for(name), Extensions::default())
            .await
            .unwrap_err();
        let data = error.data.unwrap();
        assert_eq!(data["status"], status);
        assert_eq!(
            serde_json::from_str::<Value>(data["body"].as_str().unwrap()).unwrap(),
            wire,
            "{name}: {code}"
        );
        proxy.verify().await;
        proxy.reset().await;
    }
}

#[tokio::test]
async fn template_media_picture_rejects_missing_name_invalid_or_empty_base64() {
    let proxy = MockServer::start().await;
    let server = SerenMcpServer::new("owner-key", &proxy.uri()).unwrap();
    let name = MEDIA_TOOLS[0].0;
    for (field, value) in [
        ("file_name", "  "),
        ("image_base64", "not base64!"),
        ("image_base64", ""),
    ] {
        let mut params = params_for(name);
        params[field] = json!(value);
        assert_eq!(
            call_media(&server, name, params, Extensions::default())
                .await
                .unwrap_err()
                .code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
    }
    assert!(proxy.received_requests().await.unwrap().is_empty());
}
