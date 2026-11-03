use serde_json::{Value, json};
use seren::{Client, ClientConfig, PublisherErrorKind, publisher_bytes_result, publisher_result};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ID: &str = "00000000-0000-4000-8000-000000000001";
const SECRET: &str = "https://private.invalid/?token=do-not-disclose";

// ApiResultResponse, seren-core main 7f43fb4, routes/agent_payments/types.rs:139.
// List shapes reproduce the production captures in seren#289; identifiers and
// content are synthetic. The wire fixture includes the producer's billing fields.
fn gateway(status: u16, body: Value) -> Value {
    json!({"data": {"status": status, "body": body, "response_bytes": body.to_string().len(),
        "execution_time_ms": 20, "cost": "0.000100", "asset_symbol": "USDC", "payment_source": "prepaid_balance"}})
}
fn note() -> Value {
    json!({"id": ID, "title": "Gateway fixture", "excerpt": "hello", "content": "hello", "format": "markdown",
        "position": 0, "is_archived": false, "is_pinned": false, "tags": [], "version": 1,
        "created_at": "2026-11-03T12:00:00Z", "updated_at": "2026-11-03T12:00:00Z"})
}
fn skill() -> Value {
    json!({"id": ID, "owner_kind": "organization", "slug": "gateway-fixture", "skill_folder_name": "gateway-fixture",
        "name": "Gateway fixture", "description": "fixture", "visibility": "public", "discoverability": "listed",
        "status": "published", "sponsor_mode": "skip", "price_cents": 0, "install_count": 0,
        "owner_organization_id": ID, "created_by_user_id": ID, "github_mirror_health": "healthy",
        "created_at": "2026-11-03T12:00:00Z", "updated_at": "2026-11-03T12:00:00Z"})
}
fn client(server: &MockServer) -> Client {
    Client::from_config(&ClientConfig::new("fixture").with_base_url(server.uri())).unwrap()
}
async fn serve(server: &MockServer, verb: &str, route: &str, status: u16, body: Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn skills_and_notes_lists_accept_direct_and_gateway_replies() {
    for wrapped in [false, true] {
        let server = MockServer::start().await;
        let skills = json!({"data": [skill()]});
        let notes = json!({"data": [note()]});
        serve(
            &server,
            "GET",
            "/publishers/seren-skills/skills",
            200,
            if wrapped {
                gateway(200, skills.clone())
            } else {
                skills
            },
        )
        .await;
        serve(
            &server,
            "GET",
            "/publishers/seren-notes/notes",
            200,
            if wrapped {
                gateway(200, notes.clone())
            } else {
                notes
            },
        )
        .await;
        let client = client(&server);
        let skills = publisher_result(client.list_skills(None, None, None, None, None, None).await)
            .await
            .unwrap();
        assert_eq!(skills.data[0].id.to_string(), ID);
        let notes = publisher_result(client.list_notes(None, None, None, None, None).await)
            .await
            .unwrap();
        assert_eq!(notes.data[0].id.to_string(), ID);
        server.verify().await;
    }
}

#[tokio::test]
async fn note_creation_fetch_and_empty_delete_do_not_retry() {
    for wrapped in [false, true] {
        let server = MockServer::start().await;
        let body = json!({"data": note()});
        serve(
            &server,
            "POST",
            "/publishers/seren-notes/notes",
            if wrapped { 200 } else { 201 },
            if wrapped {
                gateway(201, body.clone())
            } else {
                body.clone()
            },
        )
        .await;
        serve(
            &server,
            "GET",
            &format!("/publishers/seren-notes/notes/{ID}"),
            200,
            if wrapped {
                gateway(200, body.clone())
            } else {
                body
            },
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/publishers/seren-notes/notes/{ID}")))
            .respond_with(if wrapped {
                ResponseTemplate::new(200).set_body_json(gateway(204, Value::Null))
            } else {
                ResponseTemplate::new(204)
            })
            .expect(1)
            .mount(&server)
            .await;
        let client = client(&server);
        let request =
            serde_json::from_value(json!({"title": "Gateway fixture", "content": "hello"}))
                .unwrap();
        let created = publisher_result(client.create_note(&request).await)
            .await
            .unwrap();
        assert_eq!(created.data.id.to_string(), ID);
        let fetched = publisher_result(client.get_note(&created.data.id, None).await)
            .await
            .unwrap();
        assert_eq!(fetched.data.content, "hello");
        publisher_result(client.delete_note(&created.data.id).await)
            .await
            .unwrap();
        server.verify().await;
    }
}

#[tokio::test]
async fn publisher_errors_and_malformed_replies_are_safe() {
    for status in [404, 409] {
        for outer in [200, status] {
            let server = MockServer::start().await;
            let body = json!({"error": "not_found", "message": "Note not found"});
            serve(
                &server,
                "GET",
                &format!("/publishers/seren-notes/notes/{ID}"),
                outer,
                if outer == 200 {
                    gateway(status, body.clone())
                } else {
                    body
                },
            )
            .await;
            let error =
                publisher_result(client(&server).get_note(&ID.parse().unwrap(), None).await)
                    .await
                    .unwrap_err();
            assert_eq!(error.kind, PublisherErrorKind::PublisherError);
            assert_eq!(error.status, Some(status));
            assert_eq!(error.error.as_deref(), Some("not_found"));
            assert_eq!(error.message.as_deref(), Some("Note not found"));
        }
    }
    for body in [
        json!({"unexpected": SECRET}),
        gateway(200, json!({"data": SECRET})),
        gateway(200, json!(SECRET)),
        gateway(200, Value::Null),
    ] {
        let server = MockServer::start().await;
        serve(&server, "GET", "/publishers/seren-notes/notes", 200, body).await;
        let error = publisher_result(
            client(&server)
                .list_notes(None, None, None, None, None)
                .await,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind, PublisherErrorKind::ClientContractMismatch);
        assert!(
            !format!(
                "{error:?} {error} {}",
                serde_json::to_string(&error).unwrap()
            )
            .contains("do-not-disclose")
        );
    }
}

#[tokio::test]
async fn binary_downloads_decode_exact_bytes_and_text_without_exposing_envelopes() {
    for thumbnail in [false, true] {
        let route = format!(
            "/publishers/seren-notes/attachments/{ID}/{}",
            if thumbnail { "thumbnail" } else { "data" }
        );
        let server = MockServer::start().await;
        let mut body = gateway(200, Value::Null);
        body["data"]["body_base64"] = json!("AP+AQUJD");
        body["data"]["content_type"] = json!("application/octet-stream");
        body["data"]["response_bytes"] = json!(6);
        serve(&server, "GET", &route, 200, body).await;
        let result = publisher_bytes_result(if thumbnail {
            client(&server)
                .download_thumbnail(&ID.parse().unwrap(), None, None)
                .await
        } else {
            client(&server)
                .download_attachment(&ID.parse().unwrap())
                .await
        })
        .await
        .unwrap();
        assert_eq!(result, b"\x00\xff\x80ABC");
    }
    for wrapped in [false, true] {
        let server = MockServer::start().await;
        let response = if wrapped {
            ResponseTemplate::new(200).set_body_json(gateway(200, json!("# Skill\n")))
        } else {
            ResponseTemplate::new(200).set_body_raw("# Skill\n", "text/markdown")
        };
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        assert_eq!(
            publisher_bytes_result(client(&server).skill_md().await)
                .await
                .unwrap(),
            b"# Skill\n"
        );
    }
    for body in [json!({"secret": SECRET}), gateway(200, json!(null)), {
        let mut body = gateway(200, Value::Null);
        body["data"]["body_base64"] = json!(SECRET);
        body
    }] {
        let server = MockServer::start().await;
        serve(
            &server,
            "GET",
            "/publishers/seren-skills/skill.md",
            200,
            body,
        )
        .await;
        let error = publisher_bytes_result(client(&server).skill_md().await)
            .await
            .unwrap_err();
        assert_eq!(error.kind, PublisherErrorKind::ClientContractMismatch);
        assert!(!format!("{error:?} {error}").contains("do-not-disclose"));
    }
}

#[tokio::test]
async fn every_inner_success_status_and_text_encoded_json_are_supported() {
    for status in [200, 201, 202, 204, 299] {
        for text in [false, true] {
            let server = MockServer::start().await;
            let body = json!({"data": [note()]});
            serve(
                &server,
                "GET",
                "/publishers/seren-notes/notes",
                200,
                gateway(status, if text { json!(body.to_string()) } else { body }),
            )
            .await;
            let notes = publisher_result(
                client(&server)
                    .list_notes(None, None, None, None, None)
                    .await,
            )
            .await
            .unwrap();
            assert_eq!(notes.data[0].id.to_string(), ID);
        }
    }
}

#[tokio::test]
async fn direct_attachment_bytes_and_gateway_binary_errors_are_preserved() {
    let route = format!("/publishers/seren-notes/attachments/{ID}/data");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"\x00\xff\x80ABC".to_vec()))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        publisher_bytes_result(
            client(&server)
                .download_attachment(&ID.parse().unwrap())
                .await
        )
        .await
        .unwrap(),
        b"\x00\xff\x80ABC"
    );
    server.verify().await;
    for status in [404, 409] {
        for outer in [200, status] {
            let server = MockServer::start().await;
            let body = json!({"error": "not_found", "message": "Attachment not found"});
            serve(
                &server,
                "GET",
                &route,
                outer,
                if outer == 200 {
                    gateway(status, body.clone())
                } else {
                    body
                },
            )
            .await;
            let error = publisher_bytes_result(
                client(&server)
                    .download_attachment(&ID.parse().unwrap())
                    .await,
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind, PublisherErrorKind::PublisherError);
            assert_eq!(error.status, Some(status));
            assert_eq!(error.message.as_deref(), Some("Attachment not found"));
        }
    }
}

// Raw generated calls retain their direct typed contract. These observations
// reproduce the original failure without making a second mutation request.
#[tokio::test]
async fn unrecovered_generated_calls_expose_the_original_gateway_mismatch() {
    let server = MockServer::start().await;
    serve(
        &server,
        "GET",
        "/publishers/seren-notes/notes",
        200,
        gateway(200, json!({"data": [note()]})),
    )
    .await;
    assert!(matches!(
        client(&server)
            .list_notes(None, None, None, None, None)
            .await,
        Err(seren::Error::InvalidResponsePayload(..))
    ));
    serve(
        &server,
        "POST",
        "/publishers/seren-notes/notes",
        200,
        gateway(201, json!({"data": note()})),
    )
    .await;
    let request =
        serde_json::from_value(json!({"title": "Gateway fixture", "content": "hello"})).unwrap();
    assert!(matches!(
        client(&server).create_note(&request).await,
        Err(seren::Error::UnexpectedResponse(_))
    ));
    server.verify().await;
}

#[tokio::test]
async fn skills_details_and_unconstrained_responses_recover_gateway_data() {
    for wrapped in [false, true] {
        let server = MockServer::start().await;
        let mut detail = skill();
        detail["access"] = json!({"can_view": true, "can_download": true, "can_manage": false, "reason": "public"});
        let detail = json!({"data": detail});
        serve(
            &server,
            "GET",
            "/publishers/seren-skills/skills/gateway-fixture",
            200,
            if wrapped {
                gateway(200, detail.clone())
            } else {
                detail
            },
        )
        .await;
        let result = publisher_result(client(&server).get_skill("gateway-fixture").await)
            .await
            .unwrap();
        assert_eq!(result.data.id.to_string(), ID);
        let metadata = json!({"data": {"name": "Seren Skills"}});
        serve(
            &server,
            "GET",
            "/publishers/seren-skills",
            200,
            if wrapped {
                gateway(200, metadata.clone())
            } else {
                metadata
            },
        )
        .await;
        let result = publisher_result(client(&server).publisher_root().await)
            .await
            .unwrap();
        assert_eq!(result.data["name"], "Seren Skills");
        server.verify().await;
    }
}

#[tokio::test]
async fn undocumented_success_status_is_a_contract_mismatch_for_downloads() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(201).set_body_raw("private bytes", "application/octet-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = publisher_bytes_result(client(&server).skill_md().await)
        .await
        .unwrap_err();
    assert_eq!(error.kind, PublisherErrorKind::ClientContractMismatch);
    assert_eq!(error.status, Some(201));
}

#[test]
fn skills_and_notes_response_types_require_unwrapping() {
    let envelope = gateway(
        409,
        json!({"error": "conflict", "message": "Version conflict"}),
    );
    macro_rules! rejects {
        ($($ty:ty),+ $(,)?) => { $(assert!(serde_json::from_value::<$ty>(envelope.clone()).is_err(), stringify!($ty));)+ };
    }
    rejects!(
        seren::DataResponseAuthorIdentity,
        seren::DataResponseChatDraftResponse,
        seren::DataResponseCollaborator,
        seren::DataResponseCreateVersionResponse,
        seren::DataResponseFileEditResponse,
        seren::DataResponseGetFileResponse,
        seren::DataResponseMergeStateResponse,
        seren::DataResponseOrphanFoldersResponse,
        seren::DataResponsePurchaseResponse,
        seren::DataResponseSkillAgentGrant,
        seren::DataResponseSkillBundle,
        seren::DataResponseSkillBundleFileDownload,
        seren::DataResponseSkillBundleManifest,
        seren::DataResponseSkillDetail,
        seren::DataResponseSkillEditDocument,
        seren::DataResponseUpdateRequest,
        seren::DataResponseUpdateRequestDetail,
        seren::DataResponseUpdateRequestDiff,
        seren::DataResponseUsageSummaryResponse,
        seren::DataResponseValue,
        seren::DataResponseVecCollaborator,
        seren::DataResponseVecFileListing,
        seren::DataResponseVecSkillAgentGrant,
        seren::DataResponseVecSkillSummary,
        seren::DataResponseVecSkillVersion,
        seren::DataResponseVecUpdateRequest,
        seren::DataResponseVecUpdateRequestComment,
        seren::DataResponseVecUsageEvent,
        seren::DataResponseBool,
        seren::DataResponseAttachment,
        seren::DataResponseNoteResponse,
        seren::DataResponseNoteShare,
        seren::DataResponseSharedNoteResponse,
        seren::DataResponseVecAttachment,
        seren::DataResponseVecNoteShare,
        seren::DataResponseVecNoteSummary,
        seren::DataResponseVecSemanticSearchResultResponse,
        seren::DataResponseVecString,
    );
}
