mod storage_gateway {
    use super::*;
    use rmcp::ServiceExt;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_bytes, header, method, path},
    };
    #[allow(dead_code)]
    mod fixtures {
        include!("../../sdk/src/storage_gateway_fixtures.rs");
    }
    use fixtures::*;

    async fn invoke(
        proxy: &MockServer,
        tool: &str,
        arguments: Value,
    ) -> Result<CallToolResult, McpError> {
        let mut server = server_with_http_client(reqwest::Client::new());
        server.api_base_url = proxy.uri();
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let client = ().serve(client_transport).await.unwrap();
        let result = client
            .call_tool(
                CallToolRequestParams::new(format!("seren_storage_{tool}"))
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await;
        client.cancel().await.unwrap();
        task.await.unwrap();
        match result {
            Ok(result) => Ok(result),
            Err(rmcp::service::ServiceError::McpError(error)) => Err(error),
            Err(error) => panic!("unexpected transport failure: {error}"),
        }
    }
    async fn mount(proxy: &MockServer, case: &Case, response: ResponseTemplate) {
        Mock::given(method(case.method))
            .and(path(format!("/publishers/seren-storage{}", case.route)))
            .and(header("authorization", "Bearer test-key"))
            .respond_with(response)
            .expect(1)
            .mount(proxy)
            .await;
    }
    fn success(result: Result<CallToolResult, McpError>) -> Value {
        let result = result.unwrap();
        assert!(!result.is_error.unwrap_or(false));
        serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
    }
    #[tokio::test]
    async fn every_tool_decodes_gateway_and_direct_success() {
        for wrapped in [true, false] {
            for case in cases("https://objects.invalid") {
                let proxy = MockServer::start().await;
                let response = if wrapped {
                    ResponseTemplate::new(200)
                        .set_body_raw(gateway(case.status, case.body.clone()), "application/json")
                } else if case.status == 204 {
                    ResponseTemplate::new(204)
                } else {
                    ResponseTemplate::new(case.status).set_body_json(case.body.clone())
                };
                mount(&proxy, &case, response).await;
                let actual = success(invoke(&proxy, case.tool, case.arguments.clone()).await);
                let expected = if case.status == 204 {
                    json!({"revoked":ID})
                } else {
                    case.body
                };
                assert_eq!(
                    normalized(actual),
                    normalized(expected),
                    "{} wrapped={wrapped}",
                    case.tool
                );
                proxy.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn every_tool_reports_publisher_failure_without_retry() {
        for case in cases("https://objects.invalid") {
            for status in [404, 409] {
                let proxy = MockServer::start().await;
                mount(&proxy, &case, ResponseTemplate::new(200).set_body_raw(gateway(status, json!({"error":"storage_error", "message":"Object storage key already exists."})), "application/json")).await;
                let error = invoke(&proxy, case.tool, case.arguments.clone())
                    .await
                    .unwrap_err();
                assert_eq!(error.data.as_ref().unwrap()["kind"], "publisher_error");
                assert_eq!(error.data.as_ref().unwrap()["status"], status);
                assert!(error.message.contains("Object storage key already exists."));
                proxy.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn malformed_replies_and_undocumented_successes_are_safe() {
        for tool in ["health", "create_upload", "delete_bucket_agent_grant"] {
            let case = cases("https://objects.invalid")
                .into_iter()
                .find(|c| c.tool == tool)
                .unwrap();
            for body in [
                json!({"signed":SIGNED}),
                json!({"data":{"status":200,"body":{"data":{"status":[SIGNED]}}}}),
                json!({"data":{"status":"200","body":SIGNED}}),
                json!({"data":{"status":200,"body":SIGNED}}),
            ] {
                let proxy = MockServer::start().await;
                mount(
                    &proxy,
                    &case,
                    ResponseTemplate::new(200).set_body_json(body),
                )
                .await;
                let error = invoke(&proxy, tool, case.arguments.clone())
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.data.as_ref().unwrap()["kind"],
                    "client_contract_mismatch"
                );
                assert!(
                    !serde_json::to_string(&error)
                        .unwrap()
                        .contains("do-not-disclose")
                );
                proxy.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn base64_and_manual_upload_confirm_and_download_exact_bytes() {
        for base64 in [true, false] {
            let proxy = MockServer::start().await;
            for case in cases(&proxy.uri()).into_iter().filter(|c| {
                ["create_upload", "confirm_upload", "download_object"].contains(&c.tool)
            }) {
                mount(
                    &proxy,
                    &case,
                    ResponseTemplate::new(200)
                        .set_body_raw(gateway(case.status, case.body.clone()), "application/json"),
                )
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
            let result = if base64 {
                success(invoke(&proxy, "put_object_base64", json!({"bucket_slug":"files", "object_key":KEY, "content_base64": BASE64.encode(CONTENT)})).await)
            } else {
                let case = cases(&proxy.uri())
                    .into_iter()
                    .find(|c| c.tool == "create_upload")
                    .unwrap();
                let upload = success(invoke(&proxy, "create_upload", case.arguments).await);
                let put = reqwest::Client::new()
                    .put(upload["data"]["upload_url"].as_str().unwrap())
                    .header(
                        "x-storage-fixture",
                        upload["data"]["upload_headers"]["x-storage-fixture"]
                            .as_str()
                            .unwrap(),
                    )
                    .body(CONTENT)
                    .send()
                    .await
                    .unwrap();
                assert!(put.status().is_success());
                success(
                    invoke(
                        &proxy,
                        "confirm_upload",
                        json!({"bucket_slug":"files", "object_id":ID, "etag":"verified"}),
                    )
                    .await,
                )
            };
            assert_eq!(result["data"]["status"], "uploaded");
            let download = success(
                invoke(
                    &proxy,
                    "download_object",
                    json!({"bucket_slug":"files", "object_key":KEY}),
                )
                .await,
            );
            let bytes = reqwest::Client::new()
                .get(download["data"]["download_url"].as_str().unwrap())
                .header("x-storage-fixture", "required")
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            assert_eq!(bytes.as_ref(), CONTENT);
            let requests = proxy.received_requests().await.unwrap();
            let confirm = requests
                .iter()
                .position(|r| r.url.path().ends_with("confirm-upload"))
                .unwrap();
            let put = requests
                .iter()
                .position(|r| r.url.path() == "/signed-upload")
                .unwrap();
            let create = requests
                .iter()
                .position(|r| r.url.path().ends_with("/uploads"))
                .unwrap();
            assert!(create < put && put < confirm);
            assert_eq!(
                serde_json::from_slice::<Value>(&requests[confirm].body).unwrap(),
                json!({"etag":"verified"})
            );
            let create: Value = serde_json::from_slice(&requests[create].body).unwrap();
            assert_eq!(create["byte_length"], CONTENT.len());
            if base64 {
                assert_eq!(create["checksum"]["value"], sha256_hex(CONTENT));
            }
            proxy.verify().await;
        }
    }
    #[tokio::test]
    async fn raw_undocumented_200_is_not_a_success() {
        for case in cases("https://objects.invalid")
            .into_iter()
            .filter(|c| c.status != 200)
        {
            let proxy = MockServer::start().await;
            mount(
                &proxy,
                &case,
                ResponseTemplate::new(200).set_body_json(case.body.clone()),
            )
            .await;
            let error = invoke(&proxy, case.tool, case.arguments).await.unwrap_err();
            assert_eq!(error.data.unwrap()["kind"], "client_contract_mismatch");
            proxy.verify().await;
        }
    }
    #[tokio::test]
    async fn presigned_upload_errors_do_not_expose_url_or_body() {
        let proxy = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/signed-upload"))
            .respond_with(ResponseTemplate::new(403).set_body_string(SIGNED))
            .expect(1)
            .mount(&proxy)
            .await;
        let error = put_presigned_object_storage_object(
            &format!("{}/signed-upload?signature=do-not-disclose", proxy.uri()),
            &HashMap::new(),
            CONTENT.to_vec(),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains("403"));
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("do-not-disclose")
        );
        proxy.verify().await;
    }
}
