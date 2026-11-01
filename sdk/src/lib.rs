//! # Seren API Client
//!
//! Rust SDK for the Seren API, providing programmatic access to managed agents, Seren Passwords, branchable Postgres, object storage, payments, and other Seren platform APIs.
//!
//! ## Example
//!
//! ```no_run
//! use seren::{Client, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ClientConfig::new("seren_your_api_key_here");
//!     let client = Client::from_config(&config)?;
//!
//!     let projects = client.seren_db_list_projects().await?;
//!     println!("Found {} projects", projects.into_inner().data.len());
//!
//!     Ok(())
//! }
//! ```

#[allow(dead_code, clippy::all, unused_imports)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

mod config;
mod examples;
mod models;
mod query_error;
mod shared;

#[cfg(test)]
mod storage_tests;

// Re-export the generated client and types
pub use generated::Client;
pub use generated::types::*;

// Re-export progenitor types used in return values
pub use progenitor_client::{ByteStream, Error, ResponseValue};

// Re-export our config
pub use config::ClientConfig;

// Re-export product example metadata
pub use examples::*;

// Re-export additional model types
pub use models::*;
pub use query_error::*;
pub use shared::*;

/// Create a new authenticated client
impl Client {
    /// Create an authenticated client from a configuration
    pub fn from_config(config: &ClientConfig) -> Result<Self, reqwest::Error> {
        let mut headers = reqwest::header::HeaderMap::new();

        if let Some(ref token) = config.bearer_token {
            let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("Invalid bearer token");
            headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }

        let builder = reqwest::Client::builder().default_headers(headers);

        #[cfg(not(target_arch = "wasm32"))]
        let builder = {
            let mut builder =
                builder.timeout(std::time::Duration::from_secs(config.timeout_seconds));
            if !config.user_agent.trim().is_empty() {
                builder = builder.user_agent(config.user_agent.clone());
            }
            builder
        };

        let http_client = builder.build()?;

        Ok(Self::new_with_client(&config.base_url, http_client))
    }

    /// Upload and normalize the signed-in user's avatar.
    ///
    /// This method is implemented manually because Progenitor does not
    /// currently generate multipart request bodies.
    // Returns `progenitor_client::Error` by value to keep the signature
    // identical to the generated operations, which allow the same lint.
    #[allow(clippy::result_large_err)]
    pub async fn upload_current_user_avatar(
        &self,
        file_name: &str,
        file: Vec<u8>,
    ) -> Result<ResponseValue<DataResponseAvatarUploaded>, Error<()>> {
        use progenitor_client::{ClientHooks, ClientInfo, OperationInfo};

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(file).file_name(file_name.to_string()),
        );
        let url = format!("{}/users/me/avatar", self.baseurl.trim_end_matches('/'));
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("api-version", <Self as ClientInfo<()>>::api_version())
            .multipart(form)
            .build()?;
        let info = OperationInfo {
            operation_id: "upload_current_user_avatar",
        };

        self.pre(&mut request, &info).await?;
        let result = self.exec(request, &info).await;
        self.post(&result, &info).await?;
        let response = result?;

        match response.status().as_u16() {
            200 => ResponseValue::from_response(response).await,
            _ => Err(Error::UnexpectedResponse(response)),
        }
    }

    /// Upload and normalize a managed agent template's profile picture.
    ///
    /// This method is implemented manually because Progenitor does not
    /// currently generate multipart request bodies.
    #[allow(clippy::result_large_err)]
    pub async fn upload_managed_agent_template_avatar(
        &self,
        organization_id: &uuid::Uuid,
        slug: &str,
        file_name: &str,
        file: Vec<u8>,
    ) -> Result<ResponseValue<DataResponseManagedAgentTemplateProfile>, Error<()>> {
        use progenitor_client::{ClientHooks, ClientInfo, OperationInfo};

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(file).file_name(file_name.to_string()),
        );
        let url = format!(
            "{}/organizations/{organization_id}/templates/{}/avatar",
            self.baseurl.trim_end_matches('/'),
            progenitor_client::encode_path(slug),
        );
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("api-version", <Self as ClientInfo<()>>::api_version())
            .multipart(form)
            .build()?;
        let info = OperationInfo {
            operation_id: "upload_managed_agent_template_avatar",
        };
        self.pre(&mut request, &info).await?;
        let result = self.exec(request, &info).await;
        self.post(&result, &info).await?;
        let response = result?;
        match response.status().as_u16() {
            200 => ResponseValue::from_response(response).await,
            _ => Err(Error::UnexpectedResponse(response)),
        }
    }
}

// Re-export commonly used types
pub mod prelude {
    pub use crate::{Client, ClientConfig, Error, ResponseValue};
}

#[cfg(test)]
mod tests {
    use crate::{Client, ClientConfig, CloudRunErrorCode, PublisherCredentialProposalRequest};
    use serde_json::json;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

    #[tokio::test]
    async fn publisher_estimates_decode_wrapped_data() {
        let server = MockServer::start().await;
        let estimate = json!({
            "estimated_rows": 12,
            "estimated_cost": "0.0012",
            "asset_symbol": "USDC",
            "estimated_cost_atomic": 1200,
            "publisher_name": "Example",
            "publisher_slug": "example"
        });
        Mock::given(method("POST"))
            .and(path("/publishers/example/estimate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": estimate})))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            Client::from_config(&ClientConfig::new("synthetic-key").with_base_url(server.uri()))
                .unwrap();
        let response = client
            .estimate_query(
                "example",
                &crate::EstimateRequestBody {
                    publisher_id: Uuid::from_u128(1),
                    query: "SELECT 1".into(),
                    asset_id: None,
                },
            )
            .await
            .unwrap()
            .into_inner();
        assert_eq!(serde_json::to_value(response.data).unwrap(), estimate);
    }

    #[tokio::test]
    async fn deadline_and_otp_refusals_preserve_http_status_and_body() {
        let server = MockServer::start().await;
        let organization_id = Uuid::from_u128(301);
        let organization_route = format!("/organizations/{organization_id}/otp");
        let refusals = [
            (
                "POST",
                format!("{organization_route}/enrollment"),
                400,
                "otp_already_enrolled",
            ),
            (
                "POST",
                format!("{organization_route}/enrollment/confirm"),
                400,
                "otp_code_reused",
            ),
            (
                "POST",
                format!("{organization_route}/verify"),
                400,
                "otp_invalid_code",
            ),
            (
                "GET",
                "/publishers/example/deadline".to_owned(),
                408,
                "request_timeout",
            ),
            (
                "POST",
                "/publishers/example/deadline".to_owned(),
                408,
                "request_timeout",
            ),
            ("GET", "/wallet/balance".to_owned(), 408, "request_timeout"),
        ];
        for (verb, route, status, code) in &refusals {
            Mock::given(method(*verb))
                .and(path(route))
                .respond_with(ResponseTemplate::new(*status).set_body_json(json!({
                    "error": code, "message": "Synthetic refusal", "details": {"retained": true}
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client =
            Client::from_config(&ClientConfig::new("synthetic-key").with_base_url(server.uri()))
                .unwrap();
        let code = crate::OrganizationOtpCodeRequest {
            code: "000000".into(),
        };
        let verify = serde_json::from_value::<crate::OrganizationOtpVerifyRequest>(json!({
            "scope": "org_sign_in", "code": "000000"
        }))
        .unwrap();
        let results = [
            client
                .begin_organization_otp_enrollment(&organization_id)
                .await
                .map(|_| ()),
            client
                .confirm_organization_otp_enrollment(&organization_id, &code)
                .await
                .map(|_| ()),
            client
                .verify_organization_otp_scope(&organization_id, &verify)
                .await
                .map(|_| ()),
            client
                .proxy_to_publisher_get("example", "deadline", None, None, Vec::<u8>::new())
                .await
                .map(|_| ()),
            client
                .proxy_to_publisher_post("example", "deadline", None, None, Vec::<u8>::new())
                .await
                .map(|_| ()),
            client.get_wallet_balance().await.map(|_| ()),
        ];
        for (result, (_, _, status, code)) in results.into_iter().zip(refusals) {
            let error = match result {
                Err(error) => error,
                Ok(()) => panic!("refusal must not become a successful response"),
            };
            let crate::Error::UnexpectedResponse(response) = error else {
                panic!("refusal must retain its HTTP response");
            };
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap(),
                json!({
                    "error": code, "message": "Synthetic refusal", "details": {"retained": true}
                })
            );
        }
        server.verify().await;
    }

    #[test]
    fn publisher_access_preserves_not_needed_outcome() {
        let outcome: crate::PublisherAccessContinuationOutcome =
            serde_json::from_value(json!("not_needed")).unwrap();
        assert_eq!(serde_json::to_value(outcome).unwrap(), json!("not_needed"));
    }

    #[tokio::test]
    async fn connector_clients_bind_catalog_deployment_and_removal_key() {
        use wiremock::matchers::{header, query_param};

        let server = MockServer::start().await;
        let deployment_id = Uuid::from_u128(7);
        let key = Uuid::from_u128(8).to_string();
        Mock::given(method("GET"))
            .and(path("/publishers/seren-cloud/connectors"))
            .and(query_param("deployment_id", deployment_id.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                "connectors": [{
                    "connector_ref": "slack", "display_name": "Slack",
                    "description": "Messaging", "capability": "messaging", "credentials": [],
                    "supports_webhook_ingress": true, "requires_always_on": false,
                    "connected": true, "available_on_this_employee": true,
                    "receiver": "seren_webhook"
                }]
            }})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/publishers/seren-cloud/deployments/{deployment_id}/connectors/slack"
            )))
            .and(header("Idempotency-Key", key.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": true})))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            Client::from_config(&ClientConfig::new("synthetic-key").with_base_url(server.uri()))
                .unwrap();
        let catalog = client
            .seren_cloud_list_connectors(Some(&deployment_id))
            .await
            .unwrap()
            .into_inner()
            .data;
        assert_eq!(catalog.connectors.len(), 1);
        let connector = &catalog.connectors[0];
        assert_eq!(connector.available_on_this_employee, Some(true));
        assert_eq!(
            serde_json::to_value(connector.receiver).unwrap(),
            json!("seren_webhook")
        );
        assert!(
            client
                .seren_cloud_remove_connector(&deployment_id, "slack", &key)
                .await
                .unwrap()
                .into_inner()
                .data
        );
    }

    #[tokio::test]
    async fn workspace_snapshot_http_reads_typed_download_with_explicit_credential() {
        use wiremock::matchers::header;
        let timestamp = "2026-10-28T00:15:00.123456Z";
        let expected: jiff::Timestamp = timestamp.parse().unwrap();
        let conversions: [Result<crate::StorageTimestamp, jiff::Error>; 3] = [
            timestamp.parse(),
            crate::StorageTimestamp::try_from(timestamp),
            crate::StorageTimestamp::try_from(timestamp.to_owned()),
        ];
        for converted in conversions {
            assert_eq!(jiff::Timestamp::from(converted.unwrap()), expected);
        }
        let invalid = "not-a-timestamp";
        let failures: [Result<crate::StorageTimestamp, jiff::Error>; 3] = [
            invalid.parse(),
            crate::StorageTimestamp::try_from(invalid),
            crate::StorageTimestamp::try_from(invalid.to_owned()),
        ];
        for failure in failures {
            assert!(failure.is_err());
        }
        let deployment_id = Uuid::from_u128(42);
        let route = format!("/publishers/seren-cloud/deployments/{deployment_id}/snapshots/latest");
        for (algorithm, checksum) in [
            ("sha256", "a".repeat(64)),
            ("crc32c", "AAAAAA==".to_owned()),
        ] {
            let server = MockServer::start().await;
            let archive = MockServer::start().await;
            let timestamp = "2026-10-28T00:00:00Z";
            let owner = Uuid::from_u128(1);
            let organization = Uuid::from_u128(2);
            let bucket = Uuid::from_u128(3);
            let wire = json!({"data": {
                "snapshot": {
                    "id": Uuid::from_u128(4), "organization_id": organization,
                    "bucket_id": bucket, "bucket_slug": "workspaces", "deployment_id": deployment_id,
                    "base_snapshot_id": null,
                    "object": {
                        "id": Uuid::from_u128(5), "organization_id": organization,
                        "bucket_id": bucket, "bucket_slug": "workspaces", "object_key": "archive.zst",
                        "content_type": "application/zstd", "byte_length": 27,
                        "checksum": {"algorithm": algorithm, "value": checksum},
                        "upload_mode": "single", "status": "uploaded",
                        "uri": "seren-storage://workspaces/archive.zst", "metadata": {"fixture": true},
                        "created_by_user_id": owner, "uploaded_by_user_id": owner,
                        "uploaded_at": timestamp, "upload_expires_at": timestamp,
                        "created_at": timestamp, "updated_at": timestamp,
                        "multipart_part_size": null, "multipart_part_count": null,
                        "etag": null, "expires_at": null, "purge_after": null,
                        "trashed_at": null, "trashed_by_user_id": null, "trash_reason": null
                    },
                    "archive_sha256": "c".repeat(64), "file_count": 2, "uncompressed_bytes": 41,
                    "status": "active", "created_by_user_id": owner,
                    "created_at": timestamp, "updated_at": timestamp, "retired_at": null
                },
                "download_url": format!("{}/archive?signature=synthetic", archive.uri()),
                "download_headers": {"x-fixture": "required"},
                "download_expires_at": "2026-10-28T00:15:00.123456Z"
            }});
            Mock::given(method("GET"))
                .and(path(&route))
                .and(header("authorization", "Bearer synthetic-workspace-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::from_config(
                &ClientConfig::new("synthetic-workspace-key").with_base_url(server.uri()),
            )
            .unwrap();
            let response = client
                .seren_cloud_get_latest_workspace_snapshot(&deployment_id)
                .await
                .unwrap()
                .into_inner();
            let mut actual = serde_json::to_value(response).unwrap();
            let mut expected = wire;
            for value in [&mut actual, &mut expected] {
                for field in ["base_snapshot_id", "retired_at"] {
                    remove_null_field(value, "/data/snapshot", field);
                }
                for field in [
                    "multipart_part_size",
                    "multipart_part_count",
                    "etag",
                    "expires_at",
                    "purge_after",
                    "trashed_at",
                    "trashed_by_user_id",
                    "trash_reason",
                ] {
                    remove_null_field(value, "/data/snapshot/object", field);
                }
            }
            assert_eq!(actual, expected);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.query(), None);
            assert!(requests[0].body.is_empty());
            assert!(archive.received_requests().await.unwrap().is_empty());
            server.verify().await;

            // A response outside the contract is a decode failure, not a partial download.
            let mut invalid = Vec::new();
            for (pointer, value) in [
                ("/data/snapshot/object/checksum/algorithm", json!("md5")),
                ("/data/snapshot/status", json!("deleted")),
                ("/data/download_expires_at", json!("not-a-timestamp")),
            ] {
                let mut body = expected.clone();
                *body.pointer_mut(pointer).unwrap() = value;
                invalid.push(body);
            }
            let mut body = expected.clone();
            body["data"]
                .as_object_mut()
                .unwrap()
                .remove("download_expires_at");
            invalid.push(body);
            let mut body = expected.clone();
            body["data"]["snapshot"]["object"]["checksum"]["encoding"] = json!("hex");
            invalid.push(body);
            for body in invalid {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(path(&route))
                    .respond_with(ResponseTemplate::new(200).set_body_json(body))
                    .expect(1)
                    .mount(&server)
                    .await;
                let result = Client::from_config(
                    &ClientConfig::new("synthetic-workspace-key").with_base_url(server.uri()),
                )
                .unwrap()
                .seren_cloud_get_latest_workspace_snapshot(&deployment_id)
                .await;
                assert!(matches!(
                    result,
                    Err(crate::Error::InvalidResponsePayload(..))
                ));
                server.verify().await;
            }
        }
    }

    #[tokio::test]
    async fn workspace_snapshot_http_preserves_refusals_without_credential_fallback() {
        use wiremock::matchers::header;
        let deployment_id = Uuid::from_u128(42);
        let route = format!("/publishers/seren-cloud/deployments/{deployment_id}/snapshots/latest");
        // Core refusal codes; Storage refusals keep their body and retry hint.
        // These bodies test transport only and do not prove Core authorization.
        for (status, code, retry) in [
            (400, "BadRequest", false),
            (401, "Unauthorized", false),
            (403, "Forbidden", false),
            (404, "workspace_snapshot_not_found", false),
            (409, "storage_conflict", true),
            (410, "workspace_archive_unavailable", false),
            (502, "storage_response_unrecognized", false),
            (503, "storage_organization_provisioning", true),
        ] {
            let server = MockServer::start().await;
            let mut wire = json!({"error": code, "message": "Synthetic refusal."});
            let mut refusal = ResponseTemplate::new(status);
            if retry {
                wire["retry_after_seconds"] = json!(5);
                refusal = refusal.insert_header("retry-after", "5");
            }
            let refusal = refusal.set_body_json(wire.clone());
            Mock::given(method("GET"))
                .and(path(&route))
                .and(header("authorization", "Bearer synthetic-workspace-key"))
                .respond_with(refusal)
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::from_config(
                &ClientConfig::new("synthetic-workspace-key").with_base_url(server.uri()),
            )
            .unwrap();
            let error = client
                .seren_cloud_get_latest_workspace_snapshot(&deployment_id)
                .await
                .unwrap_err();
            let crate::Error::UnexpectedResponse(response) = error else {
                panic!("snapshot refusal must retain its raw HTTP response");
            };
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(
                response
                    .headers()
                    .get("retry-after")
                    .map(|value| value.to_str().unwrap()),
                retry.then_some("5")
            );
            assert_eq!(response.json::<serde_json::Value>().await.unwrap(), wire);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].url.query(), None);
            assert!(requests[0].body.is_empty());
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn storage_http_preserves_provisioning_retry_metadata() {
        for retry_after in [None, Some(json!(null)), Some(json!(0)), Some(json!(5))] {
            let server = MockServer::start().await;
            let object_id = Uuid::from_u128(42);
            let mut wire = json!({
                "error": "storage_organization_provisioning",
                "message": "Organization storage is being provisioned."
            });
            // The producer sends Retry-After exactly when the body carries a delay.
            let retry_header = retry_after
                .as_ref()
                .and_then(serde_json::Value::as_u64)
                .map(|seconds| seconds.to_string());
            if let Some(retry_after) = retry_after {
                wire["retry_after_seconds"] = retry_after;
            }
            let mut refusal = ResponseTemplate::new(503).set_body_json(wire.clone());
            if let Some(seconds) = &retry_header {
                refusal = refusal.insert_header("Retry-After", seconds.as_str());
            }
            Mock::given(method("GET"))
                .and(path(format!(
                    "/publishers/seren-storage/buckets/files/objects/{object_id}"
                )))
                .respond_with(refusal)
                .expect(1)
                .mount(&server)
                .await;

            let error = Client::new(&server.uri())
                .seren_storage_object_status("files", &object_id)
                .await
                .expect_err("provisioning must remain an HTTP refusal");
            let crate::Error::UnexpectedResponse(response) = error else {
                panic!("storage provisioning refusal must retain its HTTP response");
            };
            assert_eq!(response.status().as_u16(), 503);
            assert_eq!(
                response
                    .headers()
                    .get("Retry-After")
                    .map(|value| value.to_str().unwrap().to_owned()),
                retry_header
            );
            assert_eq!(response.json::<serde_json::Value>().await.unwrap(), wire);
            server.verify().await;
        }
    }

    #[test]
    fn conversation_tasks_preserve_setup_hold_and_queue_reasons() {
        for reason in ["setup_pending", "setup_failed"] {
            let wire = json!({
                "task_id": Uuid::new_v4(), "conversation_id": "setup-conversation",
                "state": "waiting", "files": [], "created_at": "2026-10-24T01:00:00Z",
                "serving_fallback": false,
                "activation": {"recovering_automatically": true, "attempts": 2,
                    "last_refusal_permanence": "transient", "next_attempt_at": "2026-10-24T01:01:00Z"},
                "hold_reason": reason,
                "queue_state": {"state": "waiting", "since": "2026-10-24T01:00:00Z",
                    "attempts": 0, "reason": reason}
            });
            let task: crate::CloudConversationTask = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(task).unwrap(), wire);
            for pointer in ["/hold_reason", "/queue_state/reason"] {
                let mut invalid = wire.clone();
                *invalid.pointer_mut(pointer).unwrap() = json!("setup_unknown");
                assert!(serde_json::from_value::<crate::CloudConversationTask>(invalid).is_err());
            }
        }
    }

    #[test]
    fn conversation_tasks_preserve_retry_refusals_and_require_serving_evidence() {
        for end_reason in ["retry_refused", "retry_limit", "hold_expired"] {
            let wire = json!({"task_id": Uuid::new_v4(), "conversation_id": "held-conversation",
                "state": "removed", "files": [], "created_at": "2026-10-24T01:00:00Z",
                "activation": {"recovering_automatically": false, "attempts": 3,
                    "last_refusal_permanence": "permanent_for_this_spec"},
                "serving_fallback": true, "desired_revision": 9, "serving_revision": 8,
                "end_reason": end_reason, "retry_refusal": "admission_refused",
                "retry_refused_at": "2026-10-24T01:02:00Z",
                "queue_state": {"state": "waiting", "since": "2026-10-24T01:02:00Z", "attempts": 2}});
            let task: crate::CloudConversationTask = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(task).unwrap(), wire);
            for (field, value) in [
                ("activation", json!(null)),
                ("end_reason", json!("unknown")),
                ("retry_refusal", json!("unknown")),
                ("retry_refused_at", json!("not-a-timestamp")),
                ("serving_fallback", json!(null)),
            ] {
                let mut malformed = wire.clone();
                malformed[field] = value;
                assert!(serde_json::from_value::<crate::CloudConversationTask>(malformed).is_err());
            }
            for field in ["activation", "serving_fallback"] {
                let mut missing = wire.clone();
                missing.as_object_mut().unwrap().remove(field);
                assert!(serde_json::from_value::<crate::CloudConversationTask>(missing).is_err());
            }
        }
    }

    #[test]
    fn managed_owner_and_update_views_preserve_serving_revisions() {
        let owner_wire = json!({"id": Uuid::new_v4(), "organization_id": Uuid::new_v4(),
            "name": "Researcher", "skill_slug": "research", "mode": "cron", "platform_managed": true,
            "status": "running", "desired_lifecycle_state": "running",
            "template": {"slug": "research", "display_name": "Researcher", "revision": 9},
            "desired_revision": 9, "serving_revision": 8, "serving_fallback": true,
            "run_kinds": [], "spend_limits": {"per_task_atomic": 2000000, "per_day_atomic": 10000000,
                "day_timezone": "UTC", "defaults": {"per_task_atomic": 2000000, "per_day_atomic": 10000000}, "run_kinds": []},
            "created_at": "2026-10-24T01:00:00Z", "updated_at": "2026-10-24T01:00:00Z"});
        let owner: crate::ManagedAgentOwnerView =
            serde_json::from_value(owner_wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(owner).unwrap(), owner_wire);
        let mut update_wire = template_update_with_activation(
            json!({"progress": "pending", "availability": "pending",
                "recovering_automatically": true, "attempts": 2, "last_refusal_permanence": "transient"}),
        );
        update_wire["desired_revision"] = json!(9);
        update_wire["serving_revision"] = json!(8);
        update_wire["serving_fallback"] = json!(true);
        let update: crate::ManagedAgentTemplateUpdate =
            serde_json::from_value(update_wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(update).unwrap(), update_wire);
        for mut wire in [owner_wire, update_wire] {
            wire.as_object_mut().unwrap().remove("serving_fallback");
            if wire.get("template_slug").is_some() {
                assert!(serde_json::from_value::<crate::ManagedAgentTemplateUpdate>(wire).is_err());
            } else {
                assert!(serde_json::from_value::<crate::ManagedAgentOwnerView>(wire).is_err());
            }
        }
        for state in ["pending", "delivered", "failed", "unconfigured"] {
            let decoded: crate::ManagedAgentHealthIncidentDeliveryState =
                serde_json::from_value(json!(state)).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), state);
        }
        assert!(
            serde_json::from_value::<crate::ManagedAgentHealthIncidentDeliveryState>(json!(
                "unknown"
            ))
            .is_err()
        );
    }

    #[test]
    fn publisher_continuations_preserve_setup_and_stopped_errors() {
        for error in ["setup_pending", "setup_failed", "stopped"] {
            let wire = json!({"outcome": "granted", "error": error,
                "activation": {"recovering_automatically": true, "attempts": 2,
                    "last_refusal_permanence": "unknown"}});
            let continuation: crate::PublisherAccessContinuation =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(continuation).unwrap(), wire);
        }
        assert!(
            serde_json::from_value::<crate::PublisherAccessContinuation>(json!({
                "outcome": "granted", "error": "setup_unknown",
                "activation": {"recovering_automatically": false, "attempts": 0,
                    "last_refusal_permanence": "unknown"}
            }))
            .is_err()
        );
    }

    #[test]
    fn recovery_status_preserves_schedule_and_rejects_invalid_evidence() {
        for permanence in [
            "permanent_for_this_spec",
            "transient",
            "capability",
            "needs_controller_change",
            "unknown",
        ] {
            for next_attempt_at in [None, Some(json!(null)), Some(json!("2026-10-24T01:01:00Z"))] {
                let mut wire = json!({"recovering_automatically": true, "attempts": 3,
                    "last_refusal_permanence": permanence});
                if let Some(next_attempt_at) = next_attempt_at {
                    wire["next_attempt_at"] = next_attempt_at;
                }
                let decoded: crate::RecoveryStatus = serde_json::from_value(wire.clone()).unwrap();
                if wire
                    .get("next_attempt_at")
                    .is_some_and(serde_json::Value::is_null)
                {
                    wire.as_object_mut().unwrap().remove("next_attempt_at");
                }
                assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
            }
        }
        let unscheduled = json!({"recovering_automatically": false, "attempts": 0,
            "last_refusal_permanence": "unknown"});
        let decoded: crate::RecoveryStatus = serde_json::from_value(unscheduled.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), unscheduled);
        for field in [
            "recovering_automatically",
            "attempts",
            "last_refusal_permanence",
        ] {
            for explicit_null in [false, true] {
                let mut wire = unscheduled.clone();
                if explicit_null {
                    wire[field] = json!(null);
                } else {
                    wire.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    serde_json::from_value::<crate::RecoveryStatus>(wire).is_err(),
                    "{field}"
                );
            }
        }
        for (field, value) in [
            ("recovering_automatically", json!("false")),
            ("attempts", json!(1.5)),
            ("last_refusal_permanence", json!("future_refusal")),
            ("next_attempt_at", json!("not-a-timestamp")),
        ] {
            let mut wire = unscheduled.clone();
            wire[field] = value;
            assert!(
                serde_json::from_value::<crate::RecoveryStatus>(wire).is_err(),
                "{field}"
            );
        }
        let health_wire = json!({"activation": unscheduled, "deployment_id": Uuid::new_v4(),
            "name": "Researcher", "agent_slug": "research", "status": "pending",
            "desired_lifecycle_state": "running", "desired_egress_state": "enabled",
            "control_generation": 3, "mode": "always_on", "compute_backend": "aws_container",
            "runtime_kind": "rust", "created_at": "2026-10-24T01:00:00Z",
            "updated_at": "2026-10-24T01:00:00Z"});
        let health: crate::ManagedAgentDeploymentHealth =
            serde_json::from_value(health_wire.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(health).unwrap()["activation"],
            unscheduled
        );
        for explicit_null in [false, true] {
            let mut wire = health_wire.clone();
            if explicit_null {
                wire["activation"] = json!(null);
            } else {
                wire.as_object_mut().unwrap().remove("activation");
            }
            assert!(serde_json::from_value::<crate::ManagedAgentDeploymentHealth>(wire).is_err());
        }
        for activation in [None, Some(json!(null))] {
            let mut wire = json!({"outcome": "granted", "error": "setup_pending"});
            if let Some(activation) = activation {
                wire["activation"] = activation;
            }
            assert!(serde_json::from_value::<crate::PublisherAccessContinuation>(wire).is_err());
        }
    }

    fn template_update_with_activation(activation: serde_json::Value) -> serde_json::Value {
        json!({
            "template_slug": "release-test", "current_revision": 8, "newest_revision": 9,
            "state": "applying", "decision_needed": false, "serving_fallback": false,
            "setting": "ask_first", "setting_source": "hire", "activation": activation
        })
    }

    #[tokio::test]
    async fn template_update_http_preserves_activation_states() {
        for (progress, availability) in [
            ("pending", "pending"),
            ("applied", "ready"),
            ("applied", "stopped"),
            ("staged_next_start", "stopped"),
            ("failed", "unverified"),
            ("superseded", "unverified"),
            ("unverified", "unverified"),
        ] {
            let server = MockServer::start().await;
            let deployment_id = Uuid::new_v4();
            let mut activation = json!({
                "progress": progress, "availability": availability,
                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown",
                "revision_id": Uuid::new_v4(), "action_id": Uuid::new_v4(),
                "is_current_revision": true
            });
            if progress == "pending" {
                activation["recovering_automatically"] = json!(true);
                activation["attempts"] = json!(2);
                activation["last_refusal_permanence"] = json!("transient");
                activation["next_attempt_at"] = json!("2026-10-24T01:01:00Z");
            }
            if progress == "applied" {
                activation["applied_at"] = json!("2026-10-24T01:00:00Z");
            } else if progress == "failed" {
                activation["attempts"] = json!(3);
                activation["last_refusal_permanence"] = json!("permanent_for_this_spec");
                activation["failure"] = json!("runtime_rejected");
                activation["controller_refusal_kind"] = json!("workload_rejected");
                activation["obstruction"] = json!("terminal_failure");
            } else if progress == "superseded" {
                activation["is_current_revision"] = json!(false);
                activation["obstruction"] = json!("binding_superseded");
            } else if progress == "unverified" {
                activation["revision_id"] = serde_json::Value::Null;
                activation["action_id"] = serde_json::Value::Null;
                activation["is_current_revision"] = serde_json::Value::Null;
                activation["obstruction"] = json!("incomplete_evidence");
            }
            let wire = json!({"data": template_update_with_activation(activation.clone())});
            Mock::given(method("GET"))
                .and(path(format!(
                    "/publishers/seren-agent/deployments/{deployment_id}/updates"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(wire))
                .expect(1)
                .mount(&server)
                .await;
            let response = Client::new(&server.uri())
                .seren_agent_get_managed_agent_template_update(&deployment_id)
                .await
                .unwrap()
                .into_inner();
            let actual = serde_json::to_value(response).unwrap();
            assert_eq!(actual["data"]["current_revision"], 8);
            // Null evidence is omitted on re-encoding; nothing is defaulted or added.
            activation
                .as_object_mut()
                .unwrap()
                .retain(|_, value| !value.is_null());
            assert_eq!(actual["data"]["activation"], activation, "{progress}");
        }
    }

    #[test]
    fn template_update_activation_preserves_nullable_and_absent_evidence() {
        let fields = [
            "revision_id",
            "action_id",
            "applied_at",
            "is_current_revision",
            "failure",
            "obstruction",
            "controller_refusal_kind",
            "next_attempt_at",
        ];
        for explicit_null in [false, true] {
            let mut activation = json!({"progress": "unverified", "availability": "unverified",
                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"});
            if explicit_null {
                for field in fields {
                    activation[field] = serde_json::Value::Null;
                }
            }
            let decoded: crate::ManagedAgentTemplateUpdate =
                serde_json::from_value(template_update_with_activation(activation)).unwrap();
            let actual = serde_json::to_value(decoded).unwrap();
            assert_eq!(
                actual["activation"],
                json!({"progress": "unverified", "availability": "unverified",
                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
                "explicit null: {explicit_null}"
            );
        }
        let mut wire = template_update_with_activation(json!({
            "progress": "superseded", "availability": "unverified", "is_current_revision": false,
            "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"
        }));
        let decoded: crate::ManagedAgentTemplateUpdate =
            serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap()["activation"]["is_current_revision"],
            false
        );
        for omit in [false, true] {
            if omit {
                wire.as_object_mut().unwrap().remove("activation");
            } else {
                wire["activation"] = serde_json::Value::Null;
            }
            let decoded: crate::ManagedAgentTemplateUpdate =
                serde_json::from_value(wire.clone()).unwrap();
            assert!(
                serde_json::to_value(decoded)
                    .unwrap()
                    .get("activation")
                    .is_none()
            );
        }
    }

    #[test]
    fn template_update_activation_rejects_invalid_values_and_evidence() {
        for (field, value) in [
            ("progress", json!("ready")),
            ("availability", json!("applied")),
            ("obstruction", json!("unknown")),
            ("failure", json!("unknown")),
            ("controller_refusal_kind", json!("future_kind")),
            ("revision_id", json!("not-a-uuid")),
            ("action_id", json!("not-a-uuid")),
            ("is_current_revision", json!("false")),
            ("applied_at", json!("not-a-timestamp")),
            ("recovering_automatically", json!("false")),
            ("attempts", json!("0")),
            ("last_refusal_permanence", json!("future_refusal")),
            ("next_attempt_at", json!("not-a-timestamp")),
        ] {
            let mut activation = json!({"progress": "unverified", "availability": "unverified",
                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"});
            activation[field] = value;
            assert!(
                serde_json::from_value::<crate::ManagedAgentTemplateUpdate>(
                    template_update_with_activation(activation)
                )
                .is_err(),
                "{field}"
            );
        }
        for field in [
            "progress",
            "availability",
            "recovering_automatically",
            "attempts",
            "last_refusal_permanence",
        ] {
            for explicit_null in [false, true] {
                let mut activation = json!({"progress": "unverified", "availability": "unverified",
                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"});
                if explicit_null {
                    activation[field] = serde_json::Value::Null;
                } else {
                    activation.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    serde_json::from_value::<crate::ManagedAgentTemplateUpdate>(
                        template_update_with_activation(activation)
                    )
                    .is_err(),
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn runtime_actions_preserve_typed_controller_refusals() {
        let wire = json!({
            "id": Uuid::new_v4(), "request_id": Uuid::new_v4(), "deployment_id": Uuid::new_v4(),
            "revision_id": Uuid::new_v4(), "state": "failed", "target": "controller",
            "control_generation": 3, "desired_runtime_fingerprint": "desired", "attempt_count": 1,
            "status_path": "/action-status", "accepted_at": "2026-10-24T01:00:00Z",
            "updated_at": "2026-10-24T01:00:00Z", "reason": "runtime_rejected"
        });
        for (kind, code) in [
            ("invalid_request", "workload_not_admitted"),
            ("peer_contract_mismatch", "controller_request_undecodable"),
            (
                "peer_contract_mismatch",
                "secrets_gateway_issuer_contract_mismatch",
            ),
            ("workload_rejected", "workload_not_admitted"),
            ("secrets_gateway_material", "secret_material_missing"),
            ("deployment_strategy_transition", "strategy_change_blocked"),
            ("runtime_intent_mismatch", "intent_mismatch"),
            // The code is open: a code this SDK has never seen is preserved verbatim.
            ("unknown", "controller_code_added_later"),
        ] {
            let mut wire = wire.clone();
            wire["controller_refusal"] = json!({"code": code, "kind": kind});
            let action: crate::ManagedRuntimeReconciliationSummary =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(action).unwrap(), wire);
        }
        for refusal in [None, Some(serde_json::Value::Null)] {
            let mut absent = wire.clone();
            if let Some(refusal) = refusal {
                absent["controller_refusal"] = refusal;
            }
            let action: crate::ManagedRuntimeReconciliationSummary =
                serde_json::from_value(absent).unwrap();
            assert_eq!(serde_json::to_value(action).unwrap(), wire);
        }
        for refusal in [
            json!({"code": "workload_not_admitted", "kind": "future_kind"}),
            json!({"code": "workload_not_admitted", "kind": null}),
            json!({"code": null, "kind": "workload_rejected"}),
            json!({"code": "workload_not_admitted"}),
            json!({"kind": "workload_rejected"}),
            json!("workload_not_admitted"),
        ] {
            let mut invalid = wire.clone();
            invalid["controller_refusal"] = refusal;
            assert!(
                serde_json::from_value::<crate::ManagedRuntimeReconciliationSummary>(invalid)
                    .is_err()
            );
        }
    }

    #[test]
    fn script_approval_preserves_the_exact_reviewed_action() {
        let wire = json!({
            "publisher_slug": "slack",
            "operation_id": "post_messages",
            "operation_binding": {"kind": "reviewed", "binding_sha256": "a".repeat(64)},
            "payload_digest": format!("sha256:{}", "b".repeat(64)),
            "consequences": ["A message is posted"],
            "purpose": "action",
            "operation": {"transport": "api", "method": "POST", "path": "/messages", "description": "Post message"},
            "request": {"publisher": "slack", "operation": "post", "path": "/messages", "connection_id": "approved-account", "body": {"channel": "test-channel", "text": "Exact proposed text"}}
        });
        let approval: crate::CloudRunScriptPublisherApproval =
            serde_json::from_value(wire.clone()).expect("current script action");
        assert_eq!(serde_json::to_value(approval).unwrap(), wire);
    }

    #[test]
    fn script_approval_without_retained_review_evidence_remains_readable() {
        let wire = json!({
            "publisher_slug": "slack",
            "operation_id": "post_messages",
            "operation_binding": {"kind": "reviewed", "binding_sha256": "a".repeat(64)},
            "payload_digest": format!("sha256:{}", "b".repeat(64))
        });
        let approval: crate::CloudRunScriptPublisherApproval =
            serde_json::from_value(wire.clone()).expect("retained script hold");
        assert!(approval.purpose.is_none());
        assert!(approval.operation.is_none());
        assert!(approval.request.is_none());
        assert_eq!(serde_json::to_value(approval).unwrap(), wire);
    }

    #[test]
    fn script_approval_rejects_an_unknown_reviewed_purpose() {
        let wire = json!({
            "publisher_slug": "slack",
            "operation_id": "post_messages",
            "operation_binding": {"kind": "reviewed", "binding_sha256": "a".repeat(64)},
            "payload_digest": format!("sha256:{}", "b".repeat(64)),
            "purpose": "unreviewed"
        });
        assert!(serde_json::from_value::<crate::CloudRunScriptPublisherApproval>(wire).is_err());
    }

    #[test]
    fn managed_memory_resources_decode_the_current_policy_contract() {
        let wire = json!({
            "policy_configured": true,
            "semantic_memory_enabled": true,
            "graph_memory_enabled": false,
            "knowledge_enabled": true
        });
        let resources: crate::ManagedAgentMemoryResources =
            serde_json::from_value(wire.clone()).expect("current memory resources");
        assert!(resources.policy_configured);
        assert!(resources.semantic_memory_enabled);
        assert!(!resources.graph_memory_enabled);
        assert!(resources.knowledge_enabled);
        assert_eq!(serde_json::to_value(resources).unwrap(), wire);
    }

    fn run_fee_measurement_fixture() -> serde_json::Value {
        json!({
            "model_id": "opus-5-5", "model_name": "Claude Opus 5.5",
            "runs": 10, "window_days": 30, "average_atomic": 0,
            "median_atomic": 0, "p90_atomic": 0, "average_price_atomic": 500000,
            "computed_at": "2026-10-24T03:00:00Z", "price_list_version": 7
        })
    }

    fn run_fee_view_fixture(measured: bool) -> serde_json::Value {
        let measurement = run_fee_measurement_fixture();
        json!({"data": {
            "run_kind": "work", "name": "Work", "charge": "fee",
            "atomic": 500000, "usd": "$0.50", "owner_share_atomic": 350000,
            "minimum": {"atomic": 300000, "usd": "$0.30", "compute_atomic": 3600,
                "model_atomic": 189400, "wake_atomic": 105000,
                "computed_at": "2026-10-24T03:00:00Z", "price_list_version": 7},
            "measured_cost": if measured { measurement.clone() } else { serde_json::Value::Null },
            "measured_cost_by_model": if measured { vec![measurement] } else { vec![] }
        }})
    }

    fn run_fee_history_fixture() -> serde_json::Value {
        json!({"data": [
            {"changed_at": "2026-10-25T03:00:00Z", "previous_atomic": 500000,
                "current_atomic": 600000, "changed_by_user_id": null, "reason": "minimum"},
            {"changed_at": "2026-10-24T03:00:00Z", "previous_atomic": 0,
                "current_atomic": 500000, "changed_by_user_id": Uuid::from_u128(1), "reason": "owner"}
        ]})
    }

    /// An absent optional value and an explicit null have the same contract meaning.
    fn remove_null_field(value: &mut serde_json::Value, pointer: &str, field: &str) {
        let object = value.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        if object.get(field).is_some_and(serde_json::Value::is_null) {
            object.remove(field);
        }
    }

    /// Producer refusal bodies; only the conflict carries details.
    fn run_fee_refusal_fixtures() -> Vec<(u16, serde_json::Value)> {
        let minimum = run_fee_view_fixture(false)["data"]["minimum"].clone();
        vec![
            (
                400,
                json!({"error": "BadRequest",
                "message": "run_fee_atomic must be nonnegative and a whole number of cents."}),
            ),
            (
                401,
                json!({"error": "Unauthorized", "message": "Authentication required"}),
            ),
            (
                403,
                json!({"error": "managed_agent_run_fee_owner_required",
                "message": "Only a built-in Owner using an unrestricted direct credential of this organization can manage its Employee fees."}),
            ),
            (
                404,
                json!({"error": "managed_agent_run_fee_not_applicable",
                "message": "This cost-only run kind has no service fee."}),
            ),
            (
                409,
                json!({"error": "run_fee_below_minimum",
                "message": "An Employee's run fee can't be below its minimum of $0.30.",
                "details": {"run_kind": "work", "run_fee_atomic": 0, "minimum": minimum}}),
            ),
        ]
    }

    #[tokio::test]
    async fn managed_agent_run_fee_http_preserves_owner_measurements_and_history() {
        use wiremock::matchers::header;
        let organization_id = Uuid::from_u128(42);
        let route = format!("/organizations/{organization_id}/templates/fee-test/fees/work");
        for measured in [false, true] {
            let server = MockServer::start().await;
            let wire = run_fee_view_fixture(measured);
            Mock::given(method("GET"))
                .and(path(&route))
                .and(header("authorization", "Bearer fee-owner-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::from_config(
                &ClientConfig::new("fee-owner-key").with_base_url(server.uri()),
            )
            .unwrap();
            let response = client
                .get_managed_agent_run_fee(&organization_id, "fee-test", "work")
                .await
                .unwrap()
                .into_inner();
            let mut expected = wire;
            let mut actual = serde_json::to_value(response).unwrap();
            for value in [&mut expected, &mut actual] {
                remove_null_field(value, "/data", "measured_cost");
            }
            assert_eq!(actual, expected);
            server.verify().await;
        }
        let server = MockServer::start().await;
        let request_wire = json!({"run_fee_atomic": 500000});
        let amount = json!({"data": {"atomic": 500000, "usd": "$0.50"}});
        Mock::given(method("PUT"))
            .and(path(&route))
            .and(header("authorization", "Bearer fee-owner-key"))
            .and(body_json(request_wire.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(amount.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let history = run_fee_history_fixture();
        Mock::given(method("GET"))
            .and(path(format!("{route}/history")))
            .and(header("authorization", "Bearer fee-owner-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let client =
            Client::from_config(&ClientConfig::new("fee-owner-key").with_base_url(server.uri()))
                .unwrap();
        let request: crate::SetManagedAgentRunFee =
            serde_json::from_value(request_wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), request_wire);
        let response = client
            .set_managed_agent_run_fee(&organization_id, "fee-test", "work", &request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(serde_json::to_value(response).unwrap(), amount);
        let response = client
            .list_managed_agent_run_fee_changes(&organization_id, "fee-test", "work")
            .await
            .unwrap()
            .into_inner();
        let mut expected = history;
        let mut actual = serde_json::to_value(response).unwrap();
        // A minimum increase has no Owner actor.
        for value in [&mut expected, &mut actual] {
            remove_null_field(value, "/data/0", "changed_by_user_id");
        }
        assert_eq!(actual, expected);
        assert_eq!(
            actual["data"][1]["changed_by_user_id"],
            json!(Uuid::from_u128(1))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn managed_agent_run_fee_http_rejects_incomplete_or_invalid_contracts() {
        let organization_id = Uuid::from_u128(42);
        let route = format!("/organizations/{organization_id}/templates/fee-test/fees/work");
        let mut invalid = Vec::new();
        for field in ["owner_share_atomic", "measured_cost_by_model"] {
            let mut wire = run_fee_view_fixture(true);
            wire["data"].as_object_mut().unwrap().remove(field);
            invalid.push(wire);
        }
        let mut wire = run_fee_view_fixture(true);
        wire["data"]["measured_cost"]["computed_at"] = json!("not-a-timestamp");
        invalid.push(wire);
        let mut wire = run_fee_view_fixture(true);
        wire["data"]["measured_cost_by_model"][0]
            .as_object_mut()
            .unwrap()
            .remove("price_list_version");
        invalid.push(wire);
        // A measurement admits no extra figures, such as a derived total.
        let mut wire = run_fee_view_fixture(true);
        wire["data"]["measured_cost"]["total_atomic"] = json!(500000);
        invalid.push(wire);
        for wire in invalid {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(&route))
                .respond_with(ResponseTemplate::new(200).set_body_json(wire))
                .expect(1)
                .mount(&server)
                .await;
            let result = Client::new(&server.uri())
                .get_managed_agent_run_fee(&organization_id, "fee-test", "work")
                .await;
            assert!(matches!(
                result,
                Err(crate::Error::InvalidResponsePayload(..))
            ));
            server.verify().await;
        }
        let server = MockServer::start().await;
        let mut wire = run_fee_history_fixture();
        wire["data"][0]["reason"] = json!("unknown_reason");
        Mock::given(method("GET"))
            .and(path(format!("{route}/history")))
            .respond_with(ResponseTemplate::new(200).set_body_json(wire))
            .expect(1)
            .mount(&server)
            .await;
        let result = Client::new(&server.uri())
            .list_managed_agent_run_fee_changes(&organization_id, "fee-test", "work")
            .await;
        assert!(matches!(
            result,
            Err(crate::Error::InvalidResponsePayload(..))
        ));
        server.verify().await;
    }

    #[tokio::test]
    async fn managed_agent_run_fee_http_preserves_refusal_status_and_body() {
        for (status, wire) in run_fee_refusal_fixtures() {
            let server = MockServer::start().await;
            let organization_id = Uuid::from_u128(42);
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/fee-test/fees/work"
                )))
                .and(body_json(json!({"run_fee_atomic": 0})))
                .respond_with(ResponseTemplate::new(status).set_body_json(wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let request: crate::SetManagedAgentRunFee =
                serde_json::from_value(json!({"run_fee_atomic": 0})).unwrap();
            let error = Client::new(&server.uri())
                .set_managed_agent_run_fee(&organization_id, "fee-test", "work", &request)
                .await
                .unwrap_err();
            let crate::Error::UnexpectedResponse(response) = error else {
                panic!("fee refusal must retain its HTTP response");
            };
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.json::<serde_json::Value>().await.unwrap(), wire);
            server.verify().await;
        }
    }

    fn template_release_request_wire() -> serde_json::Value {
        json!({
            "display_name": "Release test",
            "listed": true,
            "source_bundle_id": Uuid::new_v4(),
            "source_commit_sha": "a".repeat(40),
            "deploy_defaults": {
                "mode": "cron",
                "cron_schedule": "0 9 * * *",
                "model_policy": "balanced",
                "max_runtime_seconds": 300,
                "browser": {"display": "headless", "max_session_seconds": 60},
                "network_egress": [],
                "script_publisher_grants": []
            }
        })
    }

    #[tokio::test]
    async fn a_release_sends_its_hires_tool_output_limit() {
        let server = MockServer::start().await;
        let organization_id = Uuid::new_v4();
        let mut request_wire = template_release_request_wire();
        request_wire["deploy_defaults"]["max_tool_output_chars"] = json!(40_000);
        let request: crate::PublishManagedAgentTemplateReleaseRequest =
            serde_json::from_value(request_wire.clone()).unwrap();
        assert_eq!(request.deploy_defaults.max_tool_output_chars, Some(40_000));
        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{organization_id}/templates/release-test/releases"
            )))
            .and(body_json(request_wire))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": true, "active": true, "listed": true, "review_state": "approved",
                "providers": ["google"]
            }})))
            .expect(1)
            .mount(&server)
            .await;
        Client::new(&server.uri())
            .publish_managed_agent_template_release(&organization_id, "release-test", &request)
            .await
            .unwrap();
        server.verify().await;
    }

    #[test]
    fn a_release_without_a_tool_output_limit_leaves_it_to_the_model_policy() {
        let wire = template_release_request_wire();
        let request: crate::PublishManagedAgentTemplateReleaseRequest =
            serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(request.deploy_defaults.max_tool_output_chars, None);
        assert_eq!(serde_json::to_value(&request).unwrap(), wire);
    }

    #[test]
    fn a_publication_preview_shows_the_deployments_tool_output_limit() {
        let mut deploy_defaults = template_release_request_wire()["deploy_defaults"].clone();
        deploy_defaults["max_tool_output_chars"] = json!(40_000);
        let wire = json!({"published_files": [], "removed_files": [],
            "deploy_defaults": deploy_defaults, "omitted_tools": [], "changes": []});
        let preview: crate::ManagedAgentDeploymentPublicationPreview =
            serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(preview.deploy_defaults.max_tool_output_chars, Some(40_000));
        assert_eq!(serde_json::to_value(preview).unwrap(), wire);
    }

    #[test]
    fn an_employer_sees_the_tool_output_limit_a_hire_runs_with() {
        let wire = json!({"id": Uuid::new_v4(), "organization_id": Uuid::new_v4(),
            "name": "Vera Hale", "skill_slug": "vera-hale", "mode": "cron", "platform_managed": true,
            "status": "running", "desired_lifecycle_state": "running",
            "template": {"slug": "vera-hale", "display_name": "Vera Hale", "revision": 9},
            "serving_fallback": false, "run_kinds": [],
            "spend_limits": {"per_task_atomic": 6000000, "per_day_atomic": 30000000,
                "day_timezone": "UTC", "defaults": {"per_task_atomic": 6000000, "per_day_atomic": 30000000}, "run_kinds": []},
            "max_tool_output_chars": 40000,
            "created_at": "2026-11-01T01:00:00Z", "updated_at": "2026-11-01T01:00:00Z"});
        let view: crate::CloudDeploymentView = serde_json::from_value(wire.clone()).unwrap();
        let crate::CloudDeploymentView::ManagedAgentOwnerView(owner) = view else {
            panic!("a hire decodes as the Employer's view");
        };
        assert_eq!(owner.max_tool_output_chars, Some(40_000));
        assert_eq!(serde_json::to_value(owner).unwrap(), wire);
    }

    #[tokio::test]
    async fn template_publication_preserves_rollout_requests_and_applied_revision() {
        for rollout in [None, Some(false), Some(true)] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let mut request_wire = template_release_request_wire();
            request_wire["listed"] = json!(rollout != Some(false));
            if let Some(rollout) = rollout {
                request_wire["rollout"] = json!(rollout);
            }
            if rollout == Some(true) {
                request_wire["release_note"] = json!("Use the updated design guidance.");
            }
            let request: crate::PublishManagedAgentTemplateReleaseRequest =
                serde_json::from_value(request_wire.clone()).unwrap();
            assert_eq!(request.rollout, rollout);
            assert_eq!(serde_json::to_value(&request).unwrap(), request_wire);
            let mut response_wire = json!({"data": {
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true, "listed": false, "review_state": "pending",
                "providers": ["google", "microsoft"]
            }});
            if rollout == Some(false) {
                response_wire["data"]["rollout"] = serde_json::Value::Null;
            } else if rollout == Some(true) {
                // Installing reports the current revision's pending activation.
                let installing_revision = Uuid::new_v4();
                response_wire["data"]["rollout"] = json!({
                    "template_slug": "release-test", "template_revision": 8,
                    "deployments": [
                        {"deployment_id": Uuid::new_v4(), "outcome": "updated", "revision_id": Uuid::new_v4(),
                            "activation": {"progress": "applied", "availability": "ready",
                                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "applying", "revision_id": Uuid::new_v4(),
                            "activation": {"progress": "pending", "availability": "pending",
                                "recovering_automatically": true, "attempts": 1,
                                "last_refusal_permanence": "transient", "next_attempt_at": "2026-10-24T01:01:00Z"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "installing", "revision_id": installing_revision,
                            "activation": {"progress": "pending", "availability": "pending",
                                "revision_id": installing_revision, "is_current_revision": true,
                                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "staged", "revision_id": Uuid::new_v4(),
                            "activation": {"progress": "staged_next_start", "availability": "stopped",
                                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "superseded", "revision_id": Uuid::new_v4(),
                            "activation": {"progress": "superseded", "availability": "unverified",
                                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "unverified", "revision_id": null,
                            "activation": {"progress": "unverified", "availability": "unverified",
                                "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}},
                        {"deployment_id": Uuid::new_v4(), "outcome": "already_current", "revision_id": Uuid::new_v4()},
                        {"deployment_id": Uuid::new_v4(), "outcome": "hire_incomplete", "revision_id": null, "failure": null},
                        {"deployment_id": Uuid::new_v4(), "outcome": "pending_approval"},
                        {"deployment_id": Uuid::new_v4(), "outcome": "declined"},
                        {"deployment_id": Uuid::new_v4(), "outcome": "staying"},
                        {"deployment_id": Uuid::new_v4(), "outcome": "held"},
                        {"deployment_id": Uuid::new_v4(), "outcome": "waiting_for_task"},
                        {"deployment_id": Uuid::new_v4(), "outcome": "failed", "failure": "revision_conflict"}
                    ]
                });
            }
            Mock::given(method("POST"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/release-test/releases"
                )))
                .and(body_json(request_wire))
                .respond_with(ResponseTemplate::new(200).set_body_json(response_wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::new(&server.uri());
            let response = client
                .publish_managed_agent_template_release(&organization_id, "release-test", &request)
                .await
                .unwrap()
                .into_inner();
            let decoded = serde_json::to_value(response).unwrap();
            assert_eq!(decoded["data"]["revision"], 7);
            assert_eq!(decoded["data"]["providers"], json!(["google", "microsoft"]));
            if rollout == Some(true) {
                assert_eq!(decoded["data"]["rollout"]["template_revision"], 8);
                assert_eq!(
                    decoded["data"]["rollout"]["deployments"]
                        .as_array()
                        .unwrap()
                        .len(),
                    14
                );
                for (decoded, wire) in decoded["data"]["rollout"]["deployments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .zip(
                        response_wire["data"]["rollout"]["deployments"]
                            .as_array()
                            .unwrap(),
                    )
                {
                    // Null fields are omitted on re-encoding; nothing is defaulted or added.
                    let mut expected = wire.clone();
                    expected
                        .as_object_mut()
                        .unwrap()
                        .retain(|_, value| !value.is_null());
                    assert_eq!(decoded, &expected);
                }
            } else {
                assert!(decoded["data"]["rollout"].is_null());
            }
        }
    }

    #[test]
    fn template_release_providers_preserve_the_admitted_contract() {
        for providers in [json!([]), json!(["google"]), json!(["google", "microsoft"])] {
            let wire = json!({
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true, "listed": false, "review_state": "pending", "providers": providers
            });
            let release: crate::ManagedAgentTemplateRelease =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(
                serde_json::to_value(release).unwrap()["providers"],
                providers
            );
        }
        for providers in [None, Some(json!(["other"]))] {
            let mut wire = json!({
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true, "listed": false, "review_state": "pending"
            });
            if let Some(providers) = providers {
                wire["providers"] = providers;
            }
            assert!(serde_json::from_value::<crate::ManagedAgentTemplateRelease>(wire).is_err());
        }
    }

    #[test]
    fn template_release_requires_listing_and_review_evidence() {
        for field in ["listed", "review_state"] {
            for value in [None, Some(json!(null)), Some(json!("unknown"))] {
                let mut wire = json!({"slug": "research", "revision": 7, "created": false,
                    "revision_added": false, "active": true, "listed": false,
                    "review_state": "rejected", "review_reason": "Clarify the description.", "providers": []});
                if let Some(value) = value {
                    wire[field] = value;
                } else {
                    wire.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    serde_json::from_value::<crate::ManagedAgentTemplateRelease>(wire).is_err()
                );
            }
        }
        for listed in [true, false] {
            let wire = json!({"deployment_id": Uuid::new_v4(), "display_name": "Researcher", "listed": listed});
            let request: crate::PublishManagedAgentDeploymentRequest =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(request).unwrap(), wire);
        }
    }

    #[test]
    fn template_rollout_rejects_unknown_outcomes_and_failures() {
        for outcome in [
            "updated",
            "applying",
            "installing",
            "staged",
            "superseded",
            "unverified",
            "already_current",
            "hire_incomplete",
            "pending_approval",
            "declined",
            "staying",
            "held",
            "waiting_for_task",
            "waiting_for_rollout",
            "cannot_install_yet",
            "failed",
        ] {
            let decoded: crate::TemplateRevisionOutcome =
                serde_json::from_value(json!(outcome)).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), json!(outcome));
        }
        for failure in [
            "revision_conflict",
            "superseded",
            "deployment_unavailable",
            "invalid_material",
            "template_suspended",
            "internal",
        ] {
            let decoded: crate::TemplateRevisionFailure =
                serde_json::from_value(json!(failure)).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), json!(failure));
        }
        assert!(
            serde_json::from_value::<crate::TemplateRevisionOutcome>(json!("pending")).is_err()
        );
        assert!(
            serde_json::from_value::<crate::TemplateRevisionFailure>(json!("unknown")).is_err()
        );
        for (outcome, failure) in [("pending", "internal"), ("failed", "unknown")] {
            let report = json!({"template_slug": "release-test", "template_revision": 8,
                "deployments": [{"deployment_id": Uuid::new_v4(), "outcome": outcome, "failure": failure}]
            });
            assert!(
                serde_json::from_value::<crate::AdminTemplateRevisionApplication>(report).is_err()
            );
        }
        let report_with_activation = |activation: serde_json::Value| {
            json!({"template_slug": "release-test", "template_revision": 8,
                "deployments": [{"deployment_id": Uuid::new_v4(), "outcome": "updated",
                    "revision_id": Uuid::new_v4(), "activation": activation}]
            })
        };
        let valid = report_with_activation(json!({"progress": "applied", "availability": "ready",
            "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}));
        let decoded: crate::AdminTemplateRevisionApplication =
            serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), valid);
        // Malformed activation fields retain complete recovery evidence to isolate their failures.
        for activation in [
            json!({"progress": "ready", "availability": "ready", "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
            json!({"progress": "applied", "availability": "applied", "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
            json!({"progress": "applied", "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
            json!({"availability": "ready", "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
            json!({"progress": "applied", "availability": "ready", "revision_id": "not-a-uuid", "recovering_automatically": false, "attempts": 0, "last_refusal_permanence": "unknown"}),
            json!("applied"),
            json!({"progress": "applied", "availability": "ready"}),
        ] {
            assert!(
                serde_json::from_value::<crate::AdminTemplateRevisionApplication>(
                    report_with_activation(activation)
                )
                .is_err()
            );
        }
        let mut request = template_release_request_wire();
        request["rollout"] = json!("true");
        assert!(
            serde_json::from_value::<crate::PublishManagedAgentTemplateReleaseRequest>(request)
                .is_err()
        );
    }

    fn public_template_list_wire(organization_id: Uuid) -> serde_json::Value {
        json!({
            "data": [{
                "slug": "release-test",
                "display_name": "Release test",
                "publisher": {"organization_id": organization_id, "name": "Acme Studio",
                    "handle": "acme-studio", "made_by_seren": false, "verified": true},
                "owner_connection": "mail_and_files",
                "spend_limit_defaults": {"per_task_atomic":2000000,"per_day_atomic":10000000},
                "published_at": "2026-10-07T12:34:56Z",
                "capabilities": ["Research"], "example_tasks": ["Summarize the latest report"],
                "works_in": ["1password", "google-drive", "slack"], "pronouns": "they/them",
                "job_title": "Researcher", "tagline": "Research made clear",
                "description": "Find primary sources.", "activity_url": "https://example.com/activity",
                "avatar_url": "https://example.com/avatar.png",
                "run_kinds": [{
                    "key": "run", "name": "Run", "charge": "fee",
                    "triggers": ["hire_cron", "schedule", "chat", "webhook", "api"],
                    "amount": {"atomic": 500000, "usd": "$0.50"}, "changed_at": null,
                    "expected_cost_atomic": 300000
                }],
                "catalog": {"hires_30d": 3, "hours_of_work": 802, "active_hires": 3,
                    "best_sellers_rank": 1, "seren_choice": false, "also_hired": ["iris"],
                    "rating": {"average": 5.0, "count": 1, "histogram": [100, 0, 0, 0, 0]},
                    "updated_at": "2026-11-01T04:00:03.759627Z"},
                "similar": [{"slug": "iris", "score": 0.842,
                    "shared": {"words": ["research"], "tools": ["slack"], "skills": []}}]
            }]
        })
    }

    #[tokio::test]
    async fn public_template_list_decodes_each_template_with_its_publisher() {
        let server = MockServer::start().await;
        let organization_id = Uuid::new_v4();
        let mut wire = public_template_list_wire(organization_id);
        // The listing's shared run-kind price must carry the recorded measurement.
        wire["data"][0]["run_kinds"][0]["measured_cost"] = run_fee_measurement_fixture();
        Mock::given(method("GET"))
            .and(path("/publishers/seren-agent/templates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(wire.clone()))
            .expect(1)
            .mount(&server)
            .await;

        let response = Client::new(&server.uri())
            .seren_agent_list_managed_agent_templates()
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.data.len(), 1);
        assert_eq!(response.data[0].publisher.organization_id, organization_id);
        assert_eq!(
            response.data[0].published_at,
            "2026-10-07T12:34:56Z".parse::<jiff::Timestamp>().unwrap()
        );
        // An absent optional timestamp and an explicit null have the same contract meaning.
        let mut expected = wire;
        let mut actual = serde_json::to_value(response).unwrap();
        for value in [&mut expected, &mut actual] {
            let price = value["data"][0]["run_kinds"][0].as_object_mut().unwrap();
            if price
                .get("changed_at")
                .is_some_and(serde_json::Value::is_null)
            {
                price.remove("changed_at");
            }
        }
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn template_stats_decode_before_core_first_computes_them() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/publishers/seren-agent/templates/vera-hale/stats"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                "run_kinds": [], "hours_of_work": 0, "skills_count": 0, "active_hires": 0,
                "threads_30d": 0, "top_skills": [], "updated_at": null
            }})))
            .expect(1)
            .mount(&server)
            .await;
        let stats = Client::new(&server.uri())
            .seren_agent_get_managed_agent_template_stats("vera-hale")
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stats.data.updated_at, None);
        server.verify().await;
    }

    fn template_profile_wire() -> serde_json::Value {
        json!({"avatar_url": "https://example.com/avatar.png", "capabilities": ["Research"],
            "description": "Find primary sources.", "example_tasks": ["Summarize a report"],
            "job_title": "Researcher", "pronouns": "they/them", "tagline": "Research made clear",
            "works_in": ["1password", "google-drive", "slack"]})
    }

    #[tokio::test]
    async fn template_profile_patch_http_preserves_partial_requests_and_complete_profiles() {
        for wire in [
            json!({}),
            json!({"tagline": null, "description": null, "job_title": null}),
            json!({"capabilities": [], "example_tasks": [], "works_in": []}),
            json!({"job_title": "Researcher", "pronouns": "she/her", "works_in": ["gmail"]}),
        ] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let request: crate::PutManagedAgentTemplateProfile =
                serde_json::from_value(wire.clone()).unwrap();
            let response_wire = json!({"data": template_profile_wire()});
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/research/profile"
                )))
                .and(body_json(wire))
                .respond_with(ResponseTemplate::new(200).set_body_json(response_wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let response = Client::new(&server.uri())
                .put_managed_agent_template_profile(&organization_id, "research", &request)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(serde_json::to_value(response).unwrap(), response_wire);
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn template_profile_http_rejects_missing_required_fields_and_unknown_values() {
        let mutations = [
            ("capabilities", None),
            ("example_tasks", None),
            ("works_in", None),
            ("pronouns", None),
            ("capabilities", Some(json!(null))),
            ("pronouns", Some(json!("unknown"))),
            ("works_in", Some(json!(["unknown"]))),
            ("example_tasks", Some(json!([null]))),
        ];
        for (field, value) in mutations {
            let mut profile = template_profile_wire();
            if let Some(value) = value {
                profile[field] = value;
            } else {
                profile.as_object_mut().unwrap().remove(field);
            }
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            Mock::given(method("GET"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/research/profile"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": profile})))
                .expect(1)
                .mount(&server)
                .await;
            let error = Client::new(&server.uri())
                .get_managed_agent_template_profile(&organization_id, "research")
                .await
                .expect_err("malformed profile must reject the typed response");
            assert!(
                matches!(error, crate::Error::InvalidResponsePayload(_, _)),
                "{field}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn public_template_http_rejects_missing_card_and_publisher_fields() {
        for pointer in [
            "/data/0/example_tasks",
            "/data/0/works_in",
            "/data/0/pronouns",
            "/data/0/catalog",
            "/data/0/publisher/made_by_seren",
            "/data/0/publisher/verified",
        ] {
            let mut wire = public_template_list_wire(Uuid::new_v4());
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            wire.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/publishers/seren-agent/templates"))
                .respond_with(ResponseTemplate::new(200).set_body_json(wire))
                .expect(1)
                .mount(&server)
                .await;
            let error = Client::new(&server.uri())
                .seren_agent_list_managed_agent_templates()
                .await
                .expect_err("incomplete card must reject the typed response");
            assert!(
                matches!(error, crate::Error::InvalidResponsePayload(_, _)),
                "{pointer}: {error:?}"
            );
        }
        for (pointer, value) in [
            ("/data/0/pronouns", json!("unknown")),
            ("/data/0/catalog", json!(null)),
            ("/data/0/works_in", json!(["unknown"])),
            ("/data/0/publisher/verified", json!("true")),
        ] {
            let mut wire = public_template_list_wire(Uuid::new_v4());
            *wire.pointer_mut(pointer).unwrap() = value;
            assert!(
                serde_json::from_value::<crate::ManagedAgentTemplateListing>(
                    wire["data"][0].clone()
                )
                .is_err()
            );
        }
    }

    fn organization_template_wire(review_state: &str) -> serde_json::Value {
        let mut wire = json!({"slug": "research", "display_name": "Researcher", "active": true,
            "listed": false, "current_revision": 7, "review_state": review_state,
            "source_deployment_id": Uuid::new_v4()});
        if review_state == "rejected" {
            wire["review_reason"] = json!("Add a clearer job description.");
        }
        wire
    }

    #[tokio::test]
    async fn template_listing_and_review_http_preserve_owner_decisions() {
        for review_state in ["pending", "approved", "rejected"] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let response_wire = json!({"data": organization_template_wire(review_state)});
            Mock::given(method("PUT"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/research/listing"
                )))
                .and(body_json(json!({"listed": false})))
                .respond_with(ResponseTemplate::new(200).set_body_json(response_wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let review_wire = json!({"data": organization_template_wire("pending")});
            Mock::given(method("POST"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/research/reviews"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(review_wire.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::new(&server.uri());
            let request: crate::PutManagedAgentTemplateListing =
                serde_json::from_value(json!({"listed": false})).unwrap();
            let listing = client
                .put_managed_agent_template_listing(&organization_id, "research", &request)
                .await
                .unwrap()
                .into_inner();
            let review = client
                .request_managed_agent_template_review(&organization_id, "research")
                .await
                .unwrap()
                .into_inner();
            assert_eq!(serde_json::to_value(listing).unwrap(), response_wire);
            assert_eq!(serde_json::to_value(review).unwrap(), review_wire);
            server.verify().await;
        }
        for field in ["listed", "review_state"] {
            for malformed in [None, Some(json!(null)), Some(json!("unknown"))] {
                let mut wire = organization_template_wire("pending");
                if let Some(value) = malformed {
                    wire[field] = value;
                } else {
                    wire.as_object_mut().unwrap().remove(field);
                }
                assert!(
                    serde_json::from_value::<crate::OrganizationManagedAgentTemplate>(wire)
                        .is_err()
                );
            }
        }
        for wire in [
            json!({}),
            json!({"listed": null}),
            json!({"listed": true, "active": true}),
        ] {
            assert!(serde_json::from_value::<crate::PutManagedAgentTemplateListing>(wire).is_err());
        }
    }

    #[tokio::test]
    async fn organization_update_http_accepts_a_store_address_without_a_name() {
        let server = MockServer::start().await;
        let organization_id = Uuid::new_v4();
        let request_wire = json!({"public_handle": "acme-studio"});
        let request: crate::RenameOrganizationRequest =
            serde_json::from_value(request_wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), request_wire);
        let response_wire = json!({"data": {"id": organization_id, "name": "Acme Studio",
            "slug": "acme-studio", "public_handle": "acme-studio", "created_by": Uuid::new_v4(),
            "is_personal": false, "created_at": "2026-10-24T01:00:00Z", "updated_at": "2026-10-24T01:00:00Z"}});
        Mock::given(method("PATCH"))
            .and(path(format!("/organizations/{organization_id}")))
            .and(body_json(request_wire))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_wire.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let response = Client::new(&server.uri())
            .rename_organization(&organization_id, &request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(serde_json::to_value(response).unwrap(), response_wire);
        assert!(
            serde_json::from_value::<crate::RenameOrganizationRequest>(
                json!({"handle": "acme-studio"})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn login_form_http_preserves_explicit_modes_callbacks_and_refusals() {
        use wiremock::matchers::{body_string_contains, header};

        for mode in [None, Some("html"), Some("json")] {
            for status in [200, 303, 400, 401, 403, 429, 500, 503] {
                if status == 200 && mode != Some("json") || status == 303 && mode == Some("json") {
                    continue;
                }
                let server = MockServer::start().await;
                let mut wire = json!({"email": "person@example.com", "password": "example password", "state": "pending-state"});
                if let Some(mode) = mode {
                    wire["response_mode"] = json!(mode);
                }
                let request: crate::LoginFormData = serde_json::from_value(wire.clone()).unwrap();
                assert_eq!(serde_json::to_value(&request).unwrap(), wire);
                let callback = "https://example.com/callback?code=example&state=pending-state";
                let response_wire = match status {
                    200 => json!({"data": {"redirect_uri": callback}}),
                    429 => json!({"error": {"code": "rate_limited", "message": "Try later."}}),
                    503 => {
                        json!({"error": {"code": "service_unavailable", "message": "Try later."}})
                    }
                    401 => json!({"error": "invalid_credentials", "message": "Try again."}),
                    403 => json!({"error": "confirm_email", "message": "Confirm your email."}),
                    400 => json!({"error": "invalid_request", "message": "Invalid form."}),
                    _ => json!({"error": "service_unavailable", "message": "Try later."}),
                };
                let is_html = mode == Some("html") && matches!(status, 401 | 403 | 429 | 500);
                let (response_body, content_type) = if is_html {
                    ("<form><input name=email value=person@example.com><input name=password value=></form>".to_owned(), "text/html")
                } else {
                    (
                        serde_json::to_string(&response_wire).unwrap(),
                        "application/json",
                    )
                };
                let mut matcher = Mock::given(method("POST"))
                    .and(path("/oauth2/login"))
                    .and(header("content-type", "application/x-www-form-urlencoded"))
                    .and(body_string_contains("state=pending-state"));
                if let Some(mode) = mode {
                    matcher = matcher.and(body_string_contains(format!("response_mode={mode}")));
                }
                matcher
                    .respond_with(
                        ResponseTemplate::new(status)
                            .insert_header("Location", callback)
                            .insert_header("Retry-After", "30")
                            .set_body_raw(response_body.clone(), content_type),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                let http = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .unwrap();
                let result = Client::new_with_client(&server.uri(), http)
                    .login_form(&request)
                    .await;
                if status == 200 {
                    assert_eq!(
                        serde_json::to_value(result.unwrap().into_inner()).unwrap(),
                        response_wire
                    );
                } else {
                    let error =
                        result.expect_err("redirects and refusals retain their raw HTTP response");
                    let crate::Error::UnexpectedResponse(response) = error else {
                        panic!("{error:?}")
                    };
                    assert_eq!(response.status().as_u16(), status);
                    assert_eq!(response.headers()["location"], callback);
                    assert_eq!(response.headers()["retry-after"], "30");
                    assert_eq!(response.text().await.unwrap(), response_body);
                }
                let received = server.received_requests().await.unwrap();
                let body = std::str::from_utf8(&received[0].body).unwrap();
                assert!(body.contains("email=person%40example.com"));
                assert!(body.contains("password=example+password"));
                assert_eq!(body.contains("response_mode="), mode.is_some());
                server.verify().await;
            }
        }
        assert!(serde_json::from_value::<crate::LoginFormData>(json!({
            "email": "person@example.com", "password": "example", "state": "pending", "response_mode": "xml"
        })).is_err());
        for refusal in [
            "invalid_credentials",
            "too_many_attempts",
            "password_sign_in_locked",
            "confirm_email",
            "expired_session",
            "service_unavailable",
        ] {
            let wire = json!({"error": refusal, "message": "Try again."});
            let decoded: crate::BrowserSignInError = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
        }
        assert!(
            serde_json::from_value::<crate::BrowserSignInError>(
                json!({"error": "unknown", "message": "Try again."})
            )
            .is_err()
        );
        for wire in [
            json!({"error": "admission_limit", "message": "Try later.", "details": [{"retry_after": 30}, false, 5]}),
            json!({"error": {"code": "gateway_maintenance", "message": "Try later."}}),
        ] {
            let decoded: crate::LoginFormAdmissionError =
                serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
        }
    }

    #[tokio::test]
    async fn template_publication_rejects_unknown_rollout_wire_values() {
        for (outcome, failure) in [("pending", "internal"), ("failed", "unknown")] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let mut request_wire = template_release_request_wire();
            request_wire["rollout"] = json!(true);
            let request = serde_json::from_value(request_wire).unwrap();
            let response_wire = json!({"data": {
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true, "listed": false, "review_state": "pending",
                "providers": ["google"],
                "rollout": {"template_slug": "release-test", "template_revision": 8,
                    "deployments": [{"deployment_id": Uuid::new_v4(), "outcome": outcome, "failure": failure}]
                }
            }});
            Mock::given(method("POST"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/release-test/releases"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(response_wire))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::new(&server.uri());
            let error = client
                .publish_managed_agent_template_release(&organization_id, "release-test", &request)
                .await
                .expect_err("unknown rollout wire values must reject the response");
            assert!(
                matches!(error, crate::Error::InvalidResponsePayload(_, _)),
                "{error:?}"
            );
        }
    }

    #[tokio::test]
    async fn run_events_decode_conversation_refusals_and_reject_unknown_codes() {
        let run_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        for (code, expected, retryable) in [
            (
                "conversation_busy",
                Some(CloudRunErrorCode::ConversationBusy),
                true,
            ),
            (
                "conversation_awaiting_approval",
                Some(CloudRunErrorCode::ConversationAwaitingApproval),
                false,
            ),
            ("conversation_unrecognized", None, false),
        ] {
            assert_eq!(
                serde_json::from_value::<CloudRunErrorCode>(json!(code)).ok(),
                expected
            );
            let server = MockServer::start().await;
            let response_wire = json!({"data": [{
                "sequence_number": 3,
                "event_type": "error",
                "kind": "error",
                "type": "error",
                "code": code,
                "cause": "session",
                "message": "The conversation cannot accept this turn.",
                "retryable": retryable
            }]});
            for endpoint in [
                format!("/publishers/seren-cloud/runs/{run_id}/events"),
                format!("/publishers/seren-cloud/deployments/{deployment_id}/runs/{run_id}/events"),
            ] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(response_wire.clone()))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let client = Client::new(&server.uri());
            let global = client
                .seren_cloud_run_events(&run_id, None, None, None, None, None)
                .await;
            let deployment = client
                .seren_cloud_deployment_run_events(
                    &deployment_id,
                    &run_id,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            for result in [global, deployment] {
                if expected.is_some() {
                    let decoded = result.expect("decode run events").into_inner();
                    let decoded = serde_json::to_value(decoded).expect("serialize run events");
                    assert_eq!(decoded["data"].as_array().unwrap().len(), 1);
                    for (field, value) in response_wire["data"][0].as_object().unwrap() {
                        assert_eq!(&decoded["data"][0][field], value, "{field}");
                    }
                } else {
                    let error = result.expect_err("unknown error codes are rejected");
                    assert!(
                        matches!(error, crate::Error::InvalidResponsePayload(_, _)),
                        "{error:?}"
                    );
                }
            }
            server.verify().await;
        }
    }

    /// Run events carry `kind` as one scalar from the taxonomy or budget-action
    /// union, and budget actions keep their envelope metadata. Both event routes
    /// decode and re-encode each event exactly, and refuse a value outside the
    /// union, a non-string kind, a missing required field, or invalid metadata.
    #[tokio::test]
    async fn run_events_preserve_scalar_kind_unions_and_refuse_invalid_kinds() {
        let run_id = Uuid::new_v4();
        let deployment_id = Uuid::new_v4();
        let events = json!([
            {
                "sequence_number": 1, "event_type": "response.output_text.done",
                "kind": "text", "type": "text", "text": "hello from the employee"
            },
            {
                "sequence_number": 2, "event_type": "response.output_item.done",
                "kind": "tool_call_completed", "type": "tool_result", "id": "call_123",
                "content": "Provider rate limit exceeded", "is_error": true,
                "code": "tool_rate_limited", "retryable": true
            },
            {
                "sequence_number": 3, "event_type": "error", "kind": "error", "type": "error",
                "code": "conversation_busy", "cause": "session",
                "message": "The conversation cannot accept this turn.", "retryable": true
            },
            {
                "sequence_number": 4, "output_index": 0, "kind": "raise_task_limit",
                "type": "action", "scope": "task", "suggested_atomic": 1000000
            },
            {
                "sequence_number": 5, "event_type": "response.output_item.done",
                "item_id": "action_1", "producer_id": "runtime", "kind": "top_up",
                "type": "action"
            }
        ]);
        for (data, valid) in [
            (events, true),
            (json!([{"type": "text", "text": "without a kind"}]), true),
            (
                json!([{"type": "text", "kind": "future_unknown", "text": "unknown"}]),
                false,
            ),
            (
                json!([{"type": "text", "kind": {"subtype_0": "text"}, "text": "object"}]),
                false,
            ),
            (
                json!([{"type": "text", "kind": ["text"], "text": "array kind"}]),
                false,
            ),
            (json!([{"type": "text", "kind": "text"}]), false),
            (json!([{"type": "action", "kind": "text"}]), false),
            (json!([{"type": "action"}]), false),
            (
                json!([{"type": "action", "kind": "raise_task_limit", "scope": "task"}]),
                false,
            ),
            (
                json!([{
                    "type": "action", "kind": "raise_task_limit",
                    "scope": "week", "suggested_atomic": 1000000
                }]),
                false,
            ),
            (
                json!([{"type": "action", "kind": "top_up", "sequence_number": "5"}]),
                false,
            ),
        ] {
            let server = MockServer::start().await;
            let wire = json!({"data": data});
            for endpoint in [
                format!("/publishers/seren-cloud/runs/{run_id}/events"),
                format!("/publishers/seren-cloud/deployments/{deployment_id}/runs/{run_id}/events"),
            ] {
                Mock::given(method("GET"))
                    .and(path(endpoint))
                    .respond_with(ResponseTemplate::new(200).set_body_json(wire.clone()))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let client = Client::new(&server.uri());
            let global = client
                .seren_cloud_run_events(&run_id, None, None, None, None, None)
                .await;
            let deployment = client
                .seren_cloud_deployment_run_events(
                    &deployment_id,
                    &run_id,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .await;
            for result in [global, deployment] {
                if valid {
                    let decoded = result
                        .expect("valid scalar event kinds decode")
                        .into_inner();
                    assert_eq!(serde_json::to_value(decoded).unwrap()["data"], wire["data"]);
                } else {
                    assert!(
                        matches!(result, Err(crate::Error::InvalidResponsePayload(_, _))),
                        "{result:?}"
                    );
                }
            }
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn publisher_credential_create_preserves_replay_acceptance_and_validation_responses() {
        let deployment_id = Uuid::new_v4();
        let revision_id = Uuid::new_v4();
        let proposal_id = Uuid::new_v4();
        let request_wire = json!({
            "expected_active_revision_id": revision_id,
            "idempotency_key": Uuid::new_v4(),
            "changes": [{
                "operation": "add",
                "name": "publisher_token",
                "publisher_slug": "slack-byok",
                "kind": "api_key",
                "binding": "header",
                "binding_target": "X-Passthrough-Authorization"
            }]
        });
        let request: PublisherCredentialProposalRequest =
            serde_json::from_value(request_wire.clone()).expect("proposal request");

        for status in [200, 202, 400, 409] {
            let server = MockServer::start().await;
            let response_wire = if status < 300 {
                json!({"data": {
                    "id": proposal_id,
                    "deployment_id": deployment_id,
                    "expected_active_revision_id": revision_id,
                    "proposal_fingerprint": "a".repeat(64),
                    "requirements_fingerprint": "b".repeat(64),
                    "requested_environment_names": ["publisher_token"],
                    "requires_secret_resolution_result": true,
                    "changes": request_wire["changes"],
                    "state": if status == 202 { "awaiting_review" } else { "applied" },
                    "result_id": if status == 200 { Some(Uuid::new_v4()) } else { None },
                    "applied_revision_id": if status == 200 { Some(Uuid::new_v4()) } else { None }
                }})
            } else {
                json!({"error": "BadRequest", "message": "Invalid publisher credential proposal"})
            };
            Mock::given(method("POST"))
                .and(path(format!(
                    "/publishers/seren-cloud/deployments/{deployment_id}/credentials/proposals"
                )))
                .and(body_json(request_wire.clone()))
                .respond_with(ResponseTemplate::new(status).set_body_json(response_wire))
                .expect(1)
                .mount(&server)
                .await;
            let client =
                Client::from_config(&ClientConfig::unauthenticated().with_base_url(server.uri()))
                    .expect("client");
            let result = client
                .seren_cloud_create_publisher_credential_proposal(&deployment_id, &request)
                .await;
            if status < 300 {
                let response = result.expect("both accepted and replayed proposals are success");
                assert_eq!(response.status().as_u16(), status);
                let proposal = response.into_inner().data;
                assert_eq!(proposal.id, proposal_id);
                assert_eq!(proposal.deployment_id, deployment_id);
                assert_eq!(proposal.expected_active_revision_id, revision_id);
                assert_eq!(proposal.requested_environment_names, ["publisher_token"]);
                assert_eq!(proposal.changes[0].name, "publisher_token");
            } else {
                let error = result.expect_err("invalid and conflicting proposals remain errors");
                assert_eq!(error.status().expect("HTTP response").as_u16(), status);
            }
            server.verify().await;
        }
    }

    /// `build.rs` omits these operations from code generation because
    /// Progenitor cannot emit multipart request bodies, and the methods of the
    /// same name are hand-written against that omission. If the bundled
    /// contract stops declaring an operation as multipart, the filter and the
    /// hand-written method both need to be revisited.
    #[test]
    fn bundled_spec_declares_the_hand_written_multipart_uploads() {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../openapi/openapi.json"))
            .expect("parse bundled OpenAPI document");

        for (path, operation_id, response) in [
            (
                "/users/me/avatar",
                "upload_current_user_avatar",
                "#/components/schemas/DataResponse_AvatarUploaded",
            ),
            (
                "/organizations/{organization_id}/templates/{slug}/avatar",
                "upload_managed_agent_template_avatar",
                "#/components/schemas/DataResponse_ManagedAgentTemplateProfile",
            ),
        ] {
            let operation = &spec["paths"][path]["post"];
            assert_eq!(operation["operationId"], operation_id, "{path}");
            assert!(
                operation["requestBody"]["content"]
                    .get("multipart/form-data")
                    .is_some(),
                "POST {path} must remain a multipart operation",
            );
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                response,
                "the hand-written {operation_id} parses this response on 200",
            );
        }
    }

    /// Every multipart operation needs a hand-written SDK method.
    #[test]
    fn bundled_spec_has_no_other_multipart_operations() {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../openapi/openapi.json"))
            .expect("parse bundled OpenAPI document");

        let mut unexpected = Vec::new();
        for (path, item) in spec["paths"].as_object().expect("paths object") {
            for (method, operation) in item.as_object().expect("path item object") {
                if method == "post"
                    && matches!(
                        path.as_str(),
                        "/users/me/avatar"
                            | "/organizations/{organization_id}/templates/{slug}/avatar"
                    )
                {
                    continue;
                }
                if operation
                    .pointer("/requestBody/content/multipart~1form-data")
                    .is_some()
                {
                    unexpected.push(format!("{method} {path}"));
                }
            }
        }

        assert!(
            unexpected.is_empty(),
            "unsupported multipart operations need a hand-written SDK method: {unexpected:?}",
        );
    }

    #[tokio::test]
    async fn template_avatar_upload_sends_the_file_and_preserves_errors() {
        use wiremock::matchers::{body_string_contains, header};

        let organization_id = Uuid::from_u128(91);
        for status in [200, 400, 403, 413, 503] {
            let server = MockServer::start().await;
            let payload = json!({
                "data": {
                    "avatar_url": "https://example.com/avatar.png",
                    "capabilities": ["Research"], "example_tasks": [], "works_in": [], "pronouns": "they/them"
                }
            });
            Mock::given(method("POST"))
                .and(path(format!(
                    "/organizations/{organization_id}/templates/research/avatar"
                )))
                .and(header("authorization", "Bearer seren_test"))
                .and(body_string_contains(
                    "name=\"file\"; filename=\"avatar.png\"",
                ))
                .and(body_string_contains("image bytes"))
                .respond_with(ResponseTemplate::new(status).set_body_json(&payload))
                .expect(1)
                .mount(&server)
                .await;
            let client = Client::from_config(&ClientConfig {
                base_url: server.uri(),
                bearer_token: Some("seren_test".to_owned()),
                ..ClientConfig::default()
            })
            .unwrap();
            let result = client
                .upload_managed_agent_template_avatar(
                    &organization_id,
                    "research",
                    "avatar.png",
                    b"image bytes".to_vec(),
                )
                .await;
            if status == 200 {
                assert_eq!(
                    serde_json::to_value(result.unwrap().into_inner()).unwrap(),
                    payload
                );
            } else {
                assert_eq!(result.unwrap_err().status().unwrap().as_u16(), status);
            }
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn template_avatar_upload_keeps_the_slug_in_one_path_segment() {
        let server = MockServer::start().await;
        let organization_id = Uuid::from_u128(92);
        Mock::given(method("POST"))
            .and(path(format!(
                "/organizations/{organization_id}/templates/team%2Fresearch%3F%23/avatar"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"capabilities": [], "example_tasks": [], "works_in": [], "pronouns": "they/them"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let response = Client::new(&server.uri())
            .upload_managed_agent_template_avatar(
                &organization_id,
                "team/research?#",
                "avatar.png",
                b"image bytes".to_vec(),
            )
            .await
            .unwrap()
            .into_inner();
        assert!(response.data.capabilities.is_empty());
        server.verify().await;
    }

    /// Raw uploads with several media types stay outside Progenitor's fixed
    /// media-type methods. Single-media uploads remain generated operations.
    #[test]
    fn bundled_cloud_spec_distinguishes_single_and_multi_media_uploads() {
        let spec: serde_json::Value =
            serde_json::from_str(include_str!("../openapi/openapi-seren-cloud.json"))
                .expect("parse bundled seren-cloud OpenAPI document");

        for (path, operation_id, multiple_media_types) in [
            (
                "/deployments/{id}/executions/{execution_id}/artifact-files",
                "seren_cloud_runtime_publish_run_artifact",
                true,
            ),
            (
                "/deployments/{id}/files",
                "seren_cloud_upload_run_file",
                false,
            ),
            (
                "/folders/{id}/files",
                "seren_cloud_upload_folder_file",
                false,
            ),
        ] {
            let operation = &spec["paths"][path]["post"];
            assert_eq!(operation["operationId"], operation_id, "{path}");
            let content = operation["requestBody"]["content"]
                .as_object()
                .unwrap_or_else(|| panic!("{operation_id} must declare a request body"));
            if multiple_media_types {
                assert!(content.len() > 1, "{operation_id} must remain multi-media");
            } else {
                assert_eq!(content.len(), 1, "{operation_id} must have one media type");
                assert!(content.contains_key("application/octet-stream"));
            }
            assert!(
                content.values().all(|media| {
                    media["schema"]["$ref"] == "#/components/schemas/RunFileContent"
                }),
                "{operation_id} must upload raw RunFileContent for every media type",
            );
        }
    }

    #[tokio::test]
    async fn organization_funding_clients_preserve_personal_deposit_binding() {
        use wiremock::matchers::header;

        let server = MockServer::start().await;
        let organization_id = Uuid::from_u128(201);
        let deposit_id = Uuid::from_u128(202);
        let idempotency_key = Uuid::from_u128(203);
        let wallet_route = format!("/organizations/{organization_id}/wallet");
        let deposit = json!({
            "id": deposit_id, "organization_id": organization_id,
            "amount_atomic": 500_000_000_i64, "status": "pending",
            "reversed_atomic": 0, "owed_atomic": 0,
            "checkout_url": "https://checkout.example.test/organization"
        });
        let organization_request = json!({
            "amount_cents": 500,
            "success_url": "https://console.example.test/success",
            "cancel_url": "https://console.example.test/cancel"
        });
        Mock::given(method("GET"))
            .and(path(&wallet_route))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                "organization_id": organization_id,
                "available_atomic": 9_007_199_254_740_993_i64,
                "owed_atomic": 17
            }})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{wallet_route}/deposits")))
            .and(header("Idempotency-Key", idempotency_key.to_string()))
            .and(body_json(&organization_request))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": deposit})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{wallet_route}/deposits/{deposit_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": deposit})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/wallet/deposit"))
            .and(body_json(json!({"amount_cents": 500})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                "deposit_id": deposit_id,
                "checkout_url": "https://checkout.example.test/personal",
                "amount_atomic": 500_000_000_i64, "bonus_atomic": 0,
                "total_atomic": 500_000_000_i64,
                "amount_usd": "5.00", "bonus_usd": "0.00", "total_usd": "5.00"
            }})))
            .expect(1)
            .mount(&server)
            .await;

        let client =
            Client::from_config(&ClientConfig::new("synthetic-key").with_base_url(server.uri()))
                .unwrap();
        let wallet = client
            .get_organization_wallet(&organization_id)
            .await
            .unwrap()
            .into_inner()
            .data;
        assert_eq!(wallet.organization_id, organization_id);
        assert_eq!(wallet.available_atomic, 9_007_199_254_740_993_i64);
        assert_eq!(wallet.owed_atomic, 17);
        let request =
            serde_json::from_value::<crate::OrganizationDepositRequest>(organization_request)
                .unwrap();
        let created = client
            .create_organization_deposit(&organization_id, &idempotency_key, &request)
            .await
            .unwrap()
            .into_inner()
            .data;
        assert_eq!(serde_json::to_value(created).unwrap(), deposit);
        let fetched = client
            .get_organization_deposit(&organization_id, &deposit_id)
            .await
            .unwrap()
            .into_inner()
            .data;
        assert_eq!(serde_json::to_value(fetched).unwrap(), deposit);
        let personal = client
            .create_deposit(&crate::DepositRequest {
                amount_cents: 500,
                referral_code: None,
                success_url: None,
                cancel_url: None,
            })
            .await
            .unwrap()
            .into_inner()
            .data;
        assert_eq!(personal.deposit_id, deposit_id);
        assert_eq!(
            personal.checkout_url,
            "https://checkout.example.test/personal"
        );
        server.verify().await;
    }

    #[test]
    fn cloud_file_contract_requires_verification_path_and_pagination() {
        let file = json!({
            "id": Uuid::from_u128(211), "folder_id": Uuid::from_u128(212),
            "origin": "owner_upload", "path": "reports/result.csv", "file_name": "result.csv",
            "revision": 1, "content_type": "text/csv", "content_state": "verifying",
            "byte_length": 9, "sha256": "a".repeat(64), "created_at": "2026-10-30T00:00:00Z"
        });
        let page = json!({"files": [file], "has_more": true, "next_cursor": "opaque-cursor"});
        let parsed: crate::CloudFolderFileListResponse =
            serde_json::from_value(page.clone()).unwrap();
        assert!(parsed.has_more);
        assert_eq!(parsed.next_cursor.as_deref(), Some("opaque-cursor"));
        assert_eq!(parsed.files[0].path, "reports/result.csv");
        assert_eq!(
            serde_json::to_value(parsed.files[0].content_state).unwrap(),
            json!("verifying")
        );
        for required in ["path", "content_state"] {
            let mut missing = file.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(serde_json::from_value::<crate::CloudFolderFile>(missing).is_err());
        }
        let mut missing_pagination = page;
        missing_pagination
            .as_object_mut()
            .unwrap()
            .remove("has_more");
        assert!(
            serde_json::from_value::<crate::CloudFolderFileListResponse>(missing_pagination)
                .is_err()
        );
        for cursor in [None, Some(serde_json::Value::Null)] {
            let mut last_page = json!({"files": [], "has_more": false});
            if let Some(cursor) = cursor {
                last_page["next_cursor"] = cursor;
            }
            let parsed: crate::CloudFolderFileListResponse =
                serde_json::from_value(last_page).unwrap();
            assert!(!parsed.has_more);
            assert!(parsed.next_cursor.is_none());
        }
        for state in ["verifying", "ready"] {
            let parsed: crate::FileVerificationState =
                serde_json::from_value(json!(state)).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), json!(state));
        }
        assert!(serde_json::from_value::<crate::FileVerificationState>(json!("unknown")).is_err());
        for state in [
            "uploading",
            "verifying",
            "ready",
            "verification_failed",
            "cancelled",
            "expired",
        ] {
            let parsed: crate::UploadState = serde_json::from_value(json!(state)).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), json!(state));
        }
        assert!(serde_json::from_value::<crate::UploadState>(json!("unknown")).is_err());
    }

    #[test]
    fn script_publisher_grants_preserve_optional_catalog_operation() {
        let grant = json!({
            "publisher_slug": "example", "method": "POST", "path": "/query",
            "require_approval": true
        });
        for operation in [None, Some(serde_json::Value::Null)] {
            let mut body = grant.clone();
            if let Some(operation) = operation {
                body["operation_id"] = operation;
            }
            let parsed: crate::ManagedAgentTemplateScriptPublisherGrant =
                serde_json::from_value(body).unwrap();
            assert!(parsed.operation_id.is_none());
            assert!(parsed.require_approval);
        }
        let mut body = grant;
        body["operation_id"] = json!("post_messages");
        let parsed: crate::ManagedAgentTemplateScriptPublisherGrant =
            serde_json::from_value(body).unwrap();
        assert_eq!(parsed.operation_id.as_deref(), Some("post_messages"));
        assert_eq!(
            serde_json::to_value(parsed).unwrap()["operation_id"],
            "post_messages"
        );
    }

    #[test]
    fn profile_request_documents_and_serializes_empty_avatar_clear() {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../openapi/openapi.json"))
            .expect("parse bundled OpenAPI document");
        let avatar =
            &spec["components"]["schemas"]["UpdateProfileRequest"]["properties"]["avatar_url"];
        assert!(
            avatar["description"]
                .as_str()
                .is_some_and(|description| description.contains("empty string to clear")),
            "the public contract must document SDK-compatible avatar clearing",
        );

        let request = crate::UpdateProfileRequest {
            name: None,
            avatar_url: Some(String::new()),
        };
        assert_eq!(
            serde_json::to_value(request).expect("serialize profile update"),
            serde_json::json!({"avatar_url": ""}),
        );
    }

    #[test]
    fn bundled_passwords_spec_documents_invitation_email_contract() {
        let spec: serde_json::Value =
            serde_json::from_str(include_str!("../openapi/openapi-seren-passwords.json"))
                .expect("parse bundled seren-passwords OpenAPI document");
        let request = &spec["components"]["schemas"]["CreateInvitationRequest"];

        assert_eq!(request["properties"]["invitee_email"]["type"], "string");
        assert!(
            request["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "invitee_email")),
            "CreateInvitationRequest.invitee_email must remain required",
        );
        assert!(
            spec["paths"]["/vaults/{vault_id}/invitations"]["post"]["responses"]
                .get("422")
                .is_some(),
            "invitation_create must document JSON extractor failures",
        );
    }
}
