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

    fn template_release_request_wire() -> serde_json::Value {
        json!({
            "display_name": "Release test",
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
    async fn template_publication_preserves_rollout_requests_and_applied_revision() {
        for rollout in [None, Some(false), Some(true)] {
            let server = MockServer::start().await;
            let organization_id = Uuid::new_v4();
            let mut request_wire = template_release_request_wire();
            if let Some(rollout) = rollout {
                request_wire["rollout"] = json!(rollout);
            }
            let request: crate::PublishManagedAgentTemplateReleaseRequest =
                serde_json::from_value(request_wire.clone()).unwrap();
            assert_eq!(request.rollout, rollout);
            assert_eq!(serde_json::to_value(&request).unwrap(), request_wire);
            let mut response_wire = json!({"data": {
                "slug": "release-test", "revision": 7, "created": false,
                "revision_added": false, "active": true
            }});
            if rollout == Some(false) {
                response_wire["data"]["rollout"] = serde_json::Value::Null;
            } else if rollout == Some(true) {
                response_wire["data"]["rollout"] = json!({
                    "template_slug": "release-test", "template_revision": 8,
                    "deployments": [
                        {"deployment_id": Uuid::new_v4(), "outcome": "updated", "revision_id": Uuid::new_v4()},
                        {"deployment_id": Uuid::new_v4(), "outcome": "already_current", "revision_id": Uuid::new_v4()},
                        {"deployment_id": Uuid::new_v4(), "outcome": "hire_incomplete", "revision_id": null, "failure": null},
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
            if rollout == Some(true) {
                assert_eq!(decoded["data"]["rollout"]["template_revision"], 8);
                assert_eq!(
                    decoded["data"]["rollout"]["deployments"]
                        .as_array()
                        .unwrap()
                        .len(),
                    4
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
                    for (field, value) in wire.as_object().unwrap() {
                        assert_eq!(&decoded[field], value, "{field}");
                    }
                }
            } else {
                assert!(decoded["data"]["rollout"].is_null());
            }
        }
    }

    #[test]
    fn template_rollout_rejects_unknown_outcomes_and_failures() {
        for outcome in ["updated", "already_current", "hire_incomplete", "failed"] {
            let decoded: crate::TemplateRevisionOutcome =
                serde_json::from_value(json!(outcome)).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), json!(outcome));
        }
        for failure in [
            "revision_conflict",
            "superseded",
            "deployment_unavailable",
            "invalid_material",
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
        let mut request = template_release_request_wire();
        request["rollout"] = json!("true");
        assert!(
            serde_json::from_value::<crate::PublishManagedAgentTemplateReleaseRequest>(request)
                .is_err()
        );
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
                "revision_added": false, "active": true,
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

    /// `build.rs` omits this operation from code generation because Progenitor
    /// cannot emit multipart request bodies, and
    /// `upload_current_user_avatar` is hand-written against that omission. If
    /// the bundled contract stops declaring this operation as multipart, the
    /// filter and the hand-written method both need to be revisited.
    #[test]
    fn bundled_spec_declares_the_hand_written_multipart_avatar_upload() {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../openapi/openapi.json"))
            .expect("parse bundled OpenAPI document");
        let operation = &spec["paths"]["/users/me/avatar"]["post"];

        assert_eq!(operation["operationId"], "upload_current_user_avatar");
        assert!(
            operation["requestBody"]["content"]
                .get("multipart/form-data")
                .is_some(),
            "POST /users/me/avatar must remain a multipart operation",
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/DataResponse_AvatarUploaded",
            "the hand-written method parses DataResponseAvatarUploaded on 200",
        );
    }

    /// The hand-written upload is the only multipart operation the SDK carries.
    /// Any new one silently disappears from the generated client, so fail here
    /// rather than at a missing-method call site.
    #[test]
    fn bundled_spec_has_no_other_multipart_operations() {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../openapi/openapi.json"))
            .expect("parse bundled OpenAPI document");

        let mut unexpected = Vec::new();
        for (path, item) in spec["paths"].as_object().expect("paths object") {
            for (method, operation) in item.as_object().expect("path item object") {
                if path == "/users/me/avatar" && method == "post" {
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

    /// `build.rs` omits these raw uploads from code generation because their
    /// Content-Type header selects the stored file type and Progenitor sends a
    /// single fixed media type. They stay in the bundled public contract; if an
    /// operation narrows to one media type, drop its omission so the generated
    /// client gains the method.
    #[test]
    fn bundled_cloud_spec_keeps_the_raw_upload_operations_omitted_from_codegen() {
        let spec: serde_json::Value =
            serde_json::from_str(include_str!("../openapi/openapi-seren-cloud.json"))
                .expect("parse bundled seren-cloud OpenAPI document");

        for (path, operation_id) in [
            (
                "/deployments/{id}/executions/{execution_id}/artifact-files",
                "seren_cloud_runtime_publish_run_artifact",
            ),
            ("/deployments/{id}/files", "seren_cloud_upload_run_file"),
        ] {
            let operation = &spec["paths"][path]["post"];
            assert_eq!(operation["operationId"], operation_id, "{path}");
            let content = operation["requestBody"]["content"]
                .as_object()
                .unwrap_or_else(|| panic!("{operation_id} must declare a request body"));
            assert!(
                content.len() > 1,
                "{operation_id} now has one media type; remove its codegen omission",
            );
            assert!(
                content.values().all(|media| {
                    media["schema"]["$ref"] == "#/components/schemas/RunFileContent"
                }),
                "{operation_id} must upload raw RunFileContent for every media type",
            );
        }
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
