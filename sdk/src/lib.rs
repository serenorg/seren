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
    use crate::{Client, ClientConfig, PublisherCredentialProposalRequest};
    use serde_json::json;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

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

    /// `build.rs` omits exactly one operation from code generation because
    /// Progenitor cannot emit multipart request bodies, and
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
