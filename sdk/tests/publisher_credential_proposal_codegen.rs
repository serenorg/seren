//! Codegen + route regression test for the Core #384 publisher-credential
//! proposal surface.
//!
//! These assertions fail to compile if the committed `sdk/openapi/` snapshots
//! stop generating the publisher-credential proposal methods/models, and fail
//! at runtime if the generated client stops addressing the exact Core routes
//! and request bodies. That turns a snapshot re-sync regression into a red
//! build instead of a silently-missing tool.

use seren::{
    AgentCredentialBinding, AgentCredentialKind, ApplyPublisherCredentialProposalRequest, Client,
    ClientConfig, InitiateManagedAgentSecretsSetupRequest, ManagedPublisherCredentialChange,
    ManagedPublisherCredentialEffectiveMapping, ManagedPublisherCredentialProposalOperation,
    ManagedPublisherCredentialProposalState, PublisherCredentialProposalRequest,
};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

/// The setup-initiation request must carry all three mutually-exclusive
/// proposal selectors after the re-sync (connector/model/publisher).
#[test]
fn setup_request_exposes_all_three_proposal_selectors() {
    let request = InitiateManagedAgentSecretsSetupRequest {
        connector_binding_proposal_id: None,
        model_credential_proposal_id: None,
        publisher_credential_proposal_id: Some(Uuid::nil()),
        deployment_id: Uuid::nil(),
        redirect_origin: "https://passwords.serendb.com".to_string(),
    };
    // Field access is the compile-time proof the selectors exist.
    assert!(request.connector_binding_proposal_id.is_none());
    assert!(request.model_credential_proposal_id.is_none());
    assert_eq!(request.publisher_credential_proposal_id, Some(Uuid::nil()));
}

fn sample_change() -> ManagedPublisherCredentialChange {
    ManagedPublisherCredentialChange {
        operation: ManagedPublisherCredentialProposalOperation::Add,
        name: "SLACK_BOT_TOKEN".to_string(),
        publisher_slug: "slack".to_string(),
        kind: AgentCredentialKind::ApiKey,
        binding: AgentCredentialBinding::ReferenceEnv,
        binding_target: "SLACK_BOT_TOKEN".to_string(),
    }
}

/// Preview must POST the non-secret intent to the exact Core preview route and
/// decode the typed seven-field preview envelope.
#[tokio::test]
async fn preview_publisher_credential_proposal_targets_core_route() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::from_u128(1);
    let expected_active_revision_id = Uuid::from_u128(2);
    let idempotency_key = Uuid::from_u128(3);

    let request = PublisherCredentialProposalRequest {
        changes: vec![sample_change()],
        expected_active_revision_id,
        idempotency_key,
        replace_proposal_id: None,
    };

    Mock::given(method("POST"))
        .and(path(format!(
            "/publishers/seren-cloud/deployments/{deployment_id}/credentials/proposals/preview"
        )))
        .and(body_json(serde_json::json!({
            "changes": [{
                "operation": "add",
                "name": "SLACK_BOT_TOKEN",
                "publisher_slug": "slack",
                "kind": "api_key",
                "binding": "reference_env",
                "binding_target": "SLACK_BOT_TOKEN"
            }],
            "expected_active_revision_id": expected_active_revision_id,
            "idempotency_key": idempotency_key,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "deployment_id": deployment_id,
                "expected_active_revision_id": expected_active_revision_id,
                "proposal_fingerprint": "fp-preview",
                "requested_environment_names": ["SLACK_BOT_TOKEN"],
                "requires_secret_resolution_result": true,
                "changes": [{
                    "operation": "add",
                    "name": "SLACK_BOT_TOKEN",
                    "publisher_slug": "slack",
                    "kind": "api_key",
                    "binding": "reference_env",
                    "binding_target": "SLACK_BOT_TOKEN"
                }]
            }
        })))
        .mount(&server)
        .await;

    let client =
        Client::from_config(&ClientConfig::unauthenticated().with_base_url(server.uri())).unwrap();
    let preview = client
        .seren_cloud_preview_publisher_credential_proposal(&deployment_id, &request)
        .await
        .expect("preview deserializes")
        .into_inner()
        .data;

    assert_eq!(preview.requested_environment_names, ["SLACK_BOT_TOKEN"]);
    assert!(preview.requires_secret_resolution_result);
    assert_eq!(preview.changes.len(), 1);
}

/// Apply must POST to the proposal-bound apply route, carry the
/// `Idempotency-Key` header, send the server-returned effective mapping, and
/// decode the applied proposal state.
#[tokio::test]
async fn apply_publisher_credential_proposal_targets_proposal_bound_route() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::from_u128(10);
    let proposal_id = Uuid::from_u128(11);
    let idempotency_key = Uuid::from_u128(12);
    let result_id = Uuid::from_u128(13);
    let vault_id = Uuid::from_u128(14);
    let item_id = Uuid::from_u128(15);
    let applied_revision_id = Uuid::from_u128(16);

    let body = ApplyPublisherCredentialProposalRequest {
        effective_mapping: vec![ManagedPublisherCredentialEffectiveMapping {
            environment_name: "SLACK_BOT_TOKEN".to_string(),
            ref_uri: format!("seren-secrets://{vault_id}/{item_id}/token"),
            vault_id,
            item_id,
            field: "token".to_string(),
        }],
        secret_resolution_result_id: Some(result_id),
    };

    Mock::given(method("POST"))
        .and(path(format!(
            "/publishers/seren-cloud/deployments/{deployment_id}/credentials/proposals/{proposal_id}/apply"
        )))
        .and(header("Idempotency-Key", idempotency_key.to_string().as_str()))
        .and(body_json(serde_json::json!({
            "effective_mapping": [{
                "environment_name": "SLACK_BOT_TOKEN",
                "ref_uri": format!("seren-secrets://{vault_id}/{item_id}/token"),
                "vault_id": vault_id,
                "item_id": item_id,
                "field": "token"
            }],
            "secret_resolution_result_id": result_id,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": proposal_id,
                "deployment_id": deployment_id,
                "expected_active_revision_id": Uuid::from_u128(2),
                "proposal_fingerprint": "fp",
                "requirements_fingerprint": "rfp",
                "requested_environment_names": ["SLACK_BOT_TOKEN"],
                "requires_secret_resolution_result": true,
                "changes": [],
                "state": "applied",
                "applied_revision_id": applied_revision_id,
                "result_id": result_id
            }
        })))
        .mount(&server)
        .await;

    let client =
        Client::from_config(&ClientConfig::unauthenticated().with_base_url(server.uri())).unwrap();
    let proposal = client
        .seren_cloud_apply_publisher_credential_proposal(
            &deployment_id,
            &proposal_id,
            &idempotency_key,
            &body,
        )
        .await
        .expect("apply deserializes")
        .into_inner()
        .data;

    assert_eq!(
        proposal.state,
        ManagedPublisherCredentialProposalState::Applied
    );
    assert_eq!(proposal.applied_revision_id, Some(applied_revision_id));
}
