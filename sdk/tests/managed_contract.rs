use serde_json::json;
use seren::{ApprovalInboxDecisionRequest, Client, ManagedPublisherAllowanceCheck};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path, query_param},
};

#[tokio::test]
async fn standing_approval_preserves_exact_lease_and_entry_identity() {
    let server = MockServer::start().await;
    let entry_id = "review/42";
    let body = json!({
        "decision": "allow_always",
        "comment": "Allow the reviewed operation three times.",
        "lease": {
            "action": "create_record",
            "capability": {"kind": "specific", "actions": ["create_record"]},
            "expiry": "2026-11-01T00:00:00Z",
            "use_budget": 3
        }
    });
    let request: ApprovalInboxDecisionRequest = serde_json::from_value(body.clone()).unwrap();
    Mock::given(method("POST"))
        .and(path(
            "/publishers/seren-cloud/inbox/approvals/review%2F42/decide",
        ))
        .and(body_json(body))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"entry_id": entry_id, "decision_state": "approved"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let response = Client::new(&server.uri())
        .seren_cloud_approval_inbox_decide(entry_id, &request)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.data.entry_id, entry_id);
    assert_eq!(
        serde_json::to_value(response.data.decision_state).unwrap(),
        "approved"
    );
    server.verify().await;
}

#[tokio::test]
async fn allowance_check_preserves_publisher_operation_and_denial() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::new_v4();
    let request = ManagedPublisherAllowanceCheck {
        publisher_slug: "seren-notes".into(),
        operation_id: "create_note".into(),
    };
    Mock::given(method("POST"))
        .and(path(format!(
            "/publishers/seren-agent/deployments/{deployment_id}/allowances/check"
        )))
        .and(body_json(
            json!({"publisher_slug": "seren-notes", "operation_id": "create_note"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"allowed": false}})))
        .expect(1)
        .mount(&server)
        .await;

    let response = Client::new(&server.uri())
        .seren_agent_check_managed_publisher_allowance(&deployment_id, &request)
        .await
        .unwrap()
        .into_inner();
    assert!(!response.data.allowed);
    server.verify().await;
}

#[tokio::test]
async fn access_list_decodes_owner_reason_and_cursor() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let wire = json!({
        "data": {
            "entries": [{
                "id": request_id,
                "publisher_id": Uuid::new_v4(),
                "publisher_slug": "seren-notes",
                "kind": "api_key",
                "state": "pending",
                "created_at": "2026-10-03T12:00:00Z",
                "reason": "Save the owner's reviewed notes.",
                "conversation_id": "owner-chat",
                "session_id": Uuid::new_v4(),
                "execution_id": "run-42"
            }],
            "next_cursor": "next-page"
        }
    });
    Mock::given(method("GET"))
        .and(path(format!(
            "/publishers/seren-agent/deployments/{deployment_id}/access"
        )))
        .and(query_param("cursor", "previous-page"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wire.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let response = Client::new(&server.uri())
        .seren_agent_list_managed_agent_publisher_access_requests(
            &deployment_id,
            Some("previous-page"),
            std::num::NonZeroU32::new(5),
        )
        .await
        .unwrap()
        .into_inner();
    let decoded = serde_json::to_value(response).unwrap();
    assert_eq!(decoded["data"]["next_cursor"], wire["data"]["next_cursor"]);
    for (field, value) in wire["data"]["entries"][0].as_object().unwrap() {
        assert_eq!(&decoded["data"]["entries"][0][field], value, "{field}");
    }
    server.verify().await;
}
