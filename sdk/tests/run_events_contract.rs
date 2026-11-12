use serde_json::{Value, json};
use seren::Client;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Managed agent events with tool output, model timing, and recoverable warnings.
fn current_run_events() -> Value {
    json!([
        {
            "type": "tool_call", "kind": "tool_call_started", "sequence_number": 1,
            "id": "call_1", "name": "web_search", "item_id": "call_1",
            "arguments": "{\"q\":\"seren\"}", "display_arguments": "{\"q\":\"seren\"}"
        },
        {
            "type": "tool_output", "kind": "tool_output", "sequence_number": 2,
            "item_id": "call_1", "name": "web_search", "stream": "stdout",
            "text": "searching\n", "offset": 0, "truncated": false
        },
        {
            "type": "tool_result", "kind": "tool_call_completed", "sequence_number": 3,
            "id": "call_1", "item_id": "call_1", "content": "3 results", "is_error": false,
            "display_content": "3 results", "retryable": false
        },
        {
            "type": "model_call_finished", "kind": "model_call_finished", "sequence_number": 4,
            "item_id": "model_1", "state": "finished", "duration_ms": 1250,
            "model": "anthropic/claude-opus-5-5",
            "started_at": "2026-11-12T10:00:00Z", "finished_at": "2026-11-12T10:00:01.250Z"
        },
        {
            "type": "warning", "kind": "warning", "sequence_number": 5,
            "tool": "web_search", "code": "tool_provider_failed"
        }
    ])
}

#[tokio::test]
async fn deployment_run_events_decode_current_runtime_kinds() {
    let server = MockServer::start().await;
    let deployment_id = Uuid::from_u128(7);
    let run_id = Uuid::from_u128(8);
    Mock::given(method("GET"))
        .and(path(format!(
            "/publishers/seren-cloud/deployments/{deployment_id}/runs/{run_id}/events"
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"data": current_run_events()})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(&server.uri());
    let events = client
        .seren_cloud_deployment_run_events(&deployment_id, &run_id, None, None, None, None, None)
        .await
        .expect("current runtime events decode")
        .into_inner();
    let events = serde_json::to_value(events).unwrap();
    let events = events["data"].as_array().unwrap();

    let kinds: Vec<&str> = events.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "tool_call_started",
            "tool_output",
            "tool_call_completed",
            "model_call_finished",
            "warning"
        ]
    );
    assert_eq!(events[0]["display_arguments"], "{\"q\":\"seren\"}");
    assert_eq!(events[1]["stream"], "stdout");
    assert_eq!(events[1]["text"], "searching\n");
    assert_eq!(events[2]["display_content"], "3 results");
    assert_eq!(events[3]["state"], "finished");
    assert_eq!(events[3]["duration_ms"], 1250);
    assert_eq!(events[4]["tool"], "web_search");
}
