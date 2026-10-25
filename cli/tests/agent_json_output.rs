use serde_json::{Value, json};
use std::process::Command;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DEPLOYMENT_ID: &str = "11111111-1111-1111-1111-111111111111";
const RUN_ID: &str = "22222222-2222-2222-2222-222222222222";

// Fixtures follow the bundled publisher response schemas, including envelope metadata.
fn envelope(data: Value, count: i64) -> Value {
    json!({
        "data": data,
        "pagination": {
            "total": count,
            "count": count,
            "limit": 20,
            "offset": 0,
            "has_more": false
        }
    })
}

fn action_response(status: &str) -> Value {
    envelope(
        json!({
            "status": status,
            "confirmation": "control change recorded",
            "desired_lifecycle_state": "stopped",
            "desired_egress_state": "muted",
            "control_generation": 17
        }),
        1,
    )
}

fn run_response(status: &str) -> Value {
    envelope(
        json!({
            "status": status,
            "run_id": RUN_ID,
            "execution_id": "execution-123",
            "execution_time_ms": 321,
            "compute_cost_atomic": 987654,
            "exit_code": 0,
            "job_name": "nightly-job",
            "sandbox_id": "sandbox-123",
            "script_name": "worker-123",
            "result": {"message": "done", "items": [1, {"ok": true}]}
        }),
        1,
    )
}

async fn invoke(
    args: &[&str],
    format: &str,
    http_method: &str,
    endpoint: &str,
    status: u16,
    response: &Value,
    request: Option<Value>,
) -> Vec<u8> {
    let server = MockServer::start().await;
    let mut mock = Mock::given(method(http_method))
        .and(path(endpoint))
        .and(header("authorization", "Bearer json-output-test"));
    if let Some(request) = request {
        mock = mock.and(body_partial_json(request));
    }
    mock.respond_with(ResponseTemplate::new(status).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let home = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_seren"));
    command
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("APPDATA", home.path())
        .env("NO_COLOR", "1")
        .current_dir(home.path())
        .args([
            "--api-base",
            &server.uri(),
            "--api-key",
            "json-output-test",
            "--profile",
            "json-output-tests",
            "--format",
            format,
        ])
        .args(args);
    let output = tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.verify().await;
    output.stdout
}

async fn assert_output_formats(
    args: &[&str],
    http_method: &str,
    endpoint: &str,
    status: u16,
    response: Value,
    request: Option<Value>,
    text_fragments: &[&str],
) {
    let stdout = invoke(
        args,
        "json",
        http_method,
        endpoint,
        status,
        &response,
        request.clone(),
    )
    .await;
    let actual: Value = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must contain exactly one JSON response: {error}: {}",
            String::from_utf8_lossy(&stdout)
        )
    });
    assert_eq!(actual, response);

    let stdout = invoke(
        args,
        "table",
        http_method,
        endpoint,
        status,
        &response,
        request,
    )
    .await;
    let text = String::from_utf8(stdout).unwrap();
    for fragment in text_fragments {
        assert!(text.contains(fragment), "missing {fragment:?} in {text:?}");
    }
}

#[tokio::test]
async fn managed_delete_preserves_response_and_text_confirmation() {
    assert_output_formats(
        &["agent", "managed-delete", DEPLOYMENT_ID],
        "DELETE",
        &format!("/publishers/seren-agent/deployments/{DEPLOYMENT_ID}"),
        200,
        action_response("deleted"),
        None,
        &["Managed deployment", DEPLOYMENT_ID, "deleted."],
    )
    .await;
}

#[tokio::test]
async fn cloud_destroy_preserves_response_and_text_confirmation() {
    assert_output_formats(
        &["agent", "cloud", "deployment", "destroy", DEPLOYMENT_ID],
        "DELETE",
        &format!("/publishers/seren-cloud/deployments/{DEPLOYMENT_ID}"),
        200,
        action_response("destroyed"),
        None,
        &["Deployment", DEPLOYMENT_ID, "destroyed."],
    )
    .await;
}

#[tokio::test]
async fn cloud_update_config_preserves_response_and_text_confirmation() {
    assert_output_formats(
        &[
            "agent",
            "cloud",
            "deployment",
            "update-config",
            DEPLOYMENT_ID,
            "--clear-alert-policy",
        ],
        "PATCH",
        &format!("/publishers/seren-cloud/deployments/{DEPLOYMENT_ID}"),
        200,
        action_response("updated"),
        Some(json!({"clear_alert_policy": true})),
        &["Deployment settings updated for", DEPLOYMENT_ID],
    )
    .await;
}

#[tokio::test]
async fn synchronous_cloud_run_preserves_full_result() {
    assert_output_formats(
        &[
            "agent",
            "cloud",
            "run",
            "start",
            "--deployment-id",
            DEPLOYMENT_ID,
            "--message",
            "hello",
        ],
        "POST",
        &format!("/publishers/seren-cloud/deployments/{DEPLOYMENT_ID}/runs"),
        200,
        run_response("completed"),
        Some(json!({"message": "hello"})),
        &["Run accepted for deployment", DEPLOYMENT_ID, RUN_ID],
    )
    .await;
}

#[tokio::test]
async fn asynchronous_cloud_run_preserves_full_acceptance() {
    assert_output_formats(
        &[
            "agent",
            "cloud",
            "run",
            "start",
            "--deployment-id",
            DEPLOYMENT_ID,
            "--async",
        ],
        "POST",
        &format!("/publishers/seren-cloud/deployments/{DEPLOYMENT_ID}/runs"),
        202,
        run_response("queued"),
        Some(json!({"async": true})),
        &[
            "Run accepted for deployment",
            DEPLOYMENT_ID,
            RUN_ID,
            "execution-123",
            "Check status: seren agent cloud run get",
        ],
    )
    .await;
}

#[tokio::test]
async fn environment_list_preserves_full_records_and_pagination() {
    let response = envelope(
        json!([{
            "id": DEPLOYMENT_ID,
            "organization_id": "33333333-3333-3333-3333-333333333333",
            "user_id": "44444444-4444-4444-4444-444444444444",
            "name": "Python runtime",
            "description": "Shared runtime",
            "docker_image": "python:3.13",
            "setup_commands": ["pip install requests"],
            "is_default": true,
            "created_at": "2026-10-25T00:00:00Z",
            "updated_at": "2026-10-25T01:00:00Z"
        }]),
        1,
    );
    assert_output_formats(
        &["agent", "cloud", "environment", "list"],
        "GET",
        "/publishers/seren-cloud/environments",
        200,
        response,
        None,
        &[
            "ID",
            "NAME",
            "DEFAULT",
            "IMAGE",
            "Python runtime",
            "python:3.13",
            "yes",
        ],
    )
    .await;
}

#[tokio::test]
async fn empty_environment_list_emits_json_envelope() {
    assert_output_formats(
        &["agent", "cloud", "environment", "list"],
        "GET",
        "/publishers/seren-cloud/environments",
        200,
        envelope(json!([]), 0),
        None,
        &["No cloud environments found."],
    )
    .await;
}
