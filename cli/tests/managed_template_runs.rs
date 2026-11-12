use serde_json::{Value, json};
use std::process::Command;
use std::time::{Duration, Instant};
use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEMPLATE: &str = "release-notes-writer";
const RUN_CODE: &str = "R-7F3K";

// Fixtures follow the bundled `ManagedAgentRunSummary` and `ManagedAgentRunTimeline` schemas.
fn run(ended: bool) -> Value {
    json!({
        "run_code": RUN_CODE,
        "employer": "Employer 14",
        "release": 40,
        "status": if ended { "failed" } else { "running" },
        "started_at": "2026-11-11T10:00:00Z",
        "ended_at": if ended { json!("2026-11-11T10:05:00Z") } else { Value::Null },
        "ending": if ended { json!("script_failed") } else { Value::Null },
        "ending_code": if ended { json!("script_exit_nonzero") } else { Value::Null },
        "exit_code": if ended { json!(2) } else { Value::Null },
        "model_calls": 388,
        "input_tokens": 120000,
        "output_tokens": 9000,
        "cost": "1.25"
    })
}

fn step(id: i64, name: &str) -> Value {
    json!({
        "id": id,
        "kind": "publisher_call",
        "name": name,
        "status": "succeeded",
        "started_at": "2026-11-11T10:01:00Z",
        "ended_at": "2026-11-11T10:01:30Z",
        "calls": 617,
        "exit_code": null,
        "error_code": null
    })
}

fn timeline(ended: bool, steps: Vec<Value>, next_after: i64) -> Value {
    json!({"data": {
        "run": run(ended),
        "stages": [],
        "steps": steps,
        "next_after": next_after
    }})
}

/// Run the real binary against the mock server, off the async runtime that serves it.
async fn seren(server: &MockServer, home: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_seren"));
    command
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("APPDATA", home)
        .env("NO_COLOR", "1")
        .current_dir(home)
        .args([
            "--api-base",
            &server.uri(),
            "--api-key",
            "run-timeline-test",
            "--profile",
            "run-timeline-tests",
            "--format",
            "json",
        ])
        .args(args);
    // Windows socket providers resolve system DLL paths through SystemRoot.
    #[cfg(windows)]
    command.env(
        "SystemRoot",
        std::env::var_os("SystemRoot")
            .expect("Windows provides SystemRoot for socket initialization"),
    );
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

fn assert_clean_success(output: &std::process::Output) {
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
}

/// The SDK leaves absent optional fields out when it prints a response again.
fn without_nulls(value: Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, without_nulls(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(without_nulls).collect()),
        other => other,
    }
}

/// Every JSON document the CLI printed, in order.
fn json_documents(stdout: &[u8]) -> Vec<Value> {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<Value>()
        .collect::<Result<_, _>>()
        .expect("stdout is a sequence of JSON documents")
}

#[tokio::test]
async fn managed_template_runs_prints_the_listed_runs_as_json() {
    let server = MockServer::start().await;
    let response = json!({"data": [run(true), run(false)]});
    Mock::given(method("GET"))
        .and(path(format!(
            "/publishers/seren-agent/templates/{TEMPLATE}/runs"
        )))
        .and(header("authorization", "Bearer run-timeline-test"))
        .and(query_param("ending", "script_failed"))
        .and(query_param("since", "2026-11-01T00:00:00Z"))
        .and(query_param("until", "2026-11-12T00:00:00Z"))
        .and(query_param("employer", "yours"))
        .and(query_param("release", "40"))
        .and(query_param("limit", "5"))
        .and(query_param("offset", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .expect(1)
        .mount(&server)
        .await;

    let home = tempfile::tempdir().unwrap();
    let output = seren(
        &server,
        home.path(),
        &[
            "agent",
            "managed-template-runs",
            TEMPLATE,
            "--ending",
            "script_failed",
            "--since",
            "2026-11-01T00:00:00Z",
            "--until",
            "2026-11-12T00:00:00Z",
            "--employer",
            "yours",
            "--release",
            "40",
            "--limit",
            "5",
            "--offset",
            "10",
        ],
    )
    .await;
    assert_clean_success(&output);
    assert_eq!(
        json_documents(&output.stdout),
        vec![without_nulls(response)]
    );
    server.verify().await;
}

#[tokio::test]
async fn following_a_run_stops_once_a_read_shows_it_ended() {
    let server = MockServer::start().await;
    let run_path = format!("/publishers/seren-agent/templates/{TEMPLATE}/runs/{RUN_CODE}");
    let first = timeline(
        false,
        vec![
            step(911, "daytona.create_session"),
            step(912, "daytona.get_session_command"),
        ],
        912,
    );
    let second = timeline(true, vec![step(913, "daytona.delete_session")], 913);
    Mock::given(method("GET"))
        .and(path(&run_path))
        .and(query_param_is_missing("after"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&first))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(&run_path))
        .and(query_param("after", "912"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&second))
        .expect(1)
        .mount(&server)
        .await;

    let home = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let output = seren(
        &server,
        home.path(),
        &[
            "agent",
            "managed-template-run",
            TEMPLATE,
            RUN_CODE,
            "--follow",
        ],
    )
    .await;
    assert_clean_success(&output);
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "the second read waits for the follow interval"
    );
    assert_eq!(
        json_documents(&output.stdout),
        [
            first,
            json!({"data": [step(913, "daytona.delete_session")]}),
            json!({"data": run(true)}),
        ]
        .map(without_nulls)
    );
    server.verify().await;
}
