use serde_json::json;
use std::process::{Command, Output};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

async fn cli(server: &MockServer, args: Vec<String>) -> Output {
    let host = server.uri();
    let home = tempfile::tempdir().unwrap();
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_seren"));
        command
            .env_clear()
            .current_dir(home.path())
            .args(["--api-base", &host, "--api-key", "seren_test_key"])
            .args(args)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("APPDATA", home.path())
            .env("NO_COLOR", "1");
        // Windows socket providers resolve system DLL paths through SystemRoot.
        #[cfg(windows)]
        command.env(
            "SystemRoot",
            std::env::var_os("SystemRoot")
                .expect("Windows provides SystemRoot for socket initialization"),
        );
        command.output().unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn lifecycle_hints_name_executable_status_commands() {
    for cloud in [false, true] {
        for (action, status, final_status) in [
            ("start", "starting", "running"),
            ("stop", "stopping", "stopped"),
        ] {
            let server = MockServer::start().await;
            if cloud {
                Mock::given(method("GET"))
                    .and(path(format!("/publishers/seren-cloud/deployments/{ID}")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {
                        "id": ID, "organization_id": ID, "user_id": ID, "name": "Lifecycle",
                        "skill_slug": "lifecycle", "code_bundle_hash": "bundle-sha", "compute_backend": "aws_container",
                        "control_generation": 7, "created_at": "2026-10-23T00:00:00Z",
                        "desired_egress_state": "muted", "desired_lifecycle_state": "stopped",
                        "mode": "always_on", "orchestration_mode": "llm", "requirements": [],
                        "runtime_kind": "python", "status": "stopped", "updated_at": "2026-10-23T00:00:00Z", "visibility": "open"
                    }})))
                    .expect(1).mount(&server).await;
            }
            let publisher = if cloud { "seren-cloud" } else { "seren-agent" };
            Mock::given(method("POST"))
                .and(path(format!("/publishers/{publisher}/deployments/{ID}/{action}")))
                .respond_with(ResponseTemplate::new(202).set_body_json(json!({"data": {
                    "status": status, "desired_lifecycle_state": if action == "start" { "running" } else { "stopped" },
                    "desired_egress_state": "muted", "control_generation": 7
                }})))
                .expect(1).mount(&server).await;
            let args: Vec<String> = if cloud {
                vec![
                    "agent".into(),
                    "cloud".into(),
                    "deployment".into(),
                    action.into(),
                    ID.into(),
                ]
            } else {
                vec!["agent".into(), format!("managed-{action}"), ID.into()]
            };
            let result = cli(&server, args).await;
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let stdout = String::from_utf8(result.stdout).unwrap();
            assert!(stdout.contains("accepted; not yet converged"), "{stdout}");
            assert!(
                stdout.contains(&format!("until it reports {final_status}.")),
                "{stdout}"
            );
            let hint = stdout.split('`').nth(1).expect("status command hint");
            let expected = if cloud {
                format!("seren agent cloud deployment status {ID}")
            } else {
                format!("seren agent managed-get {ID}")
            };
            assert_eq!(hint, expected);
            // Exercise the real parser using the command emitted to the user, without another API call.
            let mut hinted: Vec<String> =
                hint.split_whitespace().skip(1).map(str::to_owned).collect();
            hinted.push("--help".into());
            let parsed = cli(&server, hinted).await;
            assert!(
                parsed.status.success(),
                "{}",
                String::from_utf8_lossy(&parsed.stderr)
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), if cloud { 2 } else { 1 });
            server.verify().await;
        }
    }
}
