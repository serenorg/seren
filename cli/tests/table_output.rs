use serde_json::{Value, json};
use std::process::Command;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const ID: &str = "11111111-1111-1111-1111-111111111111";

async fn table_output(args: Vec<String>, endpoint: String, body: Value) -> String {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(endpoint))
        .and(header("authorization", "Bearer table-output-fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;
    let base = server.uri();
    let home = tempfile::tempdir().unwrap();
    let output = tokio::task::spawn_blocking(move || {
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
                &base,
                "--api-key",
                "table-output-fixture",
                "--format",
                "table",
            ])
            .args(args);
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
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.verify().await;
    String::from_utf8(output.stdout).unwrap()
}

fn rows(table: &str) -> Vec<Vec<&str>> {
    table
        .lines()
        .filter_map(|line| line.strip_prefix('\u{2502}')?.strip_suffix('\u{2502}'))
        .map(|line| line.split('\u{2506}').map(str::trim).collect())
        .collect()
}

#[tokio::test]
async fn organization_members_table_preserves_columns_and_values() {
    let stdout = table_output(
        vec![
            "orgs".into(),
            "members".into(),
            "--org-id".into(),
            ID.into(),
        ],
        format!("/organizations/{ID}/members"),
        json!({"data": [{
            "id": ID, "organization_id": ID, "user_id": ID,
            "email": "table@example.com", "name": "Table Member", "role": "admin",
            "created_at": "2026-10-01T00:00:00Z"
        }, {
            "id": "22222222-2222-2222-2222-222222222222", "organization_id": ID, "user_id": ID,
            "email": "other@example.com", "name": null, "role": "viewer",
            "created_at": "2026-10-02T00:00:00Z"
        }]}),
    )
    .await;
    assert_eq!(
        rows(&stdout),
        vec![
            vec!["Email", "Name", "Role", "Joined"],
            vec![
                "table@example.com",
                "Table Member",
                "admin",
                "2026-10-01T00:00:00Z"
            ],
            vec![
                "other@example.com",
                "\u{2014}",
                "viewer",
                "2026-10-02T00:00:00Z"
            ],
        ]
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with('\u{251c}'))
            .count(),
        1
    );
}

#[tokio::test]
async fn database_table_preserves_condensed_columns_and_values() {
    let stdout = table_output(
        vec!["database".into(), "list".into()],
        "/databases".into(),
        json!({"data": [{
            "id": ID, "project_id": ID, "branch_id": ID,
            "project_name": "Table Project", "branch_name": "main", "is_default_branch": false,
            "name": "table_db", "owner_name": "table_owner", "created_at": "2026-10-01T00:00:00Z"
        }, {
            "id": "22222222-2222-2222-2222-222222222222", "project_id": ID, "branch_id": ID,
            "project_name": "Other Project", "branch_name": "release", "is_default_branch": true,
            "name": "other_db", "owner_name": null, "created_at": "2026-10-02T00:00:00Z"
        }]}),
    )
    .await;
    assert_eq!(
        rows(&stdout),
        vec![
            vec!["Project", "Branch", "Default", "Database", "Owner", "ID"],
            vec!["Table Project", "main", "", "table_db", "table_owner", ID],
            vec![
                "Other Project",
                "release",
                "\u{2713}",
                "other_db",
                "-",
                "22222222-2222-2222-2222-222222222222"
            ],
        ]
    );
    assert!(!stdout.lines().any(|line| line.starts_with('\u{251c}')));
}
