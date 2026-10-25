use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_seren"))
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("APPDATA", home.path())
        .env("NO_COLOR", "1")
        .current_dir(home.path())
        .args(args)
        .output()
        .expect("the CLI process starts")
}

#[test]
fn help_starts_without_a_stack_override() {
    for args in [&["--help"][..], &["agent", "--help"][..]] {
        let output = invoke(args);
        assert!(
            output.status.success(),
            "CLI startup failed: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn version_starts_without_a_stack_override() {
    let output = invoke(&["--version"]);
    assert!(output.status.success(), "CLI startup failed: {output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("seren "));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_arguments_exit_before_authentication() {
    let output = invoke(&[
        "orgs",
        "update",
        "--org-id",
        "11111111-1111-1111-1111-111111111111",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--name"));
    assert!(stderr.contains("--public-handle"));
    assert!(output.stdout.is_empty());
}
