// ABOUTME: Installs and removes the Seren Memory lifecycle hooks in agent configuration.
// ABOUTME: Only entries owned by Seren are ever created, reported, or removed.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

const HOOK_EVENTS: [(&str, &str); 2] = [
    (
        "SessionStart",
        "seren memory hook session-start --platform claude",
    ),
    ("Stop", "seren memory hook stop --platform claude"),
];

fn claude_settings_path() -> Result<PathBuf> {
    if let Some(config_dir) = std::env::var_os("CLAUDE_CONFIG_DIR")
        && !config_dir.is_empty()
    {
        return Ok(PathBuf::from(config_dir).join("settings.json"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".claude").join("settings.json"))
}

fn entry_contains_command(entry: &serde_json::Value, expected: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|hooks| hooks.as_array())
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command").and_then(|command| command.as_str()) == Some(expected)
            })
        })
}

fn validate_settings(settings: &serde_json::Value) -> Result<()> {
    let settings = settings
        .as_object()
        .context("agent settings are not a JSON object")?;
    if settings
        .get("disableAllHooks")
        .is_some_and(|disabled| !disabled.is_boolean())
    {
        anyhow::bail!("agent settings disableAllHooks value is not a boolean");
    }
    let Some(hooks) = settings.get("hooks") else {
        return Ok(());
    };
    let hooks = hooks
        .as_object()
        .context("agent settings hooks section is not a JSON object")?;
    for (event, _) in HOOK_EVENTS {
        let Some(entries) = hooks.get(event) else {
            continue;
        };
        let entries = entries
            .as_array()
            .with_context(|| format!("agent settings {event} hooks are not a JSON array"))?;
        for (entry_index, entry) in entries.iter().enumerate() {
            let entry = entry.as_object().with_context(|| {
                format!("agent settings {event} hook entry {entry_index} is not a JSON object")
            })?;
            let commands = entry
                .get("hooks")
                .and_then(|hooks| hooks.as_array())
                .with_context(|| {
                    format!(
                        "agent settings {event} hook entry {entry_index} does not contain a hooks array"
                    )
                })?;
            for (hook_index, command) in commands.iter().enumerate() {
                let command = command.as_object().with_context(|| {
                    format!(
                        "agent settings {event} hook entry {entry_index} command {hook_index} is not a JSON object"
                    )
                })?;
                if command
                    .get("command")
                    .is_some_and(|command| !command.is_string())
                {
                    anyhow::bail!(
                        "agent settings {event} hook entry {entry_index} command {hook_index} has a non-string command"
                    );
                }
            }
        }
    }
    Ok(())
}

fn hooks_enabled(settings: &serde_json::Value) -> bool {
    settings
        .get("disableAllHooks")
        .and_then(|value| value.as_bool())
        != Some(true)
}

fn event_entries<'a>(
    settings: &'a mut serde_json::Value,
    event: &str,
) -> Result<&'a mut Vec<serde_json::Value>> {
    if !settings.is_object() {
        anyhow::bail!("agent settings are not a JSON object");
    }
    let hooks = settings
        .as_object_mut()
        .expect("checked object above")
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        anyhow::bail!("agent settings hooks section is not a JSON object");
    }
    let entries = hooks
        .as_object_mut()
        .expect("checked object above")
        .entry(event)
        .or_insert_with(|| serde_json::json!([]));
    entries
        .as_array_mut()
        .context("agent settings hook event is not a JSON array")
}

fn installed_events(settings: &serde_json::Value) -> Result<Vec<&'static str>> {
    validate_settings(settings)?;
    Ok(HOOK_EVENTS
        .iter()
        .filter(|(event, command)| {
            settings
                .get("hooks")
                .and_then(|hooks| hooks.get(*event))
                .and_then(|entries| entries.as_array())
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry_contains_command(entry, command))
                })
        })
        .map(|(event, _)| *event)
        .collect())
}

/// Add the Seren hook entries, leaving every unrelated entry untouched.
/// Returns true when the document changed.
fn install_into(settings: &mut serde_json::Value) -> Result<bool> {
    validate_settings(settings)?;
    let mut changed = false;
    for (event, command) in HOOK_EVENTS {
        let entries = event_entries(settings, event)?;
        if entries
            .iter()
            .any(|entry| entry_contains_command(entry, command))
        {
            continue;
        }
        entries.push(serde_json::json!({
            "hooks": [{"type": "command", "command": command}]
        }));
        changed = true;
    }
    Ok(changed)
}

/// Remove only Seren-owned entries. Returns true when the document changed.
fn uninstall_from(settings: &mut serde_json::Value) -> Result<bool> {
    validate_settings(settings)?;
    let mut changed = false;
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return Ok(false);
    };
    for (event, command) in HOOK_EVENTS {
        let Some(entries) = hooks.get_mut(event).and_then(|e| e.as_array_mut()) else {
            continue;
        };
        entries.retain_mut(|entry| {
            let commands = entry
                .get_mut("hooks")
                .and_then(|hooks| hooks.as_array_mut())
                .expect("validated hook entry");
            let before = commands.len();
            commands.retain(|hook| {
                hook.get("command").and_then(|command| command.as_str()) != Some(command)
            });
            let removed_owned_command = commands.len() != before;
            changed |= removed_owned_command;
            !removed_owned_command || !commands.is_empty()
        });
    }
    Ok(changed)
}

fn load_settings(path: &Path) -> Result<(serde_json::Value, Option<Vec<u8>>)> {
    match std::fs::read(path) {
        Ok(raw) => {
            let settings = serde_json::from_slice(&raw)
                .with_context(|| format!("could not parse {}", path.display()))?;
            Ok((settings, Some(raw)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok((serde_json::json!({}), None))
        }
        Err(error) => Err(error.into()),
    }
}

fn create_settings_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn resolved_settings_path(path: &Path) -> Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => std::fs::canonicalize(path)
            .with_context(|| format!("could not resolve settings symlink {}", path.display())),
        Ok(_) => Ok(path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(error.into()),
    }
}

fn current_settings_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_new_file(
    path: &Path,
    contents: &[u8],
    permissions: Option<std::fs::Permissions>,
) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Some(permissions) = permissions {
        file.set_permissions(permissions)?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn write_settings_with_backup(
    path: &Path,
    settings: &serde_json::Value,
    expected_original: Option<&[u8]>,
) -> Result<()> {
    let path = resolved_settings_path(path)?;
    let parent = path
        .parent()
        .context("Claude settings path does not have a parent directory")?;
    create_settings_dir(parent)?;

    let lock_path = parent.join(".seren_memory_hooks.lock");
    let mut lock_options = std::fs::OpenOptions::new();
    lock_options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options.open(lock_path)?;
    lock.lock()?;

    let write_result = (|| -> Result<()> {
        let current = current_settings_bytes(&path)?;
        if current.as_deref() != expected_original {
            anyhow::bail!(
                "{} changed after it was read; retry without discarding the concurrent edit",
                path.display()
            );
        }

        let existing_permissions = path.metadata().ok().map(|metadata| metadata.permissions());
        if let Some(current) = current.as_deref() {
            let backup = path.with_extension(format!(
                "json.seren-backup-{}-{}",
                jiff::Timestamp::now().as_second(),
                uuid::Uuid::new_v4().simple()
            ));
            write_new_file(&backup, current, None)
                .with_context(|| format!("could not back up {}", path.display()))?;
            println!("Backed up existing settings to {}", backup.display());
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Claude settings filename is not valid UTF-8")?;
        let temporary = parent.join(format!(".{file_name}.seren_tmp-{}", uuid::Uuid::new_v4()));
        let mut serialized = serde_json::to_vec_pretty(settings)?;
        serialized.push(b'\n');
        if let Err(error) = write_new_file(&temporary, &serialized, existing_permissions) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }

        if current_settings_bytes(&path)?.as_deref() != expected_original {
            let _ = std::fs::remove_file(&temporary);
            anyhow::bail!(
                "{} changed while the update was being prepared; retry without discarding the concurrent edit",
                path.display()
            );
        }

        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        if let Err(error) = std::fs::rename(&temporary, &path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    let unlock_result = lock.unlock();
    match (write_result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn require_claude(claude: bool) -> Result<()> {
    if !claude {
        anyhow::bail!("specify --claude; it is the only supported platform so far");
    }
    Ok(())
}

pub async fn install(claude: bool) -> Result<()> {
    require_claude(claude)?;
    let path = claude_settings_path()?;
    let (mut settings, original) = load_settings(&path)?;
    if install_into(&mut settings)? {
        write_settings_with_backup(&path, &settings, original.as_deref())?;
        println!("Installed Seren Memory hooks into {}", path.display());
        println!(
            "The seren binary must stay on PATH; run `seren memory hook status` to inspect capture."
        );
    } else {
        println!(
            "Seren Memory hooks are already installed in {}",
            path.display()
        );
    }
    if !hooks_enabled(&settings) {
        eprintln!(
            "Seren Memory hooks are configured but Claude Code disableAllHooks is true; automatic capture remains disabled"
        );
    }
    Ok(())
}

pub async fn uninstall(claude: bool) -> Result<()> {
    require_claude(claude)?;
    let path = claude_settings_path()?;
    let (mut settings, original) = load_settings(&path)?;
    if uninstall_from(&mut settings)? {
        write_settings_with_backup(&path, &settings, original.as_deref())?;
        println!("Removed Seren Memory hooks from {}", path.display());
    } else {
        println!("No Seren Memory hooks were installed in {}", path.display());
    }
    Ok(())
}

pub async fn status(claude: bool) -> Result<()> {
    require_claude(claude)?;
    let path = claude_settings_path()?;
    let (settings, _) = load_settings(&path)?;
    let installed = installed_events(&settings)?;
    let hooks_enabled = hooks_enabled(&settings);
    println!(
        "{}",
        serde_json::json!({
            "settings_path": path.display().to_string(),
            "installed_events": installed,
            "hooks_enabled": hooks_enabled,
            "fully_installed": hooks_enabled && installed.len() == HOOK_EVENTS.len(),
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent_and_preserves_unrelated_hooks() {
        let mut settings = serde_json::json!({
            "model": "opus",
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "other-tool run"}]}],
                "Notification": [{"hooks": [{"type": "command", "command": "notify"}]}],
            }
        });
        assert!(install_into(&mut settings).unwrap());
        assert!(
            !install_into(&mut settings).unwrap(),
            "second run is a no-op"
        );
        assert_eq!(
            installed_events(&settings).unwrap(),
            vec!["SessionStart", "Stop"]
        );
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 2, "unrelated Stop hook is preserved");
        assert_eq!(settings["model"], "opus");
    }

    #[test]
    fn uninstall_removes_only_owned_entries() {
        let mut settings = serde_json::json!({});
        install_into(&mut settings).unwrap();
        let stop_entry = &mut settings["hooks"]["Stop"].as_array_mut().unwrap()[0];
        stop_entry["hooks"].as_array_mut().unwrap().extend([
            serde_json::json!({
                "type": "command",
                "command": "other-tool run"
            }),
            serde_json::json!({
                "type": "command",
                "command": "echo 'seren memory hook is mentioned, not owned'"
            }),
        ]);
        assert!(uninstall_from(&mut settings).unwrap());
        assert!(installed_events(&settings).unwrap().is_empty());
        let stop = settings["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0]["hooks"].as_array().unwrap().len(), 2);
        assert!(
            !uninstall_from(&mut settings).unwrap(),
            "second run is a no-op"
        );
    }

    #[test]
    fn malformed_settings_fail_loudly_instead_of_being_overwritten() {
        let mut not_object = serde_json::json!([]);
        assert!(install_into(&mut not_object).is_err());
        assert!(uninstall_from(&mut not_object).is_err());
        assert!(installed_events(&not_object).is_err());
        let mut bad_hooks = serde_json::json!({"hooks": "broken"});
        assert!(install_into(&mut bad_hooks).is_err());
        assert!(uninstall_from(&mut bad_hooks).is_err());
        assert!(installed_events(&bad_hooks).is_err());
        let mut bad_event = serde_json::json!({"hooks": {"Stop": "broken"}});
        assert!(install_into(&mut bad_event).is_err());
        assert!(uninstall_from(&mut bad_event).is_err());
        assert!(installed_events(&bad_event).is_err());
        let mut bad_disabled = serde_json::json!({"disableAllHooks": "yes"});
        assert!(install_into(&mut bad_disabled).is_err());
        assert!(uninstall_from(&mut bad_disabled).is_err());
        assert!(installed_events(&bad_disabled).is_err());
    }

    #[test]
    fn disabled_hooks_are_not_operationally_complete() {
        let mut settings = serde_json::json!({"disableAllHooks": true});
        install_into(&mut settings).unwrap();
        assert_eq!(
            installed_events(&settings).unwrap(),
            vec!["SessionStart", "Stop"]
        );
        assert!(!hooks_enabled(&settings));
    }

    #[test]
    fn file_updates_create_unique_backups_and_preserve_concurrent_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, br#"{"model":"opus"}"#).unwrap();

        let (mut settings, original) = load_settings(&path).unwrap();
        install_into(&mut settings).unwrap();
        write_settings_with_backup(&path, &settings, original.as_deref()).unwrap();

        let (mut settings, original) = load_settings(&path).unwrap();
        uninstall_from(&mut settings).unwrap();
        write_settings_with_backup(&path, &settings, original.as_deref()).unwrap();

        let backups = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".seren-backup-")
            })
            .count();
        assert_eq!(backups, 2);

        let (mut stale, original) = load_settings(&path).unwrap();
        install_into(&mut stale).unwrap();
        std::fs::write(&path, br#"{"model":"concurrent"}"#).unwrap();
        let error = write_settings_with_backup(&path, &stale, original.as_deref()).unwrap_err();
        assert!(error.to_string().contains("changed after it was read"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            serde_json::json!({"model": "concurrent"})
        );
    }

    #[cfg(unix)]
    #[test]
    fn updating_symlinked_settings_preserves_the_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("dotfiles");
        std::fs::create_dir(&target_dir).unwrap();
        let target = target_dir.join("settings.json");
        std::fs::write(&target, b"{}").unwrap();
        let link = dir.path().join("settings.json");
        symlink(&target, &link).unwrap();

        let (mut settings, original) = load_settings(&link).unwrap();
        install_into(&mut settings).unwrap();
        write_settings_with_backup(&link, &settings, original.as_deref()).unwrap();

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let updated: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
        assert_eq!(
            installed_events(&updated).unwrap(),
            vec!["SessionStart", "Stop"]
        );
    }
}
