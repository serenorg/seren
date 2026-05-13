use anyhow::{Context, Result};
use etcetera::base_strategy::{BaseStrategy, choose_base_strategy};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Default profile name when --profile/SEREN_PROFILE is not provided.
pub const DEFAULT_PROFILE: &str = "default";

static ACTIVE_PROFILE: OnceLock<String> = OnceLock::new();

/// Resolve a profile name from explicit overrides and env, with precedence:
///   1. `cli_flag` (e.g. parsed `--profile`)
///   2. `env` (e.g. `SEREN_PROFILE`)
///   3. `DEFAULT_PROFILE`
pub fn resolve_profile(cli_flag: Option<&str>, env: Option<&str>) -> String {
    let normalize = |value: &str| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    cli_flag
        .and_then(normalize)
        .or_else(|| env.and_then(normalize))
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string())
}

/// Resolve the active profile name for the current process with precedence:
///   1. CLI flag (set via `set_active_profile`)
///   2. `SEREN_PROFILE` env var
///   3. `DEFAULT_PROFILE`
pub fn active_profile() -> &'static str {
    ACTIVE_PROFILE
        .get()
        .map(String::as_str)
        .or_else(|| {
            // Lazy-init from env on first read if not explicitly set.
            let from_env = std::env::var("SEREN_PROFILE").ok()?;
            let value = from_env.trim();
            if value.is_empty() {
                return None;
            }
            ACTIVE_PROFILE.set(value.to_string()).ok()?;
            ACTIVE_PROFILE.get().map(String::as_str)
        })
        .unwrap_or(DEFAULT_PROFILE)
}

/// Set the active profile (from CLI flag). First call wins.
pub fn set_active_profile(profile: Option<String>) {
    let env = std::env::var("SEREN_PROFILE").ok();
    let resolved = resolve_profile(profile.as_deref(), env.as_deref());
    if resolved != DEFAULT_PROFILE || profile.is_some() {
        let _ = ACTIVE_PROFILE.set(resolved);
    }
}

/// Base config root for the CLI, e.g. `~/.config/seren`.
pub fn config_root() -> Result<PathBuf> {
    let strategy = choose_base_strategy().context("Could not determine config directory")?;
    let config_dir = strategy.config_dir().join("seren");
    std::fs::create_dir_all(&config_dir).context("Could not create config directory")?;
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(&config_dir)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&config_dir, permissions)?;
    }
    Ok(config_dir)
}

/// Directory for the given (or active) profile, e.g. `~/.config/seren/profiles/dev/`.
pub fn profile_dir(profile: Option<&str>) -> Result<PathBuf> {
    let profile = profile.unwrap_or_else(|| active_profile());
    let dir = config_root()?.join("profiles").join(profile);
    std::fs::create_dir_all(&dir).context("Could not create profile directory")?;
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(&dir)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&dir, permissions)?;
    }
    Ok(dir)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Config {
    pub fn from_api_key(api_key: String) -> Self {
        Self {
            api_key: Some(api_key),
            access_token: None,
            refresh_token: None,
            expires_at: None,
        }
    }

    pub fn from_oauth(access_token: String, refresh_token: String, expires_at: i64) -> Self {
        Self {
            api_key: None,
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(expires_at),
        }
    }

    pub fn get_bearer_token(&self) -> Option<&str> {
        self.api_key.as_deref().or(self.access_token.as_deref())
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ContextConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

impl Config {
    /// Get the path to the credentials file for the active profile.
    ///
    /// Layout:
    /// - Linux/macOS: `~/.config/seren/profiles/<profile>/credentials.toml`
    /// - Windows:    `%APPDATA%\Seren\profiles\<profile>\credentials.toml`
    ///
    /// When the active profile is `default` and the per-profile file does not
    /// yet exist, the legacy single-profile path
    /// (`~/.config/seren/credentials.toml`) is returned for backwards
    /// compatibility. If both exist, the per-profile path wins; the legacy
    /// file is then ignored and never migrated automatically.
    pub fn config_path() -> Result<PathBuf> {
        Self::config_path_for(None)
    }

    /// Same as `config_path` but allows specifying an explicit profile.
    pub fn config_path_for(profile: Option<&str>) -> Result<PathBuf> {
        let profile_name = profile.unwrap_or_else(|| active_profile());
        let profile_path = profile_dir(Some(profile_name))?.join("credentials.toml");

        if profile_name == DEFAULT_PROFILE && !profile_path.exists() {
            let legacy = config_root()?.join("credentials.toml");
            if legacy.exists() {
                return Ok(legacy);
            }
        }

        Ok(profile_path)
    }

    /// Load config from disk
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if !path.exists() {
            anyhow::bail!(
                "Not authenticated. Run 'seren auth login' first.\nConfig path: {}",
                path.display()
            );
        }

        let contents = std::fs::read_to_string(&path).context("Could not read config file")?;

        toml::from_str(&contents).context("Could not parse config file")
    }

    /// Save config to disk with secure permissions
    pub fn save(&self) -> Result<()> {
        let path = self.write_to_disk()?;
        println!("✓ Credentials saved to {}", path.display());
        Ok(())
    }

    pub fn save_silent(&self) -> Result<()> {
        self.write_to_disk().map(|_| ())
    }

    fn write_to_disk(&self) -> Result<PathBuf> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self).context("Could not serialize config")?;

        std::fs::write(&path, contents).context("Could not write config file")?;

        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(&path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions)?;
        }

        Ok(path)
    }

    /// Delete config file
    pub fn delete() -> Result<()> {
        let path = Self::config_path()?;

        if path.exists() {
            std::fs::remove_file(&path).context("Could not delete config file")?;
            println!("✓ Credentials removed from {}", path.display());
        } else {
            println!("No credentials found");
        }

        Ok(())
    }
}

impl ContextConfig {
    /// Get the path to the context config file for the active profile.
    ///
    /// When the active profile is `default` and no per-profile file exists,
    /// the legacy single-profile path (`~/.config/seren/context.toml`) is
    /// returned for backwards compatibility. If both exist, the per-profile
    /// path wins.
    pub fn context_path() -> Result<PathBuf> {
        Self::context_path_for(None)
    }

    /// Same as `context_path` but allows specifying an explicit profile.
    pub fn context_path_for(profile: Option<&str>) -> Result<PathBuf> {
        let profile_name = profile.unwrap_or_else(|| active_profile());
        let profile_path = profile_dir(Some(profile_name))?.join("context.toml");

        if profile_name == DEFAULT_PROFILE && !profile_path.exists() {
            let legacy = config_root()?.join("context.toml");
            if legacy.exists() {
                return Ok(legacy);
            }
        }

        Ok(profile_path)
    }

    /// Load context from disk, returns empty context if file doesn't exist
    pub fn load() -> Result<Self> {
        let path = Self::context_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&path).context("Could not read context file")?;

        toml::from_str(&contents).context("Could not parse context file")
    }

    /// Save context to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::context_path()?;
        let contents = toml::to_string_pretty(self).context("Could not serialize context")?;

        std::fs::write(&path, contents).context("Could not write context file")?;

        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(&path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions)?;
        }

        Ok(())
    }

    /// Delete context file
    pub fn clear() -> Result<()> {
        let path = Self::context_path()?;

        if path.exists() {
            std::fs::remove_file(&path).context("Could not delete context file")?;
        }

        Ok(())
    }
}

/// Helper function to set project context
pub fn set_context_project(project_id: &str) -> Result<()> {
    let mut context = ContextConfig::load()?;
    context.project_id = Some(project_id.to_string());
    context.save()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Serializes env-mutating tests in this module so concurrent runs do
    /// not race on `XDG_CONFIG_HOME` / `SEREN_PROFILE`. `serial_test` is not
    /// a dependency in this crate, so we roll our own.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Scope guard: snapshots an env var on construction and restores it
    /// (or unsets it) on drop, even if the test panics in between.
    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: tests in this module hold ENV_LOCK while mutating env,
            // so concurrent threads in the test runner cannot observe a
            // half-updated value. The guard restores the previous value on
            // drop.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }

        fn remove(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn resolve_profile_defaults_when_no_overrides() {
        assert_eq!(resolve_profile(None, None), DEFAULT_PROFILE);
    }

    #[test]
    fn resolve_profile_uses_env_when_cli_missing() {
        assert_eq!(resolve_profile(None, Some("staging")), "staging");
    }

    #[test]
    fn resolve_profile_cli_flag_beats_env() {
        assert_eq!(resolve_profile(Some("dev"), Some("staging")), "dev");
    }

    #[test]
    fn resolve_profile_empty_strings_fall_through() {
        assert_eq!(resolve_profile(Some("   "), Some("")), DEFAULT_PROFILE);
        assert_eq!(resolve_profile(Some(""), Some("ci")), "ci");
    }

    #[test]
    fn per_profile_credentials_path_wins_over_legacy_when_both_exist() {
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::remove("SEREN_PROFILE");

        let seren_root = xdg.path().join("seren");
        std::fs::create_dir_all(&seren_root).unwrap();
        let legacy = seren_root.join("credentials.toml");
        std::fs::write(&legacy, "legacy = true").unwrap();

        let per_profile_dir = seren_root.join("profiles").join(DEFAULT_PROFILE);
        std::fs::create_dir_all(&per_profile_dir).unwrap();
        let per_profile = per_profile_dir.join("credentials.toml");
        std::fs::write(&per_profile, "profile = true").unwrap();

        let resolved = Config::config_path_for(Some(DEFAULT_PROFILE)).unwrap();
        assert_eq!(resolved, per_profile);
        // Legacy file is untouched -- no auto-migration ever happens.
        assert!(legacy.exists());
        assert_eq!(std::fs::read_to_string(&legacy).unwrap(), "legacy = true");
    }

    #[test]
    fn legacy_credentials_path_returned_only_when_per_profile_missing() {
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::remove("SEREN_PROFILE");

        let seren_root = xdg.path().join("seren");
        std::fs::create_dir_all(&seren_root).unwrap();
        let legacy = seren_root.join("credentials.toml");
        std::fs::write(&legacy, "legacy = true").unwrap();

        // Only the default profile gets the legacy fallback.
        let resolved = Config::config_path_for(Some(DEFAULT_PROFILE)).unwrap();
        assert_eq!(resolved, legacy);

        // A non-default profile never falls back to the legacy path.
        let staging = Config::config_path_for(Some("staging")).unwrap();
        assert_ne!(staging, legacy);
        assert!(staging.ends_with("profiles/staging/credentials.toml"));
    }

    #[test]
    fn legacy_credentials_file_is_not_auto_migrated_on_read() {
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::remove("SEREN_PROFILE");

        let seren_root = xdg.path().join("seren");
        std::fs::create_dir_all(&seren_root).unwrap();
        let legacy = seren_root.join("credentials.toml");
        std::fs::write(&legacy, "api_key = \"seren_legacy\"").unwrap();

        // Two reads through the resolver should never copy the legacy file
        // into the per-profile location. The resolver is read-only.
        let _ = Config::config_path_for(Some(DEFAULT_PROFILE)).unwrap();
        let _ = Config::config_path_for(Some(DEFAULT_PROFILE)).unwrap();

        let per_profile = seren_root
            .join("profiles")
            .join(DEFAULT_PROFILE)
            .join("credentials.toml");
        assert!(
            !per_profile.exists(),
            "resolver must not migrate the legacy credentials file"
        );
        assert!(legacy.exists());
    }

    #[test]
    fn per_profile_context_path_wins_over_legacy_when_both_exist() {
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::remove("SEREN_PROFILE");

        let seren_root = xdg.path().join("seren");
        std::fs::create_dir_all(&seren_root).unwrap();
        let legacy = seren_root.join("context.toml");
        std::fs::write(&legacy, "project_id = \"legacy\"").unwrap();
        let per_profile_dir = seren_root.join("profiles").join(DEFAULT_PROFILE);
        std::fs::create_dir_all(&per_profile_dir).unwrap();
        let per_profile = per_profile_dir.join("context.toml");
        std::fs::write(&per_profile, "project_id = \"current\"").unwrap();

        let resolved = ContextConfig::context_path_for(Some(DEFAULT_PROFILE)).unwrap();
        assert_eq!(resolved, per_profile);
        assert_eq!(
            std::fs::read_to_string(&legacy).unwrap(),
            "project_id = \"legacy\""
        );
    }

    #[test]
    fn cli_flag_beats_seren_profile_env_for_path_resolution() {
        // CLI flag vs SEREN_PROFILE env precedence: `--profile staging`
        // should resolve `staging/credentials.toml` even when
        // SEREN_PROFILE=other is set in the environment.
        //
        // `set_active_profile` writes to a process-global OnceLock, so we
        // exercise the same precedence rule through `resolve_profile` plus
        // the path resolver, which is what the rest of the codebase uses.
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::set("SEREN_PROFILE", "from-env");

        let env_value = std::env::var("SEREN_PROFILE").ok();
        let resolved_name = resolve_profile(Some("from-cli"), env_value.as_deref());
        assert_eq!(resolved_name, "from-cli");

        let path = Config::config_path_for(Some(&resolved_name)).unwrap();
        assert!(
            path.ends_with("profiles/from-cli/credentials.toml"),
            "expected CLI flag profile in path, got {}",
            path.display()
        );
    }

    #[test]
    fn seren_profile_env_used_when_cli_flag_absent() {
        let _lock = ENV_LOCK.lock().unwrap();
        let xdg = tempdir().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", xdg.path().to_str().unwrap());
        let _profile_guard = EnvGuard::set("SEREN_PROFILE", "ci");

        let env_value = std::env::var("SEREN_PROFILE").ok();
        let resolved_name = resolve_profile(None, env_value.as_deref());
        assert_eq!(resolved_name, "ci");

        let path = Config::config_path_for(Some(&resolved_name)).unwrap();
        assert!(
            path.ends_with("profiles/ci/credentials.toml"),
            "expected env-derived profile in path, got {}",
            path.display()
        );
    }
}
