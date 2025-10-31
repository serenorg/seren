use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    /// Get the path to the config file
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("seren");

        fs::create_dir_all(&config_dir).context("Could not create config directory")?;

        // Set secure permissions on config directory (0o700)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&config_dir)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&config_dir, permissions)?;
        }

        Ok(config_dir.join("credentials.toml"))
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

        let contents = fs::read_to_string(&path).context("Could not read config file")?;

        toml::from_str(&contents).context("Could not parse config file")
    }

    /// Save config to disk with secure permissions
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self).context("Could not serialize config")?;

        fs::write(&path, contents).context("Could not write config file")?;

        // Set secure permissions on credentials file (0o600)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions)?;
        }

        println!("✓ Credentials saved to {}", path.display());

        Ok(())
    }

    /// Delete config file
    pub fn delete() -> Result<()> {
        let path = Self::config_path()?;

        if path.exists() {
            fs::remove_file(&path).context("Could not delete config file")?;
            println!("✓ Credentials removed from {}", path.display());
        } else {
            println!("No credentials found");
        }

        Ok(())
    }
}

impl ContextConfig {
    /// Get the path to the context config file
    pub fn context_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("seren");

        fs::create_dir_all(&config_dir).context("Could not create config directory")?;

        Ok(config_dir.join("context.toml"))
    }

    /// Load context from disk, returns empty context if file doesn't exist
    pub fn load() -> Result<Self> {
        let path = Self::context_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path).context("Could not read context file")?;

        toml::from_str(&contents).context("Could not parse context file")
    }

    /// Save context to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::context_path()?;
        let contents = toml::to_string_pretty(self).context("Could not serialize context")?;

        fs::write(&path, contents).context("Could not write context file")?;

        Ok(())
    }

    /// Delete context file
    pub fn clear() -> Result<()> {
        let path = Self::context_path()?;

        if path.exists() {
            fs::remove_file(&path).context("Could not delete context file")?;
        }

        Ok(())
    }
}
