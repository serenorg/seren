use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

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
    pub async fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("seren");

        fs::create_dir_all(&config_dir)
            .await
            .context("Could not create config directory")?;

        // Set secure permissions on config directory (0o700)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&config_dir).await?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&config_dir, permissions).await?;
        }

        Ok(config_dir.join("credentials.toml"))
    }

    /// Load config from disk
    pub async fn load() -> Result<Self> {
        let path = Self::config_path().await?;

        if !tokio::fs::try_exists(&path).await? {
            anyhow::bail!(
                "Not authenticated. Run 'seren auth login' first.\nConfig path: {}",
                path.display()
            );
        }

        let contents = fs::read_to_string(&path)
            .await
            .context("Could not read config file")?;

        toml::from_str(&contents).context("Could not parse config file")
    }

    /// Save config to disk with secure permissions
    pub async fn save(&self) -> Result<()> {
        let path = self.write_to_disk().await?;
        println!("✓ Credentials saved to {}", path.display());
        Ok(())
    }

    pub async fn save_silent(&self) -> Result<()> {
        self.write_to_disk().await.map(|_| ())
    }

    async fn write_to_disk(&self) -> Result<PathBuf> {
        let path = Self::config_path().await?;
        let contents = toml::to_string_pretty(self).context("Could not serialize config")?;

        fs::write(&path, contents)
            .await
            .context("Could not write config file")?;

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&path).await?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions).await?;
        }

        Ok(path)
    }

    /// Delete config file
    pub async fn delete() -> Result<()> {
        let path = Self::config_path().await?;

        if tokio::fs::try_exists(&path).await? {
            fs::remove_file(&path)
                .await
                .context("Could not delete config file")?;
            println!("✓ Credentials removed from {}", path.display());
        } else {
            println!("No credentials found");
        }

        Ok(())
    }
}

impl ContextConfig {
    /// Get the path to the context config file
    pub async fn context_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("seren");

        fs::create_dir_all(&config_dir)
            .await
            .context("Could not create config directory")?;

        Ok(config_dir.join("context.toml"))
    }

    /// Load context from disk, returns empty context if file doesn't exist
    pub async fn load() -> Result<Self> {
        let path = Self::context_path().await?;

        if !tokio::fs::try_exists(&path).await? {
            return Ok(Self::default());
        }

        let contents = fs::read_to_string(&path)
            .await
            .context("Could not read context file")?;

        toml::from_str(&contents).context("Could not parse context file")
    }

    /// Save context to disk
    pub async fn save(&self) -> Result<()> {
        let path = Self::context_path().await?;
        let contents = toml::to_string_pretty(self).context("Could not serialize context")?;

        fs::write(&path, contents)
            .await
            .context("Could not write context file")?;

        Ok(())
    }

    /// Delete context file
    pub async fn clear() -> Result<()> {
        let path = Self::context_path().await?;

        if tokio::fs::try_exists(&path).await? {
            fs::remove_file(&path)
                .await
                .context("Could not delete context file")?;
        }

        Ok(())
    }
}

/// Helper function to set project context
pub async fn set_context_project(project_id: &str) -> Result<()> {
    let mut context = ContextConfig::load().await?;
    context.project_id = Some(project_id.to_string());
    context.save().await
}
