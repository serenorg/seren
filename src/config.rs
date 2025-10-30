use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub api_key: String,
}

impl Config {
    /// Get the path to the config file
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("seren");

        fs::create_dir_all(&config_dir)
            .context("Could not create config directory")?;

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

        let contents = fs::read_to_string(&path)
            .context("Could not read config file")?;
        
        toml::from_str(&contents)
            .context("Could not parse config file")
    }

    /// Save config to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let contents = toml::to_string_pretty(self)
            .context("Could not serialize config")?;
        
        fs::write(&path, contents)
            .context("Could not write config file")?;
        
        println!("✓ Credentials saved to {}", path.display());
        
        Ok(())
    }

    /// Delete config file
    pub fn delete() -> Result<()> {
        let path = Self::config_path()?;
        
        if path.exists() {
            fs::remove_file(&path)
                .context("Could not delete config file")?;
            println!("✓ Credentials removed from {}", path.display());
        } else {
            println!("No credentials found");
        }
        
        Ok(())
    }
}
