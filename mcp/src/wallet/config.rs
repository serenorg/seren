//! Signer configuration for x402 local signing
//!
//! Config file location:
//! - Linux/macOS: `~/.config/seren-mcp/signer.toml` (XDG, respects $XDG_CONFIG_HOME)
//! - Windows: `%APPDATA%\seren-mcp\signer.toml`
//!
//! Auto-created with defaults on first use.

// Allow unused - some methods are infrastructure for future integration
#![allow(dead_code)]

use etcetera::base_strategy::{BaseStrategy, Xdg, choose_native_strategy};
use serde::{Deserialize, Serialize, de};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::money::{parse_usd_to_micros, usd_f64_to_micros};

/// Signer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerConfig {
    /// Auto-approve payments under this amount (in USD)
    /// Payments above this threshold will prompt for confirmation
    /// Set to 0 to always prompt for confirmation
    #[serde(
        default = "default_auto_approve_limit_micros",
        rename = "auto_approve_limit",
        deserialize_with = "deserialize_auto_approve_limit_usd_to_micros"
    )]
    pub auto_approve_limit_micros: i64,
}

fn default_auto_approve_limit_micros() -> i64 {
    // $0.10 expressed as micro-USD (x402 atomic units).
    100_000
}

fn deserialize_auto_approve_limit_usd_to_micros<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct V;

    impl<'de> de::Visitor<'de> for V {
        type Value = i64;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "a USD amount as string (e.g. \"0.10\") or number (e.g. 0.10)"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_usd_to_micros(v).map_err(de::Error::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            usd_f64_to_micros(v).map_err(de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v < 0 {
                return Err(de::Error::custom("Amount must be non-negative"));
            }
            v.checked_mul(1_000_000)
                .ok_or_else(|| de::Error::custom("Amount is too large"))
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let v: i64 = v
                .try_into()
                .map_err(|_| de::Error::custom("Amount is too large"))?;
            v.checked_mul(1_000_000)
                .ok_or_else(|| de::Error::custom("Amount is too large"))
        }
    }

    deserializer.deserialize_any(V)
}

impl Default for SignerConfig {
    fn default() -> Self {
        Self {
            auto_approve_limit_micros: default_auto_approve_limit_micros(),
        }
    }
}

impl SignerConfig {
    /// Get the default config file path using platform-appropriate directories.
    ///
    /// Uses XDG base directories on Linux/macOS (~/.config, respects $XDG_CONFIG_HOME),
    /// and native Windows paths (%APPDATA%).
    pub fn default_path() -> Option<PathBuf> {
        #[cfg(windows)]
        {
            choose_native_strategy().ok().map(|strategy| {
                strategy
                    .config_dir()
                    .join(crate::MCP_SERVER_NAME)
                    .join("signer.toml")
            })
        }
        #[cfg(not(windows))]
        {
            Xdg::new().ok().map(|strategy| {
                strategy
                    .config_dir()
                    .join(crate::MCP_SERVER_NAME)
                    .join("signer.toml")
            })
        }
    }

    /// Load config from the default path, creating it with defaults if it doesn't exist
    pub fn load_or_create() -> Self {
        let path = match Self::default_path() {
            Some(p) => p,
            None => {
                warn!("Could not determine config directory, using default signer config");
                return Self::default();
            }
        };

        if path.exists() {
            match Self::load_from_path(&path) {
                Ok(config) => config,
                Err(e) => {
                    warn!(
                        "Failed to load signer config from {:?}: {}, using defaults",
                        path, e
                    );
                    Self::default()
                }
            }
        } else {
            // Create default config
            if let Err(e) = Self::create_default_at(&path) {
                warn!(
                    "Failed to create default signer config at {:?}: {}",
                    path, e
                );
            } else {
                info!("Created default signer config at {:?}", path);
            }
            Self::default()
        }
    }

    /// Load config from a specific path
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let contents =
            fs::read_to_string(path).map_err(|e| ConfigError::ReadFailed(e.to_string()))?;

        toml::from_str(&contents).map_err(|e| ConfigError::ParseFailed(e.to_string()))
    }

    /// Create a default config file at the given path
    fn create_default_at(path: &Path) -> Result<(), ConfigError> {
        // Ensure parent directory exists with restrictive permissions
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::WriteFailed(e.to_string()))?;

            // Set directory permissions to 700 (owner only) on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o700);
                let _ = fs::set_permissions(parent, perms); // Best effort
            }
        }

        let default_content = r#"# Seren Local Signer Configuration
#
# This file configures x402 payment signing behavior.
# For documentation, see: https://docs.serendb.com/mcp/x402-signing

# Auto-approve payments under this amount (in USD)
# Payments above this threshold will prompt for confirmation
# Set to 0 to always prompt for confirmation
auto_approve_limit = "0.10"
"#;

        fs::write(path, default_content).map_err(|e| ConfigError::WriteFailed(e.to_string()))?;

        // Set file permissions to 600 (owner read/write only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(path, perms); // Best effort
        }

        Ok(())
    }

    /// Check if a payment amount should be auto-approved
    ///
    /// # Arguments
    /// * `amount_micros` - Payment amount in micro-USD (x402 atomic units; 1 USD = 1_000_000)
    ///
    /// # Returns
    /// `true` if amount is at or below the auto-approve limit
    pub fn should_auto_approve(&self, amount_micros: i64) -> bool {
        // If limit is 0, never auto-approve (always prompt)
        if self.auto_approve_limit_micros == 0 {
            return false;
        }
        if amount_micros < 0 {
            return false;
        }
        amount_micros <= self.auto_approve_limit_micros
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)] // Intentional naming pattern
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadFailed(String),

    #[error("Failed to parse config file: {0}")]
    ParseFailed(String),

    #[error("Failed to write config file: {0}")]
    WriteFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = SignerConfig::default();
        assert_eq!(config.auto_approve_limit_micros, 100_000);
    }

    #[test]
    fn test_load_config_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "auto_approve_limit = 0.50").unwrap();

        let config = SignerConfig::load_from_path(file.path()).unwrap();
        assert_eq!(config.auto_approve_limit_micros, 500_000);
    }

    #[test]
    fn test_load_config_from_file_accepts_string_amount() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "auto_approve_limit = \"0.125\"").unwrap();

        let config = SignerConfig::load_from_path(file.path()).unwrap();
        assert_eq!(config.auto_approve_limit_micros, 125_000);
    }

    #[test]
    fn test_config_auto_approve_check() {
        let config = SignerConfig {
            auto_approve_limit_micros: 100_000,
        };

        assert!(config.should_auto_approve(50_000)); // Under limit
        assert!(config.should_auto_approve(100_000)); // At limit
        assert!(!config.should_auto_approve(110_000)); // Over limit
        assert!(!config.should_auto_approve(1_000_000)); // Way over
    }

    #[test]
    fn test_config_zero_limit_always_prompts() {
        let config = SignerConfig {
            auto_approve_limit_micros: 0,
        };

        assert!(!config.should_auto_approve(1)); // Even tiny amounts need approval
        assert!(!config.should_auto_approve(0)); // Even zero needs approval (edge case)
    }
}
