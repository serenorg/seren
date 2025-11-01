use crate::error::{Error, Result};

/// Default API base URL
///
/// Automatically selected based on build profile:
/// - Debug builds (`cargo build`): http://localhost:8080
/// - Release builds (`cargo build --release`): https://api.serendb.com
const DEFAULT_API_HOST: &str = if cfg!(debug_assertions) {
    "http://localhost:8080"
} else {
    "https://api.serendb.com"
};

/// Configuration for the Seren API client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// API key for authentication (format: seren_...)
    pub api_key: String,

    /// Base URL for the API (default: set at compile-time via build profile)
    pub base_url: String,

    /// Request timeout in seconds (default: 60)
    pub timeout_seconds: u64,

    /// User agent for requests
    pub user_agent: String,
}

impl ClientConfig {
    /// Create a new client configuration with the given API key
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: format!("{}/api", DEFAULT_API_HOST),
            timeout_seconds: 60,
            user_agent: format!("seren-api-rust/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Set a custom base URL
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set a custom timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Validate the API key format
    pub fn validate(&self) -> Result<()> {
        // Accept either API keys (seren_...) or OAuth bearer tokens (JWT format)
        // JWT tokens have 3 parts separated by dots
        let is_api_key = self.api_key.starts_with("seren_");
        let is_jwt = self.api_key.matches('.').count() == 2 && !self.api_key.is_empty();
        
        if !is_api_key && !is_jwt {
            return Err(Error::InvalidApiKey);
        }
        Ok(())
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new("")
    }
}
