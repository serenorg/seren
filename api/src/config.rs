use crate::error::{Error, Result};

/// Configuration for the Seren API client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// API key for authentication (format: seren_...)
    pub api_key: String,

    /// Base URL for the API (default: https://api.seren.com)
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
            base_url: "http://localhost:3000/api/v1".to_string(), // TODO: Change to production URL
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
        if !self.api_key.starts_with("seren_") {
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
