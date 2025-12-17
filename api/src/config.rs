/// Default API host URL (production).
///
/// Local/development endpoints can be configured via [`ClientConfig::with_base_url`].
const DEFAULT_API_HOST: &str = "https://api.serendb.com";

/// Configuration for the Seren API client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Bearer token for authentication (API key or OAuth token)
    pub bearer_token: Option<String>,

    /// Base URL for the API (default: `https://api.serendb.com/api`)
    pub base_url: String,

    /// Request timeout in seconds (default: 60)
    pub timeout_seconds: u64,

    /// User agent for requests
    pub user_agent: String,
}

impl ClientConfig {
    /// Create a new client configuration with the given API key or bearer token
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            bearer_token: Some(token.into()),
            base_url: format!("{}/api", DEFAULT_API_HOST),
            timeout_seconds: 60,
            user_agent: format!("seren-api-rust/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// Create a client configuration without authentication
    pub fn unauthenticated() -> Self {
        Self {
            bearer_token: None,
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

    /// Set the bearer token
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::unauthenticated()
    }
}
