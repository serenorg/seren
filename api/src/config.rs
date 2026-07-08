/// Default API host URL (production).
///
/// Local/development endpoints can be configured via [`ClientConfig::with_base_url`].
const DEFAULT_API_HOST: &str = "https://api.serendb.com";

fn normalize_base_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

fn default_user_agent() -> String {
    format!("seren-rust/{}", env!("CARGO_PKG_VERSION"))
}

/// Configuration for the Seren API client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Bearer token for authentication (API key or OAuth token)
    pub bearer_token: Option<String>,

    /// Base URL for the API (default: `https://api.serendb.com`)
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
            base_url: DEFAULT_API_HOST.to_string(),
            timeout_seconds: 60,
            user_agent: default_user_agent(),
        }
    }

    /// Create a client configuration without authentication
    pub fn unauthenticated() -> Self {
        Self {
            bearer_token: None,
            base_url: DEFAULT_API_HOST.to_string(),
            timeout_seconds: 60,
            user_agent: default_user_agent(),
        }
    }

    /// Create a client configuration from the environment.
    ///
    /// Reads `SEREN_API_KEY` for the bearer token and `SEREN_API_BASE` for the
    /// base URL, matching the `@serendb/sdk` and `seren-python` defaults. Both
    /// values are optional: a missing or empty `SEREN_API_KEY` yields an
    /// unauthenticated configuration, and a missing `SEREN_API_BASE` falls back
    /// to the production host.
    pub fn from_env() -> Self {
        let bearer_token = std::env::var("SEREN_API_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let base_url = std::env::var("SEREN_API_BASE")
            .ok()
            .map(|value| normalize_base_url(&value))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_API_HOST.to_string());
        Self {
            bearer_token,
            base_url,
            timeout_seconds: 60,
            user_agent: default_user_agent(),
        }
    }

    /// Set a custom base URL
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = normalize_base_url(&url.into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVar {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // Tests serialize environment access through ENV_LOCK.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            // Tests serialize environment access through ENV_LOCK.
            unsafe {
                if let Some(value) = &self.previous {
                    std::env::set_var(self.key, value);
                } else {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn from_env_reads_key_and_base_url() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _api_key = EnvVar::set("SEREN_API_KEY", "  seren_test  ");
        let _api_base = EnvVar::set("SEREN_API_BASE", "https://api.example.test/");

        let config = ClientConfig::from_env();

        assert_eq!(config.bearer_token.as_deref(), Some("seren_test"));
        assert_eq!(config.base_url, "https://api.example.test");
        assert_eq!(config.timeout_seconds, 60);
        assert!(config.user_agent.starts_with("seren-rust/"));
    }

    #[test]
    fn from_env_allows_missing_or_empty_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _api_key = EnvVar::set("SEREN_API_KEY", "  ");
        let _api_base = EnvVar::set("SEREN_API_BASE", "  ");

        let config = ClientConfig::from_env();

        assert_eq!(config.bearer_token, None);
        assert_eq!(config.base_url, DEFAULT_API_HOST);
    }
}
