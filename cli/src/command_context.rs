use anyhow::Result;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use seren::{Client, ClientConfig};

use crate::OutputFormat;
use crate::commands::auth::get_bearer_token;
use crate::defaults;

/// Shared context for CLI command execution.
///
/// Contains common configuration that most commands need:
/// - API connection settings (host, authentication)
/// - Output format preferences
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub api_host: Option<String>,
    pub api_key: Option<String>,
    pub format: OutputFormat,
}

impl CommandContext {
    pub fn new(api_host: Option<String>, api_key: Option<String>, format: OutputFormat) -> Self {
        Self {
            api_host,
            api_key,
            format,
        }
    }

    /// Create an authenticated API client using this context's settings.
    pub async fn client(&self) -> Result<Client> {
        let bearer_token = get_bearer_token(self.api_key.clone()).await?;

        let mut client_config = ClientConfig::new(bearer_token);

        let base_url = match self.api_host.as_deref() {
            Some(host) => defaults::api_base_url(host),
            None => defaults::api_base_url(defaults::DEFAULT_API_HOST),
        };
        client_config = client_config.with_base_url(base_url);

        Client::from_config(&client_config)
            .map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
    }

    /// Get the API base URL for raw HTTP requests.
    pub fn api_base(&self) -> String {
        match self.api_host.as_deref() {
            Some(host) => defaults::api_base_url(host),
            None => defaults::api_base_url(defaults::DEFAULT_API_HOST),
        }
    }

    /// Create an authenticated reqwest client for raw HTTP requests.
    /// Use this for endpoints not covered by the SDK.
    pub async fn http_client(&self) -> Result<reqwest::Client> {
        let bearer_token = get_bearer_token(self.api_key.clone()).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))
                .map_err(|e| anyhow::anyhow!("Invalid bearer token: {}", e))?,
        );

        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))
    }
}
