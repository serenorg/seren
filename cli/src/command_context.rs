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

    pub async fn require_user_session(&self, operation: &str) -> Result<()> {
        let bearer_token = get_bearer_token(self.api_key.clone()).await?;
        if bearer_token.starts_with("seren_") {
            anyhow::bail!(
                "{operation} requires an interactive OAuth user session. Run `seren auth login` and choose browser login; API keys cannot carry user approval authority."
            );
        }
        Ok(())
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
        self.http_client_with_redirect(reqwest::redirect::Policy::default())
            .await
    }

    /// Create an authenticated reqwest client for raw HTTP requests with a custom redirect policy.
    /// Use this for endpoints not covered by the SDK.
    pub async fn http_client_with_redirect(
        &self,
        redirect_policy: reqwest::redirect::Policy,
    ) -> Result<reqwest::Client> {
        let bearer_token = get_bearer_token(self.api_key.clone()).await?;

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))
                .map_err(|e| anyhow::anyhow!("Invalid bearer token: {}", e))?,
        );

        reqwest::Client::builder()
            .default_headers(headers)
            .redirect(redirect_policy)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))
    }

    /// Create an authenticated reqwest client with redirects disabled.
    ///
    /// Useful when the API endpoint intentionally returns 3xx (e.g. OAuth authorize redirect)
    /// and the caller needs to inspect the Location header.
    pub async fn http_client_no_redirect(&self) -> Result<reqwest::Client> {
        self.http_client_with_redirect(reqwest::redirect::Policy::none())
            .await
    }
}
