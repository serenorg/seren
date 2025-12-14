use anyhow::Result;
use seren::{Client, ClientConfig};

use crate::OutputFormat;
use crate::commands::auth::get_bearer_token;

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

        if let Some(host) = &self.api_host {
            client_config = client_config.with_base_url(host.clone());
        }

        Client::new(client_config)
            .map_err(|e| anyhow::anyhow!("Failed to create API client: {}", e))
    }
}
