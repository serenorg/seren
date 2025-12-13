use crate::error::{McpError, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub auth: AuthConfig,
    pub api_base_url: String,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// Local mode: direct API key authentication
    ApiKey(String),
    /// Hosted mode: OAuth2 with SerenDB token storage
    OAuth {
        database_url: String,
        client_id: String,
        server_host: String,
    },
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let api_base_url =
            std::env::var("SEREN_API_URL").unwrap_or_else(|_| "https://api.serendb.com/api".into());

        let auth = if let Ok(key) = std::env::var("SEREN_API_KEY") {
            AuthConfig::ApiKey(key)
        } else {
            let database_url = std::env::var("MCP_DATABASE_URL").map_err(|_| {
                McpError::Config(
                    "Set SEREN_API_KEY for local mode, or MCP_DATABASE_URL for hosted mode".into(),
                )
            })?;
            let client_id = std::env::var("SEREN_OAUTH_CLIENT_ID").map_err(|_| {
                McpError::Config("SEREN_OAUTH_CLIENT_ID required for hosted mode".into())
            })?;
            let server_host = std::env::var("MCP_SERVER_HOST")
                .map_err(|_| McpError::Config("MCP_SERVER_HOST required for hosted mode".into()))?;

            AuthConfig::OAuth {
                database_url,
                client_id,
                server_host,
            }
        };

        Ok(Self {
            auth,
            api_base_url,
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .map_err(|_| McpError::Config("Invalid PORT".into()))?,
        })
    }

    pub fn is_local_mode(&self) -> bool {
        matches!(self.auth, AuthConfig::ApiKey(_))
    }
}
