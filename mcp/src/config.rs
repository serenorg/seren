use crate::error::{McpError, Result};

/// OAuth client ID for upstream authentication.
/// This identifies the MCP server as a trusted OAuth client.
const UPSTREAM_OAUTH_CLIENT_ID: &str = "seren-mcp";

#[derive(Debug, Clone)]
pub struct Config {
    pub auth: AuthConfig,
    pub api_base_url: String,
    pub oauth_redirect_base_url: String,
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
        public_url: String,
    },
}

impl Config {
    #[allow(clippy::result_large_err)]
    pub fn from_env_for_command(command: &str) -> Result<Self> {
        // Note: Do NOT include /api suffix - the generated API client already adds it
        let api_base_url =
            std::env::var("API_URL").unwrap_or_else(|_| "https://api.serendb.com".into());
        let oauth_redirect_base_url =
            std::env::var("OAUTH_REDIRECT_URL").unwrap_or_else(|_| api_base_url.clone());

        let auth = match command {
            "start" | "start:http" => {
                let key = std::env::var("API_KEY").map_err(|_| {
                    McpError::Config(format!("API_KEY is required for {} mode", command))
                })?;
                AuthConfig::ApiKey(key)
            }
            "start:oauth" => {
                let database_url = std::env::var("DATABASE_URL").map_err(|_| {
                    McpError::Config("DATABASE_URL required for start:oauth mode".into())
                })?;
                let public_url = std::env::var("PUBLIC_URL").map_err(|_| {
                    McpError::Config("PUBLIC_URL required for start:oauth mode".into())
                })?;

                AuthConfig::OAuth {
                    database_url,
                    client_id: UPSTREAM_OAUTH_CLIENT_ID.to_string(),
                    public_url,
                }
            }
            _ => return Err(McpError::Config(format!("Unknown command: {}", command))),
        };

        Ok(Self {
            auth,
            api_base_url,
            oauth_redirect_base_url,
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .map_err(|_| McpError::Config("Invalid PORT".into()))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requires_api_key() {
        temp_env::with_var_unset("API_KEY", || {
            let res = Config::from_env_for_command("start");
            assert!(matches!(res, Err(McpError::Config(_))));
        });
    }

    #[test]
    fn start_builds_config_with_defaults() {
        temp_env::with_vars(
            [
                ("API_KEY", Some("test-key")),
                ("HOST", None),
                ("PORT", None),
                ("API_URL", None),
            ],
            || {
                let cfg = Config::from_env_for_command("start").unwrap();
                assert!(matches!(cfg.auth, AuthConfig::ApiKey(_)));
                assert_eq!(cfg.host, "0.0.0.0");
                assert_eq!(cfg.port, 3000);
                assert_eq!(cfg.api_base_url, "https://api.serendb.com");
            },
        );
    }

    #[test]
    fn start_oauth_requires_oauth_env_vars() {
        temp_env::with_vars_unset(["DATABASE_URL", "PUBLIC_URL"], || {
            let res = Config::from_env_for_command("start:oauth");
            assert!(matches!(res, Err(McpError::Config(_))));
        });
    }

    #[test]
    fn start_oauth_builds_oauth_config() {
        temp_env::with_vars(
            [
                ("DATABASE_URL", Some("postgres://localhost/test")),
                ("PUBLIC_URL", Some("https://mcp.serendb.com")),
                ("API_URL", Some("https://example.com")),
            ],
            || {
                let cfg = Config::from_env_for_command("start:oauth").unwrap();
                match cfg.auth {
                    AuthConfig::OAuth {
                        database_url,
                        client_id,
                        public_url,
                    } => {
                        assert_eq!(database_url, "postgres://localhost/test");
                        assert_eq!(client_id, "seren-mcp");
                        assert_eq!(public_url, "https://mcp.serendb.com");
                    }
                    _ => panic!("expected OAuth config"),
                }
                assert_eq!(cfg.api_base_url, "https://example.com");
            },
        );
    }

    #[test]
    fn unknown_command_returns_error() {
        let res = Config::from_env_for_command("nope");
        assert!(matches!(res, Err(McpError::Config(_))));
    }
}
