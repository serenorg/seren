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
        server_host: String,
    },
}

impl Config {
    pub fn from_env_for_command(command: &str) -> Result<Self> {
        let api_base_url =
            std::env::var("SEREN_API_URL").unwrap_or_else(|_| "https://api.serendb.com/api".into());
        let oauth_redirect_base_url =
            std::env::var("SEREN_OAUTH_REDIRECT_BASE_URL").unwrap_or_else(|_| api_base_url.clone());

        let auth = match command {
            "start" | "start:http" => {
                let key = std::env::var("SEREN_API_KEY").map_err(|_| {
                    McpError::Config(format!("SEREN_API_KEY is required for {} mode", command))
                })?;
                AuthConfig::ApiKey(key)
            }
            "start:oauth" => {
                let database_url = std::env::var("DATABASE_URL").map_err(|_| {
                    McpError::Config("DATABASE_URL required for start:oauth mode".into())
                })?;
                let server_host = std::env::var("MCP_SERVER_HOST").map_err(|_| {
                    McpError::Config("MCP_SERVER_HOST required for start:oauth mode".into())
                })?;

                AuthConfig::OAuth {
                    database_url,
                    client_id: UPSTREAM_OAUTH_CLIENT_ID.to_string(),
                    server_host,
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
        temp_env::with_var_unset("SEREN_API_KEY", || {
            let res = Config::from_env_for_command("start");
            assert!(matches!(res, Err(McpError::Config(_))));
        });
    }

    #[test]
    fn start_builds_config_with_defaults() {
        temp_env::with_vars(
            [
                ("SEREN_API_KEY", Some("test-key")),
                ("HOST", None),
                ("PORT", None),
                ("SEREN_API_URL", None),
            ],
            || {
                let cfg = Config::from_env_for_command("start").unwrap();
                assert!(matches!(cfg.auth, AuthConfig::ApiKey(_)));
                assert_eq!(cfg.host, "0.0.0.0");
                assert_eq!(cfg.port, 3000);
                assert_eq!(cfg.api_base_url, "https://api.serendb.com/api");
            },
        );
    }

    #[test]
    fn start_oauth_requires_oauth_env_vars() {
        temp_env::with_vars_unset(["DATABASE_URL", "MCP_SERVER_HOST"], || {
            let res = Config::from_env_for_command("start:oauth");
            assert!(matches!(res, Err(McpError::Config(_))));
        });
    }

    #[test]
    fn start_oauth_builds_oauth_config() {
        temp_env::with_vars(
            [
                ("DATABASE_URL", Some("postgres://localhost/test")),
                ("MCP_SERVER_HOST", Some("mcp.serendb.com")),
                ("SEREN_API_URL", Some("https://example.com/api")),
            ],
            || {
                let cfg = Config::from_env_for_command("start:oauth").unwrap();
                match cfg.auth {
                    AuthConfig::OAuth {
                        database_url,
                        client_id,
                        server_host,
                    } => {
                        assert_eq!(database_url, "postgres://localhost/test");
                        assert_eq!(client_id, "seren-mcp");
                        assert_eq!(server_host, "mcp.serendb.com");
                    }
                    _ => panic!("expected OAuth config"),
                }
                assert_eq!(cfg.api_base_url, "https://example.com/api");
            },
        );
    }

    #[test]
    fn unknown_command_returns_error() {
        let res = Config::from_env_for_command("nope");
        assert!(matches!(res, Err(McpError::Config(_))));
    }
}
