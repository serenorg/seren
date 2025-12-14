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
    pub fn from_env_for_command(command: &str) -> Result<Self> {
        let api_base_url =
            std::env::var("SEREN_API_URL").unwrap_or_else(|_| "https://api.serendb.com/api".into());

        let auth = match command {
            "start" | "start:http" => {
                let key = std::env::var("SEREN_API_KEY").map_err(|_| {
                    McpError::Config(format!("SEREN_API_KEY is required for {} mode", command))
                })?;
                AuthConfig::ApiKey(key)
            }
            "start:oauth" => {
                let database_url = std::env::var("MCP_DATABASE_URL").map_err(|_| {
                    McpError::Config("MCP_DATABASE_URL required for start:oauth mode".into())
                })?;
                let client_id = std::env::var("SEREN_OAUTH_CLIENT_ID").map_err(|_| {
                    McpError::Config("SEREN_OAUTH_CLIENT_ID required for start:oauth mode".into())
                })?;
                let server_host = std::env::var("MCP_SERVER_HOST").map_err(|_| {
                    McpError::Config("MCP_SERVER_HOST required for start:oauth mode".into())
                })?;

                AuthConfig::OAuth {
                    database_url,
                    client_id,
                    server_host,
                }
            }
            _ => return Err(McpError::Config(format!("Unknown command: {}", command))),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set_env(key: &str, value: Option<&str>) -> Option<String> {
        let old = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        old
    }

    fn restore_env(key: &str, old: Option<String>) {
        match old {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn start_requires_api_key() {
        let _guard = ENV_LOCK.lock().unwrap();

        let old_key = set_env("SEREN_API_KEY", None);
        let res = Config::from_env_for_command("start");
        assert!(matches!(res, Err(McpError::Config(_))));
        restore_env("SEREN_API_KEY", old_key);
    }

    #[test]
    fn start_builds_config_with_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();

        let old_key = set_env("SEREN_API_KEY", Some("test-key"));
        let old_host = set_env("HOST", None);
        let old_port = set_env("PORT", None);
        let old_url = set_env("SEREN_API_URL", None);

        let cfg = Config::from_env_for_command("start").unwrap();
        assert!(matches!(cfg.auth, AuthConfig::ApiKey(_)));
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.api_base_url, "https://api.serendb.com/api");

        restore_env("SEREN_API_KEY", old_key);
        restore_env("HOST", old_host);
        restore_env("PORT", old_port);
        restore_env("SEREN_API_URL", old_url);
    }

    #[test]
    fn start_oauth_requires_oauth_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap();

        let old_db = set_env("MCP_DATABASE_URL", None);
        let old_client = set_env("SEREN_OAUTH_CLIENT_ID", None);
        let old_host = set_env("MCP_SERVER_HOST", None);

        let res = Config::from_env_for_command("start:oauth");
        assert!(matches!(res, Err(McpError::Config(_))));

        restore_env("MCP_DATABASE_URL", old_db);
        restore_env("SEREN_OAUTH_CLIENT_ID", old_client);
        restore_env("MCP_SERVER_HOST", old_host);
    }

    #[test]
    fn start_oauth_builds_oauth_config() {
        let _guard = ENV_LOCK.lock().unwrap();

        let old_db = set_env("MCP_DATABASE_URL", Some("postgres://localhost/test"));
        let old_client = set_env("SEREN_OAUTH_CLIENT_ID", Some("client-id"));
        let old_host = set_env("MCP_SERVER_HOST", Some("mcp.serendb.com"));
        let old_url = set_env("SEREN_API_URL", Some("https://example.com/api"));

        let cfg = Config::from_env_for_command("start:oauth").unwrap();
        match cfg.auth {
            AuthConfig::OAuth {
                database_url,
                client_id,
                server_host,
            } => {
                assert_eq!(database_url, "postgres://localhost/test");
                assert_eq!(client_id, "client-id");
                assert_eq!(server_host, "mcp.serendb.com");
            }
            _ => panic!("expected OAuth config"),
        }
        assert_eq!(cfg.api_base_url, "https://example.com/api");

        restore_env("MCP_DATABASE_URL", old_db);
        restore_env("SEREN_OAUTH_CLIENT_ID", old_client);
        restore_env("MCP_SERVER_HOST", old_host);
        restore_env("SEREN_API_URL", old_url);
    }

    #[test]
    fn unknown_command_returns_error() {
        let res = Config::from_env_for_command("nope");
        assert!(matches!(res, Err(McpError::Config(_))));
    }
}
