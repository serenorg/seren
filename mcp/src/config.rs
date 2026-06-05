use crate::error::{McpError, Result};
use std::path::PathBuf;

/// OAuth client ID for upstream authentication.
/// This identifies the MCP server as a trusted OAuth client.
const UPSTREAM_OAUTH_CLIENT_ID: &str = crate::MCP_SERVER_NAME;
const SEREN_PASSWORDS_PUBLISHER_SLUG: &str = "seren-passwords";

#[derive(Debug, Clone)]
pub struct Config {
    pub auth: AuthConfig,
    pub api_base_url: String,
    pub passwords_api_base_url: String,
    pub oauth_redirect_base_url: String,
    pub passwords_master_password_file: Option<PathBuf>,
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
        let api_base_url =
            std::env::var("API_URL").unwrap_or_else(|_| "https://api.serendb.com".into());
        let passwords_api_base_url = std::env::var("SEREN_PASSWORDS_API_URL")
            .map(|base_url| publisher_api_base_url(&base_url, SEREN_PASSWORDS_PUBLISHER_SLUG))
            .unwrap_or_else(|_| {
                publisher_api_base_url(&api_base_url, SEREN_PASSWORDS_PUBLISHER_SLUG)
            });
        let oauth_redirect_base_url =
            std::env::var("OAUTH_REDIRECT_URL").unwrap_or_else(|_| api_base_url.clone());

        let auth = match command {
            "start" | "start:http" => {
                let key = std::env::var("API_KEY").map_err(|_| {
                    McpError::Config(format!("API_KEY is required for {} mode", command))
                })?;
                AuthConfig::ApiKey(key)
            }
            "start:server" | "start:oauth" => {
                let database_url = std::env::var("DATABASE_URL").map_err(|_| {
                    McpError::Config("DATABASE_URL required for start:server mode".into())
                })?;
                let public_url = std::env::var("PUBLIC_URL").map_err(|_| {
                    McpError::Config("PUBLIC_URL required for start:server mode".into())
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
            passwords_api_base_url,
            oauth_redirect_base_url,
            passwords_master_password_file: None,
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".into())
                .parse()
                .map_err(|_| McpError::Config("Invalid PORT".into()))?,
        })
    }
}

fn publisher_api_base_url(api_base_url: &str, publisher_slug: &str) -> String {
    let publisher_prefix = format!("/publishers/{publisher_slug}");
    let trimmed = api_base_url.trim_end_matches('/');
    if trimmed.ends_with(&publisher_prefix) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{publisher_prefix}")
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
                ("SEREN_PASSWORDS_API_URL", None),
            ],
            || {
                let cfg = Config::from_env_for_command("start").unwrap();
                assert!(matches!(cfg.auth, AuthConfig::ApiKey(_)));
                assert_eq!(cfg.host, "0.0.0.0");
                assert_eq!(cfg.port, 3000);
                assert_eq!(cfg.api_base_url, "https://api.serendb.com");
                assert_eq!(
                    cfg.passwords_api_base_url,
                    "https://api.serendb.com/publishers/seren-passwords"
                );
            },
        );
    }

    #[test]
    fn start_default_passwords_api_url_does_not_duplicate_prefix() {
        temp_env::with_vars(
            [
                ("API_KEY", Some("test-key")),
                (
                    "API_URL",
                    Some("https://api.serendb.com/publishers/seren-passwords/"),
                ),
                ("SEREN_PASSWORDS_API_URL", None),
            ],
            || {
                let cfg = Config::from_env_for_command("start").unwrap();
                assert_eq!(
                    cfg.passwords_api_base_url,
                    "https://api.serendb.com/publishers/seren-passwords"
                );
            },
        );
    }

    #[test]
    fn start_configured_passwords_api_url_appends_publisher_prefix() {
        temp_env::with_vars(
            [
                ("API_KEY", Some("test-key")),
                ("API_URL", Some("http://internal-api.invalid")),
                ("SEREN_PASSWORDS_API_URL", Some("https://api.serendb.com/")),
            ],
            || {
                let cfg = Config::from_env_for_command("start").unwrap();
                assert_eq!(
                    cfg.passwords_api_base_url,
                    "https://api.serendb.com/publishers/seren-passwords"
                );
            },
        );
    }

    #[test]
    fn start_server_requires_database_env_vars() {
        temp_env::with_vars_unset(["DATABASE_URL", "PUBLIC_URL"], || {
            let res = Config::from_env_for_command("start:server");
            assert!(matches!(res, Err(McpError::Config(_))));
        });
    }

    #[test]
    fn start_server_builds_oauth_config() {
        temp_env::with_vars(
            [
                ("DATABASE_URL", Some("postgres://localhost/test")),
                ("PUBLIC_URL", Some("https://mcp.serendb.com")),
                ("API_URL", Some("http://internal-api.invalid")),
                (
                    "SEREN_PASSWORDS_API_URL",
                    Some("https://api.serendb.com/publishers/seren-passwords"),
                ),
            ],
            || {
                let cfg = Config::from_env_for_command("start:server").unwrap();
                match cfg.auth {
                    AuthConfig::OAuth {
                        database_url,
                        client_id,
                        public_url,
                    } => {
                        assert_eq!(database_url, "postgres://localhost/test");
                        assert_eq!(client_id, crate::MCP_SERVER_NAME);
                        assert_eq!(public_url, "https://mcp.serendb.com");
                    }
                    _ => panic!("expected OAuth config"),
                }
                assert_eq!(cfg.api_base_url, "http://internal-api.invalid");
                assert_eq!(
                    cfg.passwords_api_base_url,
                    "https://api.serendb.com/publishers/seren-passwords"
                );
            },
        );
    }

    #[test]
    fn start_oauth_legacy_alias_still_builds_oauth_config() {
        temp_env::with_vars(
            [
                ("DATABASE_URL", Some("postgres://localhost/test")),
                ("PUBLIC_URL", Some("https://mcp.serendb.com")),
            ],
            || {
                let cfg = Config::from_env_for_command("start:oauth").unwrap();
                assert!(matches!(cfg.auth, AuthConfig::OAuth { .. }));
            },
        );
    }

    #[test]
    fn unknown_command_returns_error() {
        let res = Config::from_env_for_command("nope");
        assert!(matches!(res, Err(McpError::Config(_))));
    }
}
