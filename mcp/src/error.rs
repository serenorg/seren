use thiserror::Error;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("API error: {0}")]
    Api(#[from] seren::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("Transport error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, McpError>;
