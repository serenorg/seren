use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error: {status} - {message}")]
    Api { status: u16, message: String },

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Invalid API key format")]
    InvalidApiKey,

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Resource locked: {message}. Retry after {retry_after_ms}ms")]
    Locked {
        retry_after_ms: u64,
        message: String,
    },

    #[error("Rate limited: {message}. Retry after {retry_after_secs} seconds")]
    RateLimited {
        retry_after_secs: u64,
        message: String,
    },

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Server error ({status}): {message}")]
    ServerError { status: u16, message: String },
}

impl Error {
    /// Returns true if this error can be retried
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Locked { .. }
                | Error::RateLimited { .. }
                | Error::ServerError { .. }
                | Error::Http(_)
        )
    }
}
