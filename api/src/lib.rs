//! # Seren API Client
//!
//! Rust SDK for the Seren API, providing programmatic access to Seren database management.
//!
//! ## Example
//!
//! ```no_run
//! use seren::{Client, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ClientConfig::new("seren_your_api_key_here");
//!     let client = Client::new(&config)?;
//!
//!     let projects = client.list_projects(None, None).await?;
//!     println!("Found {} projects", projects.data.len());
//!
//!     Ok(())
//! }
//! ```

#[allow(dead_code, clippy::all, unused_imports)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

mod config;
mod models;

// Re-export the generated client and types
pub use generated::Client;
pub use generated::types::*;

// Re-export progenitor types used in return values
pub use progenitor_client::{ByteStream, Error, ResponseValue};

// Re-export our config
pub use config::ClientConfig;

// Re-export additional model types
pub use models::*;

/// Create a new authenticated client
impl Client {
    /// Create an authenticated client from a configuration
    pub fn from_config(config: &ClientConfig) -> Result<Self, reqwest::Error> {
        let mut headers = reqwest::header::HeaderMap::new();

        if let Some(ref token) = config.bearer_token {
            let auth_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                .expect("Invalid bearer token");
            headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        }

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self::new_with_client(&config.base_url, http_client))
    }
}

// Re-export commonly used types
pub mod prelude {
    pub use crate::{Client, ClientConfig, Error, ResponseValue};
}
