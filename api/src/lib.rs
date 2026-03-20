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
//!     let client = Client::from_config(&config)?;
//!
//!     let projects = client.list_projects(None, None, None).await?;
//!     println!("Found {} projects", projects.into_inner().data.len());
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
mod shared;

// Re-export the generated client and types
pub use generated::Client;
pub use generated::types::*;

// Re-export progenitor types used in return values
pub use progenitor_client::{ByteStream, Error, ResponseValue};

// Re-export our config
pub use config::ClientConfig;

// Re-export additional model types
pub use models::*;
pub use shared::*;

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

        let builder = reqwest::Client::builder().default_headers(headers);

        #[cfg(not(target_arch = "wasm32"))]
        let builder = {
            let mut builder =
                builder.timeout(std::time::Duration::from_secs(config.timeout_seconds));
            if !config.user_agent.trim().is_empty() {
                builder = builder.user_agent(config.user_agent.clone());
            }
            builder
        };

        let http_client = builder.build()?;

        Ok(Self::new_with_client(&config.base_url, http_client))
    }
}

// Re-export commonly used types
pub mod prelude {
    pub use crate::{Client, ClientConfig, Error, ResponseValue};
}
