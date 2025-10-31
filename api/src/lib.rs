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
//!     let client = Client::new(config)?;
//!
//!     let projects = client.projects().list().await?;
//!     println!("Found {} projects", projects.len());
//!
//!     Ok(())
//! }
//! ```
#[allow(dead_code, clippy::all)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
 
 mod client;
 mod config;
 mod error;
 mod models;
 
 pub use client::Client;
 pub use config::ClientConfig;
 pub use error::{Error, Result};
 pub use models::*;
 
 // Re-export commonly used types
 pub mod prelude {
     pub use crate::{Client, ClientConfig, Error, Result};
 }
