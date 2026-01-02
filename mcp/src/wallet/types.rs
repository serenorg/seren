//! Wallet types and errors for x402 signing

// Allow unused - some variants are infrastructure for future use
#![allow(dead_code)]

use thiserror::Error;

/// Errors that can occur during wallet operations
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Invalid private key format")]
    InvalidPrivateKey,

    #[error("Wallet not configured (WALLET_PRIVATE_KEY not set)")]
    NotConfigured,

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}
