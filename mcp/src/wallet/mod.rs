//! Wallet module for x402 local signing
//!
//! This module provides private key management for signing x402 payments locally.
//! The private key never leaves the user's machine.
//!
//! ## Public API
//!
//! Types and functions are exported for future x402 payment integration:
//! - [`PrivateKeyWallet`] - Secure wallet wrapper
//! - [`SignerConfig`] - Auto-approve threshold configuration
//! - [`PaymentRequirements`] - Parse 402 response
//! - [`select_payment_method`] - Choose x402 vs prepaid
//! - [`build_x402_payment_payload`] - Create signed payment

// Allow unused exports - these are public API for x402 integration
#![allow(unused_imports)]

mod config;
mod payment;
mod privatekey;
mod signing;
mod types;

pub use config::{ConfigError, SignerConfig};
pub use payment::{
    PaymentError, PaymentMethod, PaymentOption, PaymentRequirements, UserCapabilities,
    X402Authorization, X402PayloadInner, X402PaymentOption, X402PaymentPayload,
    build_x402_payment_payload, select_payment_method,
};
pub use privatekey::PrivateKeyWallet;
pub use signing::{
    AuthorizationMessage, Eip712Domain, build_authorization_message, sign_transfer_authorization,
};
pub use types::WalletError;
