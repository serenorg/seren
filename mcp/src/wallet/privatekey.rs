//! Private key wallet for local x402 signing
//!
//! SECURITY: This module handles sensitive cryptographic material.
//! - Private keys are NEVER logged
//! - Private keys are NEVER included in error messages
//! - Private keys are held in memory only for session duration

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use std::fmt;

use super::types::WalletError;

/// A wallet backed by a private key for signing x402 payments
#[derive(Clone)]
pub struct PrivateKeyWallet {
    signer: PrivateKeySigner,
}

// Custom Debug impl that doesn't expose the private key
impl fmt::Debug for PrivateKeyWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyWallet")
            .field("address", &self.signer.address())
            .finish_non_exhaustive()
    }
}

impl PrivateKeyWallet {
    /// Create a wallet from an optional private key string.
    ///
    /// Returns `Ok(None)` if no key is provided (x402 signing disabled).
    /// Returns `Ok(Some(wallet))` if key is valid.
    /// Returns `Err` if key is provided but invalid.
    ///
    /// # Arguments
    /// * `private_key` - Optional hex-encoded private key (with or without 0x prefix)
    ///
    /// # Security
    /// - The private key is NOT logged even on error
    /// - Callers should get this from WALLET_PRIVATE_KEY env var
    pub fn from_env_or_key(private_key: Option<String>) -> Result<Option<Self>, WalletError> {
        let key = match private_key {
            Some(k) => {
                let k = k.trim();
                if k.is_empty() {
                    return Ok(None);
                }
                k.to_string()
            }
            None => return Ok(None),
        };

        // Normalize: ensure 0x prefix
        let key_normalized = if key.starts_with("0x") || key.starts_with("0X") {
            key
        } else {
            format!("0x{}", key)
        };

        let signer: PrivateKeySigner = key_normalized
            .parse()
            .map_err(|_| WalletError::InvalidPrivateKey)?;

        Ok(Some(Self { signer }))
    }

    /// Get the wallet's Ethereum address
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Get a reference to the underlying signer (for EIP-712 signing)
    pub fn signer(&self) -> &PrivateKeySigner {
        &self.signer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_wallet_derives_correct_address() {
        // Known test vector - DO NOT use in production
        // This is Foundry's default test account #0
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let wallet = PrivateKeyWallet::from_env_or_key(Some(private_key.to_string()))
            .unwrap()
            .unwrap();

        assert_eq!(
            wallet.address().to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn test_private_key_wallet_without_0x_prefix() {
        let private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let wallet = PrivateKeyWallet::from_env_or_key(Some(private_key.to_string()))
            .unwrap()
            .unwrap();

        assert_eq!(
            wallet.address().to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn test_private_key_wallet_rejects_invalid_key() {
        let result = PrivateKeyWallet::from_env_or_key(Some("not_a_valid_key".to_string()));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WalletError::InvalidPrivateKey
        ));
    }

    #[test]
    fn test_private_key_wallet_returns_none_when_no_key() {
        let result = PrivateKeyWallet::from_env_or_key(None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_private_key_wallet_returns_none_for_empty_string() {
        let result = PrivateKeyWallet::from_env_or_key(Some("".to_string()));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_wallet_debug_hides_private_key() {
        let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let wallet = PrivateKeyWallet::from_env_or_key(Some(private_key.to_string()))
            .unwrap()
            .unwrap();

        let debug_output = format!("{:?}", wallet);

        // Should NOT contain the private key
        assert!(
            !debug_output
                .contains("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
            "Debug output should not contain private key"
        );

        // Should contain the address (public info)
        assert!(
            debug_output
                .to_lowercase()
                .contains("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            "Debug output should contain wallet address"
        );
    }
}
