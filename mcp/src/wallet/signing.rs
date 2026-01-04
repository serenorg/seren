//! EIP-712 signing for x402 payments
//!
//! Implements signing for USDC transferWithAuthorization (EIP-3009).
//!
//! References:
//! - EIP-712: https://eips.ethereum.org/EIPS/eip-712
//! - EIP-3009: https://eips.ethereum.org/EIPS/eip-3009

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::signers::Signer;
use alloy::sol;
use alloy::sol_types::SolStruct;
use rand::Rng;

use super::{PrivateKeyWallet, WalletError};

// Define TransferWithAuthorization struct using sol! macro
// This auto-generates the EIP-712 type hash and encoding
sol! {
    /// EIP-3009 TransferWithAuthorization message
    #[derive(Debug, PartialEq)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// EIP-712 domain for signing
///
/// This wrapper allows dynamic domain construction from payment requirements.
/// For static domains, prefer using the `eip712_domain!` macro directly.
#[derive(Debug, Clone)]
pub struct Eip712Domain {
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<U256>,
    pub verifying_contract: Option<Address>,
}

impl Eip712Domain {
    /// Convert to alloy's Eip712Domain for use with SolStruct::eip712_signing_hash
    fn to_alloy_domain(&self) -> alloy::sol_types::Eip712Domain {
        alloy::sol_types::Eip712Domain {
            name: self.name.clone().map(std::borrow::Cow::Owned),
            version: self.version.clone().map(std::borrow::Cow::Owned),
            chain_id: self.chain_id,
            verifying_contract: self.verifying_contract,
            salt: None,
        }
    }
}

/// Build EIP-712 domain for USDC on a given chain
///
/// # Arguments
/// * `chain_id` - The chain ID (e.g., 8453 for Base)
/// * `usdc_address` - The USDC contract address on that chain
#[cfg(test)]
pub fn build_eip712_domain(chain_id: u64, usdc_address: &str) -> Eip712Domain {
    Eip712Domain {
        name: Some("USD Coin".to_string()),
        version: Some("2".to_string()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: usdc_address.parse().ok(),
    }
}

/// Authorization message for signing (public API wrapper)
#[derive(Debug, Clone)]
pub struct AuthorizationMessage {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: FixedBytes<32>,
}

impl AuthorizationMessage {
    /// Convert to the sol! generated struct for EIP-712 signing
    fn to_sol_struct(&self) -> TransferWithAuthorization {
        TransferWithAuthorization {
            from: self.from,
            to: self.to,
            value: self.value,
            validAfter: self.valid_after,
            validBefore: self.valid_before,
            nonce: self.nonce,
        }
    }
}

/// Build a TransferWithAuthorization message
///
/// # Arguments
/// * `from` - Sender address (must match signer)
/// * `to` - Recipient address
/// * `value` - Amount in smallest unit (e.g., USDC has 6 decimals, so 1 USDC = 1_000_000)
/// * `valid_after` - Unix timestamp after which the authorization is valid
/// * `valid_before` - Unix timestamp before which the authorization is valid
/// * `nonce` - Optional nonce; if None, generates random 32 bytes
pub fn build_authorization_message(
    from: &str,
    to: &str,
    value: &str,
    valid_after: u64,
    valid_before: u64,
    nonce: Option<FixedBytes<32>>,
) -> Result<AuthorizationMessage, WalletError> {
    let from_addr: Address = from
        .parse()
        .map_err(|_| WalletError::SigningFailed("Invalid 'from' address".into()))?;
    let to_addr: Address = to
        .parse()
        .map_err(|_| WalletError::SigningFailed("Invalid 'to' address".into()))?;
    let value_u256: U256 = value
        .parse()
        .map_err(|_| WalletError::SigningFailed("Invalid value".into()))?;

    let nonce = nonce.unwrap_or_else(generate_random_nonce);

    Ok(AuthorizationMessage {
        from: from_addr,
        to: to_addr,
        value: value_u256,
        valid_after: U256::from(valid_after),
        valid_before: U256::from(valid_before),
        nonce,
    })
}

/// Generate a random 32-byte nonce
pub fn generate_random_nonce() -> FixedBytes<32> {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    FixedBytes::from(bytes)
}

/// Sign a TransferWithAuthorization message using EIP-712
///
/// Uses alloy's built-in EIP-712 support via the sol! macro and SolStruct trait.
///
/// # Returns
/// The signature as a hex string with 0x prefix (65 bytes = 130 hex chars + 0x)
pub async fn sign_transfer_authorization(
    wallet: &PrivateKeyWallet,
    domain: &Eip712Domain,
    message: &AuthorizationMessage,
) -> Result<String, WalletError> {
    // Convert to alloy types
    let alloy_domain = domain.to_alloy_domain();
    let sol_message = message.to_sol_struct();

    // Use alloy's built-in EIP-712 signing hash computation
    // This handles all the encoding correctly (32-byte words, type hashes, etc.)
    let signing_hash = sol_message.eip712_signing_hash(&alloy_domain);

    // Sign the hash
    let signature = wallet
        .signer()
        .sign_hash(&signing_hash)
        .await
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    Ok(format!("0x{}", hex::encode(signature.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_domain_for_usdc_on_base() {
        let domain = build_eip712_domain(
            8453,                                         // Base mainnet chain ID
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
        );

        assert_eq!(domain.name, Some("USD Coin".into()));
        assert_eq!(domain.version, Some("2".into()));
        assert_eq!(domain.chain_id, Some(U256::from(8453u64)));
    }

    #[test]
    fn test_build_transfer_authorization_message() {
        let msg = build_authorization_message(
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", // from
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // to
            "1000000",                                    // 1 USDC (6 decimals)
            1704067200,                                   // validAfter
            1704153600,                                   // validBefore
            None,                                         // auto-generate nonce
        )
        .unwrap();

        assert_eq!(msg.value.to_string(), "1000000");
    }

    #[test]
    fn test_sol_struct_type_hash() {
        // Verify the sol! macro generates the correct type hash
        let expected_type_string = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
        let expected_hash = alloy::primitives::keccak256(expected_type_string.as_bytes());

        // Verify struct hash computation works
        let msg = TransferWithAuthorization {
            from: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse()
                .unwrap(),
            to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap(),
            value: U256::from(1000000u64),
            validAfter: U256::ZERO,
            validBefore: U256::MAX,
            nonce: FixedBytes::ZERO,
        };

        // This should not panic - verifies encoding works
        let _hash = msg.eip712_hash_struct();

        // Verify type hash matches expected
        assert_eq!(msg.eip712_type_hash(), expected_hash);
    }

    #[tokio::test]
    async fn test_sign_transfer_authorization() {
        // Use test wallet (Foundry default account #0)
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();

        let domain = build_eip712_domain(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let message = build_authorization_message(
            &wallet.address().to_string(),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "1000000",
            0,
            u64::MAX,
            None,
        )
        .unwrap();

        let signature = sign_transfer_authorization(&wallet, &domain, &message)
            .await
            .unwrap();

        // Signature should be 65 bytes (r: 32 + s: 32 + v: 1) as hex = 130 chars + 0x = 132
        assert!(signature.starts_with("0x"));
        assert_eq!(signature.len(), 132);
    }

    #[tokio::test]
    async fn test_signature_is_deterministic_for_same_inputs() {
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();

        let domain = build_eip712_domain(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");

        // Use fixed nonce for deterministic test
        let fixed_nonce = FixedBytes::from([1u8; 32]);

        let message = build_authorization_message(
            &wallet.address().to_string(),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "1000000",
            0,
            u64::MAX,
            Some(fixed_nonce),
        )
        .unwrap();

        let sig1 = sign_transfer_authorization(&wallet, &domain, &message)
            .await
            .unwrap();
        let sig2 = sign_transfer_authorization(&wallet, &domain, &message)
            .await
            .unwrap();

        assert_eq!(sig1, sig2, "Same inputs should produce same signature");
    }
}
