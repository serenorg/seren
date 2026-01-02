//! EIP-712 signing for x402 payments
//!
//! Implements signing for USDC transferWithAuthorization (EIP-3009).
//!
//! References:
//! - EIP-712: https://eips.ethereum.org/EIPS/eip-712
//! - EIP-3009: https://eips.ethereum.org/EIPS/eip-3009

use alloy::primitives::{Address, FixedBytes, U256, keccak256};
use alloy::signers::Signer;
use rand::Rng;

use super::{PrivateKeyWallet, WalletError};

/// EIP-712 domain for signing
#[derive(Debug, Clone)]
pub struct Eip712Domain {
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<U256>,
    pub verifying_contract: Option<Address>,
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

/// Authorization message for signing
#[derive(Debug, Clone)]
pub struct AuthorizationMessage {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub valid_after: U256,
    pub valid_before: U256,
    pub nonce: FixedBytes<32>,
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
/// # Returns
/// The signature as a hex string with 0x prefix (65 bytes = 130 hex chars + 0x)
pub async fn sign_transfer_authorization(
    wallet: &PrivateKeyWallet,
    domain: &Eip712Domain,
    message: &AuthorizationMessage,
) -> Result<String, WalletError> {
    // Build the EIP-712 typed data hash
    let domain_separator = compute_domain_separator(domain);
    let struct_hash = compute_struct_hash(message);

    // EIP-712: hash = keccak256("\x19\x01" || domainSeparator || structHash)
    let mut digest_input = Vec::with_capacity(2 + 32 + 32);
    digest_input.extend_from_slice(&[0x19, 0x01]);
    digest_input.extend_from_slice(domain_separator.as_slice());
    digest_input.extend_from_slice(struct_hash.as_slice());
    let digest = keccak256(&digest_input);

    // Sign the digest
    let signature = wallet
        .signer()
        .sign_hash(&digest)
        .await
        .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

    Ok(format!("0x{}", hex::encode(signature.as_bytes())))
}

/// Compute EIP-712 domain separator
fn compute_domain_separator(domain: &Eip712Domain) -> FixedBytes<32> {
    let type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );

    let name_hash = keccak256(domain.name.as_deref().unwrap_or(""));
    let version_hash = keccak256(domain.version.as_deref().unwrap_or(""));

    let mut encoded = Vec::new();
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(name_hash.as_slice());
    encoded.extend_from_slice(version_hash.as_slice());
    encoded.extend_from_slice(&domain.chain_id.unwrap_or_default().to_be_bytes::<32>());
    encoded.extend_from_slice(
        domain
            .verifying_contract
            .unwrap_or_default()
            .into_word()
            .as_slice(),
    );

    keccak256(&encoded)
}

/// Compute EIP-712 struct hash for TransferWithAuthorization
fn compute_struct_hash(msg: &AuthorizationMessage) -> FixedBytes<32> {
    let type_hash = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );

    let mut encoded = Vec::new();
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(msg.from.into_word().as_slice());
    encoded.extend_from_slice(msg.to.into_word().as_slice());
    encoded.extend_from_slice(&msg.value.to_be_bytes::<32>());
    encoded.extend_from_slice(&msg.valid_after.to_be_bytes::<32>());
    encoded.extend_from_slice(&msg.valid_before.to_be_bytes::<32>());
    encoded.extend_from_slice(msg.nonce.as_slice());

    keccak256(&encoded)
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
}
