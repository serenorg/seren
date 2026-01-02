//! Payment method detection and selection for x402
//!
//! Parses 402 responses and determines the best payment method.
//!
//! This module provides infrastructure for x402 payment integration.
//! Types are used in tests and will be used in future tool integration.

// Allow unused - infrastructure for x402 integration
#![allow(dead_code)]

use alloy::primitives::{FixedBytes, U256};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    Eip712Domain, PrivateKeyWallet, build_authorization_message, sign_transfer_authorization,
};

/// Parsed payment requirements from a 402 response
#[derive(Debug, Clone)]
pub struct PaymentRequirements {
    pub x402_version: Option<u8>,
    pub resource: Option<X402ResourceInfo>,
    pub accepts: Vec<PaymentOption>,
    pub insufficient_credit: Option<InsufficientCredit>,
}

#[derive(Debug, Clone)]
pub enum PaymentOption {
    X402(X402PaymentOption),
    Prepaid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402ResourceInfo {
    pub url: String,
    pub description: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentOption {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    pub amount: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct InsufficientCredit {
    pub minimum_required: String,
    pub current_balance: String,
}

/// Raw 402 response for parsing
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawPaymentResponse {
    X402 {
        #[serde(rename = "x402Version")]
        x402_version: u8,
        #[serde(default)]
        resource: Option<X402ResourceInfo>,
        accepts: Vec<X402PaymentOption>,
    },
    InsufficientCredit {
        #[allow(dead_code)]
        error: String,
        #[serde(rename = "minimumRequired")]
        minimum_required: String,
        #[serde(rename = "currentBalance")]
        current_balance: String,
    },
}

impl PaymentRequirements {
    fn from_raw(raw: RawPaymentResponse) -> Result<Self, PaymentError> {
        match raw {
            RawPaymentResponse::X402 {
                x402_version,
                resource,
                accepts,
            } => Ok(Self {
                x402_version: Some(x402_version),
                resource,
                accepts: accepts.into_iter().map(PaymentOption::X402).collect(),
                insufficient_credit: None,
            }),
            RawPaymentResponse::InsufficientCredit {
                minimum_required,
                current_balance,
                ..
            } => Ok(Self {
                x402_version: None,
                resource: None,
                accepts: vec![PaymentOption::Prepaid],
                insufficient_credit: Some(InsufficientCredit {
                    minimum_required,
                    current_balance,
                }),
            }),
        }
    }

    /// Parse a 402 response body into payment requirements
    pub fn parse(body: &str) -> Result<Self, PaymentError> {
        let raw: RawPaymentResponse =
            serde_json::from_str(body).map_err(|e| PaymentError::ParseFailed(e.to_string()))?;

        Self::from_raw(raw)
    }

    /// Parse a base64-encoded x402 `PAYMENT-REQUIRED` header into payment requirements.
    pub fn parse_payment_required_header(header_b64: &str) -> Result<Self, PaymentError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header_b64.trim())
            .map_err(|e| PaymentError::ParseFailed(format!("Invalid PAYMENT-REQUIRED: {}", e)))?;
        let raw: RawPaymentResponse = serde_json::from_slice(&decoded)
            .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;
        Self::from_raw(raw)
    }

    /// Check if x402 on-chain payment is accepted
    pub fn accepts_x402(&self) -> bool {
        self.accepts
            .iter()
            .any(|a| matches!(a, PaymentOption::X402(_)))
    }

    /// Check if this is an insufficient credit error
    pub fn is_insufficient_credit(&self) -> bool {
        self.insufficient_credit.is_some()
    }

    /// Get the first x402 payment option if available
    pub fn x402_option(&self) -> Option<&X402PaymentOption> {
        self.accepts.iter().find_map(|a| match a {
            PaymentOption::X402(opt) => Some(opt),
            _ => None,
        })
    }
}

/// User's payment capabilities
#[derive(Debug, Clone)]
pub struct UserCapabilities {
    pub has_wallet: bool,
    pub wallet_address: Option<String>,
    pub has_prepaid: bool,
}

/// Selected payment method
#[derive(Debug, Clone)]
pub enum PaymentMethod {
    X402 {
        option: X402PaymentOption,
        wallet_address: String,
    },
    Prepaid,
}

/// Select the best payment method based on requirements and user capabilities
///
/// Priority: x402 > prepaid (as specified in design doc)
pub fn select_payment_method(
    requirements: &PaymentRequirements,
    user: &UserCapabilities,
) -> Option<PaymentMethod> {
    // Try x402 first if available and user has wallet
    if let Some(x402_opt) = requirements.x402_option()
        && user.has_wallet
        && let Some(ref addr) = user.wallet_address
    {
        return Some(PaymentMethod::X402 {
            option: x402_opt.clone(),
            wallet_address: addr.clone(),
        });
    }

    // Fall back to prepaid if available
    if user.has_prepaid
        && requirements
            .accepts
            .iter()
            .any(|a| matches!(a, PaymentOption::Prepaid))
    {
        return Some(PaymentMethod::Prepaid);
    }

    // Prepaid is always available as a fallback for x402-only publishers
    // if user has prepaid balance (even if not explicitly in accepts)
    if user.has_prepaid && !requirements.is_insufficient_credit() {
        return Some(PaymentMethod::Prepaid);
    }

    None
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("Failed to parse payment requirements: {0}")]
    ParseFailed(String),

    #[error("No payment method available")]
    NoPaymentMethod,

    #[error("Insufficient balance: need {required}, have {available}")]
    InsufficientBalance { required: String, available: String },

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// Complete x402 payment payload ready for submission
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentPayload {
    pub x402_version: u8,
    pub resource: X402ResourceInfo,
    pub accepted: X402PaymentOption,
    pub payload: X402PayloadInner,
}

#[derive(Debug, Clone, Serialize)]
pub struct X402PayloadInner {
    pub signature: String,
    pub authorization: X402Authorization,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Authorization {
    pub from: String,
    pub to: String,
    pub value: String,
    pub valid_after: String,
    pub valid_before: String,
    pub nonce: String,
}

/// Build a complete x402 payment payload
pub async fn build_x402_payment_payload(
    wallet: &PrivateKeyWallet,
    requirements: &PaymentRequirements,
    option: &X402PaymentOption,
) -> Result<X402PaymentPayload, PaymentError> {
    let from_address = wallet.address().to_string();
    let resource = requirements.resource.clone().ok_or_else(|| {
        PaymentError::ParseFailed("Missing x402 resource info in 402 response".to_string())
    })?;

    let chain_id = option
        .network
        .strip_prefix("eip155:")
        .and_then(|id| id.parse::<u64>().ok())
        .ok_or_else(|| {
            PaymentError::SigningFailed(format!(
                "Unsupported network for EIP-3009 signing: {}",
                option.network
            ))
        })?;

    let verifying_contract = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("domain"))
        .and_then(|v| v.get("verifyingContract"))
        .and_then(|v| v.as_str())
        .unwrap_or(&option.asset);

    let domain_name = option
        .extra
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| {
            option
                .extra
                .get("eip712TypedData")
                .and_then(|v| v.get("domain"))
                .and_then(|v| v.get("name"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("USD Coin");

    let domain_version = option
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .or_else(|| {
            option
                .extra
                .get("eip712TypedData")
                .and_then(|v| v.get("domain"))
                .and_then(|v| v.get("version"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("2");

    // Calculate validity window
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PaymentError::ParseFailed(e.to_string()))?
        .as_secs();
    let valid_after = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.get("validAfter"))
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| now.saturating_sub(60));
    let valid_before = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.get("validBefore"))
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or_else(|| now + option.max_timeout_seconds);

    let nonce = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.get("nonce"))
        .and_then(|v| v.as_str())
        .and_then(|nonce| {
            let hex_str = nonce.strip_prefix("0x").unwrap_or(nonce);
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(FixedBytes::from(arr))
        });

    let domain = Eip712Domain {
        name: Some(domain_name.to_string()),
        version: Some(domain_version.to_string()),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: verifying_contract.parse().ok(),
    };
    let message = build_authorization_message(
        &from_address,
        &option.pay_to,
        &option.amount,
        valid_after,
        valid_before,
        nonce,
    )
    .map_err(|e| PaymentError::SigningFailed(e.to_string()))?;

    // Sign
    let signature = sign_transfer_authorization(wallet, &domain, &message)
        .await
        .map_err(|e| PaymentError::SigningFailed(e.to_string()))?;

    Ok(X402PaymentPayload {
        x402_version: 2,
        resource,
        accepted: option.clone(),
        payload: X402PayloadInner {
            signature,
            authorization: X402Authorization {
                from: from_address,
                to: option.pay_to.clone(),
                value: option.amount.clone(),
                valid_after: valid_after.to_string(),
                valid_before: valid_before.to_string(),
                nonce: format!("0x{}", hex::encode(message.nonce.as_slice())),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_x402_payment_required() {
        let response_body = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x1234567890123456789012345678901234567890",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "paymentRequestId": "req-1",
                    "expires": 1740672154,
                    "settlementMethod": "eip3009"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();
        assert!(requirements.accepts_x402());
        assert_eq!(requirements.accepts.len(), 1);
        assert!(requirements.resource.is_some());
    }

    #[test]
    fn test_detect_prepaid_insufficient_credit() {
        let response_body = r#"{
            "error": "insufficient_credit",
            "minimumRequired": "0.50",
            "currentBalance": "0.00"
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();
        assert!(requirements.is_insufficient_credit());
    }

    #[test]
    fn test_select_payment_method_prefers_x402() {
        let response_body = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x1234567890123456789012345678901234567890",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "paymentRequestId": "req-1"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();

        let user_caps = UserCapabilities {
            has_wallet: true,
            wallet_address: Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into()),
            has_prepaid: true,
        };

        let method = select_payment_method(&requirements, &user_caps);
        assert!(matches!(method, Some(PaymentMethod::X402 { .. })));
    }

    #[test]
    fn test_select_payment_method_fallback_to_prepaid() {
        let response_body = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x1234567890123456789012345678901234567890",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "paymentRequestId": "req-1"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();

        let user_caps = UserCapabilities {
            has_wallet: false, // No wallet
            wallet_address: None,
            has_prepaid: true,
        };

        // X402 required but no wallet, should fallback to prepaid
        let method = select_payment_method(&requirements, &user_caps);
        assert!(matches!(method, Some(PaymentMethod::Prepaid)));
    }

    #[test]
    fn test_select_payment_method_no_options() {
        let response_body = r#"{
            "error": "insufficient_credit",
            "minimumRequired": "0.50",
            "currentBalance": "0.00"
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();

        let user_caps = UserCapabilities {
            has_wallet: false,
            wallet_address: None,
            has_prepaid: false, // No prepaid either
        };

        let method = select_payment_method(&requirements, &user_caps);
        assert!(method.is_none());
    }

    #[tokio::test]
    async fn test_build_payment_payload() {
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();

        let response_body = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "paymentRequestId": "req-1"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();
        let x402_option = requirements.x402_option().unwrap();

        let payload = build_x402_payment_payload(&wallet, &requirements, x402_option)
            .await
            .unwrap();

        assert_eq!(payload.x402_version, 2);
        assert!(payload.payload.signature.starts_with("0x"));
        assert_eq!(payload.payload.authorization.value, "1000000");
        assert!(payload.payload.authorization.nonce.starts_with("0x"));
    }

    #[tokio::test]
    async fn test_payload_validity_window() {
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();

        let response_body = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "100000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "paymentRequestId": "req-1"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();
        let x402_option = requirements.x402_option().unwrap();

        let payload = build_x402_payment_payload(&wallet, &requirements, x402_option)
            .await
            .unwrap();

        let valid_after: u64 = payload
            .payload
            .authorization
            .valid_after
            .parse()
            .expect("valid_after should be a number");
        let valid_before: u64 = payload
            .payload
            .authorization
            .valid_before
            .parse()
            .expect("valid_before should be a number");

        // Validity window should span approximately max_timeout_seconds (300s)
        let window = valid_before - valid_after;
        assert!(
            window >= 300 && window <= 360,
            "Validity window should be ~300-360 seconds, got {}",
            window
        );

        // valid_after should be roughly now - 60 seconds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time")
            .as_secs();

        assert!(
            valid_after <= now && valid_after >= now - 120,
            "valid_after should be within last 2 minutes"
        );
    }

    #[test]
    fn test_multiple_payment_options() {
        let multi_response = r#"{
            "x402Version": 2,
            "resource": {
                "url": "/api/agent/database",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json"
            },
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "100000",
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                    "maxTimeoutSeconds": 300,
                    "extra": {
                        "paymentRequestId": "req-1"
                    }
                },
                {
                    "scheme": "exact",
                    "network": "eip155:1",
                    "amount": "100000",
                    "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                    "maxTimeoutSeconds": 300,
                    "extra": {
                        "paymentRequestId": "req-2"
                    }
                }
            ]
        }"#;

        let requirements = PaymentRequirements::parse(multi_response).unwrap();

        assert!(requirements.accepts_x402());
        assert_eq!(requirements.accepts.len(), 2);

        // First option should be Base (what x402_option returns)
        let first = requirements.x402_option().unwrap();
        assert_eq!(first.network, "eip155:8453");
    }
}
