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
    pub error: Option<String>,
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

// ============================================================================
// Response parsing
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InsufficientCreditResponse {
    #[allow(dead_code)]
    error: String,
    minimum_required: String,
    current_balance: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402PaymentOptionV1 {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    pub asset: String,
    pub pay_to: String,
    pub resource: String,
    pub description: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402PaymentRequiredV1 {
    pub x402_version: u8,
    pub error: String,
    pub accepts: Vec<X402PaymentOptionV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct X402PaymentRequiredV2 {
    pub x402_version: u8,
    #[serde(default)]
    pub resource: Option<X402ResourceInfo>,
    pub accepts: Vec<X402PaymentOption>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

impl PaymentRequirements {
    fn parse_json_value(value: serde_json::Value) -> Result<Self, PaymentError> {
        // Prepaid/credits 402 shape
        if value.get("minimumRequired").is_some() && value.get("currentBalance").is_some() {
            let raw: InsufficientCreditResponse = serde_json::from_value(value)
                .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;
            return Ok(Self {
                x402_version: None,
                resource: None,
                accepts: vec![PaymentOption::Prepaid],
                insufficient_credit: Some(InsufficientCredit {
                    minimum_required: raw.minimum_required,
                    current_balance: raw.current_balance,
                }),
                error: Some(raw.error),
            });
        }

        let version = value
            .get("x402Version")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| PaymentError::ParseFailed("Missing x402Version".to_string()))?;

        match version {
            1 => {
                let raw: X402PaymentRequiredV1 = serde_json::from_value(value)
                    .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;

                let resource = raw.accepts.first().map(|opt| X402ResourceInfo {
                    url: opt.resource.clone(),
                    description: opt.description.clone(),
                    mime_type: opt
                        .mime_type
                        .clone()
                        .unwrap_or_else(|| "application/json".to_string()),
                });

                let accepts = raw
                    .accepts
                    .into_iter()
                    .map(|opt| {
                        PaymentOption::X402(X402PaymentOption {
                            scheme: opt.scheme,
                            network: opt.network,
                            asset: opt.asset,
                            amount: opt.max_amount_required,
                            pay_to: opt.pay_to,
                            max_timeout_seconds: opt.max_timeout_seconds,
                            extra: opt.extra.unwrap_or_default(),
                        })
                    })
                    .collect::<Vec<_>>();

                Ok(Self {
                    x402_version: Some(1),
                    resource,
                    accepts,
                    insufficient_credit: None,
                    error: Some(raw.error),
                })
            }
            2 => {
                let raw: X402PaymentRequiredV2 = serde_json::from_value(value)
                    .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;
                Ok(Self {
                    x402_version: Some(2),
                    resource: raw.resource,
                    accepts: raw.accepts.into_iter().map(PaymentOption::X402).collect(),
                    insufficient_credit: None,
                    error: raw.error,
                })
            }
            other => Err(PaymentError::ParseFailed(format!(
                "Unsupported x402Version: {}",
                other
            ))),
        }
    }

    /// Parse a 402 response body into payment requirements
    pub fn parse(body: &str) -> Result<Self, PaymentError> {
        let value: serde_json::Value =
            serde_json::from_str(body).map_err(|e| PaymentError::ParseFailed(e.to_string()))?;
        Self::parse_json_value(value)
    }

    /// Parse a base64-encoded x402 `PAYMENT-REQUIRED` header into payment requirements.
    pub fn parse_payment_required_header(header_b64: &str) -> Result<Self, PaymentError> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header_b64.trim())
            .map_err(|e| PaymentError::ParseFailed(format!("Invalid PAYMENT-REQUIRED: {}", e)))?;
        let value: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;
        Self::parse_json_value(value)
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

/// x402 v1 PaymentPayload (transport-v1/http)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentPayloadV1 {
    pub x402_version: u8,
    pub scheme: String,
    pub network: String,
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

#[derive(Debug, Clone)]
pub enum BuiltX402PaymentPayload {
    V1(X402PaymentPayloadV1),
    V2(X402PaymentPayload),
}

impl BuiltX402PaymentPayload {
    pub fn x402_version(&self) -> u8 {
        match self {
            BuiltX402PaymentPayload::V1(_) => 1,
            BuiltX402PaymentPayload::V2(_) => 2,
        }
    }

    pub fn header_name(&self) -> &'static str {
        match self {
            BuiltX402PaymentPayload::V1(_) => "X-PAYMENT",
            BuiltX402PaymentPayload::V2(_) => "PAYMENT-SIGNATURE",
        }
    }

    pub fn encode_b64(&self) -> Result<String, PaymentError> {
        let json = match self {
            BuiltX402PaymentPayload::V1(payload) => serde_json::to_vec(payload),
            BuiltX402PaymentPayload::V2(payload) => serde_json::to_vec(payload),
        }
        .map_err(|e| PaymentError::ParseFailed(e.to_string()))?;

        Ok(base64::engine::general_purpose::STANDARD.encode(json))
    }
}

fn chain_id_from_network(network: &str) -> Option<u64> {
    if let Some(chain_id) = network.strip_prefix("eip155:") {
        return chain_id.parse().ok();
    }

    match network {
        "base" => Some(8453),
        "base-sepolia" => Some(84532),
        "ethereum" => Some(1),
        "ethereum-sepolia" => Some(11155111),
        "avalanche" => Some(43114),
        "avalanche-fuji" => Some(43113),
        _ => None,
    }
}

/// Build a complete x402 payment payload
pub async fn build_x402_payment_payload(
    wallet: &PrivateKeyWallet,
    requirements: &PaymentRequirements,
    option: &X402PaymentOption,
) -> Result<BuiltX402PaymentPayload, PaymentError> {
    match requirements.x402_version {
        Some(1) => Ok(BuiltX402PaymentPayload::V1(
            build_x402_payment_payload_v1(wallet, option).await?,
        )),
        Some(2) => Ok(BuiltX402PaymentPayload::V2(
            build_x402_payment_payload_v2(wallet, requirements, option).await?,
        )),
        other => Err(PaymentError::ParseFailed(format!(
            "Unsupported x402 version in requirements: {:?}",
            other
        ))),
    }
}

async fn build_x402_payment_payload_v2(
    wallet: &PrivateKeyWallet,
    requirements: &PaymentRequirements,
    option: &X402PaymentOption,
) -> Result<X402PaymentPayload, PaymentError> {
    let from_address = wallet.address().to_string();
    let resource = requirements.resource.clone().ok_or_else(|| {
        PaymentError::ParseFailed("Missing x402 resource info in 402 response".to_string())
    })?;

    let chain_id = chain_id_from_network(&option.network).ok_or_else(|| {
        PaymentError::SigningFailed(format!(
            "Unsupported network for EIP-3009 signing: {}",
            option.network
        ))
    })?;

    let typed_verifying_contract = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("domain"))
        .and_then(|v| v.get("verifyingContract"))
        .and_then(|v| v.as_str());
    if let Some(vc) = typed_verifying_contract
        && !vc.eq_ignore_ascii_case(&option.asset)
    {
        return Err(PaymentError::SigningFailed(format!(
            "Mismatched verifyingContract ({}) for asset {}",
            vc, option.asset
        )));
    }
    let verifying_contract = typed_verifying_contract.unwrap_or(&option.asset);
    let verifying_contract = verifying_contract.parse().map_err(|_| {
        PaymentError::SigningFailed("Invalid verifyingContract address".to_string())
    })?;

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
        verifying_contract: Some(verifying_contract),
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

async fn build_x402_payment_payload_v1(
    wallet: &PrivateKeyWallet,
    option: &X402PaymentOption,
) -> Result<X402PaymentPayloadV1, PaymentError> {
    let from_address = wallet.address().to_string();

    let chain_id = chain_id_from_network(&option.network).ok_or_else(|| {
        PaymentError::SigningFailed(format!(
            "Unsupported network for EIP-3009 signing: {}",
            option.network
        ))
    })?;

    let typed_verifying_contract = option
        .extra
        .get("eip712TypedData")
        .and_then(|v| v.get("domain"))
        .and_then(|v| v.get("verifyingContract"))
        .and_then(|v| v.as_str());
    if let Some(vc) = typed_verifying_contract
        && !vc.eq_ignore_ascii_case(&option.asset)
    {
        return Err(PaymentError::SigningFailed(format!(
            "Mismatched verifyingContract ({}) for asset {}",
            vc, option.asset
        )));
    }
    let verifying_contract = typed_verifying_contract.unwrap_or(&option.asset);
    let verifying_contract = verifying_contract.parse().map_err(|_| {
        PaymentError::SigningFailed("Invalid verifyingContract address".to_string())
    })?;

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
        verifying_contract: Some(verifying_contract),
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

    Ok(X402PaymentPayloadV1 {
        x402_version: 1,
        scheme: option.scheme.clone(),
        network: option.network.clone(),
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
                "url": "/publishers/test-publisher/query",
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
                "url": "/publishers/test-publisher/query",
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
                "url": "/publishers/test-publisher/query",
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
                "url": "/publishers/test-publisher/query",
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

        assert_eq!(payload.x402_version(), 2);
        match payload {
            BuiltX402PaymentPayload::V2(payload) => {
                assert!(payload.payload.signature.starts_with("0x"));
                assert_eq!(payload.payload.authorization.value, "1000000");
                assert!(payload.payload.authorization.nonce.starts_with("0x"));
            }
            BuiltX402PaymentPayload::V1(_) => panic!("expected v2 payment payload"),
        }
    }

    #[tokio::test]
    async fn test_build_payment_payload_v1() {
        let wallet = PrivateKeyWallet::from_env_or_key(Some(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into(),
        ))
        .unwrap()
        .unwrap();

        let response_body = r#"{
            "x402Version": 1,
            "error": "Payment required",
            "accepts": [{
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "1000000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                "resource": "/publishers/test-publisher/query",
                "description": "SQL query on Test Publisher",
                "mimeType": "application/json",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        }"#;

        let requirements = PaymentRequirements::parse(response_body).unwrap();
        assert_eq!(requirements.x402_version, Some(1));

        let x402_option = requirements.x402_option().unwrap();
        let payload = build_x402_payment_payload(&wallet, &requirements, x402_option)
            .await
            .unwrap();

        assert_eq!(payload.x402_version(), 1);
        assert_eq!(payload.header_name(), "X-PAYMENT");
        assert!(!payload.encode_b64().unwrap().is_empty());

        match payload {
            BuiltX402PaymentPayload::V1(payload) => {
                assert_eq!(payload.scheme, "exact");
                assert_eq!(payload.network, "base-sepolia");
                assert!(payload.payload.signature.starts_with("0x"));
                assert_eq!(payload.payload.authorization.value, "1000000");
                assert!(payload.payload.authorization.nonce.starts_with("0x"));
            }
            BuiltX402PaymentPayload::V2(_) => panic!("expected v1 payment payload"),
        }
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
                "url": "/publishers/test-publisher/query",
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

        let BuiltX402PaymentPayload::V2(payload) = payload else {
            panic!("expected v2 payment payload");
        };

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
            (300..=360).contains(&window),
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
                "url": "/publishers/test-publisher/query",
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
