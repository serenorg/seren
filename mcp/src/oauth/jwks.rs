//! JWKS (JSON Web Key Set) fetching and JWT validation.
//!
//! This module provides JWKS-based JWT validation for MCP OAuth.
//! Instead of issuing our own tokens, we validate JWTs from serencore
//! using its public JWKS endpoint.

use arc_swap::ArcSwapOption;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::Semaphore;

// JWKS refresh configuration
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30); // 30 seconds minimum between forced refreshes
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CLOCK_SKEW_LEEWAY: u64 = 60; // 60 seconds leeway for clock skew

/// JWT claims from serencore tokens.
/// Must match the Claims struct in serencore/seren-core/src/auth/jwt.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // user_id
    pub email: String,
    pub name: String,
    pub exp: i64, // expiration timestamp
    pub iat: i64, // issued at timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

/// JSON Web Key from JWKS response
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA")
    pub kty: String,
    /// Algorithm (e.g., "RS256")
    #[serde(default)]
    #[allow(dead_code)]
    pub alg: Option<String>,
    /// Key use (e.g., "sig")
    #[serde(rename = "use", default)]
    pub use_: Option<String>,
    /// Key ID
    #[serde(default)]
    pub kid: Option<String>,
    /// RSA modulus (base64url encoded)
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url encoded)
    #[serde(default)]
    pub e: Option<String>,
}

/// JWKS response from the well-known endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// Cached JWKS entry with metadata
struct JwksCacheEntry {
    keys: HashMap<String, DecodingKey>,
    last_fetched: Instant,
}

/// JWKS cache for JWT validation
pub struct JwksCache {
    /// HTTP client for fetching JWKS
    client: Client,
    /// JWKS endpoint URL
    jwks_url: String,
    /// Cached keys (wrapped in ArcSwap for lock-free reads)
    cache: ArcSwapOption<JwksCacheEntry>,
    /// Semaphore to prevent concurrent JWKS fetches
    fetch_semaphore: Semaphore,
    /// Expected issuer (optional validation)
    expected_issuer: Option<String>,
    /// Expected audience (optional validation)
    expected_audience: Option<String>,
}

#[derive(Error, Debug)]
pub enum JwksError {
    #[error("Failed to fetch JWKS: {0}")]
    FetchError(#[from] reqwest::Error),

    #[error("No keys found in JWKS response")]
    NoKeysFound,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(#[from] jsonwebtoken::errors::Error),

    #[error("Missing key ID in JWT header")]
    MissingKeyId,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

impl JwksCache {
    /// Create a new JWKS cache
    pub fn new(
        jwks_url: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> Self {
        let client = Client::builder()
            .user_agent(format!("seren-mcp/{}", env!("CARGO_PKG_VERSION")))
            .timeout(JWKS_FETCH_TIMEOUT)
            .connect_timeout(JWKS_CONNECT_TIMEOUT)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            jwks_url,
            cache: ArcSwapOption::empty(),
            fetch_semaphore: Semaphore::new(1),
            expected_issuer,
            expected_audience,
        }
    }

    /// Fetch JWKS from the upstream endpoint
    async fn fetch_jwks(&self) -> Result<HashMap<String, DecodingKey>, JwksError> {
        tracing::debug!(url = %self.jwks_url, "Fetching JWKS");

        let response = self.client.get(&self.jwks_url).send().await?;
        let jwks: JwksResponse = response.json().await?;

        if jwks.keys.is_empty() {
            return Err(JwksError::NoKeysFound);
        }

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            // Only process RSA signing keys
            if jwk.kty != "RSA" {
                continue;
            }
            if let Some(ref use_) = jwk.use_
                && use_ != "sig"
            {
                continue;
            }

            let kid = match &jwk.kid {
                Some(kid) => kid.clone(),
                None => continue, // Skip keys without kid
            };

            // Build RSA public key from n and e components
            let (n, e) = match (&jwk.n, &jwk.e) {
                (Some(n), Some(e)) => (n, e),
                _ => continue,
            };

            // Decode base64url-encoded components
            let n_bytes = URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|e| JwksError::InvalidKeyFormat(format!("Invalid modulus: {}", e)))?;
            let e_bytes = URL_SAFE_NO_PAD
                .decode(e)
                .map_err(|e| JwksError::InvalidKeyFormat(format!("Invalid exponent: {}", e)))?;

            // Create DecodingKey from RSA components
            let decoding_key = DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes);
            keys.insert(kid, decoding_key);
        }

        if keys.is_empty() {
            return Err(JwksError::NoKeysFound);
        }

        tracing::info!(key_count = keys.len(), "JWKS fetched successfully");
        Ok(keys)
    }

    /// Get or refresh the JWKS cache
    async fn get_or_refresh_cache(&self, force: bool) -> Result<Arc<JwksCacheEntry>, JwksError> {
        // Check if we have a valid cache
        if let Some(cached) = self.cache.load_full() {
            let age = cached.last_fetched.elapsed();

            // Return cached keys if not forcing refresh and cache is fresh
            if !force && age < JWKS_REFRESH_INTERVAL {
                return Ok(cached);
            }

            // If forcing refresh, ensure we don't refresh too often
            if force && age < JWKS_MIN_REFRESH_INTERVAL {
                tracing::debug!("JWKS refresh rate limited, using cached keys");
                return Ok(cached);
            }

            // Try to acquire refresh permit without blocking
            if let Ok(_permit) = self.fetch_semaphore.try_acquire() {
                // Perform refresh (blocking on result)
                return self.do_refresh().await;
            } else {
                // Another refresh is in progress, return cached
                return Ok(cached);
            }
        }

        // No cache, must fetch
        let _permit = self.fetch_semaphore.acquire().await.unwrap();

        // Double-check after acquiring permit
        if let Some(cached) = self.cache.load_full() {
            return Ok(cached);
        }

        self.do_refresh().await
    }

    /// Actually perform the JWKS refresh
    async fn do_refresh(&self) -> Result<Arc<JwksCacheEntry>, JwksError> {
        let keys = self.fetch_jwks().await?;
        let entry = Arc::new(JwksCacheEntry {
            keys,
            last_fetched: Instant::now(),
        });
        self.cache.store(Some(entry.clone()));
        Ok(entry)
    }

    /// Validate a JWT token and return its claims
    pub async fn validate_token(&self, token: &str) -> Result<Claims, JwksError> {
        // Decode header to get kid
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(JwksError::MissingKeyId)?;

        // Verify algorithm
        if header.alg != Algorithm::RS256 {
            return Err(JwksError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
        }

        // Get the cache (Arc keeps it alive for the duration of this function)
        let cache = self.get_or_refresh_cache(false).await?;

        // Check if key exists in current cache
        let cache = if cache.keys.contains_key(&kid) {
            cache
        } else {
            // Key not found, try refreshing JWKS (key rotation scenario)
            tracing::debug!(kid = %kid, "Key not found, forcing JWKS refresh");
            self.get_or_refresh_cache(true).await?
        };

        // Now get the key (cache is still alive due to Arc)
        let decoding_key = cache
            .keys
            .get(&kid)
            .ok_or_else(|| JwksError::KeyNotFound(kid.clone()))?;

        // Set up validation
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = CLOCK_SKEW_LEEWAY;

        // Set expected issuer if configured
        if let Some(ref issuer) = self.expected_issuer {
            validation.set_issuer(&[issuer]);
        }
        // Note: jsonwebtoken crate requires issuer validation if set_issuer is called,
        // but doesn't validate if not set.

        // Set expected audience if configured
        if let Some(ref audience) = self.expected_audience {
            validation.set_audience(&[audience]);
        }
        // Note: Similarly, audience is only validated if set_audience is called.

        // Validate and decode the token
        let token_data = decode::<Claims>(token, decoding_key, &validation)?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_deserialize() {
        let json = r#"{
            "sub": "user-123",
            "email": "test@example.com",
            "name": "Test User",
            "exp": 1704067200,
            "iat": 1704063600,
            "iss": "serencore",
            "aud": "serendb"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.iss, Some("serencore".to_string()));
    }

    #[test]
    fn test_jwks_response_deserialize() {
        let json = r#"{
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "serencore-1",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB"
            }]
        }"#;

        let jwks: JwksResponse = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, Some("serencore-1".to_string()));
    }
}
