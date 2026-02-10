use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use rand::RngCore;

use crate::error::{McpError, Result};

const TOKEN_PREFIX: &str = "enc_v1:";

#[derive(Clone)]
pub(crate) struct TokenCipher {
    primary: Aes256Gcm,
    fallbacks: Vec<Aes256Gcm>,
}

impl TokenCipher {
    /// Reads token-encryption keys from environment variables.
    ///
    /// Supports:
    /// - `OAUTH_TOKEN_ENCRYPTION_KEYS`: comma-separated keys (first is primary)
    ///
    /// Keys can be:
    /// - 64-char hex (32 bytes)
    /// - base64/base64url encoding of 32 bytes
    /// - a raw string of at least 32 bytes (exactly 32 used directly; longer is SHA-256 hashed)
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let raw = std::env::var("OAUTH_TOKEN_ENCRYPTION_KEYS").ok();

        let Some(raw) = raw else {
            return Ok(None);
        };

        let keys: Vec<&str> = raw
            .split(',')
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .collect();

        if keys.is_empty() {
            return Err(McpError::Config(
                "OAUTH_TOKEN_ENCRYPTION_KEYS is set but empty".into(),
            ));
        }

        let mut ciphers = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = parse_key_material(key)?;
            ciphers.push(Aes256Gcm::new_from_slice(&key_bytes).expect("32-byte key"));
        }

        let mut it = ciphers.into_iter();
        let primary = it.next().expect("at least one key");
        let fallbacks = it.collect();

        Ok(Some(Self { primary, fallbacks }))
    }

    pub(crate) fn is_encrypted(value: &str) -> bool {
        value.starts_with(TOKEN_PREFIX)
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn encrypt(&self, plaintext: &str) -> Result<String> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let ciphertext = self
            .primary
            .encrypt(
                aes_gcm::Nonce::from_slice(&nonce_bytes),
                plaintext.as_bytes(),
            )
            .map_err(|_| McpError::Config("Token encryption failed".into()))?;

        let nonce_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            nonce_bytes,
        );
        let ciphertext_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ciphertext,
        );

        Ok(format!("{TOKEN_PREFIX}{nonce_b64}.{ciphertext_b64}"))
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn decrypt_or_plain(&self, value: &str) -> Result<String> {
        if !Self::is_encrypted(value) {
            return Ok(value.to_string());
        }

        let value = value
            .strip_prefix(TOKEN_PREFIX)
            .expect("prefix check performed above");

        let (nonce_b64, ciphertext_b64) = value.split_once('.').ok_or_else(|| {
            McpError::Config("Invalid encrypted token format (missing '.')".into())
        })?;

        let nonce = decode_key_material(nonce_b64).map_err(|_| {
            McpError::Config("Invalid encrypted token format (nonce decode)".into())
        })?;
        if nonce.len() != 12 {
            return Err(McpError::Config(
                "Invalid encrypted token format (nonce length)".into(),
            ));
        }

        let ciphertext = decode_key_material(ciphertext_b64).map_err(|_| {
            McpError::Config("Invalid encrypted token format (ciphertext decode)".into())
        })?;

        for cipher in std::iter::once(&self.primary).chain(self.fallbacks.iter()) {
            if let Ok(plaintext) =
                cipher.decrypt(aes_gcm::Nonce::from_slice(&nonce), ciphertext.as_ref())
            {
                return String::from_utf8(plaintext)
                    .map_err(|_| McpError::Config("Decrypted token is not UTF-8".into()));
            }
        }

        Err(McpError::Config("Token decryption failed".into()))
    }
}

#[allow(clippy::result_large_err)]
fn parse_key_material(raw: &str) -> Result<[u8; 32]> {
    let raw = raw.trim();

    // hex (32 bytes)
    if raw.len() == 64 && raw.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        let decoded = hex::decode(raw)
            .map_err(|_| McpError::Config("Invalid hex token-encryption key".into()))?;
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
    }

    // base64 / base64url (32 bytes)
    if let Ok(decoded) = decode_key_material(raw)
        && decoded.len() == 32
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(&decoded);
        return Ok(out);
    }

    // raw string fallback
    let raw_bytes = raw.as_bytes();
    if raw_bytes.len() < 32 {
        return Err(McpError::Config(
            "Token-encryption key must be at least 32 bytes (or base64/hex encoding of 32 bytes)"
                .into(),
        ));
    }

    let mut out = [0u8; 32];
    if raw_bytes.len() == 32 {
        out.copy_from_slice(raw_bytes);
        return Ok(out);
    }

    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw_bytes);
    out.copy_from_slice(&digest);
    Ok(out)
}

fn decode_key_material(raw: &str) -> std::result::Result<Vec<u8>, ()> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw)
        .or_else(|_| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw))
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let cipher = TokenCipher {
            primary: Aes256Gcm::new_from_slice(&key).unwrap(),
            fallbacks: vec![],
        };

        let plaintext = "test-token-value";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert!(encrypted.starts_with(TOKEN_PREFIX));

        let decrypted = cipher.decrypt_or_plain(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_uses_fallback_keys() {
        let old_key = [1u8; 32];
        let new_key = [2u8; 32];

        let old_cipher = TokenCipher {
            primary: Aes256Gcm::new_from_slice(&old_key).unwrap(),
            fallbacks: vec![],
        };
        let new_cipher = TokenCipher {
            primary: Aes256Gcm::new_from_slice(&new_key).unwrap(),
            fallbacks: vec![Aes256Gcm::new_from_slice(&old_key).unwrap()],
        };

        let plaintext = "test-token-value";
        let encrypted = old_cipher.encrypt(plaintext).unwrap();
        let decrypted = new_cipher.decrypt_or_plain(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
