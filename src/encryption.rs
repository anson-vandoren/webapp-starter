//! Encryption and token management utilities.

use aes_gcm::{Aes256Gcm, KeyInit as _, aead::OsRng};
use anyhow::anyhow;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey as _};
use serde::Deserialize;
use sha2::Sha256;

use crate::error::AppError;

/// Generates a cryptographically secure 256-bit encryption key.
pub fn generate_root_key() -> Vec<u8> {
    Aes256Gcm::generate_key(OsRng).to_vec()
}

/// Provider for encryption and token operations.
pub struct EncryptionProvider {
    /// The root encryption key used for HMAC operations.
    key: Vec<u8>,
}

impl EncryptionProvider {
    /// Creates a new encryption provider with the given key.
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Signs a token payload with HMAC-SHA256.
    ///
    /// This method creates a JWT token signed with the provider's key,
    /// ensuring the token's authenticity and integrity.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HMAC key initialization fails
    /// - Token signing fails
    pub fn sign_token<T>(&self, token: T) -> Result<String, AppError>
    where
        T: SignWithKey<String>,
    {
        let hmac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|err| AppError::internal(anyhow!("Failed to create HMAC: {err}")))?;

        token
            .sign_with_key(&hmac)
            .map_err(|err| AppError::internal(anyhow!("Failed to sign token with HMAC: {err}")))
    }

    /// Verifies and decodes a JWT token.
    ///
    /// This method:
    /// 1. Parses the JWT token structure
    /// 2. Verifies the HMAC signature
    /// 3. Extracts and returns the token claims
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HMAC key initialization fails (invalid key length)
    /// - Token parsing fails (malformed token)
    /// - Signature verification fails (invalid or tampered token)
    pub fn verify_token_sig<T>(&self, token: &str) -> Result<T, AppError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let hmac =
            Hmac::<Sha256>::new_from_slice(self.key.as_ref()).map_err(|_| AppError::internal(anyhow!("Invalid length for HMAC key.")))?;

        // Differentiate between failed to parse and failed to verify
        let token = jwt::Token::<jwt::Header, T, _>::parse_unverified(token)
            .map_err(|error| AppError::internal(anyhow!("Failed to parse token: {error}")))?;

        let (_header, claims) = token.verify_with_key(&hmac).map_err(AppError::internal)?.into();

        Ok(claims)
    }
}
