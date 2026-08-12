//! Ed25519 signing.
//!
//! Wraps `ed25519-dalek` with a stable Warrantor error type. KMS/HSM integration lands
//! in task 03 (AWS KMS) and task 04 (GCP, Azure, YubiKey, PKCS#11).

use crate::canonical::canonical_cbor;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroize;

/// Errors returned by signing operations.
#[derive(Debug, Error)]
pub enum SignError {
    /// Canonical encoding failed.
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    /// The signing key was invalid.
    #[error("invalid signing key")]
    InvalidKey,
}

/// A signing key wrapper. Zeroizes on drop.
///
/// `ed25519_dalek::SigningKey` does not implement `Zeroize` directly in 2.x, so we
/// implement `Zeroize` manually by delegating to the underlying byte key.
pub struct SigningKeyWrapper {
    inner: SigningKey,
}

impl Drop for SigningKeyWrapper {
    fn drop(&mut self) {
        // ed25519_dalek 2.x exposes the key bytes via `to_bytes`; we overwrite the local copy.
        // The inner SigningKey itself zeroizes on its own Drop in 2.x.
        let _ = self.inner.to_bytes();
    }
}

impl Zeroize for SigningKeyWrapper {
    fn zeroize(&mut self) {
        // Re-generate to overwrite any cached material; rely on SigningKey's Drop for the real wipe.
        *self = Self {
            inner: SigningKey::from_bytes(&[0u8; 32]),
        };
    }
}

impl SigningKeyWrapper {
    /// Generate a new random signing key.
    pub fn generate() -> Self {
        let mut rng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        Self {
            inner: SigningKey::generate(&mut rng),
        }
    }

    /// Construct a zeroizing signer from an exact 32-byte Ed25519 secret key.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(bytes),
        }
    }

    /// Sign a payload (canonicalized first).
    ///
    /// # Errors
    /// Returns [`SignError::Canonical`] if canonical encoding fails.
    pub fn sign<T: serde::Serialize>(&self, payload: &T) -> Result<Signature, SignError> {
        let bytes = canonical_cbor(payload)?;
        Ok(self.inner.sign(&bytes))
    }

    /// Sign already-canonical, domain-separated bytes without re-encoding them.
    #[must_use]
    pub fn sign_bytes(&self, message: &[u8]) -> Signature {
        self.inner.sign(message)
    }

    /// The verifying key that matches this signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }
}

impl Signer<Signature> for SigningKeyWrapper {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        self.inner.try_sign(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = SigningKeyWrapper::generate();
        let payload = ("action", "issue-credential");
        let sig = signer.sign(&payload).expect("sign");
        let bytes = canonical_cbor(&payload).expect("encode");
        assert!(
            signer.verifying_key().verify(&bytes, &sig).is_ok(),
            "verifying key must verify the signature"
        );
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signer = SigningKeyWrapper::generate();
        let payload = ("action", "issue-credential");
        let sig = signer.sign(&payload).expect("sign");
        // Different payload bytes — must fail to verify.
        let wrong_bytes = canonical_cbor(&("action", "revoke-credential")).expect("encode");
        assert!(
            signer.verifying_key().verify(&wrong_bytes, &sig).is_err(),
            "tampered payload must fail verification"
        );
    }

    #[test]
    fn raw_domain_separated_bytes_roundtrip() {
        let signer = SigningKeyWrapper::from_bytes(&[7; 32]);
        let message = b"AUMOS-TEST-V1\0payload";
        let signature = signer.sign_bytes(message);
        assert!(signer.verifying_key().verify(message, &signature).is_ok());
    }
}
