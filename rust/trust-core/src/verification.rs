//! Ed25519 verification.

use crate::canonical::canonical_cbor;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

/// Errors returned by verification operations.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Canonical encoding failed.
    #[error("canonical encoding failed: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    /// The signature was invalid (constant-time failure).
    #[error("signature verification failed")]
    InvalidSignature,
}

/// Verify a signature over a serializable payload against a verifying key.
///
/// Constant-time in the secret material. Fails closed on any error.
///
/// # Errors
/// Returns [`VerifyError::InvalidSignature`] if the signature does not verify.
pub fn verify<T: serde::Serialize>(
    payload: &T,
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    let bytes = canonical_cbor(payload)?;
    verifying_key
        .verify(&bytes, signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

/// Verify already-canonical, domain-separated bytes.
///
/// # Errors
/// Returns [`VerifyError::InvalidSignature`] if the signature does not verify.
pub fn verify_bytes(
    message: &[u8],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<(), VerifyError> {
    verifying_key
        .verify(message, signature)
        .map_err(|_| VerifyError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::SigningKeyWrapper;

    #[test]
    fn verify_accepts_valid_signature() {
        let signer = SigningKeyWrapper::generate();
        let payload = ("action", "issue-credential");
        let sig = signer.sign(&payload).expect("sign");
        verify(&payload, &sig, &signer.verifying_key()).expect("valid signature verifies");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer_a = SigningKeyWrapper::generate();
        let signer_b = SigningKeyWrapper::generate();
        let payload = ("action", "issue-credential");
        let sig = signer_a.sign(&payload).expect("sign");
        assert!(
            matches!(
                verify(&payload, &sig, &signer_b.verifying_key()),
                Err(VerifyError::InvalidSignature)
            ),
            "wrong key must reject"
        );
    }

    #[test]
    fn verify_bytes_rejects_tampered_domain_separated_message() {
        let signer = SigningKeyWrapper::generate();
        let signature = signer.sign_bytes(b"AUMOS-RAW-V1\0payload");
        verify_bytes(
            b"AUMOS-RAW-V1\0payload",
            &signature,
            &signer.verifying_key(),
        )
        .expect("valid raw signature");
        assert!(matches!(
            verify_bytes(
                b"AUMOS-RAW-V1\0tampered",
                &signature,
                &signer.verifying_key()
            ),
            Err(VerifyError::InvalidSignature)
        ));
    }
}
