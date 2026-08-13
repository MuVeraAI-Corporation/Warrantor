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
    /// The key has been zeroized. It cannot sign again, by design.
    #[error("signing key has been zeroized")]
    Zeroized,
}

/// A signing key that fails closed once zeroized.
///
/// `ed25519_dalek::SigningKey` is `ZeroizeOnDrop`, so dropping this wrapper wipes the
/// secret. What this type adds is that [`Zeroize::zeroize`] leaves **no usable key
/// behind** — the same rule the rest of the product follows, that an absent authority
/// means *none* rather than *some weaker thing*.
///
/// # Why the key is an `Option`
///
/// The previous implementation zeroized by overwriting with
/// `SigningKey::from_bytes(&[0u8; 32])`. That does wipe the old secret — but it installs
/// a *valid, publicly derivable* key in its place. Anything signing after `zeroize()`
/// produced a genuine signature under a key any attacker can reconstruct from a
/// constant, and the signature verified, so nothing downstream could notice.
///
/// Representing absence as `None` makes signing-after-zeroize impossible rather than
/// merely different. Given the choice between a crash and a valid signature under a
/// known key, this product takes the crash.
pub struct SigningKeyWrapper {
    inner: Option<SigningKey>,
}

impl Zeroize for SigningKeyWrapper {
    fn zeroize(&mut self) {
        // Dropping the SigningKey wipes it (ZeroizeOnDrop, verified against 3.0). Leaving
        // `None` behind is the point: there is no key here now, and every accessor says so.
        self.inner = None;
    }
}

impl SigningKeyWrapper {
    /// Generate a new random signing key.
    pub fn generate() -> Self {
        let mut rng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        Self {
            inner: Some(SigningKey::generate(&mut rng)),
        }
    }

    /// Construct a zeroizing signer from an exact 32-byte Ed25519 secret key.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: Some(SigningKey::from_bytes(bytes)),
        }
    }

    /// Has this key been zeroized? Lets a caller check before reaching for one of the
    /// panicking accessors below.
    #[must_use]
    pub const fn is_zeroized(&self) -> bool {
        self.inner.is_none()
    }

    fn key(&self) -> Result<&SigningKey, SignError> {
        self.inner.as_ref().ok_or(SignError::Zeroized)
    }

    /// Sign a payload (canonicalized first).
    ///
    /// # Errors
    /// Returns [`SignError::Canonical`] if canonical encoding fails, or
    /// [`SignError::Zeroized`] if the key has been zeroized.
    pub fn sign<T: serde::Serialize>(&self, payload: &T) -> Result<Signature, SignError> {
        let bytes = canonical_cbor(payload)?;
        Ok(self.key()?.sign(&bytes))
    }

    /// Sign already-canonical, domain-separated bytes without re-encoding them.
    ///
    /// # Panics
    /// Panics if the key has been zeroized. Signing with a dead key is a program error,
    /// and the alternative — returning something that looks like a signature — is worse
    /// than stopping. Call [`Self::is_zeroized`] first if the state is in doubt.
    #[must_use]
    pub fn sign_bytes(&self, message: &[u8]) -> Signature {
        self.key()
            .expect("sign_bytes called on a zeroized signing key")
            .sign(message)
    }

    /// The verifying key that matches this signing key.
    ///
    /// # Panics
    /// Panics if the key has been zeroized. There is no verifying key to return, and
    /// returning one derived from a placeholder would be a lie a caller cannot detect.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key()
            .expect("verifying_key called on a zeroized signing key")
            .verifying_key()
    }
}

impl Signer<Signature> for SigningKeyWrapper {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        self.key()
            .map_err(|_| ed25519_dalek::SignatureError::new())?
            .try_sign(msg)
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

    #[test]
    fn zeroize_leaves_no_usable_key() {
        let mut signer = SigningKeyWrapper::from_bytes(&[7; 32]);
        assert!(!signer.is_zeroized());
        signer.zeroize();
        assert!(signer.is_zeroized(), "zeroize must leave no key behind");
        assert!(
            matches!(signer.sign(&("action", "x")), Err(SignError::Zeroized)),
            "signing after zeroize must fail closed, not succeed under some other key"
        );
        assert!(
            signer.try_sign(b"payload").is_err(),
            "the Signer impl must fail closed too"
        );
    }

    /// The regression this whole change exists for.
    ///
    /// The previous `zeroize()` installed `SigningKey::from_bytes(&[0u8; 32])` — a valid
    /// key derived from a constant. Signing still worked and the signatures still
    /// verified, under a key any attacker can reconstruct. This asserts that a zeroized
    /// wrapper cannot produce anything that verifies under that all-zero-seed key.
    #[test]
    fn zeroize_does_not_install_the_all_zero_seed_key() {
        let all_zero_seed = SigningKey::from_bytes(&[0u8; 32]);
        let attacker_derivable = all_zero_seed.verifying_key();

        let mut signer = SigningKeyWrapper::from_bytes(&[7; 32]);
        signer.zeroize();

        // Under the old implementation this returned Ok and the resulting signature
        // verified under `attacker_derivable`.
        let Err(SignError::Zeroized) = signer.sign(&("action", "issue-credential")) else {
            panic!("a zeroized key produced a signature — the defect has returned");
        };

        // And the placeholder key must not be reachable at all.
        assert!(
            signer.is_zeroized(),
            "the wrapper must hold no key, not a well-known one"
        );
        let _ = attacker_derivable; // named to document what must never come back
    }

    #[test]
    #[should_panic(expected = "verifying_key called on a zeroized signing key")]
    fn verifying_key_after_zeroize_panics_rather_than_lying() {
        let mut signer = SigningKeyWrapper::generate();
        signer.zeroize();
        let _ = signer.verifying_key();
    }

    #[test]
    #[should_panic(expected = "sign_bytes called on a zeroized signing key")]
    fn sign_bytes_after_zeroize_panics_rather_than_signing() {
        let mut signer = SigningKeyWrapper::generate();
        signer.zeroize();
        let _ = signer.sign_bytes(b"payload");
    }
}
