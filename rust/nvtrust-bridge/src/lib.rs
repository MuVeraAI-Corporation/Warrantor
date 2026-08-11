//! # warrantor-nvtrust-bridge
//!
//! Bindings to NVIDIA NVTrust (GPU attestation), with a Mock backend for CI.
//!
//! The real NVTrust SDK is NDA-gated and is NOT downloaded in this repo (per scope boundary).
//! We define a `NvTrustBackend` trait with `Mock` and `Real` (FFI) implementations.
//! Wave-1 ships with the `Mock` implementation; `Real` lands when the team has NVTrust access.
//!
//! See `docs/rfcs/C1-1-nvtrust-bridge.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use warrantor_api::attestation::v1::GpuAttestationReport;

/// A GPU attestation report. The proto-canonical view (warrantor_api::attestation::v1::GpuAttestationReport)
/// is the wire type; this is the AumOS-side ergonomic wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationReport {
    /// GPU model (e.g. "H100", "H200").
    pub gpu_model: String,
    /// Opaque attestation bytes from the GPU.
    pub attestation_bytes: Vec<u8>,
    /// 16-byte nonce used to prevent replay.
    pub nonce: [u8; 16],
}

impl AttestationReport {
    /// Convert to the wire (proto) type.
    #[must_use]
    pub fn to_proto(&self) -> GpuAttestationReport {
        GpuAttestationReport {
            gpu_model: self.gpu_model.clone(),
            attestation_bytes: self.attestation_bytes.clone(),
            nonce: self.nonce.to_vec(),
            ..Default::default()
        }
    }

    /// Convert from the wire (proto) type. Returns an error if the nonce isn't 16 bytes.
    ///
    /// # Errors
    /// Returns [`AttestationError::InvalidNonce`] if the proto nonce isn't 16 bytes.
    pub fn from_proto(p: &GpuAttestationReport) -> Result<Self, AttestationError> {
        let nonce_arr: [u8; 16] = if p.nonce.len() == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&p.nonce);
            a
        } else {
            return Err(AttestationError::InvalidNonce(p.nonce.len()));
        };
        Ok(Self {
            gpu_model: p.gpu_model.clone(),
            attestation_bytes: p.attestation_bytes.clone(),
            nonce: nonce_arr,
        })
    }
}

/// Errors returned by attestation operations.
#[derive(Debug, Error)]
pub enum AttestationError {
    /// The attestation report did not verify.
    #[error("attestation verification failed")]
    VerifyFailed,
    /// The backend was unavailable.
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    /// The nonce length was invalid (expected 16).
    #[error("invalid nonce length: expected 16, got {0}")]
    InvalidNonce(usize),
}

/// A backend that can issue and verify GPU attestations.
pub trait NvTrustBackend {
    /// Request an attestation report from the local GPU.
    ///
    /// # Errors
    /// Returns [`AttestationError::BackendUnavailable`] if the GPU is not present.
    fn attest(&self, nonce: [u8; 16]) -> Result<AttestationReport, AttestationError>;

    /// Verify an attestation report against a caller-supplied challenge nonce.
    ///
    /// C4: the challenge nonce is the anti-replay control. The verifier sent `challenge_nonce`
    /// to the GPU when requesting the report; the report must echo it back in `report.nonce`.
    /// A report captured from a previous session (with a different nonce) MUST be rejected here.
    /// This is the method real callers should use.
    ///
    /// # Errors
    /// Returns [`AttestationError::VerifyFailed`] if the report is invalid OR if
    /// `report.nonce != challenge_nonce` (replay attack).
    fn verify_with_challenge(
        &self,
        report: &AttestationReport,
        challenge_nonce: [u8; 16],
    ) -> Result<(), AttestationError>;

    /// Verify an attestation report using the report's own embedded nonce.
    ///
    /// This is a backward-compatible convenience that delegates to [`Self::verify_with_challenge`]
    /// with `challenge_nonce = report.nonce`. It does NOT provide replay protection on its own —
    /// it only confirms the report is well-formed. Callers that need anti-replay guarantees
    /// (i.e. all production callers) MUST use [`Self::verify_with_challenge`] with a nonce they
    /// generated for this verification.
    ///
    /// # Errors
    /// Returns [`AttestationError::VerifyFailed`] if the report is invalid.
    fn verify(&self, report: &AttestationReport) -> Result<(), AttestationError> {
        self.verify_with_challenge(report, report.nonce)
    }
}

/// A mock backend for CI / offline / development use. Always verifies successfully
/// for the well-known mock attestation bytes.
pub struct MockBackend {
    /// GPU model reported by the mock.
    pub gpu_model: String,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            gpu_model: "mock-H100".to_string(),
        }
    }
}

impl NvTrustBackend for MockBackend {
    fn attest(&self, nonce: [u8; 16]) -> Result<AttestationReport, AttestationError> {
        Ok(AttestationReport {
            gpu_model: self.gpu_model.clone(),
            // Deterministic mock attestation; NOT real GPU bytes.
            attestation_bytes: b"warrantor-mock-attestation".to_vec(),
            nonce,
        })
    }

    fn verify_with_challenge(
        &self,
        report: &AttestationReport,
        challenge_nonce: [u8; 16],
    ) -> Result<(), AttestationError> {
        // C4: enforce the challenge nonce — a report whose nonce does not match the challenge
        // the verifier issued is a replay and must be rejected.
        if report.nonce != challenge_nonce {
            return Err(AttestationError::VerifyFailed);
        }
        if report.attestation_bytes == b"warrantor-mock-attestation" {
            Ok(())
        } else {
            Err(AttestationError::VerifyFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backend_round_trips() {
        let backend = MockBackend::default();
        let nonce = [1u8; 16];
        let report = backend.attest(nonce).expect("attest");
        assert_eq!(report.nonce, nonce);
        backend.verify(&report).expect("verify");
    }

    #[test]
    fn mock_backend_rejects_tampered_report() {
        let backend = MockBackend::default();
        let mut report = backend.attest([2u8; 16]).expect("attest");
        report.attestation_bytes[0] ^= 0xff; // tamper
        assert!(matches!(
            backend.verify(&report),
            Err(AttestationError::VerifyFailed)
        ));
    }

    #[test]
    fn proto_round_trip_preserves_fields() {
        let report = AttestationReport {
            gpu_model: "mock-H100".into(),
            attestation_bytes: b"warrantor-mock".to_vec(),
            nonce: [7u8; 16],
        };
        let proto = report.to_proto();
        let back = AttestationReport::from_proto(&proto).expect("round trip");
        assert_eq!(back, report);
    }

    #[test]
    fn from_proto_rejects_bad_nonce_length() {
        let bad = GpuAttestationReport {
            gpu_model: "x".into(),
            attestation_bytes: vec![],
            nonce: vec![0u8; 15], // wrong length
            ..Default::default()
        };
        assert!(matches!(
            AttestationReport::from_proto(&bad),
            Err(AttestationError::InvalidNonce(15))
        ));
    }

    #[test]
    fn golden_vector_sign_ed25519_unrelated_but_locks_proto_shape() {
        // Confirms the proto GpuAttestationReport shape is stable (it's the wire type C1-2 cuda-gram
        // will consume via PyO3). This locks the shape so any breaking proto change fails CI here.
        let r = GpuAttestationReport {
            gpu_model: "mock-H100".into(),
            attestation_bytes: b"warrantor-mock-attestation".to_vec(),
            nonce: vec![42u8; 16],
            ..Default::default()
        };
        assert_eq!(r.gpu_model, "mock-H100");
    }

    #[test]
    fn verify_with_challenge_rejects_nonce_mismatch_c4() {
        // C4: a report captured from a previous session (different nonce) must be rejected as a
        // replay. The verifier issued `challenge`, the report carries `report.nonce`; if they
        // differ, verification must fail.
        let backend = MockBackend::default();
        let challenge = [10u8; 16];
        let report = backend.attest(challenge).expect("attest");
        // Correct challenge verifies.
        backend
            .verify_with_challenge(&report, challenge)
            .expect("matching challenge verifies");
        // Wrong challenge (a replayed report from a different session) must fail.
        let wrong_challenge = [99u8; 16];
        assert!(matches!(
            backend.verify_with_challenge(&report, wrong_challenge),
            Err(AttestationError::VerifyFailed)
        ));
    }

    #[test]
    fn verify_convenience_uses_report_own_nonce_c4() {
        // The backward-compatible verify() delegates to verify_with_challenge with the report's
        // own nonce, so existing callers keep working (round-trips).
        let backend = MockBackend::default();
        let nonce = [3u8; 16];
        let report = backend.attest(nonce).expect("attest");
        backend.verify(&report).expect("verify convenience works");
    }
}
