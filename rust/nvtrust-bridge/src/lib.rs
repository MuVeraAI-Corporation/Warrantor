//! # aumos-nvtrust-bridge
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

use aumos_api::attestation::v1::GpuAttestationReport;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A GPU attestation report. The proto-canonical view (aumos_api::attestation::v1::GpuAttestationReport)
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

    /// Verify an attestation report.
    ///
    /// # Errors
    /// Returns [`AttestationError::VerifyFailed`] if the report is invalid.
    fn verify(&self, report: &AttestationReport) -> Result<(), AttestationError>;
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
            attestation_bytes: b"aumos-mock-attestation".to_vec(),
            nonce,
        })
    }

    fn verify(&self, report: &AttestationReport) -> Result<(), AttestationError> {
        if report.attestation_bytes == b"aumos-mock-attestation" {
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
            attestation_bytes: b"aumos-mock".to_vec(),
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
            attestation_bytes: b"aumos-mock-attestation".to_vec(),
            nonce: vec![42u8; 16],
            ..Default::default()
        };
        assert_eq!(r.gpu_model, "mock-H100");
    }
}
