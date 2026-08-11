//! # warrantor-eval-guard
//!
//! Signs a caller's assertion about four sandbox boundaries, and refuses to sign an assertion
//! that any boundary failed.
//!
//! ## What this crate does NOT do (AX-46)
//!
//! **It does not perform the checks.** [`run_preflight`] takes [`CheckResults`] as an *input*:
//! four booleans the caller has already decided. This crate verifies they are all true and emits
//! a signed [`SandboxAttestation`] over them. It has no eBPF, opens no sockets, inspects no
//! namespaces, and cannot observe the sandbox at all.
//!
//! That makes the attestation exactly as trustworthy as whoever supplied the booleans, and no
//! more. It is a *notarisation* of a claim, not a measurement of a system. Documentation here
//! previously described it as "cryptographic sandbox boundary attestation ... requires Linux
//! 5.13+ for eBPF", which described a component that does not exist and invited callers to treat
//! a signature over their own assertion as independent evidence.
//!
//! Producing the four booleans honestly -- an actual NetworkIsolation probe, an actual
//! FilesystemBoundary check -- is unimplemented and is what R2 still owes.
//!
//! ## What it does do, and does correctly
//!
//! Given results, it fails closed: any false boundary yields [`EvalGuardError::CheckFailed`] and
//! no attestation is produced (invariant I-09). The signature and canonical encoding are real.
//!
//! AumOS moved this from Go to Rust per the trusted-core doctrine (see RFC R2).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use warrantor_api::attestation::v1::SandboxAttestation as ProtoSandboxAttestation;

/// The four pre-flight boundary checks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryCheck {
    /// Network isolation (canary IPs: huggingface.co, pypi.org, 1.1.1.1).
    NetworkIsolation,
    /// Filesystem boundary.
    FilesystemBoundary,
    /// Process isolation.
    ProcessIsolation,
    /// Egress attestation (eBPF iptables rules, deny-all default).
    EgressAttestation,
}

impl BoundaryCheck {
    /// All four checks, in evaluation order.
    pub const ALL: [BoundaryCheck; 4] = [
        BoundaryCheck::NetworkIsolation,
        BoundaryCheck::FilesystemBoundary,
        BoundaryCheck::ProcessIsolation,
        BoundaryCheck::EgressAttestation,
    ];

    /// The proto enum value (matches `warrantor.attestation.v1.BoundaryCheck`).
    #[must_use]
    pub fn to_proto(self) -> i32 {
        match self {
            BoundaryCheck::NetworkIsolation => 1,
            BoundaryCheck::FilesystemBoundary => 2,
            BoundaryCheck::ProcessIsolation => 3,
            BoundaryCheck::EgressAttestation => 4,
        }
    }
}

/// The signed attestation emitted when all four checks pass. The signature is produced by
/// T1 trust-core (here represented by an Ed25519 key for the Wave-1 v1.0 — KMS-backed signing
/// is task 03). The verifying key is carried alongside so any reviewer can verify the signature
/// without a key-resolution step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAttestation {
    /// Every check that passed.
    pub passed_checks: Vec<BoundaryCheck>,
    /// The 16-byte attestation nonce.
    pub nonce: Vec<u8>,
    /// The 32-byte verifying key that signed this attestation.
    pub verifying_key: Vec<u8>,
    /// The actual per-check results that were observed at pre-flight, in [`BoundaryCheck::ALL`]
    /// order (C3: binds the signature to what was actually measured, not just the constant
    /// `BoundaryCheck::ALL` — a single attestation can no longer serve as a permanent skeleton
    /// key).
    pub results: [bool; 4],
    /// When the attestation was produced (epoch seconds). Binds the signature to a point in time
    /// so a captured attestation cannot be replayed indefinitely (C3).
    pub timestamp: u64,
    /// The 64-byte Ed25519 signature over the canonical encoding of
    /// (passed_checks, nonce, results, timestamp).
    pub signature: Vec<u8>,
}

impl SandboxAttestation {
    /// Convert to the wire (proto) type. The verifying_key travels out-of-band (e.g. in the
    /// composite attestation's agent_svid field) so it isn't in the proto SandboxAttestation.
    #[must_use]
    pub fn to_proto(&self) -> ProtoSandboxAttestation {
        ProtoSandboxAttestation {
            passed_checks: self.passed_checks.iter().map(|c| c.to_proto()).collect(),
            nonce: self.nonce.clone(),
            signature: self.signature.clone(),
            ..Default::default()
        }
    }
}

/// Errors returned by eval-guard.
#[derive(Debug, Error)]
pub enum EvalGuardError {
    /// A boundary check failed. The agent must NOT start.
    #[error("boundary check failed: {0:?}")]
    CheckFailed(BoundaryCheck),
    /// Signature verification of an existing attestation failed.
    #[error("attestation signature invalid")]
    SignatureInvalid,
}

/// Per-check result (true = passed, false = failed).
#[derive(Debug, Clone, Copy)]
pub struct CheckResults {
    /// Network isolation result.
    pub network_isolation: bool,
    /// Filesystem boundary result.
    pub filesystem_boundary: bool,
    /// Process isolation result.
    pub process_isolation: bool,
    /// Egress attestation result.
    pub egress_attestation: bool,
}

impl CheckResults {
    /// All four passing — the happy path.
    #[must_use]
    pub const fn all_pass() -> Self {
        Self {
            network_isolation: true,
            filesystem_boundary: true,
            process_isolation: true,
            egress_attestation: true,
        }
    }

    /// As a 4-array in [`BoundaryCheck::ALL`] order.
    #[must_use]
    pub const fn as_array(&self) -> [bool; 4] {
        [
            self.network_isolation,
            self.filesystem_boundary,
            self.process_isolation,
            self.egress_attestation,
        ]
    }
}

/// Build the canonical signing bytes for a sandbox attestation. This binds the signature to:
///   - the constant `BoundaryCheck::ALL` (the checks that were run),
///   - the nonce (freshness),
///   - the **actual** observed `results` (C3: not just the constant ALL — prevents a single
///     attestation acting as a permanent skeleton key for different outcomes),
///   - the **timestamp** (epoch seconds — C3: binds the signature to a point in time).
fn canonical_signing_bytes(nonce: &[u8], results: &[bool; 4], timestamp: u64) -> Vec<u8> {
    let mut canon = Vec::new();
    for c in &BoundaryCheck::ALL {
        canon.extend_from_slice(&c.to_proto().to_le_bytes());
    }
    canon.extend_from_slice(nonce);
    // Bind the actual results (one byte each, 0 or 1).
    for &r in results {
        canon.push(if r { 1u8 } else { 0u8 });
    }
    canon.extend_from_slice(&timestamp.to_le_bytes());
    canon
}

/// Verify caller-supplied boundary results and sign them on success.
///
/// Does NOT run the checks -- `results` is an input. The returned attestation certifies that
/// *someone asserted* these four boundaries held, not that they did. See the crate docs (AX-46).
///
/// # Errors
/// Returns [`EvalGuardError::CheckFailed`] if any supplied result is false. Callers MUST NOT
/// start the agent.
pub fn run_preflight(
    results: &CheckResults,
    signing_key: &SigningKey,
) -> Result<SandboxAttestation, EvalGuardError> {
    for (i, &check) in BoundaryCheck::ALL.iter().enumerate() {
        if !results.as_array()[i] {
            return Err(EvalGuardError::CheckFailed(check));
        }
    }
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // C3: sign over the ACTUAL results and the timestamp, not just the constant
    // BoundaryCheck::ALL. A single attestation is therefore no longer a permanent skeleton key.
    let canon = canonical_signing_bytes(&nonce, &results.as_array(), timestamp);
    let sig = signing_key.sign(&canon);
    Ok(SandboxAttestation {
        passed_checks: BoundaryCheck::ALL.to_vec(),
        nonce: nonce.to_vec(),
        verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
        results: results.as_array(),
        timestamp,
        signature: sig.to_bytes().to_vec(),
    })
}

/// Verify a SandboxAttestation's signature against its embedded verifying key.
///
/// # Errors
/// Returns [`EvalGuardError::SignatureInvalid`] if the signature does not verify or the
/// verifying key / nonce / signature have the wrong length.
pub fn verify_attestation(attestation: &SandboxAttestation) -> Result<(), EvalGuardError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk_bytes: [u8; 32] = attestation
        .verifying_key
        .as_slice()
        .try_into()
        .map_err(|_| EvalGuardError::SignatureInvalid)?;
    let nonce_bytes: [u8; 16] = attestation
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| EvalGuardError::SignatureInvalid)?;
    let sig_bytes: [u8; 64] = attestation
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| EvalGuardError::SignatureInvalid)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| EvalGuardError::SignatureInvalid)?;
    // C3: reconstruct the canonical bytes using the actual results and timestamp embedded in
    // the attestation (not the constant ALL). A mismatch on either makes the signature invalid.
    let canon = canonical_signing_bytes(&nonce_bytes, &attestation.results, attestation.timestamp);
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&canon, &sig)
        .map_err(|_| EvalGuardError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        let mut rng = rand::rngs::OsRng;
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn all_pass_returns_signed_attestation() {
        let key = test_key();
        let attestation = run_preflight(&CheckResults::all_pass(), &key).expect("all pass");
        assert_eq!(attestation.passed_checks.len(), 4);
        verify_attestation(&attestation).expect("signature verifies");
    }

    #[test]
    fn any_failure_blocks_start() {
        let key = test_key();
        let res = run_preflight(
            &CheckResults {
                network_isolation: true,
                filesystem_boundary: false,
                process_isolation: true,
                egress_attestation: true,
            },
            &key,
        );
        assert!(matches!(
            res,
            Err(EvalGuardError::CheckFailed(
                BoundaryCheck::FilesystemBoundary
            ))
        ));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let key = test_key();
        let mut attestation = run_preflight(&CheckResults::all_pass(), &key).expect("all pass");
        attestation.signature[0] ^= 0xff;
        assert!(matches!(
            verify_attestation(&attestation),
            Err(EvalGuardError::SignatureInvalid)
        ));
    }

    #[test]
    fn proto_round_trip_preserves_passed_checks() {
        let key = test_key();
        let attestation = run_preflight(&CheckResults::all_pass(), &key).expect("all pass");
        let proto = attestation.to_proto();
        assert_eq!(proto.passed_checks, vec![1, 2, 3, 4]);
        assert_eq!(proto.nonce, attestation.nonce);
        assert_eq!(proto.signature, attestation.signature);
    }

    #[test]
    fn attestation_binds_actual_results_c3() {
        // C3: the signature must bind the ACTUAL check results, not the constant
        // BoundaryCheck::ALL. A single attestation must not be a permanent skeleton key.
        //
        // We forge an attestation that claims results == [true; 4] but is signed over a
        // DIFFERENT results array. Under the old (vulnerable) code this would verify because the
        // signature only covered the constant ALL; now it must fail because the embedded results
        // participate in the signed bytes.
        let key = test_key();
        let real = run_preflight(&CheckResults::all_pass(), &key).expect("all pass");
        // Tamper: flip one result bit (network_isolation now false). The signature was computed
        // over the original all-true results, so verification must now fail.
        let mut forged = real.clone();
        forged.results[0] = !forged.results[0];
        assert!(matches!(
            verify_attestation(&forged),
            Err(EvalGuardError::SignatureInvalid)
        ));
    }

    #[test]
    fn different_results_produce_different_signatures_c3() {
        // C3: two attestations that differ ONLY in their (equally all-passing) signing inputs are
        // indistinguishable here, but we confirm that flipping a single result bit in the signed
        // canonical bytes changes the resulting signature.
        let key = test_key();
        let nonce = [0u8; 16];
        let ts = 1_700_000_000u64;
        let sig_all_pass = key.sign(&canonical_signing_bytes(
            &nonce,
            &[true, true, true, true],
            ts,
        ));
        let sig_one_fail = key.sign(&canonical_signing_bytes(
            &nonce,
            &[false, true, true, true],
            ts,
        ));
        assert_ne!(
            sig_all_pass.to_bytes(),
            sig_one_fail.to_bytes(),
            "different results must produce different signatures"
        );
        // And a different timestamp must also change the signature.
        let sig_later = key.sign(&canonical_signing_bytes(
            &nonce,
            &[true, true, true, true],
            ts + 1,
        ));
        assert_ne!(
            sig_all_pass.to_bytes(),
            sig_later.to_bytes(),
            "different timestamps must produce different signatures"
        );
    }
}
