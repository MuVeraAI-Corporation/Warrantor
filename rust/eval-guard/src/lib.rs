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
//! ## The one thing it now refuses to let a caller omit (Task 13.7)
//!
//! It could not previously say *where the booleans came from*, and its CLI supplied
//! [`CheckResults::all_pass`] by default -- so the shipped binary, run on a developer's laptop in
//! no sandbox at all, emitted a signed attestation asserting that four boundaries held. The
//! signature was real and the claim inside it was manufactured by the default value of an argument
//! nobody passed.
//!
//! [`Provenance`] closes that. It is a required argument to [`run_preflight`], it participates in
//! the signed bytes, and the CLI has no default for it: a caller who cannot name a source can no
//! longer be handed a signature.
//!
//! **Read [`Provenance::Measured`] exactly as far as it goes.** It records that the *caller says* a
//! named probe produced the boolean. This crate still opens no sockets and inspects no namespaces,
//! so it cannot tell a real probe from an invented probe name. What changed is that the claim is
//! now attributed and non-omittable rather than absent -- a reviewer can go and look for
//! `netns-probe/1` and find that it does not exist. That is weaker than measurement and stronger
//! than silence, and calling it measurement would repeat the defect this field exists to fix.
//!
//! ## What it does do, and does correctly
//!
//! Given results, it fails closed: any false boundary yields [`EvalGuardError::CheckFailed`] and
//! no attestation is produced (invariant I-09). The signature and canonical encoding are real.
//!
//! Warrantor moved this from Go to Rust per the trusted-core doctrine (see RFC R2).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
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

/// Where the four booleans in [`CheckResults`] came from.
///
/// # Why this is required rather than defaulted
///
/// A signature over four booleans is worth exactly what the booleans are worth, and before this
/// existed the attestation carried no field saying who decided them. The CLI defaulted them to
/// [`CheckResults::all_pass`], so the shipped binary produced a signed "all four boundaries held"
/// on a host with no sandbox on it. There is deliberately no `Default` and no CLI default: the
/// absent-limit rule this workspace applies to bounds applies here too, and an unnamed source is
/// the one case where a signature actively misleads.
///
/// # `Measured` is the caller's word, not this crate's measurement
///
/// This crate has no eBPF, opens no sockets and inspects no namespaces (see the crate docs). It
/// cannot check that `probe` ran, or that it exists. [`Self::Measured`] therefore records an
/// *attributed* claim: a reviewer holding the attestation can go and look for the named probe. That
/// is worth having and it is not evidence of isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// The caller says a named probe ran and returned this boolean.
    Measured {
        /// The probe, named so a reader can go and look for it. Never empty.
        probe: String,
    },
    /// A caller asserted the boolean with no probe behind it.
    Asserted {
        /// Who asserted it. Never empty -- an anonymous assertion is the case this type exists
        /// to stop.
        by: String,
    },
}

impl Provenance {
    /// The stable wire word. Equal to the serde tag value.
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Self::Measured { .. } => "measured",
            Self::Asserted { .. } => "asserted",
        }
    }

    /// The named source: the probe, or the asserting party.
    #[must_use]
    pub fn source(&self) -> &str {
        match self {
            Self::Measured { probe } => probe,
            Self::Asserted { by } => by,
        }
    }

    /// What this provenance does NOT establish, in one clause that ships with it.
    #[must_use]
    pub fn caveat(&self) -> &'static str {
        match self {
            Self::Measured { .. } => {
                "the caller named a probe; this crate did not run it and cannot tell whether it \
                 exists, so the boolean is attributed rather than verified"
            }
            Self::Asserted { .. } => {
                "nothing measured this boundary; a named party asserted it and the signature \
                 covers the assertion, not the boundary"
            }
        }
    }

    /// Parse `measured:<probe>` or `asserted:<name>`.
    ///
    /// Split on the FIRST colon only, so `asserted:operator:vj` names `operator:vj` rather than
    /// being refused for having two.
    ///
    /// # Errors
    /// A sentence naming the two forms. There is no fallback: guessing a source would put a
    /// fabricated one into the signed bytes, which is the defect and not a convenience.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (kind, source) = raw.split_once(':').ok_or_else(|| {
            format!(
                "{raw:?} is not a provenance. Write measured:<probe> or asserted:<who>. There is \
                 no default: a signature over four booleans whose source is unnamed is the one \
                 case where this attestation actively misleads its reader."
            )
        })?;
        let source = source.trim();
        if source.is_empty() {
            return Err(format!(
                "{raw:?} names a kind and no source. A probe or a person has to be named, because \
                 the whole value of this field is that a reviewer can go and look for it."
            ));
        }
        match kind.trim() {
            "measured" => Ok(Self::Measured {
                probe: source.to_string(),
            }),
            "asserted" => Ok(Self::Asserted {
                by: source.to_string(),
            }),
            other => Err(format!(
                "{other:?} is not a provenance kind. The two are: measured, asserted."
            )),
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
    /// Where the four booleans came from. Participates in the signed bytes, so relabelling a
    /// measured attestation as an asserted one -- or the reverse -- invalidates the signature.
    pub provenance: Provenance,
    /// The 64-byte Ed25519 signature over the canonical encoding of
    /// (passed_checks, nonce, results, timestamp, provenance).
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
fn canonical_signing_bytes(
    nonce: &[u8],
    results: &[bool; 4],
    timestamp: u64,
    provenance: &Provenance,
) -> Vec<u8> {
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
    // Task 13.7: bind WHERE the results came from, on the same reasoning C3 applied to `results`
    // and `timestamp`. Both halves are length-prefixed rather than delimited: a source may contain
    // any byte a shell can pass, so `measured` + `x:y` and `measured:x` + `y` must not be able to
    // encode to the same bytes.
    for part in [provenance.word(), provenance.source()] {
        let bytes = part.as_bytes();
        canon.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
        canon.extend_from_slice(bytes);
    }
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
    provenance: &Provenance,
    signing_key: &SigningKey,
) -> Result<SandboxAttestation, EvalGuardError> {
    for (i, &check) in BoundaryCheck::ALL.iter().enumerate() {
        if !results.as_array()[i] {
            return Err(EvalGuardError::CheckFailed(check));
        }
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("system entropy source");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // C3: sign over the ACTUAL results and the timestamp, not just the constant
    // BoundaryCheck::ALL. A single attestation is therefore no longer a permanent skeleton key.
    let canon = canonical_signing_bytes(&nonce, &results.as_array(), timestamp, provenance);
    let sig = signing_key.sign(&canon);
    Ok(SandboxAttestation {
        passed_checks: BoundaryCheck::ALL.to_vec(),
        nonce: nonce.to_vec(),
        verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
        results: results.as_array(),
        timestamp,
        provenance: provenance.clone(),
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
    let canon = canonical_signing_bytes(
        &nonce_bytes,
        &attestation.results,
        attestation.timestamp,
        &attestation.provenance,
    );
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&canon, &sig)
        .map_err(|_| EvalGuardError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        let mut rng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
        SigningKey::generate(&mut rng)
    }

    fn measured() -> Provenance {
        Provenance::Measured {
            probe: "netns-probe/1".to_string(),
        }
    }

    fn asserted() -> Provenance {
        Provenance::Asserted {
            by: "operator:vj".to_string(),
        }
    }

    #[test]
    fn all_pass_returns_signed_attestation() {
        let key = test_key();
        let attestation =
            run_preflight(&CheckResults::all_pass(), &measured(), &key).expect("all pass");
        assert_eq!(attestation.passed_checks.len(), 4);
        verify_attestation(&attestation).expect("signature verifies");
    }

    // -- Task 13.7: the source of the four booleans is signed, and cannot be omitted -----------

    #[test]
    fn a_measured_pass_and_an_asserted_pass_do_not_produce_the_same_signed_bytes() {
        // The defect, made executable at the level it lives at. `canonical_signing_bytes` bound
        // checks, nonce, results and timestamp -- and nothing about where the results came from,
        // so a signature over an operator's guess and a signature over a probe's output were
        // byte-identical.
        //
        // Deviation from the plan, recorded in docs/task-evidence/task-13.7.md: the plan compared
        // the bytes of two `run_preflight` calls. Those differ unconditionally, because each call
        // draws a fresh 16-byte nonce -- so that assertion would have passed on the unfixed code
        // and proved nothing. The inputs are pinned here instead.
        let nonce = [7u8; 16];
        let results = [true; 4];
        let ts = 1_700_000_000u64;

        // CONTROL: identical inputs, provenance included, give identical bytes. Without this the
        // inequality below could be satisfied by nondeterminism rather than by the binding.
        assert_eq!(
            canonical_signing_bytes(&nonce, &results, ts, &measured()),
            canonical_signing_bytes(&nonce, &results, ts, &measured()),
            "control: the encoding must be deterministic, or the inequality below means nothing",
        );

        assert_ne!(
            canonical_signing_bytes(&nonce, &results, ts, &measured()),
            canonical_signing_bytes(&nonce, &results, ts, &asserted()),
            "a measured pass and an asserted pass must not produce the same signed bytes: the \
             signature would then say nothing about where four booleans came from, which is the \
             one thing a reader of an unmeasured attestation needs to know",
        );
    }

    #[test]
    fn an_attestation_relabelled_as_a_different_source_no_longer_verifies() {
        let key = test_key();

        // CONTROL: an honestly-sourced result still signs and still verifies. Without this the
        // assertion below would pass on a `run_preflight` that refused everything.
        let attestation = run_preflight(&CheckResults::all_pass(), &measured(), &key)
            .expect("a measured all-pass must still sign");
        assert_eq!(attestation.provenance, measured());
        verify_attestation(&attestation).expect("the control verifies");

        // An asserted all-pass may also sign -- this is not a gate on honesty, it is a gate on
        // silence -- and it must be distinguishable from the measured one.
        let asserted_attestation = run_preflight(&CheckResults::all_pass(), &asserted(), &key)
            .expect("an asserted all-pass may sign");
        assert_eq!(asserted_attestation.provenance, asserted());

        // The bound: rewriting the source on a signed attestation breaks the signature.
        let mut relabelled = attestation.clone();
        relabelled.provenance = asserted();
        assert!(
            matches!(
                verify_attestation(&relabelled),
                Err(EvalGuardError::SignatureInvalid)
            ),
            "relabelling a measured attestation as asserted must invalidate it; otherwise the \
             provenance field is a comment beside the signature rather than part of it",
        );
    }

    #[test]
    fn a_provenance_with_no_named_source_is_refused_rather_than_defaulted() {
        // CONTROL: both real forms parse, and a source containing a colon survives.
        assert_eq!(
            Provenance::parse("measured:netns-probe/1").expect("measured"),
            measured()
        );
        assert_eq!(
            Provenance::parse("asserted:operator:vj").expect("asserted"),
            asserted()
        );

        // Each refusal is checked against the sentence it should produce, not against a
        // disjunction that any error would satisfy.
        for (bad, expected) in [
            ("measured", "is not a provenance"),
            ("", "is not a provenance"),
            ("asserted:", "names a kind and no source"),
            ("measured:   ", "names a kind and no source"),
            ("probed:thing", "is not a provenance kind"),
        ] {
            let error = Provenance::parse(bad).expect_err("a source-less provenance is refused");
            assert!(
                error.contains(expected),
                "parsing {bad:?} must say {expected:?}; it said {error:?}",
            );
        }
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
            &measured(),
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
        let mut attestation =
            run_preflight(&CheckResults::all_pass(), &measured(), &key).expect("all pass");
        attestation.signature[0] ^= 0xff;
        assert!(matches!(
            verify_attestation(&attestation),
            Err(EvalGuardError::SignatureInvalid)
        ));
    }

    #[test]
    fn proto_round_trip_preserves_passed_checks() {
        let key = test_key();
        let attestation =
            run_preflight(&CheckResults::all_pass(), &measured(), &key).expect("all pass");
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
        let real = run_preflight(&CheckResults::all_pass(), &measured(), &key).expect("all pass");
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
            &measured(),
        ));
        let sig_one_fail = key.sign(&canonical_signing_bytes(
            &nonce,
            &[false, true, true, true],
            ts,
            &measured(),
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
            &measured(),
        ));
        assert_ne!(
            sig_all_pass.to_bytes(),
            sig_later.to_bytes(),
            "different timestamps must produce different signatures"
        );
    }
}
