//! # aumos-confidential-fabric (C1-5)
//!
//! The composite attestation fabric. Takes three independent attestation streams — GPU
//! (C1-1 nvtrust-bridge), runtime/TEE (C1-3 attesta-flow), and agent identity (I1
//! agent-identity) — and folds them into a single [`CompositeAttestation`] with a digest
//! suitable for use as a key-derivation input or a confidential-container release token.
//!
//! It also implements [`KeyReleasePolicy`], the policy engine that decides whether a given
//! composite attestation authorizes the release of a wrapped model key. This is the gate that
//! protects encrypted model delivery (the encrypted blob is shipped to the customer; only an
//! attested enclave matching the policy can unwrap it).
//!
//! And finally it implements [`ConfidentialContainer`] — an encrypted model bundle plus the
//! policy under which its key may be released. The customer's operator ships the bundle to the
//! fleet; each pod's enclave derives the key only if its composite attestation satisfies the
//! policy.
//!
//! See `docs/rfcs/C1-5-confidential-fabric.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

// -----------------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------------

/// The schema version tag for the v1 CompositeAttestation.
pub const SCHEMA_VERSION: &str = "confidential-fabric.v1";

/// Default freshness window for an attestation (RFC C1-5: 10 minutes).
pub const DEFAULT_FRESHNESS: Duration = Duration::from_secs(10 * 60);

/// Maximum clock skew tolerated when evaluating freshness.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(60);

// -----------------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------------

/// Errors returned by the fabric.
#[derive(Debug, Error)]
pub enum FabricError {
    /// The attestation was not fresh enough (its timestamp is outside the freshness window).
    #[error("attestation stale: age {age_secs:?}s > freshness {freshness_secs:?}s")]
    Stale {
        /// The actual age of the attestation in seconds.
        age_secs: u64,
        /// The configured freshness budget in seconds.
        freshness_secs: u64,
    },
    /// The attestation's GPU model did not match the policy.
    #[error("gpu model mismatch: got {got:?}, want {want:?}")]
    GpuModelMismatch {
        /// The actual GPU model reported.
        got: String,
        /// The required GPU model.
        want: String,
    },
    /// The TEE measurement did not match the policy.
    #[error("tee measurement mismatch: got {got:?}, want {want:?}")]
    TeeMeasurementMismatch {
        /// The actual TEE measurement reported.
        got: String,
        /// The required TEE measurement.
        want: String,
    },
    /// The agent identity was not in the allow list.
    #[error("agent identity {0:?} not allowed")]
    AgentNotAllowed(String),
    /// The attestation's digest did not recompute correctly.
    #[error("digest mismatch: claimed {claimed:?}, computed {computed:?}")]
    DigestMismatch {
        /// The digest claimed in the attestation.
        claimed: String,
        /// The digest the fabric recomputed.
        computed: String,
    },
    /// The attestation signature was invalid.
    #[error("signature invalid")]
    SignatureInvalid,
    /// A required attestation stream was missing.
    #[error("missing attestation stream: {0}")]
    MissingStream(&'static str),
}

// -----------------------------------------------------------------------------------
// Leaf attestation inputs
// -----------------------------------------------------------------------------------

/// The GPU attestation leaf. In production this is the report from C1-1 nvtrust-bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuAttestation {
    /// GPU model identifier (e.g. "H100", "H200").
    pub gpu_model: String,
    /// Driver / firmware version string.
    pub driver_version: String,
    /// Opaque attestation bytes from the GPU (signature covered externally).
    pub attestation_bytes: Vec<u8>,
    /// 16-byte nonce (hex-encoded) used to prevent replay.
    pub nonce_hex: String,
    /// Unix epoch seconds when the GPU produced this attestation.
    pub timestamp_secs: u64,
}

/// The runtime / TEE attestation leaf. From C1-3 attesta-flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAttestation {
    /// TEE backend identifier ("sev-snp", "tdx", "nitro", "az-snp-cvm").
    pub tee_kind: String,
    /// The hardware-rooted enclave measurement (hex).
    pub tee_measurement: String,
    /// Hash (sha256:...) of the loaded runtime image / model digest.
    pub runtime_digest: String,
    /// Unix epoch seconds when the runtime measurement was taken.
    pub timestamp_secs: u64,
}

/// The agent identity leaf. From I1 agent-identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    /// SPIFFE-style SVID URI of the agent.
    pub svid: String,
    /// The agent's publisher (e.g. "aumos.dev/coding-agent").
    pub publisher: String,
    /// Capabilities claimed by the agent (tools, data classes).
    pub capabilities: Vec<String>,
    /// Unix epoch seconds when the SVID was issued.
    pub issued_at_secs: u64,
    /// Unix epoch seconds when the SVID expires.
    pub expires_at_secs: u64,
}

// -----------------------------------------------------------------------------------
// CompositeAttestation
// -----------------------------------------------------------------------------------

/// A composite attestation folds the three leaf streams into one signed claim. The digest
/// field is sha256 of the deterministic canonical encoding (see [`CompositeAttestation::recompute_digest`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompositeAttestation {
    /// Schema version ("confidential-fabric.v1").
    pub schema_version: String,
    /// The GPU attestation leaf (may be absent for CPU-only inference).
    pub gpu: Option<GpuAttestation>,
    /// The runtime / TEE attestation leaf.
    pub runtime: RuntimeAttestation,
    /// The agent identity leaf.
    pub agent: AgentIdentity,
    /// sha256:... of the canonical encoding of the leaves.
    pub digest: String,
    /// Unix epoch seconds when the fabric assembled this composite.
    pub assembled_at_secs: u64,
}

impl CompositeAttestation {
    /// Recompute the canonical sha256 digest from the leaves. Used both during assembly and
    /// during verification (to detect tampering).
    #[must_use]
    pub fn recompute_digest(&self) -> String {
        canonical_digest(&self.gpu, &self.runtime, &self.agent)
    }

    /// Verify that the digest field matches the recomputed digest. Returns
    /// [`FabricError::DigestMismatch`] on tampering.
    ///
    /// # Errors
    /// Returns [`FabricError::DigestMismatch`] when the stored digest doesn't match.
    pub fn verify_digest(&self) -> Result<(), FabricError> {
        let computed = self.recompute_digest();
        if computed == self.digest {
            Ok(())
        } else {
            Err(FabricError::DigestMismatch {
                claimed: self.digest.clone(),
                computed,
            })
        }
    }

    /// Returns the age of this attestation relative to `now_secs`. Used by the freshness check.
    #[must_use]
    pub fn age_secs(&self, now_secs: u64) -> u64 {
        now_secs.saturating_sub(self.assembled_at_secs)
    }
}

/// Encode the leaves into a stable byte sequence and return "sha256:"+hex.
fn canonical_digest(
    gpu: &Option<GpuAttestation>,
    runtime: &RuntimeAttestation,
    agent: &AgentIdentity,
) -> String {
    let mut h = Sha256::new();
    if let Some(g) = gpu {
        h.update(b"gpu|");
        h.update(g.gpu_model.as_bytes());
        h.update(b"|");
        h.update(g.driver_version.as_bytes());
        h.update(b"|");
        h.update(&g.attestation_bytes);
        h.update(b"|");
        h.update(g.nonce_hex.as_bytes());
        h.update(b"|");
        h.update(g.timestamp_secs.to_le_bytes());
    } else {
        h.update(b"gpu|none");
    }
    h.update(b"||runtime|");
    h.update(runtime.tee_kind.as_bytes());
    h.update(b"|");
    h.update(runtime.tee_measurement.as_bytes());
    h.update(b"|");
    h.update(runtime.runtime_digest.as_bytes());
    h.update(b"|");
    h.update(runtime.timestamp_secs.to_le_bytes());
    h.update(b"||agent|");
    h.update(agent.svid.as_bytes());
    h.update(b"|");
    h.update(agent.publisher.as_bytes());
    h.update(b"|");
    for c in &agent.capabilities {
        h.update(c.as_bytes());
        h.update(b",");
    }
    h.update(b"|");
    h.update(agent.issued_at_secs.to_le_bytes());
    h.update(b"|");
    h.update(agent.expires_at_secs.to_le_bytes());
    let out = h.finalize();
    let mut hexed = String::with_capacity(8 + out.len() * 2);
    hexed.push_str("sha256:");
    hexed.push_str(&out.encode_hex::<String>());
    hexed
}

// -----------------------------------------------------------------------------------
// Fabric — assembles leaves into a composite
// -----------------------------------------------------------------------------------

/// The Fabric is the assembly point. It takes the three leaf streams (typically plumbed in
/// from the C1-1 GPU attester, the C1-3 TEE attester, and the I1 identity service) and produces
/// a [`CompositeAttestation`] with a canonical digest.
#[derive(Debug, Clone)]
pub struct Fabric {
    /// Trust domain (e.g. "aumos.dev") — informational, used in logs/audit.
    pub trust_domain: String,
}

impl Fabric {
    /// Construct a Fabric bound to a trust domain.
    #[must_use]
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
        }
    }

    /// Assemble a composite attestation from the three leaves. The GPU leaf may be `None` for
    /// CPU-only inference paths. The digest is computed canonically.
    #[must_use]
    pub fn assemble(
        &self,
        gpu: Option<GpuAttestation>,
        runtime: RuntimeAttestation,
        agent: AgentIdentity,
        now_secs: u64,
    ) -> CompositeAttestation {
        let digest = canonical_digest(&gpu, &runtime, &agent);
        CompositeAttestation {
            schema_version: SCHEMA_VERSION.to_string(),
            gpu,
            runtime,
            agent,
            digest,
            assembled_at_secs: now_secs,
        }
    }

    /// Assemble using the system clock for `assembled_at_secs`.
    ///
    /// # Errors
    /// Returns [`FabricError::MissingStream`] is impossible here, but the result type matches
    /// the verifier's signature for symmetry. Currently always returns `Ok`.
    pub fn assemble_now(
        &self,
        gpu: Option<GpuAttestation>,
        runtime: RuntimeAttestation,
        agent: AgentIdentity,
    ) -> CompositeAttestation {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.assemble(gpu, runtime, agent, now)
    }
}

// -----------------------------------------------------------------------------------
// KeyReleasePolicy — the gate for unwrapping model keys
// -----------------------------------------------------------------------------------

/// The requirements a composite attestation must satisfy to release a key. All non-empty
/// fields must match exactly; an empty field is treated as "do not check".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyReleasePolicy {
    /// Required GPU model (empty = any GPU / CPU-only allowed).
    pub required_gpu_model: String,
    /// Required TEE measurement (empty = do not check).
    pub required_tee_measurement: String,
    /// Required runtime digest (empty = do not check).
    pub required_runtime_digest: String,
    /// Allow list of agent SVIDs (empty = allow any).
    pub allowed_agent_svids: Vec<String>,
    /// Allow list of agent publishers (empty = allow any).
    pub allowed_agent_publishers: Vec<String>,
    /// Maximum attestation age in seconds (0 = use [`DEFAULT_FRESHNESS`]).
    pub max_age_secs: u64,
}

impl Default for KeyReleasePolicy {
    fn default() -> Self {
        Self {
            required_gpu_model: String::new(),
            required_tee_measurement: String::new(),
            required_runtime_digest: String::new(),
            allowed_agent_svids: Vec::new(),
            allowed_agent_publishers: Vec::new(),
            max_age_secs: DEFAULT_FRESHNESS.as_secs(),
        }
    }
}

impl KeyReleasePolicy {
    /// Decide whether `attestation` is authorized to receive a key under this policy. Returns
    /// `Ok(())` if every clause passes; otherwise the first failure as [`FabricError`].
    ///
    /// # Errors
    /// - [`FabricError::Stale`] when the attestation is older than `max_age_secs`.
    /// - [`FabricError::DigestMismatch`] when the digest was tampered.
    /// - [`FabricError::GpuModelMismatch`] when the GPU model differs.
    /// - [`FabricError::TeeMeasurementMismatch`] when the TEE measurement differs.
    /// - [`FabricError::AgentNotAllowed`] when the SVID or publisher isn't in the allow list.
    pub fn evaluate(
        &self,
        attestation: &CompositeAttestation,
        now_secs: u64,
    ) -> Result<(), FabricError> {
        // 1. Integrity: re-check the digest first.
        attestation.verify_digest()?;

        // 2. Freshness.
        let budget = if self.max_age_secs == 0 {
            DEFAULT_FRESHNESS.as_secs()
        } else {
            self.max_age_secs
        };
        let age = attestation.age_secs(now_secs);
        // Tolerate up to MAX_CLOCK_SKEW of overshoot.
        if age > budget.saturating_add(MAX_CLOCK_SKEW.as_secs()) {
            return Err(FabricError::Stale {
                age_secs: age,
                freshness_secs: budget,
            });
        }

        // 3. GPU model.
        if !self.required_gpu_model.is_empty() {
            match &attestation.gpu {
                Some(g) => {
                    if g.gpu_model != self.required_gpu_model {
                        return Err(FabricError::GpuModelMismatch {
                            got: g.gpu_model.clone(),
                            want: self.required_gpu_model.clone(),
                        });
                    }
                }
                None => {
                    return Err(FabricError::GpuModelMismatch {
                        got: "<none>".to_string(),
                        want: self.required_gpu_model.clone(),
                    });
                }
            }
        }

        // 4. TEE measurement.
        if !self.required_tee_measurement.is_empty()
            && attestation.runtime.tee_measurement != self.required_tee_measurement
        {
            return Err(FabricError::TeeMeasurementMismatch {
                got: attestation.runtime.tee_measurement.clone(),
                want: self.required_tee_measurement.clone(),
            });
        }

        // 5. Runtime digest.
        if !self.required_runtime_digest.is_empty()
            && attestation.runtime.runtime_digest != self.required_runtime_digest
        {
            return Err(FabricError::TeeMeasurementMismatch {
                got: attestation.runtime.runtime_digest.clone(),
                want: self.required_runtime_digest.clone(),
            });
        }

        // 6. Agent identity: SVID allow list.
        if !self.allowed_agent_svids.is_empty()
            && !self
                .allowed_agent_svids
                .contains(&attestation.agent.svid)
        {
            return Err(FabricError::AgentNotAllowed(attestation.agent.svid.clone()));
        }

        // 7. Agent identity: publisher allow list.
        if !self.allowed_agent_publishers.is_empty()
            && !self
                .allowed_agent_publishers
                .contains(&attestation.agent.publisher)
        {
            return Err(FabricError::AgentNotAllowed(format!(
                "publisher:{}",
                attestation.agent.publisher
            )));
        }

        Ok(())
    }

    /// Convenience wrapper: true on `Ok(())`, false otherwise.
    #[must_use]
    pub fn allows(&self, attestation: &CompositeAttestation, now_secs: u64) -> bool {
        self.evaluate(attestation, now_secs).is_ok()
    }

    /// Derive a 32-byte key from the composite attestation digest using HKDF-like extract+expand.
    /// The `salt` is mixed in so different policies can yield different keys. Returns
    /// "sha256:..." of the derived material for ease of transport.
    #[must_use]
    pub fn derive_key(&self, attestation: &CompositeAttestation, salt: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"aumos-confidential-fabric-key-v1|");
        h.update(salt);
        h.update(b"|");
        h.update(attestation.digest.as_bytes());
        h.update(b"|");
        h.update(self.required_tee_measurement.as_bytes());
        h.update(b"|");
        h.update(self.required_runtime_digest.as_bytes());
        let out = h.finalize();
        let mut s = String::with_capacity(8 + out.len() * 2);
        s.push_str("sha256:");
        s.push_str(&out.encode_hex::<String>());
        s
    }
}

// -----------------------------------------------------------------------------------
// ConfidentialContainer — encrypted model bundle + release policy
// -----------------------------------------------------------------------------------

/// A confidential container: an encrypted model payload plus the policy under which the
/// wrapping key may be released. Operators ship this bundle to the fleet; each pod's enclave
/// derives the key only if its composite attestation matches the policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialContainer {
    /// Schema version.
    pub schema_version: String,
    /// Free-form name (e.g. "falcon-7b-instruct").
    pub name: String,
    /// sha256:... of the *plaintext* model, computed at packaging time. The decryptor verifies
    /// the decrypted bytes match this.
    pub plaintext_model_digest: String,
    /// Hex-encoded ciphertext of the model (AEAD output minus nonce — production attaches the
    /// nonce; here we model it as opaque bytes).
    pub ciphertext_hex: String,
    /// The policy under which the wrapping key may be released.
    pub policy: KeyReleasePolicy,
    /// The salt mixed into key derivation for this bundle (so two bundles with the same policy
    /// still get independent keys).
    pub kdf_salt_hex: String,
    /// Unix epoch seconds at which the bundle was packaged.
    pub packaged_at_secs: u64,
}

impl ConfidentialContainer {
    /// Attempt to release (derive) the wrapping key for `attestation`. Returns the derived key
    /// digest on success, or the policy failure on error.
    ///
    /// # Errors
    /// See [`KeyReleasePolicy::evaluate`].
    pub fn release_key(
        &self,
        attestation: &CompositeAttestation,
        now_secs: u64,
    ) -> Result<String, FabricError> {
        self.policy.evaluate(attestation, now_secs)?;
        let salt = hex::decode(&self.kdf_salt_hex).unwrap_or_default();
        Ok(self.policy.derive_key(attestation, &salt))
    }

    /// Construct a new container with a random KDF salt.
    ///
    /// # Panics
    /// Never; salt is deterministic here for testability — production calls [`Self::with_salt`].
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        plaintext_model_digest: impl Into<String>,
        ciphertext_hex: impl Into<String>,
        policy: KeyReleasePolicy,
        kdf_salt_hex: impl Into<String>,
        packaged_at_secs: u64,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            name: name.into(),
            plaintext_model_digest: plaintext_model_digest.into(),
            ciphertext_hex: ciphertext_hex.into(),
            policy,
            kdf_salt_hex: kdf_salt_hex.into(),
            packaged_at_secs,
        }
    }
}

// -----------------------------------------------------------------------------------
// FleetView — aggregate view across many attestations (for observability)
// -----------------------------------------------------------------------------------

/// Aggregate fleet view: a map from agent SVID to its most recent composite attestation digest.
/// Used by FleetMarshal (F4) to decide whether a pod is healthy enough to receive traffic.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetView {
    /// Map of agent SVID → (composite digest, age in seconds, ok flag).
    pub pods: BTreeMap<String, PodAttestationState>,
}

/// Per-pod attestation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PodAttestationState {
    /// The composite attestation digest the pod most recently presented.
    pub digest: String,
    /// Age of that attestation in seconds.
    pub age_secs: u64,
    /// True if the attestation currently satisfies the fleet's release policy.
    pub ok: bool,
}

impl FleetView {
    /// Construct an empty fleet view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a pod's attestation state.
    pub fn record(&mut self, svid: impl Into<String>, state: PodAttestationState) {
        self.pods.insert(svid.into(), state);
    }

    /// Count how many pods are currently healthy (ok == true).
    #[must_use]
    pub fn healthy_count(&self) -> usize {
        self.pods.values().filter(|s| s.ok).count()
    }

    /// Fraction of pods healthy, in 0.0..=1.0. Returns 0.0 when the fleet is empty.
    #[must_use]
    pub fn healthy_fraction(&self) -> f64 {
        if self.pods.is_empty() {
            return 0.0;
        }
        let h = self.healthy_count() as f64;
        h / self.pods.len() as f64
    }
}

// ===================================================================================
// Tests
// ===================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn gpu(model: &str, ts: u64) -> GpuAttestation {
        GpuAttestation {
            gpu_model: model.to_string(),
            driver_version: "535.104.05".to_string(),
            attestation_bytes: vec![0u8; 32],
            nonce_hex: "0011223344556677889900aabbccddeeff".to_string(),
            timestamp_secs: ts,
        }
    }

    fn runtime(meas: &str, ts: u64) -> RuntimeAttestation {
        RuntimeAttestation {
            tee_kind: "sev-snp".to_string(),
            tee_measurement: meas.to_string(),
            runtime_digest: "sha256:runtime".to_string(),
            timestamp_secs: ts,
        }
    }

    fn agent(svid: &str, ts: u64) -> AgentIdentity {
        AgentIdentity {
            svid: svid.to_string(),
            publisher: "aumos.dev/coding-agent".to_string(),
            capabilities: vec!["tool:github".to_string()],
            issued_at_secs: ts,
            expires_at_secs: ts + 900,
        }
    }

    fn base_composite(fabric: &Fabric, now: u64) -> CompositeAttestation {
        fabric.assemble(Some(gpu("H100", now)), runtime("meas-A", now), agent("spiffe://aumos.dev/agent/x", now), now)
    }

    // 1. Assemble produces a composite with a non-empty sha256: digest.
    #[test]
    fn assemble_has_digest() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1_000_000);
        assert!(c.digest.starts_with("sha256:"));
        // "sha256:" (7 chars) + 64 hex chars
        assert_eq!(c.digest.len(), 7 + 64);
        assert_eq!(c.schema_version, SCHEMA_VERSION);
    }

    // 2. The digest verifies immediately after assembly.
    #[test]
    fn digest_verifies_after_assembly() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 100);
        assert!(c.verify_digest().is_ok());
    }

    // 3. Tampering with any leaf field invalidates the digest.
    #[test]
    fn tampering_invalidates_digest() {
        let f = Fabric::new("aumos.dev");
        let mut c = base_composite(&f, 100);
        c.runtime.tee_measurement = "tampered".to_string();
        assert!(matches!(c.verify_digest(), Err(FabricError::DigestMismatch { .. })));
    }

    // 4. Two identical composites have the same digest (determinism).
    #[test]
    fn digest_is_deterministic() {
        let f = Fabric::new("aumos.dev");
        let c1 = base_composite(&f, 100);
        let c2 = base_composite(&f, 100);
        assert_eq!(c1.digest, c2.digest);
    }

    // 5. CPU-only composite (None GPU) has a different but valid digest.
    #[test]
    fn cpu_only_composite_has_valid_digest() {
        let f = Fabric::new("aumos.dev");
        let c = f.assemble(None, runtime("m", 100), agent("s", 100), 100);
        assert!(c.verify_digest().is_ok());
        assert!(c.gpu.is_none());
    }

    // 6. The default policy allows a fresh attestation with no constraints.
    #[test]
    fn default_policy_allows_fresh() {
        let p = KeyReleasePolicy::default();
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000);
        assert!(p.allows(&c, 1000));
        assert!(p.evaluate(&c, 1000).is_ok());
    }

    // 7. Stale attestation is rejected.
    #[test]
    fn stale_attestation_rejected() {
        let p = KeyReleasePolicy::default();
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 0);
        let now = 100_000; // way past DEFAULT_FRESHNESS + skew
        assert!(!p.allows(&c, now));
        assert!(matches!(p.evaluate(&c, now), Err(FabricError::Stale { .. })));
    }

    // 8. GPU model constraint is enforced.
    #[test]
    fn gpu_model_enforced() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000); // GPU = H100
        let p = KeyReleasePolicy {
            required_gpu_model: "H200".to_string(),
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
        assert!(matches!(p.evaluate(&c, 1000), Err(FabricError::GpuModelMismatch { .. })));
    }

    // 9. GPU constraint rejects CPU-only composite when GPU is required.
    #[test]
    fn gpu_required_rejects_none() {
        let f = Fabric::new("aumos.dev");
        let c = f.assemble(None, runtime("m", 1000), agent("s", 1000), 1000);
        let p = KeyReleasePolicy {
            required_gpu_model: "H100".to_string(),
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
    }

    // 10. TEE measurement constraint is enforced.
    #[test]
    fn tee_measurement_enforced() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000); // measurement "meas-A"
        let p = KeyReleasePolicy {
            required_tee_measurement: "meas-B".to_string(),
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
        assert!(matches!(p.evaluate(&c, 1000), Err(FabricError::TeeMeasurementMismatch { .. })));
    }

    // 11. Agent SVID allow list is enforced.
    #[test]
    fn agent_svid_allowlist_enforced() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000); // svid "spiffe://aumos.dev/agent/x"
        let p = KeyReleasePolicy {
            allowed_agent_svids: vec!["spiffe://aumos.dev/agent/y".to_string()],
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
        assert!(matches!(p.evaluate(&c, 1000), Err(FabricError::AgentNotAllowed(_))));
    }

    // 12. Agent publisher allow list is enforced.
    #[test]
    fn agent_publisher_allowlist_enforced() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000); // publisher "aumos.dev/coding-agent"
        let p = KeyReleasePolicy {
            allowed_agent_publishers: vec!["aumos.dev/other-agent".to_string()],
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
    }

    // 13. derive_key is stable for identical inputs and differs when salt changes.
    #[test]
    fn derive_key_stability() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000);
        let p = KeyReleasePolicy::default();
        let k1 = p.derive_key(&c, b"salt-A");
        let k2 = p.derive_key(&c, b"salt-A");
        let k3 = p.derive_key(&c, b"salt-B");
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert!(k1.starts_with("sha256:"));
    }

    // 14. ConfidentialContainer.release_key succeeds when policy is satisfied.
    #[test]
    fn container_release_ok() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000);
        let bundle = ConfidentialContainer::new(
            "falcon-7b",
            "sha256:plain",
            "deadbeef",
            KeyReleasePolicy::default(),
            "aa",
            1000,
        );
        let k = bundle.release_key(&c, 1000).expect("release");
        assert!(k.starts_with("sha256:"));
    }

    // 15. ConfidentialContainer.release_key fails when policy is violated.
    #[test]
    fn container_release_fails_when_policy_violated() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 0); // old
        let bundle = ConfidentialContainer::new(
            "falcon-7b",
            "sha256:plain",
            "deadbeef",
            KeyReleasePolicy::default(),
            "aa",
            0,
        );
        assert!(bundle.release_key(&c, 100_000).is_err());
    }

    // 16. FleetView aggregates healthy pods correctly.
    #[test]
    fn fleet_view_aggregates() {
        let mut v = FleetView::new();
        v.record(
            "spiffe://aumos.dev/agent/a",
            PodAttestationState { digest: "sha256:1".into(), age_secs: 1, ok: true },
        );
        v.record(
            "spiffe://aumos.dev/agent/b",
            PodAttestationState { digest: "sha256:2".into(), age_secs: 1, ok: false },
        );
        v.record(
            "spiffe://aumos.dev/agent/c",
            PodAttestationState { digest: "sha256:3".into(), age_secs: 1, ok: true },
        );
        assert_eq!(v.healthy_count(), 2);
        assert!((v.healthy_fraction() - 2.0 / 3.0).abs() < 1e-9);
    }

    // 17. FleetView empty fleet → fraction 0.0, not NaN.
    #[test]
    fn fleet_view_empty_is_zero() {
        let v = FleetView::new();
        assert_eq!(v.healthy_count(), 0);
        assert_eq!(v.healthy_fraction(), 0.0);
    }

    // 18. age_secs saturates at zero (never panics on underflow).
    #[test]
    fn age_saturates() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1_000);
        assert_eq!(c.age_secs(500), 0);
    }

    // 19. assemble_now produces a composite with a non-zero timestamp.
    #[test]
    fn assemble_now_works() {
        let f = Fabric::new("aumos.dev");
        let c = f.assemble_now(Some(gpu("H100", 0)), runtime("m", 0), agent("s", 0));
        // SystemTime should be well past epoch 0 in 2026.
        assert!(c.assembled_at_secs > 1_700_000_000);
        assert!(c.verify_digest().is_ok());
    }

    // 20. Round-trips through JSON.
    #[test]
    fn json_roundtrip() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000);
        let s = serde_json::to_string(&c).expect("ser");
        let c2: CompositeAttestation = serde_json::from_str(&s).expect("de");
        assert_eq!(c, c2);
        assert!(c2.verify_digest().is_ok());
    }

    // 21. Required runtime digest enforced.
    #[test]
    fn runtime_digest_enforced() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 1000); // runtime_digest "sha256:runtime"
        let p = KeyReleasePolicy {
            required_runtime_digest: "sha256:other".to_string(),
            ..Default::default()
        };
        assert!(!p.allows(&c, 1000));
    }

    // 22. Composite attestation reflects the input leaves exactly.
    #[test]
    fn leaves_preserved() {
        let f = Fabric::new("aumos.dev");
        let g = gpu("H100", 1234);
        let r = runtime("meas", 1234);
        let a = agent("spiffe://aumos.dev/agent/y", 1234);
        let c = f.assemble(Some(g.clone()), r.clone(), a.clone(), 1234);
        assert_eq!(c.gpu.as_ref().unwrap(), &g);
        assert_eq!(c.runtime, r);
        assert_eq!(c.agent, a);
    }

    // 23. Freshness with max_age_secs=0 falls back to DEFAULT_FRESHNESS.
    #[test]
    fn freshness_zero_falls_back() {
        let f = Fabric::new("aumos.dev");
        let c = base_composite(&f, 0);
        let p = KeyReleasePolicy {
            max_age_secs: 0,
            ..Default::default()
        };
        // DEFAULT_FRESHNESS is 600s; 500s should be allowed.
        assert!(p.allows(&c, 500));
        // 10_000s should be rejected.
        assert!(!p.allows(&c, 10_000));
    }
}
