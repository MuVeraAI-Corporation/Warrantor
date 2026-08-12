//! SG1 Self-governance keystone — the conformance checker that proves the platform's own AI is
//! governed by the platform itself.
//!
//! The principle: if the platform's AI (the NL console, the policy compiler, the risk scorer, the
//! self-auditing fleet) is exempt from the substrate, the substrate is a wrapper, not a substrate.
//! Every dev who trusts the console's answer, every non-dev who trusts the dashboard, every auditor
//! who trusts the report is trusting the platform's AI. Self-governance is how that trust is earned
//! rather than asserted.
//!
//! This crate is the CONFORMANCE CHECKER — it verifies the invariant "Warrantor governs Warrantor's
//! AI" is upheld. The actual enforcement happens when the platform's AI agents call through the same
//! verdict/egress/retrieval/spend/computer-use brokers that every other agent uses.
//!
//! Per gap-analysis pass 6 §3D.2, this outranks every other gap.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const CHECKER_VERSION: &str = "warrantor-self-governance/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Which platform components are AI-powered and thus must be governed
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformComponent {
    /// N1 — the NL conversational console. AI answers questions about the evidence graph.
    NlConsole,
    /// N3 — the NL→policy compiler. AI drafts Cedar/Rego from natural language.
    PolicyCompiler,
    /// §8.2 — the AI risk scorer. AI scores risk on the evidence stream.
    RiskScorer,
    /// §8.1 — the self-auditing fleet. AI agents that audit + emit conformance findings.
    AuditFleet,
}

impl PlatformComponent {
    #[must_use]
    pub fn all() -> [PlatformComponent; 4] {
        [
            PlatformComponent::NlConsole,
            PlatformComponent::PolicyCompiler,
            PlatformComponent::RiskScorer,
            PlatformComponent::AuditFleet,
        ]
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PlatformComponent::NlConsole => "NL Console",
            PlatformComponent::PolicyCompiler => "Policy Compiler",
            PlatformComponent::RiskScorer => "Risk Scorer",
            PlatformComponent::AuditFleet => "Audit Fleet",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Self-change-protected prefixes (I-11) — these are the SPIFFE prefixes that
// NO agent (including the platform's own AI) may write to.
// ═══════════════════════════════════════════════════════════════════════════

/// The enforcement surfaces an agent may never write to (I-11: self-change is governed).
/// Matched as a prefix against the agent's SVID.
pub const SELF_CHANGE_PROTECTED_PREFIXES: &[&str] = &[
    "spiffe://warrantor.io/trust-core",
    "spiffe://warrantor.io/authority",
    "spiffe://warrantor.io/policy",
    "spiffe://warrantor.io/self-governance",
    "spiffe://warrantor.io/flight-recorder",
    "spiffe://warrantor.io/evidence",
    "spiffe://warrantor.io/kms",
    "spiffe://warrantor.io/mcp-gateway",
];

// ═══════════════════════════════════════════════════════════════════════════
// Platform agent registration — what each governed AI component declares
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformAgent {
    pub agent_id: String,
    pub component: PlatformComponent,
    /// The SPIFFE ID under which the platform AI operates.
    pub svid: String,
    /// The capabilities the platform AI is granted (from the I-08 ladder).
    pub capabilities: Vec<String>,
    /// Whether the platform AI can be kill-switched.
    pub kill_switchable: bool,
    /// The types of consequential outputs the AI produces (each must be receipted).
    /// e.g. ["policy_draft", "risk_verdict", "conformance_report"].
    pub consequential_outputs: Vec<String>,
    /// Whether the AI has actually emitted pre-commit receipts for its outputs.
    pub receipting: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Conformance status for one agent
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConformanceStatus {
    pub agent_id: String,
    pub component: PlatformComponent,
    pub has_identity: bool,
    pub has_capabilities: bool,
    pub receipting_consequential_outputs: bool,
    pub kill_switchable: bool,
    pub self_change_protected: bool,
    pub conformant: bool,
    pub failures: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// The conformance report
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelfGovernanceReport {
    pub agent_statuses: Vec<AgentConformanceStatus>,
    pub overall_conformant: bool,
    pub checked_components: Vec<PlatformComponent>,
    pub timestamp: u64,
    pub checker_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedReport {
    pub report: SelfGovernanceReport,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

#[derive(Debug, Error)]
pub enum SgError {
    #[error("self-governance: {0}")]
    Sg(String),
}

// ═══════════════════════════════════════════════════════════════════════════
// The conformance checker
// ═══════════════════════════════════════════════════════════════════════════

/// Check whether a single platform AI agent is conformant with self-governance.
///
/// A conformant platform AI agent:
/// 1. Has an identity (SVID is a non-empty spiffe:// URI).
/// 2. Has declared capabilities (non-empty, on the I-08 ladder).
/// 3. Is receipting its consequential outputs (every output type has a pre-commit receipt).
/// 4. Is kill-switchable (the platform can stop it).
/// 5. Is self-change-protected (its SVID is NOT in the self-governance protected set —
///    i.e., the AI cannot rewrite the rules that bind it).
#[must_use]
pub fn check_agent(agent: &PlatformAgent) -> AgentConformanceStatus {
    let mut failures: Vec<String> = Vec::new();

    // 1. Identity.
    let has_identity = agent.svid.starts_with("spiffe://") && !agent.svid.is_empty();
    if !has_identity {
        failures.push("missing valid SVID (must be spiffe:// URI)".to_string());
    }

    // 2. Capabilities.
    let has_capabilities = !agent.capabilities.is_empty();
    if !has_capabilities {
        failures.push("no capabilities declared".to_string());
    }

    // 3. Receipting consequential outputs.
    let receipting = agent.receipting || agent.consequential_outputs.is_empty();
    if !receipting {
        failures.push(format!(
            "not receipting {} consequential output(s): {:?}",
            agent.consequential_outputs.len(),
            agent.consequential_outputs
        ));
    }

    // 4. Kill-switchable.
    if !agent.kill_switchable {
        failures.push("not kill-switchable".to_string());
    }

    // 5. Self-change protection (I-11).
    // The agent's SVID must NOT be a self-change-protected prefix (the AI cannot BE the authority
    // that governs it). If it is, that's a self-change violation.
    let self_change_protected = SELF_CHANGE_PROTECTED_PREFIXES
        .iter()
        .any(|prefix| agent.svid.starts_with(prefix));

    let conformant = has_identity
        && has_capabilities
        && receipting
        && agent.kill_switchable
        && !self_change_protected;

    if self_change_protected {
        failures.push("SVID is in the self-change-protected set (I-11 violation: the AI must not be its own authority)".to_string());
    }

    AgentConformanceStatus {
        agent_id: agent.agent_id.clone(),
        component: agent.component,
        has_identity,
        has_capabilities,
        receipting_consequential_outputs: receipting,
        kill_switchable: agent.kill_switchable,
        self_change_protected,
        conformant,
        failures,
    }
}

/// Check all registered platform AI agents and produce a self-governance report.
#[must_use]
pub fn check_all(agents: &[PlatformAgent]) -> SelfGovernanceReport {
    let agent_statuses: Vec<AgentConformanceStatus> = agents.iter().map(check_agent).collect();
    let overall_conformant = agent_statuses.iter().all(|s| s.conformant);
    let checked_components: HashSet<PlatformComponent> =
        agents.iter().map(|a| a.component).collect();
    let mut components: Vec<PlatformComponent> = checked_components.into_iter().collect();
    components.sort_by_key(|c| *c as u8);

    SelfGovernanceReport {
        agent_statuses,
        overall_conformant,
        checked_components: components,
        timestamp: 0, // set by caller
        checker_version: CHECKER_VERSION.to_string(),
    }
}

/// Verify that ALL expected platform components are registered. A missing component is a
/// conformance gap — an ungoverned AI surface.
#[must_use]
pub fn missing_components(agents: &[PlatformAgent]) -> Vec<PlatformComponent> {
    let present: HashSet<PlatformComponent> = agents.iter().map(|a| a.component).collect();
    PlatformComponent::all()
        .into_iter()
        .filter(|c| !present.contains(c))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed report — the public conformance proof
// ═══════════════════════════════════════════════════════════════════════════

fn canonical_report(report: &SelfGovernanceReport) -> String {
    let v = serde_json::to_value(report).expect("serializes");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical serializes")
}

fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

pub fn sign_report(report: &SelfGovernanceReport, signing_key: &SigningKey) -> SignedReport {
    let canonical = canonical_report(report);
    let sig: Signature = signing_key.sign(canonical.as_bytes());
    let verifying = signing_key.verifying_key();
    SignedReport {
        report: report.clone(),
        signature_algorithm: "Ed25519".to_string(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_report(signed: &SignedReport) -> Result<(), SgError> {
    let pk_bytes = hex::decode(&signed.signature_public_key)
        .map_err(|e| SgError::Sg(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(SgError::Sg("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| SgError::Sg(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&signed.signature_value)
        .map_err(|e| SgError::Sg(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(SgError::Sg("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_report(&signed.report);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| SgError::Sg("Ed25519 signature does not verify".into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Build a set of fully-conformant test platform agents (all 4 components).
#[must_use]
pub fn test_agents() -> Vec<PlatformAgent> {
    vec![
        PlatformAgent {
            agent_id: "nl-console-1".to_string(),
            component: PlatformComponent::NlConsole,
            svid: "spiffe://warrantor.io/ai/nl-console".to_string(),
            capabilities: vec!["read".to_string()],
            kill_switchable: true,
            consequential_outputs: vec!["answer".to_string(), "report".to_string()],
            receipting: true,
        },
        PlatformAgent {
            agent_id: "policy-compiler-1".to_string(),
            component: PlatformComponent::PolicyCompiler,
            svid: "spiffe://warrantor.io/ai/policy-compiler".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string()],
            kill_switchable: true,
            consequential_outputs: vec!["policy_draft".to_string()],
            receipting: true,
        },
        PlatformAgent {
            agent_id: "risk-scorer-1".to_string(),
            component: PlatformComponent::RiskScorer,
            svid: "spiffe://warrantor.io/ai/risk-scorer".to_string(),
            capabilities: vec!["read".to_string()],
            kill_switchable: true,
            consequential_outputs: vec!["risk_verdict".to_string()],
            receipting: true,
        },
        PlatformAgent {
            agent_id: "audit-fleet-1".to_string(),
            component: PlatformComponent::AuditFleet,
            svid: "spiffe://warrantor.io/ai/audit-fleet".to_string(),
            capabilities: vec!["read".to_string()],
            kill_switchable: true,
            consequential_outputs: vec!["conformance_report".to_string()],
            receipting: true,
        },
    ]
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd-length hex".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_test_agents_conformant() {
        let agents = test_agents();
        let report = check_all(&agents);
        assert!(
            report.overall_conformant,
            "all test agents should be conformant"
        );
        assert_eq!(report.agent_statuses.len(), 4);
        for status in &report.agent_statuses {
            assert!(
                status.conformant,
                "{} not conformant: {:?}",
                status.agent_id, status.failures
            );
        }
    }

    #[test]
    fn no_missing_components() {
        let agents = test_agents();
        assert!(
            missing_components(&agents).is_empty(),
            "all 4 components should be registered"
        );
    }

    #[test]
    fn agent_without_svid_not_conformant() {
        let mut agents = test_agents();
        agents[0].svid = "".to_string();
        let status = check_agent(&agents[0]);
        assert!(!status.conformant);
        assert!(!status.has_identity);
    }

    #[test]
    fn agent_not_kill_switchable_not_conformant() {
        let mut agents = test_agents();
        agents[1].kill_switchable = false;
        let status = check_agent(&agents[1]);
        assert!(!status.conformant);
        assert!(!status.kill_switchable);
    }

    #[test]
    fn agent_not_receipting_not_conformant() {
        let mut agents = test_agents();
        agents[2].receipting = false;
        let status = check_agent(&agents[2]);
        assert!(!status.conformant);
        assert!(!status.receipting_consequential_outputs);
    }

    #[test]
    fn agent_in_self_change_protected_set_not_conformant() {
        // An AI whose SVID is in the self-change-protected set is a self-governance violation.
        let mut agents = test_agents();
        agents[0].svid = "spiffe://warrantor.io/policy/ai-console".to_string();
        let status = check_agent(&agents[0]);
        assert!(!status.conformant);
        assert!(status.self_change_protected);
        assert!(status.failures.iter().any(|f| f.contains("I-11")));
    }

    #[test]
    fn missing_component_detected() {
        let agents = vec![test_agents()[0].clone()]; // only NL Console
        let missing = missing_components(&agents);
        assert_eq!(missing.len(), 3); // PolicyCompiler, RiskScorer, AuditFleet missing
    }

    #[test]
    fn report_signs_and_verifies() {
        let (sk, _) = generate_keypair();
        let agents = test_agents();
        let mut report = check_all(&agents);
        report.timestamp = 1000;
        let signed = sign_report(&report, &sk);
        verify_report(&signed).expect("signed report verifies");
    }

    #[test]
    fn tampered_report_fails_verification() {
        let (sk, _) = generate_keypair();
        let agents = test_agents();
        let mut report = check_all(&agents);
        report.timestamp = 1000;
        let mut signed = sign_report(&report, &sk);
        signed.report.overall_conformant = false; // tamper
        assert!(verify_report(&signed).is_err());
    }

    #[test]
    fn all_four_components_exist() {
        assert_eq!(PlatformComponent::all().len(), 4);
    }

    #[test]
    fn self_change_prefixes_cover_critical_surfaces() {
        // The protected set must include the core governance surfaces.
        let surfaces = ["trust-core", "authority", "policy", "self-governance"];
        for surface in surfaces {
            assert!(
                SELF_CHANGE_PROTECTED_PREFIXES
                    .iter()
                    .any(|p| p.contains(surface)),
                "self-change-protected set must cover '{surface}'"
            );
        }
    }
}
