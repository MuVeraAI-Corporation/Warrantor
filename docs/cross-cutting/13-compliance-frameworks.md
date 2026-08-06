# Compliance Frameworks Matrix

> Every DefStack component maps to one or more regulatory/compliance frameworks. This is non-negotiable for enterprise and government adoption.

## Frameworks Tracked (August 2026)

| Framework | Jurisdiction | Status (Aug 2026) | DefStack Impact |
|-----------|-------------|-------------------|-----------------|
| **EU AI Act** | EU | Entered force 1 Aug 2024; applies from 2 Aug 2026; GPAI model providers must comply by 2 Aug 2027 | SafeTensors++, ModelNotary, ModelSBOM, DataProvenanceKit (provenance), ComplyGate (deployment gates) |
| **NIST AI RMF 1.0** | US (voluntary) | Released Jan 2023; revision concept note published April 7, 2026 | All components map to Govern/Map/Measure/Manage functions |
| **ISO/IEC 42001:2023** | International | Published Dec 2023; certification available 2024-2026 | DefStack org should pursue ISO 42001 certification by M18 |
| **FedRAMP AI** | US Government | 2025 AI Prioritization Initiative completed April 2026; 4 authorization paths in 2026 | KillSwitchKit, AgentVault, AttestaFlow target FedRAMP authorization |
| **OpenSSF SLSA v1.0** | Industry | Released April 2023; widely adopted by 2026 | All components target SLSA Level 3+ |
| **EU DORA** | EU (financial) | Applies from Jan 17, 2025; enforcement active 2026 | OpenServeKit, InferenceProxy, TenantGuard for financial sector customers |
| **AI Kill Switch Act (H.R. 2026)** | US (pending) | Introduced July 23, 2026 (Reps. Lieu/Moran) | KillSwitchKit is the reference implementation |
| **EU NIS2** | EU (cyber) | Applies from Oct 2024; transposition ongoing 2026 | AgentVault, audit logging for critical infrastructure |
| **UK AI Safety Bill** | UK (proposed) | In consultation 2026 | Mirror EU AI Act requirements |
| **China Generative AI Measures** | China | In force 2023; updated 2025 | Out of scope for v1 (no China deployment) |

## Component → Framework Mapping

| Component | EU AI Act | NIST AI RMF | ISO 42001 | FedRAMP | SLSA | DORA | Kill Switch |
|-----------|-----------|-------------|-----------|---------|------|------|-------------|
| C1.1 CudaGram | ✓ | ✓ | ✓ | ✓ | L3 | — | — |
| C1.2 AttestaFlow | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | — |
| C1.3 TeeServe | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | ✓ |
| C2.1 SafeTensors++ | ✓ Art.55 | ✓ | ✓ | — | L3 | — | — |
| C2.2 ModelNotary | ✓ Art.55 | ✓ | ✓ | — | L3 | ✓ | — |
| C2.3 ProvenaChain | ✓ Art.55 | ✓ | ✓ | — | L3 | — | — |
| C4.1 ModelSBOM | ✓ Art.55 | ✓ | ✓ | ✓ | L3 | ✓ | — |
| C4.2 DataProvenanceKit | ✓ Art.55 | ✓ | ✓ | — | L3 | — | — |
| C5.1 SafeEval | ✓ | ✓ | ✓ | — | L3 | — | — |
| C5.4 ComplyGate | ✓ | ✓ | ✓ | — | L3 | ✓ | ✓ |
| C6.1 OpenServeKit | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | — |
| C6.3 TenantGuard | — | ✓ | — | ✓ | L3 | ✓ | — |
| C6.4 InferenceProxy | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | ✓ |
| F2 AgentVault | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | ✓ |
| C7.1 EvalGuard | ✓ | ✓ | ✓ | — | L3 | — | ✓ |
| C7.2 KillSwitchKit | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | ✓✓ |
| C7.3 SentinelTrace | ✓ | ✓ | ✓ | — | L3 | ✓ | ✓ |
| C7.4 CredentialVault | ✓ | ✓ | ✓ | ✓ | L3 | ✓ | ✓ |
| F7 ExfilGuard | ✓ | ✓ | ✓ | — | L3 | ✓ | — |
| F5 CryptoAuditAI | ✓ | ✓ | ✓ | — | L3 | — | — |
| F6 RetroSpecKit | ✓ | ✓ | ✓ | — | L3 | — | — |
| F8 METRBridge | ✓ | ✓ | ✓ | — | L3 | — | — |

## EU AI Act Article 55 — GPAI Model Obligations

Article 55 (entered force 2 Aug 2025; providers must comply by 2 Aug 2027) requires GPAI model providers to:

1. **Model documentation** — ModelSBOM (C4.1) generates this automatically
2. **Training data summary** — DataProvenanceKit (C4.2) tracks this
3. **Downstream provider information** — ProvenaChain (C2.3) records lineage
4. **Copyright compliance** — BiasSentinel (C5.3) includes copyright detection
5. **Technical documentation** — ModelSBOM + ProvenaChain + ModelNotary
6. **Systemic risk assessment** — SafeEval (C5.1) + Adversaria (C5.2)
7. **Adversarial testing** — Adversaria (C5.2)
8. **Serious incident reporting** — RetroSpecKit (F6) + ComplyGate (C5.4)

**DefStack advantage:** A GPAI model provider using the full DefStack stack can demonstrate Article 55 compliance with a single `defstack compliance-report` command.

## NIST AI RMF Mapping

NIST AI RMF 1.0 (revision concept note published April 7, 2026) has four functions:

| Function | Component(s) | How |
|----------|-------------|-----|
| **Govern** | AgentVault, ComplyGate | Identity, permissions, deployment gates |
| **Map** | ModelSBOM, DataProvenanceKit, ProvenaChain | Document the system |
| **Measure** | SafeEval, Adversaria, BiasSentinel, TamperScan | Evaluate risks |
| **Manage** | KillSwitchKit, SentinelTrace, CredentialVault, ExfilGuard | Respond to risks |

## ISO/IEC 42001:2023 — AI Management System

ISO 42001 is the AI management system standard (published Dec 2023). DefStack should pursue organizational certification by M18. Components that support ISO 42001 controls:

- **Clause 6 (Planning):** ModelSBOM, ProvenaChain (document AI systems)
- **Clause 7 (Support):** SafeTensors++, ModelNotary (documentation and records)
- **Clause 8 (Operation):** ComplyGate, SafeEval (operational controls)
- **Clause 9 (Performance Evaluation):** RetroSpecKit, METRBridge (monitoring)
- **Clause 10 (Improvement):** CryptoAuditAI (continuous improvement)

## FedRAMP AI Authorization

FedRAMP completed its AI Prioritization Initiative in April 2026. Four authorization paths exist in 2026:
1. **Rev 5** (traditional)
2. **Rev 5 + GRC tooling** (accelerated)
3. **Accelerators** (agency-specific)
4. **20x** (new, faster)

DefStack target: KillSwitchKit, AgentVault, AttestaFlow achieve FedRAMP authorization by M18 (Horizon 2). Use the "20x" path if available; otherwise Rev 5 + GRC tooling.

## OpenSSF SLSA v1.0

SLSA (Supply-chain Levels for Software Artifacts) v1.0 defines build integrity levels:

| Level | Requirement | DefStack Status |
|-------|-------------|-----------------|
| L1 | Build process documented | ✅ All components (CI) |
| L2 | Hosted build service, provenance generated | ✅ All components (GitHub Actions) |
| L3 | Hardened build platform, non-falsifiable provenance | 🎯 Target for all v1.0 releases |
| L4 | Two-party review, reproducible builds | 📋 Target for v2.0 |

## EU DORA (Digital Operational Resilience Act)

DORA (applies from Jan 17, 2025; enforcement active 2026) requires financial institutions to manage ICT risks. DefStack components for financial customers:

- **OpenServeKit, InferenceProxy** — high availability inference
- **TenantGuard** — multi-tenant isolation
- **KillSwitchKit, SentinelTrace** — incident response
- **AgentVault** — audit trail for regulatory reporting

## Compliance Reporting

`defstack compliance-report` command generates:
```json
{
  "framework": "EU-AI-Act-Article-55",
  "generated_at": "2026-08-02T14:23:01Z",
  "model": "llama-3-70b",
  "model_hash": "sha256:abc123...",
  "documentation": { "sbom": "...", "provenance": "..." },
  "training_data": { "provenance_graph": "..." },
  "evaluations": { "safety": "passed", "adversarial": "passed" },
  "incidents": [],
  "signed_by": "did:web:defstack.org"
}
```

## Review Cadence

- This matrix is reviewed monthly
- New regulatory developments trigger updates within 14 days
- Compliance gaps trigger RFC updates for affected components
