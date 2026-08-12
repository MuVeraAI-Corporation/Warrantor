# Compliance Frameworks Matrix

> Every DefStack component maps to one or more regulatory/compliance frameworks. This is non-negotiable for enterprise and government adoption.
>
> **Ordering is deliberate.** The platform's primary markets are US/North America, GCC, and India, so
> those anchors lead. EU frameworks are tracked because they are factually load-bearing for some
> customers, not because they lead the positioning.

## Frameworks Tracked (August 2026)

### United States

| Framework | Status (Aug 2026) | DefStack Impact |
|-----------|-------------------|-----------------|
| **Interagency Model Risk Management — OCC Bulletin 2026-13 / Fed SR 26-2** | Issued 17 Apr 2026; **supersedes SR 11-7 and SR 21-8** (never cite those as current). States generative and agentic AI are *"not within the scope of this guidance"* and that it *"does not set forth enforceable standards"*. The agencies plan an **RFI specifically on banks' use of AI, including agentic AI** | Read as a **deferral, not an exemption**: obligations on the underlying action (safety & soundness, consumer protection, third-party risk) are untouched — only the control *specification* was withdrawn. The eventual guidance will be written against what industry can already demonstrate. Warrant bounds + signed receipts + approval records are exactly that demonstration. Contributing evidence to the RFI is a live opportunity |
| **NIST AI RMF 1.0** | Released Jan 2023; revision concept note published 7 Apr 2026 | All components map to Govern/Map/Measure/Manage functions (see mapping below) |
| **FedRAMP AI** | 2025 AI Prioritization Initiative completed Apr 2026; 4 authorization paths | KillSwitchKit, AgentVault, AttestaFlow target FedRAMP authorization |
| **AI Kill Switch Act (H.R. 9917)** | Introduced 23 Jul 2026 (Reps. Lieu/Moran); pending | KillSwitchKit is the reference implementation |

### India

| Framework | Status (Aug 2026) | DefStack Impact |
|-----------|-------------------|-----------------|
| **RBI FREE-AI** | Framework for Responsible and Ethical Enablement of AI in the Financial Sector; committee report published Aug 2025 with **seven guiding sutras** and practical implementation guidance for regulated entities | Principle-based — so compliance is an *evidentiary* claim: "human oversight was maintained" must be demonstrated, not asserted. Staged effects + approval records + refusal logs are that demonstration. Warrant register serves the AI-inventory expectation |
| **India AI Governance Guidelines** | Released Feb 2026 (AI Impact Summit); principle-based techno-legal approach anchored in seven sutras | Same evidentiary posture as FREE-AI; applies beyond financial sector |
| **DPDP Act 2023** | In force; implementing rules progressing through 2026 (verify current rules status before customer-facing claims) | Data an agent touches while working is in scope: write-path bounds + egress allowlists limit exposure; receipts record what was accessed. Also drives the data-residency case for local/sovereign deployment |

### GCC

| Framework | Status (Aug 2026) | DefStack Impact |
|-----------|-------------------|-----------------|
| **SDAIA national AI risk management framework** (Saudi Arabia) | Launched **14 Jul 2026**: unified methodology for identifying, assessing, treating and **continuously monitoring** AI risks, for government and private sector. Sits alongside PDPL (in force Sep 2023) and the AI Adoption Framework (4 maturity levels, Sep 2024) | "Continuously" is the differentiator: point-in-time attestations don't satisfy it. Reconciliation timer + live run state + refusal trends are continuous by construction |
| **DIFC Regulation 10** (UAE) | In force; regulates autonomous and semi-autonomous systems directly — requires privacy impact assessments and **risk-based audits of automated decision-making**. The most AI-specific provision in the Gulf | Warrant bounds are a machine-readable answer to "what may this autonomous system do"; evidence packs serve the audit requirement |
| **UAE federal agentic-AI programme** | 23 Apr 2026: 50% of federal sectors/services/operations to agentic AI within two years | Demand signal, not an obligation — the buyer explicitly needs agent governance at sovereign scale |

> GCC entries above are drawn from secondary analyses; confirm against SDAIA/DIFC primary texts
> before they appear in customer-facing material.

### International & industry

| Framework | Jurisdiction | Status (Aug 2026) | DefStack Impact |
|-----------|-------------|-------------------|-----------------|
| **ISO/IEC 42001:2023** | International | Published Dec 2023; certification available | DefStack org should pursue ISO 42001 certification by M18 |
| **OpenSSF SLSA v1.0** | Industry | Released Apr 2023; widely adopted by 2026 | All components target SLSA Level 3+ |

### EU & other (tracked where factually required)

| Framework | Jurisdiction | Status (Aug 2026) | DefStack Impact |
|-----------|-------------|-------------------|-----------------|
| **EU AI Act** | EU | Entered force 1 Aug 2024; applies from 2 Aug 2026; GPAI providers by 2 Aug 2027 | SafeTensors++, ModelNotary, ModelSBOM, DataProvenanceKit (provenance), ComplyGate (deployment gates) |
| **EU DORA** | EU (financial) | Applies from 17 Jan 2025; enforcement active | OpenServeKit, InferenceProxy, TenantGuard for financial-sector customers |
| **EU NIS2** | EU (cyber) | Applies from Oct 2024; transposition ongoing | AgentVault, audit logging for critical infrastructure |
| **UK AI Safety Bill** | UK (proposed) | In consultation 2026 | Mirrors EU AI Act requirements |
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

## US / India / GCC — what supervisors ask for, and what answers it

The primary-market frameworks are principle- and evidence-based rather than checklist-based, so the
mapping is from *asked-for artefact* to *producing primitive* rather than component-by-component:

| Supervisors ask for | Producing primitive | Where it lives |
|---|---|---|
| AI inventory | Every warrant ever granted, with bounds and state | `WarrantStore::list()` |
| Use-case ownership | Warrant `goal` + owner (owner field pending) | warrant claims |
| Risk classification | `SideEffectClass`: read / write / financial / destructive / physical | authority spec |
| Testing controls | Pre-flight (eval-guard); staged effects as a dry-run that never commits | staging queue |
| **Continuous** monitoring (SDAIA) | Reconciliation timer + live run state + refusal counts | daemon + proxy |
| Evidence of accountability | Signed receipts; who settled/voided, when; hash-chained log | flight-recorder, settle |
| Human oversight demonstrated (FREE-AI) | Approval-before-commit on consequential classes; settle-key separation | staged effects + settle authority |
| Risk-based audit of automated decisions (DIFC Reg 10) | Evidence pack export: bounds + receipts + approvals + refusals per period | OCSF export + retention |

Two properties do disproportionate work here:

1. **Refusal records.** Most platforms can show what an agent did; supervisors increasingly ask what
   it *attempted*. `AuthorityRequest {tool, bound, reason, count}` answers that directly.
2. **Enforced vs Observed labelling** (`BoundStrength`). Presenting a measured bound as an enforced
   one to a regulator is a misrepresentation; the platform distinguishes them in the type system.

## Primary sources (verified 11 Aug 2026)

- OCC Bulletin 2026-13: <https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13.html>
- Fed SR 26-2: <https://www.federalreserve.gov/supervisionreg/srletters/SR2602.pdf>
- RBI FREE-AI report: <https://rbidocs.rbi.org.in/rdocs/PublicationReport/Pdfs/FREEAIR130820250A24FF2D4578453F824C72ED9F5D5851.PDF>
- India AI Governance Guidelines: <https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/feb/doc2026215790801.pdf>
- SDAIA / DIFC entries: secondary analyses pending primary-text confirmation (see note above)

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
  "signed_by": "did:web:muveraai.com"
}
```

## Review Cadence

- This matrix is reviewed monthly
- New regulatory developments trigger updates within 14 days
- Compliance gaps trigger RFC updates for affected components
