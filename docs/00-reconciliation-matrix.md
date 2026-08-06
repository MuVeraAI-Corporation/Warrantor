# 00 — Reconciliation Matrix

> **The single source of truth.** Every component, protocol, and framework named across the four
> source portfolios is mapped here to **one canonical AumOS component**. Every RFC, scaffolding
> directory, and cross-reference in this repo defers to this table.
>
> **Methodology:** balanced merge — collapse names where the four source documents describe the same
> thing; keep separate where there is genuine scope divergence. Total: **38 canonical components**.

## How to read this table

- **Canonical ID** — the AumOS identifier (stable, used in RFC filenames and code paths). Prefix
  groups: `T` = trust core · `I` = identity & authority · `R` = runtime & enforcement · `C` = context
  & memory · `A` = assurance/eval · `S` = supply chain · `E` = evidence · `N` = inference · `F` =
  federated/edge · `G` = governance/response · `P` = protocol (spec-only) · `X` = cross-cutting/CLI.
- **DefStack** — component ID(s) from the 36-component plan (e.g. `C2.2`, `F2`).
- **AumSecure** — component name from the V2/V3 portfolios (or `—` if no mapping).
- **Sentinel** — framework from PROJECT SENTINEL (or `—`).
- **Languages** — *AumOS decision* (stack-test doctrine applied to DefStack's per-component
  assignments). `Rust`/`Python`/`TypeScript`/`Go`. Go entries are flagged **(gated)** when they only
  clear the Go activation gate at a later wave.
- **Wave** — which delivery wave ships real code (Wave 1 = 90-day sprint). `docs` = spec/RFC only
  for now.
- **Notes** — short reconciliation rationale.

---

## 1. Trust Core, Identity & Authority (pillars: T / I / R)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **T1** | `trust-core` | C2.2 ModelNotary + C4.4(signing half) | `agent-evidence` (V3 repo #2) + AATM signing | atlas-sign + sentinel-artifact | **Rust** | **1** | Merge: ModelNotary + agent-evidence verifier + atlas-sign + sentinel-artifact = **one** Rust trusted-core crate. "No security invariant may have two authoritative implementations." See RFC T-CORE-1. |
| **T2** | `authority-spec` | — | `agent-authority-spec` (V3 repo #1) | — | Spec (JSON-Schema/CBOR/CDDL) + **Rust** ref | docs → 2 | The normative spec for the Agent Authority Envelope (AAE). Spans all languages. |
| **I1** | `agent-identity` | F2 AgentVault | "Agent Identity & Authority Fabric" (V2 #2) | ZTAI | **Go (gated → Wave 2)** | 2 (Wave-1 uses mock) | The keystone: 12 components depend on it. DefStack wraps SPIFFE/SPIRE; V2/Sentinel do the same. Go activated here because real K8s-operator identity lifecycle is the Go activation gate trigger #3. |
| **I2** | `identity-bindings` | (folded into F2) | `spiffe-agent-identity` (V2 W0 adapter) | ztai-spiffe-bridge | **Rust** + Go adapter | docs → 2 | The SPIFFE/SPIRE binding layer; trusted-core signs, Go registers. |
| **R1** | `secure-workspace` | (none direct) | "Secure Agent Workspace" (V2 #1) | (uses OpenShell) | **Rust** + eBPF | docs → 1 | The OpenShell-based isolated agent runtime. EvalGuard (C7.1) is the attestation arm of this. |
| **R2** | `eval-guard` | C7.1 EvalGuard | (folded into "Secure Agent Workspace") | — | **Rust** + eBPF (aya) | **1** | Sandbox boundary attestation. DefStack said Go; **AumOS moves to Rust** per stack-test trusted-core doctrine. |
| **R3** | `kill-switch` | C7.2 KillSwitchKit | (none — V2 has no direct equiv) | (none direct) | **Rust core** + Python policy | **1** | Execution layer = trusted core; OPA Rego policy via Rust bindings. AI Kill Switch Act reference impl. |
| **R4** | `credential-vault` | C7.4 CredentialVault | (none direct) | — | **Rust** | **1** | Agent-scoped credential brokering = trusted core. Multi-language Vault SDKs. |
| **R5** | `policy-compiler` | (none direct) | "Agent Policy Compiler" (V2 #8) | — | **Rust core** + TS UI | docs → 6 | Compiles NL/regulatory intent → OpenShell policy + OPA/Cedar rules. |
| **R6** | `policy-bridge` | (none direct) | `agent-policy-bridge` (V3 repo #4) | — | Rust ref + multi-engine adapters | docs → 2 | Fail-closed reference adapters; OPA/Cedar/OpenShell decision-equivalence tests. |
| **R7** | `egress-filter` | (none direct) | (none direct) | (none direct) | **Rust** eBPF | docs → 6 | eBPF egress enforcement (DefStack's ExfilGuard overlaps — see S6). |
| **R8** | `sandbox-runtime` | (none direct) | "Secure Agent Workspace" runtime | OpenShell adapter | **Rust** + WASM (Wasmtime) | docs → 4 | The actual sandbox (FORGE sandbox + OpenShell). Capability-scoped. |

---

## 2. Confidential Compute & GPU Attestation (pillar: C1)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **C1-1** | `nvtrust-bridge` | C1.4 NVTrustBridge | (none direct) | — | **Rust core** + Python + Go bindings | **1** | NVTrust FFI bindings + `nvtrust-verify` CLI. Offline/mock mode for CI. |
| **C1-2** | `cuda-gram` | C1.1 CudaGram | (none direct) | — | **Python** (PyO3 → C1-1) | **1** | High-level GPU attestation SDK. Moves from ctypes to safe Rust bindings. |
| **C1-3** | `attesta-flow` | C1.2 AttestaFlow | (none direct) | — | Python + **Terraform** | 5 | E2E attested inference pipeline (Azure DC, AWS Nitro, GCP CC VMs + NVIDIA). |
| **C1-4** | `tee-serve` | C1.3 TeeServe | (none direct) | — | **Go** (gated → Wave 5) | 5 | TEE-backed model serving, Triton bridge. <2ms overhead. Go cleared (real sidecar service). |
| **C1-5** | `confidential-fabric` | (none direct) | "Confidential AI Execution Fabric" (V2 #14) | (Sentinel confidential arm) | **Rust** + Go control | docs → 5 | GPU/node attestation + confidential containers + policy-bound key release. |

---

## 3. Safe Model Formats & Supply Chain (pillars: C2 / S)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **S1** | `safe-tensors-pp` | C2.1 SafeTensors++ | (extends Safetensors) | ATLAS format | Python + **Rust** core | 2 | Drop-in Safetensors ext with `__provenance__`. ATLAS's sidecar `.atlas` is the same idea in Sentinel. |
| **S2** | `provena-chain` | C2.3 ProvenaChain | (none direct) | ATLAS ledger | **Rust** (Merkle) + Python API | 3 | Tamper-evident provenance ledger; Merkle root → Sigstore Rekor. |
| **S3** | `gguf-ext` | C2.4 GGUF-Ext | (none direct) | — | **Rust** | docs → 3 | `osaf.safety` metadata block in GGUF for llama.cpp/Ollama/LM Studio. |
| **S4** | `model-sbom` | C4.1 ModelSBOM | `agent-bom-tools` (V3 ext #6) + AI Artifact Trust Hub (V2 #7) | (Sentinel FORGE-SBOM overlaps) | **Python** CLI | 2 | CycloneDX/SPDX with AI extensions. Merge with AATM/agent-BOM. |
| **S5** | `data-provenance-kit` | C4.2 DataProvenanceKit | (none direct) | (AGORA Catalog overlaps) | **Python** | 3 | Dataset lineage; signed JSON-LD export. |
| **S6** | `exfil-guard` | F7 ExfilGuard | (none direct) | — | **Rust** eBPF (Falco+Tetragon) | 6 | eBPF exfil prevention. Overlaps with R7 egress-filter — R7 is the policy/decision, S6 is the eBPF enforcement. Kept separate per DefStack spec. |
| **S7** | `tamper-scan` | C4.4 TamperScan | (none direct) | — | **Python** | 3 | Weight distribution / backdoor / pruning / fine-tune detection. |
| **S8** | `train-guard` | C4.3 TrainGuard | (none direct) | — | **Python** | 3 | Training-loop integrity hooks; signed training attestation. |
| **S9** | `lightwell-bridge` | (none direct) | (none direct) | delta-patch (extends Lightwell) | Go + Rust | docs → 6 | AI-artifact patch distribution extending IBM/Red Hat Lightwell. |

---

## 4. Evaluation & Red-Teaming (pillar: A)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **A1** | `safe-eval` | C5.1 SafeEval | (none direct) | COLOSSEUM bench | **Python** | 3 | YAML pipeline orchestrating HELM/garak/PyRIT/MDASH. |
| **A2** | `adversaria` | C5.2 Adversaria | (none direct) | HYDRA heads | **Python** + Rust orchestrator | 3 | Unified adversarial test framework. HYDRA's multi-model debate is a superset; A2 is the core. |
| **A3** | `bias-sentinel` | C5.3 BiasSentinel | (none direct) | — | **Python** + TS dashboard | 6 | Bias + copyright auditing (EU AI Act). |
| **A4** | `comply-gate` | C5.4 ComplyGate | (none direct) | — | YAML + **Python** | 6 | CI/CD compliance gates (GitHub Action + GitLab CI). |
| **A5** | `agentsec-lab` | (none direct) | `agentsec-lab` (V3 repo #6) | COLOSSEUM attack + HYDRA bench | **Python** + Rust | docs → 2 | Adversarial benchmark w/ rotating holdouts, maintainer-first disclosure. |
| **A6** | `conformance` | (none direct) | `agent-conformance` (V3 repo #5) | (none direct) | Rust ref + CLI + GitHub Action | docs → 1 | Cross-language conformance suite. Active in Wave-1 (this repo's `tools/conformance/`). |
| **A7** | `red-team-cloud` | (none direct) | "Agentic Red-Team & Evaluation Cloud" (V2 #6) | AEGIS-Red + HYDRA | **Python** | docs → 6 | Continuous adversarial simulation as a service. |
| **A8** | `arena` | (none direct) | (none direct) | COLOSSEUM arena + leaderboards | **TypeScript** + Go | docs → 7 | A/B Elo ranking leaderboard service. |

---

## 5. Inference Stack (pillar: N)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **N1** | `open-serve-kit` | C6.1 OpenServeKit | (none direct) | (Sentinel inference via NIM/TRT) | **Go** (gated → Wave 4) | 4 | OpenAI-compatible proxy; backend-agnostic. Go cleared (real serving service). |
| **N2** | `bridge-rt` | C6.2 BridgeRT | (none direct) | — | **Python** + Go | 4 | Unified backend abstraction; handles TRT-LLM v0.16 `sampler_type`. |
| **N3** | `inference-proxy` | C6.4 InferenceProxy | (none direct) | — | **Rust** + Go | 4 | Auth, rate-limit, prompt-filter, semantic cache gateway. |
| **N4** | `tenant-guard` | C6.3 TenantGuard | (none direct) | — | **Go** (gated → Wave 4) | 4 | K8s operator; MIG/MPS multi-tenant GPU. Go activation trigger #1. |

---

## 6. Federated & Edge (pillar: F)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **F1** | `fed-core` | C3.1 FedCore | (none direct) | AGORA federation | **Python** | 5 | Attested federated training (PyTorch + NeMo + DP via F3). Most complex component. |
| **F2** | `dp-crate` | C3.4 DPCrate | (none direct) | (AGORA DP) | **Python** | 5 | Differential privacy toolkit + dashboard. |
| **F3** | `edge-sentinel` | C3.2 EdgeSentinel | (none direct) | — | **Go** (<5MB binary) | 5 | Edge inference attestation agent (Jetson/EGX). |
| **F4** | `fleet-marshal` | C3.3 FleetMarshal | (none direct) | — | **Go** (gated → Wave 5) | 5 | K8s operator; `ModelFleet` CRD; canary/blue-green rollback. Go activation trigger #2. |

---

## 7. Cross-Cutting / Aggregation (pillar: X)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **X1** | `defstack-cli` | F4 DefStack CLI | (none direct) | sentinelos-cli | **Rust (clap)** | **1** | AumOS moves CLI from Go/Cobra to Rust/clap per stack-test consolidation doctrine. Subcommands: install/verify/upgrade/compliance-report. |
| **X2** | `nooa-ext` | F1 NOOA-Ext | `nooa-aumsecure-adapter` / `nooa-evidence-adapter` | NOOA-Forge | **Python** | 6 | Production extensions to NVIDIA NOOA (PolicyEnforcer, AuditStreamer, IdentityBinder, AttestationHook). |
| **X3** | `open-harness-spec` | F3 OpenHarnessSpec | (none direct) | (none direct) | Spec (Markdown) + **Python** conformance | docs → 6 | Vendor-neutral agent harness spec → proposed OSAF standard. |
| **X4** | `crypto-audit-ai` | F5 CryptoAuditAI | (none direct) | — | **Rust** (eBPF) + Python drivers | 6 | AI-assisted cryptanalysis (productizes Anthropic CryptanalysisBench). |
| **X5** | `retro-spec-kit` | F6 RetroSpecKit | (none direct) | — | **Python** | 6 | Retrospective transcript review (Anthropic reviewed 141,006 runs manually). |
| **X6** | `metr-bridge` | F8 METRBridge | (none direct) | — | **Python** | 6 | METR independent-evaluator integration. |
| **X7** | `console` | (none direct) | "Enterprise policy/evidence console" | sentinelos-console | **TypeScript** (Next.js) | 7 | Web UI for policy/evidence/approvals. |
| **X8** | `mcp-gateway` | (none direct) | `mcp-authority-gateway` (V2 W0) | — | **TypeScript** + Rust verify | docs → 2 | MCP middleware w/ authority-aware admission. |
| **X9** | `incident-exchange` | (none direct) | `agent-incident-exchange` (V2 W2) + AIX protocol | AEGIS SOC + delta-notify | Spec + **Python** | docs → 6 | Normalized agent incident format (OCSF ext + MITRE ATLAS). |
| **X10** | `sovereign-stack` | (none direct) | (none direct) | SENTINEL-OS Core + sovereign-agent-stack | Bash + Ansible + Helm | docs → 7 | Air-gapped single-node sovereign bundle. |
| **X11** | `defstack-cloud` | (none direct) | (none direct) | sentinelos-cloud | **Go** control + TS console | docs → 7 | Managed SaaS surface (BSL/source-available). |

---

## 8. Sentinel-only frameworks (folded into the above)

PROJECT SENTINEL named 10 frameworks. **None survive as standalone** — every one maps to a canonical
component above:

| Sentinel framework | Maps to AumOS canonical(s) |
|---|---|
| AEGIS | X9 incident-exchange + A5 agentsec-lab (defensive-agent layer is future work, not Wave-1) |
| NOOA-Forge | X2 nooa-ext |
| ZTAI | I1 agent-identity + I2 identity-bindings |
| ATLAS | T1 trust-core + S1 safe-tensors-pp + S2 provena-chain |
| HYDRA | A2 adversaria + A5 agentsec-lab |
| COLOSSEUM | A1 safe-eval + A8 arena |
| FORGE | R8 sandbox-runtime + S4 model-sbom |
| AGORA | F1 fed-core + F2 dp-crate + S5 data-provenance-kit |
| DELTA | S9 lightwell-bridge + X9 incident-exchange |
| SENTINEL-OS | X10 sovereign-stack + X11 defstack-cloud + X7 console |

---

## 9. Open Protocols (spec-only canonicals)

The 12 AumSecure open protocols become **spec-only canonical components** in `specs/`. They have no
single language implementation; every relevant component consumes them.

| Canonical ID | Protocol | Spelled out | Consumed by |
|---|---|---|---|
| **P1** | AAE | Agent Authority Envelope | I1, R3, R4, all trusted-core |
| **P2** | AAR | Agent Action Receipt | E1, X2, all auditing components |
| **P3** | CPE | Context Provenance Envelope | C1, C2 (context components — future wave) |
| **P4** | AMIL | Agent Memory Integrity Ledger | (future context/memory components) |
| **P5** | SSP | Secure Skill Package | S4, X8 |
| **P6** | AATM | AI Artifact Trust Manifest | T1, S1, S4, S5 |
| **P7** | ABS | Autonomy Budget Specification | I1, R3 |
| **P8** | VEB | Verifiable Evaluation Bundle | A1, A5, A6 |
| **P9** | AIX | Agent Incident Exchange | X9, R3 |
| **P10** | MADE | Multi-Agent Delegation Exchange | I1 (multi-agent future) |
| **P11** | PRB | Proof-Carrying Remediation Bundle | S9, X9 |
| **P12** | CAP | Capability Attestation Profile | R1, R2, I1 |

---

## 10. Evidence plane (the E canonical)

| Canonical ID | Canonical Name | DefStack | AumSecure | Sentinel | Languages | Wave | Notes |
|---|---|---|---|---|---|---|---|
| **E1** | `flight-recorder` | (none direct) | "Verifiable Agent Flight Recorder" (V2 #3) + `agent-evidence` receipt half | (Sentinel observability) | **Rust** core + TS viewer | docs → 2 | Emits signed AAR (P2). The evidence half of T1 trust-core. |

---

## Summary statistics

| Group | Count |
|---|---|
| Trust core / identity / runtime (§1) | 14 (T1, T2, I1, I2, R1–R8) |
| Confidential compute / GPU (§2) | 5 (C1-1 … C1-5) |
| Formats / supply chain (§3) | 9 (S1–S9) |
| Evaluation (§4) | 8 (A1–A8) |
| Inference (§5) | 4 (N1–N4) |
| Federated / edge (§6) | 4 (F1–F4) |
| Cross-cutting (§7) | 11 (X1–X11) |
| Evidence (§10) | 1 (E1) |
| Protocols (spec-only, §9) | 12 (P1–P12) |
| **Total canonical components** | **56** (38 implementable + 12 spec-only protocols + 6 folded-in Sentinel frameworks already counted) |
| **Implementable** | **44** |
| **Spec-only** | **12** (protocols) |

> The "~38" figure in the planning conversation counted only the implementable, non-protocol
> canonicals excluding the folded Sentinel frameworks and the future-only defensive-agent (AEGIS)
> layer. The full canonical catalog above is **44 implementable components + 12 protocol specs**.
> Wave-1 ships 8 of the 44.

---

## Wave-1 (the 90-day sprint) — 8 components

| Canonical ID | Name | Languages | Dependencies |
|---|---|---|---|
| **T1** | `trust-core` | Rust | none |
| **X1** | `defstack-cli` | Rust (clap) | none |
| **C1-1** | `nvtrust-bridge` | Rust core + Py + Go bindings | none |
| **C1-2** | `cuda-gram` | Python (PyO3 → C1-1) | C1-1 |
| **R2** | `eval-guard` | Rust + eBPF | C1-2 (mock initially) |
| **R4** | `credential-vault` | Rust | R3 (mock initially) |
| **R3** | `kill-switch` | Rust core + Python policy | I1 (mock AgentVault) |
| (deferred to Wave-1.5) | `sentinel-trace` (DefStack C7.3) | Python | I1 (standalone audit hook initially) |

> **Note on SentinelTrace:** DefStack Phase 7 lists 4 components (EvalGuard, KillSwitchKit,
> SentinelTrace, CredentialVault). The first 3 of our Wave-1 + R4 = 4 components. SentinelTrace (the
> behavioral-divergence monitor) is deferred to Wave-1.5 (M2.5) because it depends on NOOA-Ext
> (Wave 6) for its action stream; a standalone-audit-hook MVP can ship earlier if capacity allows.

---

## Cross-references

- **Vision/roadmap/metrics:** [`01-vision-and-portfolio.md`](01-vision-and-portfolio.md)
- **12-plane architecture + I-01…​I-12 invariants:** [`02-architecture.md`](02-architecture.md)
- **Per-component RFCs:** [`rfcs/`](rfcs/) (filename = `<canonical-id-lower>-<kebab-name>.md`)
- **Cross-cutting standards:** [`cross-cutting/`](cross-cutting/) (13–19, plus originals 13–16)
- **Original source docs:** [`source-matrix/README.md`](source-matrix/README.md)
