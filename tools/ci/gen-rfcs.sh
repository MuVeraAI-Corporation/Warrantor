#!/usr/bin/env bash
# RFC generator — emits conforming 10-section RFCs for the canonical components
# listed in docs/00-reconciliation-matrix.md.
#
# Usage: bash tools/ci/gen-rfcs.sh
#
# Each RFC is compact but complete: every one of the 10 required sections is present
# (verified by tools/ci/check-docs.sh). Detailed Wave-1 RFCs (T1, I1) are written
# by hand; this generator handles the remaining 42 implementable components and
# the 12 spec-only protocol specs.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RFC_DIR="$REPO_ROOT/docs/rfcs"
mkdir -p "$RFC_DIR"

# Each entry: id|name|wave|languages|defstack_origin|aumsecure_origin|sentinel_origin|deps|purpose
# (the metadata table; the body is templated)
read -r -d '' COMPONENTS <<'EOF' || true
X1|defstack-cli|1|Rust (clap)|F4 DefStack CLI|(none)|sentinelos-cli|none|Unified installer/orchestrator CLI: install/verify/upgrade/compliance-report. AumOS moves from Go/Cobra to Rust/clap per stack-test consolidation.
C1-1|nvtrust-bridge|1|Rust core + Python + Go bindings|C1.4 NVTrustBridge|(none)|(none)|none|NVTrust FFI bindings + nvtrust-verify CLI. Offline/mock mode for CI; reference verifiers for H100/H200.
C1-2|cuda-gram|1|Python (PyO3)|C1.1 CudaGram|(none)|(none)|C1-1|High-level GPU attestation SDK wrapping C1-1. Exposes AttestationReport, CCSession, AttestationVerifier. Moves from ctypes to safe Rust bindings.
R2|eval-guard|1|Rust + eBPF (aya)|C7.1 EvalGuard|(Secure Agent Workspace arm)|(none)|C1-2|Sandbox boundary attestation. Four pre-flight checks (NetworkIsolation, FilesystemBoundary, ProcessIsolation, EgressAttestation). Emits signed SandboxAttestation. AumOS moves from Go to Rust per trusted-core doctrine.
R3|kill-switch|1|Rust core + Python policy|C7.2 KillSwitchKit|(none)|(none)|I1 (mock)|Three layers: Policy (OPA Rego), Decision Engine, Execution (vLLM/Triton/K8s/eBPF). <5s end-to-end. Government Compliance API for AI Kill Switch Act (H.R. 2026). AumOS moves execution layer to Rust trusted core.
R4|credential-vault|1|Rust|C7.4 CredentialVault|(none)|(none)|R3 (mock)|Agent-scoped credential brokering: 15-min TTL scoped tokens bound to SPIFFE identity + task + IP. Integrates Vault/AWS Secrets Mgr/K8s Secrets. Revokes <1s on kill. AumOS moves from Go to Rust per trusted-core doctrine.
T2|authority-spec|2|Spec (JSON-Schema/CBOR/CDDL) + Rust ref|(none)|agent-authority-spec (V3 repo #1)|(none)|none|Normative spec for the Agent Authority Envelope (P1 AAE). Issuer, subject, purpose, resources, tools, data classes, side-effect class, budget, geography, delegation depth, approvals, expiry, revocation.
I2|identity-bindings|2|Rust + Go adapter|(folded into F2)|spiffe-agent-identity (V2 W0)|ztai-spiffe-bridge|T1, I1|SPIFFE/SPIRE binding layer. Rust signs; Go registers workloads via SPIRE WorkloadAPI.
E1|flight-recorder|2|Rust core + TS viewer|(none)|Verifiable Agent Flight Recorder (V2 #3) + agent-evidence receipt half|(none)|T1, I1|Emits signed Agent Action Receipts (P2 AAR) before commit. Framework-neutral. Export OCSF + OpenTelemetry.
S1|safe-tensors-pp|2|Python + Rust core|C2.1 SafeTensors++|(extends Safetensors)|atlas-format|T1|Drop-in extension of HF Safetensors with __provenance__ block (signer, Ed25519 sig, signed_at, evaluations, lineage). Backward-compatible. ATLAS sidecar .atlas is the same idea.
S4|model-sbom|2|Python CLI|C4.1 ModelSBOM|agent-bom-tools (V3 ext #6) + AI Artifact Trust Hub (V2 #7)|FORGE-SBOM (overlaps)|S1, T1|CycloneDX + SPDX SBOMs with AI extensions: model.architecture, .parameters, .training_data, .base_model, .evaluations, .license. Merges with AATM/agent-BOM.
A6|conformance|2|Rust ref + CLI + GitHub Action|(none)|agent-conformance (V3 repo #5)|(none)|T1|Cross-language conformance suite. CLI, GitHub Action, CI images. Verifies golden vectors across Rust/Python/TS/Go. Active in Wave-1 as tools/conformance/.
A5|agentsec-lab|2|Python + Rust|(none)|agentsec-lab (V3 repo #6)|COLOSSEUM attack + HYDRA bench|T1, E1|Adversarial benchmark with safe targets, rotating holdouts, maintainer-first disclosure. Public + hidden tasks; anti-gaming.
S2|provena-chain|3|Rust (Merkle) + Python API|C2.3 ProvenaChain|(none)|atlas-ledger|T1, S1|Tamper-evident provenance ledger; Merkle root published to Sigstore Rekor or blockchain. Required for EU AI Act lineage (Art. 55).
S5|data-provenance-kit|3|Python|C4.2 DataProvenanceKit|(none)|(AGORA Catalog overlaps)|S4|Dataset lineage tracker. Wraps HF Datasets/S3/local; records every transformation as a node; exports signed JSON-LD.
S7|tamper-scan|3|Python|C4.4 TamperScan|(none)|(none)|S2|Model tamper detection. weight_distribution, backdoor_patterns, neuron_pruning, fine_tune_detection. AI equivalent of a virus scanner.
S8|train-guard|3|Python|C4.3 TrainGuard|(none)|(none)|S4|Training-time integrity monitor. Hooks PyTorch training loop; checks gradient distributions, loss curves, dependency integrity, weight init; emits signed training attestation.
A1|safe-eval|3|Python|C5.1 SafeEval|(none)|COLOSSEUM bench|I1, T1|YAML pipeline framework. Stages: benchmarks (HELM/LM-Eval), adversarial (garak/PyRIT), safety, bias, red_team (MDASH). Exports results into S4.
A2|adversaria|3|Python + Rust orchestrator|C5.2 Adversaria|(none)|HYDRA heads|A1|Unified adversarial testing. Wraps garak + PyRIT; built-in generators: PromptInjection, Jailbreak, EncodingAttack, MultiTurnManipulation, TrainingDataExtraction.
N1|open-serve-kit|4|Go (gated)|(none)|C6.1 OpenServeKit|(none)|I1, C1-2|OpenAI-compatible proxy; backend-agnostic (vLLM, TensorRT-LLM, Triton, Ollama). Optional attestation envelope per response. Go cleared (real serving service).
N2|bridge-rt|4|Python + Go|C6.2 BridgeRT|(none)|(none)|N1|Unified backend abstraction. Auto-selects TRT-LLM > vLLM > Ollama. Handles TRT-LLM v0.16 sampler_type at runtime. Auto-converts SafeTensors to TRT engine.
N3|inference-proxy|4|Rust + Go|C6.4 InferenceProxy|(none)|(none)|N1, I1|LLM inference gateway. Middleware: auth (SPIFFE/API/OAuth), rate_limit, prompt_filter (injection/PII/policy), cache (semantic), audit, fallback.
N4|tenant-guard|4|Go (gated)|C6.3 TenantGuard|(none)|(none)|I1, N1|K8s operator. GPUQuota/TenantWorkload CRDs. NVIDIA MIG (HW) + MPS (SW) isolation. Per-tenant attestation. Go activation trigger #1.
C1-3|attesta-flow|5|Python + Terraform|C1.2 AttestaFlow|(none)|(none)|C1-2, I1|E2E attested inference pipeline. Terraform module (Azure DC, AWS Nitro, GCP CC VMs + NVIDIA). Python orchestrator in TEE. External verifier. Emits signed PipelineAttestation per batch.
C1-4|tee-serve|5|Go (gated)|C1.3 TeeServe|(none)|(none)|C1-2, I1|TEE-backed model serving. Go sidecar to Triton/vLLM. TLS terminates in TEE; forwards via UDS; wraps responses in AttestationEnvelope. <2ms overhead.
C1-5|confidential-fabric|5|Rust + Go control|(none)|Confidential AI Execution Fabric (V2 #14)|Sentinel confidential arm|C1-2, I1|GPU/node attestation + confidential containers + policy-bound key release + encrypted model delivery.
F1|fed-core|5|Python|C3.1 FedCore|(none)|AGORA federation|C1-2, I1, F2|Attested federated training orchestration. Roles: Aggregator/Trainer/Verifier. PyTorch + NeMo. DP via F2. Most complex component in the portfolio.
F2|dp-crate|5|Python|C3.4 DPCrate|(none)|(AGORA DP)|none|Differential privacy toolkit. DPSGDOptimizer, PrivacyAccountant (moments accountant), DPDashboard. PyTorch + NeMo + Opacus-compatible.
F3|edge-sentinel|5|Go (<5MB)|C3.2 EdgeSentinel|(none)|(none)|T1, F4|Edge inference attestation agent. Jetson/EGX. systemd service. Kills inference on tamper; alerts F4.
F4|fleet-marshal|5|Go (gated)|C3.3 FleetMarshal|(none)|(none)|T1|K8s operator. ModelFleet CRD. Canary/blue-green/all-at-once OTA. Auto-rollback at failure threshold. Go activation trigger #2.
X2|nooa-ext|6|Python|F1 NOOA-Ext|nooa-aumsecure-adapter / nooa-evidence-adapter|NOOA-Forge|I1, E1|Production extensions to NVIDIA NOOA. PolicyEnforcer (OPA/Rego), AuditStreamer (Kafka/Kinesis/webhook), IdentityBinder (SPIFFE), AttestationHook.
X3|open-harness-spec|6|Spec (Markdown) + Python conformance|F3 OpenHarnessSpec|(none)|(none)|X2|Vendor-neutral agent harness spec. 5 interfaces: AgentIdentity, ToolPermission, AuditEvent, AttestationEnvelope, EvaluationReport. Proposed OSAF standard; AumOS = reference implementation.
X4|crypto-audit-ai|6|Rust (eBPF) + Python drivers|F5 CryptoAuditAI|(none)|(none)|T1, A1|AI-assisted cryptanalysis. Modes: IMPLEMENTATION_AUDIT, ALGORITHM_STRESS_TEST, DEPENDENCY_SCAN. Integrates Anthropic CryptanalysisBench. Productizes Anthropic's research.
X5|retro-spec-kit|6|Python|F6 RetroSpecKit|(none)|(none)|T1, S4|Automated retrospective transcript review. Analyzers: network_access, real_system, behavioral_divergence, credential_exposure, supply_chain_attack, unauthorized_access. Anthropic reviewed 141,006 runs manually; this does it in hours.
X6|metr-bridge|6|Python|F8 METRBridge|(none)|(none)|X2, A1|METR independent-evaluator integration. METREvalAdapter, TranscriptExporter, RiskReportBridge, IndependentVerifier. Lets METR verify AumOS attestation claims independently.
X9|incident-exchange|6|Spec + Python|(none)|agent-incident-exchange (V2 W2) + AIX protocol|AEGIS SOC + delta-notify|R3, E1|Normalized agent incidents: goal hijack, memory poisoning, tool abuse, identity compromise, exfiltration, rogue delegation. OCSF extension + MITRE ATLAS mapping.
A3|bias-sentinel|6|Python + TS dashboard|C5.3 BiasSentinel|(none)|(none)|A1|Combined bias + copyright auditing. Bias (BOLD, HONEST, CrowS-Pairs, WinoBias) + copyright (n-gram overlap, fuzzy). EU AI Act copyright compliance.
A4|comply-gate|6|YAML + Python|C5.4 ComplyGate|(none)|(none)|A1, T1|CI/CD compliance gates for AI. GitHub Action + GitLab CI template. .complygate.yml. Break-glass overrides with 2 mandatory approvers.
R5|policy-compiler|6|Rust core + TS UI|(none)|Agent Policy Compiler (V2 #8)|(none)|T1, I1|Compiles NL intent + enterprise rules + regulatory controls into OpenShell policy + OPA/Cedar rules + test cases.
R7|egress-filter|6|Rust eBPF|(none)|(none)|(none)|R3, T1|eBPF egress enforcement. Policy/decision half of S6 exfil-guard. Domain blocklist + canary IPs (huggingface.co, pypi.org, 1.1.1.1).
S6|exfil-guard|6|Rust eBPF (Falco + Tetragon)|F7 ExfilGuard|(none)|(none)|R3, A1|eBPF exfiltration prevention. PatternMatcher (AWS/GitHub/OpenAI keys, SSNs, CCs), EntropyDetector (4.5 min_entropy, 32 min_length), VolumeMonitor (1MB/transfer, 10MB/hr). Integrates Falco + Tetragon.
S9|lightwell-bridge|6|Go + Rust|(none)|(none)|delta-patch (extends Lightwell)|S4, X9|AI-artifact patch distribution extending IBM/Red Hat Lightwell. Model weight updates, guardrail updates, config changes, runtime updates.
A7|red-team-cloud|6|Python|(none)|Agentic Red-Team & Evaluation Cloud (V2 #6)|AEGIS-Red + HYDRA|A5|Continuous adversarial simulation as a service. Injection, tool poisoning, identity abuse, memory poisoning, rogue delegation, exfiltration, cascading failures.
X7|console|7|TypeScript (Next.js)|(none)|Enterprise policy/evidence console|sentinelos-console|I1, E1|Web UI for policy administration, evidence explorer, approvals, fleet management, compliance reports.
X8|mcp-gateway|2 (docs)|TypeScript + Rust verify|(none)|mcp-authority-gateway (V2 W0)|(none)|I1, S4, T1|MCP middleware with authority-aware admission. Token audience, confused-deputy defense, result provenance.
X10|sovereign-stack|7|Bash + Ansible + Helm|(none)|(none)|SENTINEL-OS Core + sovereign-agent-stack|all|Air-gapped single-node sovereign bundle. RTX/Linux + import/export bundles. Three modes: Safe Local / Safe Team / Safe Production.
X11|defstack-cloud|7|Go control + TS console|(none)|(none)|sentinelos-cloud|all|Managed SaaS surface. Per-tenant ZTAI isolation. Usage-based pricing. BSL/source-available.
A8|arena|7|TypeScript + Go|(none)|(none)|COLOSSEUM arena + leaderboards|A1|A/B Elo ranking leaderboard service. Dual leaderboard: defensive (most robust models) + offensive (most effective attacks).
R1|secure-workspace|1|Rust + eBPF|(none)|Secure Agent Workspace (V2 #1)|(uses OpenShell)|T1, I1|OpenShell-based isolated workspace. Signed policy, credential brokering, network allowlists, controlled inference, approval gates, full action evidence. R2 is its attestation arm.
R6|policy-bridge|2|Rust ref + multi-engine adapters|(none)|agent-policy-bridge (V3 repo #4)|(none)|T1, R5|Fail-closed reference adapters. One policy produces consistent decisions across OPA/Cedar/OpenShell. Decision-equivalence tests.
R8|sandbox-runtime|4|Rust + WASM (Wasmtime)|(none)|Secure Agent Workspace runtime|OpenShell adapter|T1|Actual sandbox (FORGE sandbox + OpenShell). Capability-scoped FS/network/process; default no process spawning; all syscalls logged.
EOF

count=0
while IFS='|' read -r id name wave langs defstack aumsecure sentinel deps purpose; do
  [ -z "$id" ] && continue
  [[ "$id" == \#* ]] && continue
  file="$RFC_DIR/${id}-${name}.md"
  # Skip if a hand-written detailed RFC already exists (T1, I1)
  if [ -f "$file" ] && { [ "$id" == "T1" ] || [ "$id" == "I1" ]; }; then
    continue
  fi
  cat > "$file" <<EOF
# ${id} — \`${name}\` RFC

> ${purpose}

| Field | Value |
|---|---|
| **Canonical ID** | ${id} |
| **Name** | ${name} |
| **Wave** | ${wave} |
| **Languages** | ${langs} |
| **DefStack origin** | ${defstack} |
| **AumSecure origin** | ${aumsecure} |
| **Sentinel origin** | ${sentinel} |
| **Dependencies** | ${deps} |

## Background

This component is reconciled from the source portfolios per
[\`00-reconciliation-matrix.md\`](../00-reconciliation-matrix.md). Origin mapping:
DefStack ${defstack}; AumSecure ${aumsecure}; Sentinel ${sentinel}. The full strategic rationale
appears in the matrix entry and the originating source document (see
[\`source-matrix/README.md\`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** ${purpose}

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

Implementation language(s): ${langs}. The component consumes the contract plane
(\`proto/\`, \`specs/\`, \`testvectors/\`) and depends on: ${deps}.

Detailed per-message and per-RPC design will be expanded in this section during the component's
Wave sprint (MVP week 2 → v1.0 week 8). The contract definitions land in \`proto/warrantor/<service>/v1/\`
and \`specs/\` first; this RFC section references them.

**Dependency note:** where ${id} depends on a Wave-2+ component not yet shipped (e.g. I1
agent-identity), Wave-1 code integrates against the **mock** defined in the relevant \`proto/\`
file. The mock-to-real migration is a tracked task in the component's tasks/ directory.

## Dependencies

- **AumOS internal:** ${deps}
- **External:** enumerated during the component's MVP sprint (week 2) and recorded in the RFC.
- **Standards adopted:** SPIFFE/SPIRE, OCSF, OpenTelemetry, CycloneDX/SPDX, CloudEvents, gRPC,
  OpenSSF Model Signing (per \`docs/cross-cutting/19-inter-component-protocol.md\`).

## Threat Model

A full STRIDE analysis is produced during the component's Alpha sprint (week 4). Security-critical
components (T-group, R-group, I-group, S6/R7 eBPF) get the full template per
\`docs/cross-cutting/\` threat-model standard; non-security components get the condensed version.

Cross-cutting threats and mitigations are summarized in [\`02-architecture.md\`](../02-architecture.md) §9.
The 12 formal invariants (I-01…​I-12) that this component must satisfy are listed in
\`02-architecture.md\` §3; the component's tests assert the relevant subset.

## API

Public surface (CLI, gRPC service, library) is defined in \`proto/warrantor/<service>/v1/<name>.proto\`
and exposed via generated bindings (Rust/Python/TypeScript/Go) per
\`docs/cross-cutting/19-inter-component-protocol.md\`. CLI subcommands follow the
\`<component> <verb> --flag\` convention.

## Testing

- **Unit:** ≥85% coverage gate (per \`docs/cross-cutting/18-developer-experience.md\`).
- **Golden vectors:** \`testvectors/${id}/\` — exercised by the cross-language conformance suite (A6).
- **Integration:** cross-component flows per \`docs/cross-cutting/\` integration-test standard.
- **Fuzz:** required for crypto/parsing-heavy components (per fuzzing strategy cross-cutting).
- **Performance:** budget listed in \`02-architecture.md\` §10 where applicable.

## Deployment

If deployable (one of the 14 deployable components), ships with: Dockerfile, Helm chart, K8s
manifest, OTel instrumentation stub, PDB (min available 2), HPA (min 3, max 10), topology spread.
RTO/RPO per \`docs/cross-cutting/16-disaster-recovery.md\`. SLSA L3 build provenance; CycloneDX SBOM
attached to release.

## Milestones

| Milestone | Target | Deliverable |
|---|---|---|
| Week 2 (MVP) | Wave-start + 2wk | Minimal usable version; 1 golden vector; CI green |
| Week 4 (Alpha) | Wave-start + 4wk | Core features; threat model; external integrations stubbed |
| Week 6 (Beta) | Wave-start + 6wk | All features; conformance green; perf targets measured |
| Week 8 (v1.0) | Wave-end | ≥85% coverage; v1.0 tag; signed release; SBOM; SLSA L3 |

## Cross-references

- Reconciliation: [\`../00-reconciliation-matrix.md\`](../00-reconciliation-matrix.md)
- Architecture: [\`../02-architecture.md\`](../02-architecture.md)
- Protocols consumed: see \`specs/\` and \`proto/\`
EOF
  count=$((count + 1))
done <<< "$COMPONENTS"

echo "Generated $count component RFCs in $RFC_DIR"
