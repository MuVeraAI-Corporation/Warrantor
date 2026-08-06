# Changelog

All notable changes to AumOS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per `docs/cross-cutting/15-open-source-governance.md` release process, every release tag
has its CHANGELOG entry populated by the release workflow and reviewed by a maintainer.

## [Unreleased]

### Added — Wave 6 (cross-cutting aggregation)

13 components at v1.0.0:
- **X2 nooa-ext** (Python, 14 tests): PolicyEnforcer (OPA/Rego), AuditStreamer, IdentityBinder, AttestationHook.
- **X3 open-harness-spec** (Python, 10 tests): 5 vendor-neutral interfaces + conformance checker.
- **X4 crypto-audit-ai** (Python, 16 tests): IMPLEMENTATION_AUDIT / ALGORITHM_STRESS_TEST / DEPENDENCY_SCAN.
- **X5 retro-spec-kit** (Python, 17 tests): 6 transcript analyzers (network/real-system/behavioral/credential/supply-chain/unauthorized).
- **X6 metr-bridge** (Python, 10 tests): METREvalAdapter, TranscriptExporter, RiskReportBridge, IndependentVerifier.
- **X9 incident-exchange** (Python, 14 tests): 6 incident types, OCSF extension, MITRE ATLAS mapping.
- **A3 bias-sentinel** (Python, 15 tests): bias (BOLD/HONEST/CrowS-Pairs/WinoBias) + copyright (n-gram).
- **A4 comply-gate** (Python, 16 tests): CI/CD gates (coverage/sbom/eval/disclosure), break-glass overrides.
- **A7 red-team-cloud** (Python, 15 tests): continuous adversarial simulation wrapping A2.
- **R5 policy-compiler** (Python, 17 tests): NL/rules → OPA Rego + Cedar policy emitter.
- **R7 egress-filter** (Rust, 12 tests): eBPF egress enforcement; domain blocklist; canary IP detection.
- **S6 exfil-guard** (Rust, 20 tests): PatternMatcher (AWS/GitHub/OpenAI/SSN/CC), EntropyDetector, VolumeMonitor.
- **S9 lightwell-bridge** (Go, 17 tests): AI-artifact patch distribution extending Lightwell.

### Verified at the Wave-6 exit gate
- 592 tests passing total (148 Rust + 113 Go + 331 Python).
- 44 components at v1.0.0 shipped across Waves 1–6.
- clippy clean; buf clean; conformance verified; docs sound.

## [1.0.0] — Wave 5 (confidential compute + federated/edge)

- **C1-3 attesta-flow** v1.0 (Python, 5 tests + Terraform): E2E attested inference pipeline
  orchestrator running inside a TEE; emits signed PipelineAttestation per batch; Azure
  DC-series Terraform provisioning.
- **C1-4 tee-serve** v1.0 (Go, 21 tests): TEE-backed model serving sidecar; TLS terminates in
  TEE; forwards via Unix Domain Socket; wraps responses in Ed25519-signed AttestationEnvelope;
  <2ms overhead target; healthz/readyz/versionz/pubkey routes.
- **C1-5 confidential-fabric** v1.0 (Rust, 23 tests): composite attestation (GPU + runtime +
  agent identity → CompositeAttestation with canonical digest); KeyReleasePolicy (freshness /
  GPU / TEE / runtime-digest / SVID / publisher clauses); ConfidentialContainer with KDF;
  FleetView aggregation.
- **F1 fed-core** v1.0 (Python, 34 tests): attested federated training orchestration;
  Aggregator/Trainer/Verifier roles; admit gate (attestation required); FedAvg aggregator;
  DefaultVerifier (NaN/Inf/norm/free-rider/image-digest); DP delegated to F2 via callback.
- **F2 dp-crate** v1.0 (Python, 41 tests): production-grade differential privacy;
  DPSGDOptimizer (clip-then-noise); PrivacyAccountant (RDP-based moments accountant with
  composition); DPDashboard; pure-Python (TEE-safe).
- **F3 edge-sentinel** v1.0 (Go, 26 tests): edge inference attestation agent (<5MB binary);
  periodic attestation loop; TamperDetector; idempotent kill switch; alerter; systemd shape.
- **F4 fleet-marshal** v1.0 (Go, 25 tests): Kubernetes operator; ModelFleet CRD; canary /
  blue-green / all-at-once rollout strategies; FailureThreshold auto-rollback; RolloutExecutor.

### Verified at the Wave-5 exit gate
- 399 tests passing total (116 Rust + 96 Go + 187 Python).
- 31 components at v1.0.0 shipped across Waves 1–5.

## [1.0.0] — Wave 4 (inference stack)

- **N1 open-serve-kit** v1.0 (Go, 7 tests): OpenAI-compatible /v1/chat/completions proxy with
  per-model router; pluggable backends (vLLM/Triton/TensorRT-LLM/Ollama/Mock); optional
  attestation envelope per response; healthz/versionz.
- **N2 bridge-rt** v1.0 (Python, 17 tests): unified generate() API auto-selecting
  TRT-LLM > vLLM > Ollama > Mock; **TRT-LLM v0.16 sampler_type detection and adaptation**;
  CLI probe + generate.
- **N3 inference-proxy** v1.0 (Rust, 10 tests): middleware chain — allow-list/open auth,
  per-identity token-bucket rate limit, prompt-injection/PII/content-policy filter, exact-match
  cache. Cache hit verified end-to-end.
- **N4 tenant-guard** v1.0 (Go, 9 tests): multi-tenant GPU scheduler; MIG (hw) + MPS (sw)
  + none isolation; per-tenant quota; per-tenant AAE attestation enforcement; MIG-limit cap.
- **Wave-4 integration guide + verification report**.

### Verified at the Wave-4 exit gate
- 224 tests passing total (93 Rust + 107 Python + 24 Go).
- 24 components at v1.0.0 shipped across Waves 1–4.

## [1.0.0] — Wave 3 (supply chain + eval)

- **S2 provena-chain** v1.0 (Rust, 11 tests): Merkle provenance ledger; entry append with
  deterministic leaf hashes; checkpoint sign/verify (Ed25519) anchored to a transparency log;
  JSON-LD export.
- **S5 data-provenance-kit** v1.0 (Python, 11 tests): dataset lineage tracker recording 7
  transformation types (filter/map/dedup/concat/pii_redact/custom); order-independent snapshot
  digests; signed JSON-LD export; CLI.
- **S7 tamper-scan** v1.0 (Python, 13 tests): 4 analyzers (weight-distribution / backdoor /
  neuron-pruning / fine-tune); numpy acceleration with pure-Python fallback; CLI exits non-zero
  on HIGH/CRITICAL.
- **S8 train-guard** v1.0 (Python, 15 tests): framework-agnostic training monitor; gradient
  NaN/explosion/vanishing; loss divergence; dependency-hash integrity; weight-init sanity;
  signed TrainingAttestation.
- **A1 safe-eval** v1.0 (Python, 10 tests): YAML pipeline framework; 5 stage adapters
  (benchmarks/adversarial/safety/bias/red_team); pipeline error isolation; VEB (P8) emission;
  CLI.
- **A2 adversaria** v1.0 (Python, 15 tests): unified adversarial framework with 5 built-in
  attack generators (prompt-injection / jailbreak / encoding / multi-turn / training-data-
  extraction); per-type detectors; passthrough + (future) garak/PyRIT backends; CLI.
- **Wave-3 integration guide**: `docs/wave-3-integration-guide.md` documenting the supply-chain
  pipeline + EU AI Act Art. 55 §1/§2/§3/§7 coverage.
- **Wave-3 verification report**: `docs/wave-3-verification-report.md`.

### Verified at the Wave-3 exit gate
- 181 tests passing total (83 Rust + 90 Python + 8 Go).
- clippy clean with `-D warnings`; buf lint clean.
- 20 components at v1.0.0 shipped across Waves 1–3.

## [1.0.0] — Wave 2 (keystone + foundations)

- **T2 authority-spec** v1.0 (Rust, 9 tests): normative Agent Authority Envelope (P1 AAE) CDDL +
  JSON-Schema schemas (`specs/protocols/P1-aae.{cddl,schema.json}`) + Rust reference validator
  enforcing signature, expiry, side-effect class, I-08 approval, delegation depth.
- **I1 agent-identity** v1.0 (Go, 8 tests): real SPIFFE-style SVID issuance + JWT capability
  tokens + delegation chain with intersection semantics (invariant I-02) + in-memory revocation
  meeting the 5s budget (I-05). HTTP/JSON gateway at `/v1/agent-identity:{issue,verify,revoke}`.
  Go activation gate cleared (trigger #3).
- **E1 flight-recorder** v1.0 (Rust, 8 tests): signed Agent Action Receipts (P2 AAR) emitted
  pre-commit (invariant I-07), tamper detection, OCSF + OTel JSON export.
- **S1 safe-tensors-pp** v1.0 (Rust, 7 tests): `__provenance__` block in the safetensors header,
  Ed25519 sign/verify, tamper detection, write/read round-trip, backward-compatible with unsigned
  files.
- **S4 model-sbom** v1.0 (Python, 8 tests): CycloneDX 1.5 + SPDX 3.0 SBOM generator with the
  AI extensions (model.architecture, .parameters, .training_data, .base_model, .evaluations,
  .license). CLI.
- **A6 conformance** v1.0 (Rust + Python + Go, 1 vector × 3 langs): cross-language conformance
  runner proving the same Ed25519 signature verifies identically in all three languages.
- **A5 agentsec-lab** v1.0 (Python, 9 tests): adversarial benchmark framework with rotating
  holdouts, maintainer-first disclosure gating; built-in prompt-injection scenario + refusing and
  compliant baselines.
- **Wire-off-mock documentation**: `docs/wave-2-integration-guide.md` documenting how Wave-1
  components (R2, R3, R4) consume the real Go I1 instead of the proto mock.
- **Wave-2 verification report**: `docs/wave-2-verification-report.md`.

### Verified at the Wave-2 exit gate
- 106 tests passing total (72 Rust + 26 Python + 8 Go).
- clippy clean with `-D warnings`; buf lint clean.
- Cross-language Ed25519 verification confirmed in Rust + Python + Go.

## [1.0.0] — Wave 1.5 (CI hardening)

- **CI**: main workflow (`.github/workflows/ci.yml`) — buf lint + breaking, Rust test/clippy/fmt,
  Python test/ruff, conformance + docs gate scripts. Runs on every push and pull request.
- **Coverage**: `.github/workflows/coverage.yml` — Rust (`cargo-llvm-cov`) and Python
  (`pytest-cov`) coverage reports uploaded as artifacts. ≥85% gate becomes hard in Wave-2.
- **SBOM**: `.github/workflows/sbom.yml` — CycloneDX SBOM per Rust crate and per Python package,
  aggregated and uploaded.
- **SLSA L3 provenance**: `.github/workflows/provenance.yml` — GitHub Actions build-attestations
  for every release binary.
- **Fuzz CI**: `.github/workflows/fuzz.yml` — nightly `cargo-fuzz` on three trust-core targets
  (canonical_cbor, signature_decode, rekor_response); regression corpus uploaded.
- **Release**: `.github/workflows/release.yml` — tag-triggered GitHub Release with binaries,
  SBOM bundle, SHA-256 checksums.
- **Fuzz crate**: `rust/trust-core/fuzz/` — three committed fuzz targets (canonical_cbor,
  signature_decode, rekor_response); excluded from the parent workspace.
- **SECURITY.md** at repo root (mirrors `docs/cross-cutting/14-security-disclosure-policy.md`).
- **Dependabot** config (`.github/dependabot.yml`) — weekly Rust/Python deps, monthly Actions.

## [1.0.0] — Wave 1 (initial release)

### Added — Phase 0 (docs + foundation)
- Reconciliation matrix (`docs/00-reconciliation-matrix.md`) mapping all four source portfolios
  to 44 canonical components + 12 protocols.
- Vision + architecture docs (`docs/01-vision-and-portfolio.md`, `docs/02-architecture.md`):
  12-plane pressure-tested architecture, 12 formal invariants (I-01…I-12), deployment topologies.
- 53 component RFCs (10-section template) — T1 and I1 hand-written in full detail; 51 generated.
- 12 protocol specs (`specs/protocols/P1..P12-*.md`).
- 7 Wave-1 agent-handoff bundles (CLAUDE.md, AGENTS.md, PROMPT.md, tasks 01–08).
- 3 missing cross-cutting docs authored (17-data-classification-privacy, 18-developer-experience,
  19-inter-component-protocol) + originals 13–16 copied in.
- Monorepo skeleton (contract-hub layout per polyglot stack pressure test).
- Makefile (one-command dev/test/release), buf.yaml, conformance + doc-checker scripts.

### Added — Phase 1 (Wave-1 v1.0 components)
- **Proto contract plane** (`proto/aumos/`): identity, trust, attestation, AAR protocols. Buf lint clean.
- **aumos-api** crate: prost/tonic codegen at build time. Single source of truth for wire types.
- **T1 trust-core** v1.0.0 — Ed25519 sign/verify, canonical CBOR, RFC 6962 Merkle. 14 tests.
- **X1 defstack-cli** v1.0.0 — list/install/verify/compliance-report (10 frameworks). 4 tests.
- **C1-1 nvtrust-bridge** v1.0.0 — NvTrustBackend trait + Mock, proto round-trip. 5 tests.
- **C1-2 cuda-gram** v1.0.0 (Python) — AttestationVerifier, CCSession, Rust CLI JSON interop. 9 tests.
- **R2 eval-guard** v1.0.0 — 4 pre-flight checks, signed SandboxAttestation via T1. 4 tests.
- **R3 kill-switch** v1.0.0 — PolicyEngine trait + Mock, Government API stub, <5s budget. 9 tests.
- **R4 credential-vault** v1.0.0 — CredentialBackend trait + Mock/Vault/AWS/K8s stubs, exposure
  scanner. 10 tests.

### Verified
- 57 tests passing (48 Rust + 9 Python).
- clippy clean with `-D warnings`.
- buf lint clean; buf build succeeds.
- Contract plane authoritative: proto → aumos-api → all consumers.
- Cross-language interop locked: Rust nvtrust-bridge ↔ Python cuda-gram JSON shape.

### Deferred
- Coverage % instrumentation, CycloneDX SBOM, SLSA L3, signed releases — CI/release-engineering
  tasks (addressed in 1.5 above).
- Real KMS/HSM, Rekor, OPA Rego, Vault/AWS/K8s, eBPF — Wave-1 task 03/04 work; traits + stubs in place.

[Unreleased]: https://github.com/aumos/aumos/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/aumos/aumos/releases/tag/v1.0.0
