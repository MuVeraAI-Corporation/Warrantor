# Changelog

All notable changes to AumOS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per `docs/cross-cutting/15-open-source-governance.md` release process, every release tag
has its CHANGELOG entry populated by the release workflow and reviewed by a maintainer.

## [Unreleased]

### Added — Wave 3 (supply chain + eval)

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
