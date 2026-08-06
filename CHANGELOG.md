# Changelog

All notable changes to AumOS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per `docs/cross-cutting/15-open-source-governance.md` release process, every release tag
has its CHANGELOG entry populated by the release workflow and reviewed by a maintainer.

## [Unreleased]

### Added — Wave 1.5 (CI hardening)

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
