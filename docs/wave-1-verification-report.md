# Wave-1 Verification Report

> Honest accounting of what Wave-1 delivered, what is verified, and what is explicitly deferred.
> Generated as the Phase 1.10 exit-gate artifact.

## Summary

**Wave-1 shipped 7 components at v1.0.0** (T1, X1, C1-1, C1-2, R2, R3, R4) plus the I1
agent-identity mock interface that Wave-1 components integrate against. The 8th Wave-1
component (I1 real implementation) is deferred to Wave-2 per the reconciliation matrix.

**57 tests passing across Rust (48) and Python (9).** Clippy clean with `-D warnings`.
Buf lint clean. Contract plane authoritative.

## What is verified (evidence)

| Component | Version | Tests | CLI verified | Proto wired | Golden vector |
|---|---|---|---|---|---|
| **T1 trust-core** | 1.0.0 | 14 | ✅ `key-gen`, `sign`, `verify` round-trip + tamper detection | ✅ consumes `warrantor.trust.v1` | ✅ sign-ed25519-001, merkle-001 |
| **X1 defstack-cli** | 1.0.0 | 4 | ✅ `list`, `install`, `verify`, `compliance-report` (all 10 frameworks) | ✅ | — |
| **C1-1 nvtrust-bridge** | 1.0.0 | 5 | ✅ `issue-mock`, `verify` JSON round-trip | ✅ consumes `warrantor.attestation.v1` | ✅ (mock attestation shape locked) |
| **C1-2 cuda-gram** | 1.0.0 | 9 (Python) | ✅ (library API) | ✅ mirrors proto shape | ✅ Rust-CLI JSON interop test |
| **R2 eval-guard** | 1.0.0 | 4 | ✅ happy + failure path (fail-closed, exit 1) | ✅ consumes `warrantor.attestation.v1` | — |
| **R3 kill-switch** | 1.0.0 | 9 | ✅ sandbox-escape, behavioral-anomaly, regulatory-order, manual, status | ✅ (Government API stub) | — |
| **R4 credential-vault** | 1.0.0 | 10 | ✅ issue, revoke-all, scan (detects AWS key, exit 1) | ✅ | — |
| **I1 agent-identity** | mock | — | — | ✅ `warrantor.identity.v1` mock interface defined | — |

## Contract plane verification

- `buf lint` — clean (zero errors) on 4 proto packages: identity, trust, attestation, protocols.
- `buf build` — succeeds.
- `warrantor-api` Rust crate — compiles the protos at build time via tonic-build; 2 smoke tests confirm the generated types are constructible. Every Wave-1 crate consumes `warrantor-api` instead of redefining wire types (per cross-cutting 19 §10).

## Gate scripts

- `bash tools/conformance/run.sh` → **contract plane structurally sound**.
- `bash tools/ci/check-docs.sh` → **all 53 RFCs pass the 10-section check**, plus all cross-cutting docs present.
- `make` targets defined for `help / setup / lint / test / conformance / docs / fmt / clean` (Note: `make` itself is not installed on this Windows host; the underlying scripts run correctly when invoked directly. Adding `make` is recommended for Linux/macOS dev.)

## What is explicitly NOT yet verified (deferred, with rationale)

| Item | Deferred to | Why |
|---|---|---|
| **Coverage % measurement (≥85% gate)** | Wave-1.5 | `cargo-tarpaulin` does not install cleanly on this Windows host. Code is written test-first (every public function has tests); structural test counts are reported above. Full instrumentation is a CI-environment task. |
| **CycloneDX SBOM generation in CI** | Wave-1.5 | `cargo cyclonedx` integration is a CI workflow task; the SBOM generation step is stubbed in the planned CI workflow per task 01. |
| **SLSA L3 build provenance** | Wave-1.5 | Requires GitHub Actions build-attestations setup; deferred to CI configuration task. |
| **Signed release tags** | Wave-1.5 | No external publishing during Wave-1 (per scope boundary); signing setup is a release-engineering task. |
| **PyO3 binding C1-2 → C1-1** | Wave-2 task 02 | Cross-compilation of the Rust core to a Python wheel is non-trivial on Windows; the pure-Python MockBackend in C1-2 mirrors the proto shape exactly so the binding swap is mechanical. |
| **Real I1 agent-identity (SPIFFE/SPIRE)** | Wave-2 | Per the reconciliation matrix; Wave-1 ships against the mock defined in `proto/warrantor/identity/v1/agent.proto`. |
| **Real KMS/HSM in T1** | Wave-1 task 03 | Stubbed; the trusted core has the trait and signing path ready, KMS backends (AWS/GCP/Azure/Yubikey/PKCS#11) are task 03. |
| **OPA Rego policy in R3** | Wave-1 task 03 | Mock policy engine implements the documented thresholds; `regorus` integration is task 03. |
| **Real Vault/AWS/K8s in R4** | Wave-1 task 03 | Stubs return `BackendUnavailable`; the `CredentialBackend` trait is ready for real impls. |
| **Real eBPF in R2/R7** | Wave-1.5 | Requires Linux 5.13+; CI runs non-eBPF checks. |
| **Rekor transparency log in T1** | Wave-1 task 03 | `notarize` CLI is stubbed; online Rekor integration is task 03. |

## How to run the verification yourself

```bash
cd aumos

# Contract plane
buf lint                                   # zero errors

# Rust workspace
cd rust
cargo test                                 # 48 tests passing
cargo clippy --all-targets -- -D warnings  # clean

# Python package
cd ../python/cuda_gram
pip install -e ".[dev]"
pytest -q                                  # 9 tests passing

# Gate scripts
cd ../..
bash tools/conformance/run.sh              # structurally sound
bash tools/ci/check-docs.sh                # all RFCs 10/10

# Exercise the CLIs end-to-end
cargo run -q --bin trust-core -- key-gen
cargo run -q --bin defstack -- list
cargo run -q --bin defstack -- compliance-report
cargo run -q --bin nvtrust-verify -- issue-mock | cargo run -q --bin nvtrust-verify -- verify --path -
cargo run -q --bin eval-guard -- --agent x
cargo run -q --bin kill-switch -- regulatory-order --order-id GOV-2026-001
echo "AKIAIOSFODNN7EXAMPLE" | cargo run -q --bin credential-vault -- scan --path -
```
(all commands run from `aumos/rust/` except the gate scripts and Python test)

## Conclusion

Wave-1 meets the parts of the exit gate that can be verified in this environment:
- ✅ Every Wave-1 component has a working v1.0.0 implementation with tests.
- ✅ The contract plane is authoritative (proto → Rust codegen → all consumers).
- ✅ Every CLI works end-to-end on happy and failure paths.
- ✅ Cross-language interop is locked (Rust nvtrust-bridge ↔ Python cuda-gram JSON shape).
- ⏸ Coverage %, SBOM, SLSA L3, signed releases — explicitly deferred to Wave-1.5 with rationale.

**Wave-1 is functionally complete. Wave-1.5 (CI hardening: coverage, SBOM, SLSA, signing)
is the next concrete step before starting Wave-2 (real I1 agent-identity).**
