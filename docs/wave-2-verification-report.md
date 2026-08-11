# Wave-2 Verification Report

> Honest accounting of Wave-2 — what shipped, what is verified, what is deferred. Generated as
> the Phase 2.8 exit-gate artifact.

## Summary

Wave-2 shipped **7 components at v1.0.0** (T2, I1, E1, S1, S4, A6, A5) and wired the Wave-1
components off the mock I1 onto the real Go I1 implementation (documented in
`docs/wave-2-integration-guide.md`).

**Test totals across the repo: 106 tests passing** (72 Rust + 26 Python + 8 Go), clippy clean,
buf lint clean, cross-language conformance verified in Rust + Python + Go.

## What is verified (evidence)

| Component | Version | Language | Tests | Verification |
|---|---|---|---|---|
| **T2 authority-spec** | 1.0.0 | Rust | 9 | AAE validator: signature + expiry + side-effect class + I-08 approval + delegation depth |
| **I1 agent-identity** | 1.0.0 | Go (activated) | 8 | Real SVID issue/verify/revoke + delegation intersection (I-02) + revocation budget (I-05); binary runs, `/healthz` + `/versionz` green |
| **E1 flight-recorder** | 1.0.0 | Rust | 8 | Signed AAR emission pre-commit (I-07), tamper detection, OCSF + OTel JSON export |
| **S1 safe-tensors-pp** | 1.0.0 | Rust | 7 | `__provenance__` block, sign/verify, tamper detection, write/read round-trip, backward-compat |
| **S4 model-sbom** | 1.0.0 | Python | 8 | CycloneDX 1.5 + SPDX 3.0 with AI extensions (model.architecture/parameters/training_data/base_model/evaluations/license); CLI |
| **A6 conformance** | 1.0.0 | Rust + Python + Go | 1 vector × 3 langs | **Cross-language Ed25519 verification** — same signature verifies identically in all three languages |
| **A5 agentsec-lab** | 1.0.0 | Python | 9 | Adversarial benchmark framework; prompt-injection scenario; refusing + compliant baselines; rotating holdouts; maintainer-first disclosure gating |

## Cross-language conformance proof (A6)

The single most load-bearing Wave-2 result. The same Ed25519 signature in
`testvectors/T1/sign-ed25519-conformance-001.json` verifies identically in:

- ✅ Rust (`warrantor-trust-core` CLI)
- ✅ Python (`tools/conformance/verify_python.py` via cryptography/PyNaCl)
- ✅ Go (`tools/conformance/verify_go.go` via `crypto/ed25519`)

This is the proof that the contract plane actually works across the language boundaries.

## Wave-1 wire-off-mock

Documented in `docs/wave-2-integration-guide.md`. The 3 Wave-1 components that depended on mock
I1 (R2 eval-guard, R3 kill-switch, R4 credential-vault) now have a real wire path to the Go
I1 service at the HTTP/JSON endpoints defined in `go/agent-identity/service.go`. Type-stable:
the Go service emits JSON shapes matching `warrantor_api::identity::v1::*` exactly, so a future
`buf generate` swap to connect-go / tonic stubs is mechanical.

## What is explicitly NOT yet verified (deferred)

| Item | Deferred to | Why |
|---|---|---|
| Real SPIRE integration in I1 | Wave-3 task 03 | I1 v1.0 uses an in-process Ed25519 CA (same algorithm as T1). SPIRE WorkloadAPI integration is task 03. |
| OTLP export (real OTel collector) in E1 | Wave-3 task 03 | E1 v1.0 emits the OTel-shaped JSON a collector consumes; real OTLP wiring is task 03. |
| CBOR canonicalization alignment | Wave-3 task 03 | T1 trust-core uses canonical CBOR; the Go I1 and Rust E1 use stable byte-concatenation encodings for v1.0 (still verifiable cross-language). CBOR alignment is task 03. |
| Real garak/PyRIT/MDASH wrapping in A2 | Wave-3 | A2 adversaria is Wave-3; A5 v1.0 ships the framework + a built-in scenario, with external-tool wrapping landing in A2. |
| Coverage % gate (≥85% hard) | Wave-3 | Coverage workflow is in place (`coverage.yml`); the ≥85% hard gate activates in Wave-3 once cargo-llvm-cov reports baseline numbers on Linux CI. |

## How to run the verification yourself

```bash
cd aumos

# Contract plane
buf lint

# Rust workspace (72 tests)
cd rust && cargo test && cargo clippy --all-targets -- -D warnings && cd ..

# Python packages (26 tests across cuda_gram + model_sbom + agentsec_lab)
cd python/cuda_gram     && pip install -e ".[dev]" && pytest -q && cd ../..
cd python/model_sbom    && pip install -e ".[dev]" && pytest -q && cd ../..
cd python/agentsec_lab  && pip install -e ".[dev]" && pytest -q && cd ../..

# Go (8 tests)
cd go/agent-identity && go test ./... && cd ../..

# Cross-language conformance (Rust + Python + Go against the same signature)
bash tools/conformance/run.sh

# Gate scripts
bash tools/conformance/run.sh   # conformance
bash tools/ci/check-docs.sh     # docs

# Smoke the new CLIs
model-sbom --name m --architecture transformer --parameters 7000000000 --training-data dataset://x --license Apache-2.0 --format cyclonedx | head -20
agentsec-lab run --target-compliant
go run ./go/agent-identity/cmd/agent-identity -addr=:18442 & sleep 1 && curl -s http://127.0.0.1:18442/healthz
```

## Conclusion

Wave-2 is **functionally complete and verified**. The most important deliverable — provable
cross-language conformance — is green. Wave-3 (supply chain + eval: S2 ProvenaChain, S5
DataProvenanceKit, S7 TamperScan, S8 TrainGuard, A1 SafeEval, A2 Adversaria) is the next
concrete step.
