# AGENTS.md — C1-1 nvtrust-bridge anti-patterns

What **not** to do when building C1-1 nvtrust-bridge.

## Universal (apply to every component)
- ❌ Don't reinvent SPIFFE, OCSF, OTel, CycloneDX, CloudEvents, OpenSSF Model Signing — extend them.
- ❌ Don't hand-write protobuf messages; generate from `proto/`.
- ❌ Don't add a fourth protocol tier (only gRPC internal, REST external, CloudEvents async).
- ❌ Don't commit without `-s` (DCO).
- ❌ Don't merge without two reviewer approvals.
- ❌ Don't ship with <85% test coverage.
- ❌ Don't cut a release without an attached CycloneDX SBOM.
- ❌ Don't log PII — redact before logging (per cross-cutting 17).

## C1-1-specific
- ❌ Don't re-implement a security invariant that T1 trust-core owns — call T1.
- ❌ Don't implement crypto in Python or Go — route through T1.
- ❌ Don't log credentials or attestation reports at trace level — they may contain sensitive material.
- ❌ Don't download the real NVIDIA NVTrust SDK in CI (NDA-gated). Use the documented Mock impl.
- ❌ Don't use ctypes for FFI — use the Rust binding via PyO3 (C1-2 calls C1-1's Rust core).
