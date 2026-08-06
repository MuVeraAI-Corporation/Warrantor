# AGENTS.md — R2 eval-guard anti-patterns

What **not** to do when building R2 eval-guard.

## Universal (apply to every component)
- ❌ Don't reinvent SPIFFE, OCSF, OTel, CycloneDX, CloudEvents, OpenSSF Model Signing — extend them.
- ❌ Don't hand-write protobuf messages; generate from `proto/`.
- ❌ Don't add a fourth protocol tier (only gRPC internal, REST external, CloudEvents async).
- ❌ Don't commit without `-s` (DCO).
- ❌ Don't merge without two reviewer approvals.
- ❌ Don't ship with <85% test coverage.
- ❌ Don't cut a release without an attached CycloneDX SBOM.
- ❌ Don't log PII — redact before logging (per cross-cutting 17).

## R2-specific
- ❌ Don't re-implement a security invariant that T1 trust-core owns — call T1.
- ❌ Don't implement crypto in Python or Go — route through T1.
- ❌ Don't log credentials or attestation reports at trace level — they may contain sensitive material.
- ❌ Don't run eBPF tests on non-Linux CI; gate them and document Linux 5.13+ requirement.
- ❌ Don't make EvalGuard fail-open on attestation errors — invariant I-09 (failure is safe = fail closed).
