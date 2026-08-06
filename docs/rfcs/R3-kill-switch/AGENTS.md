# AGENTS.md — R3 kill-switch anti-patterns

What **not** to do when building R3 kill-switch.

## Universal (apply to every component)
- ❌ Don't reinvent SPIFFE, OCSF, OTel, CycloneDX, CloudEvents, OpenSSF Model Signing — extend them.
- ❌ Don't hand-write protobuf messages; generate from `proto/`.
- ❌ Don't add a fourth protocol tier (only gRPC internal, REST external, CloudEvents async).
- ❌ Don't commit without `-s` (DCO).
- ❌ Don't merge without two reviewer approvals.
- ❌ Don't ship with <85% test coverage.
- ❌ Don't cut a release without an attached CycloneDX SBOM.
- ❌ Don't log PII — redact before logging (per cross-cutting 17).

## R3-specific
- ❌ Don't re-implement a security invariant that T1 trust-core owns — call T1.
- ❌ Don't implement crypto in Python or Go — route through T1.
- ❌ Don't log credentials or attestation reports at trace level — they may contain sensitive material.
- ❌ Don't exceed the 5-second end-to-end kill budget — benchmark it in CI.
- ❌ Don't skip the Government Compliance API stub even though the law isn't in force yet.
