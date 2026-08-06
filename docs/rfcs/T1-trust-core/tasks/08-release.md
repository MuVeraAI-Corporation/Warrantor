# Task 08-release — T1 trust-core

> **Sprint:** v1.0 week 7–8. **Acceptance:** v1.0 tag signed; SBOM; SLSA L3; security review scheduled.

## Objective
Cut the v1.0 release.

## Steps
1. Final coverage check: ≥90% on signing/verification/canonical; ≥85% overall.
2. Final clippy: zero warnings.
3. Generate CycloneDX SBOM (`cargo cyclonedx`); attach to the release.
4. Configure SLSA L3 build provenance in CI (GitHub Actions build-attestations).
5. Update CHANGELOG.md with the v1.0 entry.
6. Tag `v1.0.0` (signed); publish crate locally (crates.io publication deferred until Wave-1
   signoff per scope boundary).
7. Schedule external security review (engage NCC Group or Trail of Bits).
8. Update `docs/rfcs/T1-trust-core.md` with final status.

## Acceptance criteria
- [ ] `v1.0.0` tag exists and is signed.
- [ ] CycloneDX SBOM attached to the GitHub release.
- [ ] SLSA L3 provenance present.
- [ ] Coverage gates met.
- [ ] External security review engagement letter filed.
- [ ] RFC marked "Status: v1.0 shipped" at the top.
