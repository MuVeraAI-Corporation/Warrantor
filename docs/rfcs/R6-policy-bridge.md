# R6 — `policy-bridge` RFC

> Fail-closed reference adapters. One policy produces consistent decisions across OPA/Cedar/OpenShell. Decision-equivalence tests.

| Field | Value |
|---|---|
| **Canonical ID** | R6 |
| **Name** | policy-bridge |
| **Wave** | 2 |
| **Languages** | Rust ref + multi-engine adapters |
| **DefStack origin** | (none) |
| **AumSecure origin** | agent-policy-bridge (V3 repo #4) |
| **Sentinel origin** | (none) |
| **Dependencies** | T1, R5 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack (none); AumSecure agent-policy-bridge (V3 repo #4); Sentinel (none). The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** Fail-closed reference adapters. One policy produces consistent decisions across OPA/Cedar/OpenShell. Decision-equivalence tests.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

The reference implementation is [`rust/policy-bridge`](../../rust/policy-bridge). It defines one
validated `osaf.policy/1` model with an explicit default deny, ordered identity-independent rules,
exact or wildcard principal/action matching, exact/global/trailing-prefix resource matching, and
exact context conditions. Canonical serialization produces a SHA-256 policy digest.

The in-process reference evaluator implements deterministic deny-overrides. OPA, Cedar, and
OpenShell adapters use an injected `EngineClient`; every request includes the complete canonical
policy and digest. An adapter rejects a different digest, unknown matched-rule IDs, malformed
responses, or transport failure. `DecisionBridge` requires at least two uniquely named engines
and returns no partial result unless every engine agrees on allow/deny and digest.

The crate also provides the stable OPA Rego module and a deterministic OpenShell bundle compiler.
The adapter boundary is deliberately transport-neutral so the caller can use local processes,
mTLS services, or embedded engines without hardcoding credentials or endpoints.

## Dependencies

- **AumOS internal:** R5 source compiler and T1 digest/signature policy.
- **External adapters:** OPA/Rego, Cedar, and OpenShell. The crate does not vendor or silently
  substitute those engines.

## Threat Model

| Threat | Enforced mitigation |
|---|---|
| Permissive empty/default policy | Format requires explicit default deny and at least one valid rule. |
| Semantic drift | All engines receive the same canonical document/digest and must agree. |
| Stale/wrong policy response | Returned digest must equal the request digest. |
| Fabricated rule evidence | Matched IDs must exist in the canonical policy. |
| One-engine outage | Equivalence returns an error and no decision. |
| Duplicate engine masquerading as independence | Engine kinds must be unique. |
| Prefix confusion | Only a trailing `*` is a resource prefix; interior wildcards are invalid. |

## API

The public surface includes `CanonicalPolicy`, `Rule`, `DecisionRequest`, `ReferenceEngine`,
`ExternalEngine`, `EngineClient`, `DecisionBridge`, `OPA_REGO_MODULE`, and `compile_openshell`.
External clients return structured `EngineResponse`; no adapter parses unstructured success text.

## Testing

- Unit tests cover validation, deny-overrides, exact/prefix matching, four-engine equivalence,
  digest substitution, unknown rules, engine outage, divergence, and OpenShell bundle output.
- Local acceptance: focused tests pass and the crate participates in workspace formatting/Clippy.
- A retained run against independently installed OPA, Cedar, and OpenShell binaries, performance
  evidence, and cross-version semantic vectors are still required before claiming external-engine
  interoperability. Injected client tests prove fail-closed contracts, not those deployments.

## Deployment

R6 is a library used by policy-enforcing services. Production wiring must authenticate engine
connections, pin supported engine versions, retain equivalence evidence, and fail readiness when
the configured quorum is unavailable. This reference crate is not a deployable policy service.

## Milestones

| Milestone | Target | Deliverable |
|---|---|---|
| Week 2 (MVP) | Wave-start + 2wk | Minimal usable version; 1 golden vector; CI green |
| Week 4 (Alpha) | Wave-start + 4wk | Core features; threat model; external integrations stubbed |
| Week 6 (Beta) | Wave-start + 6wk | All features; conformance green; perf targets measured |
| Week 8 (v1.0) | Wave-end | ≥85% coverage; v1.0 tag; signed release; SBOM; SLSA L3 |

## Cross-references

- Reconciliation: [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md)
- Architecture: [`../02-architecture.md`](../02-architecture.md)
- Protocols consumed: see `specs/` and `proto/`
