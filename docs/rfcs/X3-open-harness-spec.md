# X3 — `open-harness-spec` RFC

> Vendor-neutral agent harness spec. 5 interfaces: AgentIdentity, ToolPermission, AuditEvent, AttestationEnvelope, EvaluationReport. Proposed OSAF standard; AumOS = reference implementation.

| Field | Value |
|---|---|
| **Canonical ID** | X3 |
| **Name** | open-harness-spec |
| **Wave** | 6 |
| **Languages** | Spec (Markdown) + Python conformance |
| **DefStack origin** | F3 OpenHarnessSpec |
| **AumSecure origin** | (none) |
| **Sentinel origin** | (none) |
| **Dependencies** | X2 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack F3 OpenHarnessSpec; AumSecure (none); Sentinel (none). The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** Vendor-neutral agent harness spec. 5 interfaces: AgentIdentity, ToolPermission, AuditEvent, AttestationEnvelope, EvaluationReport. Proposed OSAF standard; AumOS = reference implementation.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

Implementation language(s): Spec (Markdown) + Python conformance. The component consumes the contract plane
(`proto/`, `specs/`, `testvectors/`) and depends on: X2.

Detailed per-message and per-RPC design will be expanded in this section during the component's
Wave sprint (MVP week 2 → v1.0 week 8). The contract definitions land in `proto/aumos/<service>/v1/`
and `specs/` first; this RFC section references them.

**Dependency note:** where X3 depends on a Wave-2+ component not yet shipped (e.g. I1
agent-identity), Wave-1 code integrates against the **mock** defined in the relevant `proto/`
file. The mock-to-real migration is a tracked task in the component's tasks/ directory.

## Dependencies

- **AumOS internal:** X2
- **External:** enumerated during the component's MVP sprint (week 2) and recorded in the RFC.
- **Standards adopted:** SPIFFE/SPIRE, OCSF, OpenTelemetry, CycloneDX/SPDX, CloudEvents, gRPC,
  OpenSSF Model Signing (per `docs/cross-cutting/19-inter-component-protocol.md`).

## Threat Model

A full STRIDE analysis is produced during the component's Alpha sprint (week 4). Security-critical
components (T-group, R-group, I-group, S6/R7 eBPF) get the full template per
`docs/cross-cutting/` threat-model standard; non-security components get the condensed version.

Cross-cutting threats and mitigations are summarized in [`02-architecture.md`](../02-architecture.md) §9.
The 12 formal invariants (I-01…​I-12) that this component must satisfy are listed in
`02-architecture.md` §3; the component's tests assert the relevant subset.

## API

Public surface (CLI, gRPC service, library) is defined in `proto/aumos/<service>/v1/<name>.proto`
and exposed via generated bindings (Rust/Python/TypeScript/Go) per
`docs/cross-cutting/19-inter-component-protocol.md`. CLI subcommands follow the
`<component> <verb> --flag` convention.

## Testing

- **Unit:** ≥85% coverage gate (per `docs/cross-cutting/18-developer-experience.md`).
- **Golden vectors:** `testvectors/X3/` — exercised by the cross-language conformance suite (A6).
- **Integration:** cross-component flows per `docs/cross-cutting/` integration-test standard.
- **Fuzz:** required for crypto/parsing-heavy components (per fuzzing strategy cross-cutting).
- **Performance:** budget listed in `02-architecture.md` §10 where applicable.

## Deployment

If deployable (one of the 14 deployable components), ships with: Dockerfile, Helm chart, K8s
manifest, OTel instrumentation stub, PDB (min available 2), HPA (min 3, max 10), topology spread.
RTO/RPO per `docs/cross-cutting/16-disaster-recovery.md`. SLSA L3 build provenance; CycloneDX SBOM
attached to release.

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
