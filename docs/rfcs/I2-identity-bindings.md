# I2 — `identity-bindings` RFC

> SPIFFE/SPIRE binding layer. Rust signs; Go registers workloads via SPIRE WorkloadAPI.

| Field | Value |
|---|---|
| **Canonical ID** | I2 |
| **Name** | identity-bindings |
| **Wave** | 2 |
| **Languages** | Go adapter (consumes T1/I1 identity contracts) |
| **DefStack origin** | (folded into F2) |
| **AumSecure origin** | spiffe-agent-identity (V2 W0) |
| **Sentinel origin** | ztai-spiffe-bridge |
| **Dependencies** | T1, I1 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack (folded into F2); AumSecure spiffe-agent-identity (V2 W0); Sentinel ztai-spiffe-bridge. The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** SPIFFE/SPIRE binding layer. Go registers validated workloads with SPIRE and obtains
continuously maintained X.509-SVIDs from the Workload API. T1 remains the only signing-policy
owner; I2 does not create a second identity or signature format.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

The reference implementation is [`go/identity-bindings`](../../go/identity-bindings). It has two
independent, dependency-injected boundaries:

1. `Registrar` validates a registration entry, renders one exact `spire-server entry create`
   argument vector, invokes it without a shell, and accepts success only when the CLI returns a
   non-empty entry ID. Parent/child SPIFFE IDs must share the configured trust domain. Selector
   type/value pairs must be unique and free of command/control characters. TTL is bounded.
2. `WorkloadSource` uses `github.com/spiffe/go-spiffe/v2/workloadapi` v2.8.1 to maintain an
   X.509 source over the configured Workload API address. Retrieval rejects an empty chain,
   missing URI SAN, wrong SPIFFE ID, future-dated leaf, expired leaf, and source ID mismatch.

The default library has no success-shaped fallback. An unavailable SPIRE CLI or Workload API is
an error. The CLI executor and Workload API source factory are injected so tests can assert exact
arguments and outage behavior without claiming a live SPIRE deployment.

## Dependencies

- **AumOS internal:** T1 and I1 identity/authority contracts.
- **External:** `go-spiffe/v2` v2.8.1 and the operator-installed `spire-server` CLI.
- **Authoritative standards:** [SPIRE registration](https://spiffe.io/docs/latest/deploying/registering/),
  [SPIRE server CLI](https://github.com/spiffe/spire/blob/main/doc/spire_server.md), and
  [go-spiffe Workload API](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi).

## Threat Model

| Threat | Enforced mitigation |
|---|---|
| CLI injection | Arguments are a slice passed directly to `exec.CommandContext`; no shell exists. |
| Trust-domain escape | Parent and child IDs are parsed and compared to the configured domain. |
| Selector ambiguity | Empty, duplicate, NUL, CR, and LF selector values are rejected. |
| Stale credential | Leaf validity is checked against an injected trusted clock on every retrieval. |
| Wrong identity | URI SAN and Workload API source ID must equal the requested SPIFFE ID. |
| Control outage | Registration/source/retrieval errors propagate; no local credential is minted. |

## API

The Go package exports `BindingConfig`, `RegistrationEntry`, `ValidateRegistrationEntry`,
`SPIRECLIRegistrar`, `WorkloadAPISource`, `IdentityCertificate`, and narrow interfaces for command
execution/source construction. Every constructor validates the Workload API address and trust
domain before external work.

## Testing

- Unit tests exercise validation, exact SPIRE arguments, command failure/malformed output,
  Workload API source construction, a real generated X.509-SVID chain, expiry, and ID mismatch.
- Local acceptance: `go test ./...` and `go vet ./...` pass in `go/identity-bindings`.
- Retained live-SPIRE integration evidence, coverage percentage, workload rotation timing, and
  production trust-domain deployment remain release gates; local unit evidence is not that proof.

## Deployment

I2 is a library/adapter deployed with the identity control plane. Operators provide the SPIRE
server socket, Workload API address, trust domain, and CLI binary. This reference implementation
does not by itself prove HA SPIRE deployment, node/workload attestation policy, rotation SLOs,
revocation propagation, SBOM publication, or SLSA provenance.

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
