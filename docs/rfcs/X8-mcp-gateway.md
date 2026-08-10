# X8 — `mcp-gateway` RFC

> MCP middleware with authority-aware admission. Token audience, confused-deputy defense, result provenance.

| Field | Value |
|---|---|
| **Canonical ID** | X8 |
| **Name** | mcp-gateway |
| **Wave** | 2 (docs) |
| **Languages** | TypeScript + Rust verify |
| **DefStack origin** | (none) |
| **AumSecure origin** | mcp-authority-gateway (V2 W0) |
| **Sentinel origin** | (none) |
| **Dependencies** | I1, S4, T1 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack (none); AumSecure mcp-authority-gateway (V2 W0); Sentinel (none). The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** MCP middleware with authority-aware admission. Token audience, confused-deputy defense, result provenance.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

The TypeScript implementation is split into two explicit boundaries:

1. `mcp-gateway` resolves the requested tool in a registry, evaluates the caller's P1 Agent
   Authority Envelope, and passes only an `AllowedAuthorizationResult` to a required
   `ToolTransport`. The discriminated result type guarantees that an allowed decision carries
   the exact tool SVID and side-effect class that were evaluated.
2. `aumos-mcp-server` exposes the AumOS control operations over stdio. Its default `connected`
   dependency graph calls the real HTTP services and CLIs. The deterministic `standalone`
   implementation is an explicit demo-only graph and is never used as an error fallback.

The bundled `McpHttpTransport` sends one JSON-RPC `tools/call` POST to the endpoint resolved for
the authorized tool SVID. It declares the MCP protocol version, accepts JSON or Server-Sent
Events, enforces a timeout, requires HTTPS except for loopback development, matches the response
ID, validates the JSON-RPC envelope, and converts remote errors into typed gateway failures.
Only a validated remote result increments the `forwarded` counter; denials and transport failures
increment `failed` and cannot produce a success acknowledgement.

The stdio server implements the modern `2026-07-28` stateless era: every request carries the
reserved `io.modelcontextprotocol/*` version and client-capability metadata, `server/discover`
advertises supported versions and server capabilities, and modern tool/list results carry
`resultType` plus required cache metadata. A contained dual-era path retains explicit
`initialize` compatibility for `2025-11-25` and `2024-11-05`; requests without modern metadata
are rejected unless that legacy handshake has succeeded.

Connected server adapters validate every security-relevant response field before returning
success. Outages use `CONTROL_UNAVAILABLE`; malformed success-status responses use
`CONTROL_RESPONSE_INVALID`. Neither error contains a synthetic `valid`, `allowed`, `triggered`,
`revoked`, receipt, SVID, signature, attestation, SBOM, or evaluation bundle.

## Dependencies

- **AumOS internal:** I1, S4, T1
- **External:** MCP Streamable HTTP; the T1 `trust-core` and X1 `defstack` CLIs; configured HTTP
  endpoints for I1, E1, C1-1, R2, R3, R4, S4, and A1.
- **Standards adopted:** SPIFFE/SPIRE, OCSF, OpenTelemetry, CycloneDX/SPDX, CloudEvents, gRPC,
  OpenSSF Model Signing (per `docs/cross-cutting/19-inter-component-protocol.md`).

## Threat Model

Primary threats and implemented mitigations:

| Threat | Mitigation |
|---|---|
| Confused deputy calls a tool outside delegated authority | Exact tool SVID membership and gateway audience checks before transport invocation |
| Consequential action bypasses approval | Side-effect rank plus explicit approval binding for financial, destructive, and physical tools |
| Dependency outage is misreported as control success | Required transport and fail-closed connected adapters; no mock fallback |
| Compromised service returns a success-shaped but incomplete payload | Runtime validation of required security fields |
| Response substitution or stale event is accepted | JSON-RPC version and request-ID matching |
| Cleartext remote interception | HTTPS required for non-loopback Streamable HTTP endpoints |
| Hung server consumes the caller's time budget | AbortController timeout and typed retryability |
| Remote error is hidden behind a synthetic acknowledgement | JSON-RPC errors propagate as `remote_error`; forwarding counters advance only on validated results |

Cross-cutting threats and mitigations are summarized in [`02-architecture.md`](../02-architecture.md) §9.
The 12 formal invariants (I-01…​I-12) that this component must satisfy are listed in
`02-architecture.md` §3; the component's tests assert the relevant subset.

## API

Public surface (CLI, gRPC service, library) is defined in `proto/warrantor/<service>/v1/<name>.proto`
and exposed via generated bindings (Rust/Python/TypeScript/Go) per
`docs/cross-cutting/19-inter-component-protocol.md`. CLI subcommands follow the
`<component> <verb> --flag` convention.

## Testing

- **Unit:** authority ordering, confused-deputy defenses, consequential approvals, required
  transport injection, JSON and SSE forwarding, response-ID matching, HTTPS, timeout, HTTP and
  JSON-RPC error propagation, and all connected adapter outage/malformed-response paths.
- **Golden vectors:** `testvectors/X8/` — exercised by the cross-language conformance suite (A6).
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
