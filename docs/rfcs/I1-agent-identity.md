# I1 — `agent-identity` RFC

> The keystone. Wraps SPIFFE/SPIRE with agent identities, tool permissions, action audit logs, and
> revocation. **12 other components depend on it.** Wave-1 components ship against a mock; the real
> implementation lands in Wave-2.

| Field | Value |
|---|---|
| **Canonical ID** | I1 |
| **Name** | agent-identity |
| **Wave** | 2 (M3–M6) — Wave-1 uses the **mock** defined in `proto/warrantor/identity/v1/agent.proto` |
| **Languages** | **Go** (gated — clears activation trigger #3: SPIRE registration lifecycle) + Rust verify calls |
| **Warrantor origin** | F2 AgentVault |
| **AumSecure origin** | "Agent Identity & Authority Fabric" (V2 #2) |
| **Sentinel origin** | ZTAI |
| **Dependencies** | T1 trust-core (signs/verifies SVIDs) |
| **Dependents** | R2, R3, R4, C1-3, C1-5, N1, N3, N4, F1, F3, F4, X2, X6, X9 (12 components) |

## Background

All four source portfolios converge on the same component: Warrantor's `AgentVault` (Go, wraps
SPIFFE/SPIRE), AumSecure's "Agent Identity & Authority Fabric," and Sentinel's `ZTAI`. All extend
SPIFFE/SPIRE with agent-specific claims (publisher, model, version, rules-of-engagement, parent) and
issue short-lived (5–60s) scoped capability tokens. This is the keystone — every dependent component
must verify an identity before acting (invariant I-01).

The polyglot stack pressure test gates Go behind activation triggers; I1 is the canonical
justification for activating Go (trigger #3: SPIRE registration/federation needs programmatic
lifecycle management, and trigger #1: production K8s operator required for the identity controller).

## Goals

- Extend SPIFFE/SPIRE workload identity with agent claims: `agent.publisher`,
  `agent.model`, `agent.version`, `agent.roe` (rules of engagement), `agent.parent`.
- Issue short-lived capability tokens (TTL 5–60s) scoped per AAE (P1): tools, data classes,
  side-effect class, spend/time/token budget, geography, delegation depth.
- Maintain a hash-chained delegation graph (intersection, not union — invariant I-02).
- Revocation propagation: identity <5s fleet-wide, credentials <1s (invariant I-05).
- Audit every identity issuance and revocation to E1 flight-recorder.

## Non-Goals

- Being the policy engine (that's R5/R6 — I1 enforces *identity*; R5/R6 enforce *policy*).
- Cryptographic primitive implementation (delegated to T1 trust-core).
- A second authority engine in another language (forbidden — Go is the sole impl; everyone calls it
  via gRPC).

## Detailed Design

### Architecture
```
                ┌────────────────────────────────────────┐
                │  I1 agent-identity (Go service)        │
                │                                        │
                │  ┌──────────┐  ┌──────────┐           │
                │  │  CA +    │  │ Policy   │           │
                │  │  SVID    │  │ engine   │           │
                │  │  issuer  │  │ (OPA)    │           │
                │  └────┬─────┘  └────┬─────┘           │
                │       │             │                  │
                │  ┌────▼─────────────▼─────┐           │
                │  │  Audit ledger → E1     │           │
                │  │  Delegation graph      │           │
                │  │  Revocation fan-out    │           │
                │  └────────────────────────┘           │
                └────────────────────────────────────────┘
                       │  gRPC (mTLS)
                       ▼
            every other component (R2, R3, R4, N1, ...)
```

### SPIRE extension
- **Sidecar pattern** (not a fork): I1 runs alongside SPIRE, registering agent workloads and
  adding agent claims to the SVID via SPIFFE's `WorkloadAPI`.
- **HSM/TPM-backed CA:** cloud HSM (AWS CloudHSM, GCP HSM) or on-prem TPM for sovereign.
- **Trust domain:** `muveraai.com` default; customer-configurable per deployment.

### Capability token (JWT, signed by I1 via T1)
```json
{
  "iss": "spiffe://muveraai.com/agent-identity",
  "sub": "spiffe://muveraai.com/agent/coding-agent-abc",
  "aud": ["spiffe://muveraai.com/tool/github"],
  "scope": "repo:write",
  "args": { "repo": "warrantor/aumos", "branch": "feat/*" },
  "iat": 1722859200,
  "exp": 1722859260,
  "jti": "uuid",
  "parent_svid": "spiffe://muveraai.com/agent/parent-xyz",
  "policy_hash": "sha256:...",
  "delegation_depth": 2
}
```

### Delegation chain
- Each token carries `parent_svid`; the chain is a hash-chained sequence.
- **Authority = intersection** of every token in the chain (invariant I-02). A child cannot exceed
  its parent's authority. Enforced at every policy check.
- Max delegation depth: 32 (Sentinel target).

### Performance targets
- Token issuance: 5,000/sec/core.
- Token validation: <1ms p99.
- Policy evaluation (OPA inline): <2ms p99.
- Delegation chain validate (32-deep): <10ms p99.
- Revocation propagation fleet-wide: <5s (credential revocation via R4: <1s).

## Dependencies

- **External:** `spire-api-sdk` (Go), OPA/Rego, gRPC-Go, Kafka client (for revocation fan-out
  events).
- **Warrantor:** T1 trust-core (signs SVIDs and capability tokens).

## Threat Model (STRIDE — security-critical, full)

| Threat | Surface | Mitigation |
|---|---|---|
| **Spoofing** | Forged SVID | SVIDs signed by CA (T1); certificate transparency via Sigstore Rekor |
| **Tampering** | Token claims modified | JWT signature (Ed25519 via T1); canonical claims encoding |
| **Repudiation** | Agent denies action | Every issuance/revocation logged to E1 with SVID + AAE hash |
| **Information disclosure** | Token leakage | Short TTL (5–60s); bound to IP; audience-restricted |
| **Denial of service** | Token storm | Per-publisher rate limiting; reputation scoring; backpressure |
| **Elevation of privilege** | Privilege amplification via delegation | Delegation = intersection, not union (I-02); default-deny |

## API / CLI

```
agent-identity issue --publisher <did> --model <id> --purpose <text> --budget <abs.json>
agent-identity verify --token <jwt>
agent-identity revoke --svid <id> --reason <text>
agent-identity delegate --parent <jwt> --child-claims <abs.json>
```

Wire: gRPC service `warrantor.identity.v1.AgentIdentity` (see
`proto/warrantor/identity/v1/agent.proto`). Async: `warrantor.identity.revoked.v1` CloudEvent on Kafka.

## Testing

- **Unit:** ≥85% coverage on token issue/verify, delegation chain, revocation.
- **Integration:** mTLS handshake against a real SPIRE dev server; revocation propagation across 3
  replicas.
- **Property tests:** delegation intersection (the child's authority is always ⊆ parent's).
- **Adversarial:** stolen-token replay, delegation-depth-exceeded, audience-confusion
  (confused-deputy), clock-skew.
- **Performance:** Locust/k6 hitting 5,000 token-issue RPS; verify p99 <1ms.
- **Exit gate:** 12 dependent components integrated and passing their identity tests against I1.

## Deployment

- **Deployable service** (one of the 14 deployable components): 3+ replicas across 3 AZs, HPA (min
  3, max 10), topology spread, PDB (min available 2).
- RTO 1 minute, RPO 0 (sync replication of the audit ledger) — see cross-cutting 16-disaster-recovery.
- Helm chart + K8s manifest + OTel instrumentation stub in `deploy/`.
- SBOM CycloneDX; SLSA L3; FedRAMP target by M18 (per cross-cutting 13).

## Milestones

| Milestone | Target | Deliverable |
|---|---|---|
| Wave-1 (mock) | M0 | `proto/warrantor/identity/v1/agent.proto` mock server returns canned tokens; Wave-1 components integrate |
| Week 2 (MVP) | M3+2wk | Real SPIRE integration; SVID issuance + verify; revocation (single-node) |
| Week 4 (Alpha) | M3+4wk | Capability tokens (JWT); delegation chain; OPA policy eval |
| Week 6 (Beta) | M3+6wk | Multi-replica revocation fan-out; HSM-backed CA; 12 dependents migrated from mock |
| Week 8 (v1.0) | M5 | All features; ≥85% coverage; perf targets met; FedRAMP readiness checklist started |

## Cross-references

- Reconciliation: [`../00-reconciliation-matrix.md`](../00-reconciliation-matrix.md#I1)
- Architecture: [`../02-architecture.md`](../02-architecture.md) planes 1–3
- Mock contract: `proto/warrantor/identity/v1/agent.proto` (Wave-1)
- Protocols: P1 AAE, P7 ABS, P10 MADE, P12 CAP
