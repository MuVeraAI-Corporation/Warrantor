# R1 — `secure-workspace` RFC

> OpenShell-based isolated workspace. Signed policy, credential brokering, network allowlists, controlled inference, approval gates, full action evidence. R2 is its attestation arm.

| Field | Value |
|---|---|
| **Canonical ID** | R1 |
| **Name** | secure-workspace |
| **Wave** | 1 |
| **Languages** | Rust orchestration; injected R8/OpenShell/FORGE backend |
| **DefStack origin** | (none) |
| **AumSecure origin** | Secure Agent Workspace (V2 #1) |
| **Sentinel origin** | (uses OpenShell) |
| **Dependencies** | T1, I1 |

## Background

This component is reconciled from the source portfolios per
[`00-reconciliation-matrix.md`](../00-reconciliation-matrix.md). Origin mapping:
DefStack (none); AumSecure Secure Agent Workspace (V2 #1); Sentinel (uses OpenShell). The full strategic rationale
appears in the matrix entry and the originating source document (see
[`source-matrix/README.md`](../source-matrix/README.md)).

## Goals and Non-Goals

**Goals:** Isolated workspace transaction orchestration with signed policy, credential brokering,
network/filesystem/inference allowlists, consequence ceilings, approval gates, and redacted action
evidence. R2 remains its attestation arm and R8 supplies an in-process sandbox option.

**Non-Goals:**
- Reinventing mature standards (SPIFFE, OCSF, OTel, CycloneDX) — we extend, not fork.
- A second authoritative implementation of any security invariant owned by T1 trust-core.
- Features outside the scope defined in the reconciliation matrix.

## Detailed Design

The reference implementation is [`rust/secure-workspace`](../../rust/secure-workspace). A
`WorkspacePolicy` is serialized and signed through T1 canonical CBOR. Authorization verifies the
signature, format, expiry, exact agent SPIFFE ID, maximum consequence class, command, normalized
guest paths, HTTP(S) origins, inference endpoints, credential references, duration, and output
limits before any allocating or external operation.

Execution is an explicit transaction:

1. Validate policy/request and any approval bound to the exact request digest.
2. Durably append redacted `ExecutionIntent` evidence. If this fails, no credential or sandbox
   call occurs.
3. Lease only the requested broker references; reject empty, expired, overlong, duplicate, or
   unsafe lease bindings and revoke a malformed lease.
4. Create a sandbox from policy-derived limits and execute without a shell.
5. Independently enforce the combined output bound, append the final outcome, destroy the
   sandbox, and revoke the lease. Multiple execution/evidence/cleanup failures are aggregated so
   cleanup loss cannot disappear behind the primary error.

`PolicyVerifier`, `ApprovalGate`, `CredentialBroker`, `EvidenceSink`, and `SandboxBackend` are
required dependencies. There is no permissive default implementation. Evidence contains digests,
identity, outcome, and failure class; arguments, credential references, and secret values are not
serializable in its wire shape.

## Dependencies

- **AumOS internal:** T1 signing, I1/I2 identity, R4 credential broker, R6 policy semantics, R8 or
  an OpenShell/FORGE `SandboxBackend`, and E1 durable evidence.
- **External:** none in the orchestration crate. Physical backends are injected adapters.

## Threat Model

| Threat | Enforced mitigation |
|---|---|
| Policy substitution | T1 signature and policy digest bind every authority/limit field. |
| Subject confusion | Authenticated request SPIFFE ID must exactly equal the signed subject. |
| Path traversal | Absolute guest paths are normalized and checked on component boundaries. |
| Consequence escalation | Request class cannot exceed the signed ceiling; high-impact classes require bound approval. |
| Audit bypass | Durable intent is append-before-lease/create/execute. |
| Credential leakage | Evidence has no argument/secret fields; leases go only to the sandbox backend. |
| Malicious backend output | Orchestrator rechecks combined output length after backend return. |
| Partial cleanup | Destroy and revoke are attempted on every post-allocation execution path; simultaneous failures aggregate. |

## API

The library exposes `WorkspacePolicy`, `SignedWorkspacePolicy`, `ExecutionRequest`,
`SecureWorkspace::authorize`, `SecureWorkspace::execute`, typed dependency traits, redacted
`EvidenceEvent`, and `WorkspaceError`. It intentionally has no local-success CLI or embedded
credential store.

## Testing

- Twelve unit tests cover T1 signature tampering, normal execution, path/network/credential
  escapes, consequence ceiling, approval, intent outage, malformed lease, output overflow,
  execution failure, simultaneous cleanup failures, expiry/subject mismatch, and evidence
  redaction.
- Local acceptance: focused tests and strict `cargo clippy --all-targets --all-features -D warnings`
  pass.
- Retained OpenShell/FORGE integration, eBPF enforcement, credential-manager integration,
  coverage percentage, chaos cleanup, and production evidence-store proof remain open release
  gates. The reference transaction layer is not proof that a particular backend isolates hosts.

## Deployment

R1 is an orchestration library embedded by a control service. The service must wire durable E1,
R4, approval, and physical sandbox dependencies and expose readiness only after all are usable.
This crate does not itself constitute a production deployment, HA proof, or eBPF policy.

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
