# AumOS Error Code Registry

> Centralized registry of error codes for all AumOS components.
> Per cross-cutting 19 §6.1: every error uses the format `AUMOS.<COMPONENT>.<REASON>`.
> This file is the single source of truth for error code strings.

## Format

```
AUMOS.<COMPONENT_PREFIX>.<REASON>
```

## Component Prefixes

| Prefix | Component | Language | Status |
|--------|-----------|----------|--------|
| `TRUST` | T1 trust-core | Rust | Active |
| `AUTH` | T2 authority-spec | Rust | Active |
| `IDENTITY` | I1 agent-identity | Go | Active |
| `EVALGUARD` | R2 eval-guard | Rust | Active |
| `KILLSWITCH` | R3 kill-switch | Rust | Active |
| `CREDVAULT` | R4 credential-vault | Rust | Active |
| `POLICY` | R5 policy-compiler | Python | Active |
| `EGRESS` | R7 egress-filter | Rust | Active |
| `EXFIL` | S6 exfil-guard | Rust | Active |
| `EVIDENCE` | E1 flight-recorder | Rust | Active |
| `NVTRUST` | C1-1 nvtrust-bridge | Rust | Active |
| `CUDAGRAM` | C1-2 cuda-gram | Python | Active |
| `ATTESTA` | C1-3 attesta-flow | Python | Active |
| `TEE` | C1-4 tee-serve | Go | Active |
| `FABRIC` | C1-5 confidential-fabric | Rust | Active |
| `STPP` | S1 safe-tensors-pp | Rust | Active |
| `PROVENA` | S2 provena-chain | Rust | Active |
| `SBOM` | S4 model-sbom | Python | Active |
| `DATAPROV` | S5 data-provenance-kit | Python | Active |
| `TAMPER` | S7 tamper-scan | Python | Active |
| `TRAINGUARD` | S8 train-guard | Python | Active |
| `LIGHTWELL` | S9 lightwell-bridge | Go | Active |
| `EVAL` | A1 safe-eval | Python | Active |
| `ADVERSARIA` | A2 adversaria | Python | Active |
| `BIAS` | A3 bias-sentinel | Python | Active |
| `COMPLY` | A4 comply-gate | Python | Active |
| `AGENTSEC` | A5 agentsec-lab | Python | Active |
| `CONFORM` | A6 conformance | Rust | Active |
| `REDTEAM` | A7 red-team-cloud | Python | Active |
| `ARENA` | A8 arena | TypeScript | Active |
| `SERVE` | N1 open-serve-kit | Go | Active |
| `BRIDGE` | N2 bridge-rt | Python | Active |
| `PROXY` | N3 inference-proxy | Rust | Active |
| `TENANT` | N4 tenant-guard | Go | Active |
| `FED` | F1 fed-core | Python | Active |
| `DP` | F2 dp-crate | Python | Active |
| `EDGE` | F3 edge-sentinel | Go | Active |
| `FLEET` | F4 fleet-marshal | Go | Active |
| `NOOA` | X2 nooa-ext | Python | Active |
| `HARNESS` | X3 open-harness-spec | Python | Active |
| `CRYPTOAUDIT` | X4 crypto-audit-ai | Python | Active |
| `RETRO` | X5 retro-spec-kit | Python | Active |
| `METR` | X6 metr-bridge | Python | Active |
| `CONSOLE` | X7 console | TypeScript | Active |
| `MCP` | X8 mcp-gateway | TypeScript | Active |
| `INCIDENT` | X9 incident-exchange | Python | Active |
| `DEFSTACK` | X1 defstack-cli | Rust | Active |

## Standard Reason Categories

Every component should use these standard reason suffixes where applicable:

| Reason | HTTP Status | Description |
|--------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid identity credential |
| `FORBIDDEN` | 403 | Identity valid but action not permitted |
| `NOT_FOUND` | 404 | Requested resource does not exist |
| `CONFLICT` | 409 | Resource already exists or state conflict |
| `INVALID` | 400/422 | Malformed input or validation failure |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `UNAVAILABLE` | 503 | Service or backend unavailable |
| `TIMEOUT` | 504 | Operation timed out |
| `INTERNAL` | 500 | Internal error (details logged server-side) |

## Security-Specific Reasons

| Reason | Description |
|--------|-------------|
| `SIGNATURE_INVALID` | Cryptographic signature did not verify |
| `SIGNATURE_EXPIRED` | Signature valid but past expiry |
| `ATTESTATION_FAILED` | Hardware/runtime attestation failed |
| `SANDBOX_VIOLATED` | Sandbox boundary check failed (R2 eval-guard) |
| `POLICY_DENIED` | OPA/Cedar policy engine denied the action |
| `AAE_INVALID` | Agent Authority Envelope (P1) validation failed |
| `AAE_EXPIRED` | AAE has passed its expiry timestamp |
| `DELEGATION_DEPTH_EXCEEDED` | Delegation chain too deep |
| `AUDIENCE_MISMATCH` | Token presented to wrong audience (confused deputy) |
| `REPLAY_DETECTED` | Nonce/timestamp replay attack detected |
| `REVOKED` | Identity or credential has been revoked |
| `KILL_SWITCH_TRIGGERED` | Kill-switch activated; session terminated |
| `CAPABILITY_NEGOTIATION_FAILED` | Client/server could not agree on capabilities |
| `QUOTA_EXCEEDED` | Tenant resource quota exceeded |

## JSON Error Format

All errors MUST be returned in this format:

```json
{
  "code": "AUMOS.PROXY.RATE_LIMITED",
  "message": "The agent identity token expired at 2026-08-05T12:00:00Z",
  "details": {
    "identity": "spiffe://aumos.dev/agent/x",
    "limit_per_sec": 100
  },
  "request_id": "req-abc-123",
  "trace_id": "trace-xyz-789"
}
```

## Implementation Guide

### Rust
```rust
// In each component's error module:
impl From<YourError> for (String, u16) {
    fn from(e: YourError) -> (String, u16) {
        match e {
            YourError::SignatureInvalid => ("AUMOS.TRUST.SIGNATURE_INVALID".into(), 401),
            YourError::Expired { .. } => ("AUMOS.TRUST.SIGNATURE_EXPIRED".into(), 401),
            // ...
        }
    }
}
```

### Go
```go
// Centralized error → wire code mapping
func ErrorCode(err error) (code string, httpStatus int) {
    switch {
    case errors.Is(err, ErrRevoked):
        return "AUMOS.IDENTITY.REVOKED", 401
    case errors.Is(err, ErrAudienceMismatch):
        return "AUMOS.IDENTITY.AUDIENCE_MISMATCH", 401
    case errors.Is(err, ErrAuthorityExpanded):
        return "AUMOS.IDENTITY.DELEGATION_DEPTH_EXCEEDED", 403
    default:
        return "AUMOS.IDENTITY.INTERNAL", 500
    }
}
```

### Python
```python
# Centralized error registry
ERROR_CODES = {
    "scan_failed": ("AUMOS.TAMPER.INTERNAL", 500),
    "backdoor_detected": ("AUMOS.TAMPER.POLICY_DENIED", 403),
}
```

## Review Cadence

- This registry is reviewed quarterly.
- New components must register their prefix before shipping.
- Breaking changes to error codes require a major version bump.
