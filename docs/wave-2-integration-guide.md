# Wave-2 Integration Guide — Wiring off the Mock I1

> How the Wave-1 components (which integrated against the proto mock of I1 agent-identity) now
> consume the **real** I1 service shipped in Wave-2. Also documents the wire-off for the new
> Wave-2 components (T2, E1, S1, S4, A5, A6) and their dependencies on each other.

## The "wire off the mock" transition

Wave-1 components (`aumos-kill-switch`, `aumos-credential-vault`, `aumos-eval-guard`) integrated
against the proto-defined **mock** I1 interface in `proto/aumos/identity/v1/agent.proto`. Wave-2
ships the real I1 implementation in Go (`go/agent-identity/`), which exposes the same RPCs over
HTTP/JSON at the endpoints defined in `go/agent-identity/service.go`:

| RPC | Method + path | Request body | Response body |
|---|---|---|---|
| `Issue` | `POST /v1/agent-identity:issue` | `IssueRequest` (subject, attributes, claims, parent_svid) | `IssueResponse` (svid, capability_token, verifying_key, expires_at) |
| `Verify` | `POST /v1/agent-identity:verify` | `VerifyRequest` (svid, audience) | `VerifyResponse` (valid, reason, subject) |
| `Revoke` | `POST /v1/agent-identity:revoke` | `RevokeRequest` (jti, reason) | `RevokeResponse` (revoked, revoked_at) |
| `Health` | `GET /healthz` | — | `{"status":"ok"}` |
| `Version` | `GET /versionz` | — | `{"component":"agent-identity","version":"1.0.0","trust_domain":...}` |

### Wiring change (Rust kill-switch example)

The Wave-1 kill-switch reads its trigger from the CLI and (in production) calls I1 to revoke the
agent's identity as part of the kill execution. Wave-1 used the proto mock; Wave-2 swaps in the
real HTTP client:

```rust
// Wave-1 (mock): kill-switch/test set up a mock_svid string inline.
// Wave-2 (real):
let resp = reqwest::Client::new()
    .post("http://agent-identity.aumos.svc.cluster.local:8441/v1/agent-identity:revoke")
    .json(&serde_json::json!({ "jti": &svid_jti, "reason": "kill_switch: sandbox_escape" }))
    .send().await?
    .json::<RevokeResponse>().await?;
assert!(resp.revoked);
```

The wiring is **type-stable**: the JSON shapes the Go service emits match the proto types
`aumos_api::identity::v1::RevokeRequest`/`RevokeResponse` exactly. A future `buf generate`
task (03) will swap the manual `reqwest` calls for generated connect-go / tonic stubs without
changing the wire format.

### Per-component wire-off checklist

| Component | Wave-1 dep | Wave-2 wires to |
|---|---|---|
| R3 kill-switch | mock I1 SVID | real I1 `/v1/agent-identity:revoke` (revokes on kill) |
| R4 credential-vault | mock I1 SVID | real I1 `/v1/agent-identity:issue` (binds creds to SVID) |
| R2 eval-guard | mock I1 SVID | real I1 `/v1/agent-identity:verify` (verifies the agent before sandbox start) |
| E1 flight-recorder | — | real I1 `verifying_key_hex` (to anchor actor SVIDs in receipts) |
| S1 safe-tensors-pp | — | real T1 trust-core (signs the `__provenance__` block) |
| S4 model-sbom | — | real S1 (records model digest) + A1 (records evaluation refs) — A1 is Wave-3 |
| A5 agentsec-lab | — | real E1 (emits AAR per scenario result) — wired in task 03 |
| A6 conformance | — | real T1 golden vectors (already wired; verified in Rust + Python + Go) |
| T2 authority-spec | — | real T1 trust-core (verifies AAE signatures) + real I1 (resolves issuer key) |

### Integration test (smoke)

Run the real I1 service, then issue + verify + revoke an identity end-to-end:

```bash
# Terminal 1: start the real I1 service.
go run ./go/agent-identity/cmd/agent-identity -addr=:8441

# Terminal 2: issue, verify, revoke.
curl -s -X POST http://localhost:8441/v1/agent-identity:issue \
  -H 'content-type: application/json' \
  -d '{"subject":"spiffe://muveraai.com/agent/coding-1",
       "attributes":{"publisher":"muveraai.com/coding-agent","model":"claude-opus-4.5"},
       "claims":{"tools":["github"],"data_classes":["L0","L1"],"side_effect_class":"write","delegation_depth":2}}'

# The response contains the SVID token; pass it to verify.
SVID=$(...)  # extracted from the issue response
curl -s -X POST http://localhost:8441/v1/agent-identity:verify \
  -d "{\"svid\":\"$SVID\"}"

# Revoke by JTI (also in the issue response).
curl -s -X POST http://localhost:8441/v1/agent-identity:revoke -d '{"jti":"...","reason":"test"}'
```

The Go test suite (`go test ./go/agent-identity/...`) exercises this entire flow in-process.

## Wave-2 component dependencies (the new DAG)

```
T2 authority-spec ──────────┐
                            ├─→ I1 agent-identity (Go) ──┐
T1 trust-core (Wave-1) ─────┤                            │
                            ↓                            ↓
                  E1 flight-recorder ←──── R3 kill-switch (Wave-1)
                            │                  R4 credential-vault (Wave-1)
                            ↓                  R2 eval-guard (Wave-1)
                  S1 safe-tensors-pp ──→ S4 model-sbom
                            │
                            ↓
                  A5 agentsec-lab ←── A6 conformance
```

Every arrow is now a real wire path (HTTP/JSON or library call), not a mock.
