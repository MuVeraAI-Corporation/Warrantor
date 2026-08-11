# 19 — Inter-Component Protocol

> Components talk to each other over **typed, versioned contracts** — never ad-hoc. This standard
> closes gap-analysis-v3 gap #37 and is the practical expression of the polyglot stack pressure
> test's "contract plane is the real platform spine."

## Why this exists

DefStack v1/v2 left inter-component protocols implicit. Without an explicit protocol:
- Components drift in wire format.
- No type safety across language boundaries.
- Breaking changes ship silently.
- The 6 pairwise language boundaries explode into unmaintainable surface area.

The fix: **three protocol tiers**, each with strict rules, all defined in `proto/` and `specs/`,
gated by Buf breaking-change detection.

---

## 1. The Three Tiers

| Tier | Use case | Wire format | Defined in |
|---|---|---|---|
| **Internal (service-to-service)** | AumOS components talking to each other | **gRPC + protobuf** | `proto/warrantor/<service>/v1/*.proto` |
| **External (client-facing)** | REST APIs, webhooks, third-party integrations | **REST + JSON** (HTTP/1.1 or HTTP/2) | `specs/rest/<service>/v1/*.yaml` (OpenAPI 3.1) |
| **Async (event-driven)** | Audit events, action receipts, eval results, incident signals | **CloudEvents + Kafka** | `specs/events/<topic>/v1/*.yaml` + `proto/warrantor/events/v1/*.proto` |

**Rule:** no component invents a fourth tier. No raw TCP, no custom binary, no XML, no SOAP. If you
need streaming, use gRPC server-streaming or bidirectional streaming.

---

## 2. Protobuf Conventions (internal tier)

### 2.1 Package and file layout
```
proto/
└── aumos/
    ├── identity/v1/         # I1 agent-identity
    │   ├── agent.proto
    │   └── spiffe.proto
    ├── trust/v1/            # T1 trust-core
    │   ├── signing.proto
    │   └── verification.proto
    ├── evidence/v1/         # E1 flight-recorder
    │   └── receipt.proto
    └── ...
```

- Package: `aumos.<service>.v1` — the `v1` is mandatory and bumps on breaking change.
- File: lowercase underscore. One message type per file when practical.
- Use `buf lint` with the `STANDARD` ruleset (configured in repo-root `buf.yaml`).

### 2.2 Message and field rules
- `message Names` use PascalCase. Fields use snake_case.
- Every field gets a stable, explicitly-numbered tag (`= 1`, `= 2`, …). Never renumber.
- Required fields use the explicit `required` keyword (proto3 optional semantics). Avoid
  `optional` unless the field is genuinely optional.
- Reserve deleted field numbers: `reserved 7, 8;` with a comment.
- Enums: `enum Color { COLOR_UNSPECIFIED = 0; RED = 1; … }` — zero value is always `<NAME>_UNSPECIFIED`.
- Timestamps: `google.protobuf.Timestamp`. Durations: `google.protobuf.Duration`.
- Money, bytes, large integers: use the appropriate well-known type, never `int64` for money.

### 2.3 Services
```proto
service AgentIdentity {
  rpc IssueIdentity(IssueIdentityRequest) returns (IssueIdentityResponse);
  rpc VerifyIdentity(VerifyIdentityRequest) returns (VerifyIdentityResponse);
  rpc Revoke(RevokeRequest) returns (RevokeResponse);
}
```
- Idempotent RPCs include a `string request_id` field.
- Long-running RPCs return a `google.longrunning.Operation`.
- Every RPC has a deadline documented in the OpenAPI/protobuf comment (default 5s; attestations may
  allow 30s).

---

## 3. REST Conventions (external tier)

### 3.1 OpenAPI 3.1 spec per service
Each external service has `specs/rest/<service>/v1/openapi.yaml`. Generated types live in each
language's SDK folder. Never hand-write REST clients — always generate.

### 3.2 URL and verb conventions
- Resource-oriented: `/v1/agents`, `/v1/agents/{id}/credentials`, not `/getAgentCredentials`.
- Standard verbs: GET (read), POST (create / non-idempotent action), PUT (replace), PATCH (partial),
  DELETE.
- Status codes: 200 OK, 201 Created, 202 Accepted (async), 204 No Content, 400 Bad Request,
  401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 422 Unprocessable, 429 Too Many
  Requests, 500/502/503/504 for server errors.

### 3.3 Pagination, filtering, sorting
- Cursor pagination: `?cursor=<opaque>&limit=<int>`. Response includes `next_cursor`.
- Filter: `?filter[<field>]=<value>`. Multiple filters AND together.
- Sort: `?sort=-created_at,name` (descending created_at, ascending name).

---

## 4. Async Events (CloudEvents + Kafka)

### 4.1 Every async event is a CloudEvent
```json
{
  "specversion": "1.0",
  "id": "uuid",
  "source": "/aumos/agent-identity",
  "type": "com.warrantor.agent.identity.revoked",
  "time": "2026-08-05T12:34:56Z",
  "datacontenttype": "application/protobuf",
  "subject": "agent/abc-123",
  "data_base64": "<base64-encoded protobuf>"
}
```

### 4.2 Topics
Kafka topics follow `aumos.<domain>.<event>.v<N>`:
- `warrantor.identity.revoked.v1`
- `warrantor.evidence.receipt.v1`
- `warrantor.evaluation.completed.v1`
- `warrantor.incident.detected.v1`

### 4.3 Delivery semantics
- **At-least-once** (default). Consumers must be idempotent (use the CloudEvent `id`).
- **Exactly-once** available for transactional consumers via the transactional API — opt-in only.
- Retention: audit events 7 years; receipts indefinite; eval results 90 days.

---

## 5. Standard RPC Catalog

These RPCs are expected on (almost) every service:

| RPC | Purpose | Required on |
|---|---|---|
| `Health` / `/healthz` | Liveness/readiness | Every service |
| `Version` / `/versionz` | Build/version info | Every service |
| `Metrics` | Prometheus scrape | Every service |
| `GetAttestation` | Returns this service's attestation (C1-1/C1-2) | Every service in CC mode |

---

## 6. Error Code Registry

Every error is a structured JSON object with a stable code:

```json
{
  "code": "AUMOS.IDENTITY.TOKEN_EXPIRED",
  "message": "The agent identity token expired at 2026-08-05T12:00:00Z",
  "details": { "expired_at": "2026-08-05T12:00:00Z" },
  "request_id": "req-abc-123",
  "trace_id": "trace-xyz-789"
}
```

### 6.1 Code format
`AUMOS.<COMPONENT>.<REASON>` — e.g. `AUMOS.TRUST.SIGNATURE_INVALID`,
`AUMOS.IDENTITY.TOKEN_EXPIRED`, `AUMOS.EVALGUARD.SANDBOX_VIOLATION`.

### 6.2 Component prefixes
Every canonical component has a registered prefix (see `docs/00-reconciliation-matrix.md`):
T1 → `TRUST`, I1 → `IDENTITY`, R2 → `EVALGUARD`, R3 → `KILLSWITCH`, R4 → `CREDVAULT`, C1-1 →
`NVTRUST`, C1-2 → `CUDAGRAM`, E1 → `EVIDENCE`, X1 → `DEFSTACK`, etc.

### 6.3 Standard categories
- `*_UNAUTHORIZED` (401), `*_FORBIDDEN` (403), `*_NOT_FOUND` (404), `*_CONFLICT` (409),
  `*_INVALID` (400/422), `*_RATE_LIMITED` (429), `*_UNAVAILABLE` (503), `*_TIMEOUT` (504),
  `*_INTERNAL` (500).
- Security-sensitive failures (signature invalid, attestation failed, sandbox violated) log full
  detail server-side but return a generic `*_UNAUTHORIZED` to the client to avoid information
  leakage.

---

## 7. Capability Negotiation

Clients and servers negotiate capabilities at connection time, **not** by version equality:

```proto
message Capability {
  string name = 1;            // e.g. " confidential-computing"
  string min_version = 2;     // semver
  string max_version = 3;
}
message HelloRequest { repeated Capability capabilities = 1; }
message HelloResponse { repeated Capability accepted = 1; }
```

A client requests the capabilities it wants; the server returns the subset it accepts. If the
intersection is empty for a required capability, the connection fails with `AUMOS.*.CAPABILITY_NEGOTIATION_FAILED`.

**Why not version equality:** different components ship at different cadences. Capability
negotiation lets a newer client talk to an older server (and vice versa) as long as the feature they
need is mutually understood.

---

## 8. Security of the Protocol Plane

| Threat | Mitigation |
|---|---|
| Eavesdropping | mTLS on every internal gRPC channel (SPIFFE identities from I1) |
| Tampering | protobuf fields are not signed individually; whole-message signatures via T1 trust-core where integrity matters |
| Replay | `request_id` + nonce + timestamp window (5 minutes) |
| Downgrade | Capability negotiation rejects unknown-critical fields; TLS 1.3 only |
| Confused deputy | Every RPC carries the caller's AAE (P1); servers enforce the AAE's scope |
| Information leakage | Generic error codes to clients; full detail server-side only |

---

## 9. Versioning and Compatibility

- **v1, v2, v3** at the package level. A new major version ships alongside the old; both supported
  for at least 12 months.
- **Adding a field** is minor (forward-compatible) — no version bump.
- **Removing/renaming/retyping a field** is major — new package version required.
- `buf breaking --against '.git#branch=main'` runs on every PR; failures block merge.
- **Compatibility manifests** (per the stack pressure test) declare which protocol versions each
  component release supports.

---

## 10. Generating Cross-Language Bindings

**Implemented today — Rust only, and not via buf:**

```
proto/ ──build.rs (tonic-build)──> OUT_DIR ──include!──> warrantor-api
         runs on every `cargo build`; nothing committed
```

**Planned — the other three languages:**

```
proto/ ──(not yet)──┬── python/      (grpcio + protobuf)
                    ├── typescript/  (connect-es + protobuf-es)
                    └── go/          (connect-go + protobuf-go)
```

Go, Python and TypeScript currently hand-mirror the wire types where they need them, and say so at
the definition site (`go/agent-identity/service.go`). buf is used for `lint` and `breaking` only;
there is no `buf.gen.yaml` and no `buf generate` step. See `proto/README.md` for why one targeting
Rust must not be reintroduced.

**Rules:**
- Generate, don't hand-write — for Rust this is enforced structurally, because the types live only
  in `OUT_DIR` and are rebuilt from `proto/` on every build, so drift is not expressible.
- Each language wraps generated types in ergonomic, idiomatic facades; the generated types are never
  the public API.
- A conformance test (A6) verifies that a message serialized in one language deserializes identically
  in every other language, using the golden vectors in `testvectors/`.

---

## 11. Review Cadence

- This standard is reviewed **monthly**.
- Any new RPC requires an RFC update to this catalog and a Buf breaking-check pass.
- Protocol changes that affect multiple components require a Steering Committee sign-off (per
  `15-open-source-governance.md`).
