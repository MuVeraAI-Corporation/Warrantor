# 16 — Agent Manifest (`agent.yaml`)

> **Status:** FROZEN CANDIDATE v1.0. The OpenAPI for agents. A declarative, signed, receipted
> description of what an agent *is* — its identity, the side-effect classes it may use, the policies
> that bind it, the model/tools/data it depends on, the runtime attestation it requires, and the
> enforcement mode under which it operates. An agent without a valid signed manifest cannot obtain
> authority.
>
> **Companion schemas:** [`16-agent-manifest.schema.json`](16-agent-manifest.schema.json) (JSON Schema
> 2020-12). **Reference implementations:** `rust/agent-manifest`, `python/warrantor_agent_manifest`.
> **Conformance:** [`testvectors/agent-manifest/vectors.json`](../../testvectors/agent-manifest/vectors.json).

---

## 1. Why this exists

Every agent framework reinvents "what is this agent?" — identity, capabilities, constraints,
dependencies — and none of the answers port. `agent.yaml` is the declarative standard that ports
across frameworks (LangChain, OpenAI Agents, CrewAI, AutoGen, n8n, the Warrantor Studio): it declares
intent, not implementation, and it is **itself signed and anchored as a receipt**. Whoever ships this
owns the agent-portability layer the way OpenAPI owns API description.

The manifest is consumed by:

- the **Warrantor gateway** (X8) — authority is granted only to agents whose manifest matches the
  requested action's side-effect class and policy refs;
- the **Warrantor receipt envelope** (W2) — every receipt names the manifest digest of the agent that
  acted;
- the **Warrantor Studio / no-code adapters** (N2) — a citizen developer's canvas emits a manifest;
- the **Warrantor marketplace** (N9) — a vendor agent is listed by its signed manifest.

## 2. The eleven fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `apiVersion` | string (`"agent.warrantor.io/v1"`) | YES | Schema version. |
| `kind` | string (`"AgentManifest"`) | YES | Always `AgentManifest`. |
| `name` | string | YES | Human-readable agent name. |
| `identity` | string (SPIFFE ID) | YES | The agent's canonical SPIFFE ID. MUST be a valid `spiffe://` URI. |
| `capabilities` | array&lt;enum&gt; | YES | Side-effect classes the agent may use. Subset of `["read","write","financial","destructive","physical"]` (the invariant I-08 ladder). MUST be non-empty. |
| `policy_refs` | array&lt;string&gt; | YES | IDs of the Cedar/Rego policies that bind the agent. MUST be non-empty. |
| `dependencies.model` | string (digest) | NO | The model weight digest that served the agent (`sha256:&lt;hex&gt;` or `&lt;algo&gt;:&lt;hex&gt;`). |
| `dependencies.tools` | array&lt;string&gt; | NO | Tool SPIFFE IDs the agent may call. |
| `dependencies.data` | array&lt;string&gt; | NO | Data resources (SPIFFE IDs or URNs) the agent may read. |
| `attestation` | array&lt;string&gt; | NO | Required runtime attesters (`tee:sev-snp`, `tee:tdx`, `gpu:nras`, `rim:&lt;algo&gt;:&lt;hex&gt;`, `svid:spiffe`). |
| `enforcement_mode` | enum | YES | One of `["observed","mediated"]`. Only `mediated` may substantiate a containment claim (per spec 03). |
| `description` | string | NO | Free-text description. |
| `version` | string (semver) | NO | The manifest's own semantic version. |

Plus the **signature envelope** (§3) and optional **metadata** (§4).

## 3. The signature envelope

A manifest is unsigned until it is wrapped:

```json
{
  "manifest": { ...the eleven fields... },
  "signature": {
    "algorithm": "Ed25519",
    "key_id":    "issuer-key-2026-01",
    "public_key": "<hex-encoded Ed25519 verifying key, 32 bytes>",
    "value":     "<hex-encoded signature over canonical(manifest)>"
  },
  "issued_at":  "2026-08-11T20:00:00Z",
  "issuer":     "spiffe://yourcorp/authority/manifest-issuer",
  "expires_at": "2027-08-11T20:00:00Z"
}
```

**Canonicalization** (deterministic, so a third party can recompute): the `manifest` object is
serialized as canonical JSON (RFC 8785, sorted keys, no insignificant whitespace, UTF-8); the
signature is Ed25519 over those exact bytes. A verifier MUST (a) validate the manifest against the
JSON Schema, (b) recompute canonical JSON independently, (c) verify the Ed25519 signature, (d) check
`issued_at <= now < expires_at`. A manifest whose signature does not verify is not a manifest; it is
a request.

## 4. Metadata (optional, unsigned)

A `metadata` map may carry non-normative information (owner, team, cost-center, tags). It is NOT
covered by the signature; a verifier MUST ignore it for authority decisions.

## 5. Normative rules

1. **Identity is immutable.** An agent's `identity` SPIFFE ID MUST NOT change across versions of the
   same manifest lineage; a new identity is a new agent.
2. **Capabilities are a ceiling, not a floor.** The gateway denies any action whose side-effect class
   exceeds the manifest's `capabilities`, regardless of what the policy or the model "believes" is
   allowed. This is invariant I-08 enforced at the manifest boundary.
3. **Enforcement mode is honest.** A manifest that declares `enforcement_mode: mediated` MUST be
   backed by a real `mediated` deployment (an escape suite, not a flag — per spec 03). A manifest
   issued under `observed` deployment MUST NOT declare `mediated`.
4. **The manifest is the agent's constitution.** An agent cannot modify its own manifest (invariant
   I-11, self-change protection). Manifest issuance is a consequential action (I-08) requiring
   human approval.
5. **The manifest digest is in every receipt.** Every W2 evidence envelope emitted by the agent MUST
   reference the manifest digest (`sha256:canonical(manifest)`) under which it acted.

## 6. Worked example

```yaml
apiVersion: agent.warrantor.io/v1
kind: AgentManifest
name: payments-bot-3
identity: spiffe://yourcorp/agents/payments-bot-3
capabilities: [read, write, financial]
policy_refs: [pol_44, pol_88]
dependencies:
  model: sha256:1a2b3c...
  tools: [spiffe://yourcorp/tools/stripe-charge, spiffe://yourcorp/tools/refund-api]
  data:  [spiffe://yourcorp/data/customer-db:read-only]
attestation: [tee:sev-snp, gpu:nras]
enforcement_mode: mediated
description: Handles customer refund requests up to $500.
version: 1.2.0
```

## 7. Conformance

Every implementation MUST pass the vectors in
[`testvectors/agent-manifest/vectors.json`](../../testvectors/agent-manifest/vectors.json): for each
vector, parse, validate against the schema, verify the signature (where present), and assert the
expected `valid` outcome AND, on failure, the specific `error_code`. A vector that all implementations
pass identically is the contract.

## 8. What this is not

- Not an orchestration spec. It does not say how the agent reasons, plans, or composes with other
  agents (W6 delegation handles inter-agent authority; orchestration is out of thesis).
- Not a runtime. It is a declaration; enforcement is the gateway's job (X8).
- Not a substitute for receipts. The manifest says what the agent *is*; the receipt says what it *did*.
- Not a guarantee of model behaviour. A manifest with `capabilities: [read]` does not prevent the
  model from *trying* to write; it guarantees the gateway will deny the write.
