# AuthZEN PDP and MCP enforcement implementation pressure test

Status: completed bounded implementation wave  
Review date: 2026-08-31  
Scope: two independent AuthZEN PDPs, two independent MCP enforcement paths, and the
decision-to-execution assurance seam required by Warrantor W2/W4/W5/W6  
Prior normative review: [`artifact-review-authzen-coaz-mcp.md`](artifact-review-authzen-coaz-mcp.md)

## Executive decision

This wave changes the prior recommendation from a standards-only design position into an
implementation-backed decision:

1. **Adopt AuthZEN 1.0 as Warrantor's public PDP/PEP decision contract.** Cerbos 0.55 and
   OpenFGA 1.19.0 both accepted final-shaped single evaluations and returned decisions through
   the standard endpoint. They demonstrate that one public API can front materially different
   policy models.
2. **Do not equate AuthZEN interoperability with policy-semantic equivalence.** Cerbos maps
   AuthZEN into a role/attribute policy engine and explicitly treats `subject.type` as
   informational when roles are supplied. OpenFGA maps `subject.type:id`, `action.name`, and
   `resource.type:id` into a Zanzibar-style tuple check. The same wire fields can therefore have
   different policy meaning, validation, and optional-feature behavior.
3. **Do not adopt Cerbos FastMCP unchanged as the Warrantor gateway.** It is a useful, small
   reference integration, but the reviewed main branch authorizes only tool calls, tool listing,
   prompt listing, and resource listing. Controlled calls to `get_prompt`, `read_resource`, and
   resource-template listing reached downstream with zero PDP calls. A controlled
   post-decision argument mutation also changed the executed operation after the PDP had allowed
   a different one. Its bundled policy failed compilation under current Cerbos 0.55.
4. **Do not adopt Vengtoo MCP Gateway 0.1.1 unchanged.** It contains stronger gateway mechanics
   than its maturity signals imply—52 native tests passed, call-time infrastructure failure
   denies, startup enforcement loading is gated, downstream credentials are filtered, and
   blocked/pending tools remain denied. However, its nominal AuthZEN request uses legacy
   `resource.name` and `resource.attributes` fields. Both Cerbos 0.55 and OpenFGA 1.19.0 rejected
   that request shape with HTTP 400. It proxies only tools, uses static bearer-token identity in
   the current release, snapshots downstream tools at startup, and emits no result/effect-bound
   receipt.
5. **Build a narrow Warrantor assurance PEP around the standard seam.** Consume the good
   implementation patterns—external PDP abstraction, fail-closed call authorization, tool-list
   filtering, startup gating, schema-drift detection, credential isolation, PDP discovery, and
   policy/model version selection—but add schema-generated MCP coverage, final AuthZEN/COAZ
   requests, trusted-field provenance, an immutable operation digest, atomic permit consumption,
   non-bypassable forwarding, result/effect linkage, and expected-event reconciliation.

The strongest uncomfortable finding is that a gateway can have a green native test suite and
still fail the basic cross-vendor contract it claims to speak. Native tests and standards-shaped
URLs are therefore insufficient release evidence. Warrantor needs the same negative corpus run
against every PDP/gateway pairing.

## Artifacts and exact versions

| Role | Artifact | Reviewed revision | Release/status | License | Why selected |
|---|---|---|---|---|---|
| PDP A | Cerbos PDP | binary v0.55.0, build `2901f6421b08bb544049bf0fae4e61ebfd52d59b`; source review at `2101aee6ec7997a437f5dce69ce764903c150e6f` | v0.55.0, published 2026-08-13; AuthZEN introduced in v0.48.0 | Apache-2.0 | Independent policy-as-code PDP with final-shaped metadata, evaluation, and boxcar endpoints |
| PDP B | OpenFGA | binary v1.19.0, build `130c30aea5e73543e63b173dadfbd1ee519aa97a`; source review at `a7dfe8491dc7f9cd5905f4e9ae6c8e1d718c4bd9` | v1.19.0, published 2026-08-25; AuthZEN explicitly experimental | Apache-2.0 | Independent Zanzibar-style PDP with evaluation, batch, search, store-scoped discovery, model pinning, and detailed implementation notes |
| PEP A | Cerbos FastMCP middleware | main `3bdaef615dd33ab18b20b48d311335459b52b54c`; latest tag v0.2.0 resolves to `3facd8aa6c8527c48d739adf713dbac014793294` | Alpha; tag says v0.2.0 while package metadata says 0.1.1 | Apache-2.0 | Small native-FastMCP enforcement middleware tied to an independent PDP |
| PEP B | Vengtoo MCP Gateway | v0.1.1 / `8eff94708bf28b8a75c4e818614de4b6f36c667e` | Initial public release, 2026-08-14 | Apache-2.0 | Real proxy/gateway with stdio and HTTP ingress, downstream multiplexing, call authorization, drift state, and audit logging |

These artifacts were selected for architectural independence, public source, free access, current
2026 relevance, and executable paths. A server that merely exposes authorization as an MCP tool
was excluded because an agent can choose not to call it; it is not a PEP.

## Questions tested

The wave tested the implementation questions left open by the normative review:

- Can two different PDPs accept the same final AuthZEN 1.0 evaluation shape?
- Does a gateway that claims AuthZEN interoperate with both without a vendor-specific adapter?
- Which exact MCP operations are intercepted?
- Do unknown or unsupported operations fail closed, fail open, or bypass the PEP?
- Can the operation change after authorization but before downstream execution?
- Is the selected tool-to-downstream mapping stable across the PDP round trip?
- Are retries, human approvals, and duplicate calls bound to one request or permit?
- Are policy/model revision, decision, forwarding, result, and external effect linked?
- Does native testing exercise a live PDP or only a stub?
- Do current example policies and documented run paths still work with current dependencies?

## Reproduction environment and receipts

### Environment

- Review host date: 2026-08-31.
- Python: CPython 3.12.3 for the successful Cerbos FastMCP run.
- Node.js: 18.19.1; npm 9.2.0.
- `uv`: 0.10.4.
- Go toolchain: unavailable; official release binaries were therefore used for PDP runtime
  interoperability while source and committed Go tests were inspected.
- Cerbos release archive SHA-256:
  `01cb5ae0b888393219846c1bc43d4ed1a4701a51fb8ae38523d3a378e685efca`,
  matching the digest published by the GitHub release API.
- OpenFGA release archive SHA-256:
  `c11005ca38dc66028930e96d8099c51e826363b0c461d9c2f4aa0837b4dbb331`,
  matching the digest published by the GitHub release API.

### Native test summary

| Artifact | Command class | Result | What it proves | What it does not prove |
|---|---|---:|---|---|
| Cerbos FastMCP | pinned Python environment, `pytest -q -s` | 36 passed, 3 skipped | Unit behavior, configuration parsing, allow/deny handling, and list filtering under the locked dependency graph | The three live-PDP integration cases were skipped because `CERBOS_GRPC` was absent; no current-PDP interop, full MCP coverage, non-bypassability, mutation resistance, or result binding |
| Cerbos FastMCP sample policy | Cerbos v0.55.0 compiler | failed | Current release compatibility was actually checked | It does not show that older Cerbos versions also fail |
| Vengtoo Gateway | `npm test` | 52 passed | Allow/deny, call blocking, startup gate, HTTP auth, caller separation, drift hashing, pending/blocked state, list filtering, environment filtering, and state behavior exercised by repository tests | AuthZEN 1.0 conformance, COAZ mapping, OAuth 2.1, resources/prompts, remote downstreams, dynamic tool updates, exact operation binding, effect evidence, or external independent evaluation |
| Vengtoo Gateway | TypeScript type-check and build | passed | The pinned source compiles and test types resolve | Runtime security, protocol conformance, and release-package equivalence |
| Cerbos PDP | verified v0.55.0 binary | final-shaped request accepted; allow decision reproduced | Live standard endpoint, metadata, policy evaluation, and final field names | Search APIs, cross-vendor policy equivalence, PEP authentication, signed decisions, or enforcement |
| OpenFGA | verified v1.19.0 binary | store/model/tuple created; final-shaped request accepted and allowed | Live store-scoped AuthZEN discovery and evaluation over a Zanzibar-style model | General availability, every interop scenario, pagination, contextual tuples, signed decisions, or enforcement |

### Current-policy compatibility failure

Cerbos FastMCP's bundled `policies/mcp_tool.yaml` was compiled with Cerbos v0.55.0. Compilation
failed at line 61 because the local constant name `meta::availableActions` is no longer a valid
identifier. This matters for three reasons:

1. The README's one-command live test path depends on these policies.
2. The three live-PDP tests were skipped in the successful local unit run.
3. A passing Python suite did not detect that its example policy could not start the current PDP.

This is version-drift evidence, not proof that the middleware cannot work with a corrected policy.
The recommended gate is to pin the PDP version and compile policies against both the supported
minimum and current target before publishing an integration release.

## Final AuthZEN interoperability

### Control request

Both PDPs accepted the final 1.0 core shape:

```json
{
  "subject": {"type": "user", "id": "alice"},
  "resource": {"type": "document", "id": "roadmap"},
  "action": {"name": "reader"}
}
```

OpenFGA returned `{"decision":true}` for a stored
`user:alice reader document:roadmap` tuple. Cerbos returned a live decision for an equivalent
policy-specific control case using final `id` and `properties` field names.

### Vengtoo request

Vengtoo 0.1.1 constructs:

```json
{
  "subject": {"type": "ai_agent", "id": "agent:test"},
  "resource": {
    "type": "mcp_tool",
    "name": "company__read",
    "attributes": {"record": "acme"}
  },
  "action": {"name": "invoke"}
}
```

That differs from Authorization API 1.0 in the two security-relevant resource members:

| Meaning | Final AuthZEN 1.0 | Vengtoo 0.1.1 |
|---|---|---|
| Resource identifier | `resource.id` | `resource.name` |
| Resource attributes | `resource.properties` | `resource.attributes` |

Observed results:

- Cerbos 0.55: HTTP 400, unknown resource field `name`.
- OpenFGA 1.19.0: HTTP 400, validation failure because required `Resource.Id` is absent.
- Vengtoo's `authorize()` converted both 400 responses into fail-closed
  `{allowed:false, reason:"authorization service error (400)"}`.

Fail-closed behavior is good, but a safe system that denies every legitimate call is not
interoperable or deployable. This exact four-way matrix must become a Warrantor release test:

| Gateway request producer | Cerbos | OpenFGA | Expected |
|---|---:|---:|---|
| Warrantor final-1.0 adapter | must pass | must pass | Same canonical request fixture accepted by both |
| Legacy `name`/`attributes` mutation | must reject | must reject | Schema failure before policy evaluation |

### Why a shared API is not a shared policy language

The two PDPs deliberately map AuthZEN into different native models:

| AuthZEN element | Cerbos 0.55 mapping | OpenFGA 1.19 mapping | Warrantor consequence |
|---|---|---|---|
| `subject.id` | principal ID | left side of `type:id` user | Portable syntax, different native identity construction |
| `subject.type` | informational; when explicit Cerbos roles are absent it can become a fallback role | part of the OpenFGA user string and must exist in the model | Type changes can be policy-significant in different ways |
| subject properties | principal roles, policy version, scope, and attributes, including Cerbos-specific reserved keys | namespaced into OpenFGA condition context | Property namespace and trust rules differ |
| `resource.type` | resource policy kind | object type | Both are policy selectors, but their languages and validation differ |
| `resource.id` | resource ID | object ID | Structurally aligned |
| resource properties | resource attributes plus Cerbos-specific policy version/scope | namespaced condition context | Translation loss and conflict rules differ |
| `action.name` | action string | relation | A verb and a graph relation are not automatically semantically equivalent |
| action properties | currently reserved/ignored by Cerbos | namespaced condition context | Same AuthZEN request can carry effective data in one PDP and inert data in another |
| request context | Cerbos request ID, auxiliary data, and implementation-specific metadata controls | ABAC context with explicit precedence over mapped properties | Trust provenance and key-collision behavior require profiling |
| response context | optional Cerbos metadata when requested | boolean normally; documented decision reasons absent | Obligations and evidence are not portable by default |

AuthZEN solves API fragmentation. W4 must still define a typed policy IR, target capability
declarations, loss reports, trust anchors, semantic differential fixtures, and version-specific
compiler results.

## MCP enforcement coverage

### Cerbos FastMCP

The installed FastMCP 2.12.3 middleware surface exposed these operation hooks:

- `on_call_tool`
- `on_get_prompt`
- `on_list_prompts`
- `on_list_resource_templates`
- `on_list_resources`
- `on_list_tools`
- `on_message`
- `on_notification`
- `on_read_resource`
- `on_request`

Cerbos FastMCP overrides only the following security-relevant hooks, plus initialization:

- `on_call_tool`
- `on_list_tools`
- `on_list_resources`
- `on_list_prompts`

It inherits pass-through behavior for `on_get_prompt`, `on_read_resource`,
`on_list_resource_templates`, generic requests, messages, and notifications.

The controlled bypass vector used a denying dummy PDP and invoked the inherited hooks. Results:

| Operation | Downstream reached | PDP calls | Result |
|---|---:|---:|---|
| Get named prompt | yes | 0 | **Bypass** relative to the README's “every prompt request” claim |
| Read resource | yes | 0 | **Bypass** relative to the README's “every resource query” claim |
| List resource templates | yes | 0 | **Bypass** |

Listing prompts/resources is not equivalent to retrieving their contents. Hiding an object from a
catalog also does not authorize a cached or directly named retrieval. Call-time checks must remain
authoritative even when list filtering is present.

### Vengtoo Gateway

Vengtoo deliberately advertises only MCP tools and handles `tools/list` and `tools/call`.
Resources and prompts are explicitly mid-term roadmap items. This is narrower but more honest:
unsupported primitives are not proxied as supported capabilities.

Current boundaries:

- Inbound: stdio or Streamable HTTP.
- Downstream: spawned stdio subprocesses only.
- Remote HTTP downstreams: roadmap.
- Tool index: startup snapshot.
- `tools/list_changed`: roadmap; a downstream that changes its tool surface after startup is not
  re-discovered in the current release.
- Current HTTP identity: static token-to-subject mapping (“grade 1”). Validated OAuth/MCP
  credentials with expiry/revocation are roadmap.
- Tool arguments: sent to the authorization service at call time.
- Tool result/content policy: roadmap, not current enforcement.

For a tool-only profile, Vengtoo's handler is materially closer to complete mediation than the
reviewed Cerbos middleware because all exposed tool calls cross one call handler. It remains a
process/network topology claim: operators must prevent clients from reaching the downstream MCP
servers directly.

## Adversarial vector results

### Summary matrix

| Vector | Cerbos FastMCP | Vengtoo 0.1.1 | Warrantor release requirement |
|---|---|---|---|
| Final AuthZEN request to two PDPs | Not applicable: native Cerbos gRPC, so vendor lock-in at the PEP seam | **Fail:** both PDPs returned 400 | Final schema fixture plus discovery-driven endpoints |
| Unknown/missing MCP primitive | **Fail/bypass:** inherited hooks forward several supported FastMCP operations without PDP calls | Narrow-deny by non-exposure; resources/prompts unsupported | Schema-generated method registry; deny unknown state-changing methods and notifications |
| Post-decision argument mutation | **Fail reproduced** | No controlled failure found in the reviewed single handler, but no canonical digest or immutable buffer | Hash canonical operation once; evaluate and forward the same immutable bytes |
| Tool mapping swap during PDP wait | No explicit mapping object; later middleware can mutate request | Handler captures the resolved downstream entry before awaiting authorization, reducing this vector | Content-address route/mapping version and bind it into decision/receipt |
| PDP outage/error | **Pass:** exception becomes MCP unauthorized error | **Pass at call time:** timeout/HTTP/network errors deny; optional secondary endpoint failover | Fail closed with typed reason, retry budget, health evidence, and no stale unlimited permit |
| Tool-list authorization error | List authorization failure returns empty list | Visibility filter fails open by default, optionally closed; call-time enforcement remains active | Treat visibility confidentiality and call authorization as separate policies; default closed for sensitive catalogs |
| Startup enforcement restore | PDP connection is checked on initialize when middleware owns the client | Startup call gate waits; timeout denies; cached blocked/pending state can be restored | Signed/versioned last-known policy state, maximum staleness, and explicit degraded mode |
| Approval retry correlation | No approval protocol | **Fail assurance:** returned `approval_id` is not echoed; no `X-Request-ID` was sent in the controlled poll | Stable request/operation digest, approval ID, subject, policy revision, expiry, and atomic consumption |
| Duplicate/retry execution | Each allowed call can execute; no idempotency/permit consumption | Each allowed call can execute; no idempotency/permit consumption | One durable authorize-and-consume record keyed by operation/intent ID |
| Result substitution or egress policy | No result inspection, digest, or evidence | Downstream result returned directly; content guardrails are roadmap | Result digest, egress decision, effect observation, and linked receipt |
| Audit completeness | PDP may log decision, but middleware emits no W2 receipt | Local JSON audit omits arguments despite README claim and has no result/effect digest | Required signed fields, durable append-only sink, expected-set reconciliation, crash boundary tests |
| Direct downstream bypass | Depends on application assembly and network topology | Gateway security policy recognizes bypass as high severity; operator topology still decisive | Bind server identity, isolate network/process access, and prove every supported transport traverses the PEP |

### Vector A — post-decision operation substitution

The Cerbos middleware extracts `tool_name` and `arguments`, builds a Cerbos resource, awaits the
PDP, and then calls the next middleware with the original mutable context. A controlled downstream
middleware changed:

```text
evaluated: transfer {amount: 1, to: "safe"}
executed:  transfer {amount: 1000000, to: "attacker"}
```

The changed call was accepted because the allow decision was a boolean with no checked operation
digest. This is not an allegation that normal FastMCP mutates requests; it proves that the current
composition does not make such mutation impossible or detectable. Middleware ordering, plugins,
normalizers, adapters, and future code all sit inside this trust boundary.

Required correction:

1. Parse and validate once.
2. Canonicalize method, target, arguments, subject, tenant, delegation state, mapping digest, and
   policy revision.
3. Compute `operation_digest`.
4. Submit that digest and structured fields to the PDP/profile.
5. Receive or construct a narrowly scoped permit bound to the digest.
6. Atomically consume the permit and forward the immutable canonical buffer.
7. Reject any byte/semantic mismatch at the forwarding boundary.
8. Link result and externally observed effect to the same operation.

### Vector B — approval retry without returned correlation

A controlled Vengtoo authorization service first returned:

```json
{
  "decision": false,
  "context": {
    "reason_code": "authorization_pending",
    "approval_id": "apr_123",
    "interval": 0.001,
    "expires_in": 2
  }
}
```

The gateway polled and accepted a later approval. Captured requests showed:

- the same legacy SARC-like body was repeated;
- no `approval_id` was echoed in the body;
- no `X-Request-ID` was sent;
- the returned approval ID was used only for logging;
- the approval was not bound to a canonical operation digest or consumed permit.

The implementation comment says the cloud recognizes the same request. That may be true for the
closed Vengtoo service, but the open gateway does not expose a portable, cryptographically bound,
or independently verifiable correlation rule. Identical concurrent requests, retries after a lost
response, and changed policy state therefore remain assurance questions.

### Vector C — result and audit substitution

Vengtoo creates a local random request ID, authorizes, calls downstream, logs, and returns the
downstream result. Its local audit record contains subject, tool, allow/deny, reason, latency, and
request ID. Although the record type receives `args` and the README says arguments are logged, the
serialized entry omits arguments. It also omits:

- canonical request/operation digest;
- PDP endpoint and authenticated identity;
- policy/model revision;
- decision or approval identifier;
- route/mapping version;
- permit expiry and consumption state;
- downstream server/workload identity;
- result digest or egress decision;
- external effect or reconciliation state.

The log is emitted after a successful downstream return. A process crash after an irreversible
effect but before the response/log leaves an evidence gap. This is precisely the W2
evidence-before-commit boundary: an intent/permit record must become durable before the effect,
then be completed or reconciled afterward.

### Vector D — policy and model revision drift

OpenFGA supports an optional `Openfga-Authorization-Model-Id` header. Without it, the latest model
is used. The live response exposed the selected model ID in an HTTP header, but Vengtoo neither
sends a model pin nor records response headers. Cerbos similarly has implementation-specific
policy-version and scope fields.

W4 cannot claim reproducible cross-engine decisions unless the compiled target, policy/model
revision, data/tuple revision or consistency token where applicable, and adapter version are
captured. “AuthZEN allowed” is not enough to replay or explain the decision.

## Per-artifact assessment

### Cerbos PDP 0.55

#### Strengths

- Current, verified release artifacts with published digests and Apache-2.0 source.
- Stateless PDP deployment model with mature native APIs and SDK ecosystem.
- Final AuthZEN metadata, single-evaluation, and boxcar-evaluation endpoints.
- Explicit field mapping documentation instead of pretending native semantics are invisible.
- Policy version, scope, principal/resource attributes, auxiliary data, and optional native
  response metadata can be carried through Cerbos-specific conventions.
- Live final-shaped request and allow decision reproduced.

#### Boundaries

- Documentation correctly says **partially implements** AuthZEN: search APIs are absent from the
  advertised metadata.
- `subject.type` is not a first-class native identity type when explicit roles are present.
- Action properties are reserved/ignored in the reviewed mapping.
- Reserved `cerbos.*` property and context keys create a vendor profile above the base API.
- Decision signing, exact forwarded-operation binding, atomic permit consumption, complete PEP
  coverage, delegation intersection, and W2 receipts are absent.
- PDP authentication and TLS remain deployment responsibilities; the base AuthZEN contract does
  not make them safe automatically.
- Cerbos produces a decision, not proof that the PEP enforced it.

#### Decision

**Adopt as one supported PDP target, not as the Warrantor policy IR or enforcement layer.** Build a
final AuthZEN adapter and a separately tested native high-performance adapter only if benchmarks
justify it. Declare Cerbos-specific property conventions and translation losses. Require mTLS or
equivalent authenticated workload identity, policy revision evidence, audit export, and PDP outage
tests.

### OpenFGA 1.19.0 AuthZEN

#### Strengths

- Mature open authorization engine with a current verified binary and Apache-2.0 source.
- Detailed implementation guide maps every AuthZEN endpoint to a native OpenFGA operation.
- Implements single evaluation, batch evaluations, subject/resource/action search, and
  store-scoped discovery.
- Explicit authorization-model pin header and response header.
- Merges subject/resource/action properties into namespaced condition context.
- Handles multi-tenancy without deriving discovery URLs from attacker-controlled Host headers.
- Live store, model, tuple, discovery, and allow decision reproduced.
- Source includes extensive server tests for feature flags, evaluation, batch semantics, search,
  configuration, property merging, and error behavior.

#### Boundaries

- AuthZEN is explicitly experimental and disabled unless selected.
- OpenFGA recommends its native API for application integration and AuthZEN for compatible
  gateways/IdPs; AuthZEN cannot create/read models or tuples.
- Pagination is not implemented; page inputs are accepted/ignored as documented.
- Decision explanations in response context and signed metadata are not implemented.
- Contextual tuples have no AuthZEN mapping.
- Type-less searches and some optional behaviors are constrained by the native model.
- The request context wins on key conflicts after property namespacing. A Warrantor profile must
  prevent untrusted context from overriding fields derived from a trusted token or resource
  registry.
- Default-latest model behavior is not reproducible unless the model ID is pinned or captured.
- The PDP still supplies only decisions; operation binding, enforcement, receipts, and effects are
  outside scope.

#### Decision

**Adopt as the primary relationship-authorization target to pressure-test W4/W6, with the
experimental status explicit.** Use AuthZEN for decisions, native APIs for model/tuple lifecycle,
and the model-ID header for every security-critical evaluation. Carry a consistency requirement
and revision evidence. Do not claim that OpenFGA by itself implements W6's exact multi-principal
intersection, holder binding, quota consumption, or mandate semantics.

### Cerbos FastMCP

#### Strengths

- Small, readable Python implementation.
- Uses FastMCP's server-side middleware seam rather than relying on agent self-policing.
- Requires a principal builder and denies missing principals.
- PDP exceptions become unauthorized errors.
- Tool call authorization includes name, arguments, and middleware source.
- Tool listing has a top-level check and per-tool visibility decisions.
- Client creation is concurrency guarded and connectivity is checked during initialization.
- Python types and unit tests are present; 36 tests passed in the pinned environment.

#### Boundaries and reproduced failures

- Native Cerbos gRPC means it does not exercise the claimed cross-vendor AuthZEN seam.
- Get-prompt, read-resource, and resource-template calls bypass the PDP.
- Generic request/message/notification hooks are inherited pass-throughs.
- Post-decision argument substitution was reproduced.
- No route/mapping digest, permit, consumption, result policy, effect record, or W2 receipt.
- The successful local run skipped all three live-PDP integration tests.
- The bundled policy fails to compile with current Cerbos 0.55.
- The latest annotated tag is v0.2.0, but package metadata still declares 0.1.1.
- Main remains on FastMCP 2.12.3 in the lock while an unmerged branch proposes FastMCP 3;
  supported framework/version policy is unclear.
- Zero visible GitHub stars/forks is not a security defect, but it provides no adoption or
  independent-assurance signal.

#### Decision

**Reference and modify; do not consume unchanged.** Preserve its principal builder, native sidecar
option, list filtering, failure conversion, and warm-up pattern. Replace manual hook coverage with
a generated current MCP method/extension registry, use final AuthZEN/COAZ at the public seam,
freeze the exact operation, add result/effect handling, and require live-PDP tests against both
Cerbos and OpenFGA.

### Vengtoo MCP Gateway 0.1.1

#### Strengths

- True proxy/PEP topology for tools, not an advisory authorization tool.
- Separate inbound stdio/HTTP and downstream stdio client/server roles.
- Per-call external authorization with arguments.
- Call-time network/timeout/5xx failure ultimately denies.
- Captures the downstream route entry before the authorization wait.
- Filters gateway secrets and the ambient host environment from spawned downstreams.
- Refuses public unauthenticated HTTP binding and tests session/caller separation.
- Startup enforcement restore has a bounded fail-closed call gate.
- Blocked and pending-review tools are denied independently of PDP success.
- Hashing and tests cover nested schema/description drift.
- Tool visibility can be filtered per subject; call-time checks remain authoritative.
- Native suite is substantial for a two-commit initial release: 52 tests, type-check, and build all
  passed.

#### Boundaries and reproduced failures

- Its access-evaluation body is not AuthZEN 1.0 compliant and failed against both selected PDPs.
- Tool-list visibility fails open by default on authorization error. Calls remain protected, but
  names/descriptions/schemas may be disclosed.
- Only tools are proxied; resources, prompts, sampling, elicitation, and newer capabilities are not
  governed.
- Downstream servers are spawned once; crash restart, remote downstreams, and dynamic tool-list
  changes are roadmap.
- HTTP identity is static bearer-token mapping; validated MCP OAuth credentials are roadmap.
- No final COAZ tool mapping, server-declared mapping validation, mapping digest, or trust-anchor
  profile.
- HITL polling does not echo approval ID or send a stable request ID.
- No idempotency or atomic permit consumption prevents duplicate approved effects.
- Local audit serialization contradicts the README's argument-logging claim by omitting args.
- Audit has no result/effect, policy revision, permit, downstream identity, or cryptographic
  integrity/completeness mechanism.
- Result/content policy is roadmap.
- The local enforcement cache is an operational safety aid, not a signed/versioned policy
  snapshot with bounded staleness.
- Direct downstream access remains an operator topology risk.
- Two public commits and no visible stars/forks supply almost no adoption or independent security
  assurance.

#### Decision

**Reject as an unchanged dependency; consume selected patterns and keep under watch.** The project
is useful prior art for startup gating, drift states, per-caller sessions, environment filtering,
and honest roadmap boundaries. Reconsider direct use only after final AuthZEN conformance, OAuth
identity, current MCP primitive coverage, dynamic downstream updates, signed/versioned enforcement
state, durable evidence, and independent security review.

## Warrantor architecture implications

### W1 — Notary core

- Store PDP decision metadata as one input, not as the final receipt.
- Notarize the canonical operation digest, mapping digest, policy/model revision, permit ID,
  enforcement event, result digest, and reconciliation state.
- Maintain expected-event records before irreversible calls so a crash or omitted log is visible.

### W2 — evidence before commit

Minimum linked records:

1. **Intent**: authenticated subject, delegation chain, requested operation, tenant, target,
   canonical bytes/digest, and idempotency key.
2. **Projection**: COAZ mapping identity/version/digest, trusted-input sources, generated AuthZEN
   request, and compiler loss report.
3. **Decision**: PDP identity, authenticated channel, policy/model/data revision, decision,
   obligations, expiry, and response digest/signature where available.
4. **Permit consumption**: atomic single-use state transition linked to the operation digest.
5. **Forwarding**: exact immutable bytes, downstream workload identity, transport, timestamp, and
   attempt number.
6. **Result/egress**: result digest, output-label/redaction decision, returned status, and evidence
   visibility.
7. **Effect/reconciliation**: observed external state, compensation, timeout/unknown outcome, and
   final completeness state.

### W3 — containment

- A kill/deny decision must close the PEP before new forwarding and define treatment of in-flight
  permits.
- Downstream MCP servers must reject direct access or accept only gateway-bound credentials.
- Gateway/PDP outage behavior, cached-state age, restore order, and operator override must be
  conformance-tested.
- Control-plane blocks and call-time policy are separate states and need separate evidence.

### W4 — cross-stack policy compiler

- AuthZEN is the external decision ABI, not the compiler IR.
- Each target adapter must publish supported AuthZEN capabilities and translation losses.
- Compile the same typed tests to Cerbos and OpenFGA, then run differential allow/deny/error
  fixtures under pinned policy/model revisions.
- Treat action-as-verb versus action-as-relation, subject-type handling, property namespaces,
  context precedence, search behavior, and response context as explicit semantic differences.
- Generate MCP mappings from pinned core and extension schemas; do not hand-maintain method lists.

### W5 — default-deny mediation and egress

- The PEP must be the only reachable downstream path for every supported transport.
- Unknown state-changing requests and notifications deny unless explicitly profiled.
- Listing visibility, invocation, result egress, network egress, and external side effect are
  distinct enforcement points.
- A boolean PDP response must never act as an unlimited bearer permit.

### W6 — authority intersection

- AuthZEN's single `subject` plus context is not a delegation-chain algebra.
- Resolve initiating principal, delegator, agent, resource owner, tenant, environment, and
  downstream service authority before generating the AuthZEN request.
- Bind the normalized intersection result and chain digest into the operation/permit.
- PDP products may evaluate the resulting policy, but Warrantor remains responsible for holder
  proof, monotone attenuation, conflict/deny semantics, quota/expiry consumption, and complete
  chain evidence.

## Required conformance corpus

Every supported Warrantor gateway/PDP pair should run the same versioned corpus.

### Protocol-shape fixtures

- final single evaluation;
- final boxcar evaluations with every legal default/override combination;
- missing `subject.id`, `resource.id`, `action.name`;
- legacy `identity`, `name`, and `attributes` fields;
- unknown security-critical fields;
- absent versus null versus empty properties/context;
- duplicate JSON keys, invalid Unicode, over-depth, over-size, integer/float edge cases;
- PDP discovery with path prefixes and tenant/store scoping;
- endpoint-host poisoning and redirect behavior;
- model/policy revision pinning and stale/unknown revision.

### MCP coverage fixtures

- every current core client request;
- every adopted extension request;
- list versus get/read/call distinctions;
- current notifications, especially cancellation and list-changed events;
- unknown future request and notification namespaces;
- direct named call after filtered listing;
- cached tool call after a tool-list update;
- nested tool call and re-entrant gateway behavior;
- stdio, Streamable HTTP, alternative transport, and raw downstream bypass attempts.

### Decision-to-execution fixtures

- mutate argument value/type/array order after decision;
- swap tool name, downstream server, tenant, route, or mapping after decision;
- policy/model update between evaluation and forwarding;
- retry before response, after lost response, and after process restart;
- two concurrent identical calls sharing one quota/approval;
- approval expiry and revocation immediately before forwarding;
- PDP timeout, malformed response, redirect, partial batch, length mismatch, and signed-response
  failure;
- downstream error before effect, after effect, and after response loss;
- result substitution, truncation, injection, redaction, and egress-deny;
- evidence sink failure before permit, before effect, and after effect;
- missing expected event, duplicate event, and reordered event reconciliation.

### Acceptance rule

A pair passes only when:

- every exposed operation crosses a named PEP;
- the final AuthZEN/COAZ request validates;
- trusted values cannot be replaced by untrusted mapping/context values;
- allow is bound to one immutable operation and one policy/model state;
- permit consumption is durable, atomic, single-use, and idempotent under retry;
- the exact operation forwarded matches the evaluated digest;
- result and effect are linked or explicitly unresolved;
- required evidence is durable and expected-set completeness is reconciled;
- direct transport/process/network bypass is denied;
- the same corpus produces documented equivalent or explicitly loss-bounded outcomes across PDPs.

## Product decisions

| Option | Benefits | Costs/risks | Recommendation |
|---|---|---|---|
| Use Cerbos FastMCP unchanged | Minimal Python integration; native fast gRPC | Coverage bypasses, mutable operation, vendor-specific seam, current policy drift | Reject |
| Use Vengtoo unchanged | Stronger gateway mechanics and tests | Nonconformant AuthZEN body, alpha identity/coverage/evidence boundaries | Reject |
| Fork one gateway and patch it | Faster prototype; existing transport/session code | Ongoing upstream divergence; inherited assumptions; security-critical maintenance | Accept only for a bounded prototype |
| Build a Warrantor assurance middleware on FastMCP | Tight integration; direct hooks | Framework-version coupling; server-local bypass/topology risk | Use as one adapter, not the universal PEP |
| Build a transport-neutral Warrantor PEP with generated protocol adapters | Strongest coverage, stable assurance seam, multiple runtimes/PDPs | Highest engineering and conformance cost | **Recommended core** |
| Support only one PDP | Simpler testing | Locks policy semantics to one vendor/engine and weakens W4 claims | Reject for the public architecture |
| Support Cerbos and OpenFGA first | ABAC/PBAC plus ReBAC pressure, both open and runnable | Requires explicit loss/equivalence testing | **Recommended initial pair** |

## Prioritized implementation plan

### P0 — before any production claim

1. Freeze final AuthZEN 1.0 request/response schemas and generate typed clients.
2. Implement discovery, endpoint pinning, authenticated PDP identity, and strict redirect policy.
3. Generate the MCP operation registry from the pinned core schema and each adopted extension.
4. Implement immutable canonical operation encoding and `operation_digest`.
5. Define a COAZ-derived mapping profile with trust anchors, mapping digest/version, CEL limits, and
   loss reporting.
6. Implement one atomic, durable `authorize-and-consume` transaction with idempotency.
7. Forward only the immutable evaluated buffer to a workload-identified downstream.
8. Emit intent, decision, consume, forward, result, and effect/reconciliation records.
9. Run the corpus against Cerbos 0.55+ and OpenFGA 1.19+.
10. Reject release if any exposed operation lacks a generated mediation case.

### P1 — controlled pilot

1. Add a Cerbos target profile with explicit reserved properties and policy-version rules.
2. Add an OpenFGA target profile with store/model/consistency requirements and tuple lifecycle.
3. Differentially compile and execute a common policy corpus; record every semantic difference.
4. Add HTTP MCP OAuth 2.1 identity and SPIFFE/mTLS workload identity between PEP and PDP/downstream.
5. Implement list visibility, call authorization, resource/prompt retrieval, and result-egress as
   separate policy actions.
6. Benchmark PDP round trip, decision cache safety, durable consumption, and receipt overhead.

### P2 — ecosystem and standards contribution

1. Contribute final AuthZEN request-shape corrections to gateways that claim compatibility.
2. Contribute current MCP method/notification corrections and generated fixtures to COAZ-MCP.
3. Publish a vendor-neutral gateway/PDP interop corpus with positive and adversarial vectors.
4. Seek independent review of the operation-binding and atomic-consumption protocol.
5. Publish performance, failure, and semantic-loss results rather than a binary “compatible” badge.

## Research, business, and content implications

### Academic opportunities

- **Semantic portability study:** quantify policy outcome divergence across Cerbos, OpenFGA,
  Cedar, and OPA behind the same AuthZEN/COAZ fixtures.
- **Decision-to-effect refinement:** formalize and test the invariant that the evaluated operation,
  consumed permit, forwarded bytes, result, and effect are one linked state transition.
- **Authorization middleware completeness:** generate framework-level PEP coverage proofs/tests
  from protocol schemas and compare manual hook implementations.
- **Approval and retry semantics:** design a linearizable, privacy-preserving approval token bound
  to an operation digest and delegation chain.
- **Evidence completeness under crashes:** measure which event sets survive failures at each
  pre-/post-effect boundary.

### Business implications

- Multi-PDP support is a defensible integration benefit only when accompanied by published
  capability/loss matrices and conformance results.
- “Works with AuthZEN” must become a testable procurement statement: version, endpoints, field
  profile, optional capabilities, PDP authentication, and corpus results.
- Cerbos and OpenFGA are consume partners/targets, not competitors to Warrantor's evidence and
  enforcement assurance layer.
- A gateway that denies because of protocol mismatch generates deployment cost and false
  confidence; interoperability qualification should be a paid-enterprise readiness gate.
- Do not market native test counts as independent assurance or claim complete MCP governance when
  only tools or listing operations are covered.

### Evidence-led content opportunities

1. “AuthZEN standardizes decisions—not enforcement, policy meaning, or effects.”
2. “How a 52-test gateway failed two real AuthZEN 1.0 PDPs.”
3. “List authorization is not read/call authorization: the MCP middleware coverage trap.”
4. “The missing link between an allow decision and the operation that actually ran.”
5. “Cerbos versus OpenFGA behind one API: portable wire format, non-portable semantics.”
6. “Why human approval needs an operation digest and atomic consumption.”
7. “From policy decision logs to evidence-before-commit receipts.”

Every article must name versions and threat-model boundaries and link to the artifact receipts; it
must not present these controlled findings as universal defects in all versions or deployments.

## Source quality decisions

| Source | Score | Band | Action | Rationale |
|---|---:|---|---|---|
| OpenFGA AuthZEN implementation v1.19.0 | 88 | High-quality | Adopt/profile | Current official code, verified release, deep documentation/tests, live reproduction, and high W4/W6 relevance; experimental status and first-party incentives prevent essential status |
| Cerbos PDP AuthZEN v0.55.0 | 84 | High-quality | Adopt/profile | Current official implementation, verified release, explicit mappings, and live reproduction; partial API and vendor-specific semantics bound portability |
| Vengtoo MCP Gateway v0.1.1 | 72 | Supporting | Reject unchanged; monitor | Strong native tests and useful gateway patterns, but a two-commit alpha with failed final-AuthZEN interop and material identity/coverage/evidence gaps |
| Cerbos FastMCP main/v0.2.0 | 70 | Supporting | Reference/modify | Directly relevant readable middleware and unit evidence, but bypassed operations, mutation, skipped live tests, current-policy incompatibility, and version ambiguity sharply limit authority |

Scores follow the research protocol's weighted dimensions and rank these repositories within their
implementation-source category, not against peer-reviewed papers or final standards.

## Evidence limits and follow-up

- Cerbos and OpenFGA were exercised through official verified binaries, but their full Go test
  suites were not run because a Go toolchain was unavailable.
- The review ran a minimal live policy/model case and bounded adversarial vectors, not every
  official AuthZEN certification or interop scenario.
- The Cerbos FastMCP compile failure applies to current Cerbos 0.55 and the reviewed policy; it does
  not prove incompatibility with all earlier PDP versions or a corrected policy.
- The mutation vector proves absence of immutable decision-to-forward binding in the reviewed
  middleware composition. It does not claim an unauthenticated remote client can directly mutate
  an already parsed in-process object.
- Vengtoo cloud behavior, policy storage, decision logs, and approval matching are closed-service
  boundaries and were not independently audited. Findings about the open gateway do not establish
  defects in the service.
- Native README claims, test counts, stars, and vendor assertions were treated as first-party
  evidence, not independent validation.
- No source in this wave establishes Warrantor novelty. The wave bounds the exact implementation
  gap and supplies disconfirming prior art.

Next bounded wave: implement the same final AuthZEN fixture and immutable-operation vector in a
small Warrantor prototype, then run it against Cerbos and OpenFGA while adding policy/model revision,
atomic consumption, result binding, and crash-point reconciliation. A paper-only expansion should
not precede that implementation gate.

## Primary sources

- [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
- [Cerbos repository](https://github.com/cerbos/cerbos)
- [Cerbos v0.55.0 release](https://github.com/cerbos/cerbos/releases/tag/v0.55.0)
- [Cerbos AuthZEN API documentation](https://docs.cerbos.dev/cerbos/latest/api/index.html#authzen)
- [Cerbos v0.48.0 AuthZEN release note](https://docs.cerbos.dev/cerbos/latest/releases/v0.48.0.html)
- [OpenFGA repository](https://github.com/openfga/openfga)
- [OpenFGA v1.19.0 release](https://github.com/openfga/openfga/releases/tag/v1.19.0)
- [OpenFGA AuthZEN documentation](https://openfga.dev/docs/interacting/authzen)
- [OpenFGA AuthZEN source documentation](https://github.com/openfga/openfga/tree/main/docs/authzen)
- [OpenFGA AuthZEN interop scenarios](https://github.com/openfga/authzen-interop)
- [Cerbos FastMCP repository](https://github.com/cerbos/cerbos-fastmcp)
- [Vengtoo MCP Gateway repository](https://github.com/vengtoo/mcp-gateway)
- [MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [COAZ Framework Draft 1](https://openid.github.io/authzen/authzen-coaz-framework-1_0.html)
- [COAZ-MCP Binding Draft 1](https://openid.github.io/authzen/authzen-coaz-mcp-binding-1_0.html)

