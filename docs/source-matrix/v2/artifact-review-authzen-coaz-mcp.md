# AuthZEN, COAZ and MCP authorization normative and artifact review

Status: normative review complete; current repositories pinned; method-set drift and permit-to-forward
gap demonstrated; no executable COAZ conformance suite located  
Reviewed: 2026-08-30  
AuthZEN repository: <https://github.com/openid/authzen>  
AuthZEN pinned commit: `e94e0a26e52346d33fef56d28bce96bd34835705`  
MCP repository: <https://github.com/modelcontextprotocol/modelcontextprotocol>  
MCP inspected commit: `efb5cb3ecae3d5e185b49901a75a8fd5a551fc0f`  
MCP Tasks repository: <https://github.com/modelcontextprotocol/ext-tasks>  
MCP Tasks pinned commit: `0d0a6bd4c258b35caa3c810a1dd506cf105b1501`  

## Decision

**Adopt AuthZEN Authorization API 1.0 as Warrantor's primary external PDP/PEP contract; adopt the
COAZ Framework as the protocol-projection model; modify rather than implement COAZ-MCP Draft 1;
and keep Warrantor's exact-operation, complete-mediation, authority-intersection, obligation,
receipt and effect-reconciliation guarantees above those standards.**

This is a consume-and-extend decision, not a new-policy-language decision. AuthZEN is now an
OpenID Final Specification and is the strongest reviewed cross-vendor wire contract for asking a
Policy Decision Point whether a subject may perform an action on a resource in context. COAZ adds
a useful declarative projection from protocol inputs into that SARC request. Those are precisely
the seams W4 should consume.

The standards do not establish Warrantor's stronger guarantees. AuthZEN explicitly leaves policy
language, policy architecture, state management and API authentication out of scope. It requires
the PDP to trust that the PEP supplied correct inputs and that the PEP will enforce the result. A
signed decision is optional. Neither the final specification nor the reviewed COAZ drafts define a
cryptographic or durable binding between a permit and the exact bytes later forwarded, the actual
external effect, or a complete set of attempted effects. They therefore bound W2/W4/W5/W6 but do
not replace them.

COAZ-MCP Draft 1 is also not current enough to adopt unchanged. The live source was amended on
2026-08-25 to remove `initialize` after MCP 2026-07-28 deleted it, but it still contains several
pre-release method assumptions. Mechanical comparison against the current MCP schema found three
valid client-to-server core requests with no COAZ default mapping:

- `server/discover`;
- `resources/templates/list`; and
- `subscriptions/listen`.

The draft's unknown-method rule requires those operations to be denied. Conversely, the draft
requires every `notifications/*` message to bypass the PDP. That wildcard includes current
`notifications/cancelled` and any future or extension-defined notification, even if the
notification changes execution state. This defeats the draft's stated future-method fail-closed
objective for the notification namespace.

The exact recommendation is therefore:

1. consume AuthZEN 1.0 and a strict versioned subset of COAZ;
2. contribute a 2026-07-28 method map, extension registry and fail-closed notification rule
   upstream;
3. bind every permit to a canonical immutable operation digest, mapping identifier/version,
   policy revision, subject/delegation context, freshness window and one-time or idempotent
   consumption record;
4. forward only the immutable operation that produced the digest; and
5. reconcile the authorized operation with authenticated result/effect evidence.

## Sources and version standing

| Work | Standing at review | Date/version treatment | Warrantor disposition |
|---|---|---|---|
| AuthZEN Authorization API 1.0 | OpenID Final Specification | Approved 2026-01-12; source prepared 2026-01-11 | **Adopt** as external PDP/PEP wire contract |
| COAZ Framework 1.0 | OpenID AuthZEN Working Group Draft 1 | Source banner says 2026-02-13; current split draft landed 2026-07-17 | **Adopt with profile** as mapping model |
| COAZ-MCP Binding 1.0 | OpenID AuthZEN Working Group Draft 1 | Split draft landed 2026-07-17; MCP method patch 2026-08-25 | **Modify/monitor**, not production profile |
| MCP Authorization 2026-07-28 | Current released MCP transport-authorization baseline | Released 2026-07-28 | **Adopt** for HTTP OAuth/OIDC transport identity |
| MCP Tasks extension | Official versioned extension | 2026-07-28 snapshot locked 2026-08-24 | **Map separately**; current COAZ task section is stale |

The COAZ HTML banner date is not sufficient version evidence. Git history shows that the current
framework/binding split was introduced on 2026-07-17 (`9eec72a`) and that the binding was changed
again on 2026-08-25 (`59a418a`). Warrantor must pin a source revision or content digest, not record
only “Draft 1.”

The older document at `authzen-mcp-profile-1_0.html` is superseded. Its content was split into the
COAZ Framework and COAZ-MCP Binding and must not be counted as a separate current source.

## AuthZEN Authorization API 1.0

### What the final specification standardizes

AuthZEN defines the interoperability boundary between a Policy Enforcement Point and a Policy
Decision Point. Its core request is Subject-Action-Resource-Context:

| Field | Role | Warrantor use |
|---|---|---|
| `subject` | Principal or identity being evaluated | Carry the verified initiating/acting subject; never treat this alone as the entire delegation chain |
| `action` | Operation under evaluation | Carry a typed canonical action, not a free-text prompt or marketing label |
| `resource` | Target of the operation | Carry the exact logical target and stable identifiers needed for policy |
| `context` | Optional environmental or request information | Carry agent identity, policy inputs, authority-chain reference, risk and freshness; classify every field by trust source |
| `decision` | Boolean permit/deny | Treat as an input to enforcement, not an execution receipt |
| response `context` | Implementation-defined decision information | Use only under an explicit profile; base AuthZEN does not standardize obligation names |

The final specification covers:

- single Access Evaluation;
- boxcar Access Evaluations with defined default/override semantics;
- subject, resource and action search APIs;
- discovery metadata, including optional signed metadata;
- HTTPS JSON endpoints and error behavior; and
- an optional signed authorization response.

It deliberately does not choose a policy language, storage model, policy architecture or state
management model. That makes it an appropriate interoperability boundary for W4, but not a policy
compiler or equivalence proof by itself.

### Normative trust boundary

The critical security contract is organizational and architectural:

- the PDP must trust that the PEP sent the correct subject, resource, action and context;
- the PDP must trust the PEP to enforce the decision;
- the PDP should authenticate the PEP, but the authentication method and strength are out of
  scope;
- authorization of the AuthZEN API itself is out of scope, with OAuth only recommended;
- a deny is HTTP 200 with `decision: false`, while HTTP 401 means PEP authentication failed; and
- a positive decision may carry context the PEP does not understand, in which case the PEP may
  reject it.

These distinctions must survive Warrantor adapters. A transport error, malformed response or
unknown critical obligation must never be coerced into a permit. A 401 is not a policy denial, and
a 200 is not necessarily a permit.

### Decision integrity is optional, enforcement integrity is absent

AuthZEN permits a signed decision response but does not require one. Even a valid signed response
would normally establish only that a PDP signed a representation of its decision. The base
specification does not require the signature to cover:

- the exact canonical bytes forwarded to the MCP server;
- a unique operation nonce or durable idempotency key;
- the selected COAZ mapping and its version/digest;
- the full delegation-chain authority intersection;
- a use count or atomic consume state;
- the PEP implementation/configuration that enforced the decision;
- the server result or external side effect; or
- evidence that every relevant operation traversed the PEP.

W2 receipts and W5 complete mediation therefore remain separate properties.

### Search and caching boundaries

The search APIs are valuable discovery interfaces, not atomic authorization snapshots. Pagination
may observe changing policy/data and can repeat or omit results across pages. PDP metadata follows
ordinary HTTP caching. Warrantor must never translate a cached search result or metadata document
into a durable authority grant without an explicit validity and revocation profile.

### Final-spec conformance evidence

The repository contains a detailed 2026 certification-scenario document with Basic, Batch, Search
and Discovery levels. It defines a small fixed policy fixture and numerous positive, negative,
structure, header, idempotency and transport requirements. It explicitly tests protocol
conformance rather than arbitrary policy correctness.

The repository also records seven interoperability events and numerous vendor result pages for
Todo, API-gateway, search and identity-provider scenarios. This is meaningful ecosystem evidence,
but most results are participant- or working-group-generated and do not establish complete
mediation, policy equivalence, hostile-input safety or production reliability.

No executable harness implementing the new certification scenario was located in the reviewed
commit. The scenario is built to HTML/text by CI. The older API-gateway runner is a separate,
limited fixture. Its package installation did not reproduce in this environment: normal npm
resolution reported a dependency-tree failure around the declared TypeScript 7 dependency, and a
legacy-peer retry hit an integrity mismatch. Static inspection also found that its `build` script
calls `tsc --noEmit` after cleaning `build`, while its `test` script expects `build/runner.js`.
Those observations do not invalidate the specification, but they prevent treating the repository
as a currently reproduced executable certification implementation.

## COAZ Framework 1.0

### Useful contribution

COAZ supplies the missing protocol-neutral projection layer between an incoming operation and an
AuthZEN request. A mapping is a JSON template with exactly one envelope:

- `evaluation` for one decision; or
- `evaluations` for multiple decisions that must all permit.

Every leaf is either a literal or an expression over binding-defined input variables. CEL is the
default expression language. A binding must define its information model, mapping location,
literal/expression discriminator, expression language, envelopes, operations in scope, default and
declared mapping behavior, trust-anchored fields, error transport and optional discoverability.

This is directly reusable for W4's protocol adapter boundary. It is not a general policy language
and should not become one.

### Strong fail-closed rules

The framework correctly distinguishes three refusal classes:

1. mapping error;
2. authorization denial; and
3. PDP communication error.

For all three, the operation must not proceed. Multi-evaluation mappings permit the operation only
if every requested decision permits. Unsupported envelope keys are mapping errors rather than
ignored extensions. These should become Warrantor conformance requirements.

### Trust-anchor model

COAZ recognizes that a mapping may be supplied by the party whose operation is being authorized.
It therefore allows a binding to mark fields as trust-anchored and requires verification or
substitution from a trusted input. It also warns that sibling attributes do not become trustworthy
merely because one identifier was anchored.

The framework makes trust anchoring optional at the framework level and binding-specific in
practice. Warrantor should strengthen this in its profile:

- `subject.id`, acting agent/workload identity, delegation root, recipient, audience and operation
  target must be derived from independently verified inputs;
- a server-authored mapping may select semantic projections but may not create trusted identity,
  authority, privilege or evidence fields;
- mapping authorship, signature/digest, retrieval source and version must be recorded; and
- a mapping change between discovery, evaluation and forwarding must invalidate the evaluation.

### Framework guarantee boundary

COAZ's five-step model ends with “enforces the returned decisions.” It does not define how the PEP
proves that the operation it enforces is the operation it evaluated. It also states that if no PEP
evaluates the mapping, access control falls back to other mechanisms. Deployment coverage is a
`SHOULD` validation, not a non-bypassability guarantee.

## COAZ-MCP Binding 1.0

### Architecture and mapping flow

The binding permits either an MCP gateway or an MCP server to act as PEP. A gateway may obtain a
server-authored declared mapping from the tool's `inputSchema` under `x-authzen-mapping`; otherwise
it applies a default mapping. It validates the token, projects message/token values through CEL,
calls AuthZEN, and forwards only after permit. A server may reauthorize.

This gives Warrantor a useful standards-compatible request vocabulary and a route to cross-vendor
PDPs. It does not make a gateway unavoidable, authenticate the semantic truth of a server-authored
mapping, or bind evaluation to effect.

### Current core method coverage

The table below compares client-to-server core requests in the current MCP 2026-07-28 schema with
the reviewed COAZ source.

| MCP 2026-07-28 request | COAZ-MCP Draft 1 | Effective behavior | Decision |
|---|---|---|---|
| `server/discover` | No mapping | Unknown-method rule denies | Add a mapping or explicitly justified pre-auth discovery profile |
| `completion/complete` | Default mapping | PDP evaluation | Retain; include request metadata and immutable digest in Warrantor profile |
| `prompts/list` | Default mapping | PDP evaluation | Retain |
| `prompts/get` | Default mapping | PDP evaluation | Retain; protect prompt identity and arguments |
| `resources/list` | Default mapping | PDP evaluation | Retain; do not infer read authority from list authority |
| `resources/templates/list` | No mapping | Unknown-method rule denies | Add a separate mapping |
| `resources/read` | Default mapping | PDP evaluation | Retain; bind exact URI and relevant range/arguments |
| `subscriptions/listen` | No mapping | Unknown-method rule denies | Add mapping over every requested notification/resource filter |
| `tools/list` | Default mapping | PDP evaluation | Retain; mapping discovery is untrusted metadata |
| `tools/call` | Default or server-declared mapping | PDP evaluation | Retain with strict mapping provenance and exact-operation binding |

Coverage is therefore seven of ten current core request methods, with three false-deny gaps. This
is not merely editorial: `server/discover` is required on current servers, resource templates are a
normal discovery surface, and `subscriptions/listen` is the current mechanism for notification
subscriptions.

### Stale and moved operations

The draft still includes or describes operations that MCP 2026-07-28 removed, replaced, deprecated
or moved:

| COAZ operation or assumption | Current MCP state | Risk |
|---|---|---|
| `ping` pass-through | Removed from current core | Dead rule and evidence that the method table is not generated from the current schema |
| `logging/setLevel` mapping | Removed; per-request `_meta` replaces it, and Logging is deprecated | Mapping never authorizes the actual current log-level input |
| `resources/subscribe` / `resources/unsubscribe` | Replaced by `subscriptions/listen` | Current subscription request is denied while obsolete operations appear supported |
| `tasks/result` and `tasks/list` | Removed in the official Tasks extension | Stale authority model |
| no `tasks/update` mapping | Current extension write operation | Valid task input can be denied |
| `tasks/get` and `tasks/cancel` old grouping | Current methods remain but current data/lifecycle changed | Mapping must be regenerated and tested against the extension schema |
| server-initiated `roots/list`, `sampling/createMessage`, `elicitation/create` | Replaced in current core flow by Multi Round-Trip Request input requests; legacy features remain deprecated | The out-of-scope statement does not analyze authorization of embedded input requests/responses |

The official Tasks 2026-07-28 extension defines `tasks/get`, `tasks/update`, `tasks/cancel` and
`notifications/tasks`. The draft maps the old task model and wildcard-passes the task notification.

### Notification wildcard is a fail-open extension seam

COAZ-MCP says all `notifications/*` are pass-through and must not call the PDP. The justification
is that notifications have no JSON-RPC ID and expect no response. Response shape is not an
authorization property.

Current `notifications/cancelled` asks processing to cease and can terminate a subscription stream
on stdio. The Tasks extension's `notifications/tasks` carries full task state. Future extensions
may add client-to-server notifications with other state effects. Because the rule is a namespace
wildcard, a new notification bypasses the PDP even though a new request method is denied.

Required correction:

- enumerate direction-specific, version-specific notification methods;
- classify each as informational, control-plane or state-changing;
- authorize control/state notifications or bind them to an already-authorized parent operation;
- deny unknown client-to-server notifications by default;
- validate subscription and request correlation; and
- never infer “safe” from absence of a response ID.

### Declared-mapping trust problem

The server whose tool is being authorized can author `x-authzen-mapping`. The draft correctly says
its action, resource, context and non-anchored subject attributes are untrusted. That warning does
not solve semantic omission. A malicious or mistaken server can describe a destructive tool as a
generic low-risk operation, omit a sensitive parameter from the resource projection, or change the
mapping after a client/gateway cached it. A PDP cannot evaluate information it was never given.

Warrantor must treat declared mappings as untrusted proposals:

1. schema-validate and resource-limit CEL before activation;
2. sign or content-address the accepted mapping;
3. compile it into a typed W4 intermediate representation;
4. require a human/vendor trust decision for privileged semantic mappings;
5. include the mapping digest and compiler version in the authorization request/receipt;
6. deny on mapping drift, unknown fields, ambiguous target projection or evaluation errors; and
7. compare advertised tool schema, forwarded operation and result schema under differential tests.

### Subject override weakens identity assurance

Defaults anchor `subject.id` to a validated token claim. A declared mapping may use another source
when acting-user identity is not available in a verifiable claim. The draft uses `SHOULD` warnings
and says such identity is only as trustworthy as its source/mapping author.

Warrantor must not silently downgrade. An unverifiable subject can be carried as an assertion, but
it must have a lower assurance class and must not satisfy policy requiring authenticated identity.
Production profiles should reject it for privileged actions unless a separate verified
on-behalf-of credential supplies the subject.

## Exact permit-to-forward and effect gap

### What the standards require

AuthZEN says a permit may go forward and a deny must not. COAZ says the PEP constructs the request,
obtains a decision and enforces it. COAZ-MCP's gateway flow orders authorization before forwarding.
These are meaningful behavioral requirements.

### What they do not define

The reviewed texts do not define a mandatory canonical operation digest, signed permit token,
transactional consume, immutable forwarding buffer or authenticated outcome link. A conforming PEP
can therefore evaluate message A and—through a race, bug, plugin, retry transform or malicious
component—forward message B while still claiming that it enforced a permit.

This is the exact W2/W4/W5 seam Warrantor should own. The distinction is:

> **decision-before-forward** is a control-flow ordering; **decision-bound-to-forward** is an
> evidence and integrity property.

### Mandatory adversarial vectors

#### Vector A — post-decision argument mutation

1. Receive `tools/call` for `transfer_funds` with `amount=10`, destination A.
2. Build the COAZ/AuthZEN request and obtain permit.
3. Mutate the queued MCP message to `amount=100000`, destination B.
4. Forward the mutated message.

Expected Warrantor result: the forwarding boundary recomputes the canonical operation digest and
rejects before any external effect. A plain decision-before-forward implementation may not detect
the mutation.

#### Vector B — mapping swap after evaluation

1. Discover tool schema and declared mapping M1.
2. Evaluate using M1 and obtain permit.
3. Server advertises or gateway loads weaker/different M2 before forwarding/retry.
4. Forward using a projection not covered by the original evaluation.

Expected Warrantor result: mapping digest/version mismatch invalidates the permit. Cached mapping
freshness must not be treated as authority.

#### Vector C — wildcard notification extension

1. Register or negotiate an extension with a client-to-server state-changing notification.
2. Send `notifications/example/commit` without a PDP decision.
3. COAZ wildcard pass-through forwards it.

Expected Warrantor result: unknown or state-changing client notifications deny by default unless a
versioned profile maps them or binds them to an already-authorized operation.

#### Vector D — current-core false denial

Send each of `server/discover`, `resources/templates/list` and `subscriptions/listen` through a
strict Draft 1 PEP.

Expected finding: the current draft's unknown-method rule denies each. The Warrantor profile must
provide current mappings and must prove the table was generated/checked against the exact MCP
schema version.

#### Vector E — result/effect substitution

1. Authorize operation digest A.
2. Execute A but return a result or claim an effect from operation B, or omit an additional side
   effect.
3. Record only the AuthZEN permit.

Expected Warrantor result: the response/effect receipt links to A, the server/workload identity,
the result digest and the expected effect set; reconciliation reports missing or extra effects.

## Reproduction receipt

| Surface | Result | Interpretation |
|---|---|---|
| AuthZEN current repository | Pinned at `e94e0a2`; commit 2026-08-25 | Current working-group source inspected |
| AuthZEN Final source history | Final-publication preparation at `2b07366`, 2026-01-11 | Supports final version/date reconciliation |
| COAZ split history | Framework/binding split at `9eec72a`, 2026-07-17 | HTML banner date alone is stale version evidence |
| Latest COAZ MCP patch | `initialize` removal at `59a418a`, 2026-08-25 | Active maintenance, but partial current-MCP reconciliation |
| MCP current repository | Inspected `efb5cb3`; schema declares version `2026-07-28` | Current method set extracted from primary schema |
| Tasks extension | Pinned `0d0a6bd`; 2026-07-28 spec/schema snapshot | Current task method set extracted |
| Current MCP core request comparison | 7/10 mapped; 3 valid methods denied | COAZ-MCP Draft 1 is not current-core complete |
| Notification behavior | all `notifications/*` pass through | Forward-compatible fail-open namespace seam |
| COAZ executable tests | None located in reviewed repository | Normative draft only; no reproduced binding conformance |
| AuthZEN certification scenario | Detailed document present and CI-rendered | Strong test specification, not an executed harness |
| Legacy gateway runner install | Did not reproduce | Dependency resolution/integrity failures; runner is not evidence for COAZ |
| Spec build | Not run | `kramdown-rfc2629` and `xml2rfc` were absent; published HTML and source were inspected |

## Quality and source standing

| Source | Score | Band | Rationale |
|---|---:|---|---|
| AuthZEN Authorization API 1.0 | 92 | Essential | Final multi-vendor standard, detailed normative contract, substantial interop history and exceptional W4 relevance; no policy correctness or enforcement proof |
| MCP Authorization 2026-07-28 | 90 | Essential | Current normative transport baseline with strong OAuth/OIDC hardening; authorization remains optional and HTTP-scoped |
| COAZ Framework Draft 1 | 83 | High quality | Strong reusable projection/conformance model with explicit fail-closed behavior; still a draft with no executable conformance artifact |
| COAZ-MCP Binding Draft 1 | 75 | Supporting | Direct and important MCP prior art, but current method drift, wildcard notification bypass, draft status and no executable suite prevent promotion to high quality |

COAZ-MCP remains in the library because a high-relevance supporting source can materially change a
build/consume decision and bound novelty. Its lower score must not be hidden by combining it with
the final AuthZEN standard.

## Claim effects

### CLM-0001 — six primitives combined uniquely

AuthZEN/COAZ provide direct prior art for a cross-vendor authorization request/decision contract
and protocol-to-policy projection. They bound W4 and parts of W5/W6. They do not provide W1
notarization, W2 evidence-before-commit receipts, W3 containment/kill conformance, complete W5
egress mediation or exact W6 multi-principal intersection. Keep as bounding evidence, not a full
combination challenge.

### CLM-0003 — delegation-chain authority intersection

SARC can carry a subject and context, and COAZ-MCP distinguishes a human subject from an agent
context. Neither standard defines a chain algebra, monotone attenuation, holder proof, exact
multi-principal intersection, atomic consumption, revocation propagation or complete-chain proof.
Keep as bounding evidence.

### New implementation claim guardrail

Do not state that adopting AuthZEN or COAZ makes MCP authorization non-bypassable, binds a decision
to execution, proves policy equivalence or creates a receipt. Each property needs independent
evidence.

## Recommended Warrantor profile

### External contract

- AuthZEN 1.0 HTTPS/JSON for PDP/PEP interoperability.
- OAuth/OIDC and current MCP 2026-07-28 authorization for HTTP transport identity and audience.
- COAZ envelopes and CEL only through a validated, resource-bounded compiler front end.
- Explicit profile identifiers for AuthZEN, COAZ, MCP core and every adopted extension version.

### Trust-classified inputs

| Input | Minimum trusted source |
|---|---|
| subject identity | validated token/on-behalf-of credential or stronger workload/user binding |
| acting agent/workload | validated workload credential and token/client binding |
| resource target | canonicalized incoming operation plus trusted routing configuration |
| action | versioned protocol method and typed semantic action mapping |
| delegation authority | verified complete chain and W6 intersection result |
| mapping | accepted signed/content-addressed mapping plus compiler output |
| policy revision | PDP-signed or independently retrieved immutable revision identifier |
| time/revocation | trusted time/status inputs under an explicit freshness profile |

### Decision-bound forwarding contract

The Warrantor PEP should create an internal permit object containing at minimum:

- canonical operation digest and canonicalization profile;
- protocol, transport and extension versions;
- tool/resource/prompt identity and relevant parameters;
- subject, acting workload and verified delegation-intersection digest;
- mapping digest and compiler/version identifiers;
- PDP identity, policy revision, decision, evaluated time and expiry;
- nonce/idempotency key and atomic consumption state;
- intended destination/audience and forwarding adapter identity; and
- obligation/profile identifiers.

The forwarding API must accept this object and the immutable operation, recompute the digest,
consume the permit atomically and reject any mismatch/reuse/expiry. Receipt emission must record
the outcome without claiming that the receipt alone proves the external effect.

### Results and effects

- hash and authenticate the MCP response/result;
- identify the executing server/workload and adapter;
- record declared/expected effects before execution where feasible;
- reconcile observed effects and report missing, extra or indeterminate outcomes;
- distinguish denied, transport-failed, execution-failed, partially effected and completed; and
- preserve retry lineage so a new request ID cannot silently double-spend one permit.

## Upstream contribution agenda

1. Generate the COAZ-MCP method table from a pinned MCP schema rather than maintaining it only in
   prose.
2. Add `server/discover`, `resources/templates/list` and `subscriptions/listen` mappings for
   2026-07-28.
3. Replace the old Tasks section with a separately versioned official-extension binding for
   `tasks/get`, `tasks/update`, `tasks/cancel` and `notifications/tasks`.
4. Replace wildcard notification pass-through with direction- and version-specific rules plus
   default deny for unknown state/control notifications.
5. Define mapping identity, version, digest, retrieval and cache-invalidation requirements.
6. Add conformance vectors for mutation, mapping swap, notification extensions, PDP timeout,
   unknown fields, CEL resource exhaustion, retry and stale schema.
7. Define an optional decision-to-operation binding profile while keeping Warrantor's stronger
   receipt/effect layer independently verifiable.

## Build, consume, defer and reject decisions

| Decision | Item | Reason |
|---|---|---|
| Adopt | AuthZEN 1.0 request/decision and discovery contract | Avoid a proprietary PDP API and preserve engine choice |
| Adopt | MCP 2026-07-28 transport authorization | Use the current OAuth/OIDC baseline rather than inventing transport identity |
| Modify | COAZ framework profile | Preserve the mapping model but make trusted fields, mapping identity and resource limits mandatory |
| Modify | COAZ-MCP | Reconcile current core/extensions and add exact-operation binding |
| Build | typed intermediate representation and differential compiler | AuthZEN/COAZ do not prove semantic equivalence across Cedar, Rego and relationship systems |
| Build | atomic permit-to-forward boundary | No reviewed standard provides this guarantee |
| Build | delegation-chain intersection | SARC transport is not a chain algebra |
| Build | evidence-before-commit and effect reconciliation | A decision is not a receipt or proof of effect |
| Defer | proprietary Warrantor policy language | Existing policy engines and AuthZEN contract should be consumed first |
| Reject | “AuthZEN-compliant means non-bypassable” claim | Compliance covers a wire contract, not complete mediation |
| Reject | production use of unmodified COAZ-MCP Draft 1 | Current method drift and notification wildcard violate the required profile |

## Follow-up acceptance gates

- [ ] Every current MCP core request has an explicit mapped, pass-through or out-of-scope decision.
- [ ] Every current client-to-server notification and adopted extension notification is classified.
- [ ] Unknown request and notification methods fail closed.
- [ ] Mapping source, signer/digest, version and compiler output are immutable through forwarding.
- [ ] Post-decision mutation and mapping-swap vectors fail before effect.
- [ ] CEL evaluation has deterministic typing, cost/memory/depth limits and negative tests.
- [ ] AuthZEN PDP authentication, TLS, timeout, invalid-response and key-rotation behavior pass.
- [ ] A second independent PDP and a second MCP gateway pass the same conformance corpus.
- [ ] Permit consumption is atomic, durable, idempotent and restart/partition tested.
- [ ] Delegation-chain authority is verified and intersected independently of mapping assertions.
- [ ] Results/effects link to the authorized operation and extra/missing effects are reported.
- [ ] Product and marketing language distinguishes authorization decision, enforcement, receipt,
  complete mediation and outcome evidence.

Until these gates pass, Warrantor may claim standards-aligned integration work, not complete
AuthZEN/COAZ conformance, non-bypassable MCP enforcement or decision-to-effect proof.
