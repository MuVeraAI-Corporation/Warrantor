# The Notary API, v1.0

> The single endpoint every harness calls. Two calls per consequential action: `Authorize` before,
> `Attest` after. Everything else in Warrantor is a plane of this contract.
>
> **Status:** FROZEN CANDIDATE — Blueprint v4, Sprint Days 1–14.

| Field | Value |
|---|---|
| **Service** | `warrantor.notary.v1.Notary` |
| **Transport** | gRPC (internal), REST+JSON (external), per `docs/cross-cutting/19-inter-component-protocol.md` |
| **Emits** | WAR v2.0 receipts (`01-war-receipt.md`) |
| **Owner** | Rust trusted core — no other language implements these semantics |

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** per RFC 2119.

---

## 1. Design constraints

Four constraints shaped this API, each from an adversarial finding:

1. **The core owns the decision, not the mediation.** Scope is the decision-plus-proof hot path.
   Enforcement lives in the kernel (OpenShell) or a gateway. This API is what those call.
2. **It must be cheap enough to be on every action.** `Authorize` has a p99 budget of **1 ms**
   excluding policy-engine time. A core that is slow becomes a core that teams route around, and a
   bypassed core provides zero security.
3. **It must fail closed without becoming a denial-of-service.** Unavailability of the *signer* is
   fatal (deny); unavailability of the *transparency log* is not (§5).
4. **It must never be the only copy of the truth.** Receipts are durable locally before any network
   call. The notary is not a database of record for someone else's system.

---

## 2. Methods

### 2.1 `Authorize` — the pre-commit gate

```
rpc Authorize(AuthorizeRequest) returns (AuthorizeResponse)
```

**Request** carries the actor (SPIFFE SVID + presented delegation tokens), the operation
(class, target, method, parameters digest, reversibility, consequence tier), the artifacts in play
(model, skills, tools — by digest), and any advisory signals already collected.

**The core MUST, in this order, fail-closed at the first failure:**

1. Verify the SVID is live, unexpired, and unrevoked. *(I-01 — no active identity, no action.)*
2. Verify every delegation token's signature and validity window.
3. Compute `effective_capabilities` as the **intersection** across the chain. *(I-02.)*
4. Reject if the requested operation is not within that intersection.
5. Evaluate policy **now**, at commit time, against a digest-identified policy. *(I-04.)*
6. Verify every artifact digest, and that tool identifiers resolve to canonical resource IDs.
7. Verify budget remains (P7/ABS).
8. Require non-delegable human approval when `consequence_tier = critical`. *(I-08.)*
9. Sign a `pre_commit` WAR and make it **durable** before returning. *(I-07.)*

**Response** returns the verdict, the signed `pre_commit` receipt, a `commit_token` that
`Attest` must present, and the receipt's `enforcement_mode`.

> **Normative.** A caller **MUST NOT** allow the effect to become visible before `Authorize`
> returns successfully with a durable receipt. A caller that proceeds on timeout is operating in
> `advisory` mode by definition, and the receipt **MUST** say so.

### 2.2 `Attest` — the post-commit receipt

```
rpc Attest(AttestRequest) returns (AttestResponse)
```

Presents the `commit_token` and the outcome (status, outcome digest, effects, error, rollback
pointer). The core verifies the token binds to a durable `pre_commit` receipt, signs the
`post_commit` WAR chaining to it, and queues it for batched anchoring.

**Normative.** A `post_commit` receipt with no durable `pre_commit` parent **MUST** be rejected.
Absent `Attest` within the policy window, the action is recorded as **indeterminate**, not
successful — a missing outcome is a finding, not a silence.

### 2.3 `Revoke` — bounded revocation

```
rpc Revoke(RevokeRequest) returns (RevokeResponse)
```

Revokes authority by principal, workload, delegation link, artifact digest, or receipt lineage.
Returns the achieved propagation latency, which is a measured value and **MUST NOT** be reported
as a constant. Targets: identity < 5 s, credentials < 1 s *(I-05)*.

Revocation semantics are **execution-count / release-consistency**, not TTL expiry: a revoked
authority **MUST NOT** authorize any subsequent action, regardless of remaining token lifetime.

### 2.4 `Contain` — kill-switch to safe state

```
rpc Contain(ContainRequest) returns (ContainResponse)
```

Scope is one of `stop_inference`, `terminate_access`, `suspend_pattern`, or `full_shutdown` —
deliberately the four capabilities named in H.R. 9917. Returns the achieved safe state, measured
latency, and a signed containment receipt suitable for a conformance report *(I-12)*.

### 2.5 `Verify` — the read path

```
rpc Verify(VerifyRequest) returns (VerifyResponse)
```

Independently verifies a WAR: signature, JCS canonicality, **recomputed** authority intersection,
artifact digests, commit ordering, anchoring state, and enforcement-mode consistency. `Verify`
**MUST** be implementable by a third party with no Warrantor deployment and no shared secret —
verification that requires the issuer's cooperation is not verification.

---

## 3. Error semantics

Errors are typed and fail-closed. Every denial produces a `deny` receipt; deny-path audit is
mandatory, not optional.

| Code | Meaning | Invariant |
|---|---|---|
| `IDENTITY_INVALID` | SVID missing, expired, or revoked | I-01 |
| `AUTHORITY_EXCEEDED` | Operation outside the chain intersection | I-02 |
| `POLICY_DENIED` | Policy engine returned deny | I-04 |
| `ARTIFACT_UNKNOWN` | Digest unverified or unsigned | I-06 |
| `APPROVAL_REQUIRED` | Critical action lacking human approval | I-08 |
| `BUDGET_EXHAUSTED` | Autonomy budget spent | — |
| `EVIDENCE_UNDURABLE` | Receipt could not be made durable | I-07 |
| `SIGNER_UNAVAILABLE` | Signing path down → **deny** | I-09 |
| `CONTAINED` | Kill-switch active for this scope | I-12 |

**Normative.** There is no error condition under which `Authorize` returns `allow`. Ambiguity
resolves to denial. `UNKNOWN` is not a permitted outcome.

---

## 4. Adapters

Adapters are thin and own no security logic. They translate a harness's tool-call boundary into
`Authorize`/`Attest` and carry the verdict back.

| Adapter | Hook point | Notes |
|---|---|---|
| NOOA | Method dispatch on the agent class | NOOA states its controls are "NOT a containment boundary" — this is exactly the seat |
| Strands | Intervention handler, alongside Cedar | Cedar computes; Warrantor signs and makes enforceable |
| LangGraph | Node pre/post hooks | Beware per-node retry multiplication — see §5 |
| MCP gateway | Tool-call proxy | Turns a gateway's audit log into cryptographic proof |
| OpenShell | Policy compilation target | The path that earns `mediated` mode |

**Normative.** An adapter **MUST NOT** cache an `allow` verdict across actions, re-sign anything,
or synthesize a receipt. Adapters transport; they do not decide.

---

## 5. Availability — a first-class requirement

A core on every action's hot path is a cross-process critical dependency. Getting this wrong turns
a security control into an outage, and the honest lesson from multi-agent retry storms is that
enforcement layers can amplify failure rather than contain it.

- The core **MUST** be deployable as a sidecar or in-process library, not solely as a remote service.
- Callers **MUST NOT** retry `Authorize` with unbounded or multiplicative backoff. Retry budgets are
  per-action, not per-node.
- Signer unavailable → **deny** (fail-closed, non-negotiable).
- Transparency log unavailable → **proceed** for `routine`/`elevated` with `anchor.status = pending`;
  **deny** only for `critical`. Availability of an external log **MUST NOT** gate routine work.
- Degradation **MUST** be observable: every response carries whether it ran in degraded mode, and
  the fail-closed chaos harness measures behavior under each failure independently.

---

## 6. Conformance

An implementation claims Notary API conformance only if it passes every P2 v2.0 adversarial vector
(`01-war-receipt.md` §9), enforces the ordered checks of §2.1 in order, emits `deny` receipts,
implements `Verify` with no privileged access, meets the p99 budget under load, and passes the
fail-closed chaos harness in its declared enforcement mode. Conformance is per-mode: passing in
`advisory` **MUST NOT** be reported as passing in `mediated`.
