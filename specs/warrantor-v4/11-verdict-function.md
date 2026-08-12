# W1 — The Composite Verdict Function

> The one place in Warrantor where `allow` is decided. Every other component either feeds this
> function or carries out what it decided.
>
> **Status:** FROZEN CANDIDATE — Tier A. The narrowed T1 trust core.

---

## 1. Signature

```
verdict(request, context) → (Allow | Deny(reason), receipt)
```

Total, deterministic, and side-effect-free except for emitting the receipt. Given identical inputs
it returns an identical decision — which is what makes a receipt reproducible by a third party and
what makes the function testable at all.

**Normative.** This function is implemented **once**, in Rust. Python, TypeScript, and Go call it
through generated bindings and **MUST NOT** re-implement any part of it. The stack rule is
unchanged and non-negotiable: *no security invariant may have two authoritative implementations.*

---

## 2. The gate sequence

Nine gates, evaluated **in order**, short-circuiting on the first denial. Order is normative, not
stylistic: cheap and unambiguous checks precede expensive and interpretive ones, so a request that
must fail does so before consuming policy-engine or attestation budget.

| # | Gate | Denies when | Invariant |
|---|---|---|---|
| 1 | **Containment** | A kill-switch is active for this scope | I-12 |
| 2 | **Identity** | SVID absent, expired, revoked, or unverifiable | I-01 |
| 3 | **Freshness** | Nonce reused, timestamp outside window, clock skew beyond tolerance | I-10 |
| 4 | **Chain** | Any delegation link fails signature or validity-window checks | I-02 |
| 5 | **Authority** | Requested operation ∉ recomputed intersection | I-02 |
| 6 | **Artifacts** | Any digest unverified, unsigned, or mismatched; tool identifier not provider-resolved | I-06 |
| 7 | **Budget** | Autonomy budget exhausted, or a blast-radius cap exceeded | — |
| 8 | **Policy** | Engine returns deny, evaluated **now** against a digest-identified policy | I-04 |
| 9 | **Approval** | `critical` action without valid, non-delegable human approval | I-08 |

Gate 1 comes first because a contained system must not spend effort adjudicating; gate 5 precedes
gate 8 because authority is cheap arithmetic over data already in hand while policy evaluation is
not. Gate 9 is last because it is the only gate a human can satisfy, and asking a human before the
machine checks have passed wastes the scarcest resource in the loop.

---

## 3. The composite rule

```
Allow  ⟺  every gate returns Allow
Deny   ⟸  any gate returns Deny, or any gate is indeterminate
```

**Normative.**

- There is **no** input under which an error, timeout, or unknown condition yields `Allow`.
  Indeterminate is denial.
- Advisory signals may contribute to `Deny` at gate 8 and **MUST NEVER** contribute to `Allow`.
- A gate that cannot be evaluated (dependency unreachable, unparseable input, unknown critical
  extension) denies. It does not skip.

The asymmetry is the entire design. Denial is always safe in the sense that matters here: it costs
availability, which is recoverable, while an unearned `Allow` costs containment, which is not.

---

## 4. Denial reasons are part of the contract

A denial returns a typed reason, carried in the receipt, drawn from the error taxonomy in the notary
API. Reasons are **coarse by design**: they identify the failing gate, not the internal condition.

**Normative.** A denial reason **MUST NOT** disclose which specific capability was missing, which
policy rule matched, or which artifact digest mismatched. An agent that learns *why* it was denied
learns the shape of the boundary, and a sufficiently patient agent converts a detailed denial oracle
into a map of the authority surface. Full detail goes to the receipt and the operator; the caller
gets the gate.

---

## 5. Performance, and why it is a security property

The p99 budget is **1 ms** excluding policy-engine and attestation time. This is not a
nice-to-have. A core that is slow becomes a core that teams route around, and a bypassed core
provides exactly zero security — the failure mode is not a slow system but an absent control.

| Gate | Budget | Note |
|---|---|---|
| 1–3 | < 50 µs | Memory lookups and arithmetic |
| 4–5 | < 300 µs | Signature verification dominates; chain results are cacheable within the freshness window |
| 6 | < 200 µs | Digest comparison |
| 7 | < 50 µs | Counter reads |
| 8 | excluded | Policy engine's own budget |
| 9 | excluded | Human latency |

**Caching is bounded by correctness, not by convenience.** A verified chain result **MAY** be cached
for at most the shortest `not_after` in the chain, and **MUST** be invalidated immediately on any
revocation event. Policy decisions **MUST NOT** be cached across actions — gate 8 exists precisely
because policy is re-evaluated at commit time, and a cache defeats invariant I-04 rather than
optimizing it.

---

## 6. Determinism

Two implementations, or the same implementation twice, **MUST** agree given identical inputs.
Concretely, that requires: canonical serialization before every hash or signature; no reliance on
map iteration order; time supplied as an explicit input rather than read from the clock inside the
function; and no locale-, environment-, or platform-dependent behavior anywhere in the path.

This is what makes `Verify` implementable by a third party with no privileged access — the property
that separates evidence from a log entry. If verification required the issuer's cooperation, it
would not be verification.

---

## 7. What the function does not do

It does not mediate, sandbox, proxy, or execute. It decides and it proves. Enforcement is carried
out by the kernel (OpenShell), the gateway, or the broker, and the receipt's `enforcement_mode`
records which of those was actually in the path.

This boundary is deliberate and load-bearing. Scope creep here — adding execution, storage, or
transport into the function — puts a monolith on every action's critical path and converts the
availability risk from a manageable one into a systemic one.

---

## 8. Conformance

| Test | Expected |
|---|---|
| Any gate errors | Deny |
| Policy engine times out | Deny |
| Identity service unreachable | Deny |
| Gates evaluated out of order | Non-conformant |
| Denial reason discloses the missing capability | Non-conformant |
| Advisory signal alone yields Allow | Non-conformant |
| Same inputs, two runs, different verdicts | Non-conformant |
| Policy decision cached across actions | Non-conformant (I-04) |
| Chain cache surviving a revocation event | Non-conformant (I-05) |
| p99 exceeds budget under load | Non-conformant |
| Rust and binding-language results disagree | Non-conformant |
