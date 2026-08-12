# W6 — The Delegation-Chain Intersection Engine

> The algebra in [`06-capability-algebra.md`](06-capability-algebra.md) defines *what* effective
> authority is. This document defines the engine that computes it from real tokens, under real
> latency, against a live revocation state.
>
> **Status:** FROZEN CANDIDATE — Tier B. The surviving half of the identity plane; the other half is
> consumed from SPIFFE/SPIRE.

---

## 1. What this engine is not

It is not an identity provider, a certificate authority, a token issuer, or a policy engine. Those
are SPIFFE/SPIRE, an existing IdP, and Cedar/OPA respectively, and re-implementing any of them
would be exactly the mistake the portfolio re-cut removed.

The engine does one thing nobody else does: **given a set of delegation tokens in heterogeneous
formats, assemble the chain, verify it, and compute the meet — such that no step can widen
authority.** Delegation *recording* is a solved problem; delegation *non-expansion as a verified
property* is not.

---

## 2. Input: heterogeneous tokens, one internal form

| Format | Source | Notes |
|---|---|---|
| **ID-JAG** | Okta Cross App Access; an OAuth working-group draft, and an MCP authorization extension | The most likely production format |
| **OAuth token exchange** | RFC 8693 on-behalf-of | Widely deployed; records delegation without constraining it |
| **AAE** | Warrantor-native | Used where no external format carries the needed constraints |

Each is verified in its own terms — issuer signature, audience, validity window, sender constraint —
and then **normalized** into a `DelegationLink`: issuer, subject, capability set, validity window,
token digest, and format.

**Normative.** Normalization **MUST** be lossless with respect to constraints. If a token carries a
restriction the internal form cannot express, the engine **MUST** reject the token rather than
normalize it away. Dropping a constraint during translation widens authority silently, which is the
same failure the unknown-constraint rule prevents inside the algebra — here at the boundary.

---

## 3. Chain assembly

Tokens arrive as a bag, not a list. Assembly is where a naive implementation is most easily fooled.

1. **Order by issuance linkage.** Each link's `subject` must match the next link's `issuer`. A bag
   that does not form a single path is rejected — not "best-effort ordered."
2. **Anchor at a trusted root.** The first link's issuer must be a configured root. A chain that
   anchors nowhere grants nothing.
3. **Reject cycles and forks.** Exactly one path from root to the acting subject. Multiple paths are
   rejected outright rather than reconciled — reconciliation is where authority-union bugs live.
4. **Exclude invalid links before the meet.** A link outside its validity window contributes
   *nothing* and is removed; the meet then proceeds over what remains.

> **The union trap.** If an agent presents two chains that each grant part of what it wants, a
> permissive implementation computes the union and grants both. The engine **MUST** evaluate exactly
> one chain per request. Multiple chains are not additive, and an agent holding two warrants has the
> narrower of the two for any given action, not the sum.

---

## 4. Revocation

Revocation is checked as part of chain verification, not as a separate later step that a caching
layer can skip.

- Every link is checked against revocation state at **evaluation time**.
- Semantics are **execution-count / release-consistency**, not TTL: a revoked link denies the next
  action regardless of remaining token lifetime.
- Revocation of any link invalidates the **whole** chain from that link downward. Descendants of a
  revoked warrant do not survive their parent.
- Cached chain results **MUST** be invalidated on any revocation event touching any link.

Targets are I-05's: identity under 5 s, credentials under 1 s, measured and reported rather than
asserted as constants.

---

## 5. Performance

Gates 4–5 of the verdict function share a 300 µs budget, dominated by signature verification.

- **Verified-chain cache**, keyed by the ordered tuple of token digests, valid for at most the
  shortest `not_after` in the chain and invalidated on revocation. This is safe because the key
  covers the exact inputs — a different chain is a different key.
- **The meet is not cached.** It is arithmetic over data already in memory, and caching it would
  introduce a staleness surface for no measurable gain.
- Chains **SHOULD** be bounded in depth by policy (a suggested default of 8). Unbounded delegation
  depth is a denial-of-service surface, and chains deeper than a handful of links are almost always
  a design error rather than a legitimate pattern.

---

## 6. Multi-agent topologies

Agent-to-agent delegation is where authority most often leaks in practice, and the engine's rules
are deliberately conservative:

| Topology | Rule |
|---|---|
| **Linear** (agent → subagent → tool) | Standard chain; each hop can only narrow |
| **Fan-out** (one agent, many subagents) | Each subagent gets its own chain; siblings **MUST NOT** be able to combine warrants |
| **Fan-in** (many agents, one action) | Rejected by default. If a legitimate use exists, it requires an explicit joint warrant, not an implicit merge of two chains |
| **Cyclic** (A delegates to B, B back to A) | Rejected — a cycle is an authority-laundering construction |

Sibling collusion is an explicit case in the attack corpus: two subagents holding complementary
capabilities attempting to act as one principal. The engine's answer is structural — one chain per
request, no merging — rather than behavioral.

---

## 7. Failure behavior

| Condition | Behavior |
|---|---|
| Revocation state unreachable | **Deny** — an unknown revocation state is a revoked one |
| Root unrecognized | Deny |
| Token format unsupported | Deny, without attempting interpretation |
| Meet yields empty | Deny (a normal outcome, not an error) |
| Any normalization loss | Deny |
| Chain depth exceeds bound | Deny |

---

## 8. Conformance

| Test | Expected |
|---|---|
| Two chains presented, union would grant more | Only one chain evaluated; narrower result |
| Sibling subagents combining complementary warrants | Denied |
| Cycle in the chain | Denied |
| Fork (two paths to the subject) | Denied |
| Middle link expired | Excluded; meet proceeds over the remainder |
| Middle link revoked | Whole chain from that link down invalidated |
| Token carrying an inexpressible constraint | Rejected, not normalized away |
| Chain reordered by the caller | Rejected unless linkage genuinely holds |
| Cached chain used after a revocation event | Non-conformant |
| Depth beyond bound | Denied |
| Same chain, different token ordering in the bag | Identical result (assembly is canonical) |
