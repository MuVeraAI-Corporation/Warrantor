# M8 — `revocation-verbs` RFC

> Kill-switch and revocation as first-class, pre-authorized, receipted verbs: halting a workload, agent
> family, evaluation, or credential is a single evidenced operation with a decision-rights protocol, and
> revocation propagates transitively across every dependent surface. Derived from the OpenAI–Hugging Face
> incident, where the response took ten days and manual forensics to enumerate 311 repositories, 22 admin
> accounts, and 6 pods — exactly the enumeration a receipt graph does in seconds.

| Field | Value |
|---|---|
| **Canonical ID** | M8 |
| **Name** | revocation-verbs |
| **Wave** | 1 (substrate) |
| **Languages** | Rust |
| **Incident requirement** | R8 |
| **Catalogue item** | M-8 |
| **Dependencies** | none (computes the closure and decision rights; execution is `rust/kill-switch`) |

## Background

The incident's response was an improvisation because revocation was never modeled as a *verb*. When
OpenAI finally moved, operators had to manually discover what a single compromised standing credential
backed — every session, staged handle, and active channel that depended on it — a ten-day forensic
enumeration. The report's remediation pillar is explicit: halting a workload, an agent family, an
evaluation, or a credential should be *"a single receipted operation with pre-delegated authority and a
decision-rights protocol — not an improvisation during the incident,"* and *"revocation propagates
everywhere (keys, sessions, staged handles, active channels) and is itself evidenced."*

Two properties make that possible and neither existed: a dependency graph you can take a closure over,
and a pre-authorized verb that checks decision rights before it fans out. This crate provides both as a
pure, testable reference.

## Goals and Non-Goals

**Goals:**
- Model revocable surfaces and their dependencies as a [`RevocationGraph`](rust/revocation-verbs/src/lib.rs), where an edge means "revoking the backing surface must propagate to the dependent."
- Compute the transitive [`RevocationGraph::closure`](rust/revocation-verbs/src/lib.rs) of a target — the target plus everything that depends on it, directly or transitively — so one verb revokes the whole
  cone.
- Gate the verb on pre-delegated authority: the requester's [`RevocationAuthority`](rust/revocation-verbs/src/lib.rs) must carry the target kind in its scope and meet the [`RevocationPolicy`](rust/revocation-verbs/src/lib.rs) clearance for that kind.
- Emit a single [`RevocationReceipt`](rust/revocation-verbs/src/lib.rs) with a content digest, so the revocation is itself evidenced and reconstructable.
- Fail-closed: any authority gap denies *before* anything is revoked.

**Non-Goals:**
- Performing the halt — `rust/kill-switch` suspends processes and `rust/credential-vault` invalidates
  handles. This crate decides *what* and *whether*; the execution layer does it.
- Maintaining the live dependency graph — the host supplies it from the receipt graph.
- Signing the receipt — the digest is a fingerprint the host records in the audit chain.

## Detailed Design

[`revoke`](rust/revocation-verbs/src/lib.rs) resolves the target's [`SurfaceKind`](rust/revocation-verbs/src/lib.rs) in the graph (absent → `UnknownTarget`), checks the authority's scope covers the kind
(`ScopeNotDelegated`) and its clearance meets `policy.required(kind)` (`InsufficientClearance`), then
computes the closure and returns an `Executed` receipt. The default policy requires clearance 3 for every
kind — matching the kill-switch crate's `operator_clearance at least 3` manual-trigger threshold — and a
custom policy can raise it per kind.

`closure` is a forward BFS/DFS over dependency edges from the target, collecting into a `HashSet` so a
surface reached by multiple paths (a diamond) is revoked once, and a cycle terminates. The result is
sorted for a deterministic digest. Revocation propagates *downward* through dependencies: pulling a
credential revokes the sessions, handles, and channels it backs, but revoking a leaf channel pulls only
itself.

## Threat Boundary

The adversary this closes is the incident's response failure: a compromised surface whose blast radius no
one can quickly enumerate, and a halt that requires ad-hoc authority negotiation mid-incident. The closure
makes the blast radius a single query; the decision-rights gate makes the authority pre-delegated and
auditable rather than improvised. The crate trusts the supplied graph to reflect real dependencies — an
incomplete graph under-propagates, which is why the graph is built from the receipt substrate, not by
hand. It does not enforce the halt at runtime; a compromised executor that ignores the receipt is outside
this boundary, which is why the receipt carries a digest the audit chain records independently.

## API

Library: `warrantor_revocation_verbs::{SurfaceKind, Surface, Dependency, RevocationGraph,
RevocationAuthority, RevocationPolicy, RevocationRequest, RevocationDenial, RevocationReceipt,
RevocationOutcome, revoke}`. `RevocationGraph::{new, add_surface, add_dependency, kind_of, closure}`;
`RevocationPolicy::required`.

## Testing

14 unit tests: revoking a leaf revokes only it; revoking a credential propagates transitively down a
four-surface chain; an unknown target is denied; insufficient clearance is denied; an undelgated scope is
denied; higher clearance is allowed; a cycle in the graph terminates; a diamond propagates each surface
once; the receipt digest is deterministic and distinguishes targets (and a leaf revokes only its own
cone); the revoked list is sorted and de-duplicated; an empty graph denies; the default policy requires
clearance 3; a custom per-kind clearance is enforced.

## Cross-references

- Incident analysis: `warrantor-incident-analysis-agent-collective-2026-09-01.html` §9, §13 R8, §14 M-8.
- Execution layer: `rust/kill-switch` (suspends/terminates, real-vs-simulated labeled), `rust/credential-vault`
  (handle revocation), `rust/agent-channel` (channel revocation).
- Conformance: `rust/containment-conformance` (M-9) validates the kill-switch capabilities this verb drives.
- Enumeration source: `rust/incident-replay` (M12) reconstructs the dependency graph the closure walks.
