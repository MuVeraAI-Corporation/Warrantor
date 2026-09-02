# C10 — `inference-router` RFC

> Spend-routed local inference (build-catalogue **C-10**, Domain C, Wave 1, loop L1): the $0 backend.
> Policy-aware selection of local Ollama models first, cloud fallback only under policy, with the routing
> decision itself receipted and a spend cap that refuses rather than overspends.

| Field | Value |
|---|---|
| **Canonical ID** | C10 (catalogue C-10) |
| **Name** | inference-router |
| **Wave** | 1 (model intelligence) |
| **Languages** | Rust |
| **Catalogue item** | C-10 |
| **Dependencies** | none (the spend engine supplies `spent_so_far`; `backends.json` supplies costs) |

## Background

The W9 spend engine already prices backends via `backends.json`; what was missing is the *routing* logic on
top. Local-first routing is simultaneously three of the platform's exponential arguments in one feature:
the **cost story** (25–600× cheaper per token than cloud), the **sovereignty story** (a routed local call
generates no egress), and the **flywheel's volume source** (local inference volume is what produces the
console/guard transcripts C-6 trains on). Because the decision controls spend and feeds the moat, it must
be as auditable as the spend it governs — hence a receipted decision, not a silent pick.

## Goals and Non-Goals

**Goals:**
- [`route`](rust/inference-router/src/lib.rs): prefer a local backend when the policy says so and the call fits the remaining cap; fall
  back to cloud only when the policy allows it; otherwise refuse.
- Receipt every decision with a [`reason`](rust/inference-router/src/lib.rs) naming the local model (or justifying the cloud escalation) and a
  content digest, so a month's routing reconciles to the cent.
- Fail-closed on budget: a call that would exceed the cap is refused, never silently overspent.

**Non-Goals:**
- Calling the model — the inference proxy executes the chosen backend.
- Maintaining the spend ledger — `spent_so_far` is supplied by the spend engine.
- Pricing backends — costs come from `backends.json`.

## Detailed Design

Cost is `ceil(tokens / 1000) × cost_per_1k_micros`, floored at one block, so a sub-1k call still bills one
block and totals are exact integers. `route` computes the remaining budget as `cap − spent_so_far`
(saturating), then: if `prefer_local`, pick the cheapest local backend and route to it when its cost fits;
else (or if local doesn't fit) if `allow_cloud_fallback`, pick the cheapest cloud backend and route with an
escalation reason that distinguishes "no local available" from "local budget exceeded"; else refuse. When
neither branch fires, it distinguishes `NoEligibleBackend` (no backend exists / policy permits none) from
`BudgetExhausted` (a backend exists but its cost exceeds the remaining cap), reporting the required and
remaining amounts. The decision digest is `sha256:` over the canonical JSON of `(backend, kind, model,
cost, reason)`.

## Threat Boundary

The adversary is silent overspend and unauditable routing — an agent quietly escalating to an expensive
cloud backend, or a month's bill that can't be reconstructed. The hard cap refuses rather than overspends;
the receipted reason makes every escalation explainable ("escalated to cloud because local budget exceeded
for this call"); and determinism (same inputs → same decision → same digest) means an independent script
reconciles the routing to the cent, tying into K-2's digest-traceable invoices. The router trusts the
supplied `spent_so_far` and backend costs (the spend engine owns those); it does not itself call models or
enforce egress — the egress broker (W5) does.

## API

Library: `warrantor_inference_router::{BackendKind, Backend, RoutingPolicy, RouteRequest, RouteDecision,
Refusal, route}`.

## Testing

14 unit tests: local is preferred when available and bills per 1k block; cloud fallback when no local
exists; escalation to cloud when local exceeds the cap (with the distinguishing reason); no-fallback
refuses when local exceeds the cap; budget exhaustion reports required and remaining; no backends yields
`NoEligibleBackend`; local-only policy ignores cloud; the cheapest local is selected; the decision digest
is deterministic and distinguishes reason; `spent_so_far` reduces the remaining budget; a sub-1k request
bills one block; a cloud-only policy routes to cloud per policy.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §6 Domain C, C-10.
- Prices backends: `rust/spend` (W9, `backends.json`); executes: `rust/inference-proxy`.
- Feeds the flywheel: local volume → transcripts → `rust/training-extractor` (C-2) → C-6 console model.
- Reconciles with: `rust/metering` (K-2) digest-traceable invoices.
