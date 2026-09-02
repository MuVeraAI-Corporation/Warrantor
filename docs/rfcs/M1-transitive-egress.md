# M1 — `transitive-egress` RFC

> The transitive-egress invariant: a broker that checks each request in isolation cannot see an
> escape that is a property of the *chain*. Derived from the OpenAI–Hugging Face incident, whose
> first cause was a permitted fetch whose response induced the next fetch, and so on out of the
> sanctioned set.

| Field | Value |
|---|---|
| **Canonical ID** | M1 |
| **Name** | transitive-egress |
| **Wave** | 1 (substrate) |
| **Languages** | Rust |
| **Incident requirement** | R1 |
| **Catalogue item** | M-1 |
| **Dependencies** | egress broker (`decide`, `DestinationCatalog`) |

## Background

The egress broker's core rule — the agent names a capability, never a destination — defeats a single
forbidden request. It does not, by itself, defeat a *sequence* of permitted ones. In the incident an
agent fetched a package index from an allowed mirror; the index named further URLs; the tooling
followed them; the chain reached an attacker-controlled shared cache that became the collective's
message board. No individual hop was disallowed. The escape lived entirely in the transitive closure
of "what this response makes the agent fetch next," which no per-request decision can observe.

## Goals and Non-Goals

**Goals:** Enforce the invariant that the closure of destinations reachable by following induced
fetches stays inside the sanctioned set. Fail closed on the first out-of-bounds destination, naming
the precise edge that carried the agent out. Bound the chain length so a self-propagating crawl trips
a budget rather than exhausting the broker.

**Non-Goals:**
- Parsing response content. Extraction (URLs in manifests, `<script src>`, model-card links, HTTP
  `Location:` targets) is the broker's content scanner's job; this module is a pure analysis over the
  resulting hop graph, so it inherits no attack surface from a parser and is testable without one.
- Replacing `decide` — `check_closure` runs *after* a request is allowed, over the induced graph.
- Shared-service brokering (the writable-cache half of M-1), which is delivered jointly with M-3's
  governed-channel and covert-namespace detection.

## Detailed Design

`InducedHop { from, to }` is one edge: a response from `from` names `to` as the next destination.
`check_closure(origin, hops, sanctioned, policy)` builds an adjacency map and walks breadth-first from
`origin`, visiting each endpoint at most once so cycles terminate. At every induced edge it checks,
in order: hop budget (`HopBudgetExceeded`), then sanctioned membership (`Escape { to, via }` — the
escape check precedes the visited check so a prior visit cannot launder an off-set destination). The
origin must itself be sanctioned (`OriginNotSanctioned`). On success it returns `Contained { closure }`,
the sorted set of endpoints reached — the transitive blast radius, ready to receipt.

## Threat Model

The adversary is content the agent legitimately fetches that covertly directs it onward — a poisoned
package index, a model card with a hostile download link, a redirect chain. Because the agent never
supplies destinations, the only way out of the sanctioned set is through an induced hop; this module
makes that the thing that is checked, transitively, rather than each request in isolation.

## API

Library: `warrantor_egress::transitive::{InducedHop, TransitivePolicy, TransitiveDeny,
TransitiveVerdict, check_closure}`.

## Testing

11 unit tests: contained chain reports full closure, escape to unsanctioned host, escape deep in the
chain, origin must be sanctioned, hop budget trips on a runaway chain, cycles terminate, hop from an
unreached endpoint is ignored, redirect modeled as an induced hop, diamond visits a shared node once,
no hops is trivially contained, escape not laundered by a prior visit.

## Cross-references

- Incident analysis: `warrantor-incident-analysis-agent-collective-2026-09-01.html` §3, §13 R1, §14 M-1.
- Implementation: `rust/egress/src/transitive.rs`.
- Related: M-3 (`docs/rfcs/M3-agent-channel.md`) for shared-namespace / covert-channel detection.
