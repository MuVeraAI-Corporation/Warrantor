# H1 — `agent-identity-graph` RFC

> The agent identity graph (build-catalogue **H-1**, Domain H, loop L5): the `agent.yaml` constitution
> becomes a queryable identity — agent → owner org → operator → delegation ancestry (A-2) → plane bindings →
> reputation events (H-4) — so an agent's full dossier assembles from signed records alone and is verifiable
> by a stranger.

| Field | Value |
|---|---|
| **Canonical ID** | H1 (catalogue H-1) |
| **Name** | agent-identity-graph |
| **Wave** | 2 (agent economy) |
| **Languages** | Rust |
| **Catalogue item** | H-1 |
| **Dependencies** | `rust/delegation-chain` (A-2) for ancestry; H-4 for reputation events |

## Background

The agent economy needs to answer "who is this agent, who vouches for it, what has it ever done?" without a
central directory (an anti-goal). The answer is a graph built from records the platform already signs.
SPIFFE/SPIRE-compatible for the machine layer, this is the identity substrate that agent-to-agent
transactions (H-5) and reputation (H-4) hang off — and because every field traces to a signed record, a
counterparty who has never met the agent can verify its dossier independently.

## Goals and Non-Goals

**Goals:**
- An [`AgentIdentity`](rust/agent-identity-graph/src/lib.rs): owner, operator, delegation parent, plane bindings, reputation events.
- [`IdentityGraph`](rust/agent-identity-graph/src/lib.rs): [`ancestry`](IdentityGraph::ancestry) walks delegation parents to the root (cycle-guarded); [`dossier`](IdentityGraph::dossier) assembles the
  full record; [`verify_by_stranger`](IdentityGraph::verify_by_stranger) confirms every ancestor resolves and every event carries a digest.

**Non-Goals:**
- Verifying signatures — digests mark records as attested; the notary checks them.
- Computing reputation (H-4) — it links the events.
- Being a mandated directory — it is a graph a deployment builds from its own receipts.

## Detailed Design

`ancestry` follows `delegates_from` links, reversing to root-first, with a `seen` set so a delegation cycle
terminates. `dossier` bundles the identity fields plus the resolved ancestry and reputation events and
computes a `sha256:` digest over them. `verify_by_stranger` is the "assembles from signed records alone"
property: every ancestor must exist in the graph and every reputation event must carry a `sha256:` digest —
a fabricated ancestor or an undigested event fails verification.

## Threat Boundary

The adversary is an agent that misrepresents its lineage or history to a counterparty. Because the dossier is
assembled from indexed, digested records and a stranger can check that every ancestor resolves and every
event is attested, a fabricated lineage (an ancestor that doesn't exist) or an unattested reputation claim
fails verification. The graph trusts the registered records (the substrate's job to sign); it guarantees the
assembly and the stranger-check, not the signatures themselves.

## API

Library: `warrantor_agent_identity_graph::{ReputationEvent, AgentIdentity, IdentityDossier, IdentityGraph}`.
`IdentityGraph::{new, register, get, ancestry, dossier, verify_by_stranger}`.

## Testing

11 unit tests: ancestry walks to root and a root has empty ancestry; the dossier assembles the full identity;
a stranger verifies a complete dossier; a missing ancestor or an undigested event fails verification; an
unknown agent has no dossier; a delegation cycle terminates; the dossier digest is deterministic and
distinguishes agents; `get` returns registered agents.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §10 Domain H, H-1.
- Ancestry from: `rust/delegation-chain` (A-2); reputation events feed from H-4.
- Enables: H-2 delegation contracts, H-5 agent organizations, H-6 registry.
