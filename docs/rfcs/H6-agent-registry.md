# H6 — `agent-registry` RFC

> The agent registry (build-catalogue **H-6**, Domain H, Wave 3): a versioned index of published agent
> manifests with highest-version lookup, exact-version resolution, per-version and whole-agent revocation,
> and publisher-trust filtering that fails closed.

| Field | Value |
|---|---|
| **Canonical ID** | H6 (catalogue H-6) |
| **Name** | agent-registry |
| **Wave** | 3 (agent plane) |
| **Languages** | Rust |
| **Catalogue item** | H-6 |
| **Dependencies** | `agent-manifest` (the signed document each version points at) |

## Background

`agent-manifest` makes a single agent definition a signed, canonical document. But a deployed fleet does not
consume one manifest — it resolves *"the current version of agent X, from a publisher I trust, that has not
been revoked."* Without a registry, that resolution is ad hoc and revocation is unenforceable: a compromised
or superseded agent version keeps being pulled because nothing says it must not be. H-6 is the discovery and
revocation layer that turns a pile of signed manifests into a resolvable namespace — the agent-domain
counterpart to B-5's issuer directory, but keyed on agents and versions rather than issuer keys, and with the
version-resolution and publisher-trust semantics a fleet actually needs.

## Goals and Non-Goals

**Goals:**
- A [`Registry`](rust/agent-registry/src/lib.rs) holds [`AgentVersion`](rust/agent-registry/src/lib.rs) entries
  and a revocation set.
- [`publish`](rust/agent-registry/src/lib.rs) admits a new version (refusing a duplicate);
  [`lookup`](rust/agent-registry/src/lib.rs) returns the highest non-revoked version;
  [`resolve`](rust/agent-registry/src/lib.rs) an exact one.
- [`trusted_lookup`](rust/agent-registry/src/lib.rs) restricts to trusted publishers, failing closed on an
  unknown one; [`revoke`](rust/agent-registry/src/lib.rs) / [`revoke_agent`](rust/agent-registry/src/lib.rs)
  retire a version or a whole agent.

**Non-Goals:**
- Parsing or verifying a manifest's signature — that is `agent-manifest`; the registry stores only the
  manifest digest and publisher.
- Mandating a central authority — a registry is a data structure a deployment maintains; publisher trust is
  supplied by the caller (the anti-goal against a mandated network trust directory holds).
- Reading a clock (`published_at_ms` is caller-supplied metadata).

## Detailed Design

Each [`AgentVersion`](rust/agent-registry/src/lib.rs) is `(agent_id, version, manifest_digest, published_by,
published_at_ms)`. The registry keeps entries plus a `revoked` set of `(agent_id, version)` pairs.
[`lookup`](rust/agent-registry/src/lib.rs) filters to non-revoked entries for the agent and takes the max
version, so revoking the newest version transparently falls back to the previous good one.
[`trusted_lookup`](rust/agent-registry/src/lib.rs) adds a publisher filter *before* taking the max — so if the
newest versions come from an untrusted publisher, resolution returns the highest version from a trusted one,
and returns `None` when no trusted publisher has ever released the agent (fail-closed, never a silent
fall-through to an untrusted entry). [`revoke`](rust/agent-registry/src/lib.rs) is idempotent and reports
whether it newly revoked; [`revoke_agent`](rust/agent-registry/src/lib.rs) retires every version at once.

## Threat Boundary

The adversary is a fleet pulling a bad agent: a superseded version still resolved (fixed by highest-version
lookup), a compromised version kept live (fixed by revocation, with fallback), a version from a publisher the
deployment never trusted (fixed by `trusted_lookup`'s fail-closed filter), or a duplicate publish corrupting
the index (refused by `publish`). The registry trusts the manifest digests and publisher identities it is
handed — signature verification and publisher authentication happen upstream in `agent-manifest` and the
identity graph; H-6 governs *which* version a consumer resolves.

## API

Library: `warrantor_agent_registry::{AgentVersion, Registry, verify_entry}`. `Registry::{new, publish, lookup,
resolve, trusted_lookup, revoke, revoke_agent, is_revoked, versions}`.

## Testing

14 unit tests: publish rejects a duplicate version; lookup returns the highest version and `None` for an
unknown agent; resolve matches an exact version; revoking a version falls back to the previous one and is
idempotent; revoking an absent version is false; `revoke_agent` retires all versions of one agent without
touching another; `trusted_lookup` skips an untrusted publisher and fails closed with no trusted versions;
`versions` lists non-revoked ascending; `is_revoked` tracks state; `verify_entry` checks the digest and
identities; the registry round-trips through JSON.

## Cross-references

- Build catalogue: `warrantor-exponential-build-catalogue-2026-09-01.html` §8 Domain H, H-6.
- Indexes: `rust/agent-manifest` (signed manifests); identity of publishers via `rust/agent-identity-graph` (H-1).
- Agent-domain counterpart to: `rust/receipt-federation`'s `IssuerDirectory` (B-5), keyed on agents not issuer keys.
