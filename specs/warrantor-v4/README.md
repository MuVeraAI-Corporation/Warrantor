# Warrantor v4 Contract Pack

> The Days 1–14 freeze artifacts. Everything downstream in the 90-day sprint depends on these being
> right, which is why they are written before any implementation and reviewed before they are
> declared frozen.

## Contents

| File | What it is | Status |
|---|---|---|
| [`01-war-receipt.md`](01-war-receipt.md) + [`.schema.json`](01-war-receipt.schema.json) | **Warrantor Action Receipt v2.0** — the single evidence object. DSSE + in-toto Statement, JCS-canonical JSON, tiered anchoring. Supersedes P2-AAR v1.0. | FROZEN CANDIDATE |
| [`02-notary-api.md`](02-notary-api.md) | **The Notary API** — `Authorize`, `Attest`, `Revoke`, `Contain`, `Verify`. The one endpoint every harness calls. | FROZEN CANDIDATE |
| [`03-enforcement-mode.md`](03-enforcement-mode.md) | **The enforcement-mode contract** — `mediated` vs `advisory`, and the escape suite that decides which you actually have. | FROZEN CANDIDATE |
| [`04-safe-finding.md`](04-safe-finding.md) + [`.schema.json`](04-safe-finding.schema.json) | **SAFE Finding v0.1** — proposed fielded data model for the Shared AI Findings Exchange. | DRAFT FOR CONTRIBUTION |
| [`05-killswitch-conformance.md`](05-killswitch-conformance.md) | **Containment conformance suite** — the four legislated capabilities, capability-elicited, with a signed report. | DRAFT SPEC |
| [`06-capability-algebra.md`](06-capability-algebra.md) | **`warrantor-intersect-v1`** — the scoped-capability lattice and meet operation that makes I-02 computable. | FROZEN CANDIDATE |
| [`07-root-compromise.md`](07-root-compromise.md) | **Root-compromise containment** — hardware-bound root, threshold issuance, transparency-log detection, blast-radius caps. | FROZEN CANDIDATE |
| [`08-egress-broker.md`](08-egress-broker.md) | **W5 egress broker** — capability-derived destinations only; the agent never supplies a hostname. | FROZEN CANDIDATE |
| [`09-eval-receipt.md`](09-eval-receipt.md) | **Eval receipts** — signing what garak/PyRIT/Inspect/AgentDojo/METR already produce. Run-provenance, not correctness. | FROZEN CANDIDATE |
| [`10-invariant-attack-corpus.md`](10-invariant-attack-corpus.md) | **A5b attack corpus** — one capability-elicited adversarial suite per invariant. | DRAFT SPEC |
| [`11-verdict-function.md`](11-verdict-function.md) | **W1 composite verdict** — the nine ordered gates; the one place `allow` is decided. | FROZEN CANDIDATE |
| [`12-delegation-engine.md`](12-delegation-engine.md) | **W6 delegation engine** — chain assembly, revocation, and the union trap. | FROZEN CANDIDATE |
| [`13-attack-to-policy.md`](13-attack-to-policy.md) | **R10 loop** — finding → candidate rule → human approval → enforced. | DRAFT SPEC |
| [`14-policy-compiler.md`](14-policy-compiler.md) | **W4 two-layer compiler** — author once, compile to gateway *and* kernel. The component that earns `mediated` mode. | DRAFT SPEC |
| [`15-conformance-harness.md`](15-conformance-harness.md) | **A6 harness** — vectors, corpus, containment; three suites, never one aggregate score. Runs against Warrantor itself. | FROZEN CANDIDATE |
| [`16-agent-manifest.md`](16-agent-manifest.md) + [`.schema.json`](16-agent-manifest.schema.json) | **`agent.yaml` (M1)** — the OpenAPI for agents. Declarative identity + capabilities + policies + dependencies + attestation + enforcement mode; signed + receipted. Reference impl: `rust/agent-manifest`, `python/warrantor_agent_manifest`. Cross-language Ed25519 interop verified. | FROZEN CANDIDATE |

Wire contract: [`../../proto/warrantor/notary/v1/notary.proto`](../../proto/warrantor/notary/v1/notary.proto) (`buf lint` clean).
Execution plan: [`../../docs/04-sprint-runbook.md`](../../docs/04-sprint-runbook.md).

Submission package for the SAFE RFC: ``../../../contrib/safe-rfc/`` (kept outside this repository).

## How these fit together

```
       harness (NOOA / Strands / LangGraph)
                    │  thin adapter, owns no security logic
                    ▼
        ┌───────────────────────────┐
        │  02 — Notary API          │   Authorize → [durable] → EFFECT → Attest
        └───────────┬───────────────┘
                    │ emits
                    ▼
        ┌───────────────────────────┐
        │  01 — WAR receipt v2.0    │ ── 03 declares what it may claim
        └───────────┬───────────────┘
                    │ projects into            ┌──────────────────────┐
                    ├─────────────────────────▶│ 04 — SAFE Finding    │
                    │                          └──────────────────────┘
                    │ aggregates into          ┌──────────────────────┐
                    └─────────────────────────▶│ 05 — Conformance rpt │
                                               └──────────────────────┘
```

The receipt is the atom. The notary produces it, the enforcement mode bounds what it may claim, and
it projects outward into a finding for the exchange and into a conformance report for an auditor or
supervisor. One object, three audiences.

## Freeze protocol

A document moves from FROZEN CANDIDATE to FROZEN when it has golden test vectors covering every
adversarial case, at least two independent readings of the normative rules that agree, and a
recorded decision on each open question below. After freeze, breaking changes require a new
protocol version per [`../protocols/README.md`](../protocols/README.md).

**Freeze the contract before fanning out.** The reason this pack exists as five documents written
ahead of any code is that an agent fleet building against an unfrozen contract produces conflicting
implementations faster than a single developer produces correct ones.

## Open questions — resolved

Four of the five original forks are now decided and specified. Each decision is recorded in the
document that implements it.

| # | Question | Decision | Where |
|---|---|---|---|
| 1 | **Intersection algebra** — flat sets break on resource scoping | **Scoped-capability lattice.** Capability = (action, resource, constraints); meet = hierarchy meet × segment-wise pattern meet × constraint conjunction. `fs:/data/**` ∧ `fs:/data/reports/q3` yields the narrower. Unknown constraint keys meet to ⊥ and reject. | [`06`](06-capability-algebra.md) |
| 2 | **Receipt volume** | **Consequence-tiered.** One receipt per `elevated`/`critical` action, never batched. `routine` actions batch into a windowed Merkle receipt where each action stays individually provable; I-07 holds at the batch boundary. No tier laundering to obtain batching. | [`01`](01-war-receipt.md) §7.1 |
| 3 | **Advisory-signal weight** | **Asymmetric.** An advisory signal MAY cause a `deny`; it MUST NEVER contribute to an `allow`. A statistical model must never sit inside the trust boundary. Decisive signals are recorded with source, score, and model digest. | [`01`](01-war-receipt.md) §3.4 |
| 5 | **Root compromise** | **Four layers.** Hardware-bound root (no key in memory/env/metadata) + M-of-N threshold issuance at root only + mandatory transparency logging of all root issuance (forcing forgery to be either rejected or permanently visible) + blast-radius caps enforced *independently of the chain*, which no warrant may raise. | [`07`](07-root-compromise.md) |

### Still open

4. **Anchoring windows.** 60 s for routine and 5 s for elevated remain asserted rather than derived.
   They need justification against measured batch throughput, which requires a running
   implementation — this is deliberately deferred to first benchmark rather than guessed at now.

## What is deliberately not here

No runnable code. This pack is normative specification only; implementation is routed to the fleet
per the sprint plan, and the specs are written to be implementable independently in Rust, Python,
and TypeScript against shared golden vectors.

No CBOR encoding. v2.0 chose JCS-canonical JSON with DSSE for interoperability with the tooling the
alliance already uses. A compact binary profile may be added later as a proven-equivalent mapping;
it is not required for v0.
