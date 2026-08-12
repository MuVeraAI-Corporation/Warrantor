# 03 — Portfolio Re-Cut, v4

> **Supersedes the wave/component assignments in [`00-reconciliation-matrix.md`](00-reconciliation-matrix.md).**
> The matrix remains the historical catalog of what each source portfolio proposed. This document is
> the authoritative statement of what Warrantor builds.
>
> Produced by applying the Blueprint v4 re-cut rules to all 54 implementable components, one
> analysis pass per component group.

---

## 1. The result in one table

| Decision | Count | Meaning |
|---|---|---|
| **KILL** | 21 | Re-implements mature OSS Warrantor should consume, or serves no v4 thesis |
| **MERGE** | 17 | Absorbed into one of six consolidated products |
| **RE-SCOPE** | 10 | Survives with a materially narrower charter |
| **SPLIT** | 2 | One half killed, one half survives |
| **ADD** | 6 | Genuinely unclaimed assets with no existing implementation anywhere |
| **KEEP** | 4 | Survives essentially intact |

**Fifty-four components collapse to six consolidated products plus a small number of standalone
survivors.** The previous portfolio's central flaw was not ambition; it was spending most of its
surface area re-implementing primitives the alliance had already contributed. Twenty-one kills is
the measure of that flaw, and removing them is what makes the remainder buildable.

---

## 2. The six consolidated products

Everything that survives belongs to one of these, or is a deliberate standalone.

| ID | Product | Absorbs | Tier |
|---|---|---|---|
| **W1** | **Notary core** — the single Rust trusted core; decision + proof hot path only | T1 (kept, narrowed), I2 (as an internal SPIFFE-binding module) | A |
| **W2** | **Evidence-before-commit envelope** — one signed object carrying pre-auth proof, delegation-chain intersection, outcome, runtime AIBOM, optional attestation bundle, composite verdict, enforcement mode | T2, R1 (commit transaction), R4 (lease gate only), S2, E1, protocols P1/P2/P6/P7/P12 as *profiles* | A |
| **W3** | **Containment conformance** — kill-switch + fail-closed + stop-anywhere as one product | R2 (chaos-harness half), R3 (H.R. 9917 suite), F3 (disconnected-edge profile), A10 | A→B |
| **W4** | **Cross-stack policy compiler** — two layers (gateway + kernel), jurisdiction as swappable modules | R5 (re-scoped), R6 (equivalence test harness), A4 | B |
| **W5** | **Egress broker** — model-belief-independent, default-deny | R7 (re-scoped), S6, N3 (tool-call admission arm) | A |
| **W6** | **Delegation-chain intersection** — the surviving half of the identity plane | I1 (authority half; identity half killed), I3 bounded revocation | B |

Two things are notable. First, **five competing protocol formats become one envelope with five
views** — P1, P2, P6, P7 and P12 are demoted from independent protocols to profiles of W2. Every
additional wire format multiplied the conformance burden while weakening the unification claim that
*is* the novelty. Second, **the identity plane is split**: SPIFFE/SPIRE is consumed for identity,
and only the delegation-chain intersection engine — the part nobody else builds — survives.

---

## 3. What was killed, and what replaces it

The twenty-one kills fall into four patterns. Each is a case where the component wrapped mature OSS
that Warrantor should call rather than re-implement.

| Killed | Consume instead |
|---|---|
| `R8` sandbox-runtime | WASI Preview 2 / Wasmtime, gVisor, Firecracker, **NVIDIA OpenShell** — demoted to a `SandboxBackend` adapter trait |
| `I1` identity half | **SPIFFE/SPIRE** (CNCF-graduated) + Cedar; only the authority-intersection half survives |
| `S1` safe-tensors-pp | Hugging Face **Safetensors** + **OpenSSF Model Signing** (production, NGC-signed) |
| `S7` tamper-scan, `A2` adversaria, `A3` bias-sentinel, `A7` red-team-cloud | **garak**, **PyRIT**, **Inspect/inspect_evals**, **AgentDojo**, **METR public-tasks** — Warrantor signs their output, it does not re-scan |
| `C1-2` cuda-gram, `C1-3` attesta-flow, `C1-4` tee-serve | **NVIDIA NRAS/RIM**, **Project Veraison**, **Intel Trust Authority** |
| `N1`, `N2`, `N4` inference stack | vLLM / TensorRT-LLM / NIM / Triton — serving is not an authority-and-evidence concern |
| `F1` fed-core, `F2` dp-crate, `F4` fleet-marshal | Flower/NVFlare, Opacus, existing K8s operators |
| `X3`, `X4`, `X6`, `X11` | Out of thesis, or duplicative of alliance and partner work |

**The discipline being enforced:** if a component's value is mostly that it wraps something mature,
it is either killed or reduced to a thin adapter. Warrantor must never appear as a *peer* to
SPIFFE, Cedar, Sigstore, Veraison, garak, or OpenShell — it is the layer that binds their outputs
into one non-bypassable, signed decision.

---

## 4. What was added

Six additions, each with no existing implementation anywhere:

| ID | Addition | Tier | Why it is unclaimed |
|---|---|---|---|
| `A5a` | **SAFE Finding schema** + reference producer/consumer | B | The SAFE RFC is prose-only — no schema, no transport, no crosswalk |
| `A5b` | **Invariant attack corpus** — one adversarial suite per invariant, capability-elicited | B | Benchmarks test models; nothing tests an authority substrate's invariants |
| `A10` | **Kill-switch conformance profile** | B | No kill-switch conformance suite exists anywhere, despite legislated capabilities |
| `I3` | **Bounded-revocation layer** — execution-count / release-consistency, not TTL | B | TTL is formally inadequate at agent speed; no OSS offers a revocation SLA |
| `R9` | **Machine-checked spec of the 12 invariants** (TLA+/Lean) | C | Machine-checked guarantees exist only for narrow slices |
| `R10` | **Attack-finding-to-policy loop** | B | Nothing ties "attack X succeeded in eval" to "deny action-class X in production" |

---

## 5. Standalone survivors

| ID | Component | Tier | v4 charter |
|---|---|---|---|
| `T1` | trust-core → **W1 notary core** | A | Narrowed to canonicalization, the composite verdict function, DSSE sign/verify, and SVID binding. Signing keys, transparency anchoring, model signing, and attestation parsing are all delegated. The `notarize` verb is retired as a cosign duplicate. |
| `A6` | conformance | A | The cross-language conformance harness — now also the carrier for the invariant attack corpus and the kill-switch profile |
| `X8` | mcp-gateway | A | The mediation point that earns `mediated` enforcement mode at the tool boundary |
| `X1` | CLI (re-scoped) | A | Verification and conformance UX; not a package manager |
| `S4` | → **warrantor-aibom** (re-scoped) | A | Runtime-bound AIBOM: binds the ML-BOM to the weight digest that actually served the action |
| `A1` | safe-eval → **eval-receipt** (re-scoped) | A | Wraps existing scanners and signs their output; an evidence *producer* for W2 |

---

## 6. Corrections applied

Two factual errors in the existing RFC set were found during the re-cut and must be fixed
everywhere they appear:

1. **The AI Kill Switch Act is H.R. 9917, not "H.R. 2026."** Introduced 23 July 2026; four mandated
   capabilities; penalties reaching $20M/day for defying a shutdown order; the DHS verification
   format is unspecified — which is precisely why the conformance suite is an unclaimed asset.
2. **SR 11-7 is superseded.** Cite Fed SR 26-2 / OCC Bulletin 2026-13 (17 April 2026), which placed
   generative and agentic AI explicitly *out of scope* pending separate guidance.

---

## 7. Build order

Tiers are hard-ordered. **Tier C does not begin before Tier A ships.** The most differentiating
work is also the least parallelizable, and that is exactly how a small team loses a year.

**Tier A (the spine):** W1 notary core · W2 evidence envelope · W5 egress broker · W3's fail-closed
chaos-harness half · eval-receipt · warrantor-aibom · A6 conformance · X8 gateway.

**Tier B (strategic bets):** W3 kill-switch conformance suite · A5a SAFE schema · W6 delegation
intersection · I3 bounded revocation · W4 two-layer compiler · R10 attack-to-policy loop ·
A5b attack corpus.

**Tier C (research-grade, gated):** R9 machine-checked spec · C1-1/C1-5 full composite attestation ·
stateful sequence evaluation · the compiler equivalence proof · re-derivable-inference profile.

---

## 8. Labeled as adopted, never as invention

CaMeL (dataflow), the AI-control protocol family (trusted monitoring, trusted editing, resampling),
MemTX and origin-bound memory, and Red Hat **asago** (governance-clause compilation) are **adopted
and credited** throughout. asago in particular is a composition seam, not a component to build: it
decides what should be allowed; Warrantor makes it provably non-bypassable and signs the result.

Stating this plainly is not modesty — it is what makes the six additions credible by contrast.

---

## 9. Cross-references

- Blueprint v4 (strategy, bets, playbook): [`../../warrantor_blueprint_v4.html`](../../warrantor_blueprint_v4.html)
- Research dossier (the evidence base): [`../../warrantor_research_dossier.html`](../../warrantor_research_dossier.html)
- Contract pack (frozen candidates): [`../specs/warrantor-v4/`](../specs/warrantor-v4/)
- Historical catalog: [`00-reconciliation-matrix.md`](00-reconciliation-matrix.md)
- Architecture, invariants I-01…I-12: [`02-architecture.md`](02-architecture.md)
