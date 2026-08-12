# 04 — The 90-Day Sprint Runbook

> Assignable work, in dependency order, against a frozen contract. This turns Blueprint v4's sprint
> section into something a fleet can execute without conflicting.
>
> **Governing rule:** contracts first, then parallel. An agent fleet building against an unfrozen
> contract produces conflicting implementations faster than one developer produces correct ones.

---

## 1. Routing principle

Work is classified by what failure would cost, not by how large it is.

| Class | Characteristics | Routing |
|---|---|---|
| **Correctness-critical** | A defect silently grants authority or breaks an invariant | Highest-capability tier, single-threaded, mandatory review gate |
| **Contract-bound volume** | Behavior fully determined by a frozen spec + vectors | Parallel fan-out; conformance vectors are the acceptance test |
| **Synthesis** | Docs, crosswalks, schema mappings, upstream PR bodies | Parallel; human review before anything leaves the repo |
| **External** | Upstream contributions, standards responses | Human-approved before submission, always |

**No additional spend.** Work routes to units with existing headroom; if a unit is out of quota it
re-routes rather than being topped up.

---

## 2. Phase 1 — Freeze (Days 1–14, sequential)

Nothing else starts. Everything downstream depends on these being right, and they are cheap to
change now and expensive to change after fan-out.

| Task | Class | Done when |
|---|---|---|
| Ratify the receipt envelope + notary API | Correctness-critical | Two independent readings agree on every normative rule |
| Ratify the capability algebra | Correctness-critical | Conformance vectors pass; attenuation property re-verified |
| Golden vectors for P2 v2.0 | Contract-bound | Every adversarial case has a vector; schema cases machine-verified |
| Resolve the anchoring-window question | Correctness-critical | Either derived from a benchmark or explicitly deferred with a recorded reason |
| Correct H.R. 9917 and SR 26-2 citations repo-wide | Synthesis | No occurrence of "H.R. 2026" or a live SR 11-7 citation remains |

**Exit gate:** the contract pack moves from FROZEN CANDIDATE to FROZEN. Until then, no implementation
work begins — this gate exists to be enforced, not admired.

---

## 3. Phase 2 — Two tracks open (Days 8–30)

The alliance track opens before the freeze completes, because its window is external and closing.

### Alliance track (runs the full quarter)

| Task | Class | Note |
|---|---|---|
| Submit the SAFE Finding schema PR | External | Human-approved. Strip every Warrantor-specific reference first |
| Post issue responses #1, #4, #5, #6, #7 | External | **Separately, over several days** — five simultaneous comments reads as capture |
| Signed-report output PR to garak | External | Uncontested value; the highest-leverage upstream contribution available |

### Core track

| Task | Class | Depends on |
|---|---|---|
| Verdict function — the nine gates, in order | Correctness-critical | Freeze |
| Receipt canonicalization + DSSE sign/verify | Correctness-critical | Freeze |
| Capability algebra implementation | Correctness-critical | Freeze |
| Delegation engine — assembly, verification, meet | Correctness-critical | Algebra |
| First harness adapter (one only) | Contract-bound | Notary API |
| Local durable receipt store | Contract-bound | Receipt spec |

**Rule:** one adapter, not three. A second adapter before the first is proven merely multiplies the
same mistakes.

---

## 4. Phase 3 — Prove the claim (Days 30–60)

This phase produces the demonstrations that make the thesis concrete rather than argued.

| Task | Class | Acceptance |
|---|---|---|
| Fail-closed chaos harness | Contract-bound | Each failure injected independently; denial verified; **no retry amplification** |
| Egress broker | Correctness-critical | Agent cannot express a destination; DNS pinned; metadata range unreachable |
| **The incident-replay demo** | Synthesis + core | Injected hostname has nowhere to go; signed `deny` receipt produced |
| Eval-receipt adapters (garak, Inspect) | Contract-bound | Lossless; no dropped cases; validity block mandatory |
| Runtime-bound AIBOM in the envelope | Contract-bound | Bound to the digest that actually served |
| Batch receipts for routine tier | Correctness-critical | I-07 holds at the batch boundary; no tier laundering |

**The demo is the deliverable.** Replaying the documented "prompt says no internet, environment says
otherwise" misconfiguration and showing the denial is worth more in a design-partner conversation
than any architecture diagram.

---

## 5. Phase 4 — Claim the category (Days 60–90)

| Task | Class | Note |
|---|---|---|
| Containment conformance suite v0 | Correctness-critical | Capability-elicited; refuses to emit a clean report without elicitation method and noise floor |
| Root-compromise battery | Correctness-critical | Off-log issuance rejected; caps engage; recovery does not silently re-grant |
| SAFE producer + verifier end-to-end | Contract-bound | Real telemetry in, valid finding out |
| Invariant attack corpus v0 | Contract-bound | At least L1 and L2 per invariant; L3 where feasible |
| Attack-to-policy loop (monitor mode) | Correctness-critical | Approval gate enforced; no blanket approval possible |
| Plane ↔ partner-contribution mapping | Synthesis | The positioning document |

---

## 6. Review gates

Every merge passes a gate; correctness-critical work passes two.

| Gate | Question |
|---|---|
| **Contract** | Does it match the frozen spec, including every normative MUST? |
| **Vectors** | Do all conformance vectors pass, including adversarial ones? |
| **Invariant** | Which invariant does this touch, and what would violating it look like? |
| **Fail-closed** | What happens when each dependency is unavailable? |
| **Duplication** | Does this re-implement something we said we would consume? |
| **Claim** | Does anything here claim more than the enforcement mode supports? |

The duplication gate is the one that protects the re-cut. Twenty-one components were killed for
re-implementing mature OSS; without an active gate, they grow back one convenience wrapper at a
time.

---

## 7. What is explicitly not in the 90 days

The machine-checked invariant specification, full composite hardware attestation, stateful
sequence-level evaluation, the compiler equivalence proof, and the re-derivable-inference profile.

All are Tier C, all are genuine differentiators, and all are the least parallelizable work in the
portfolio. **Tier C does not begin before Tier A ships.** This is the discipline most likely to be
broken under enthusiasm, and breaking it is the most probable way this program produces a year of
interesting research and no shipped substrate.

---

## 8. Success at day 90

Not stars, and not revenue. Four externally verifiable things:

1. The SAFE schema PR is **merged or actively shaping** the RFC discussion.
2. Signed-report output is **merged upstream in garak**.
3. The incident-replay demo runs end-to-end and produces a verifiable `deny` receipt.
4. A third party can run `Verify` against a Warrantor receipt **with no privileged access** and
   independently recompute the authority intersection.

The fourth is the real test. If an outsider cannot verify a receipt without our cooperation, then
what has been built is a logging system with good marketing, not an evidence substrate.
