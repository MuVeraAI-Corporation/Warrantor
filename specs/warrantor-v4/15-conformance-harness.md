# A6 — The Conformance Harness

> The acceptance test for everything else. If an implementation claims to enforce an invariant, this
> is what decides whether the claim survives contact with an adversary.
>
> **Status:** FROZEN CANDIDATE — Tier A. The last unwritten Tier A spec.

---

## 1. Three questions, deliberately separated

The harness runs three suites that must never be blended into a single score, because they answer
different questions and can disagree:

| Suite | Question | Source |
|---|---|---|
| **Vectors** | Does it match the spec? | Golden test vectors per protocol |
| **Corpus** | Can it be broken? | The invariant attack corpus, capability-elicited |
| **Containment** | Can it stop? | The four legislated capabilities + fail-closed battery |

An implementation can pass vectors and fail the corpus — that is the common and interesting case,
because vectors test what the author thought of and the corpus tests what an attacker thinks of.
**Reporting a single aggregate figure across the three destroys exactly the information that
matters.**

---

## 2. Cross-language equivalence

The stack rule says no security invariant may have two authoritative implementations. The harness
enforces the corollary: **where multiple languages expose the same operation, they must agree
byte-for-byte.**

For each vector, every language binding runs the operation and results are compared on the
canonical serialization, the resulting digest, the verdict, and the denial gate.

**Normative.** A divergence between the Rust core and any binding is a **release-blocking defect**,
never a binding-specific quirk to document. Divergence means either a binding re-implemented
something it should have called, or canonicalization is not actually deterministic — and both are
the failure this rule exists to prevent.

A language absent from the report has **not** been verified. Absence is reported as absence, never
as a pass.

---

## 3. Running the corpus honestly

The attack corpus is only meaningful under elicitation, so the harness enforces the conditions
rather than trusting the suite author:

- Every case declares its elicitation method, affordances, and noise floor. A case missing any of
  these is **INDETERMINATE** and excluded from scoring rather than counted as a pass.
- At least one **unannounced** run per capability, where the system under test is not informed.
- Situational-awareness markers are recorded per run.
- A fraction of cases is **held out** and rotated, so implementations cannot be tuned to the
  published set. Held-out results are reported separately.

> **Normative.** A corpus run with zero violations across all levels **MUST** be reported as
> `REVIEW_REQUIRED`, not `PASS`, until its elicitation has been reviewed by a human. In adversarial
> testing a perfect score is more often evidence of a weak attacker than a strong defense, and a
> harness that celebrates it is worse than no harness — it manufactures false confidence with a
> signature attached.

---

## 4. The report

A signed artifact, structured so it cannot flatter:

```
ConformanceReport
├── subject{}          — implementation, version, digests, languages exercised
├── enforcement_mode{} — mode + per-class coverage, from equivalence testing
├── vectors{}          — per-protocol pass/fail, per-language, divergences listed
├── corpus{}           — per-invariant: attempted, violated, detected-not-prevented,
│                        held-out results reported separately
├── containment{}      — per-capability verdict + latency DISTRIBUTION (never a single number)
├── elicitation{}      — method, affordances, announced/unannounced, awareness markers, noise floor
├── limitations[]      — MANDATORY, non-empty
└── integrity{}        — DSSE signature, transparency anchor
```

**Normative.**

- `limitations[]` **MUST** be non-empty. Every evaluation has blind spots; a report claiming none is
  evidence of an incomplete evaluation, not a complete system.
- Verdicts are **per-suite, per-capability, per-enforcement-mode**. There is no aggregate PASS.
- A report **MUST NOT** be emitted at all if elicitation is unsubstantiated. The harness refuses
  rather than emitting a caveated pass, because caveats are read less often than headlines.

---

## 5. Self-application

The harness runs against Warrantor itself, and its results are published alongside any claim
Warrantor makes about its own invariants. An authority substrate that tests everyone but itself has
inverted its own thesis.

**Normative.** Warrantor's published conformance report **MUST** use the same format, the same
refusal conditions, and the same held-out discipline required of any other implementation. Where
Warrantor fails a case, the failure is published; where it runs in `advisory` mode, the report says
so.

---

## 6. CI integration

The harness is the gate, not a nightly report nobody reads:

| Trigger | Suites | Blocking |
|---|---|---|
| Every PR | Vectors (all languages) | Yes |
| Every PR touching the core | Vectors + corpus L1/L2 | Yes |
| Nightly | Full corpus incl. L3 + containment | Reported; triaged next day |
| Release | All three + held-out set | Yes |

**Normative.** A vector failure **MUST** block merge. Vectors encode the frozen contract, and a
contract that can be broken by a merge is not frozen.

---

## 7. Conformance of the harness itself

| Test | Expected |
|---|---|
| Aggregate PASS across suites | Non-conformant — no such verdict exists |
| Report with empty `limitations[]` | Rejected |
| Zero-violation corpus run reported as PASS | Non-conformant — must be `REVIEW_REQUIRED` |
| Language absent from report presented as passing | Non-conformant |
| Rust/binding divergence downgraded to a note | Non-conformant — release-blocking |
| `advisory` results presented as `mediated` | Non-conformant |
| Containment latency reported as a single number | Non-conformant — distribution required |
| Report emitted despite unsubstantiated elicitation | Non-conformant — harness must refuse |
| Held-out results merged into headline figures | Non-conformant |
