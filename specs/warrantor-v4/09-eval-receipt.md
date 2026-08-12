# Eval Receipts — signing what the scanners already produce

> garak has roughly 8,000 stars, ships ~100–120 probe families, and **does not sign its output**.
> Neither does PyRIT, Inspect, AgentDojo, or the METR task suite. Every one of them produces
> evidence that cannot be distinguished from a text file someone edited.
>
> **Status:** FROZEN CANDIDATE — Tier A. The re-scoped A1; an evidence *producer* for the receipt
> envelope. Warrantor builds no scanner.

---

## 1. What the signature attests

Precisely this, and deliberately nothing more:

> **This exact scanner, at this exact version and configuration, run against this exact target
> digest, produced this exact output, at this time, on this platform.**

It does **not** attest that a finding is correct, that the absence of a finding means the target is
safe, or that the scanner's methodology is sound. Warrantor does not own these tools and will not
assert correctness about tools it does not own.

This narrower claim is the useful one. The documented gap in the field is not that scanners are
wrong — it is that their results are **inconsistent, unsigned, non-reproducible, and not
content-addressed**, so findings cannot be compared across tools, across organizations, or across
time. Run-provenance closes exactly that gap, and it is a claim that can actually be verified.

---

## 2. Structure

An eval receipt is a WAR receipt (`01-war-receipt.md`) whose operation class is `eval.run` and whose
predicate carries an `eval` block. It inherits DSSE signing, JCS canonicalization, and tiered
anchoring unchanged — one envelope, another view.

| Block | Contents |
|---|---|
| `harness` | Name, version, source digest, invocation digest, plugin/probe set with per-plugin digests |
| `target` | What was evaluated — model digest, endpoint identity, agent configuration digest, skill digests |
| `config` | Full resolved configuration digest, seeds, temperature/decode parameters, iteration counts |
| `environment` | Platform, accelerator, driver, and container digests |
| `results` | Per-case outcome records, each with a stable case identifier and a result digest |
| `summary` | Counts by outcome; **never** a single headline pass/fail |
| `validity` | Elicitation method, noise floor, eval-awareness markers (§4) |
| `provenance` | Model-BOM for every model involved, including attacker and judge models |

**Normative.** `summary` **MUST NOT** be reducible to a single score presented without its
`validity` block. A number without its noise floor invites exactly the cross-organization comparison
that is unsound.

---

## 3. Reproducibility as a recorded property

You chose run-provenance over enforced reproducibility, which is right — many of these tools are
non-deterministic by construction, and requiring determinism would exclude the most valuable
adversarial harnesses. Reproducibility is therefore **recorded, not required**:

| `reproducibility` | Meaning |
|---|---|
| `deterministic` | Seeds and versions pinned; re-running is expected to yield an identical `results` digest |
| `stochastic_bounded` | Non-deterministic, but the run reports a distribution over N repetitions |
| `stochastic_single` | Single non-deterministic run. **MUST NOT** be cited as a rate |
| `unknown` | The harness does not expose enough to classify. Permitted, and flagged |

**Normative.** A receipt claiming `deterministic` **MUST** record everything needed to re-run:
seeds, model digests, decode parameters, and harness digest. A consumer that re-runs and gets a
different `results` digest **SHOULD** emit a SAFE Finding — a determinism claim that fails to
reproduce is itself a meaningful defect.

---

## 4. Validity — why a clean result may mean nothing

Evaluation-awareness, sandbagging, and in-context scheming are documented and measured. A model can
recognize a test and behave differently, so an unqualified pass is not evidence of safety.

Every eval receipt **MUST** carry:

- `elicitation_method` — how the target was pushed toward failure. Capability-elicited (instructed
  and equipped to succeed) or propensity-observed (left to its own behavior). **Propensity-observed
  results MUST NOT be presented as capability bounds.**
- `noise_floor` — the threshold below which a failure would not have been detected.
- `awareness_markers` — situational-awareness signals in the trajectory, with the rate at which the
  target referenced being evaluated.
- `holdout_status` — whether the cases were held out or may have been trained on. Contaminated
  benchmarks flatter everyone.

**Normative.** A receipt lacking `elicitation_method` or `noise_floor` is **INDETERMINATE** and
**MUST NOT** be aggregated with qualified results or used as a gate input.

---

## 5. Wrapping, not forking

Adapters translate a harness's native output into the receipt. They **MUST NOT** modify the harness,
filter results, or re-interpret outcomes.

| Harness | Native output | Adapter obligation |
|---|---|---|
| **garak** | JSONL per attempt + HTML | Digest each attempt record; carry probe and detector identities per case |
| **PyRIT** | Orchestrator results | Record attacker model digest in `provenance` — the attacker is part of the experiment |
| **Inspect / inspect_evals** | Eval logs | Preserve per-sample identifiers so results remain sample-addressable |
| **AgentDojo** | Utility + security pairs | Carry **both** axes; a security score without its utility score is misleading |
| **METR tasks** | Task scores | Preserve task versioning; scores are not comparable across task revisions |

**Normative.** An adapter that cannot faithfully represent a harness's output **MUST** fail rather
than emit a lossy receipt. A receipt that silently drops cases is worse than no receipt, because it
looks authoritative.

**Upstream first.** Where a harness can emit signed output natively, the correct move is to
contribute that upstream rather than maintain a wrapper. garak is the first target and the reason
this component is Tier A: it is uncontested value on a widely-used project that does not sign today.

---

## 6. Where eval receipts go

Three consumers, one object:

1. **The attack-to-policy loop (`R10`).** A confirmed failure against action-class X becomes a
   proposed deny rule for X. The receipt is the input that makes the proposal auditable.
2. **SAFE findings.** A failure projects into a SAFE Finding with `verification.method` and
   `noise_floor` populated directly from `validity`.
3. **Safety cases.** Assurance-argument evidence nodes reference eval receipts by digest, so a claim
   that a control holds points at a specific, verifiable run rather than a document.

That third path is what makes Defeater Cards mechanical: when a new receipt defeats a claim, the
assurance argument can be invalidated automatically and the corresponding authority revoked within
the bounded window.

---

## 7. Conformance

| Test | Expected |
|---|---|
| Modified result record | Signature verification fails |
| Receipt without `elicitation_method` or `noise_floor` | INDETERMINATE; rejected as a gate input |
| `deterministic` receipt that does not reproduce | Flagged; SAFE Finding emitted |
| Propensity-observed result cited as a capability bound | Rejected |
| Adapter drops cases the harness reported | Adapter MUST fail instead |
| Target digest mismatch against the artifact actually served | Rejected |
| AgentDojo security score presented without utility | Rejected |
| Attacker or judge model absent from `provenance` | Rejected |
| Aggregation across differing noise floors | Rejected without explicit normalization |
