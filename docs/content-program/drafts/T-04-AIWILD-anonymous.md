# Masking a Field's Loss Does Not Isolate That Field

*Submitted to AIWILD @ NeurIPS 2026 (Third Workshop on Agents in the Wild), regular track.
Anonymized for double-blind review. Non-archival.*

> **Anonymity.** No author, institution, repository, product or internal identifier appears in this
> document. Model, corpus and infrastructure are described generically. Any artifact released with
> this submission must be anonymized to the same standard, per the workshop policy that anonymity
> violations face desk rejection.

---
### Two rejected LoRA runs, and what an unsupervised output field does when its neighbor is tuned



---

## Abstract

Structured-output guard models emit several fields per inference, typically a severity verdict and a category. When one underperforms, a natural experiment is to mask its loss and tune the
other, reasoning that withholding supervision preserves behavior.

It does not. We report two rejected fine-tuning runs on a 0.6B guard model. Run 1 supervised severity
with the binary targets its corpus supports and extinguished its third severity class, 49
Controversial verdicts falling to 0, converting a documented operator lever into a no-op that still
reported success. Run 2 masked the severity line in the loss while keeping it in
the input, and scored 17 points of overall recall below run 1 and 23 adversarial points below the
untuned base model. The masked field did not hold still: Controversial overproduced at 187
against a base of 49, Unsafe collapsed from 650 to 367, and the model began emitting its own category
vocabulary in the severity slot.

Neither mechanism is new. Concurrent work reports a masked field degrading under the same
configuration, and binary collapse is standing practice in guardrail dataset design. Three narrower
findings survive: the per-class distribution of a masked categorical enum against base-model counts;
the direction of the effect, opposite in sign to the concurrent result whose unmasked baseline
supervises a degenerate target; and the governance consequence, that a masked field is a policy
surface whose silent movement can disable an audited control.

We report both rejections, the automated gate's two verdicts, and the corpus property that blocked
the intended repair.

---

## 1. Why report two runs that were rejected

Guard models are increasingly the primary runtime control in agentic deployments, and they are
increasingly structured-output models rather than binary classifiers: a severity verdict *and* a
category, parsed downstream by policy that may treat either as dispositive.

That structure invites a specific experiment. When one field is weak, tune the other and leave the
first alone. The intuition is that supervision is what changes a model, so withholding supervision
should preserve behavior.

We ran that experiment. It failed, and it failed in a direction that is worth more than a promotion
would have been. Both runs were rejected by an automated parity gate before any promotion decision
reached a human, and the gate's two verdicts distinguish precisely between *no improvement
demonstrated* and *this made it worse* — a distinction the literature on fine-tuning guards does not
usually get to make, because unsuccessful runs are rarely reported at all.

**Contributions.**

**⚠️ Novelty, bounded first.** That loss masking fails to isolate a field under a shared adapter is
**documented concurrently**, and that binary targets produce binary behavior is **established
practice**. §7 withdraws the broader claim an earlier draft made and cites the work that refutes it.
Four narrower contributions survive:

1. **The distributional signature.** The per-class distribution of a masked *categorical enum*
   measured against the base model's own counts — overproduction of one class, collapse of another,
   and migration of the neighboring field's vocabulary into the masked slot (§4.2).
2. **The direction.** Masking cost 17 recall points *against supervising the same field with wrong
   targets*. That is the opposite sign to the concurrent result, whose unmasked baseline supervises a
   degenerate target, and the disagreement is informative rather than contradictory (§4.1, §7).
3. **The governance consequence.** A masked field is a policy surface. Its silent movement converted
   a documented operator control into a no-op that reported success (§3.3). We are aware of no
   treatment of masked-field drift as an auditability failure rather than a quality failure.
4. **The corpus constraint and the prescription.** The signal needed to supervise three-valued
   severity exists only where it cannot be trained on (§3.5), and isolation therefore requires
   separate parameters rather than a masking flag (§5).

---

## 2. Setup

**Model.** A 0.6B parameter generative guard model, fine-tuned with LoRA. A same-size untuned
baseline is retained deliberately: without a same-size comparator, a rejection cannot distinguish
*the fine-tune did not work* from *this model is smaller than the one it is being compared to* —
different findings with different next actions.

**Output format.** Each inference emits a severity line and a category line. Severity is three-valued
in the base model's vocabulary — `Safe`, `Unsafe`, `Controversial`. Downstream policy treats a gating
category as harmful in its own right, and separately allows an operator to decide whether
`Controversial` counts as harmful.

**Corpus.** A public guard training mixture of 38,694 rows. **Its severity targets are binary**: the
rendering function emits only `Safety: Unsafe` or `Safety: Safe`, and the corpus contains 19,349 of
one and 19,345 of the other. There is no third value anywhere in the training targets.

**Evaluation.** The full held-out test split, 1,699 items, scored on recall first, with per-category
recall and the confusion matrix reported alongside.

⚠️ **Reported precision of every figure in this paper.** Headline rates are reported as recorded, to
four decimal places. **Per-class counts were reconstructed from the recorded rates and denominators**
and are accurate to approximately one row; they are reported as integers because that is how they
were reconstructed, not because they were counted. Differences of one or two in a class count carry
no weight in any argument here. The two that do carry weight — 49 `Controversial` verdicts falling to
0, and 187 against a base of 49 — are order-of-magnitude effects that survive the uncertainty by a
wide margin. §6 states why the underlying per-item outputs cannot be re-derived. An automated gate compares a candidate against a
measured baseline on the same lane and precision, and rejects on either an unimproved headline or a
per-category floor breach.

**Compute.** Run 1: a single A100, 38,694 rows, one epoch, 2 hours 28 minutes, final training loss
0.0101. The runs are small; the findings are about direction, not scale.

---

## 3. Run 1 — supervising a three-valued field with binary targets

### 3.1 The gate rejected it, and was right twice

```
VERDICT: REJECT (exit 1)
 - recall 0.8329 against 0.8554 is within sampling noise at these counts (this set could
   resolve about 0.036). No improvement was demonstrated, which is not the same finding
   as a regression.
 - per-category recall fell below a measured baseline floor: others 0.7653 below 0.7857;
   social stereotypes and unfair discrimination 0.6184 below 0.7237
```

The first clause is a discipline worth naming: **the gate refuses to call an unresolvable difference
an improvement**, and says so in the language of what the test set can resolve.

### 3.2 Against the same-size baseline, the fine-tune made the model worse

| | untuned 0.6B | tuned | Δ |
|---|---|---|---|
| Overall recall | 0.8488 | **0.8329** | **−0.0159** |
| False-positive rate | 0.0624 | 0.0519 | −0.0105 |
| Precision | 0.9156 | 0.9276 | +0.0120 |
| `Controversial` verdicts emitted | 49 | **0** | extinguished |

Recall down, false positives down, precision up: **the adapter learned to be more permissive.** For a
deny gate that is the wrong direction, and it is the direction that fails silently — a guard that
blocks less looks better on every metric an operator watches casually.

**The mechanism is the target vocabulary.** One epoch of binary targets extinguished the third
severity class entirely. The rendering function's own reasoning had been that inventing a
`Controversial` target the labels do not distinguish would teach a distinction the data never made,
and that downstream policy scoring `Controversial` as harmful "would quietly absorb the difference."
**It did not absorb it.** Every prompt that would have been `Controversial` — and therefore caught,
because policy scores it harmful — is now `Safe` and missed.

### 3.3 The second-order failure: a documented lever became a no-op

This matters more to a governance product than the recall delta.

The deployment exposes an operator policy row: *does a borderline verdict count as harmful?* On the
untuned model that lever moves recall from **0.8488 to 0.8011** — a real, documented control with a
measurable effect.

On the tuned model, the same lever reports **0.8329, identical to the headline row**, because there
are no `Controversial` verdicts left for it to act on.

**A documented operator control silently became inert, and nothing in the system announced it.** No
error, no warning, no change in any interface. The lever is still in the configuration, still in the
documentation, and now does nothing. For a system whose purpose is to be auditable, a control that
reports success while having no effect is a worse failure than one that breaks loudly.

### 3.4 Targeting the weak category did not fix the weak category

The run's stated purpose was to improve three underperforming classes. Two moved marginally; the
largest collapsed.

| Class (all three targeted) | Untuned | Tuned | Δ |
|---|---|---|---|
| `fraud_assisting_illegal_activities` | 0.7833 | 0.8000 | +0.0167 |
| `others` | 0.7551 | 0.7653 | +0.0102 |
| `social_stereotypes_and_unfair_discrimination` | 0.7763 | **0.6184** | **−0.1579** |

The finding is not that LoRA does not work here. It is that **a corpus whose targets are binary
trains a binary model**, and weak-category selection does not survive contact with a three-valued
output space.

### 3.5 The repair that was not available

Two repairs were on the table. Render `Controversial` for rows the corpora mark borderline, or stop
supervising severity at all.

**The first is not implementable from either corpus.** The training mixture's borderline signal — an
agreement column distinguishing unanimous from split annotator judgments — **exists only in the test
split.** The train split does not carry it, and the second corpus in the mixture has no equivalent
column at all.

That is a corpus-level constraint with a general shape: **the signal needed to supervise a
three-valued severity output exists where it cannot be trained on and is absent where it could be.**
Any practitioner attempting a graded severity output from these corpora will hit the same wall.

**Correction, 2026-08-30: the constraint is corpus-specific, not general.** The paragraph above is
accurate about the two corpora in this program's mixture, and an earlier draft over-generalized it to
"any practitioner attempting a graded severity output from these corpora." A survey of public
alternatives refutes that. The Aegis AI Content Safety Dataset 1.0 carries an explicit third severity
value, **`Needs Caution`**, in its **training** split -- 1,658 occurrences in a 4,000-row sample --
alongside five per-annotator label columns that supply exactly the annotator-agreement signal this
section reports as available only in WildGuardMix's test split.

So the accurate statement is narrower and more useful. **Supervising a three-valued severity output
is possible; it is not possible from the mixture used here.** The corpus-selection decision that
produced the failure is the finding, not a property of the field. A practitioner who needs graded
severity should choose a corpus that labels it, and one exists.

*This correction does not rescue the runs. Both were trained on the mixture described above and both
failed for the reasons given. It removes an over-claimed generalization from the analysis of why.*


So supervising severity at all means supervising it binary. Which left the second option.

---

## 4. Run 2 — masking the field, and what the field did

The reasoning was explicit and, we thought, conservative: mask the severity line in the loss, keep it
in the input, and the base model's severity distribution should be left intact while the category
line is tuned. Downstream policy treats a gating category as harmful independently, so catch rate
could improve through the category path alone.

### 4.1 The measurement

| Run | Overall recall | Adversarial recall | Severity verdicts emitted |
|---|---|---|---|
| Untuned 0.6B | 0.8488 | 0.7918 | controversial 49, safe 1000, unsafe 650 |
| Run 1 — severity supervised | 0.8329 | 0.7947 | **controversial 0**, safe 1022, unsafe 677 |
| **Run 2 — severity masked** | **0.6804** | **0.5572** | controversial **187**, safe 1132, unsafe **367**, *plus category words* |

**Masking was 17 points of overall recall worse than supervising the field binary, and 23 adversarial
points below the untuned model.** The gate rejected run 1 as *within sampling noise* and run 2 as
*recall regressed beyond sampling noise* — correctly separating "no improvement shown" from "this
made it worse."

### 4.2 The distributional signature

The recall number says the run failed. The verdict distribution says **why**, and it is the paper's
central evidence.

An isolated field would hold its distribution. Severity did not hold anything:

- **`Controversial` returned but overproduced** — 187 against the base model's 49, nearly four times.
- **`Unsafe` collapsed** — 367 against 650.
- **The model began emitting its own category vocabulary in the severity slot** — strings such as
  `non-violent illegal acts`, `others`, `violent` appearing where `Safe`, `Unsafe` or `Controversial`
  belong.

That third observation is the one that settles it. A field that was merely *uncorrected* would drift
within its own vocabulary. A field filling with **the neighboring field's tokens** has not been left
alone; it has been actively reshaped by training it was supposedly excluded from.

### 4.3 The mechanism

A LoRA adapter modifies the query, key, value, output, gate, up and down projections across every
layer. **Both output fields are produced by those same weights.**

Not computing a loss on severity did not hold severity still. It only stopped *correcting* severity
while training moved it anyway. Masking removes a gradient signal; it does not build a wall — and in
the absence of a corrective signal, the field drifted toward the token distribution that training was
actively reinforcing next door.

Stated generally: **under a shared low-rank update there is no "rest of the model" to hold constant.**
Every output field rides the same weights. Loss masking is not a form of parameter isolation and
should not be reasoned about as one.

---

## 5. What follows

**The default was restored to supervising severity binary** — the less bad of two measured losses,
and it at least keeps the severity line well-formed. **That is not a fix**, and we record it as a
retreat rather than a resolution.

**Isolation requires separate parameters, not a flag.** Three routes remain, and none of them is a
third setting of the masking option:

1. **A second adapter** carrying the severity field, with its own parameters.
2. **Target modules that do not carry severity** — which requires knowing which projections produce
   which field, and is a real open question at this scale.
3. **A corpus that can supervise all three severity values** — which, per §3.5, does not currently
   exist in the public guard mixtures.

**A note on gates.** Both runs were stopped by an automated parity gate before a human decided
anything. The gate's value here was not that it caught a bad model; it is that it produced two
*differently worded* rejections, and the difference between them — unresolvable versus regressed —
is what made the second run interpretable as evidence rather than as noise. A promotion gate that
emits a single boolean would have discarded the finding.

---

## 6. Limitations

**Single model, single scale.** One 0.6B model, one adapter configuration. We do not claim the effect
size generalizes; we claim the mechanism does, because it follows from weight sharing rather than
from any property of this model.

**One adapter configuration tested.** A different rank or a different target-module set might reduce
the leakage. **It should not eliminate it**, since the projections producing both fields overlap
under every standard configuration we are aware of — but we did not test that, and the claim is
therefore mechanistic rather than empirical.

**The evaluations were re-run, and they reproduce.** An earlier version of this section reported that
the raw per-item outputs no longer existed: the results directory had been excluded from version
control and never committed, so every figure survived only as recorded prose and as hand-transcribed
literals whose per-class counts were back-computed from published rates.

**Both baseline evaluations were re-executed on 2026-08-30** against the same pinned configuration --
num_ctx 8192, seed 0, temperature 0, fail-closed, the full 1,699-item held-out split, both models at
Q4_K_M with the digest recorded in the original run. The regenerated figures agree with the recorded
ones on every reported metric:

| | recorded | re-run | delta |
|---|---|---|---|
| 4B overall recall | 0.8554 | 0.85676 | +0.0014 |
| 4B precision | 0.9241 | 0.92418 | +0.0001 |
| 4B adversarial=false recall | 0.8886 | 0.88862 | +0.0000 |
| 4B adversarial=true recall | 0.8152 | 0.81818 | +0.0030 |
| 0.6B overall recall | 0.8488 | 0.84615 | -0.0026 |
| 0.6B `Controversial`-scored-safe recall | 0.8011 | 0.80106 | -0.0000 |

The two per-category floors cited in the original gate rejection -- `others` at 0.7857 and
`social_stereotypes_and_unfair_discrimination` at 0.7237 -- reproduce **exactly**. Severity verdict
counts reproduce to within one or two rows (`Controversial` 48 against a recorded 49; safe 1,002
against 1,000; unsafe 649 against 650), which is precisely the one-row precision section 2 claimed
for the reconstructed figures and had no way to verify at the time.

**Consequence.** The per-item records exist again: 1,699 rows per model, each carrying the sample
identifier, expected and predicted labels, emitted severity, gated categories and error state. This
paper ships an artifact rather than an apology, and its baseline numbers are now measured twice, four
months apart, on the same configuration.

**What this does not restore.** The re-run regenerates the two *baseline* evaluations. The adapters
from the two rejected training runs were not retained, so the tuned-model figures in sections 3 and 4
remain as recorded and are **not** independently re-verified. Reproducing those requires re-training,
which is out of scope here and is stated as an open item rather than absorbed.


**Corpus access.** Both corpora are access-gated, and one carries a commercial-use restriction whose
license and gate form disagree. Reproduction requires clearing that.

---

## 7. Related work

An earlier draft of this section claimed that no treatment existed of what happens to an unsupervised
output field when a neighboring field is tuned under a shared adapter. **That claim does not survive
a literature check and has been withdrawn.** *Reasoning-Trace Collapse* (arXiv:2605.21127) runs the
same configuration — a rank-16 LoRA over the standard attention and MLP projections, four open-weight
reasoning models, two-field completions of the form (reasoning, answer), the reasoning field excluded
from the cross-entropy but left in the target while the answer field is supervised — and it measures
the masked field, which does not hold still: valid-trace rates fall to 61–67 percent and the residual
failure mode shifts from empty traces to truncated ones; that work calls masking a partial
mitigation. Three narrower components survive, and the contribution below is stated at that width.

Run 1 is the better documented of the two, and is claimed only as a confirming instance.
That binary supervision produces binary behavior is standing practice rather than a discovery: the
Aegis guardrail datasets carry an explicit third *Needs Caution* label and ship two LoRA-tuned
LlamaGuard variants differing only in whether that label was folded into Safe or into Unsafe (Ghosh
et al., NAACL 2025). Minority collapse supplies the mechanism — above an imbalance threshold the
classifiers for minority classes collapse onto a mutually indistinguishable direction, and a class
with no training targets at all is the degenerate case (Fang et al., PNAS 2021). The result was also
predicted in print: Choudhary et al. (COLM 2026) merge a four-level graded harm classifier with a
binary refusal model, find graded classification collapsing while refusal transfers under every
standard merge rule, and close by naming risk triage and content classification as capabilities
vulnerable to being overwritten by a coarser objective. Run 1 confirms that prediction in the more
common single-run setting. What the reviewed work does not report is the deployment form of §3.3: an
output schema and a documented operator lever that both remain in place after the class they act on
has been eliminated.

The mechanism behind run 2 is likewise established, and existing vocabulary is adopted rather than
any coined. Multi-task learning names cross-objective degradation through shared
parameters *negative transfer*, and its anti-correlated signature the *seesaw phenomenon*, with
separation of shared from task-specific parameters as the standard remedy (Tang et al., RecSys 2020).
Continual learning gives the sharper form: under a moving backbone, classes receiving no loss term
still have their feature distributions drift, which is why *semantic drift* compensation exists (Yu
et al., CVPR 2020; Goswami et al., ECCV 2024). The same holds for LoRA specifically — adaptation
degrades held-out capability that no loss protects, and the working remedy is an explicit
preservation term over the non-target distribution rather than its omission (Xu et al.,
arXiv:2605.29498) — while interference under a single shared adapter is documented with uniformly
parameter-space remedies (arXiv:2504.07448; arXiv:2601.09684). *Parameter isolation* is itself a term
of art in continual learning, so the formulation in §4.3 assembles two existing terms and names
nothing new. Closest of all, multi-task partially supervised learning makes zeroing an unlabeled
task's loss its standard recipe, and its pseudo-supervision machinery exists because that recipe does
not suffice (Kokkinos, CVPR 2017; Li et al., CVPR 2022).

What none of this supplies is the inverse measurement. Masking is evaluated there by its effect on
the supervised objective (arXiv:2404.07965; Huerta-Enochian and Ko, EMNLP 2024), or at the
granularity of a task, a held-out capability, or a broad disposition (arXiv:2502.17424). No located
work reports what the masked positions themselves go on to emit, as a per-class distribution measured
against the base model's. Three claims are therefore advanced: that per-field
distributional measurement (`Controversial` 49 to 187, `Unsafe` 650 to 367); the direction of the
result, in which masking cost 17 points of recall against supervising the field with targets known to
be wrong — the opposite sign to arXiv:2605.21127, whose unmasked baseline supervises a degenerate
empty target that masking removes; and the governance consequence, that a masked field is a policy
surface whose silent movement invalidates a documented control. The vocabulary migration in §4.2
already has a name — a *placement error*, a correct value emitted at the wrong position, in the
taxonomy of Zhang et al. (arXiv:2608.25358) — and that name is adopted here.

The absence asserted above is bounded by how it was tested: three independent English-language sweeps
of arXiv, alphaXiv and the open web, covering the PEFT and loss-masking literature, the multi-task
interference and partial-supervision literature, and guard-model fine-tuning, with full texts read
for the closest hits. No systematic ACL Anthology or citation-graph sweep was run; a forward sweep on
arXiv:2605.21127 or the partially-supervised multi-task line could plausibly close the remaining gap,
and the claims above are scoped to survive that.

---

## 8. Conclusion

Masking a field's loss does not isolate that field under LoRA. The masked field came unmoored,
overproduced one class, collapsed another, and filled with its neighbor's vocabulary — costing 17
points of recall against the alternative it was meant to improve on.

The prior run that motivated the masking is the more useful finding for anyone shipping a guard: a
corpus with binary targets trains a binary model, and it will **extinguish a third output class
without announcing it** — silently converting a documented operator control into a no-op that reports
success.

We publish both because they cost two runs and a week, the explanations are each one sentence, and we
could not find either sentence written down.

---
