# Masking a Field's Loss Does Not Isolate That Field

### Two rejected LoRA runs, and what an unsupervised output field does when its neighbor is tuned

**Research paper (short) · 2026-09-05 · Vikram Jha**
*Catalog ref: T-04 · ~5,300 words · target: SaTML 2027 short/position track, or an ML-safety workshop*

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

Three further runs then test the repair the first two implied. Holding corpus, base model, rank and
schedule fixed and varying **only** which projections the adapter touches, we train an attention-only
arm, a disjoint MLP-only arm, and a full control. **All three extinguish the class**, on a second
evaluation set where the untuned model emits 122 Controversial verdicts rather than 49. The
manipulation is not inert — it swings the false-positive rate by nearly a factor of three, from 0.059
to 0.165 — it simply does not touch this. Choosing better target modules is therefore not available
as a repair, and of the three isolation routes we identified, only a genuinely separate adapter and a
corpus carrying a third label remain.

A pre-registered follow-up on a different corpus and serving stack, at both scales, reproduces the
condition from a format-competent checkpoint: with the severity line contributing nothing to the
loss, the field moved significantly in both models, and every one of the 111 moved verdicts became
more permissive. Masking does not preserve a field. Whether the movement varies with adapter rank
remains untested.

We report all five runs, the automated gate's verdicts, the follow-up, and the corpus property that
blocked the intended repair.

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

**Novelty, bounded first.** That loss masking fails to isolate a field under a shared adapter is
**documented concurrently**, and that binary targets produce binary behavior is **established
practice**. §8 states the contribution at that narrower width and cites the concurrent work.
Five narrower contributions survive:

1. **The distributional signature.** The per-class distribution of a masked *categorical enum*
   measured against the base model's own counts — overproduction of one class, collapse of another,
   and migration of the neighboring field's vocabulary into the masked slot (§4.2).
2. **The direction.** Masking cost 17 recall points *against supervising the same field with wrong
   targets*. That is the opposite sign to the concurrent result, whose unmasked baseline supervises a
   degenerate target, and the disagreement is informative rather than contradictory (§4.1, §8).
3. **The governance consequence.** A masked field is a policy surface. Its silent movement converted
   a documented operator control into a no-op that reported success (§3.3). We are aware of no
   treatment of masked-field drift as an auditability failure rather than a quality failure.
4. **The corpus constraint and the prescription.** The signal needed to supervise three-valued
   severity exists only where it cannot be trained on (§3.5), and isolation therefore requires
   separate parameters rather than a masking flag (§6).
5. **The target-module ablation.** Two disjoint families of projections, each independently
   sufficient to destroy the class, on a configuration whose collapse reproduces to within one item
   across hardware and ten days (§5). This converts the paper's central mechanistic claim into an
   empirical one and closes the cheaper of the two structural repairs — the reading of "separate
   parameters" that means *choose different target modules*, as opposed to *use a second adapter*.

---

## 2. Setup

**Model.** A 0.6B parameter generative guard model, fine-tuned with LoRA: rank 16, alpha 32, dropout
0.05, learning rate 1 × 10⁻⁴, batch 2 with gradient accumulation 8, one epoch, over the query, key,
value, output, gate, up and down projections of every layer. A same-size untuned baseline is
retained deliberately: without a same-size comparator, a rejection cannot distinguish
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
wide margin. §7 states why the underlying per-item outputs cannot be re-derived. An automated gate compares a candidate against a
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

The comparator in the first clause, 0.8554, is the untuned **4B**'s recall on the same split — the
lane's registered baseline at the time. §3.2 compares against the untuned 0.6B, the same-size
comparator §2 argues for, at 0.8488; the gate's verdict is the same against either.

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

The class the lever acts on is also where a guard's measurement noise lives. A companion study
[ReproFloor] finds that the only verdicts that change between repeated runs of the untuned model
are `Safe`/`Controversial` boundary verdicts, so a fine-tune that removes the class removes the
measured floor along with the control — and a floor of zero on such a model measures the loss, not
stability.

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

**The constraint is corpus-specific, not general.** The paragraph above is accurate about the two
corpora in this mixture and does not generalize beyond them. A survey of public alternatives shows
why. The Aegis AI Content Safety Dataset 1.0 carries an explicit third severity
value, **`Needs Caution`**, in its **training** split -- 1,658 occurrences in a 4,000-row sample --
alongside five per-annotator label columns that supply exactly the annotator-agreement signal this
section reports as available only in WildGuardMix's test split.

So the accurate statement is narrower and more useful. **Supervising a three-valued severity output
is possible; it is not possible from the mixture used here.** The corpus-selection decision that
produced the failure is the finding, not a property of the field. A practitioner who needs graded
severity should choose a corpus that labels it, and one exists.

*This does not rescue the runs: both were trained on the mixture described above and both failed
for the reasons given.*


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

The weight-sharing account is mechanistic rather than demonstrated. The experiment that would
demonstrate it — training the two fields with separate adapters, as a positive control — was
deferred and is unrun (§7). What §5 establishes is that no single-adapter module choice preserves
the field, not that weight sharing is the cause.

---

## 5. Runs 3–5 — retargeting the adapter, and the limitation that closes

The mechanistic account in §4.3 makes a prediction: a different target-module set might reduce the
leakage but should not eliminate it, since the projections producing both fields overlap under every
standard configuration we are aware of. Left there, the claim is mechanistic rather than empirical.
This section tests it. The prediction holds, and the route it was hedging is closed.

### 5.1 Design

Three arms, identical in everything but the adapter's target modules. Same base model, same 11,272-row
training corpus — ⚠️ a different corpus from runs 1 and 2: rows drawn from the mixture's second member
alone, whose held-out split scores runs 3–5 below, rather than the 38,694-row mixture of §2 — rank 16,
alpha 32, bf16, one epoch, single A100.

| arm | target modules | rationale |
|---|---|---|
| **A** control | `q,k,v,o,gate,up,down` | run 1's configuration, retrained here |
| **B** attention | `q,k,v,o` | attention projections only |
| **C** MLP | `gate,up,down` | feed-forward projections only |

B and C are **disjoint**. If the severity field is produced by one family and not the other, exactly
one arm should preserve it.

A **stopping rule was fixed before arm A was dispatched**: if the control did not reproduce the
severity collapse, the diagnosis was wrong and arms B and C would be canceled rather than
interpreted. We record it because it is the condition under which we would have reported nothing.

**A different evaluation set from runs 1 and 2.** Runs 1 and 2 were scored on WildGuardTest, where
the untuned 0.6B emits 49 `Controversial` verdicts. Runs 3–5 are scored on ExpGuardTest, 2,275 items,
where it emits **122**. The collapse therefore reproduces on a second evaluation set with a
2.5× larger severity population, which is a stronger statement than a repeat on the original set.

### 5.2 The control reproduces to within one item

Arm A retrains run 1's adapter configuration on the 11,272-row corpus. The run it reproduces is not
run 1 but an earlier training run on that same corpus, from 2026-08-22, whose evaluation on the
second test set had shown the same collapse; arm A repeats it ten days later on different hardware.

| | baseline-only | candidate-only | `unsafe` | `controversial` |
|---|---|---|---|---|
| earlier run, 2026-08-22 | 31 | 115 | 1038 | 122 → **0** |
| **arm A** (retrain) | 31 | 116 | 1038 | 122 → **0** |

Identical `unsafe` count, identical baseline-only count, candidate-only differing by one. The `safe`
counts differ by exactly seven — which is exactly the number of items whose backend call failed in
the second run. Outside those seven the two runs agree item for item.

**The collapse is therefore a property of the configuration, not of the run.** Not a seed, not an
unlucky checkpoint. This is what makes the ablation interpretable at all: there is no run-to-run
variance for a module effect to hide behind.

### 5.3 Every arm loses the class

| arm | modules | recall | FPR | safe | unsafe | **controversial** | base-only | cand-only | exact *p* |
|---|---|---|---|---|---|---|---|---|---|
| baseline | — | 0.7150 | 0.0854 | 1290 | 863 | **122** | — | — | — |
| A control | all seven | 0.7842 | 0.0589 | 1230 | 1038 | **0** | 31 | 116 | <0.0001 |
| B attention | `q,k,v,o` | 0.8439 | 0.1649 | 1047 | 1227 | **0** | 2 | 164 | <0.0001 |
| C MLP | `gate,up,down` | 0.7930 | 0.0864 | 1191 | 1084 | **0** | 19 | 117 | <0.0001 |

*Paired exact-binomial McNemar over shared item ids, positives only; items either run failed to
classify are excluded rather than scored as misses. Arm A's recall is inflated by roughly the seven
backend failures, which the harness scores fail-closed as harmful; the paired counts exclude them.*

**Attention-only destroys the class. MLP-only destroys the class.** Two disjoint module families,
each independently sufficient. There is no third family to try.

### 5.4 The manipulation worked — on something else

A null result is only informative if the intervention did anything at all. It did:

- **Attention-only is badly miscalibrated.** FPR nearly doubles against the baseline, 0.0854 →
  **0.1649**, and the arm calls 1,227 of 2,275 items unsafe. Its 0.8439 recall is the highest figure
  in this program and is substantially bought with false positives.
- **MLP-only is FPR-neutral** — 0.0864 against 0.0854 — while gaining recall.
- **All seven improves FPR**, to 0.0589.

Module choice swings the false-positive rate by nearly a factor of three and leaves the severity class
at zero in every arm. The intervention is potent; it is simply not potent on this.

### 5.5 What this closes, and what it does not

§6 offered three routes to isolation. This experiment resolves one of them and touches neither other:

1. **A second adapter carrying the severity field** — **untested, and now the only surviving
   structural route.** Note that it is *not* what this experiment tested: runs 3–5 varied which
   modules a *single* adapter touches, never how many adapters exist. The distinction matters and
   was blurred in our own planning before the runs.
2. **Target modules that do not carry severity** — **closed.** No such module set exists among the
   projections a LoRA adapter can address here.
3. **A corpus that can supervise all three values** — **untouched by this experiment**, and per §3.5
   the Aegis dataset does carry a third value in its train split. That route remains open and is the
   cheaper of the two survivors, because it requires no architectural change.

The mechanistic claim of §4.3 is now an empirical one, and the weaker reading of "separate parameters"
— choose better target modules — is refuted. Only the stronger reading survives.

---

## 6. What follows

**The default was restored to supervising severity binary** — the less bad of two measured losses,
and it at least keeps the severity line well-formed. **That is not a fix**, and we record it as a
retreat rather than a resolution.

**Isolation requires separate parameters, not a flag.** Of three candidate routes, none is a third
setting of the masking option, and §5 closes one:

1. **A second adapter** carrying the severity field, with its own parameters — untested, and the
   only surviving structural route.
2. **Target modules that do not carry severity** — closed by §5: no such set exists among the
   projections a LoRA adapter addresses here.
3. **A corpus that can supervise all three severity values** — which, per §3.5, exists (Aegis
   carries a third value in its train split) but is not the mixture used here.

**A note on gates.** Both runs were stopped by an automated parity gate before a human decided
anything. The gate's value here was not that it caught a bad model; it is that it produced two
*differently worded* rejections, and the difference between them — unresolvable versus regressed —
is what made the second run interpretable as evidence rather than as noise. A promotion gate that
emits a single boolean would have discarded the finding.

---

## 7. Limitations

**Single model, single scale.** One 0.6B model, one adapter configuration. We do not claim the effect
size generalizes; we claim the mechanism does, because it follows from weight sharing rather than
from any property of this model.

**One adapter rank tested, and the condition reproduced elsewhere.** §5 tests target-module choice
and the prediction holds: attention-only and MLP-only each destroy the class outright, so for target
modules the claim is empirical. A follow-up experiment (T04-X2, pre-registered `2a223cac`) reproduced
the **condition** on a different corpus — Aegis, ungated, CC-BY-4.0 — and a different serving stack,
at two scales. Starting from a format-competent checkpoint of each model, one epoch with the severity
line masked in the loss moved its distribution significantly in both: χ² = 10.48 (0.6B) and 14.67
(4B), df = 2, *p* < 0.05, total variation distance 0.042 and 0.051. It moved **safety-adversely,
with all 111 moved verdicts going `Unsafe` → `Safe`** — 50 in the 0.6B, 61 in the 4B — and none the
other way, while emission of the field held at 99.8% in both. The claim that a masked field does not
hold still is therefore no longer purely mechanistic. Scale did not protect the field; the larger
model drifted slightly more. Only half of this paper's direction claim was testable there: Aegis is
two-valued, so both stages emit zero `Controversial` verdicts by construction and the
`Controversial`-up half needs a three-valued corpus. **The rank dimension is untested.** All three
arms and both follow-up runs ran at rank 16, alpha 32; we do not know what a much larger or much
smaller adapter does, and §5's result gives no reason to expect rank to behave like target-module
choice.

**A distinct failure mode, found while attempting the sweep.** A first attempt at that follow-up
(T04-X) masked the field during fine-tuning that was *teaching* the output format rather than
perturbing an established one, and the masked field was never emitted at all — 0 of 1,199 items
across eleven configurations spanning rank {4, 16, 64}, two target-module sets and both scales — with
the supervised field degraded alongside it, to between 11% and 51% emission against 99.8%. The
mechanism is structural: the target is `Safety: …` followed by `Categories: …`, so the model must
emit the masked line before it can reach the supervised one. The untuned base emits the bare format
on 0 of 1,199 items, so that sweep had no reference distribution and could not compute its
pre-registered statistic; the design error was foreseeable from an earlier result in the same
program, which had labeled exactly those rows *not a baseline*, and it is reported rather than
omitted. Practitioners masking part of a structured target during format acquisition should expect
loss of the whole structure, not selective preservation.

**The baseline evaluations were re-run, and they reproduce.** The original per-item outputs were not
retained — the results directory was never committed — so the figures in §2–§4 survived as recorded
rates and as hand-transcribed counts back-computed from them.

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
paper ships an artifact, and its baseline numbers are measured twice, seventeen days apart, on the
same configuration.

**What this does not restore.** The re-run regenerates the two *baseline* evaluations. The adapters
from the two rejected training runs were not retained, so the tuned-model figures in sections 3 and 4
remain as recorded and are **not** independently re-verified. Reproducing those requires re-training,
which is out of scope here and is stated as an open item rather than absorbed.

One further instance does exist with its per-item outputs retained. A third run with the severity
line masked, trained locally on 2026-08-22 and scored on the same 1,699-item split, emitted
`Controversial` 231 against the base model's 49, `Unsafe` 386 against 650, and category vocabulary —
`others` eleven times, `unethical acts` once — in the severity slot, at an overall recall of 0.7374.
It is run 2's signature at different magnitudes, from a run whose 1,699 verdicts are in the released
dataset. It does not re-derive run 2's figures; it shows the signature is not unique to them.


**Corpus access.** Both corpora are access-gated, and one carries a commercial-use restriction whose
license and gate form disagree. Reproduction requires clearing that.

---

## 8. Related work

The closest prior treatment of what happens to an unsupervised output field when a neighboring
field is tuned under a shared adapter is *Reasoning-Trace Collapse* (arXiv:2605.21127), which runs the
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
et al., CVPR 2020; Gomez-Villa et al., ECCV 2024). The same holds for LoRA specifically — adaptation
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

## 9. Conclusion

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

## References

[Twist et al. 2026] L. Twist et al. *Reasoning-Trace Collapse: Evaluating the Loss of Explicit
Reasoning During Fine-Tuning.* arXiv:2605.21127, 2026.

[Ghosh et al. 2025] S. Ghosh et al. *AEGIS2.0: A Diverse AI Safety Dataset and Risks Taxonomy for
Alignment of LLM Guardrails.* NAACL 2025.

[Fang et al. 2021] C. Fang, H. He, Q. Long and W. J. Su. *Exploring Deep Neural Networks via
Layer-Peeled Model: Minority Collapse in Imbalanced Training.* PNAS 118(43), 2021.

[Choudhary et al. 2026] A. Choudhary et al. *Asymmetric Collapse in Model Merging: When Refusal
Overwrites Recognition.* COLM 2026; arXiv:2607.27240.

[Tang et al. 2020] H. Tang, J. Liu, M. Zhao and X. Gong. *Progressive Layered Extraction (PLE): A
Novel Multi-Task Learning (MTL) Model for Personalized Recommendations.* RecSys 2020.

[Yu et al. 2020] L. Yu et al. *Semantic Drift Compensation for Class-Incremental Learning.* CVPR 2020.

[Gomez-Villa et al. 2024] A. Gomez-Villa, D. Goswami, K. Wang, A. D. Bagdanov, B. Twardowski and
J. van de Weijer. *Exemplar-Free Continual Representation Learning via Learnable Drift
Compensation.* ECCV 2024.

[Xu et al. 2026] R. Xu et al. *Mask the Target: A Plug-and-Play Regularizer Against LoRA Forgetting.*
arXiv:2605.29498, 2026.

[Zhang et al. 2025] J. Zhang et al. *LoRI: Reducing Cross-Task Interference in Multi-Task Low-Rank
Adaptation.* arXiv:2504.07448, 2025.

[Yang et al. 2026] Z. Yang et al. *Disentangling Task Conflicts in Multi-Task LoRA via Orthogonal
Gradient Projection.* arXiv:2601.09684, 2026.

[Kokkinos 2017] I. Kokkinos. *UberNet: Training a Universal Convolutional Neural Network for Low-,
Mid-, and High-Level Vision Using Diverse Datasets and Limited Memory.* CVPR 2017.

[Li et al. 2022] W.-H. Li, X. Liu and H. Bilen. *Learning Multiple Dense Prediction Tasks from
Partially Annotated Data.* CVPR 2022.

[Lin et al. 2024] Z. Lin et al. *Rho-1: Not All Tokens Are What You Need.* arXiv:2404.07965, 2024.

[Huerta-Enochian and Ko 2024] M. Huerta-Enochian and S. Y. Ko. *Instruction Fine-Tuning: Does
Prompt Loss Matter?* EMNLP 2024.

[Betley et al. 2025] J. Betley et al. *Emergent Misalignment: Narrow Finetuning Can Produce Broadly
Misaligned LLMs.* arXiv:2502.17424, 2025.

[Zhang et al. 2026] Y. Zhang et al. *Where vs What: Decomposing Structural and Content Failures in
LLM-Generated Structured Outputs.* arXiv:2608.25358, 2026.

[ReproFloor] V. Jha. *How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small.* Preprint, Zenodo, 2026. doi:10.5281/zenodo.22258094.

---

## Production notes (strip before submission)

**Status: complete, no placeholders except the related-work citations.** Every number is from the
recorded run documents. This is the only paper in the program whose results section did not require
new compute — because the runs already happened and were rejected.

**Before submission.**
1. Complete §8 from full reads. The claim of novelty is stated narrowly and must be checked against
   the PEFT literature specifically.
2. ~~Confirm the back-computed per-slice counts against a surviving log~~ — **closed by the second
   route.** The logs are gone and cannot be recovered; §2 now states the reported precision explicitly
   and identifies which two figures the argument actually rests on. No table in this paper asserts a
   count it did not reconstruct.
3. Decide the venue. Two deadlines were verified against the calls for papers on 2026-08-30:
   **AIWILD @ NeurIPS 2026** (Third Workshop on Agents in the Wild), submissions **5 September 2026
   AoE**, non-archival, 9 pages regular or 4 pages short — the immediate target, and the workshop
   whose ICML 2026 edition published a comparable three-negative-results safety paper; and **IEEE
   SaTML 2027**, abstract **22 September 2026**, paper **29 September 2026**, 12 pages of body text,
   with an anonymized artifact due within three days of submission. SaTML's position/short track
   fits, and it shares the 29 September deadline with T-12 — which is either efficient or
   overcommitted depending on the verification outcome on that paper. TMLR is the archival fallback:
   rolling submission, significance explicitly not a bar, and explicit rejection of papers that
   incorrectly claim novelty over existing published work.

**What makes this publishable where the companion empirical paper is not.** That paper's findings
need runs that have not happened. This paper's finding *is* the runs that happened and failed. The
evidence is complete, the citations are done, and **nothing in it waits on a person or a GPU.**

**Status: submittable.** No placeholders, no unfilled figures, no external dependency. The nearest
deadline is **AIWILD @ NeurIPS 2026 on 5 September** — six days — at 4 pages short or 9 regular,
non-archival, which makes it a low-cost first outing that does not spend the archival version. SaTML
follows on 29 September, and TMLR is the archival fallback whose stated policy — significance not a
bar, and explicit rejection of papers overclaiming novelty — suits a narrowed negative result
unusually well.
