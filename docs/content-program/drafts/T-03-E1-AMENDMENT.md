# T-03 Pre-registration Amendment 1 — Experiment 1 re-scoped

**Dated 2026-08-30. Written and frozen before any Aegis data was loaded for training, and before
any guard was evaluated on Aegis.**

> **Why this document exists.** T-03's pre-registration froze Experiment 1 as a test of *vertical*
> specialization. That experiment cannot be run: its vertical corpus does not resolve on the Hub and
> the program's own registry marks it `commercial_clearance = NOT CLEARED`, with its license and its
> gate form in disagreement. Rather than quietly substitute a corpus and leave the original wording
> in place, the change is recorded here with its reason, its date, and what it costs.

---

## 1. What changed

| | Original (frozen) | Amended |
|---|---|---|
| **Specialization axis** | **Domain / vertical** — finance, clinical, legal | **Harm category** — a semantic cluster of categories |
| Corpus | ExpGuardMix (inaccessible, not cleared) | Aegis AI Content Safety Dataset 1.0 |
| Hypothesis H1 | A guard tuned on vertical-specific data outperforms a general guard on in-domain content | A guard tuned on a category cluster outperforms a general guard on that cluster |
| Null H1₀ | After controlling category distribution, no significant difference | **Unchanged** |
| The reported quantity | The difference between the naive aggregate delta and the distribution-reweighted delta | **Unchanged** |

**The underlying question is unchanged**, and it is the question the paper actually argues:
*does specialization deliver a real gain, or does the apparent gain disappear once prevalence is
controlled?* Only the axis along which "specialization" is defined has moved, because the axis
originally chosen is not available.

**What this costs, stated plainly.** Domain specialization and category specialization are not the
same claim. A null on categories does not establish a null on domains. The paper must say so, must
not present this as the vertical result, and must name the vertical question as open.

---

## 2. The specialization target, selected before any measurement

**Target cluster: `Hate/Identity Hate`, `Harassment`, `Profanity`, `Threat`.**

**Selection criterion, stated in advance:** semantic coherence plus sufficient volume. All four are
forms of *directed interpersonal hostility*, and they are jointly distinct from the other clusters in
the taxonomy — criminal planning, regulated goods, sexual content, privacy, self-harm. Combined
prevalence in the training split is roughly 24%, which supports a training subset without collapsing
to a handful of rows.

⚠️ **The cluster was NOT selected on baseline performance.** No guard has been evaluated on Aegis at
the time of writing. Selecting weak categories after measuring them would make the experiment
adaptive and would guarantee the result — which is the same failure mode the E2 transformation set
was amended to avoid, and it is recorded here so a reader can check the ordering.

---

## 3. Design

**Corpus.** Aegis AI Content Safety Dataset 1.0: 10,798 training rows, 1,199 test rows, five
per-annotator label columns, four text types (`user_message`, `llm_response`, `combined`,
`multi_turn`).

**Two adapters per base model, identical in everything but corpus:**

| | Training rows |
|---|---|
| `G-cat` | Rows whose annotator labels include at least one target-cluster category |
| `G-gen` | A stratified sample across **all** categories, matched to `G-cat` on row count and token budget |

**Held constant, and verified from the Model BOMs before analysis:** base model and revision, LoRA
rank and target modules, learning rate and schedule, token budget, seed, epochs, precision. **The
only permitted difference is which rows are in the corpus.** Any other difference makes the
comparison uninterpretable, and this is the most likely way to invalidate the result accidentally.

**Base models.** 0.6B and 4B, as in the original design, so scale and specialization remain
separable at two points.

**Evaluation.** The Aegis test split. Report per-category performance, the naive aggregate, and the
aggregate after reweighting both models to a common category distribution.

**The reported finding is the difference between those two deltas.** If the naive delta favors
`G-cat` and the reweighted delta does not, the gain is a prevalence artifact rather than acquired
category knowledge.

**Replication.** A second, independently seeded split, generated now rather than after seeing the
first result. If the effect appears in one split and not the other it is reported as
**unreplicated**, not quietly dropped and not reported as confirmed.

---

## 4. A separable finding this corpus makes available

Aegis carries an explicit third severity value, **`Needs Caution`**, at roughly 17.5% prevalence
**in the training split**, plus five per-annotator label columns supplying an agreement signal.

That is precisely the signal T-04 reports as unavailable — the repair its run 1 needed and could not
implement. It is **not** part of this experiment and is not folded into it. It is recorded here as a
separable follow-up, because noticing it during E1 setup and then silently using it would blur two
questions that deserve separate answers.

---

## 5. What would invalidate this experiment

Stated in advance so none can be rationalized later:

1. **Any hyperparameter difference between `G-cat` and `G-gen`.** Check the Model BOMs before
   analyzing, not after.
2. **Re-selecting the target cluster after seeing results.** The cluster is fixed by this document.
3. **Generating the replication split after seeing split one.**
4. **Reporting the category result as though it answered the vertical question.**
5. **Reweighting to a distribution chosen after the fact.** The common distribution is the test
   split's own, fixed here.

---

## 6. Status

**Amendment frozen. No training run has started. No guard has been evaluated on Aegis.**

Compute plan: LoRA training on Modal, per the standing authorization, with adapters and result
documents brought back locally on completion. Evaluation runs locally on the RTX 5080.

---

## 7. Addendum, same day: a confound found during corpus construction

**Recorded after §§1-6 were frozen, before any training run. The hash above covers §§1-6; this
section is appended and the file re-hashed, so the ordering stays auditable.**

The first construction of `G-cat` came out **100% unsafe** -- 2,365 rows of 2,365 -- because
membership in the target cluster implies a harm label. `G-gen`, stratified across all categories
including `Safe`, contained safe rows. Training one adapter on only-unsafe data and comparing it
against an adapter that saw both would have measured **the safe/unsafe balance**, not category
specialization: a model shown only unsafe examples learns to answer unsafe.

That is structurally the same failure T-04 documents in its run 1, where a corpus with binary targets
trained a binary model. Finding the same shape twice in one program is itself worth reporting.

**The corrected construction holds the label balance constant.** Both corpora are n=2,800 at 71.4%
unsafe, which is the corpus-wide ratio. The only difference is the composition of the unsafe half:

| | n | unsafe | target-cluster |
|---|---|---|---|
| `G-cat` | 2,800 | 71.4% | **71.4%** |
| `G-gen` | 2,800 | 71.4% | **35.7%** |

**Why `G-gen` retains target content rather than excluding it.** A general guard that has never seen
hate speech is not a general guard, and beating one would prove nothing. The contrast under test is
**concentration** -- roughly twofold -- not presence. If specialization delivers a real gain,
doubling the density of the target categories should produce it.

**Consequence for interpretation.** A null under this design means specialization at 2x
concentration produced no measurable gain once distribution is controlled. It does not test
higher concentrations, and the paper must not claim it does.

Splits A and B were both generated at this point, from seeds 0 and 1, before any result was seen.

---

## 8. Addendum, 2026-08-30 23:00: training complete, and one difference the launch check could not see

**All eight runs succeeded on Modal A100-80GB. Every adapter wrote `adapter_model.safetensors`,
verified by reading the weights back rather than by exit code.**

**§5.1 verified against the artifacts, not the launch command.** The eight `run_record.json` files
agree exactly on every training hyperparameter:

| | value, identical across all eight |
|---|---|
| lora_rank / lora_alpha | 16 / 32 |
| sequence_length | 1024 |
| batch_size x grad_accum | 4 x 2 |
| learning_rate | 1e-4 |
| epochs / seed | 2 / 0 |
| technique / base_dtype | qlora / nf4 |
| precision | bf16 |

**One difference the pre-flight could not detect.** The pre-flight compared *plans*, which are
written before dispatch. It cannot see what hardware the scheduler assigns. Modal allocated two
A100 variants:

| | split A | split B |
|---|---|---|
| `G-cat` | A100 80GB **PCIe** | A100 **SXM4** 80GB |
| `G-gen` | A100 **SXM4** 80GB | A100 80GB **PCIe** |

All four 4B runs landed on SXM4, so **the 4B comparison is on matched hardware**.

For the 0.6B the assignment is **crossed**: each arm received one of each variant, so the hardware
is balanced across the treatment rather than aligned with it. It contributes noise, not bias.
Both variants report compute capability [8, 0] -- the same architecture and the same bf16 kernels;
PCIe and SXM4 differ in interconnect and power envelope, not arithmetic.

**What this obliges the analysis to do.** The amendment already requires that an effect appearing in
one split and not the other be reported as **unreplicated**. There is now a second reason a 0.6B
split could disagree, and if the 0.6B splits diverge while the 4B splits agree, **hardware variance
must be named as a candidate explanation** rather than the divergence being attributed to the
corpus by default.

**For future runs.** Pin the accelerator variant, or record it as a covariate before dispatch. A
plan-level pre-flight is necessary and not sufficient: it verifies intent, and the run record
verifies what happened. Both are needed, and only the second one saw this.

## 9. Remaining work

Training is complete; **the experiment is not**. Still outstanding: evaluate all eight adapters on
the Aegis test split, report per-category performance, the naive aggregate delta, and the delta
after reweighting both arms to the test split's own category distribution. The reported finding is
the difference between those two deltas (§3).
