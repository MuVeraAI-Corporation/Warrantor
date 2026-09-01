# T-03 Experimental Protocol — Executable Run Plan

**2026-08-30 · the spec that turns the pre-registration into results**

The pre-registration ([`T-03-measuring-guard-models-paper.md`](T-03-measuring-guard-models-paper.md))
freezes the methodology. It has **14 unfilled result markers** and cannot be submitted. This document
is what closes them: exact runs, exact order, exact compute, exact outputs.

**The binding constraint is 17 November 2026** — IEEE S&P 2027 Cycle 2, with abstract registration
mandatory around 10 November. That is **79 days from freeze**, and the runs are the long pole.

**Compute discipline, non-negotiable:** free tier first, no overages, no upgrades. Kaggle for
training (30h/week GPU, 20h/week TPU). Modal only where VRAM exceeds the local 16 GB, against the
existing grant, with a hard **$100 ceiling** for this program. Local RTX 5080 for inference and
anything touching non-public data. US-cloud tiers receive open or synthetic data only.

---

## 0. Preconditions — do these before any run

| # | Precondition | Why it blocks | Done |
|---|---|---|---|
| P1 | Pin the environment **at source**, not by resolver | A floating framework/CUDA pairing already changed what "the same environment" meant between two runs in this program | ☐ |
| P2 | Record `environment.json` — driver, CUDA, framework, tokenizer, quantization | Without it no result is reproducible and the artifact fails its own acceptance test | ☐ |
| P3 | Freeze splits with recorded seeds; generate the **second independent split** now | §4.3 pre-registers a replication check. Generating it later invites split shopping | ☐ |
| P4 | Publish the category normalization map | This is where a distribution confound would hide. Publishing it first makes that impossible to do accidentally | ☐ |
| P5 | Fix the rephrasing transformation set and freeze it | §4.4 requires non-adaptive transformations. A set adjusted after seeing guard behavior invalidates E2 | ☐ |
| P6 | Locate ALL measured evidence — **including `ml/README.md` and `baselines.py`, not only the eval_sets fixtures** | **CORRECTED 2026-08-30. First answer was wrong; see below** | ⚠️ |

### P6 — CORRECTED 2026-08-30. My first answer was wrong.

**What I said:** "zero salvageable experimental evidence."
**What is true:** real, full-split, seed-controlled measured data exists, and I missed it.

I checked two hand-built files and stopped. I never opened `ml/README.md` or
`python/warrantor_ml/src/warrantor_ml/baselines.py`, which is where every real number in this program
lives — four base-model benchmark runs and two rejected training runs, all dated 2026-08-13. That was
a mis-scoped search inside our own repository, and it is the same failure mode T-13 exists to
document.

**What actually exists.** On WildGuardTest, a general 4B guard:

```
overall            recall=0.8554  precision=0.9241  F1=0.8884  FPR=0.0561  n=1699
adversarial=false  recall=0.8886  precision=0.9709                FPR=0.0224  n=903
adversarial=true   recall=0.8152  precision=0.8688                FPR=0.0923  n=796
```

Recall falls 7.3 points on the adversarial slice; **FPR rises 4.12x**. Also measured: 0.6B versus 4B
overall recall differs by z = −0.363, **not significant** — the small model is ahead on the
non-adversarial slice and behind on the adversarial one.

**Why correcting this does not rescue the paper.** Mapping the real data onto the 14 markers:

| Markers | Experiment | Status against the pre-registration |
|---|---|---|
| `R1 R2 R3` | E1 vertical vs. general | **Cannot be filled.** Zero of the four fine-tuned checkpoints exist. What was measured is domain spread *within one untuned guard* — a different hypothesis |
| `R4 R5 R6` | E2 rephrasing | **Cannot be filled as specified.** The 4.12x gap comes from the corpus's own `adversarial` flag across **different items**, not paired rephrasings of the same benign item. No transformation set (P5 unticked), no pairs file, no annotation, no FNR control |
| `R7 R8` | E3 context length | **Nothing.** No sweep has ever run. Every `num_ctx` statement in the tree is a VRAM constraint (32768 KV cache exhausts the 16 GB card) or a config-divergence incident (4096 shipped for eight releases while published figures were 8192) |
| `R9` | scale | Partially supportable |
| `R10` | rejected runs | Supportable for **one** adapter configuration, while §7.3 promises plural |

**Two blockers worse than the missing runs.**

**1. The raw outputs no longer exist.** `/python/warrantor_ml/eval_sets/results/` is gitignored
(`.gitignore:122`), was never committed, and is absent from disk. The only surviving record of every
number is prose in `ml/README.md` plus hand-transcribed literals in `baselines.py` — whose own
comment admits the per-slice counts were **"SOLVED from the published recall, FPR, precision and n"**,
i.e. back-computed from rounded rates and accurate to roughly ±1 row. §7.1 of the paper promises
"raw per-item outputs" as an artifact deliverable. **Every existing benchmark must be re-run simply
to regenerate them.**

**2. The corpora are not on this machine and one is not cleared.** No local cache; both gated.
`baselines.py` records the expanded mixture as `commercial_clearance = "NOT CLEARED"` — its CC-BY-4.0
license and its research-only gate form disagree, and it was generated upstream by a frontier model.

**The one empirical claim defensible today, and it is not among the three.** *The apparent
finance/healthcare/law spread in a general guard is a prevalence artifact of one weak category* —
measured twice, at both scales, with z-values and Wilson intervals. That is the **mechanism behind**
§6.1, not §6.1's claim. Ship nothing else empirical without new runs.

**Net effect on the plan below: unchanged.** All three experiments still start cold, and the raw
outputs must be regenerated regardless. The timeline is still the entire budget.

---

## 1. Model matrix

Six checkpoints. The 2×3 design separates **scale** from **specialization**, which §8.6 of the paper
admits is only partially separable at two scale points.

| ID | Base | Training | Scale | Purpose |
|---|---|---|---|---|
| `G-base-0.6B` | Qwen3Guard-Gen-0.6B | none (as released) | 0.6B | Untouched baseline |
| `G-base-4B` | Qwen3Guard-Gen-4B | none (as released) | 4B | Untouched baseline |
| `G-gen-0.6B` | Qwen3Guard-Gen-0.6B | LoRA, balanced mixed-domain | 0.6B | General fine-tuned |
| `G-gen-4B` | Qwen3Guard-Gen-4B | LoRA, balanced mixed-domain | 4B | General fine-tuned |
| `G-vert-0.6B` | Qwen3Guard-Gen-0.6B | LoRA, vertical corpus | 0.6B | Vertical specialist |
| `G-vert-4B` | Qwen3Guard-Gen-4B | LoRA, vertical corpus | 4B | Vertical specialist |

**Every checkpoint emits a Model BOM**: base model + revision hash, dataset manifest hash, LoRA rank
and target modules, learning rate and schedule, seed, environment hash, and the wall-clock and
platform of the run.

**Critical control for E1.** `G-gen-*` and `G-vert-*` must be trained with **identical**
hyperparameters, identical token budget and identical adapter configuration. The only permitted
difference is the corpus. Any other difference makes E1 uninterpretable, and this is the most likely
way to accidentally invalidate the headline finding.

---

## 2. Experiment 1 — vertical vs. general, category-controlled

**Answers `⟦R1⟧ ⟦R2⟧ ⟦R3⟧`.**

### Runs

| Run | Model | Test set | Output |
|---|---|---|---|
| E1.1 | `G-gen-0.6B` | in-domain, split A | per-item + per-category |
| E1.2 | `G-vert-0.6B` | in-domain, split A | per-item + per-category |
| E1.3 | `G-gen-4B` | in-domain, split A | per-item + per-category |
| E1.4 | `G-vert-4B` | in-domain, split A | per-item + per-category |
| E1.5–E1.8 | all four | in-domain, **split B** | replication |

### Analysis, pre-registered

1. Naive aggregate per model. Record the vertical-minus-general delta.
2. Reweight both to a **common category distribution**. Record the delta again.
3. **The reported finding is the difference between those two deltas.** If the naive delta is
   positive and the reweighted delta is not distinguishable from zero, the gain is a distribution
   artifact.
4. Repeat on split B. **If the effect appears in A and not B, the finding is reported as
   unreplicated** — not quietly dropped, and not reported as confirmed.
5. Bootstrap CIs; multiple-comparison correction across categories; **effect size governs the
   claim**, not the p-value.

### Compute
Training: 4 LoRA runs. Kaggle, 0.6B comfortably; 4B on Kaggle if it fits the session limit, Modal
otherwise. Evaluation: local 5080, 8 runs.
**Estimate: 6–10 GPU-hours training, 2–4 evaluation.**

---

## 3. Experiment 2 — adversarial rephrasing and false-positive rate

**Answers `⟦R4⟧ ⟦R5⟧ ⟦R6⟧`. This is the finding with the widest operational consequence.**

### The transformation set (freeze before generating)

Five transformations, applied mechanically, non-adaptively:

| ID | Transformation | Example shape |
|---|---|---|
| `T1` | Register shift | Casual to formal, or the reverse |
| `T2` | Indirection | Direct request restated as a hypothetical or a report of a request |
| `T3` | Hedging | Modal and epistemic qualifiers added |
| `T4` | Benign framing | The item embedded inside a larger unambiguously benign context |
| `T5` | Technical framing | Restated in domain-technical register |

**Non-adaptive is the whole point.** The set is fixed before any guard sees any output and is never
adjusted in response to observed behavior. An adaptive attacker would produce a larger effect, so
**the measured amplification is a lower bound** and must be reported as one.

### Runs

| Run | Input | Models | Output |
|---|---|---|---|
| E2.1 | benign originals | all 6 | FPR baseline |
| E2.2 | benign × T1–T5 | all 6 | FPR under rephrasing |
| E2.3 | unsafe originals | all 6 | FNR control — confirms rephrasing does not simply shift the operating point |

**E2.3 is not optional.** Without it, a raised FPR is indistinguishable from a guard that has simply
become more conservative, and a reviewer will say so.

### Semantic equivalence validation
Every original/rephrased pair is published. A random sample of 200 pairs is independently annotated
for equivalence by at least two annotators, with **Cohen's κ reported**. Pairs judged non-equivalent
are excluded from the FPR calculation and **the exclusion rate is reported** — a high exclusion rate
is itself a finding about the transformation set.

### Analysis
Paired comparison on the same items. Amplification = FPR(rephrased) / FPR(original), with bootstrap
CI. Decomposed by transformation type `⟦R5⟧` — which transformation dominates is more actionable than
the aggregate.

### Compute
Inference only, no training. Roughly 6 models × 3 conditions × corpus. **Estimate: 4–8 GPU-hours
local.** Rephrasing generation uses an open-weight model locally; **do not use a frontier API to
generate the adversarial set** — provenance discipline, and it would make the artifact
non-reproducible for anyone without that API.

---

## 4. Experiment 3 — context-length sensitivity

**Answers `⟦R7⟧ ⟦R8⟧`. Cheapest experiment, widest methodological consequence.**

### Runs
Sweep `num_ctx` ∈ {2048, 4096, **8192**, 16384, 32768} — clipped to what each model supports, with
the clipping recorded. Input held identical. Three seeds per configuration to separate configuration
effects from sampling noise.

| Run | Models | Configurations | Seeds |
|---|---|---|---|
| E3.1 | all 6 | 5 | 3 |

### Analysis
Decision-change rate across the sweep. Disagreement rate against the pinned 8192 configuration.
**Report whether the direction of change is consistent** — a monotonic effect and a chaotic one have
very different implications, and only one of them supports a simple pinning recommendation.

### Compute
Inference only. **Estimate: 2–4 GPU-hours local.** No training. This experiment could run first.

---

## 5. Recommended execution order

Not the order of the paper. The order that de-risks the deadline.

| Order | Experiment | Why here |
|---|---|---|
| **1st** | **E3** | Cheapest, fastest, no training, validates the whole harness end to end on a small job before anything expensive runs |
| **2nd** | **E2** | Inference only. Independent of training. If training slips, E2 and E3 still yield two of the three findings |
| **3rd** | **E1** | Requires four training runs. The genuine long pole and the one that can miss the deadline |

**This ordering is deliberate insurance.** If E1 slips, a paper reporting the rephrasing fragility and
the context-length confound is still a coherent contribution and still submittable. If the order were
reversed and training slipped, there would be nothing.

---

## 6. Timeline to 17 November

| Weeks from freeze | Dates | Work | Gate |
|---|---|---|---|
| 1 | Aug 30 – Sep 6 | P1–P6 preconditions; harness smoke test; **resolve P6** | Environment pinned, splits frozen |
| 2 | Sep 7 – Sep 13 | **E3 complete** | First results exist. Harness validated |
| 3–4 | Sep 14 – Sep 27 | Rephrasing set frozen and generated; **E2 complete**; annotation sample out | Two of three findings in hand |
| 5–7 | Sep 28 – Oct 18 | Four training runs; **E1 complete** including split B | ⚠️ **Decision gate — see below** |
| 8 | Oct 19 – Oct 25 | Artifact assembled; **clean-room reproduction on an untouched machine** | Acceptance test passed |
| 9–10 | Oct 26 – Nov 8 | §§5–6 populated; **four blocking papers read in full**; references completed | Related work no longer from abstracts |
| 11 | Nov 9 – Nov 10 | **Abstract registration ~10 Nov** | Mandatory, one week ahead |
| 12 | Nov 11 – Nov 17 | Final pass; **submit 17 Nov** | — |

### ⚠️ The decision gate — 18 October, end of week 7

**If E1 is not complete with both splits by 18 October, stop and re-target.**

Options at that gate, in order of preference:

1. **Submit E2 + E3 to IEEE S&P** as a narrower paper on guard fragility and evaluation
   reproducibility. Two solid findings beat three rushed ones, and the pre-registration makes the
   narrowing legible rather than suspicious.
2. **Re-target USENIX Security '27 Cycle 2** (26 January 2027) with all three findings and a stronger
   artifact.
3. **arXiv preprint** on our own timeline, forfeiting peer review.

**Do not submit a three-finding paper with a rushed E1.** A vertical-specialization null result with
an underpowered design is exactly the finding a reviewer will reject, and it is the one most
vulnerable to the "single-lab, self-trained models" objection.

---

## 7. Outputs

```
results/
  environment.json              # driver, CUDA, framework, tokenizer, quantization
  splits/{A,B}.json             # frozen, with seeds
  category-normalization.json   # published — the confound-hiding place
  transformations.json          # frozen T1-T5 set
  models/<id>/model-bom.json    # one per checkpoint
  e1/{run}/per-item.jsonl       # every decision, every item
  e1/aggregate.json             # naive and reweighted, both splits
  e2/{run}/per-item.jsonl
  e2/pairs.jsonl                # every original/rephrased pair, published
  e2/annotation.json            # kappa, exclusion rate
  e2/aggregate.json             # amplification, by transformation
  e3/sweep.jsonl                # decision per (model, num_ctx, seed)
  e3/aggregate.json
  rejected-runs/                # the two masked-loss runs, with effect sizes  ⟦R10⟧
  analysis/*.py                 # every number in the paper reproducible from raw
```

**`per-item.jsonl` is mandatory for every run.** Aggregates alone cannot be re-analyzed by a
reviewer, and re-analysis is what an artifact is for.

---

## 8. What would invalidate the whole program

Stated in advance, so none of these can be rationalized away at analysis time.

1. **`G-gen-*` and `G-vert-*` trained with any difference other than corpus.** E1 becomes
   uninterpretable. Check the Model BOMs before analyzing, not after.
2. **Rephrasing set adjusted after observing guard behavior.** E2 becomes an adaptive attack measured
   as if non-adaptive. The lower-bound claim collapses.
3. **Split B generated after seeing split A results.** The replication check becomes theater.
4. **Environment drift mid-program.** Already happened once in this program. P1 and P2 exist because
   of it.
5. **Clean-room reproduction failing and being quietly re-run on a developer machine.** If it fails,
   the failure is the publication and the claims narrow.

---

## 9. Status

**Not started.** Nothing in §§2–4 has executed. T-03 has 14 unfilled markers and **is not
submittable in any form today.**

**P6 was answered wrongly and is now corrected.** Real measured data exists (four base-model runs,
two rejected training runs, 2026-08-13) but supports **none** of the three pre-registered findings as
specified, and its raw per-item outputs were gitignored and are gone. Every experiment still starts
cold, and the existing benchmarks must additionally be re-run to regenerate the artifact §7.1
promises.

**First action:** P1–P6, then E3. E3 is two weeks out and produces the first real number in the
program.
